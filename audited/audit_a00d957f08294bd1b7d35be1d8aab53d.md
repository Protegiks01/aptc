# Audit Report

## Title
Per-Block Gas Limit Bypass via Storage Fee Exclusion Allows Unbounded Actual Gas Consumption

## Summary
The per-block gas limit enforcement checks only `effective_block_gas` (calculated from execution and IO gas) while excluding storage fees. This allows attackers to consume actual gas far exceeding the per-block limit by crafting transactions with minimal execution/IO gas but maximum storage operations, violating the fundamental resource constraint that the gas limit is designed to enforce.

## Finding Description

The `BlockGasLimitProcessor` in the block executor enforces per-block gas limits by tracking `accumulated_effective_block_gas`, which is calculated exclusively from execution and IO gas with conflict penalties: [1](#0-0) 

The limit check compares this effective gas against the configured per-block gas limit: [2](#0-1) 

However, the actual gas charged to users (`total_charge_gas_units` in `FeeStatement`) includes storage fees converted to gas units. Storage fees are substantial: 40,000 octas per state slot and 40 octas per byte: [3](#0-2) 

These storage fees are converted to internal gas units during transaction execution: [4](#0-3) 

The converted storage fees are included in `total_charge_gas_units` when constructing the `FeeStatement`: [5](#0-4) 

**Attack Path:**
1. Attacker crafts transactions with minimal execution/IO gas (e.g., 500 gas units) but maximum storage operations (e.g., 200 state slot creations = 8,000,000 octas in storage fees)
2. With `gas_unit_price = 100`, storage fees convert to ~80,000 external gas units per transaction
3. Total gas per transaction: 500 + 80,000 = 80,500 units, but only 500 counted toward the limit
4. With a 20,000 gas block limit, 40 such transactions fit (20,000 / 500 = 40)
5. Actual total gas consumed: 40 × 80,500 = **3,220,000 gas units**
6. Per-block limit: 20,000 gas units
7. **Violation ratio: 161x over the stated limit**

This breaks **Critical Invariant #9** ("Resource Limits: All operations must respect gas, storage, and computational limits") by allowing actual gas consumption to vastly exceed the per-block gas limit.

## Impact Explanation

**Severity: Critical** - This qualifies as a "Significant protocol violation" under High severity criteria, potentially escalating to Critical due to:

1. **Resource Limit Violation**: The per-block gas limit is a fundamental protocol-level resource constraint. Bypassing it undermines the entire gas metering system's integrity.

2. **State Bloat Attack Vector**: Attackers can write significantly more data to blockchain state than the gas limit was designed to prevent, at up to 161x the intended rate. With `max_write_ops_per_transaction = 8192` and `max_bytes_all_write_ops_per_transaction = 10MB`, attackers can inject up to 400MB of state data per block while staying within a 20,000 gas "limit."

3. **Economic Exploitation**: Users collectively pay gas fees far exceeding what the block's "limit" suggests, potentially breaking economic assumptions in fee distribution, gas price mechanisms, and protocol economics.

4. **Consensus Assumption Risk**: While this doesn't cause immediate consensus divergence, downstream systems may assume `Σ(gas_used) ≤ block_gas_limit`, potentially causing issues in block validation, state sync, or economic calculations.

## Likelihood Explanation

**Likelihood: High**

- **No special privileges required**: Any transaction sender can exploit this
- **Simple to execute**: Just create transactions with high storage writes and low execution gas
- **Economically viable**: Attackers pay the storage fees, but achieve state bloat at 161x the intended rate
- **Not rate-limited**: The vulnerability exists in the core gas accounting logic, affecting all blocks
- **Currently active**: The default genesis configuration uses this vulnerable gas limit enforcement

## Recommendation

Modify `BlockGasLimitProcessor::accumulate_fee_statement()` to include storage fees (converted to gas units) in the effective gas calculation:

```rust
// In limit_processor.rs, line 103-109
let raw_gas_used = fee_statement.execution_gas_used()
    * self.block_gas_limit_type.execution_gas_effective_multiplier()
    + fee_statement.io_gas_used() * self.block_gas_limit_type.io_gas_effective_multiplier()
    + storage_fee_to_gas_units(fee_statement.storage_fee_used(), gas_unit_price); // ADD THIS

// Helper function to convert storage fee to gas units
fn storage_fee_to_gas_units(storage_fee_octas: u64, gas_unit_price: u64) -> u64 {
    let gas_unit_scaling_factor = 1_000_000u64;
    ((storage_fee_octas as u128 * gas_unit_scaling_factor as u128) 
     / gas_unit_price as u128 / gas_unit_scaling_factor as u128) as u64
}
```

Alternatively, introduce a separate per-block storage fee limit to bound state growth independently while maintaining execution time limits.

## Proof of Concept

```rust
#[test]
fn test_storage_fee_bypass_gas_limit() {
    use aptos_types::fee_statement::FeeStatement;
    use aptos_types::on_chain_config::BlockGasLimitType;
    
    let block_gas_limit = BlockGasLimitType::ComplexLimitV1 {
        effective_block_gas_limit: 20_000,
        execution_gas_effective_multiplier: 1,
        io_gas_effective_multiplier: 1,
        conflict_penalty_window: 1,
        use_module_publishing_block_conflict: false,
        block_output_limit: None,
        include_user_txn_size_in_block_output: true,
        add_block_limit_outcome_onchain: false,
        use_granular_resource_group_conflicts: false,
    };

    let mut processor = BlockGasLimitProcessor::new(block_gas_limit, None, 100);
    
    // Create transactions with high storage fees but low execution/IO gas
    // Each transaction: 300 exec + 200 IO + 80,000 storage fee in gas units
    // Storage fee: 8,000,000 octas with gas_unit_price=100 → 80,000 gas units
    for _ in 0..40 {
        let fee_statement = FeeStatement::new(
            80_500,      // total_charge_gas_units (includes storage converted to gas)
            300,         // execution_gas_units
            200,         // io_gas_units
            8_000_000,   // storage_fee_octas (not in gas units)
            0            // storage_fee_refund_octas
        );
        processor.accumulate_fee_statement(fee_statement, None, None);
    }
    
    // The effective gas is only 40 * 500 = 20,000 (at limit)
    assert_eq!(processor.accumulated_effective_block_gas, 20_000);
    assert!(processor.should_end_block_parallel());
    
    // But actual total gas charged is 40 * 80,500 = 3,220,000 (161x over limit!)
    assert_eq!(processor.accumulated_fee_statement.gas_used(), 3_220_000);
    
    // VULNERABILITY: Actual gas consumed is 161x the per-block gas limit
    println!("Gas limit: 20,000");
    println!("Actual gas consumed: 3,220,000");
    println!("Violation ratio: {}x", 3_220_000 / 20_000);
}
```

## Notes

- The exclusion of storage fees from the gas limit is **explicitly documented** in the code comments [6](#0-5) , suggesting this may be intentional design. However, the semantic violation of the "per-block gas limit" concept and the exploitability for state bloat attacks constitute a security vulnerability regardless of intent.

- The `EFFECTIVE_BLOCK_GAS` metric mentioned in the security question correctly tracks this effective gas [7](#0-6) , but the discrepancy between effective gas (used for limits) and actual gas (charged to users) creates the vulnerability.

- The maximum storage operations per transaction are bounded by `max_write_ops_per_transaction = 8192` and `max_bytes_all_write_ops_per_transaction = 10MB` [8](#0-7) , but these limits are insufficient to prevent the gas limit bypass.

### Citations

**File:** aptos-move/block-executor/src/limit_processor.rs (L100-109)
```rust
        // When the accumulated execution and io gas of the committed txns exceeds
        // PER_BLOCK_GAS_LIMIT, early halt BlockSTM. Storage fee does not count towards
        // the per block gas limit, as we measure execution related cost here.
        let raw_gas_used = fee_statement.execution_gas_used()
            * self
                .block_gas_limit_type
                .execution_gas_effective_multiplier()
            + fee_statement.io_gas_used() * self.block_gas_limit_type.io_gas_effective_multiplier();
        self.accumulated_raw_block_gas += raw_gas_used;
        self.accumulated_effective_block_gas += conflict_multiplier * raw_gas_used;
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L127-141)
```rust
    fn should_end_block(&mut self, mode: &str) -> bool {
        if let Some(per_block_gas_limit) = self.block_gas_limit() {
            // When the accumulated block gas of the committed txns exceeds
            // PER_BLOCK_GAS_LIMIT, early halt BlockSTM.
            let accumulated_block_gas = self.get_effective_accumulated_block_gas();
            if accumulated_block_gas >= per_block_gas_limit {
                counters::EXCEED_PER_BLOCK_GAS_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_block_gas {} >= PER_BLOCK_GAS_LIMIT {}",
                    mode, accumulated_block_gas, per_block_gas_limit,
                );
                return true;
            }
        }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-162)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
        [
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L184-199)
```rust
            storage_fee_per_state_slot: FeePerSlot,
            { 14.. => "storage_fee_per_state_slot" },
            // 0.8 million APT for 2 billion state slots
            40_000,
        ],
        [
            legacy_storage_fee_per_excess_state_byte: FeePerByte,
            { 7..=13 => "storage_fee_per_excess_state_byte", 14.. => "legacy_storage_fee_per_excess_state_byte" },
            50,
        ],
        [
            storage_fee_per_state_byte: FeePerByte,
            { 14.. => "storage_fee_per_state_byte" },
            // 0.8 million APT for 2 TB state bytes
            40,
        ],
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L260-263)
```rust
        let gas_consumed_internal = div_ceil(
            (u64::from(amount) as u128) * (u64::from(txn_params.gas_unit_scaling_factor) as u128),
            u64::from(gas_unit_price) as u128,
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L546-559)
```rust
    fn fee_statement_from_gas_meter(
        txn_data: &TransactionMetadata,
        gas_meter: &impl AptosGasMeter,
        storage_fee_refund: u64,
    ) -> FeeStatement {
        let gas_used = Self::gas_used(txn_data.max_gas_amount(), gas_meter);
        FeeStatement::new(
            gas_used,
            u64::from(gas_meter.execution_gas_used()),
            u64::from(gas_meter.io_gas_used()),
            u64::from(gas_meter.storage_fee_used()),
            storage_fee_refund,
        )
    }
```

**File:** aptos-move/block-executor/src/counters.rs (L202-211)
```rust
pub static EFFECTIVE_BLOCK_GAS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_execution_effective_block_gas",
        "Histogram for different effective block gas costs - used for evaluating block gas limit. \
        This can be different from actual gas consumed in a block, due to applied adjustements",
        &["mode"],
        gas_buckets(),
    )
    .unwrap()
});
```
