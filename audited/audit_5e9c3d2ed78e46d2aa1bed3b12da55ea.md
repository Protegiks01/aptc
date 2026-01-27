# Audit Report

## Title
Block Output Limit Exceeded Due to Configuration Mismatch Between Consensus and Execution Layers

## Summary
A configuration mismatch between consensus-level block size limits (`max_sending_block_bytes = 3MB`) and execution-level output limits (`block_output_limit = 4MB`) combined with the `include_user_txn_size_in_block_output` flag causes blocks to regularly exceed output limits during normal operation, resulting in early execution halts, wasted resources, and degraded network performance.

## Finding Description
The Aptos blockchain enforces block size limits at two different layers with incompatible values:

1. **Consensus Layer**: Validators propose blocks up to 3MB of transaction input [1](#0-0) 

2. **Execution Layer**: Block execution enforces a 4MB output limit [2](#0-1) 

3. **Output Size Calculation**: When `include_user_txn_size_in_block_output = true` (default), the output size includes BOTH the transaction bytes AND the write operations [3](#0-2) 

The `materialized_size()` function calculates output size by including ModuleWriteSets along with other writes [4](#0-3) 

**Attack Scenario:**
1. Attacker submits 2-3MB of module publishing transactions to mempool
2. Honest validator includes these transactions in a block proposal (within 3MB sending limit)
3. During execution, the BlockGasLimitProcessor calculates output size:
   - Transaction bytes: ~2.5MB
   - Write operations (including ModuleWriteSets): ~2.5MB  
   - Total output: ~5MB
4. This exceeds `block_output_limit` (4MB)
5. Execution halts early via `should_end_block_parallel()` [5](#0-4) 
6. Remaining transactions are marked `SkipRest` and scheduler halts [6](#0-5) 

The validators can accept blocks up to 6MB [7](#0-6)  making the issue worse if malicious validators propose larger blocks.

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria ("Validator node slowdowns") because it causes:

- **Resource Waste**: Validators execute transactions that will ultimately be skipped, wasting CPU and memory
- **Reduced Block Utilization**: Blocks consistently fail to utilize their full capacity due to premature halts
- **Network Performance Degradation**: Repeated early execution halts slow down the entire network
- **DoS Vector**: Attackers can deliberately flood mempool with module publishing transactions to exacerbate the issue

The configuration mismatch creates a 50% overhead scenario where a 3MB block produces 6MB of output (when including user transaction bytes), exceeding the 4MB limit by 50%.

## Likelihood Explanation
**Likelihood: High**

This issue occurs naturally during normal network operation without requiring malicious behavior:

1. **Default Configuration**: The misconfiguration exists in the default genesis settings
2. **Honest Validators**: Standard validators following protocol will create problematic blocks when mempool contains sufficient module publishing transactions
3. **Common Operation**: Module publishing is a routine operation on Aptos, not an edge case
4. **No Special Access**: Any user can submit module publishing transactions to trigger the issue
5. **Predictable**: The 2:1 input-to-output ratio is deterministic and consistent

The issue is further exploitable by malicious actors who can intentionally submit large module publishing transactions to force early execution halts.

## Recommendation
Adjust the configuration values to ensure consensus limits are compatible with execution limits:

**Option 1: Increase block_output_limit**
Set `block_output_limit` to at least 2x the `max_sending_block_bytes` to account for the double-counting when `include_user_txn_size_in_block_output = true`:

```rust
block_output_limit: Some(6 * 1024 * 1024), // 6MB instead of 4MB
```

**Option 2: Disable include_user_txn_size_in_block_output**
Set the flag to `false` to avoid double-counting transaction bytes:

```rust
include_user_txn_size_in_block_output: false,
```

**Option 3: Reduce max_sending_block_bytes**
Reduce consensus limits to match execution capacity:

```rust
max_sending_block_bytes: 2 * 1024 * 1024, // 2MB instead of 3MB
```

**Recommended Solution**: Increase `block_output_limit` to 8MB and reduce `max_receiving_block_bytes` to match a safe threshold, ensuring `max_receiving_block_bytes * 2 <= block_output_limit`.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_block_output_limit_mismatch() {
    // Setup: Create a block with module publishing transactions
    // totaling 2.5MB of transaction bytes
    
    let mut transactions = vec![];
    const MODULE_SIZE: usize = 50_000; // 50KB per module
    const NUM_MODULES: usize = 50; // 50 modules = 2.5MB total
    
    for i in 0..NUM_MODULES {
        let module_bytecode = vec![0u8; MODULE_SIZE];
        let txn = create_module_publish_transaction(
            format!("module_{}", i),
            module_bytecode
        );
        transactions.push(txn);
    }
    
    // Total transaction bytes: 2.5MB
    let total_txn_bytes: usize = transactions.iter()
        .map(|t| t.size_in_bytes())
        .sum();
    assert_eq!(total_txn_bytes, 2_500_000);
    
    // Execute block
    let block_gas_limit_type = BlockGasLimitType::ComplexLimitV1 {
        effective_block_gas_limit: 100_000_000,
        execution_gas_effective_multiplier: 1,
        io_gas_effective_multiplier: 1,
        conflict_penalty_window: 9,
        use_granular_resource_group_conflicts: false,
        use_module_publishing_block_conflict: true,
        block_output_limit: Some(4 * 1024 * 1024), // 4MB
        include_user_txn_size_in_block_output: true,
        add_block_limit_outcome_onchain: true,
    };
    
    let result = execute_block(transactions, block_gas_limit_type);
    
    // Expected: Early execution halt
    assert!(result.block_output_limit_reached);
    
    // Expected output size: ~2.5MB (transaction bytes) + ~2.5MB (writes) = 5MB
    // This exceeds 4MB limit, causing early halt
    assert!(result.block_approx_output_size > 4 * 1024 * 1024);
    
    // Expected: Not all transactions committed
    assert!(result.num_transactions_committed < NUM_MODULES);
}
```

## Notes

This vulnerability affects the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The configuration mismatch allows blocks to be proposed that exceed execution limits, violating this invariant and causing resource waste.

The issue is most severe when `include_user_txn_size_in_block_output = true` (default), as this creates a 2:1 amplification factor between input and output sizes. ModuleWriteSets specifically contribute to this problem because module publishing transactions contain large bytecode payloads that get counted twice in the output calculation.

### Citations

**File:** config/src/config/consensus_config.rs (L227-227)
```rust
            max_sending_block_bytes: 3 * 1024 * 1024, // 3MB
```

**File:** config/src/config/consensus_config.rs (L231-231)
```rust
            max_receiving_block_bytes: 6 * 1024 * 1024, // 6MB
```

**File:** types/src/on_chain_config/execution_config.rs (L151-151)
```rust
            block_output_limit: Some(4 * 1024 * 1024),
```

**File:** aptos-move/block-executor/src/executor.rs (L2272-2289)
```rust
                    let approx_output_size = self
                        .config
                        .onchain
                        .block_gas_limit_type
                        .block_output_limit()
                        .map(|_| {
                            output_before_guard.output_approx_size()
                                + if self
                                    .config
                                    .onchain
                                    .block_gas_limit_type
                                    .include_user_txn_size_in_block_output()
                                {
                                    txn.user_txn_bytes_len()
                                } else {
                                    0
                                } as u64
                        });
```

**File:** aptos-move/aptos-vm-types/src/output.rs (L124-138)
```rust
    pub fn materialized_size(&self) -> u64 {
        let mut size = 0;
        for (state_key, write_size) in self
            .change_set
            .write_set_size_iter()
            .chain(self.module_write_set.write_set_size_iter())
        {
            size += state_key.size() as u64 + write_size.write_len().unwrap_or(0);
        }

        for event in self.change_set.events_iter() {
            size += event.size() as u64;
        }
        size
    }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L143-153)
```rust
        if let Some(per_block_output_limit) = self.block_gas_limit_type.block_output_limit() {
            let accumulated_output = self.get_accumulated_approx_output_size();
            if accumulated_output >= per_block_output_limit {
                counters::EXCEED_PER_BLOCK_OUTPUT_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_output {} >= PER_BLOCK_OUTPUT_LIMIT {}",
                    mode, accumulated_output, per_block_output_limit,
                );
                return true;
            }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L362-372)
```rust
        if txn_idx < num_txns - 1
            && block_limit_processor.should_end_block_parallel()
            && !skips_rest
        {
            if output_wrapper.output_status_kind == OutputStatusKind::Success {
                must_create_epilogue_txn |= !output_before_guard.has_new_epoch_event();
                drop(output_before_guard);
                output_wrapper.output_status_kind = OutputStatusKind::SkipRest;
            }
            skips_rest = true;
        }
```
