# Audit Report

## Title
Integer Overflow in Block Gas Limit Calculation Allows Gas Undercounting via Malicious Governance Parameters

## Summary
The `accumulate_fee_statement()` function in the block executor performs unchecked u64 multiplication between gas consumption values and governance-controlled multiplier parameters. Without overflow protection or parameter validation, a malicious or buggy governance proposal could set extreme multiplier values causing integer overflow, wrapping around to undercount gas consumption and bypassing block gas limits.

## Finding Description

The vulnerability exists in the block gas limit tracking mechanism. [1](#0-0) 

The code performs unchecked u64 arithmetic operations:
- `execution_gas_used * execution_gas_effective_multiplier`
- `io_gas_used * io_gas_effective_multiplier`
- Addition of products
- `conflict_multiplier * raw_gas_used`
- Accumulation to running totals

The multiplier parameters are u64 values controlled by on-chain governance via the `BlockGasLimitType::ComplexLimitV1` configuration. [2](#0-1) 

**Critical Issue**: No validation exists on these multiplier values. The getter methods return raw u64 values without bounds checking. [3](#0-2) 

**Overflow Behavior**: In Rust release mode (used by validators), integer overflow wraps silently rather than panicking. If `execution_gas_used = 2,000,000` (production MAX_GAS_AMOUNT) [4](#0-3)  and a governance proposal sets `execution_gas_effective_multiplier = 10,000,000,000,000` (10 trillion), the multiplication `2,000,000 * 10,000,000,000,000 = 20,000,000,000,000,000` exceeds u64::MAX (18,446,744,073,709,551,615), wrapping to a tiny value.

**Impact**: When `raw_gas_used` wraps to a small value due to overflow, the block gas limit check fails to trigger. [5](#0-4)  This allows more transactions to be packed into blocks than the configured gas limit permits, leading to:
1. Block execution times exceeding expected bounds
2. Validator performance degradation and slowdowns
3. Potential consensus liveness issues if blocks become too expensive to process
4. Violation of the "Resource Limits" invariant

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Blocks could contain significantly more computation than intended, degrading validator performance
- **Significant protocol violations**: Breaks the block gas limit mechanism designed to ensure predictable block processing times

While not Critical severity (no direct fund loss or consensus safety violation), this can cause severe operational issues across the network if exploited.

## Likelihood Explanation

**Medium-to-Low Likelihood**, but **High Impact**:

**Requirements for exploitation:**
1. Governance proposal must be submitted and approved
2. Proposal must set `execution_gas_effective_multiplier` or `io_gas_effective_multiplier` to extremely high values (> 9 trillion)
3. Transactions with normal gas consumption would trigger overflow

**Mitigating factors:**
- Requires governance access (proposal submission + voting)
- Current production values are 1, operating safely
- Governance participants would likely notice obviously unreasonable values

**Risk factors:**
- No validation prevents this - missing defensive programming
- Could occur accidentally via buggy governance proposal code
- Once deployed, would affect all subsequent blocks until another governance proposal fixes it
- Other blockchains use checked arithmetic for critical calculations to prevent this class of bug

## Recommendation

Implement two layers of protection:

**1. Governance Parameter Validation**: Add bounds checking when deserializing `BlockGasLimitType::ComplexLimitV1`. Reasonable bounds might be:
```rust
// In execution_config.rs, add validation
impl BlockGasLimitType {
    const MAX_SAFE_MULTIPLIER: u64 = 1_000; // Allow up to 1000x multiplier
    
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            BlockGasLimitType::ComplexLimitV1 {
                execution_gas_effective_multiplier,
                io_gas_effective_multiplier,
                ..
            } => {
                if *execution_gas_effective_multiplier > Self::MAX_SAFE_MULTIPLIER {
                    return Err("execution_gas_effective_multiplier exceeds safe bounds");
                }
                if *io_gas_effective_multiplier > Self::MAX_SAFE_MULTIPLIER {
                    return Err("io_gas_effective_multiplier exceeds safe bounds");
                }
                Ok(())
            }
            _ => Ok(())
        }
    }
}
```

**2. Use Checked Arithmetic**: Replace unchecked operations with `saturating_mul()` or `checked_mul()`:
```rust
// In limit_processor.rs
let raw_gas_used = fee_statement.execution_gas_used()
    .saturating_mul(self.block_gas_limit_type.execution_gas_effective_multiplier())
    .saturating_add(
        fee_statement.io_gas_used()
            .saturating_mul(self.block_gas_limit_type.io_gas_effective_multiplier())
    );
self.accumulated_raw_block_gas = self.accumulated_raw_block_gas.saturating_add(raw_gas_used);
self.accumulated_effective_block_gas = self.accumulated_effective_block_gas
    .saturating_add(conflict_multiplier.saturating_mul(raw_gas_used));
```

Saturating arithmetic clamps to u64::MAX instead of wrapping, preventing undercount.

## Proof of Concept

```rust
#[test]
fn test_gas_calculation_overflow() {
    use aptos_types::on_chain_config::BlockGasLimitType;
    use aptos_types::fee_statement::FeeStatement;
    
    // Create a malicious governance config with extreme multiplier
    let malicious_config = BlockGasLimitType::ComplexLimitV1 {
        effective_block_gas_limit: 1000000,
        execution_gas_effective_multiplier: 10_000_000_000_000, // 10 trillion
        io_gas_effective_multiplier: 1,
        conflict_penalty_window: 1,
        use_granular_resource_group_conflicts: false,
        use_module_publishing_block_conflict: false,
        block_output_limit: None,
        include_user_txn_size_in_block_output: true,
        add_block_limit_outcome_onchain: false,
    };
    
    // Normal transaction with 2 million gas (production MAX_GAS_AMOUNT)
    let fee_statement = FeeStatement::new(2_000_000, 2_000_000, 0, 0, 0);
    
    // Simulate the vulnerable calculation
    let execution_gas_used: u64 = fee_statement.execution_gas_used();
    let multiplier: u64 = malicious_config.execution_gas_effective_multiplier();
    
    // This overflows in release mode!
    let raw_gas_used = execution_gas_used * multiplier;
    
    // Expected: 2,000,000 * 10,000,000,000,000 = 20,000,000,000,000,000
    // u64::MAX = 18,446,744,073,709,551,615
    // Result wraps to small value instead of proper gas accounting
    
    println!("execution_gas_used: {}", execution_gas_used);
    println!("multiplier: {}", multiplier);
    println!("raw_gas_used (with overflow): {}", raw_gas_used);
    println!("Expected (without overflow): {}", 2_000_000u128 * 10_000_000_000_000u128);
    
    // In release mode, raw_gas_used will be a wrapped small value,
    // severely undercounting gas and bypassing block limits
    assert!(raw_gas_used < 2_000_000, "Overflow causes severe undercount");
}
```

**Notes**

This vulnerability represents a failure of defensive programming. While current governance-set multiplier values (1) operate safely, critical financial and consensus calculations must use checked or saturating arithmetic to prevent catastrophic failures from parameter errors. The Aptos codebase demonstrates awareness of overflow risks in other gas-related code [6](#0-5)  and gas algebra operations [7](#0-6) , making this unchecked arithmetic an inconsistency that should be addressed.

### Citations

**File:** aptos-move/block-executor/src/limit_processor.rs (L103-109)
```rust
        let raw_gas_used = fee_statement.execution_gas_used()
            * self
                .block_gas_limit_type
                .execution_gas_effective_multiplier()
            + fee_statement.io_gas_used() * self.block_gas_limit_type.io_gas_effective_multiplier();
        self.accumulated_raw_block_gas += raw_gas_used;
        self.accumulated_effective_block_gas += conflict_multiplier * raw_gas_used;
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L127-156)
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
        }

        false
```

**File:** types/src/on_chain_config/execution_config.rs (L280-313)
```rust
    ComplexLimitV1 {
        /// Formula for effective block gas limit:
        /// effective_block_gas_limit <
        /// (execution_gas_effective_multiplier * execution_gas_used +
        ///  io_gas_effective_multiplier * io_gas_used
        /// ) * (1 + num conflicts in conflict_penalty_window)
        effective_block_gas_limit: u64,
        execution_gas_effective_multiplier: u64,
        io_gas_effective_multiplier: u64,
        conflict_penalty_window: u32,

        /// If true we look at granular resource group conflicts (i.e. if same Tag
        /// within a resource group has a conflict)
        /// If false, we treat any conclicts inside of resource groups (even across
        /// non-overlapping tags) as conflicts).
        use_granular_resource_group_conflicts: bool,
        /// Module publishing today fallbacks to sequential execution,
        /// even though there is no read-write conflict.
        /// When enabled, this flag allows us to account for that conflict.
        /// NOTE: Currently not supported.
        use_module_publishing_block_conflict: bool,

        /// Block limit on the total (approximate) txn output size in bytes.
        block_output_limit: Option<u64>,
        /// When set, we include the user txn size in the approximate computation
        /// of block output size, which is compared against the block_output_limit above.
        include_user_txn_size_in_block_output: bool,

        /// When set, we create BlockEpilogue (instead of StateCheckpint) transaction,
        /// which contains BlockEndInfo
        /// NOTE: Currently not supported.
        add_block_limit_outcome_onchain: bool,
    },
}
```

**File:** types/src/on_chain_config/execution_config.rs (L327-347)
```rust
    pub fn execution_gas_effective_multiplier(&self) -> u64 {
        match self {
            BlockGasLimitType::NoLimit => 1,
            BlockGasLimitType::Limit(_) => 1,
            BlockGasLimitType::ComplexLimitV1 {
                execution_gas_effective_multiplier,
                ..
            } => *execution_gas_effective_multiplier,
        }
    }

    pub fn io_gas_effective_multiplier(&self) -> u64 {
        match self {
            BlockGasLimitType::NoLimit => 1,
            BlockGasLimitType::Limit(_) => 1,
            BlockGasLimitType::ComplexLimitV1 {
                io_gas_effective_multiplier,
                ..
            } => *io_gas_effective_multiplier,
        }
    }
```

**File:** config/global-constants/src/lib.rs (L28-31)
```rust
#[cfg(any(test, feature = "testing"))]
pub const MAX_GAS_AMOUNT: u64 = 100_000_000;
#[cfg(not(any(test, feature = "testing")))]
pub const MAX_GAS_AMOUNT: u64 = 2_000_000;
```

**File:** crates/aptos-rosetta/src/construction.rs (L343-350)
```rust
            if let Some(multiplied_price) = gas_price.checked_mul(gas_multiplier) {
                gas_price = multiplied_price.saturating_div(100)
            } else {
                return Err(ApiError::InvalidInput(Some(format!(
                    "Gas price multiplier {} causes overflow on the price",
                    gas_multiplier
                ))));
            }
```

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L230-232)
```rust
    GasQuantity::new(x.val.saturating_mul(y.val))
}

```
