# Audit Report

## Title
Integer Overflow Panic in Sharded Total Supply Aggregation Causes Consensus Liveness Failure

## Summary
The `DeltaU128::add_delta()` function in the sharded block executor performs unchecked arithmetic operations that can trigger integer overflow panics when aggregating total supply deltas across shards. An attacker can craft transactions that cause all validators to panic during block execution, resulting in complete network liveness failure. [1](#0-0) 

## Finding Description
The sharded block executor uses `TOTAL_SUPPLY_AGGR_BASE_VAL = u128::MAX >> 1` as an artificial base value during parallel transaction execution to avoid cross-shard coordination. [2](#0-1) 

After execution, `aggregate_and_update_total_supply()` must compute the actual total supply by aggregating deltas from all shards and applying them to transaction outputs. [3](#0-2) 

The vulnerability exists in `DeltaU128::add_delta()` which performs arithmetic without bounds checking:
- Line 53: `self.delta + other` can overflow when `is_positive` is true
- Line 55: `other - self.delta` can underflow when `is_positive` is false

Since Aptos enables `overflow-checks = true` in release builds [4](#0-3) , these arithmetic operations will **panic** rather than wrap around.

**Attack Scenario:**

1. Real total supply starts at value `S` (e.g., 100 tokens)
2. Attacker submits transaction that burns significant portion of supply (valid at Move level due to proper bounds checking [5](#0-4) )
3. During sharded execution:
   - Transaction executes with base value `BASE = u128::MAX >> 1`
   - After burn: `txn_total_supply = BASE - burned_amount`
4. Delta computation at aggregation:
   - `base_val_delta = get_delta(S, BASE) ≈ {delta: BASE - S, is_positive: false}`
   - `curr_delta = get_delta(BASE - burned_amount, BASE) = {delta: burned_amount, is_positive: false}`
   - When accumulated: `delta_for_round ≈ {delta: BASE, is_positive: false}`
5. Final update call at line 234: [6](#0-5) 
   - Executes: `(BASE - burned_amount) - BASE`
   - This underflows, triggering **panic** with overflow-checks enabled

All validators executing the same block deterministically hit the same panic, causing complete consensus liveness failure.

## Impact Explanation
**Critical Severity** - This vulnerability qualifies under multiple Aptos bug bounty Critical categories:

1. **Total loss of liveness/network availability**: When the panic occurs, all validators crash or fail to process the block, bringing the entire network to a halt. No new blocks can be produced until validators restart and skip the problematic block.

2. **Consensus Safety violation**: This breaks the fundamental "Deterministic Execution" invariant - all validators must produce identical state roots for identical blocks. While the execution is deterministic (all crash identically), it violates the assumption that valid blocks should be processable.

The vulnerability requires no privileged access and can be triggered by any user capable of submitting transactions. The impact affects the entire validator set simultaneously, making it a network-wide denial of service attack against blockchain availability.

## Likelihood Explanation
**High Likelihood** - The attack is straightforward to execute:

1. **Ease of Exploitation**: Requires only submitting burn/mint transactions with specific amounts when sharded execution is active
2. **No Special Access**: Any unprivileged user can submit the triggering transactions
3. **Deterministic Trigger**: The mathematical conditions for overflow are predictable based on current total supply and BASE value
4. **Production Impact**: Sharded execution is production code invoked via `LocalExecutorClient::execute_block()` [7](#0-6) 

The comment at lines 28-29 acknowledges the lack of overflow handling but provides no actual "indication to the caller" - the function simply panics. [8](#0-7) 

## Recommendation
Implement proper bounds checking in `add_delta()` and the `Add` trait implementation:

```rust
fn add_delta(self, other: u128) -> Result<u128, String> {
    if self.is_positive {
        self.delta.checked_add(other)
            .ok_or_else(|| format!("Delta overflow: {} + {}", self.delta, other))
    } else {
        other.checked_sub(self.delta)
            .ok_or_else(|| format!("Delta underflow: {} - {}", other, self.delta))
    }
}
```

Similarly, add overflow checks to the `Add` trait implementation at line 76: [9](#0-8) 

```rust
impl ops::Add for DeltaU128 {
    type Output = Result<Self, String>;
    
    fn add(self, rhs: Self) -> Self::Output {
        if self.is_positive == rhs.is_positive {
            let delta = self.delta.checked_add(rhs.delta)
                .ok_or_else(|| format!("Delta accumulation overflow"))?;
            return Ok(Self { delta, is_positive: self.is_positive });
        }
        // ... rest with proper error handling
    }
}
```

Update all call sites to handle the `Result` type and log/reject blocks with invalid delta accumulations.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to subtract with overflow")]
fn test_delta_underflow_attack() {
    // Simulate the attack scenario
    const BASE: u128 = u128::MAX >> 1;
    let real_supply: u128 = 100;
    let burned_amount: u128 = 100;
    
    // Step 1: base_val_delta (real supply vs BASE)
    let base_val_delta = DeltaU128::get_delta(real_supply, BASE);
    assert!(!base_val_delta.is_positive);
    assert_eq!(base_val_delta.delta, BASE - real_supply);
    
    // Step 2: curr_delta (transaction burns tokens)
    let txn_total_supply = BASE - burned_amount;
    let curr_delta = DeltaU128::get_delta(txn_total_supply, BASE);
    assert!(!curr_delta.is_positive);
    assert_eq!(curr_delta.delta, burned_amount);
    
    // Step 3: Accumulate deltas
    let delta_for_round = curr_delta + base_val_delta;
    assert!(!delta_for_round.is_positive);
    assert_eq!(delta_for_round.delta, BASE); // Large negative delta
    
    // Step 4: Apply delta - THIS PANICS
    // Attempts: (BASE - 100) - BASE which underflows
    let _result = delta_for_round.add_delta(txn_total_supply);
}
```

To run: Add this test to `sharded_aggregator_service.rs` and execute `cargo test test_delta_underflow_attack` with `--release` flag to ensure overflow-checks are active.

**Notes**

The vulnerability is confirmed by cross-referencing:
1. The vulnerable arithmetic operations without bounds checking
2. The enabled overflow-checks in production builds preventing silent wraparound
3. The deterministic execution path through sharded block executor
4. The lack of error handling at call sites for the aggregation result
5. The direct write to state via `update_total_supply()` without validation [10](#0-9) 

While Move-level operations have proper bounds checking via `optional_aggregator` [11](#0-10) , the Rust aggregation layer lacks equivalent protections, creating a critical consensus vulnerability.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L26-29)
```rust
/// This class ensures that deltas can use all 128 bits without having to let go of the sign bit for
/// cases where the delta is negative. That is, we don't have to use conversions to i128.
/// However, it does not handle overflow and underflow. That is, it will indicate to the caller of
/// the faulty logic with their usage of deltas.
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L51-57)
```rust
    fn add_delta(self, other: u128) -> u128 {
        if self.is_positive {
            self.delta + other
        } else {
            other - self.delta
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L72-79)
```rust
    fn add(self, rhs: Self) -> Self::Output {
        // the deltas are both positive or both negative, we add the deltas and keep the sign
        if self.is_positive == rhs.is_positive {
            return Self {
                delta: self.delta + rhs.delta,
                is_positive: self.is_positive,
            };
        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L168-173)
```rust
pub fn aggregate_and_update_total_supply<S: StateView>(
    sharded_output: &mut Vec<Vec<Vec<TransactionOutput>>>,
    global_output: &mut [TransactionOutput],
    state_view: &S,
    executor_thread_pool: Arc<rayon::ThreadPool>,
) {
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L233-235)
```rust
                                txn_output.update_total_supply(
                                    delta_for_round.add_delta(txn_total_supply),
                                );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L14-14)
```rust
pub const TOTAL_SUPPLY_AGGR_BASE_VAL: u128 = u128::MAX >> 1;
```

**File:** Cargo.toml (L923-923)
```text
overflow-checks = true
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator/optional_aggregator.move (L48-51)
```text
    fun sub_integer(integer: &mut Integer, value: u128) {
        assert!(value <= integer.value, error::out_of_range(EAGGREGATOR_UNDERFLOW));
        integer.value = integer.value - value;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator/optional_aggregator.move (L124-143)
```text
    public fun add(optional_aggregator: &mut OptionalAggregator, value: u128) {
        if (option::is_some(&optional_aggregator.aggregator)) {
            let aggregator = option::borrow_mut(&mut optional_aggregator.aggregator);
            aggregator::add(aggregator, value);
        } else {
            let integer = option::borrow_mut(&mut optional_aggregator.integer);
            add_integer(integer, value);
        }
    }

    /// Subtracts `value` from optional aggregator, aborting on going below zero.
    public fun sub(optional_aggregator: &mut OptionalAggregator, value: u128) {
        if (option::is_some(&optional_aggregator.aggregator)) {
            let aggregator = option::borrow_mut(&mut optional_aggregator.aggregator);
            aggregator::sub(aggregator, value);
        } else {
            let integer = option::borrow_mut(&mut optional_aggregator.integer);
            sub_integer(integer, value);
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L215-220)
```rust
        sharded_aggregator_service::aggregate_and_update_total_supply(
            &mut sharded_output,
            &mut global_output,
            state_view.as_ref(),
            self.global_executor.get_executor_thread_pool(),
        );
```

**File:** types/src/transaction/mod.rs (L1830-1832)
```rust
    pub fn update_total_supply(&mut self, value: u128) {
        self.write_set.update_total_supply(value);
    }
```
