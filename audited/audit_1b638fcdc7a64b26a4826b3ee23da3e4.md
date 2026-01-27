# Audit Report

## Title
Integer Overflow in Cumulative Delta Calculation Causes Validator Crash and Network Halt

## Summary
The `aggregate_and_update_total_supply()` function in the sharded block executor accumulates deltas across shards using unchecked addition. When the cumulative sum exceeds `u128::MAX`, the validator panics due to overflow checks being enabled, causing total network liveness failure.

## Finding Description

The sharded block executor processes transactions in parallel across multiple shards, with each shard tracking changes to the total supply. After execution, the `aggregate_and_update_total_supply()` function aggregates these changes. [1](#0-0) 

At line 199, cumulative deltas are computed by adding the current shard's delta to the previous cumulative value. This addition uses the `DeltaU128::add` implementation: [2](#0-1) 

When both deltas are positive (or both negative), line 76 performs direct addition: `self.delta + rhs.delta`. This operation is subject to Rust's overflow checking configuration.

The release profile has overflow checks enabled: [3](#0-2) 

The base value for delta calculations is set to half of `u128::MAX`: [4](#0-3) 

**Overflow Scenario:**
- Maximum positive delta: `u128::MAX - (u128::MAX >> 1) = 170141183460469231731687303715884105728`
- With two shards having maximum deltas: `170141183460469231731687303715884105728 + 170141183460469231731687303715884105728 = 340282366920938463463374607431768211456`
- This equals `u128::MAX + 1`, triggering overflow

**Attack Path:**
1. Total supply reaches near `u128::MAX` (either through massive minting over time or via a separate minting vulnerability)
2. Multiple shards process transactions with minting operations
3. Each shard's final total supply is close to `u128::MAX`, producing large positive deltas
4. At line 199, when accumulating deltas, the addition at line 76 overflows
5. With `overflow-checks = true`, the program panics
6. Validator crashes and cannot process the block
7. All validators attempting to process the same block encounter identical overflow
8. Network halts completely

**Broken Invariants:**
- **Deterministic Execution**: Validators crash before completing execution, preventing state root computation
- **Liveness**: Network cannot progress when all validators crash on the same block

The code contains a misleading comment suggesting overflow will be "indicated to the caller": [5](#0-4) 

In reality, with `overflow-checks = true`, the program terminates immediately via panic rather than returning an error.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program, specifically matching:
- **"Total loss of liveness/network availability"**: All validators crash when processing blocks with overflow-inducing deltas, causing complete network halt
- **"Non-recoverable network partition (requires hardfork)"**: Recovery requires code changes and potentially a hardfork to bypass the problematic block

The deterministic panic means all honest validators fail identically, preventing any subset from making progress. The network remains halted until the code is patched.

## Likelihood Explanation

**Current Likelihood: EXTREMELY LOW**

Current APT supply is approximately 10^17 base units. For overflow to occur, total supply must approach `u128::MAX` (~3.4 × 10^38), requiring roughly 10^21 times the current supply.

**However, likelihood increases under:**
1. **Long-term operation**: After decades/centuries of continuous minting
2. **Separate minting bug**: If another vulnerability allows unlimited minting, this becomes immediately exploitable
3. **Multiple coin types**: If the aggregation logic incorrectly combines different coin types
4. **Chain parameter changes**: Future governance decisions that dramatically increase supply limits

The vulnerability represents a "time bomb" - while currently impractical to exploit, it could trigger unexpectedly if economic parameters change or if combined with other bugs.

## Recommendation

Replace unchecked addition with either checked or saturating arithmetic:

**Option 1 - Checked Addition (Fail-fast):**
```rust
impl ops::Add for DeltaU128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self.is_positive == rhs.is_positive {
            return Self {
                delta: self.delta.checked_add(rhs.delta)
                    .expect("Delta overflow: cumulative delta exceeds u128::MAX. This indicates either a bug in supply tracking or unrealistic supply growth."),
                is_positive: self.is_positive,
            };
        }
        // ... rest unchanged
    }
}
```

**Option 2 - Saturating Addition (Graceful degradation):**
```rust
impl ops::Add for DeltaU128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self.is_positive == rhs.is_positive {
            return Self {
                delta: self.delta.saturating_add(rhs.delta),
                is_positive: self.is_positive,
            };
        }
        // ... rest unchanged
    }
}
```

**Option 3 - Larger Integer Type (Most robust):**
Use `U256` or `U512` for cumulative deltas to eliminate overflow risk entirely. This requires refactoring `DeltaU128` to support larger backing types while maintaining efficient delta representation.

**Recommended**: Option 1 with a clear error message provides early detection while maintaining fail-fast semantics. Update the documentation at lines 26-29 to accurately describe the overflow behavior.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to add with overflow")]
fn test_delta_cumulative_overflow() {
    use crate::sharded_block_executor::sharded_aggregator_service::DeltaU128;
    
    // Create two deltas at maximum positive value
    // Maximum delta = u128::MAX - (u128::MAX >> 1) = u128::MAX/2 + 1
    let max_delta = u128::MAX - (u128::MAX >> 1);
    
    let delta1 = DeltaU128 {
        delta: max_delta,
        is_positive: true,
    };
    
    let delta2 = DeltaU128 {
        delta: max_delta,
        is_positive: true,
    };
    
    // This should panic due to overflow when both deltas are added
    // max_delta + max_delta = (u128::MAX/2 + 1) * 2 = u128::MAX + 2 > u128::MAX
    let _result = delta1 + delta2;
    
    // If we reach here, the test fails (overflow should have panicked)
    panic!("Expected overflow panic did not occur");
}

#[test]
fn test_delta_accumulation_realistic_scenario() {
    use crate::sharded_block_executor::sharded_aggregator_service::DeltaU128;
    
    // Simulate 3 shards each with large positive deltas
    let base_val = u128::MAX >> 1; // TOTAL_SUPPLY_AGGR_BASE_VAL
    
    // Each shard has total_supply = u128::MAX - 1000 (very high)
    let high_supply = u128::MAX - 1000;
    let shard_delta = DeltaU128::get_delta(high_supply, base_val);
    
    // Accumulate across shards (simulating lines 198-199)
    let mut cumulative = DeltaU128::default();
    
    for shard_id in 0..3 {
        // This will panic on the second or third iteration
        cumulative = cumulative + shard_delta;
        println!("Shard {}: cumulative delta = {}, positive = {}", 
                 shard_id, cumulative.delta, cumulative.is_positive);
    }
}
```

**Test Execution:**
Place this code in `aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs` within the test module. Running `cargo test test_delta_cumulative_overflow` will demonstrate the panic. The `test_delta_accumulation_realistic_scenario` shows how multiple shards with high supply values trigger the overflow.

## Notes

While this vulnerability has critical impact, its exploitation requires total supply to reach economically unrealistic levels (10^21 times current APT supply). However, defensive programming principles dictate that arithmetic operations on cumulative values should use checked or saturating operations to prevent unexpected panics. The misleading documentation further emphasizes the need for correction.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L26-29)
```rust
/// This class ensures that deltas can use all 128 bits without having to let go of the sign bit for
/// cases where the delta is negative. That is, we don't have to use conversions to i128.
/// However, it does not handle overflow and underflow. That is, it will indicate to the caller of
/// the faulty logic with their usage of deltas.
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L69-78)
```rust
impl ops::Add for DeltaU128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // the deltas are both positive or both negative, we add the deltas and keep the sign
        if self.is_positive == rhs.is_positive {
            return Self {
                delta: self.delta + rhs.delta,
                is_positive: self.is_positive,
            };
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L184-202)
```rust
    for round in 0..num_rounds {
        sharded_output.iter().for_each(|shard_output| {
            let mut curr_delta = DeltaU128::default();
            // Though we expect all the txn_outputs to have total_supply, there can be
            // exceptions like 'block meta' (first txn in the block) and 'chkpt info' (last txn
            // in the block) which may not have total supply. Hence we iterate till we find the
            // last txn with total supply.
            for txn in shard_output[round].iter().rev() {
                if let Some(last_txn_total_supply) = txn.write_set().get_total_supply() {
                    curr_delta =
                        DeltaU128::get_delta(last_txn_total_supply, TOTAL_SUPPLY_AGGR_BASE_VAL);
                    break;
                }
            }
            aggr_total_supply_delta[aggr_ts_idx] =
                curr_delta + aggr_total_supply_delta[aggr_ts_idx - 1];
            aggr_ts_idx += 1;
        });
    }
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L14-14)
```rust
pub const TOTAL_SUPPLY_AGGR_BASE_VAL: u128 = u128::MAX >> 1;
```
