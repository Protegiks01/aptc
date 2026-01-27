# Audit Report

## Title
Round Count Mismatch Causes Unvalidated Array Access Leading to Panic or Silent Data Loss in Sharded Block Executor

## Summary
The sharded block executor calculates the number of rounds (`num_rounds`) based solely on the first shard's output length without validating that all shards have the same number of rounds. This missing validation can cause out-of-bounds array access leading to node crashes (panic) when the invariant that "all shards must have equal rounds" is violated by bugs, remote executor issues, or data corruption.

## Finding Description

The sharded block executor assumes all shards return the same number of execution rounds, an invariant expected to be maintained by the partitioner. However, this invariant is **never validated** at runtime in two critical locations:

**Location 1:** The main aggregation logic calculates `num_rounds` from only the first shard: [1](#0-0) 

Then uses this to size the output array and iterate through all shards: [2](#0-1) 

**Location 2:** The total supply aggregation service has the identical vulnerability: [3](#0-2) 

Used to iterate through all shards: [4](#0-3) 

**Exploitation Scenarios:**

1. **If shard 0 is empty but other shards have results:**
   - `num_rounds = 0`, `ordered_results = vec![]`
   - Accessing `ordered_results[round * num_executor_shards + shard_id]` for any non-zero shard triggers **out-of-bounds panic**

2. **If shard 0 has fewer rounds than other shards:**
   - Example: shard 0 has 2 rounds, shard 1 has 3 rounds
   - `ordered_results` sized for 2 rounds only
   - Processing shard 1's round 2 accesses beyond array bounds → **panic**

3. **In the total supply aggregation:**
   - Similar out-of-bounds access at `aggr_total_supply_delta_ref[round * num_shards + shard_id]`
   - Or out-of-bounds at `shard_output[round]` when iterating

**How Invariant Can Be Violated:**

While the partitioner currently enforces equal rounds (verified in test utilities), the invariant can be broken by: [5](#0-4) 

- **Remote executor bugs/Byzantine behavior:** The remote executor client receives results over the network without validation: [6](#0-5) 

- **Executor service bugs:** Early return paths that don't propagate errors properly
- **Future refactoring:** Changes to partitioner that accidentally break the invariant
- **Data corruption:** Memory safety violations in unsafe code or FFI

The code violates the **defense-in-depth principle** by not validating critical invariants at trust boundaries.

## Impact Explanation

**Severity: High**

This vulnerability causes **validator node crashes** through unrecoverable panics:

1. **Availability Impact:** Affected validators cannot process blocks, reducing network capacity
2. **Non-deterministic Failures:** Different validators may crash at different times based on when they receive mismatched results, causing inconsistent network state
3. **Liveness Risk:** If multiple validators crash simultaneously, consensus could stall

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to:
- Validator node crashes (explicitly listed as High severity)
- Significant protocol violations affecting block processing

While not reaching Critical severity (no consensus safety violation or fund loss), the panic-based failure mode is worse than graceful error handling, as it provides no opportunity for recovery or rollback.

## Likelihood Explanation

**Likelihood: Medium**

Currently **unlikely** in production because:
- The partitioner correctly creates equal rounds for all shards
- Test utilities validate this invariant
- Local executor implementation is well-tested

However, likelihood increases due to:

1. **Remote Execution:** The remote executor path has no validation of received data structure consistency
2. **Code Complexity:** The invariant is maintained implicitly across multiple components (partitioner → executor → aggregator), making it fragile
3. **Future Changes:** Refactoring could inadvertently break the invariant without detection until runtime panic
4. **No Runtime Checks:** The complete absence of validation means any invariant violation immediately causes a crash

The fact that the same vulnerability appears in **two separate files** suggests a systematic gap in defensive programming practices.

## Recommendation

Add explicit validation after receiving execution results from shards:

```rust
// In mod.rs execute_block(), after line 97:
let num_rounds = sharded_output.first()
    .map(|s| s.len())
    .unwrap_or(0);

// VALIDATE: all shards must have same number of rounds
for (shard_id, shard_result) in sharded_output.iter().enumerate() {
    if shard_result.len() != num_rounds {
        return Err(VMStatus::error(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            Some(format!(
                "Shard round count mismatch: shard {} has {} rounds but shard 0 has {}",
                shard_id, shard_result.len(), num_rounds
            ))
        ));
    }
}
```

Apply the same validation in `sharded_aggregator_service.rs` after line 175:

```rust
let num_rounds = sharded_output[0].len();

// Validate all shards have same number of rounds
for (shard_id, shard_output) in sharded_output.iter().enumerate() {
    assert_eq!(
        shard_output.len(), 
        num_rounds,
        "Shard {} has {} rounds but expected {} rounds",
        shard_id, shard_output.len(), num_rounds
    );
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_round_count_mismatch_causes_panic() {
        // Simulate the vulnerability: shard 0 has 1 round, shard 1 has 2 rounds
        let mut sharded_output: Vec<Vec<Vec<TransactionOutput>>> = vec![
            vec![vec![]],  // Shard 0: 1 round (empty)
            vec![vec![], vec![]],  // Shard 1: 2 rounds (empty)
        ];
        
        let num_executor_shards = 2;
        
        // This is the vulnerable code from mod.rs line 98
        let num_rounds = sharded_output[0].len();  // = 1
        let mut ordered_results = vec![vec![]; num_executor_shards * num_rounds];  // length = 2
        
        // This loop will panic when processing shard 1's second round
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                // When shard_id=1, round=1: index = 1 * 2 + 1 = 3, but length = 2
                ordered_results[round * num_executor_shards + shard_id] = result;  // PANIC!
            }
        }
    }
}
```

## Notes

This vulnerability demonstrates a **missing defensive validation** at a critical trust boundary. While the current implementation maintains the invariant through careful coordination between partitioner and executor, the aggregation code should validate this invariant rather than assuming it holds. This is especially important for:

1. **Remote execution scenarios** where network boundaries exist
2. **Future-proofing** against refactoring that might break implicit invariants  
3. **Defense-in-depth** principle: downstream code should validate upstream assumptions

The identical pattern appearing in two separate files (`mod.rs` and `sharded_aggregator_service.rs`) indicates a systematic gap that should be addressed across the codebase.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L98-98)
```rust
        let num_rounds = sharded_output[0].len();
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L100-106)
```rust
        let mut ordered_results = vec![vec![]; num_executor_shards * num_rounds];
        // Append the output from individual shards in the round order
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                ordered_results[round * num_executor_shards + shard_id] = result;
            }
        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L175-175)
```rust
    let num_rounds = sharded_output[0].len();
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

**File:** execution/block-partitioner/src/test_utils.rs (L165-172)
```rust
    let num_rounds = output
        .sharded_txns()
        .first()
        .map(|sbs| sbs.sub_blocks.len())
        .unwrap_or(0);
    for sub_block_list in output.sharded_txns().iter().take(num_shards).skip(1) {
        assert_eq!(num_rounds, sub_block_list.sub_blocks.len());
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L163-172)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        trace!("RemoteExecutorClient Waiting for results");
        let mut results = vec![];
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
        }
        Ok(results)
    }
```
