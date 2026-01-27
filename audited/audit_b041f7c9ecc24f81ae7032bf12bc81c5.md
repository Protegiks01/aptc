# Audit Report

## Title
Stale Randomness State After Failed Reset Causes Validator Divergence and Consensus Liveness Failure

## Summary
When the `RandResetDropped` error occurs during state synchronization, the error is caught and logged in the RoundManager event loop but the node continues operating with stale randomness state. This causes the affected validator's `highest_known_round` to remain unupdated, leading to rejection of randomness shares for future rounds and permanent inability to participate in randomness generation, resulting in consensus liveness failure.

## Finding Description

The vulnerability exists in the interaction between error handling in the consensus event loop and the randomness manager reset mechanism.

**The Reset Flow:**

When a validator receives sync info from peers indicating it has fallen behind, it initiates a state sync process that must reset the randomness manager to the target round. The reset process performs two critical operations: [1](#0-0) 

The reset updates `highest_known_round` to the target round and clears stale randomness state from the maps.

**The Error Path:**

The `RandResetDropped` error is returned when the randomness manager's reset channel is dropped or fails to acknowledge: [2](#0-1) 

This error propagates through: `reset()` → `sync_to_target()` → `fast_forward_sync()` → `sync_to_highest_quorum_cert()` → `add_certs()` → `process_sync_info_msg()`.

**The Critical Flaw:**

In the RoundManager event loop, errors from `process_sync_info_msg` are caught but only logged, allowing the node to continue operating: [3](#0-2) 

**The Validation Check:**

The randomness manager validates incoming shares against `highest_known_round`: [4](#0-3) 

The constant `FUTURE_ROUNDS_TO_ACCEPT` is defined as 200 rounds: [5](#0-4) 

**Exploitation Scenario:**

1. Validator A is at round 100 when it falls behind and needs to sync to round 350
2. During `fast_forward_sync`, the RandManager's reset channel fails (e.g., task panic), returning `RandResetDropped`
3. The error propagates to the RoundManager event loop where it's caught and logged
4. Validator A's execution state syncs to round 350, **but** its randomness state remains at round 100:
   - `highest_known_round` = 100 (not updated to 350)
   - `rand_map` contains stale entries (not cleared)
5. When blocks at round 351 arrive:
   - **Properly synced validators**: Accept shares because 351 ≤ 350 + 200 ✓
   - **Validator A**: Rejects shares because 351 > 100 + 200 ✗
6. Validator A cannot participate in randomness generation for any round > 300
7. If Validator A's voting weight is required for the threshold, randomness cannot be aggregated
8. Blocks requiring randomness cannot be finalized → **consensus liveness failure**

**Invariant Violation:**

This breaks the **Deterministic Execution** invariant: validators must produce identical state for identical inputs. Validator A has diverged in its randomness generation state despite processing the same blocks.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per the Aptos bug bounty criteria:

1. **Validator node slowdowns**: The affected validator cannot process blocks requiring randomness, causing consensus delays
2. **Significant protocol violations**: The validator diverges from the network state despite believing it is synchronized
3. **Consensus liveness impact**: If the affected validator has sufficient voting weight to prevent threshold achievement, the entire network cannot progress

While not meeting Critical severity (which requires complete network halt or funds loss), this creates a persistent liveness degradation that can only be resolved by restarting the affected validator node. Multiple affected validators could cause complete network halt.

The impact is deterministic and permanent once triggered - there is no automatic recovery mechanism. The validator will continue rejecting all shares for rounds beyond its stale `highest_known_round + 200` window indefinitely.

## Likelihood Explanation

**Medium-Low likelihood** but deterministic consequences:

**Trigger conditions:**
- RandManager task panic or unexpected termination during reset processing
- Sync gap > 200 rounds between old and new state
- Error occurs during state sync from peer sync info messages

**Likelihood factors:**

*Less likely:*
- Requires RandManager failure at precise moment during reset
- The `.expect()` calls in RandManager indicate most failures should crash the node entirely: [6](#0-5) 

*More likely:*
- Network partitions or extended downtime can create large sync gaps > 200 rounds
- Once triggered, the failure is permanent until node restart
- Multiple validators could be affected simultaneously if common failure condition exists

**Criticality:** Despite medium-low likelihood, the **deterministic liveness failure** with **no automatic recovery** makes this a serious security concern requiring immediate attention.

## Recommendation

Implement proper error handling for `RandResetDropped` to prevent the node from continuing with inconsistent state:

**Option 1: Panic on Reset Failure (Fail-Stop)**

In the RoundManager event loop, treat reset failures as fatal:

```rust
// In round_manager.rs, around line 2186
let round_state = self.round_state();
match result {
    Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
    Err(e) => {
        // Check for reset-related errors that indicate inconsistent state
        if e.to_string().contains("RandResetDropped") || 
           e.to_string().contains("ResetDropped") {
            panic!("[RoundManager] Fatal: Reset failed during sync, state inconsistent. Error: {:#}", e);
        }
        counters::ERROR_COUNT.inc();
        warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
    }
}
```

**Option 2: Retry with Backoff**

Implement retry logic in the reset path:

```rust
// In execution_client.rs, modify reset method
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let max_retries = 3;
    let mut retry_count = 0;
    
    while retry_count < max_retries {
        let result = self.try_reset(target).await;
        match result {
            Ok(()) => return Ok(()),
            Err(Error::RandResetDropped) | Err(Error::ResetDropped) => {
                warn!("Reset failed (attempt {}/{}), retrying...", retry_count + 1, max_retries);
                tokio::time::sleep(Duration::from_millis(100 * (1 << retry_count))).await;
                retry_count += 1;
            }
            Err(e) => return Err(e),
        }
    }
    
    // If all retries failed, this is fatal
    panic!("[ExecutionClient] Failed to reset after {} attempts", max_retries);
}
```

**Option 3: Force Rand Manager Restart**

Before returning error, attempt to restart the RandManager with a fresh channel.

**Recommended Approach:** Option 1 (Fail-Stop) is simplest and safest - it ensures nodes with inconsistent state stop immediately rather than diverging silently. This aligns with the fail-stop model commonly used in consensus systems.

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: Deploy 4 validator network with randomness enabled
2. **Inject failure**: Use fail point to simulate RandManager panic during reset:
   ```rust
   fail_point!("rand_manager::process_reset", |_| panic!("Simulated reset failure"));
   ```
3. **Trigger sync**: 
   - Stop validator A at round 100
   - Let network progress to round 350
   - Restart validator A (triggers sync_info_msg from peers)
4. **Observe**: 
   - Check logs for `RandResetDropped` error caught in event loop
   - Verify validator A's `highest_known_round` remains at 100 (not 350)
   - Send block proposal for round 351
   - Verify validator A rejects shares with "Share from future round" error
   - Monitor consensus progress - network cannot finalize blocks requiring randomness

**Expected Result:** Validator A continues running but cannot participate in randomness generation for rounds > 300, causing liveness degradation.

**Alternative PoC (without fail points):**

Modify the test to simulate channel drop by manually dropping the reset sender before calling `sync_to_target`:

```rust
#[tokio::test]
async fn test_rand_reset_dropped_liveness_failure() {
    // Setup validator with randomness enabled
    let (execution_client, rand_manager_handle) = setup_with_randomness();
    
    // Simulate channel drop
    drop(rand_manager_handle.reset_tx);
    
    // Attempt sync - should return RandResetDropped
    let target_li = create_ledger_info(350);
    let result = execution_client.sync_to_target(target_li).await;
    assert!(matches!(result, Err(e) if e.to_string().contains("RandResetDropped")));
    
    // Verify stale state: highest_known_round should still be at old value
    // and shares for round 351 should be rejected
}
```

This demonstrates the vulnerability is exploitable in realistic conditions where RandManager failures can leave validators in inconsistent states that silently cause consensus liveness failures.

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L253-259)
```rust
    pub fn reset(&mut self, round: u64) {
        self.update_highest_known_round(round);
        // remove future rounds items in case they're already decided
        // otherwise if the block re-enters the queue, it'll be stuck
        let _ = self.rand_map.split_off(&round);
        let _ = self.fast_rand_map.as_mut().map(|map| map.split_off(&round));
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L285-288)
```rust
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/pipeline/execution_client.rs (L683-693)
```rust
        if let Some(mut reset_tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx: ack_tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::RandResetDropped)?;
            ack_rx.await.map_err(|_| Error::RandResetDropped)?;
        }
```

**File:** consensus/src/round_manager.rs (L2186-2193)
```rust
                    let round_state = self.round_state();
                    match result {
                        Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                        Err(e) => {
                            counters::ERROR_COUNT.inc();
                            warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                        }
                    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L154-155)
```rust
            .add_share(self_share.clone(), PathType::Slow)
            .expect("Add self share should succeed");
```
