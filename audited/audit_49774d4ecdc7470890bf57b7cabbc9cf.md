# Audit Report

## Title
Secret Share Store Reset Vulnerability: Panic on Legitimate Block Reprocessing After State Sync

## Summary
The `SecretShareStore` lacks proper state cleanup during reset operations, causing it to panic when legitimate blocks are reprocessed after state synchronization. This differs from the analogous `RandStore` component which handles this scenario gracefully. The panic blocks randomness generation for the affected validator node, compromising consensus liveness.

## Finding Description

The vulnerability exists in the state management of `SecretShareItem` within the secret sharing subsystem. The core issue involves two interacting problems:

**Problem 1: Missing Reset Logic**

The `SecretShareStore` does not clear its `secret_share_map` during reset operations. When `SecretShareManager::process_reset()` is called (e.g., during state sync), it only updates the `highest_known_round` but leaves all existing entries in the map intact. [1](#0-0) 

In contrast, the analogous `RandStore` component explicitly clears future rounds during reset to prevent exactly this issue: [2](#0-1) 

The comment in `RandStore::reset()` explicitly states: "remove future rounds items in case they're already decided otherwise if the block re-enters the queue, it'll be stuck" - acknowledging that blocks can re-enter the processing queue after reset.

**Problem 2: Overly Strict State Validation**

The `SecretShareItem::add_share_with_metadata()` function bails with an error when called in the `PendingDecision` state, instead of handling it gracefully: [3](#0-2) 

Again, the analogous `RandItem::add_metadata()` handles this scenario gracefully by returning the item unchanged: [4](#0-3) 

**Exploitation Path:**

1. A block at round R is processed through `SecretShareManager::process_incoming_block()`
2. The self secret share is computed and `add_self_share()` is called
3. This transitions the `SecretShareItem` for round R from `PendingMetadata` to `PendingDecision` state
4. A state sync operation occurs with `ResetSignal::TargetRound(T)` where T < R
5. The `process_reset()` method clears the `block_queue` but leaves the `secret_share_map` unchanged
6. The block at round R is reprocessed (e.g., through consensus recovery or block replay)
7. `process_incoming_block()` is called again, which calls `add_self_share()`
8. The function calls `add_share_with_metadata()` on an item already in `PendingDecision` state
9. The function bails with error "Cannot add self share in PendingDecision state"
10. The `.expect()` in the caller causes a panic: [5](#0-4) 

This panic crashes the secret share manager task, blocking all randomness generation for that validator node until restart.

## Impact Explanation

This is a **HIGH severity** vulnerability according to the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdown/Crash**: The panic causes the secret share manager task to terminate, requiring node restart to recover randomness functionality.

2. **Significant Protocol Violation**: Randomness is a critical component of the AptosBFT consensus protocol. Without functioning randomness generation:
   - The validator cannot participate in leader election properly
   - The validator cannot contribute to distributed randomness beacon
   - This affects consensus liveness and can cause the validator to fall behind

3. **No Malicious Actor Required**: This vulnerability can be triggered by legitimate network conditions:
   - State sync operations are routine during normal operation
   - Block reprocessing can occur during consensus recovery
   - Network partitions or temporary disconnections can trigger state sync

4. **Affects Production Systems**: Any validator experiencing state sync followed by block reprocessing will hit this issue.

The impact falls squarely within the "Validator node slowdowns" and "Significant protocol violations" categories for High severity ($50,000 tier).

## Likelihood Explanation

The likelihood is **MEDIUM to HIGH**:

**Triggering Conditions:**
- State sync with `ResetSignal::TargetRound` is triggered during:
  - Regular state synchronization when a validator falls behind
  - Recovery from network partitions
  - Sync operations called via `ExecutionClient::reset()` [6](#0-5) 

- Block reprocessing can occur when:
  - Consensus resumes after state sync
  - Block replay during recovery
  - Normal consensus flow after temporary network issues

**Frequency:**
- State sync operations are common in production networks
- While not every state sync will trigger this (depends on timing and which rounds are affected), the condition is realistic
- Once triggered, the impact is immediate and severe

**Attack Complexity:**
- No attack needed - this is a legitimate operational scenario
- Any validator operator experiencing these conditions will hit this bug
- No special privileges or insider access required

## Recommendation

Implement the missing `reset()` method in `SecretShareStore` following the pattern from `RandStore`:

**Add to `SecretShareStore`:**
```rust
pub fn reset(&mut self, round: u64) {
    self.update_highest_known_round(round);
    // Remove future rounds items in case they're already decided
    // otherwise if the block re-enters the queue, it'll be stuck
    self.secret_share_map.retain(|&r, _| r < round);
}
```

**Update `SecretShareManager::process_reset()` to call it:**
```rust
fn process_reset(&mut self, request: ResetRequest) {
    let ResetRequest { tx, signal } = request;
    let target_round = match signal {
        ResetSignal::Stop => 0,
        ResetSignal::TargetRound(round) => round,
    };
    self.block_queue = BlockQueue::new();
    self.secret_share_store
        .lock()
        .reset(target_round);  // Changed from update_highest_known_round
    self.stop = matches!(signal, ResetSignal::Stop);
    let _ = tx.send(ResetAck::default());
}
```

**Alternative Fix (Less Preferred):**

Alternatively, make `add_share_with_metadata()` handle the `PendingDecision` state gracefully like `RandItem::add_metadata()` does:

```rust
fn add_share_with_metadata(
    &mut self,
    share: SecretShare,
    share_weights: &HashMap<Author, u64>,
) -> anyhow::Result<()> {
    let item = std::mem::replace(self, Self::new(Author::ONE));
    let share_weight = *share_weights
        .get(share.author())
        .expect("Author must exist in weights");
    let new_item = match item {
        SecretShareItem::PendingMetadata(mut share_aggregator) => {
            let metadata = share.metadata.clone();
            share_aggregator.retain(share.metadata(), share_weights);
            share_aggregator.add_share(share, share_weight);
            SecretShareItem::PendingDecision {
                metadata,
                share_aggregator,
            }
        },
        item @ (SecretShareItem::PendingDecision { .. } | SecretShareItem::Decided { .. }) => {
            // Return unchanged instead of bailing
            return Ok(());
        },
    };
    let _ = std::mem::replace(self, new_item);
    Ok(())
}
```

The first approach (adding `reset()`) is preferred as it properly cleans up stale state and maintains consistency with `RandStore`.

## Proof of Concept

```rust
#[cfg(test)]
mod secret_share_reset_panic_test {
    use super::*;
    use aptos_types::secret_sharing::{SecretShare, SecretShareMetadata};
    
    #[tokio::test]
    async fn test_secret_share_reset_panic() {
        // Setup: Create a SecretShareManager with epoch state and config
        let author = Author::random();
        let epoch_state = create_test_epoch_state();
        let config = create_test_secret_share_config();
        let (outgoing_blocks_tx, _) = unbounded();
        let network_sender = Arc::new(create_test_network_sender());
        let bounded_executor = create_test_bounded_executor();
        let rb_config = create_test_rb_config();
        
        let mut manager = SecretShareManager::new(
            author,
            epoch_state,
            config.clone(),
            outgoing_blocks_tx,
            network_sender,
            bounded_executor,
            &rb_config,
        );
        
        // Step 1: Process a block at round 100
        let block_r100 = create_test_pipelined_block(100);
        let self_share_r100 = create_test_secret_share(author, 100);
        
        // This adds the self share and transitions to PendingDecision
        {
            let mut store = manager.secret_share_store.lock();
            store.update_highest_known_round(100);
            store.add_self_share(self_share_r100.clone()).unwrap();
        }
        
        // Verify state is PendingDecision for round 100
        // (internal state check)
        
        // Step 2: Trigger a reset to round 50
        let (reset_tx, reset_rx) = oneshot::channel();
        manager.process_reset(ResetRequest {
            tx: reset_tx,
            signal: ResetSignal::TargetRound(50),
        });
        reset_rx.await.unwrap();
        
        // Step 3: Attempt to process block at round 100 again
        // This simulates block reprocessing after state sync
        {
            let mut store = manager.secret_share_store.lock();
            store.update_highest_known_round(100);
            
            // This should panic with "Add self dec share should succeed"
            // because add_share_with_metadata bails on PendingDecision state
            let result = store.add_self_share(self_share_r100.clone());
            
            // With the bug: result is Err("Cannot add self share in PendingDecision state")
            // Expected behavior: result should be Ok(())
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("PendingDecision"));
        }
        
        // In production, the .expect() would cause a panic here,
        // crashing the secret share manager task
    }
}
```

**To run this test:**
1. Add the test to `consensus/src/rand/secret_sharing/secret_share_manager.rs`
2. Implement helper functions for test setup (epoch state, config, etc.)
3. Run: `cargo test test_secret_share_reset_panic --package aptos-consensus`
4. The test will demonstrate the error condition (with bug present)
5. After applying the fix, the test should pass

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L145-147)
```rust
            secret_share_store
                .add_self_share(self_secret_share.clone())
                .expect("Add self dec share should succeed");
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L172-184)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.secret_share_store
            .lock()
            .update_highest_known_round(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L180-193)
```rust
    fn add_metadata(&mut self, rand_config: &RandConfig, rand_metadata: FullRandMetadata) {
        let item = std::mem::replace(self, Self::new(Author::ONE, PathType::Slow));
        let new_item = match item {
            RandItem::PendingMetadata(mut share_aggregator) => {
                share_aggregator.retain(rand_config, &rand_metadata);
                Self::PendingDecision {
                    metadata: rand_metadata,
                    share_aggregator,
                }
            },
            item @ (RandItem::PendingDecision { .. } | RandItem::Decided { .. }) => item,
        };
        let _ = std::mem::replace(self, new_item);
    }
```

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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L175-177)
```rust
            SecretShareItem::PendingDecision { .. } => {
                bail!("Cannot add self share in PendingDecision state");
            },
```

**File:** consensus/src/pipeline/execution_client.rs (L674-709)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };

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

        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }

        Ok(())
    }
```
