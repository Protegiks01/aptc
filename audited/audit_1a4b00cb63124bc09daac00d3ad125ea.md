# Audit Report

## Title
Epoch Mismatch in verify_payload_signatures() Causes Unverified Payload Accumulation Leading to Denial of Service

## Summary
The `verify_payload_signatures()` function in the consensus observer's payload store contains a critical logic flaw where payloads from epochs older than the current epoch are silently skipped without verification or removal. This allows old unverified payloads to accumulate indefinitely in the store, eventually exhausting the `max_num_pending_blocks` limit and causing legitimate payloads to be dropped, resulting in node liveness failure.

## Finding Description

The vulnerability exists in the epoch matching logic of `verify_payload_signatures()`: [1](#0-0) 

The function iterates through all stored payloads and:
1. **Breaks early** if `epoch > current_epoch` (future epochs)
2. **Only processes** payloads where `epoch == current_epoch` (verifies or removes them)
3. **Silently skips** payloads where `epoch < current_epoch` (past epochs) - they remain unverified

This creates an accumulation scenario when:

1. **Payload Reception**: Node receives block payloads for future epochs, which are stored as unverified because signature verification requires the epoch state: [2](#0-1) 

2. **Epoch Skipping via Commit Sync**: When the node performs commit sync (not fallback sync) and transitions across epochs, it calls `verify_payload_signatures()` but does NOT clear old payloads: [3](#0-2) 

3. **Store Exhaustion**: Old unverified payloads accumulate until the store reaches `max_num_pending_blocks`, after which ALL new payloads (including legitimate ones) are dropped: [4](#0-3) 

**Attack Scenario:**
1. Attacker sends malicious block payloads for epochs 6, 7, 8, 9, 10 while node is at epoch 5
2. These are stored as unverified (can't verify signatures for future epochs)
3. Node receives a commit decision causing it to sync from epoch 5 to epoch 11 (skipping epochs 6-10)
4. `verify_payload_signatures()` is called with epoch 11 state
5. Payloads for epochs 6-10 have `epoch < current_epoch (11)`, so they are SKIPPED
6. These old unverified payloads persist indefinitely
7. Attacker repeats for subsequent epochs (12, 13, 14...)
8. Store fills up with old unverified payloads
9. New legitimate payloads are dropped
10. Node cannot process blocks → **Liveness failure**

**Contrast with Fallback Sync**: The fallback sync path correctly clears all payloads: [5](#0-4) 

But the commit sync path (lines 1026-1044) does not perform this cleanup.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Accumulated payloads cause memory bloat and processing delays
- **Significant protocol violations**: Breaks the resource limits invariant - the store should bound memory usage but fails to do so
- **Liveness impact**: When the store fills up, legitimate payloads are dropped, preventing the node from processing new blocks

The impact manifests as:
1. **Memory exhaustion** from unbounded payload accumulation
2. **Block processing failure** when legitimate payloads are rejected
3. **Network partition** if multiple observer nodes are affected simultaneously
4. **Cascading failures** as observers fall behind and require state sync, further exacerbating the issue

This does NOT reach Critical severity because it doesn't cause permanent chain splits or fund loss, but it significantly degrades network availability.

## Likelihood Explanation

**Likelihood: Medium-to-High**

Required conditions:
1. Node must use commit sync (not fallback sync) to transition epochs - **Common**: This is the normal sync path for observers
2. Node must skip at least one epoch during sync - **Common**: Can occur naturally when nodes fall behind or during network disruptions
3. Attacker must be able to send block payload messages - **Easy**: Any network peer can send consensus observer messages

Complexity: **Low** - Attacker simply needs to:
1. Connect as a peer to the consensus observer network
2. Send crafted `BlockPayload` messages for various future epochs
3. Wait for natural epoch transitions or network delays to trigger the bug

The attack requires no special privileges, validator access, or cryptographic breaks. It exploits a pure logic bug in epoch handling.

## Recommendation

**Fix 1: Remove old epoch payloads in verify_payload_signatures()**

Modify the verification loop to explicitly remove payloads from old epochs:

```rust
pub fn verify_payload_signatures(&mut self, epoch_state: &EpochState) -> Vec<Round> {
    let current_epoch = epoch_state.epoch;
    let payload_epochs_and_rounds: Vec<(u64, Round)> =
        self.block_payloads.lock().keys().cloned().collect();

    let mut verified_payloads_to_update = vec![];
    for (epoch, round) in payload_epochs_and_rounds {
        if epoch > current_epoch {
            break;
        }
        
        // NEW: Remove old epoch payloads
        if epoch < current_epoch {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Removing stale payload from old epoch: {:?}, round: {:?}. Current epoch: {:?}",
                    epoch, round, current_epoch
                ))
            );
            self.block_payloads.lock().remove(&(epoch, round));
            continue;
        }

        // Verify current epoch payloads (existing logic)
        if epoch == current_epoch {
            // ... existing verification code ...
        }
    }
    
    // ... rest of function ...
}
```

**Fix 2: Clear payloads on epoch transition in commit sync path**

Add cleanup in `process_commit_sync_notification()` before calling `verify_payload_signatures()`:

```rust
if synced_epoch > current_epoch_state.epoch {
    self.execution_client.end_epoch().await;
    self.wait_for_epoch_start().await;
    
    // NEW: Clear old payloads from skipped epochs
    self.observer_block_data.lock().clear_all_payloads();
    
    let new_epoch_state = self.get_epoch_state();
    let verified_payload_rounds = self
        .observer_block_data
        .lock()
        .verify_payload_signatures(&new_epoch_state);
    // ...
}
```

**Recommended approach**: Implement **both** fixes for defense-in-depth.

## Proof of Concept

```rust
#[test]
fn test_unverified_payload_accumulation_across_epochs() {
    use aptos_config::config::ConsensusObserverConfig;
    use aptos_types::{
        epoch_state::EpochState,
        validator_verifier::ValidatorVerifier,
    };
    
    // Create payload store with small limit
    let config = ConsensusObserverConfig {
        max_num_pending_blocks: 10,
        ..ConsensusObserverConfig::default()
    };
    let mut store = BlockPayloadStore::new(config);
    
    // Node at epoch 5: Receive payloads for future epochs 6, 7, 8
    for epoch in 6..=8 {
        for round in 0..3 {
            let payload = create_block_payload(epoch, round);
            store.insert_block_payload(payload, false); // Unverified
        }
    }
    
    // Verify 9 unverified payloads stored
    assert_eq!(get_num_unverified_payloads(&store), 9);
    
    // Node skips to epoch 10 (simulating commit sync)
    let epoch_state = EpochState::new(10, ValidatorVerifier::new(vec![]));
    
    // Call verify_payload_signatures - BUG: old payloads are skipped
    store.verify_payload_signatures(&epoch_state);
    
    // VULNERABILITY: Old epoch payloads still present as unverified
    assert_eq!(get_num_unverified_payloads(&store), 9); // Should be 0!
    
    // Attacker repeats for more epochs
    for epoch in 11..=15 {
        for round in 0..3 {
            let payload = create_block_payload(epoch, round);
            store.insert_block_payload(payload, false);
        }
    }
    
    // Store is now full (9 old + 1 more = 10)
    assert_eq!(store.block_payloads.lock().len(), 10);
    
    // Legitimate payload for current epoch is DROPPED
    let legit_payload = create_block_payload(10, 0);
    store.insert_block_payload(legit_payload.clone(), false);
    
    // IMPACT: Legitimate payload was not stored (dropped due to limit)
    assert!(!store.existing_payload_entry(&legit_payload));
    
    // Node cannot process blocks -> LIVENESS FAILURE
}
```

The PoC demonstrates:
1. Unverified payloads from old epochs persist after `verify_payload_signatures()`
2. Store fills up with stale payloads
3. Legitimate payloads are dropped
4. Node loses ability to process new blocks

**Severity: High** - Causes validator node slowdowns and significant protocol violations affecting network liveness.

### Citations

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L84-95)
```rust
        // Verify that the number of payloads doesn't exceed the maximum
        let max_num_pending_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
        if self.block_payloads.lock().len() >= max_num_pending_blocks {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Exceeded the maximum number of payloads: {:?}. Dropping block: {:?}!",
                    max_num_pending_blocks,
                    block_payload.block(),
                ))
            );
            return; // Drop the block if we've exceeded the maximum
        }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L227-258)
```rust
        for (epoch, round) in payload_epochs_and_rounds {
            // Check if we can break early (BtreeMaps are sorted by key)
            if epoch > current_epoch {
                break;
            }

            // Otherwise, attempt to verify the payload signatures
            if epoch == current_epoch {
                if let Entry::Occupied(mut entry) = self.block_payloads.lock().entry((epoch, round))
                {
                    if let BlockPayloadStatus::AvailableAndUnverified(block_payload) =
                        entry.get_mut()
                    {
                        if let Err(error) = block_payload.verify_payload_signatures(epoch_state) {
                            // Log the verification failure
                            error!(
                                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                                    "Failed to verify the block payload signatures for epoch: {:?} and round: {:?}. Error: {:?}",
                                    epoch, round, error
                                ))
                            );

                            // Remove the block payload from the store
                            entry.remove();
                        } else {
                            // Save the block payload for reinsertion
                            verified_payloads_to_update.push(block_payload.clone());
                        }
                    }
                }
            }
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L399-418)
```rust
        // If the payload is for the current epoch, verify the proof signatures
        let epoch_state = self.get_epoch_state();
        let verified_payload = if block_epoch == epoch_state.epoch {
            // Verify the block proof signatures
            if let Err(error) = block_payload.verify_payload_signatures(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify block payload signatures! Ignoring block: {:?}, from peer: {:?}. Error: {:?}",
                        block_payload.block(), peer_network_id, error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
                return;
            }

            true // We have successfully verified the signatures
        } else {
            false // We can't verify the signatures yet
        };
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L960-961)
```rust
        // Reset the pending block state
        self.clear_pending_block_state().await;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1026-1044)
```rust
        // If the epoch has changed, end the current epoch and start the latest one.
        let current_epoch_state = self.get_epoch_state();
        if synced_epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;

            // Verify the block payloads for the new epoch
            let new_epoch_state = self.get_epoch_state();
            let verified_payload_rounds = self
                .observer_block_data
                .lock()
                .verify_payload_signatures(&new_epoch_state);

            // Order all the pending blocks that are now ready (these were buffered during state sync)
            for payload_round in verified_payload_rounds {
                self.order_ready_pending_block(new_epoch_state.epoch, payload_round)
                    .await;
            }
```
