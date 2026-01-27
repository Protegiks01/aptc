# Audit Report

## Title
Future Epoch Payload Accumulation Causes Consensus Observer Liveness Failure

## Summary
The `remove_blocks_for_epoch_round()` function in the consensus observer's payload store fails to clean up payloads from future epochs. An attacker can exploit this by flooding a consensus observer node with block payloads for arbitrarily high future epochs, causing these payloads to persist indefinitely. Once the maximum payload limit is reached, the node can no longer store valid payloads for the current epoch, resulting in consensus participation failure. [1](#0-0) 

## Finding Description

The vulnerability exists in the `remove_blocks_for_epoch_round()` function, which is responsible for cleaning up old block payloads after commits. The function uses Rust's `BTreeMap::split_off()` operation to retain only payloads with keys greater than or equal to `(epoch, round+1)`. [1](#0-0) 

Due to lexicographic tuple ordering in Rust, when comparing `(epoch_payload, round_payload)` with `(epoch_committed, round_committed)`, payloads from **future epochs** (where `epoch_payload > epoch_committed`) will always be considered greater than the split point and will be **retained** rather than removed.

**Attack Vector:**

1. When a consensus observer node receives a block payload message, it performs validation checks before storing: [2](#0-1) 

2. The out-of-date check only filters payloads where `(block_epoch, block_round) <= (last_ordered_block.epoch, last_ordered_block.round)`. Payloads for **future epochs** pass this check.

3. Digest verification is structural only and doesn't prevent future epoch payloads: [3](#0-2) 

4. Future epoch payloads are stored as unverified since signature verification cannot be performed for epochs that haven't started yet: [4](#0-3) 

5. When `verify_payload_signatures()` is called during epoch transitions, it only processes payloads for the **current epoch** and breaks when encountering future epochs, leaving them in the store: [5](#0-4) 

6. The insertion logic enforces a maximum limit, and once reached, **new valid payloads are dropped**: [6](#0-5) 

**Exploitation Steps:**

1. Attacker identifies consensus observer nodes (publicly advertised via network discovery)
2. Attacker crafts block payloads with structurally valid data but for extremely high future epochs (e.g., epoch 999999)
3. Attacker floods the victim node with these payloads until `max_num_pending_blocks` is reached
4. Victim node can no longer store new valid payloads for the current epoch
5. Victim node fails to participate in consensus, losing synchronization with the network

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

- **Validator node liveness failure**: The affected consensus observer node cannot participate in consensus once its payload store is filled with future epoch payloads
- **State inconsistencies requiring intervention**: Manual intervention (node restart, payload store clearing) is required to recover
- **DoS on critical infrastructure**: Consensus observers are essential for blockchain operation, and their failure impacts network decentralization

The attack does not cause:
- Direct fund loss (no theft or minting)
- Network-wide consensus safety violations (affects individual nodes, not the protocol)
- Permanent network partition (recoverable with intervention)

Therefore, this is classified as **High Severity** rather than Critical.

## Likelihood Explanation

**High Likelihood:**

- **Low attack complexity**: Attacker only needs to send valid-structured block payload messages with future epoch numbers
- **No privileged access required**: Any network peer can send block payload messages to consensus observer nodes
- **Publicly known targets**: Consensus observer nodes advertise their presence in the network
- **Persistent impact**: Once the payload store is filled, the node remains unusable until manual intervention
- **No rate limiting visible**: No epoch-based rate limiting or future epoch rejection in the validation path

The main constraint is that the attacker must send `max_num_pending_blocks` messages (default appears to be in the hundreds to thousands range), but this is trivially achievable with automated scripting.

## Recommendation

Implement epoch-based bounds checking when receiving block payloads. Reject payloads that are too far in the future:

```rust
// In consensus_observer.rs, process_block_payload_message():

// Add validation after line 364:
let epoch_state = self.get_epoch_state();
let current_epoch = epoch_state.epoch;

// Reject payloads from too far in the future
const MAX_FUTURE_EPOCH_TOLERANCE: u64 = 2;
if block_epoch > current_epoch + MAX_FUTURE_EPOCH_TOLERANCE {
    warn!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Rejecting block payload from too far future epoch: {:?}, current: {:?}",
            block_epoch, current_epoch
        ))
    );
    increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
    return;
}
```

Additionally, improve the cleanup logic in `remove_blocks_for_epoch_round()` to explicitly remove future epoch payloads:

```rust
// In payload_store.rs, remove_blocks_for_epoch_round():

pub fn remove_blocks_for_epoch_round(&self, epoch: u64, round: Round) {
    let split_off_round = round.saturating_add(1);
    let mut block_payloads = self.block_payloads.lock();
    
    // Keep only payloads from the current epoch that are after the committed round
    *block_payloads = block_payloads
        .split_off(&(epoch, split_off_round))
        .into_iter()
        .filter(|((payload_epoch, _), _)| *payload_epoch == epoch)
        .collect();
}
```

## Proof of Concept

```rust
#[test]
fn test_future_epoch_payload_accumulation_vulnerability() {
    use crate::consensus_observer::observer::payload_store::BlockPayloadStore;
    use crate::consensus_observer::network::observer_message::BlockPayload;
    use aptos_config::config::ConsensusObserverConfig;
    use aptos_types::block_info::BlockInfo;
    
    // Create payload store with low limit for testing
    let max_num_pending_blocks = 10;
    let consensus_observer_config = ConsensusObserverConfig {
        max_num_pending_blocks,
        ..ConsensusObserverConfig::default()
    };
    let mut payload_store = BlockPayloadStore::new(consensus_observer_config);
    
    // Attacker floods with future epoch payloads
    for i in 0..max_num_pending_blocks {
        let future_epoch = 999999;
        let block_info = BlockInfo::random_with_epoch(future_epoch, i as u64);
        let block_payload = BlockPayload::new(
            block_info,
            crate::consensus_observer::network::observer_message::BlockTransactionPayload::empty()
        );
        payload_store.insert_block_payload(block_payload, false);
    }
    
    // Verify store is full of future epoch payloads
    assert_eq!(payload_store.get_block_payloads().lock().len(), max_num_pending_blocks as usize);
    
    // Simulate epoch progression and commits (epoch 5 -> epoch 6)
    payload_store.remove_blocks_for_epoch_round(5, 100);
    payload_store.remove_blocks_for_epoch_round(6, 50);
    
    // BUG: Future epoch payloads are NOT removed!
    // They persist because (999999, X) > (6, 51) in lexicographic ordering
    assert_eq!(
        payload_store.get_block_payloads().lock().len(), 
        max_num_pending_blocks as usize,
        "Future epoch payloads should have been cleaned up but persist!"
    );
    
    // Now try to insert valid current epoch payload - it will be REJECTED
    let current_epoch = 6;
    let valid_block_info = BlockInfo::random_with_epoch(current_epoch, 100);
    let valid_payload = BlockPayload::new(
        valid_block_info,
        crate::consensus_observer::network::observer_message::BlockTransactionPayload::empty()
    );
    
    let initial_count = payload_store.get_block_payloads().lock().len();
    payload_store.insert_block_payload(valid_payload, true);
    let final_count = payload_store.get_block_payloads().lock().len();
    
    // Valid payload is dropped because store is full!
    assert_eq!(
        initial_count, final_count,
        "Valid current epoch payload was rejected due to future epoch payload accumulation!"
    );
}
```

## Notes

This vulnerability specifically affects **consensus observer nodes**, not consensus validators. However, consensus observers play an important role in the Aptos network by:
- Providing transaction submission endpoints
- Enabling light clients
- Distributing consensus state
- Improving network decentralization

The vulnerability breaks the **Resource Limits** invariant (invariant #9) by allowing unbounded accumulation of future epoch payloads, and creates a liveness failure for affected nodes.

The issue is exacerbated by the fact that there is no automatic periodic cleanup mechanism - the only cleanup function `clear_all_payloads()` is only called when subscription checks fail, not as part of normal epoch transitions. [7](#0-6)

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

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L112-119)
```rust
    pub fn remove_blocks_for_epoch_round(&self, epoch: u64, round: Round) {
        // Determine the round to split off
        let split_off_round = round.saturating_add(1);

        // Remove the blocks from the payload store
        let mut block_payloads = self.block_payloads.lock();
        *block_payloads = block_payloads.split_off(&(epoch, split_off_round));
    }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L227-231)
```rust
        for (epoch, round) in payload_epochs_and_rounds {
            // Check if we can break early (BtreeMaps are sorted by key)
            if epoch > current_epoch {
                break;
            }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L216-230)
```rust
    /// Clears the pending block state (this is useful for changing
    /// subscriptions, where we want to wipe all state and restart).
    async fn clear_pending_block_state(&self) {
        // Clear the observer block data
        let root = self.observer_block_data.lock().clear_block_data();

        // Reset the execution pipeline for the root
        if let Err(error) = self.execution_client.reset(&root).await {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to reset the execution pipeline for the root! Error: {:?}",
                    error
                ))
            );
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L366-380)
```rust
        // Determine if the payload is behind the last ordered block, or if it already exists
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        let payload_out_of_date =
            (block_epoch, block_round) <= (last_ordered_block.epoch(), last_ordered_block.round());
        let payload_exists = self
            .observer_block_data
            .lock()
            .existing_payload_entry(&block_payload);

        // If the payload is out of date or already exists, ignore it
        if payload_out_of_date || payload_exists {
            // Update the metrics for the dropped block payload
            update_metrics_for_dropped_block_payload_message(peer_network_id, &block_payload);
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L385-397)
```rust
        // Verify the block payload digests
        if let Err(error) = block_payload.verify_payload_digests() {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payload digests! Ignoring block: {:?}, from peer: {:?}. Error: {:?}",
                    block_payload.block(), peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
            return;
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
