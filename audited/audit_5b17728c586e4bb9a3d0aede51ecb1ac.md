# Audit Report

## Title
Consensus Observer Block Payload Storage DoS via Orphaned Future Epoch Payloads

## Summary
The consensus observer stores block payloads for future epochs without signature verification and without cleanup when their corresponding ordered blocks fail chain verification. An attacker can exploit this to fill the payload store with orphaned payloads, causing legitimate payloads to be dropped and disrupting consensus observer operation.

## Finding Description

The consensus observer processes block payloads and ordered blocks as separate messages. A critical vulnerability exists in how future epoch payloads are handled: [1](#0-0) 

When a block payload arrives for a future epoch (epoch > current_epoch), signature verification is skipped and `verified_payload = false` is set. Despite this, the payload is unconditionally stored: [2](#0-1) 

The payload store has a hard limit with no garbage collection mechanism: [3](#0-2) 

When the limit is reached, NEW payloads are dropped rather than removing old orphaned payloads.

When ordered blocks with manipulated parent_id values arrive, they fail chain verification: [4](#0-3) 

The verification failure causes immediate rejection: [5](#0-4) 

Critically, there is NO cleanup of the previously stored payloads when ordered blocks fail verification. The payloads remain stored indefinitely until a higher epoch/round is committed.

**Attack Scenario:**
1. Malicious subscribed peer sends 150 BlockPayload messages for future epochs
2. These bypass signature verification and consume payload store slots
3. Attacker sends OrderedBlock messages with manipulated parent_id values
4. Chain verification fails, ordered blocks rejected, but payloads remain
5. Payload store reaches max_num_pending_blocks limit (150 or 300)
6. Legitimate current-epoch payloads are dropped
7. Consensus observer cannot process new blocks, causing service disruption

## Impact Explanation

This is a **High Severity** denial-of-service vulnerability according to Aptos bug bounty criteria. It causes:

- **Validator node slowdowns**: Consensus observers (typically VFNs) cannot sync properly
- **Significant protocol violations**: Breaks the assumption that honest observers can track consensus
- **Service disruption**: Affected nodes cannot serve clients or participate in state sync

While it doesn't directly cause fund loss or consensus safety violations, it disrupts the availability guarantee critical for validator fullnodes and can force nodes to fall back to expensive state sync mechanisms.

## Likelihood Explanation

This attack is **highly likely** to occur because:

1. **Low attacker requirements**: Any subscribed peer (including a single Byzantine validator within the < 1/3 threshold) can execute this
2. **Simple exploitation**: Requires only sending malformed messages, no complex timing or coordination
3. **No signature requirements**: Future epoch payloads bypass cryptographic verification
4. **Deterministic impact**: Filling 150 slots is straightforward and guaranteed to cause DoS
5. **No cleanup mechanism**: Orphaned payloads persist until manual intervention or epoch change

The consensus observer architecture assumes message integrity from subscribed peers, but doesn't defend against Byzantine behavior from individual validators.

## Recommendation

Implement comprehensive payload garbage collection and validation:

```rust
// In BlockPayloadStore::insert_block_payload
pub fn insert_block_payload(
    &mut self,
    block_payload: BlockPayload,
    verified_payload_signatures: bool,
) {
    // NEW: Reject unverified future epoch payloads that are too far ahead
    let max_num_pending_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
    
    // NEW: Add garbage collection before insertion
    self.garbage_collect_old_payloads();
    
    if self.block_payloads.lock().len() >= max_num_pending_blocks {
        warn!("Exceeded maximum payloads, dropping block: {:?}", block_payload.block());
        return;
    }
    
    // Only store payloads that are verified OR within epoch bounds
    if !verified_payload_signatures {
        // Reject payloads too far in the future (e.g., > current_epoch + 1)
        return;
    }
    
    // ... rest of insertion logic
}

// NEW: Add garbage collection method
fn garbage_collect_old_payloads(&mut self) {
    let mut block_payloads = self.block_payloads.lock();
    let max_pending = self.consensus_observer_config.max_num_pending_blocks as usize;
    
    // Remove oldest payloads when approaching limit
    while block_payloads.len() >= max_pending {
        if let Some((oldest_key, _)) = block_payloads.pop_first() {
            warn!("Garbage collecting old payload: {:?}", oldest_key);
        }
    }
}
```

Additionally, when an ordered block fails verification, clean up associated payloads:

```rust
// In process_ordered_block_message, after verification fails
if let Err(error) = ordered_block.verify_ordered_blocks() {
    // NEW: Clean up orphaned payloads
    for block in ordered_block.blocks() {
        self.observer_block_data.lock()
            .remove_block_payload(block.epoch(), block.round());
    }
    
    error!("Failed to verify ordered blocks, cleaning up payloads");
    return;
}
```

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
#[test]
fn test_payload_store_dos_attack() {
    use consensus_observer::observer::payload_store::BlockPayloadStore;
    use consensus_observer_config::ConsensusObserverConfig;
    
    let config = ConsensusObserverConfig {
        max_num_pending_blocks: 150,
        ..Default::default()
    };
    
    let mut payload_store = BlockPayloadStore::new(config);
    
    // Attacker sends 150 future epoch payloads (unverified)
    for i in 0..150 {
        let future_payload = create_block_payload(
            /* epoch */ 100, 
            /* round */ i,
            /* transactions */ vec![]
        );
        
        // These get stored without signature verification
        payload_store.insert_block_payload(future_payload, false);
    }
    
    // Now legitimate current epoch payload arrives
    let legitimate_payload = create_block_payload(
        /* epoch */ 1, 
        /* round */ 10,
        /* transactions */ vec![create_valid_transaction()]
    );
    
    // This gets DROPPED because store is full
    payload_store.insert_block_payload(legitimate_payload, true);
    
    // Verify the legitimate payload was not stored
    assert!(!payload_store.existing_payload_entry(&legitimate_payload));
    
    // Consensus observer cannot make progress
}
```

## Notes

The vulnerability stems from the asymmetry between payload storage (which accepts unverified future epoch data) and ordered block verification (which enforces chain integrity). The payload store lacks the defensive mechanisms present in the pending block store (garbage collection) and assumes all stored payloads will eventually have corresponding valid ordered blocks. This assumption is violated when Byzantine peers send crafted payloads with mismatched ordered blocks.

### Citations

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L427-430)
```rust
        // Update the payload store with the payload
        self.observer_block_data
            .lock()
            .insert_block_payload(block_payload, verified_payload);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L658-671)
```rust
        // Verify the ordered blocks before processing
        if let Err(error) = ordered_block.verify_ordered_blocks() {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify ordered blocks! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                    ordered_block.proof_block_info(),
                    peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        };
```

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

**File:** consensus/src/consensus_observer/network/observer_message.rs (L247-263)
```rust
        // Verify the blocks are correctly chained together (from the last block to the first)
        let mut expected_parent_id = None;
        for block in self.blocks.iter().rev() {
            if let Some(expected_parent_id) = expected_parent_id {
                if block.id() != expected_parent_id {
                    return Err(Error::InvalidMessageError(
                        format!(
                            "Block parent ID does not match the expected parent ID! Block ID: {:?}, Expected parent ID: {:?}",
                            block.id(),
                            expected_parent_id
                        )
                    ));
                }
            }

            expected_parent_id = Some(block.parent_id());
        }
```
