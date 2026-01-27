# Audit Report

## Title
Consensus Observer Partial Validation Allows Byzantine Validators to Cause Denial of Service via Orphaned Payloads

## Summary
The consensus observer accepts and stores block payloads after cryptographic verification, but when the corresponding ordered blocks fail proof verification during later processing, the already-stored payloads are not cleaned up. This allows a Byzantine validator to fill the payload store with orphaned payloads, eventually causing denial of service by preventing legitimate blocks from being processed.

## Finding Description
The consensus observer processes incoming messages through a multi-stage validation pipeline that creates an inconsistent state when `InvalidMessageError` is returned after partial validation has already mutated the observer's state.

**Attack Flow:**

1. A Byzantine validator sends a `BlockPayload` message for block (epoch E, round R) containing valid payload digests and valid cryptographic signatures for the current epoch. [1](#0-0) 

The payload passes both `verify_payload_digests()` and `verify_payload_signatures()` checks, and is inserted into the payload store with `verified_payload = true`: [2](#0-1) 

2. The Byzantine validator then sends an `OrderedBlock` message for the same block with a **forged ordered proof** (invalid quorum certificate signatures). [3](#0-2) 

The block passes basic structural validation via `verify_ordered_blocks()` (which only checks block chaining and IDs, not cryptographic proofs).

3. Since the payload exists in the store (from step 1), the condition at line 706 evaluates to `true`, triggering immediate processing: [4](#0-3) 

4. Inside `process_ordered_block()`, the forged ordered proof fails cryptographic verification: [5](#0-4) 

The function returns early with `InvalidMessageError`, **but the payload inserted in step 1 remains in the payload store**.

5. The Byzantine validator repeats steps 1-4 for different rounds until the payload store reaches its maximum capacity (`max_num_pending_blocks`): [6](#0-5) 

6. Once the limit is reached, legitimate payloads from honest validators are **dropped**, preventing the observer from processing any new blocks.

**Root Cause:**

The vulnerability stems from non-atomic validation where state mutations (payload insertion) occur before complete validation (ordered proof verification) is finished. When later validation fails, there is no rollback mechanism to remove the already-inserted payload. [7](#0-6) 

The payload store has no cleanup logic for orphaned payloads except during state sync or subscription resets, allowing them to accumulate indefinitely.

**Invariant Violation:**

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The partial state update leaves the payload store in an inconsistent state where verified payloads exist without corresponding validated ordered blocks.

## Impact Explanation
**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty)

This vulnerability allows a single Byzantine validator to cause denial of service for consensus observer nodes:

1. **Availability Impact**: Consensus observers stop processing new blocks once their payload store is filled with orphaned payloads, effectively removing them from the network.

2. **Consensus Observer Network Disruption**: All consensus observer nodes can be simultaneously disabled by a single Byzantine validator broadcasting malicious messages, impacting network monitoring, RPC nodes, and downstream applications relying on observer data.

3. **Resource Exhaustion**: The attack consumes bounded memory (`max_num_pending_blocks` * payload_size) but the impact persists until manual intervention (subscription reset or state sync).

4. **No Recovery Without Intervention**: Unlike transient DoS attacks, this requires explicit action to recover (clearing subscriptions or triggering fallback state sync).

This qualifies as **High Severity** under "Significant protocol violations" - the consensus observer protocol's correctness assumptions are violated, requiring manual intervention to restore functionality.

## Likelihood Explanation
**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Byzantine validator in the network (< 1/3 assumption in AptosBFT)
- Ability to send consensus observer messages (inherent to validator role)
- No special cryptographic capabilities needed (honest payload signing + forged proof)

**Exploitation Complexity:**
- LOW: The attack requires only standard message construction
- No race conditions or timing dependencies
- Deterministic exploitation path
- Repeatable and scalable (can target multiple observers)

**Detection Difficulty:**
- MEDIUM: Orphaned payloads appear as normal verified payloads in metrics
- No immediate error signals until payload store is full
- Difficult to distinguish from legitimate network conditions initially

The attack is realistic because:
1. Byzantine validators are explicitly part of the AptosBFT threat model
2. Message crafting requires only basic manipulation (honest payload + forged proof)
3. The attack succeeds even if other validators are honest
4. No coordination between multiple Byzantine validators needed

## Recommendation

**Immediate Fix: Implement Payload Cleanup on Ordered Block Validation Failure**

When `verify_ordered_proof()` or `verify_payloads_against_ordered_block()` fails in `process_ordered_block()`, remove the corresponding payloads from the payload store:

```rust
async fn process_ordered_block(
    &mut self,
    pending_block_with_metadata: Arc<PendingBlockWithMetadata>,
) {
    // ... existing code ...
    
    // Verify the ordered block proof
    let epoch_state = self.get_epoch_state();
    if ordered_block.proof_block_info().epoch() == epoch_state.epoch {
        if let Err(error) = ordered_block.verify_ordered_proof(&epoch_state) {
            error!(/* ... existing error logging ... */);
            
            // NEW: Clean up payloads for blocks with invalid proofs
            for block in ordered_block.blocks() {
                self.observer_block_data
                    .lock()
                    .remove_payload_for_block(block.epoch(), block.round());
            }
            
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }
    }
    
    // Verify the block payloads against the ordered block
    if let Err(error) = self
        .observer_block_data
        .lock()
        .verify_payloads_against_ordered_block(&ordered_block)
    {
        error!(/* ... existing error logging ... */);
        
        // NEW: Clean up payloads on verification failure
        for block in ordered_block.blocks() {
            self.observer_block_data
                .lock()
                .remove_payload_for_block(block.epoch(), block.round());
        }
        
        increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
        return;
    }
    
    // ... rest of function ...
}
```

Add the helper method to `BlockPayloadStore`:

```rust
/// Removes a specific payload from the store
pub fn remove_payload_for_block(&mut self, epoch: u64, round: Round) {
    self.block_payloads.lock().remove(&(epoch, round));
}
```

**Additional Hardening:**

1. **Rate Limiting**: Implement per-peer limits on invalid ordered proofs to detect and throttle Byzantine validators
2. **Payload Expiration**: Add TTL to payloads, auto-removing them if no corresponding ordered block arrives within a timeout
3. **Metrics & Monitoring**: Track orphaned payload count and alert when it exceeds thresholds

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    
    #[tokio::test]
    async fn test_orphaned_payload_dos_attack() {
        // Setup consensus observer with small max_num_pending_blocks for testing
        let config = ConsensusObserverConfig {
            max_num_pending_blocks: 10,
            ..Default::default()
        };
        
        let mut observer = create_test_observer(config);
        let byzantine_peer = PeerNetworkId::random();
        
        // Attack: Send valid payloads followed by ordered blocks with invalid proofs
        for round in 0..10 {
            // Step 1: Send valid BlockPayload
            let block_payload = create_valid_block_payload(
                current_epoch,
                round,
                valid_transactions(),
                valid_proofs(),
            );
            
            observer.process_block_payload_message(
                byzantine_peer,
                Instant::now(),
                block_payload.clone(),
            ).await;
            
            // Verify payload was inserted
            assert!(observer.observer_block_data
                .lock()
                .existing_payload_entry(&block_payload));
            
            // Step 2: Send OrderedBlock with FORGED proof
            let ordered_block = create_ordered_block_with_forged_proof(
                current_epoch,
                round,
                forged_ledger_info(), // Invalid signatures
            );
            
            observer.process_ordered_block_message(
                byzantine_peer,
                Instant::now(),
                ordered_block,
            ).await;
            
            // VULNERABILITY: Payload remains in store despite proof verification failure
            assert!(observer.observer_block_data
                .lock()
                .existing_payload_entry(&block_payload));
        }
        
        // Payload store is now full with orphaned payloads
        assert_eq!(
            observer.observer_block_data.lock()
                .get_block_payloads().lock().len(),
            10
        );
        
        // Step 3: Legitimate payload from honest validator gets DROPPED
        let legitimate_payload = create_valid_block_payload(
            current_epoch,
            11, // New round
            valid_transactions(),
            valid_proofs(),
        );
        
        observer.process_block_payload_message(
            honest_validator_peer,
            Instant::now(),
            legitimate_payload.clone(),
        ).await;
        
        // VULNERABILITY IMPACT: Legitimate payload was dropped due to full store
        assert!(!observer.observer_block_data
            .lock()
            .existing_payload_entry(&legitimate_payload));
        
        // Observer is now unable to process new blocks - DoS achieved
    }
}
```

**Notes:**

This vulnerability requires the attacker to be a Byzantine validator (or compromise the subscription mechanism), which is within the AptosBFT < 1/3 Byzantine fault tolerance model. The consensus observer should correctly handle malicious messages from Byzantine validators without entering inconsistent states. The atomic state update principle must be enforced: either both payload insertion and ordered block validation succeed, or both must be rolled back.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L385-418)
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L428-430)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L704-713)
```rust
        // If all payloads exist, process the block. Otherwise, store it
        // in the pending block store and wait for the payloads to arrive.
        if self.all_payloads_exist(pending_block_with_metadata.ordered_block().blocks()) {
            self.process_ordered_block(pending_block_with_metadata)
                .await;
        } else {
            self.observer_block_data
                .lock()
                .insert_pending_block(pending_block_with_metadata);
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L728-742)
```rust
        let epoch_state = self.get_epoch_state();
        if ordered_block.proof_block_info().epoch() == epoch_state.epoch {
            if let Err(error) = ordered_block.verify_ordered_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify ordered proof! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        ordered_block.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
                return;
            }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L78-109)
```rust
    /// Inserts the given block payload data into the payload store
    pub fn insert_block_payload(
        &mut self,
        block_payload: BlockPayload,
        verified_payload_signatures: bool,
    ) {
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

        // Create the new payload status
        let epoch_and_round = (block_payload.epoch(), block_payload.round());
        let payload_status = if verified_payload_signatures {
            BlockPayloadStatus::AvailableAndVerified(block_payload)
        } else {
            BlockPayloadStatus::AvailableAndUnverified(block_payload)
        };

        // Insert the new payload status
        self.block_payloads
            .lock()
            .insert(epoch_and_round, payload_status);
    }
```
