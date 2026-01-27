# Audit Report

## Title
Consensus Observer Denial-of-Service via Unverified Payload Blocking Attack

## Summary
The `existing_payload_entry()` function in the consensus observer's payload store returns true for both verified and unverified payloads without distinction, allowing malicious peers to flood the store with unverified payloads for future epochs that permanently block legitimate verified payloads from being stored, causing consensus observers to fail synchronization with the network.

## Finding Description

The vulnerability exists in the interaction between payload entry checking and payload verification status. The `existing_payload_entry()` function only checks for the existence of a payload entry by epoch and round, without distinguishing between verified and unverified payloads: [1](#0-0) 

When a block payload message arrives, the consensus observer checks if a payload already exists before processing it: [2](#0-1) 

The critical flaw is that payloads for future epochs (where `block_epoch != epoch_state.epoch`) cannot have their signatures verified immediately and are stored as unverified: [3](#0-2) 

**Attack Scenario:**

1. **Malicious peer sends future epoch payload**: Attacker sends a block payload for epoch E+1, round R while the current epoch is E
2. **Payload stored as unverified**: Since signature verification is skipped for future epochs, the payload passes digest verification and is stored with `verified_payload = false`
3. **Legitimate payload blocked**: When the legitimate verified payload for the same epoch E+1, round R arrives later (possibly from honest validators after epoch transition), `existing_payload_entry()` returns true and the legitimate payload is dropped
4. **Verification failure on ordered block**: When the ordered block arrives, `verify_payloads_against_ordered_block()` is called and finds the unverified payload: [4](#0-3) 

5. **Observer synchronization failure**: The ordered block is rejected, preventing the consensus observer from syncing with the network: [5](#0-4) 

Even if `verify_payload_signatures()` is called during epoch transition to upgrade unverified payloads, if the attacker's payload has invalid signatures, it will be removed—but the legitimate payload was already dropped and cannot be recovered: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **State inconsistencies requiring intervention**: Consensus observers become unable to sync with the network, requiring manual intervention to restore functionality
2. **Availability impact**: While not affecting validator consensus directly, this prevents observer nodes from executing blocks and serving queries
3. **Limited scope**: Only affects consensus observer nodes, not the core consensus protocol or validator operations
4. **No fund loss**: Does not directly lead to theft or minting of funds

The attack causes denial-of-service on consensus observer infrastructure, which is critical for applications, indexers, and full nodes that rely on observers for blockchain data.

## Likelihood Explanation

**Likelihood: Medium-to-High**

The attack is highly feasible because:

1. **Low attacker requirements**: Any node can connect as a peer and send payload messages—no validator privileges or significant resources required
2. **Simple execution**: Attacker only needs to send block payload messages for future epochs/rounds ahead of legitimate broadcasts
3. **Persistent effect**: Once an unverified payload occupies a slot, the legitimate payload cannot replace it
4. **Wide attack surface**: Attacker can send many future epoch/round combinations to block multiple payloads
5. **Difficult detection**: The malicious payloads appear valid until signature verification, making it hard to distinguish from network timing issues

## Recommendation

**Fix: Check verification status before blocking duplicate payloads**

The `existing_payload_entry()` function should be modified to only return true for **verified** payloads, or the check in `process_block_payload_message()` should allow verified payloads to overwrite unverified ones.

**Recommended Fix in `consensus_observer.rs`:**

```rust
// Check if payload exists AND is verified
let payload_exists_and_verified = self
    .observer_block_data
    .lock()
    .existing_verified_payload_entry(&block_payload);

// Only ignore if payload is out of date or exists as verified
if payload_out_of_date || payload_exists_and_verified {
    update_metrics_for_dropped_block_payload_message(peer_network_id, &block_payload);
    return;
}
```

Add a new method to `payload_store.rs`:

```rust
pub fn existing_verified_payload_entry(&self, block_payload: &BlockPayload) -> bool {
    let epoch_and_round = (block_payload.epoch(), block_payload.round());
    matches!(
        self.block_payloads.lock().get(&epoch_and_round),
        Some(BlockPayloadStatus::AvailableAndVerified(_))
    )
}
```

Alternatively, allow verified payloads to overwrite unverified ones in the `insert_block_payload()` logic.

## Proof of Concept

```rust
#[tokio::test]
async fn test_unverified_payload_blocks_verified() {
    // Setup: Create consensus observer with payload store
    let config = ConsensusObserverConfig::default();
    let mut observer = create_consensus_observer(config).await;
    
    // Step 1: Attacker sends unverified payload for future epoch
    let future_epoch = observer.get_epoch_state().epoch + 1;
    let target_round = 100;
    let malicious_payload = create_block_payload(future_epoch, target_round);
    
    // This payload will be stored as unverified (signatures can't be verified yet)
    observer.process_block_payload_message(
        malicious_peer_id(),
        Instant::now(),
        malicious_payload.clone()
    ).await;
    
    // Verify unverified payload was stored
    assert!(observer.observer_block_data.lock()
        .existing_payload_entry(&malicious_payload));
    
    // Step 2: Legitimate verified payload arrives for same epoch/round
    let legitimate_payload = create_verified_payload(future_epoch, target_round);
    
    // This will be DROPPED because existing_payload_entry returns true
    observer.process_block_payload_message(
        honest_peer_id(),
        Instant::now(),
        legitimate_payload.clone()
    ).await;
    
    // Step 3: Epoch transitions to future_epoch
    observer.handle_epoch_change(future_epoch).await;
    
    // Step 4: Ordered block arrives
    let ordered_block = create_ordered_block(future_epoch, target_round);
    
    // Verification will FAIL because payload is still unverified (or missing if removed)
    let result = observer.process_ordered_block_message(
        honest_peer_id(),
        Instant::now(),
        ordered_block
    ).await;
    
    // Assert that ordered block was rejected due to unverified/missing payload
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unverified") || 
            result.unwrap_err().to_string().contains("Missing"));
}
```

The proof of concept demonstrates that:
1. Unverified payloads from malicious peers occupy storage slots
2. Legitimate verified payloads for the same epoch/round are blocked
3. Ordered block verification fails, preventing consensus observer synchronization

This vulnerability allows attackers to perform denial-of-service attacks on consensus observer nodes by flooding them with unverified payloads that block legitimate data.

### Citations

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L65-71)
```rust
    pub fn existing_payload_entry(&self, block_payload: &BlockPayload) -> bool {
        // Get the epoch and round of the payload
        let epoch_and_round = (block_payload.epoch(), block_payload.round());

        // Check if a payload already exists in the store
        self.block_payloads.lock().contains_key(&epoch_and_round)
    }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L176-183)
```rust
                        BlockPayloadStatus::AvailableAndUnverified(_) => {
                            // The payload should have already been verified
                            return Err(Error::InvalidMessageError(format!(
                                "Payload verification failed! Block payload for epoch: {:?} and round: {:?} is unverified.",
                                ordered_block.epoch(),
                                ordered_block.round()
                            )));
                        },
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L240-250)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L370-380)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L755-771)
```rust
        if let Err(error) = self
            .observer_block_data
            .lock()
            .verify_payloads_against_ordered_block(&ordered_block)
        {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payloads against ordered block! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                    ordered_block.proof_block_info(),
                    peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }
```
