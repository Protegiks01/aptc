# Audit Report

## Title
Consensus Observer Denial of Service via Unvalidated Future Epoch BlockPayload Flooding

## Summary
The consensus observer's `process_block_payload_message` function accepts BlockPayload messages with arbitrary future epoch values without validation, bypassing signature verification. An attacker can flood the payload store with unsigned, unverified payloads, causing legitimate BlockPayload messages to be rejected and disrupting consensus observer functionality.

## Finding Description

The `BlockPayload.round()` function extracts the round number from an unvalidated `BlockInfo` structure: [1](#0-0) 

When a consensus observer receives a BlockPayload message, it performs validation in `process_block_payload_message`: [2](#0-1) 

The critical vulnerability exists in the epoch validation logic: [3](#0-2) 

**Attack Path:**

1. Attacker sends BlockPayload with `epoch = current_epoch + 100` (far future epoch) and arbitrary round values
2. The "out of date" check passes because the future epoch is greater than the current epoch
3. Digest verification passes if the attacker crafts valid transaction batch structures
4. **Signature verification is completely skipped** because `block_epoch != epoch_state.epoch` (line 401)
5. The unverified payload is stored in the payload store (line 430)

The attacker repeats this process to fill the payload store up to `max_num_pending_blocks`: [4](#0-3) 

Once the store is full, legitimate BlockPayload messages for the current epoch are silently dropped, preventing the consensus observer from functioning correctly.

**Additional Issue - Missing BlockInfo Validation:**

Even when payloads are matched with OrderedBlocks, there is no validation that the BlockInfo matches: [5](#0-4) 

The verification only checks that transaction payloads match (line 199), but never validates that `BlockPayload.block` (the BlockInfo with epoch, round, id, timestamp) corresponds to the actual block in the OrderedBlock.

## Impact Explanation

**Severity: HIGH** - This meets the Aptos bug bounty HIGH severity criteria:

1. **Validator node slowdowns**: Consensus observers fail to receive legitimate payloads, degrading performance
2. **Significant protocol violations**: The consensus observer protocol assumes payloads are validated before storage
3. **API crashes**: Observer nodes may fail when unable to retrieve expected payloads

The attack causes **denial of service** specifically targeting consensus observer nodes. While it doesn't directly compromise consensus safety or validator consensus participation, it disrupts the observer infrastructure that applications and indexers depend on for blockchain data.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack complexity**: LOW - Attacker only needs to craft BlockPayload messages with future epochs
- **Attacker requirements**: Any network peer can send consensus observer messages
- **No authentication needed**: Signature verification is bypassed for future epochs
- **Easy to execute**: Simply send `max_num_pending_blocks` worth of malicious payloads
- **Difficult to detect**: Malicious payloads appear as legitimate future-epoch payloads until epoch change

## Recommendation

Add epoch validation to reject BlockPayload messages from future epochs:

```rust
async fn process_block_payload_message(
    &mut self,
    peer_network_id: PeerNetworkId,
    message_received_time: Instant,
    block_payload: BlockPayload,
) {
    // Get the epoch and round for the block
    let block_epoch = block_payload.epoch();
    let block_round = block_payload.round();
    
    // NEW: Reject payloads from future epochs
    let epoch_state = self.get_epoch_state();
    if block_epoch > epoch_state.epoch + 1 {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Received block payload from future epoch: {:?}, current epoch: {:?}. Ignoring from peer: {:?}",
                block_epoch, epoch_state.epoch, peer_network_id
            ))
        );
        increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
        return;
    }

    // Determine if the payload is behind the last ordered block...
    // [rest of function]
}
```

Additionally, add BlockInfo validation in `verify_payloads_against_ordered_block`:

```rust
// After line 169, add:
let block_payload = match entry.get() {
    BlockPayloadStatus::AvailableAndVerified(bp) => bp,
    BlockPayloadStatus::AvailableAndUnverified(_) => {
        return Err(Error::InvalidMessageError(/*...*/));
    },
};

// Verify BlockInfo matches
if block_payload.block().id() != ordered_block.id() {
    return Err(Error::InvalidMessageError(format!(
        "BlockInfo mismatch! Payload block ID: {:?}, Ordered block ID: {:?}",
        block_payload.block().id(), ordered_block.id()
    )));
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_future_epoch_payload_dos_attack() {
    use crate::consensus_observer::network::observer_message::{BlockPayload, BlockTransactionPayload};
    use aptos_types::block_info::BlockInfo;
    
    // Setup consensus observer with max 10 pending blocks
    let config = ConsensusObserverConfig {
        max_num_pending_blocks: 10,
        ..Default::default()
    };
    let mut observer = create_consensus_observer(config);
    
    // Attacker sends 10 BlockPayloads with future epochs
    for i in 0..10 {
        let future_epoch = observer.get_epoch_state().epoch + 100;
        let malicious_payload = BlockPayload::new(
            BlockInfo::random_with_epoch(future_epoch, i),
            BlockTransactionPayload::empty(),
        );
        
        // This should be accepted (vulnerability!)
        observer.process_block_payload_message(
            malicious_peer,
            Instant::now(),
            malicious_payload,
        ).await;
    }
    
    // Verify payload store is full
    assert_eq!(observer.observer_block_data.lock()
        .get_block_payloads().lock().len(), 10);
    
    // Now send legitimate payload for current epoch
    let current_epoch = observer.get_epoch_state().epoch;
    let legitimate_payload = create_valid_payload(current_epoch, 1);
    
    observer.process_block_payload_message(
        legitimate_peer,
        Instant::now(),
        legitimate_payload,
    ).await;
    
    // Legitimate payload should be REJECTED (DOS attack succeeds!)
    // The store is still full of malicious future-epoch payloads
    assert_eq!(observer.observer_block_data.lock()
        .get_block_payloads().lock().len(), 10);
    
    // Verify legitimate payload not in store
    let has_legitimate = observer.observer_block_data.lock()
        .existing_payload_entry(&legitimate_payload);
    assert!(!has_legitimate); // DOS attack successful!
}
```

## Notes

This vulnerability exploits the asymmetry between strict validation for current-epoch payloads (requiring signature verification) versus lenient acceptance of future-epoch payloads (no signature verification). The consensus observer design assumes that future-epoch payloads will be validated when their epoch becomes current, but an attacker can exploit this window to fill the payload store with garbage, preventing legitimate payloads from being stored.

The missing BlockInfo validation in `verify_payloads_against_ordered_block` represents a secondary issue where even validated payloads are only matched by (epoch, round) without verifying the block ID, timestamp, or other BlockInfo fields actually correspond to the real consensus block.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L865-867)
```rust
    pub fn round(&self) -> Round {
        self.block.round()
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L362-380)
```rust
        // Get the epoch and round for the block
        let block_epoch = block_payload.epoch();
        let block_round = block_payload.round();

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

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L158-213)
```rust
    pub fn verify_payloads_against_ordered_block(
        &mut self,
        ordered_block: &OrderedBlock,
    ) -> Result<(), Error> {
        // Verify each of the blocks in the ordered block
        for ordered_block in ordered_block.blocks() {
            // Get the block epoch and round
            let block_epoch = ordered_block.epoch();
            let block_round = ordered_block.round();

            // Fetch the block payload
            match self.block_payloads.lock().entry((block_epoch, block_round)) {
                Entry::Occupied(entry) => {
                    // Get the block transaction payload
                    let transaction_payload = match entry.get() {
                        BlockPayloadStatus::AvailableAndVerified(block_payload) => {
                            block_payload.transaction_payload()
                        },
                        BlockPayloadStatus::AvailableAndUnverified(_) => {
                            // The payload should have already been verified
                            return Err(Error::InvalidMessageError(format!(
                                "Payload verification failed! Block payload for epoch: {:?} and round: {:?} is unverified.",
                                ordered_block.epoch(),
                                ordered_block.round()
                            )));
                        },
                    };

                    // Get the ordered block payload
                    let ordered_block_payload = match ordered_block.block().payload() {
                        Some(payload) => payload,
                        None => {
                            return Err(Error::InvalidMessageError(format!(
                                "Payload verification failed! Missing block payload for epoch: {:?} and round: {:?}",
                                ordered_block.epoch(),
                                ordered_block.round()
                            )));
                        },
                    };

                    // Verify the transaction payload against the ordered block payload
                    transaction_payload.verify_against_ordered_payload(ordered_block_payload)?;
                },
                Entry::Vacant(_) => {
                    // The payload is missing (this should never happen)
                    return Err(Error::InvalidMessageError(format!(
                        "Payload verification failed! Missing block payload for epoch: {:?} and round: {:?}",
                        ordered_block.epoch(),
                        ordered_block.round()
                    )));
                },
            }
        }

        Ok(())
    }
```
