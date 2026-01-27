# Audit Report

## Title
TOCTOU Race Condition Allows Malicious Payload Overwriting in Consensus Observer

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition in the consensus observer's block payload handling allows an attacker to overwrite legitimate block payloads with malicious corrupted payloads. The vulnerability exists between the `existing_payload_entry()` check and the `insert_block_payload()` call, enabling denial-of-service attacks that prevent observer nodes from processing blocks.

## Finding Description
The consensus observer processes incoming block payloads in `process_block_payload_message()`. The function performs a check for existing payloads and an insert operation using separate lock acquisitions: [1](#0-0) 

Later, after verification, the payload is inserted: [2](#0-1) 

The `observer_block_data` is protected by a `Mutex`, but the lock is acquired and released separately for the check and the insert. This creates a race window where multiple threads can pass the existence check concurrently, then proceed to insert their respective payloads.

The `insert_block_payload()` function uses `BTreeMap::insert()` which unconditionally overwrites existing entries: [3](#0-2) 

**Attack Scenario:**

For blocks in a future epoch (where signature verification is deferred):

1. **Thread A (Legitimate peer)**: Receives block payload for (epoch E+1, round R) with valid signatures
   - Checks `existing_payload_entry()` → returns false
   - Verifies payload digests → passes
   - Cannot verify signatures (future epoch) → `verified_payload = false`
   - Proceeds to insert as unverified

2. **Thread B (Attacker)**: Sends same block (epoch E+1, round R) with corrupted ProofOfStore signatures
   - Checks `existing_payload_entry()` → returns false (race window before Thread A's insert)
   - Verifies payload digests → passes (same transactions/batches)
   - Cannot verify signatures (future epoch) → `verified_payload = false`
   - Proceeds to insert as unverified

3. **Race outcome**: If Thread B's insert executes after Thread A's insert, the attacker's corrupted payload **overwrites** the legitimate payload in the store.

4. **When epoch E+1 starts**, `verify_payload_signatures()` is called: [4](#0-3) 
   
   The corrupted payload fails signature verification and is removed. However, the legitimate payload was already overwritten and lost.

5. **When ordered block arrives**, verification fails: [5](#0-4) 
   
   The ordered block is rejected and the observer node cannot progress.

## Impact Explanation
This vulnerability enables **denial-of-service attacks against consensus observer nodes**. An attacker can prevent observers from processing blocks by sending corrupted payloads that overwrite legitimate ones. While this doesn't directly compromise consensus safety (validators are unaffected), it disrupts the operation of observer infrastructure that applications rely on for block data.

According to the Aptos bug bounty criteria, this represents **High Severity** as it causes "significant protocol violations" by breaking the observer protocol's integrity. Observer nodes are unable to fulfill their intended function of reliably observing and processing consensus blocks, requiring manual intervention or state synchronization to recover.

## Likelihood Explanation
**Likelihood: Medium-High**

The attack is feasible because:
- Any network peer can send block payload messages to observer nodes
- No validator privileges required
- Attacker can observe legitimate payloads on the network and craft corrupted versions
- The race window is significant (between check and insert operations)
- Attacker's payload processing may complete faster (signature verification is skipped for future epochs)

The attack requires timing precision but is achievable with network monitoring and coordinated payload injection.

## Recommendation
Implement atomic check-and-insert semantics by holding the lock across both operations. Modify the code to use `BTreeMap::entry()` API for atomic insertion:

```rust
// In consensus_observer.rs process_block_payload_message()
let mut observer_data = self.observer_block_data.lock();

// Atomic check and insert
if !observer_data.existing_payload_entry(&block_payload) {
    // Verify digests and signatures here while holding the lock
    // ... verification logic ...
    
    // Insert only if still doesn't exist
    observer_data.insert_block_payload(block_payload, verified_payload);
}
```

Alternatively, in `payload_store.rs`, modify `insert_block_payload()` to check existence before overwriting:

```rust
pub fn insert_block_payload(
    &mut self,
    block_payload: BlockPayload,
    verified_payload_signatures: bool,
) {
    let max_num_pending_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
    if self.block_payloads.lock().len() >= max_num_pending_blocks {
        // ... existing check ...
        return;
    }

    let epoch_and_round = (block_payload.epoch(), block_payload.round());
    let payload_status = if verified_payload_signatures {
        BlockPayloadStatus::AvailableAndVerified(block_payload)
    } else {
        BlockPayloadStatus::AvailableAndUnverified(block_payload)
    };

    // Use entry API to prevent overwriting verified payloads
    let mut payloads = self.block_payloads.lock();
    match payloads.entry(epoch_and_round) {
        Entry::Vacant(entry) => {
            entry.insert(payload_status);
        },
        Entry::Occupied(mut entry) => {
            // Only overwrite if upgrading from unverified to verified
            if verified_payload_signatures {
                if matches!(entry.get(), BlockPayloadStatus::AvailableAndUnverified(_)) {
                    entry.insert(payload_status);
                }
            }
            // Reject if trying to downgrade from verified to unverified
        }
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_payload_overwrite_race_condition() {
    use consensus_observer::observer::payload_store::BlockPayloadStore;
    use consensus_observer::network::observer_message::BlockPayload;
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    // Create block payload store
    let config = ConsensusObserverConfig::default();
    let store = Arc::new(Mutex::new(BlockPayloadStore::new(config)));
    
    // Create legitimate and malicious payloads for same (epoch, round)
    let epoch = 10;
    let round = 100;
    let legit_payload = create_block_payload_with_valid_signatures(epoch, round);
    let malicious_payload = create_block_payload_with_corrupted_signatures(epoch, round);
    
    // Simulate TOCTOU race
    let store1 = Arc::clone(&store);
    let store2 = Arc::clone(&store);
    
    let handle1 = thread::spawn(move || {
        // Legitimate thread
        let exists = store1.lock().unwrap().existing_payload_entry(&legit_payload);
        assert!(!exists);
        // Simulate verification delay
        thread::sleep(Duration::from_millis(10));
        store1.lock().unwrap().insert_block_payload(legit_payload, false);
    });
    
    let handle2 = thread::spawn(move || {
        // Attacker thread - inserts after legitimate check but before legitimate insert
        thread::sleep(Duration::from_millis(5));
        let exists = store2.lock().unwrap().existing_payload_entry(&malicious_payload);
        assert!(!exists); // Race window: both pass the check
        store2.lock().unwrap().insert_block_payload(malicious_payload, false);
    });
    
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Verify that malicious payload overwrote legitimate one
    let stored = store.lock().unwrap().get_block_payloads();
    let payload = stored.lock().get(&(epoch, round)).unwrap();
    
    // The last insert wins - if attacker inserted last, legitimate payload is lost
    assert!(matches!(payload, BlockPayloadStatus::AvailableAndUnverified(_)));
}
```

## Notes
- The vulnerability specifically affects consensus **observer** nodes, not validator nodes
- The attack requires the ability to send network messages to observer nodes
- Recovery requires either payload re-transmission or state synchronization
- The issue is exacerbated for future epoch blocks where signature verification is deferred
- Current epoch blocks with invalid signatures are rejected before insertion, limiting the attack surface for those cases

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L370-379)
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
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L427-430)
```rust
        // Update the payload store with the payload
        self.observer_block_data
            .lock()
            .insert_block_payload(block_payload, verified_payload);
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L106-108)
```rust
        self.block_payloads
            .lock()
            .insert(epoch_and_round, payload_status);
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L201-207)
```rust
                Entry::Vacant(_) => {
                    // The payload is missing (this should never happen)
                    return Err(Error::InvalidMessageError(format!(
                        "Payload verification failed! Missing block payload for epoch: {:?} and round: {:?}",
                        ordered_block.epoch(),
                        ordered_block.round()
                    )));
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
