# Audit Report

## Title
Consensus Observer Pending Block Store Garbage Collection Selection Bias Enables Permanent Memory Exhaustion via Future Epoch Blocks

## Summary
The `garbage_collect_pending_blocks()` function in the consensus observer's pending block store uses epoch-round tuple ordering to remove the oldest blocks, creating a critical bias where blocks claiming to be from far future epochs are never garbage collected. An attacker can exploit this by flooding the pending block store with invalid blocks from arbitrarily high epoch numbers (e.g., epoch 999,999,999), permanently occupying all available storage slots and preventing legitimate blocks from being processed.

## Finding Description

The consensus observer's pending block store maintains a `BTreeMap<(u64, Round), Arc<PendingBlockWithMetadata>>` where blocks are keyed by their (epoch, round) tuple. [1](#0-0) 

When the store reaches its capacity limit (`max_num_pending_blocks`, defaulting to 150), garbage collection is triggered. [2](#0-1) 

The garbage collection mechanism removes blocks using `pop_first()`, which removes the entry with the **smallest** (epoch, round) tuple from the BTreeMap. [3](#0-2) 

**The critical flaw is in the validation logic before block insertion:**

When an ordered block message is received, the only epoch-related validation is checking whether the block is **not older** than the last ordered block. [4](#0-3) 

There is **no upper bound check** on the epoch number. The `verify_ordered_blocks()` function only validates block structure and chaining, not epoch bounds. [5](#0-4) 

**Attack Propagation Path:**

1. Attacker sends ordered block messages claiming to be from epoch 999,999,999 (or any arbitrarily high epoch)
2. Blocks pass `verify_ordered_blocks()` structural validation
3. Blocks pass the `block_out_of_date` check since `(999999999, round) > (current_epoch, round)`
4. Blocks are inserted into `pending_block_store` [6](#0-5) 
5. When garbage collection triggers, `pop_first()` removes blocks with the **lowest** epoch numbers
6. Legitimate blocks from the current epoch (e.g., epoch 5) get removed first because `(5, round) < (999999999, round)`
7. Attacker's future epoch blocks persist indefinitely, occupying all 150 storage slots

**Why blocks aren't removed:**

While blocks are eventually validated against the current epoch when processed [7](#0-6) , this validation only occurs when the block is retrieved for processing via `remove_ready_block()`. Attacker blocks from future epochs will never be processed because they're waiting for payloads that will never arrive for non-existent epochs. There is no timeout-based expiry mechanism for pending blocks - only size-based garbage collection.

## Impact Explanation

**Severity: Medium**

This vulnerability enables a **Denial of Service** attack against consensus observer nodes with the following impacts:

1. **Resource Exhaustion**: Attacker permanently occupies all 150 pending block slots with invalid future epoch blocks
2. **Consensus Observer Unavailability**: Legitimate blocks cannot be stored in the pending block store, preventing the consensus observer from functioning
3. **Degraded Validator Fullnode Performance**: Validator fullnodes (VFNs) have consensus observer enabled by default [8](#0-7) , so this attack impacts their block processing capability
4. **Network-Wide Impact**: An attacker can target multiple nodes simultaneously with minimal resources

This qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention" - the pending block store becomes permanently polluted, requiring node restart to clear.

## Likelihood Explanation

**Likelihood: High**

Attack requirements:
- **No privileged access required**: Any network peer can send ordered block messages
- **Low complexity**: Attacker only needs to craft ordered blocks with valid structure but inflated epoch numbers
- **Low cost**: Attack requires minimal bandwidth - sending 150 blocks once permanently occupies the store
- **No cryptographic bypass needed**: Blocks don't need valid signatures until processing stage, which never occurs

The attack is highly likely because:
1. Consensus observer is enabled by default on validator fullnodes
2. No authentication required to send ordered block messages
3. The vulnerability triggers deterministically with any future epoch value
4. No rate limiting on pending block insertion exists

## Recommendation

**Immediate Fix**: Add epoch bound validation before inserting blocks into the pending block store.

Modify the validation in `handle_ordered_block_message()` to reject blocks from unreasonably future epochs:

```rust
// Get the current epoch state
let current_epoch = self.get_epoch_state().epoch;

// Reject blocks from epochs too far in the future (e.g., current + 2)
const MAX_EPOCH_AHEAD: u64 = 2;
if first_block.epoch() > current_epoch.saturating_add(MAX_EPOCH_AHEAD) {
    warn!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Rejected ordered block from future epoch: {:?}, current epoch: {:?}",
            first_block.epoch(), current_epoch
        ))
    );
    increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
    return;
}
```

**Alternative/Additional Fix**: Modify garbage collection to consider block age:

```rust
fn garbage_collect_pending_blocks(&mut self) {
    let now = Instant::now();
    const MAX_PENDING_BLOCK_AGE: Duration = Duration::from_secs(300); // 5 minutes
    
    // First remove blocks older than max age
    self.blocks_without_payloads.retain(|_, block| {
        now.duration_since(block.block_receipt_time) <= MAX_PENDING_BLOCK_AGE
    });
    
    // Then apply size-based GC if still over limit
    // ... existing size-based GC logic
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_future_epoch_dos_attack() {
    use aptos_config::config::ConsensusObserverConfig;
    use consensus::consensus_observer::observer::pending_blocks::PendingBlockStore;
    
    // Create pending block store with capacity of 10 blocks
    let config = ConsensusObserverConfig {
        max_num_pending_blocks: 10,
        ..Default::default()
    };
    let mut store = PendingBlockStore::new(config);
    
    // Attacker sends 10 blocks from epoch 999999999
    let attacker_epoch = 999_999_999;
    for round in 0..10 {
        let ordered_block = create_ordered_block(attacker_epoch, round, 1, 0);
        let observed = ObservedOrderedBlock::new(ordered_block);
        let pending = PendingBlockWithMetadata::new_with_arc(
            PeerNetworkId::random(),
            Instant::now(),
            observed,
        );
        store.insert_pending_block(pending);
    }
    
    // Verify attacker blocks occupy all 10 slots
    assert_eq!(store.blocks_without_payloads.len(), 10);
    
    // Legitimate blocks from current epoch (epoch 5) arrive
    let current_epoch = 5;
    for round in 0..5 {
        let ordered_block = create_ordered_block(current_epoch, round, 1, 0);
        let observed = ObservedOrderedBlock::new(ordered_block);
        let pending = PendingBlockWithMetadata::new_with_arc(
            PeerNetworkId::random(),
            Instant::now(),
            observed,
        );
        store.insert_pending_block(pending);
    }
    
    // After GC, legitimate blocks (epoch 5) were removed, attacker blocks (epoch 999999999) remain
    assert_eq!(store.blocks_without_payloads.len(), 10);
    
    // Verify only attacker's future epoch blocks remain
    for (epoch, _round) in store.blocks_without_payloads.keys() {
        assert_eq!(*epoch, attacker_epoch);
    }
    
    // Legitimate blocks were garbage collected despite being valid
    assert!(!store.blocks_without_payloads.contains_key(&(current_epoch, 0)));
}
```

**Exploitation steps:**
1. Identify target consensus observer node (VFN or PFN)
2. Craft 150 ordered blocks with valid structure but epoch set to 999,999,999
3. Send blocks to target node via network messages
4. Monitor that pending block store fills with attacker blocks
5. Legitimate blocks from current epoch are rejected/dropped due to store capacity
6. Consensus observer functionality degraded indefinitely

### Citations

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L67-67)
```rust
    blocks_without_payloads: BTreeMap<(u64, Round), Arc<PendingBlockWithMetadata>>,
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L178-179)
```rust
            if let Some((oldest_epoch_round, pending_block)) =
                self.blocks_without_payloads.pop_first()
```

**File:** config/src/config/consensus_observer_config.rs (L72-72)
```rust
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
```

**File:** config/src/config/consensus_observer_config.rs (L119-127)
```rust
            NodeType::ValidatorFullnode => {
                if ENABLE_ON_VALIDATOR_FULLNODES
                    && !observer_manually_set
                    && !publisher_manually_set
                {
                    // Enable both the observer and the publisher for VFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L679-680)
```rust
        let block_out_of_date =
            first_block_epoch_round <= (last_ordered_block.epoch(), last_ordered_block.round());
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L710-712)
```rust
            self.observer_block_data
                .lock()
                .insert_pending_block(pending_block_with_metadata);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L729-751)
```rust
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
        } else {
            // Drop the block and log an error (the block should always be for the current epoch)
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received ordered block for a different epoch! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
            return;
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L227-265)
```rust
    pub fn verify_ordered_blocks(&self) -> Result<(), Error> {
        // Verify that we have at least one ordered block
        if self.blocks.is_empty() {
            return Err(Error::InvalidMessageError(
                "Received empty ordered block!".to_string(),
            ));
        }

        // Verify the last block ID matches the ordered proof block ID
        if self.last_block().id() != self.proof_block_info().id() {
            return Err(Error::InvalidMessageError(
                format!(
                    "Last ordered block ID does not match the ordered proof ID! Number of blocks: {:?}, Last ordered block ID: {:?}, Ordered proof ID: {:?}",
                    self.blocks.len(),
                    self.last_block().id(),
                    self.proof_block_info().id()
                )
            ));
        }

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

        Ok(())
```
