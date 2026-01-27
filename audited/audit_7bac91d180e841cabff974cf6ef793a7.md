# Audit Report

## Title
Epoch-Based Block Deletion Vulnerability in Consensus Observer Commit Callback Handling

## Summary
The `handle_committed_blocks()` function in the consensus observer removes blocks from storage BEFORE validating the epoch of the incoming commit, allowing out-of-order or malicious commit callbacks with future epoch values to incorrectly delete all blocks from the current epoch, causing consensus liveness failures.

## Finding Description
The vulnerability exists in the ordering of operations within `handle_committed_blocks()`. [1](#0-0) 

The function performs block removal operations (lines 184-189) BEFORE validating that the commit's epoch matches the current root epoch (lines 193-202). This creates a critical race window where:

1. Block removal uses tuple comparison `(epoch, round)` in BTreeMap operations
2. A commit callback with a **future epoch** (epoch > current_epoch) triggers removal at `(future_epoch, round)`
3. Due to lexicographic tuple ordering, `(current_epoch, any_round) < (future_epoch, round)`, causing ALL current epoch blocks to be removed
4. The epoch validation check fires AFTER deletion, warning about the mismatch but unable to recover the deleted blocks

The removal logic in the payload store: [2](#0-1) 

And in the ordered block store: [3](#0-2) 

Both use `split_off()` which keeps entries >= the key, effectively removing all entries from lower epochs when a future epoch commit arrives.

**Attack Scenario:**
- Current state: epoch=10, root=(10, 50), ordered_blocks=[(10, 51), (10, 52), (10, 53)]
- Malicious peer or delayed callback sends commit for (epoch=11, round=0)
- `remove_blocks_for_epoch_round(11, 0)` → keeps blocks >= (11, 1)
- Removes (10, 51), (10, 52), (10, 53) because (10, x) < (11, 1)
- Epoch check detects 11 ≠ 10, warns and returns WITHOUT updating root
- **Observer is now missing blocks 51-53 but root still at 50 → consensus halted**

Each block in an ordered batch gets its own commit callback: [4](#0-3) 

This multiplies the attack surface as each callback executes independently and can arrive out of order.

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria:

1. **Consensus Liveness Failure**: The observer node cannot progress because ordered blocks are permanently deleted while the root remains at the old round. The node becomes stuck waiting for blocks that no longer exist.

2. **Forced Fallback Mode**: The node must enter state sync fallback mode to recover, causing service disruption and degraded consensus participation.

3. **Network-Wide Impact**: If multiple observer nodes receive malicious commit messages, the attack could degrade overall network health and consensus quality.

4. **Significant Protocol Violation**: The fundamental invariant that "ordered blocks must be preserved until committed" is broken, violating the consensus safety guarantee.

The impact aligns with "Significant protocol violations" and "Validator node slowdowns" under High Severity (up to $50,000).

## Likelihood Explanation
**Likelihood: Medium-High**

**Trigger Conditions:**
1. Malicious peer sends `CommitDecision` message with future epoch value
2. OR legitimate out-of-order callback delivery during epoch transitions
3. Observer node processes the message before epoch boundary validation

**Attacker Requirements:**
- Ability to send consensus observer messages (requires being an active peer)
- No validator privileges required
- No cryptographic bypass needed (message verification checks subscription, not content validity)

**Natural Occurrence:**
- During epoch transitions, timing race conditions could cause future-epoch commits to arrive before epoch state updates
- Asynchronous callback execution means callbacks can be queued and delivered out of order

The vulnerability is realistic because commit callbacks are asynchronous and can be delayed arbitrarily in the execution pipeline, while new ordered blocks continue to be inserted.

## Recommendation
**Fix: Validate epoch BEFORE removing blocks**

Reorder the operations in `handle_committed_blocks()` to check epoch validity before any state modifications:

```rust
fn handle_committed_blocks(&mut self, ledger_info: LedgerInfoWithSignatures) {
    // Verify the ledger info is for the same epoch FIRST
    let root_commit_info = self.root.commit_info();
    if ledger_info.commit_info().epoch() != root_commit_info.epoch() {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Received commit callback for a different epoch! Ledger info: {:?}, Root: {:?}",
                ledger_info.commit_info(),
                root_commit_info
            ))
        );
        return;
    }

    // Only proceed with removal if epoch is valid
    self.block_payload_store.remove_blocks_for_epoch_round(
        ledger_info.commit_info().epoch(),
        ledger_info.commit_info().round(),
    );
    self.ordered_block_store
        .remove_blocks_for_commit(&ledger_info);

    // Update the root if round is greater
    if ledger_info.commit_info().round() > root_commit_info.round() {
        info!(/* ... */);
        self.root = ledger_info;
    }
}
```

**Additional Hardening:**
1. Add round validation to reject commits with round <= current root round before removal
2. Log suspicious commit callbacks (future epochs, very old rounds) for monitoring
3. Consider adding a maximum epoch delta check to reject obviously invalid commits

## Proof of Concept
```rust
#[test]
fn test_handle_committed_blocks_future_epoch_vulnerability() {
    use super::*;
    use aptos_consensus_types::pipelined_block::PipelinedBlock;
    
    // Setup: Create observer at epoch 10, round 50
    let current_epoch = 10;
    let current_round = 50;
    let root = create_ledger_info(current_epoch, current_round);
    let mut observer_block_data = 
        ObserverBlockData::new_with_root(ConsensusObserverConfig::default(), root);
    
    // Insert blocks for rounds 51, 52, 53 in epoch 10
    let blocks = create_and_add_ordered_blocks(
        &mut observer_block_data, 
        3, 
        current_epoch, 
        current_round + 1
    );
    create_and_add_payloads_for_ordered_block(&mut observer_block_data, &blocks[0]);
    create_and_add_payloads_for_ordered_block(&mut observer_block_data, &blocks[1]);
    create_and_add_payloads_for_ordered_block(&mut observer_block_data, &blocks[2]);
    
    // Verify blocks exist
    assert_eq!(observer_block_data.get_all_ordered_blocks().len(), 3);
    assert_eq!(observer_block_data.get_block_payloads().lock().len(), 3);
    
    // Attack: Submit commit for FUTURE epoch 11, round 0
    let malicious_commit = create_ledger_info(current_epoch + 1, 0);
    observer_block_data.handle_committed_blocks(malicious_commit);
    
    // BUG: Blocks are deleted even though epoch doesn't match!
    assert_eq!(observer_block_data.get_all_ordered_blocks().len(), 0, 
        "Ordered blocks should be deleted due to future epoch");
    assert_eq!(observer_block_data.get_block_payloads().lock().len(), 0,
        "Payloads should be deleted due to future epoch");
    
    // Root should NOT be updated (epoch mismatch detected)
    assert_eq!(observer_block_data.root().commit_info().epoch(), current_epoch);
    assert_eq!(observer_block_data.root().commit_info().round(), current_round);
    
    // VULNERABILITY: Observer is now stuck at epoch 10, round 50
    // but has no blocks for rounds 51-53, causing liveness failure
}
```

**Notes:**
- This vulnerability violates the consensus safety invariant that ordered blocks must be preserved until properly committed
- The asynchronous nature of commit callbacks makes this exploitable through both malicious messages and natural timing races
- The fix is straightforward: validate before modifying state, following standard defensive programming practices

### Citations

**File:** consensus/src/consensus_observer/observer/block_data.rs (L182-219)
```rust
    fn handle_committed_blocks(&mut self, ledger_info: LedgerInfoWithSignatures) {
        // Remove the committed blocks from the payload and ordered block stores
        self.block_payload_store.remove_blocks_for_epoch_round(
            ledger_info.commit_info().epoch(),
            ledger_info.commit_info().round(),
        );
        self.ordered_block_store
            .remove_blocks_for_commit(&ledger_info);

        // Verify the ledger info is for the same epoch
        let root_commit_info = self.root.commit_info();
        if ledger_info.commit_info().epoch() != root_commit_info.epoch() {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received commit callback for a different epoch! Ledger info: {:?}, Root: {:?}",
                    ledger_info.commit_info(),
                    root_commit_info
                ))
            );
            return;
        }

        // Update the root ledger info. Note: we only want to do this if
        // the new ledger info round is greater than the current root
        // round. Otherwise, this can race with the state sync process.
        if ledger_info.commit_info().round() > root_commit_info.round() {
            info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Updating the root ledger info! Old root: (epoch: {:?}, round: {:?}). New root: (epoch: {:?}, round: {:?})",
                root_commit_info.epoch(),
                root_commit_info.round(),
                ledger_info.commit_info().epoch(),
                ledger_info.commit_info().round(),
            ))
        );
            self.root = ledger_info;
        }
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

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L112-124)
```rust
    pub fn remove_blocks_for_commit(&mut self, commit_ledger_info: &LedgerInfoWithSignatures) {
        // Determine the epoch and round to split off
        let split_off_epoch = commit_ledger_info.ledger_info().epoch();
        let split_off_round = commit_ledger_info.commit_info().round().saturating_add(1);

        // Remove the blocks from the ordered blocks
        self.ordered_blocks = self
            .ordered_blocks
            .split_off(&(split_off_epoch, split_off_round));

        // Update the highest committed epoch and round
        self.update_highest_committed_epoch_round(commit_ledger_info);
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L276-283)
```rust
            let commit_callback =
                block_data::create_commit_callback(self.observer_block_data.clone());
            self.pipeline_builder().build_for_observer(
                block,
                parent_fut.take().expect("future should be set"),
                commit_callback,
            );
            parent_fut = Some(block.pipeline_futs().expect("pipeline futures just built"));
```
