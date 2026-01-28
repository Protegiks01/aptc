# Audit Report

## Title
Incorrect Epoch/Round Comparison Logic Enables State Sync Disruption During Epoch Transitions

## Summary
The consensus observer's commit decision processing uses inconsistent epoch/round comparison logic. While the `OrderedBlockStore` correctly uses lexicographic tuple ordering `(epoch, round)`, the commit processing code uses a flawed comparison pattern that can trigger state sync for past-epoch commits with high round numbers during epoch transitions.

## Finding Description

The `BTreeMap<(u64, Round), ...>` in the OrderedBlockStore correctly uses Rust's lexicographic tuple comparison, which orders by epoch first, then by round: [1](#0-0) 

This same correct pattern is used elsewhere in the codebase for comparing blocks: [2](#0-1) 

However, the commit decision processing at the critical state sync decision point uses a flawed comparison pattern: [3](#0-2) 

This code checks `epoch_changed || commit_round > last_block.round()`, which incorrectly triggers when:
- `commit_epoch < last_block.epoch()` (commit from past epoch)
- AND `commit_round > last_block.round()` (high round number)

**Attack Scenario:**
1. Node is transitioning from epoch 9 to epoch 10
2. Highest committed block: `(epoch=9, round=100)`
3. Last ordered block: `(epoch=10, round=50)`
4. Subscribed peer sends commit decision for `(epoch=9, round=200)`

**Execution Flow:**

The initial check passes because tuple comparison works correctly: [4](#0-3) 

Verification is skipped because the commit is not for the current epoch: [5](#0-4) 

Pending block processing fails (no block exists at epoch 9, round 200): [6](#0-5) 

The flawed comparison incorrectly triggers state sync:
- `epoch_changed = 9 > 10 = false`
- `commit_round > last_block.round() = 200 > 50 = true`
- Condition evaluates to true, triggering state sync to a past epoch

The node then updates its root to the unverified past-epoch commit and initiates state sync: [7](#0-6) 

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria. The vulnerability enables:

1. **State inconsistencies requiring intervention**: Consensus observer nodes (Validator Fullnodes and Public Fullnodes) can be forced into incorrect state sync operations for past epochs, updating their root to unverified past-epoch commits.

2. **Resource consumption**: Unnecessary state sync operations consume resources and degrade performance of VFNs and PFNs.

3. **Protocol violations**: The consensus observer component behaves incorrectly during epoch transitions, violating the expected ordering invariant.

The attack does not directly compromise consensus safety (full validators use only the publisher component, not the observer) or cause fund loss, preventing Critical severity classification. However, it disrupts consensus observer operations used by Validator Fullnodes and requires manual intervention to resolve.

## Likelihood Explanation

**Moderate to High likelihood** during normal operation:
- Epoch transitions occur regularly in Aptos (every ~2 hours in production)
- The vulnerable window exists whenever `highest_committed_epoch_round` lags behind `last_ordered_block` epoch during transitions
- Attacker must be a subscribed peer (subscription verification occurs before processing): [8](#0-7) 
- However, subscriptions can be established through normal network participation
- Attacker only needs to observe epoch transitions and send crafted commit messages

## Recommendation

Fix the comparison logic to use proper tuple comparison:

```rust
let last_block = self.observer_block_data.lock().get_last_ordered_block();
if (commit_epoch, commit_round) > (last_block.epoch(), last_block.round()) {
    // State sync logic
}
```

This ensures consistent epoch/round ordering matching the pattern used elsewhere in the codebase at line 369.

## Proof of Concept

A working PoC would require:
1. Setting up a consensus observer node during epoch transition
2. Establishing a subscription from an attacker-controlled peer
3. Sending a crafted CommitDecision for a past epoch with high round number
4. Observing the incorrect state sync trigger and root update

The logic vulnerability is confirmed through code analysis showing the inconsistent comparison patterns between lines 369 (correct) and 503-504 (incorrect).

---

## Notes

- This vulnerability specifically affects nodes running the consensus observer component (Validator Fullnodes and Public Fullnodes), not full validator consensus nodes which use only the publisher component
- The peer must be subscribed to send messages, not "any network peer" as initially stated
- The comparison inconsistency is a clear logic bug that violates the epoch/round ordering invariant maintained by the BTreeMap data structure

### Citations

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L28-28)
```rust
    ordered_blocks: BTreeMap<(u64, Round), (ObservedOrderedBlock, Option<CommitDecision>)>,
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L369-369)
```rust
            (block_epoch, block_round) <= (last_ordered_block.epoch(), last_ordered_block.round());
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L457-457)
```rust
        if (commit_epoch, commit_round) <= get_highest_committed_epoch_round {
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L468-468)
```rust
        if commit_epoch == epoch_state.epoch {
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L492-493)
```rust
            if self.process_commit_decision_for_pending_block(&commit_decision) {
                return; // The commit decision was successfully processed
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L503-504)
```rust
        let epoch_changed = commit_epoch > last_block.epoch();
        if epoch_changed || commit_round > last_block.round() {
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L520-526)
```rust
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);

            // Start state syncing to the commit decision
            self.state_sync_manager
                .sync_to_commit(commit_decision, epoch_changed);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L579-594)
```rust
        if let Err(error) = self
            .subscription_manager
            .verify_message_for_subscription(peer_network_id)
        {
            // Update the rejected message counter
            increment_rejected_message_counter(&peer_network_id, &message);

            // Log the error and return
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received message that was not from an active subscription! Error: {:?}",
                    error,
                ))
            );
            return;
        }
```
