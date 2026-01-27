# Audit Report

## Title
Inconsistent Metric Labeling for Dropped Commit Decision Messages Causes Monitoring Inaccuracy

## Summary
The `update_metrics_for_dropped_commit_decision_message` function uses an incorrect metric label (`COMMITTED_BLOCKS_LABEL` instead of `COMMIT_DECISION_LABEL`) when recording dropped commit decision messages, causing these messages to be mislabeled as "committed_blocks" in metrics. This breaks the invariant that message type labels should accurately reflect the actual message type being processed.

## Finding Description

In the consensus observer system, all message types follow a consistent pattern where the metric label matches the message type. However, there is an inconsistency in how dropped commit decision messages are labeled. [1](#0-0) 

The `get_label()` method correctly returns `"commit_decision"` for `CommitDecision` messages. However, when a commit decision message is dropped (because it's behind the highest committed block), the metrics function uses the wrong label: [2](#0-1) 

This function uses `metrics::COMMITTED_BLOCKS_LABEL` instead of `metrics::COMMIT_DECISION_LABEL`. Comparing with other message types shows this inconsistency: [3](#0-2) [4](#0-3) 

The metric label constants confirm the mismatch: [5](#0-4) 

Note that `COMMITTED_BLOCKS_LABEL = "committed_blocks"` (line 16) is used for tracking committed block rounds in gauges, not for commit decision message counting: [6](#0-5) 

## Impact Explanation

This falls under **Low Severity** per the Aptos bug bounty criteria as it causes "minor information leaks" and "non-critical implementation bugs" affecting monitoring accuracy. The impact includes:

1. **Incomplete Monitoring**: Operators monitoring `OBSERVER_DROPPED_MESSAGES` with label "commit_decision" will see zero dropped messages, even when commit decisions are being dropped
2. **Confusion**: Dropped messages appear under the "committed_blocks" label, which doesn't correspond to any actual message type
3. **Difficult Debugging**: When investigating consensus observer issues, operators cannot accurately track the rate of dropped commit decision messages
4. **Alert Failures**: Monitoring alerts configured for dropped "commit_decision" messages will never fire, potentially masking performance or synchronization issues

This does NOT affect:
- Consensus safety or liveness
- Funds or state integrity
- Transaction processing
- Validator behavior

## Likelihood Explanation

This issue occurs **every time** a commit decision message is dropped (i.e., when it arrives after the node has already committed beyond that round). This is a common occurrence in normal network operation when:
- Nodes receive delayed messages from peers
- A node temporarily falls behind and then catches up
- Multiple validators send commit decisions for the same round

The likelihood is **HIGH** that this metric mislabeling is actively occurring in production networks, but the impact remains limited to observability.

## Recommendation

Change line 1253 to use the correct label constant:

```rust
fn update_metrics_for_dropped_commit_decision_message(
    peer_network_id: PeerNetworkId,
    commit_decision: &CommitDecision,
) {
    // Update the dropped message counter
    increment_dropped_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);  // Changed from COMMITTED_BLOCKS_LABEL
    
    // Log the dropped commit decision message
    debug!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Ignoring commit decision message from peer: {:?}! Commit epoch and round: ({}, {})",
            peer_network_id,
            commit_decision.epoch(),
            commit_decision.round()
        ))
    );
}
```

This aligns the dropped commit decision metric with the pattern used for all other message types (ordered blocks, block payloads, etc.).

## Proof of Concept

This can be verified by examining the Prometheus/metrics endpoint on a running consensus observer node:

1. Start a consensus observer node
2. Query the `consensus_observer_dropped_messages` metric
3. Observe that dropped commit decisions appear under the `message_type="committed_blocks"` label instead of `message_type="commit_decision"`
4. Compare with other dropped message types (ordered_block, block_payload) which correctly use their message type as the label

**Notes**

While this is a valid bug affecting monitoring accuracy, it does not constitute an exploitable security vulnerability. The mislabeling occurs in metrics collection only and does not affect the consensus protocol, message processing logic, or any security-critical invariants. This is classified as a Low severity observability issue rather than a security vulnerability eligible for higher bounty tiers.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L137-147)
```rust
impl ConsensusObserverDirectSend {
    /// Returns a summary label for the direct send
    pub fn get_label(&self) -> &'static str {
        match self {
            ConsensusObserverDirectSend::OrderedBlock(_) => "ordered_block",
            ConsensusObserverDirectSend::CommitDecision(_) => "commit_decision",
            ConsensusObserverDirectSend::BlockPayload(_) => "block_payload",
            ConsensusObserverDirectSend::OrderedBlockWithWindow(_) => "ordered_block_with_window",
        }
    }
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1228-1245)
```rust
/// Updates the metrics for the dropped block payload message
fn update_metrics_for_dropped_block_payload_message(
    peer_network_id: PeerNetworkId,
    block_payload: &BlockPayload,
) {
    // Update the dropped message counter
    increment_dropped_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);

    // Log the dropped block payload message
    debug!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Ignoring block payload message from peer: {:?}! Block epoch and round: ({}, {})",
            peer_network_id,
            block_payload.epoch(),
            block_payload.round()
        ))
    );
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1247-1264)
```rust
/// Updates the metrics for the dropped commit decision message
fn update_metrics_for_dropped_commit_decision_message(
    peer_network_id: PeerNetworkId,
    commit_decision: &CommitDecision,
) {
    // Update the dropped message counter
    increment_dropped_message_counter(&peer_network_id, metrics::COMMITTED_BLOCKS_LABEL);

    // Log the dropped commit decision message
    debug!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Ignoring commit decision message from peer: {:?}! Commit epoch and round: ({}, {})",
            peer_network_id,
            commit_decision.epoch(),
            commit_decision.round()
        ))
    );
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1266-1283)
```rust
/// Updates the metrics for the dropped ordered block message
fn update_metrics_for_dropped_ordered_block_message(
    peer_network_id: PeerNetworkId,
    ordered_block: &OrderedBlock,
) {
    // Update the dropped message counter
    increment_dropped_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);

    // Log the dropped ordered block message
    debug!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Ignoring ordered block message from peer: {:?}! Block epoch and round: ({}, {})",
            peer_network_id,
            ordered_block.proof_block_info().epoch(),
            ordered_block.proof_block_info().round()
        ))
    );
}
```

**File:** consensus/src/consensus_observer/common/metrics.rs (L14-20)
```rust
pub const BLOCK_PAYLOAD_LABEL: &str = "block_payload";
pub const COMMIT_DECISION_LABEL: &str = "commit_decision";
pub const COMMITTED_BLOCKS_LABEL: &str = "committed_blocks";
pub const CREATED_SUBSCRIPTION_LABEL: &str = "created_subscription";
pub const ORDERED_BLOCK_ENTRIES_LABEL: &str = "ordered_block_entries";
pub const ORDERED_BLOCK_LABEL: &str = "ordered_block";
pub const ORDERED_BLOCK_WITH_WINDOW_LABEL: &str = "ordered_block_with_window";
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L205-215)
```rust
        // Update the highest round for the committed blocks
        let highest_committed_round = self
            .highest_committed_epoch_round
            .map(|(_, round)| round)
            .unwrap_or(0);
        metrics::set_gauge_with_label(
            &metrics::OBSERVER_PROCESSED_BLOCK_ROUNDS,
            metrics::COMMITTED_BLOCKS_LABEL,
            highest_committed_round,
        );
    }
```
