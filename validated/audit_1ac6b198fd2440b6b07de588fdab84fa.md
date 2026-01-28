# Audit Report

## Title
DAG Consensus: Insufficient Causal History Window Allows Permanent Transaction Loss via Orphaned Certified Nodes

## Summary
The DAG consensus implementation contains a liveness vulnerability where certified nodes can become permanently orphaned due to the narrow 10-round causal history window combined with the OptimisticResponsive round advancement strategy. Nodes arriving late to validators miss the parent-inclusion window, resulting in permanent transaction loss without requiring any malicious behavior.

## Finding Description

The vulnerability stems from a race condition in the DAG consensus ordering mechanism where the aggressive round advancement policy creates orphaned certified nodes that can never be ordered.

**Detailed Technical Flow:**

1. **Immediate Round Advancement**: The `OptimisticResponsive` strategy advances to round R+1 immediately upon receiving 2f+1 certified nodes from round R, without any delay mechanism. [1](#0-0) 

2. **Fixed Parent Selection**: When creating a node for round R+1, validators call `get_strong_links_for_round(R)` which returns ALL nodes from round R that the validator currently possesses (if they collectively have 2f+1 voting power). These become immutable parents. [2](#0-1) [3](#0-2) 

3. **Immutable Parent Digests**: Parents are embedded in the node's digest calculation, making them permanently fixed at creation time. [4](#0-3) 

4. **Orphaned Nodes Without Descendants**: If a certified node N from round R arrives at a validator AFTER that validator has created its round R+1 node, the R+1 node cannot include N as a parent. If this occurs across 2f+1+ validators, node N lacks sufficient descendants for future reachability. [5](#0-4) 

5. **Limited Ordering Window**: When an anchor at round R+K orders nodes, it only traverses backward `dag_window_size_config` rounds from the anchor. [6](#0-5) 

6. **Backward-Only Reachability**: The ordering algorithm uses `reachable_mut()` which traverses backward from the anchor following parent links. A node without descendants is never included in the reachable set from any anchor. [7](#0-6) [8](#0-7) 

7. **Reachable Nodes Exclusively Ordered**: Only nodes in the reachable set are marked as ordered during anchor finalization. [9](#0-8) 

8. **Automatic Pruning**: After `3 * window_size` rounds (30 rounds with default configuration), orphaned nodes are automatically pruned from memory regardless of ordering status. [10](#0-9) 

9. **Permanent Deletion**: All pruned nodes, including unordered certified nodes, are permanently deleted from persistent storage. [11](#0-10) 

10. **Insufficient Default Window**: The default causal history window is configured to only 10 rounds. [12](#0-11) 

**Security Guarantee Violation**: This breaks the **liveness property** of consensus - certified nodes (approved by 2f+1 validators) should eventually be ordered and their transactions committed. Instead, they can be permanently lost.

## Impact Explanation

**HIGH Severity** - This vulnerability causes permanent transaction loss affecting network liveness:

1. **Permanent Transaction Loss**: Transactions contained in orphaned certified nodes are never committed to the blockchain, despite 2f+1 validators certifying the node. This directly violates the fundamental liveness guarantee that all valid transactions will eventually be processed.

2. **Consensus Liveness Violation**: While not a safety violation (validators still agree on what IS ordered), this violates the critical liveness property. In a properly functioning consensus system, any transaction included in a certified node should eventually be finalized.

3. **No Recovery Mechanism**: The codebase contains no explicit detection or recovery mechanisms for orphaned certified nodes. Once pruned, transactions are permanently lost unless users manually resubmit them (which many users will not realize is necessary).

4. **Potential Fund Loss**: If orphaned transactions include fund transfers, token operations, or NFT transactions, those operations become permanently lost. While users can theoretically resubmit, many won't realize their transaction was dropped, leading to effective fund loss scenarios.

This aligns with Aptos bug bounty **High severity** criteria: significant transaction loss affecting network operation and user funds.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability can be triggered through normal network conditions:

1. **Geographically Distributed Validators**: Aptos validators operate globally with varying network latencies (200-500ms+ cross-continental). Well-connected validator subsets naturally form "fast groups" that advance rounds ahead of distant validators.

2. **OptimisticResponsive Design**: The immediate advancement upon 2f+1 (with no delay) maximizes the race condition window. Any node that hasn't reached 2f+1 validators before they advance will be excluded from those validators' next-round parents.

3. **Narrow Time Window**: With a 10-round window and fast round progression in high-throughput scenarios, the tolerance is only seconds. Network congestion, traffic spikes, or temporary connectivity issues can easily cause nodes to miss this window.

4. **No Malicious Behavior Required**: This occurs naturally through network topology and latency variation. No Byzantine validators or attacks needed - just normal network conditions under load.

5. **Cumulative Effect**: Even if individual occurrences are rare, the cumulative impact over time leads to increasing transaction loss affecting user confidence and network reliability.

## Recommendation

Implement multiple protective measures to ensure liveness:

1. **Increase Default Window Size**: Raise `dag_ordering_causal_history_window` from 10 to at least 50-100 rounds to provide adequate time for node propagation across geographically distributed validators.

2. **Implement Orphan Detection**: Add explicit detection for certified nodes that have insufficient descendants, with alerts to operators.

3. **Add Recovery Mechanism**: Before pruning, verify that all certified nodes have been ordered. Implement a "catch-up" ordering phase for orphaned but still valid certified nodes.

4. **Use Adaptive Responsive Strategy**: Switch from `OptimisticResponsive` to `AdaptiveResponsive` to add minimal wait times, reducing the race condition window: [13](#0-12) 

5. **Add Liveness Monitoring**: Implement metrics tracking the percentage of certified nodes successfully ordered vs. pruned unordered to detect this issue in production.

## Proof of Concept

The vulnerability can be demonstrated through a scenario test simulating network latency:

```rust
// Conceptual PoC structure (requires full DAG test harness)
// 1. Setup 7 validators with simulated network latency
// 2. Fast group (V1-V5): 10ms latency between them
// 3. Slow group (V6-V7): 500ms latency to fast group
// 4. Each validator creates round R node
// 5. Fast group certifies and advances to R+1 before slow nodes arrive
// 6. Verify slow group nodes are in DAG but have no descendants
// 7. Progress through 30+ rounds
// 8. Verify slow group nodes are pruned without being ordered
```

A complete PoC would require access to the DAG test infrastructure to simulate the timing conditions, but the logic vulnerability is evident from the code structure.

## Notes

**Critical Distinction**: This is a **liveness violation**, not a safety violation. Validators still agree on the order of transactions that ARE committed (safety preserved), but some valid transactions are never committed at all (liveness violated).

**Scope Clarification**: While the report mentions potential Byzantine exploitation, the vulnerability is valid even without malicious actors - normal network conditions are sufficient to trigger orphaned nodes.

**Production Impact**: This issue is particularly critical if DAG consensus is deployed on mainnet, as the 10-round window provides insufficient tolerance for real-world network conditions across global validator distribution.

### Citations

**File:** consensus/src/dag/round_state.rs (L96-108)
```rust
impl ResponsiveCheck for OptimisticResponsive {
    fn check_for_new_round(
        &self,
        highest_strong_links_round: Round,
        _strong_links: Vec<NodeCertificate>,
        _health_backoff_delay: Duration,
    ) {
        let new_round = highest_strong_links_round + 1;
        let _ = self.event_sender.send(new_round);
    }

    fn reset(&self) {}
}
```

**File:** consensus/src/dag/round_state.rs (L125-148)
```rust
pub struct AdaptiveResponsive {
    inner: Mutex<AdaptiveResponsiveInner>,
    epoch_state: Arc<EpochState>,
    minimal_wait_time: Duration,
    event_sender: tokio::sync::mpsc::UnboundedSender<Round>,
}

impl AdaptiveResponsive {
    pub fn new(
        event_sender: tokio::sync::mpsc::UnboundedSender<Round>,
        epoch_state: Arc<EpochState>,
        minimal_wait_time: Duration,
    ) -> Self {
        Self {
            inner: Mutex::new(AdaptiveResponsiveInner {
                start_time: duration_since_epoch(),
                state: State::Initial,
            }),
            epoch_state,
            minimal_wait_time,
            event_sender,
        }
    }
}
```

**File:** consensus/src/dag/dag_store.rs (L128-164)
```rust
    fn validate_new_node(&mut self, node: &CertifiedNode) -> anyhow::Result<()> {
        ensure!(
            node.epoch() == self.epoch_state.epoch,
            "different epoch {}, current {}",
            node.epoch(),
            self.epoch_state.epoch
        );
        let author = node.metadata().author();
        let index = *self
            .author_to_index
            .get(author)
            .ok_or_else(|| anyhow!("unknown author"))?;
        let round = node.metadata().round();
        ensure!(
            round >= self.lowest_round(),
            "round too low {}, lowest in dag {}",
            round,
            self.lowest_round()
        );
        ensure!(
            round <= self.highest_round() + 1,
            "round too high {}, highest in dag {}",
            round,
            self.highest_round()
        );
        if round > self.lowest_round() {
            for parent in node.parents() {
                ensure!(self.exists(parent.metadata()), "parent not exist");
            }
        }
        let round_ref = self
            .nodes_by_round
            .entry(round)
            .or_insert_with(|| vec![None; self.author_to_index.len()]);
        ensure!(round_ref[index].is_none(), "duplicate node");
        Ok(())
    }
```

**File:** consensus/src/dag/dag_store.rs (L288-300)
```rust
    fn reachable_filter(start: Vec<HashValue>) -> impl FnMut(&Arc<CertifiedNode>) -> bool {
        let mut reachable: HashSet<HashValue> = HashSet::from_iter(start);
        move |node| {
            if reachable.contains(&node.digest()) {
                for parent in node.parents() {
                    reachable.insert(*parent.metadata().digest());
                }
                true
            } else {
                false
            }
        }
    }
```

**File:** consensus/src/dag/dag_store.rs (L302-318)
```rust
    pub fn reachable_mut(
        &mut self,
        from: &Arc<CertifiedNode>,
        until: Option<Round>,
    ) -> impl Iterator<Item = &mut NodeStatus> + use<'_> {
        let until = until.unwrap_or(self.lowest_round());
        let mut reachable_filter = Self::reachable_filter(vec![from.digest()]);
        self.nodes_by_round
            .range_mut(until..=from.round())
            .rev()
            .flat_map(|(_, round_ref)| round_ref.iter_mut())
            .flatten()
            .filter(move |node_status| {
                matches!(node_status, NodeStatus::Unordered { .. })
                    && reachable_filter(node_status.as_node())
            })
    }
```

**File:** consensus/src/dag/dag_store.rs (L346-367)
```rust
    pub fn get_strong_links_for_round(
        &self,
        round: Round,
        validator_verifier: &ValidatorVerifier,
    ) -> Option<Vec<NodeCertificate>> {
        if validator_verifier
            .check_voting_power(
                self.get_round_iter(round)?
                    .map(|node_status| node_status.as_node().metadata().author()),
                true,
            )
            .is_ok()
        {
            Some(
                self.get_round_iter(round)?
                    .map(|node_status| node_status.as_node().certificate())
                    .collect(),
            )
        } else {
            None
        }
    }
```

**File:** consensus/src/dag/dag_store.rs (L423-423)
```rust
        let new_start_round = commit_round.saturating_sub(3 * self.window_size);
```

**File:** consensus/src/dag/dag_store.rs (L538-550)
```rust
    pub fn commit_callback(&self, commit_round: Round) {
        let to_prune = self.dag.write().commit_callback(commit_round);
        if let Some(to_prune) = to_prune {
            let digests = to_prune
                .iter()
                .flat_map(|(_, round_ref)| round_ref.iter().flatten())
                .map(|node_status| *node_status.as_node().metadata().digest())
                .collect();
            if let Err(e) = self.storage.delete_certified_nodes(digests) {
                error!("Error deleting expired nodes: {:?}", e);
            }
        }
    }
```

**File:** consensus/src/dag/dag_driver.rs (L214-219)
```rust
            let strong_links = dag_reader
                .get_strong_links_for_round(new_round - 1, &self.epoch_state.verifier)
                .unwrap_or_else(|| {
                    assert_eq!(new_round, 1, "Only expect empty strong links for round 1");
                    vec![]
                });
```

**File:** consensus/src/dag/types.rs (L172-181)
```rust
        let digest = Self::calculate_digest_internal(
            epoch,
            round,
            author,
            timestamp,
            &validator_txns,
            &payload,
            &parents,
            &extensions,
        );
```

**File:** consensus/src/dag/order_rule.rs (L167-167)
```rust
        let lowest_round_to_reach = anchor.round().saturating_sub(self.dag_window_size_config);
```

**File:** consensus/src/dag/order_rule.rs (L197-203)
```rust
        let mut ordered_nodes: Vec<_> = dag_writer
            .reachable_mut(&anchor, Some(lowest_round_to_reach))
            .map(|node_status| {
                node_status.mark_as_ordered();
                node_status.as_node().clone()
            })
            .collect();
```

**File:** types/src/on_chain_config/consensus_config.rs (L594-594)
```rust
            dag_ordering_causal_history_window: 10,
```
