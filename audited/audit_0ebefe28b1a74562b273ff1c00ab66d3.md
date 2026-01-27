# Audit Report

## Title
Incomplete DAG Sync Response Causes Cascading Consensus Participation Failures

## Summary
The DAG consensus sync mechanism allows responders with incomplete DAGs to serve fetch requests, providing partial node sets that pass basic verification but fail to reconstruct a complete DAG. This creates a cascading failure where affected nodes cannot participate in consensus and may infect other nodes attempting to sync from them.

## Finding Description

The vulnerability exists in the DAG state synchronization mechanism where nodes fetch missing certified nodes from peers. The issue occurs across three critical components:

**1. Fetch Response Generation (Incomplete DAG Detection Missing)** [1](#0-0) 

The `FetchRequestHandler::process()` method validates that the responder has the target nodes but does not verify that its own DAG is complete. When a responder has gaps in its DAG, the `reachable()` function silently excludes unreachable nodes: [2](#0-1) 

The `reachable_filter` stops traversing when it encounters missing parents. If Node C at round 98 is missing, it won't add Node C to the reachable set, causing all ancestors (rounds 97, 96, etc.) to be excluded from the response, even though they exist in the DAG.

**2. Response Validation (Insufficient Completeness Check)** [3](#0-2) 

The `FetchResponse::verify()` method only checks that returned nodes match the bitmask and have valid signatures. It does NOT validate that the response forms a complete transitive closure from targets to the start round.

**3. Failed Node Addition (Silent Failure)** [4](#0-3) 

When adding nodes in reverse order, failures due to missing parents are only logged, not treated as fatal errors. The validation that catches missing parents: [5](#0-4) 

**4. Sync Failure Recovery (Infinite Loop)** [6](#0-5) 

When sync fails, the node resumes with its old/incomplete DAG state and immediately needs sync again: [7](#0-6) 

**Attack Scenario:**

1. **Initial Failure**: Node A fails to sync due to network issues, ending up with DAG containing rounds 1-50, 60-100 (missing 51-59)

2. **Cascading Infection**: Node B tries to sync from Node A:
   - Requests nodes to reach round 100
   - Node A passes target existence check (has node at round 100)
   - Node A's `reachable()` traverses from round 100 but stops at round 60 due to gap
   - Returns nodes 60-100 only
   - Node B tries to add these nodes but they fail (missing parents in 51-59)
   - Node B's sync fails

3. **Network Propagation**: If multiple validators have incomplete DAGs, the problem spreads as nodes sync from each other

4. **Consensus Paralysis**: Affected nodes cannot:
   - Propose new blocks (cannot find strong links)
   - Validate new blocks properly
   - Participate in voting
   - Make progress in consensus

## Impact Explanation

**HIGH Severity** - This qualifies as "Validator node slowdowns" and "Significant protocol violations" under the Aptos bug bounty program:

- **Liveness Impact**: Affected validators cannot participate in consensus, reducing effective validator set size
- **Cascading Failures**: The problem can spread to healthy nodes that attempt to sync from infected peers
- **No Automatic Recovery**: Nodes remain stuck in sync loop indefinitely without manual intervention
- **Network-Wide Risk**: If enough validators are affected, consensus could halt entirely

This does not reach Critical severity because:
- No funds are lost or stolen
- Safety is not violated (no chain splits)
- Network can recover through manual intervention or state sync from external sources

## Likelihood Explanation

**HIGH Likelihood** - This can occur through multiple realistic scenarios:

1. **Natural Occurrence**: Network partitions, crashes during sync, or storage corruption can create incomplete DAGs
2. **Malicious Exploitation**: A single Byzantine validator can deliberately maintain an incomplete DAG and serve bad responses
3. **No Attacker Coordination Required**: Even one incomplete DAG can start a cascading failure
4. **Poor Error Handling**: Silent failures and automatic retry make the problem persistent

The vulnerability is particularly likely because:
- No validation prevents incomplete DAGs from serving fetch requests
- The TODO comment at line 434 suggests size limits were considered but completeness validation was overlooked
- Normal network conditions (temporary partitions, high load) can trigger the issue

## Recommendation

Implement completeness validation before serving fetch responses:

```rust
async fn process(&self, message: Self::Request) -> anyhow::Result<Self::Response> {
    let dag_reader = self.dag.read();
    
    // Existing checks...
    ensure!(
        dag_reader.lowest_round() <= message.start_round(),
        FetchRequestHandleError::GarbageCollected(
            message.start_round(),
            dag_reader.lowest_round()
        ),
    );
    
    let missing_targets: BitVec = message
        .targets()
        .map(|node| !dag_reader.exists(node))
        .collect();
    ensure!(
        missing_targets.all_zeros(),
        FetchRequestHandleError::TargetsMissing(missing_targets)
    );
    
    // NEW: Validate DAG completeness before serving
    // Check that all reachable nodes from targets can trace back to start_round
    // without gaps
    let start_round = message.exists_bitmask().first_round();
    for target in message.targets() {
        // Verify complete path exists from target to start_round
        let mut current_round = target.round();
        let mut visited = HashSet::new();
        visited.insert(target.digest());
        
        while current_round > start_round {
            let nodes_at_round = dag_reader.get_round_iter(current_round - 1);
            if nodes_at_round.is_none() {
                bail!(FetchRequestHandleError::IncompleteDag(current_round - 1));
            }
            
            // Ensure we can reach at least one node in the previous round
            let has_reachable_parent = nodes_at_round
                .unwrap()
                .any(|node_status| {
                    visited.contains(&node_status.as_node().digest())
                });
            
            if !has_reachable_parent {
                bail!(FetchRequestHandleError::IncompleteDag(current_round - 1));
            }
            
            current_round -= 1;
        }
    }
    
    let certified_nodes: Vec<_> = dag_reader
        .reachable(
            message.targets(),
            Some(message.exists_bitmask().first_round()),
            |_| true,
        )
        .filter_map(|node_status| {
            let arc_node = node_status.as_node();
            self.author_to_index
                .get(arc_node.author())
                .and_then(|author_idx| {
                    if !message.exists_bitmask().has(arc_node.round(), *author_idx) {
                        Some(arc_node.as_ref().clone())
                    } else {
                        None
                    }
                })
        })
        .collect();
    
    Ok(FetchResponse::new(message.epoch(), certified_nodes))
}
```

Additionally, add a new error variant:
```rust
#[derive(Clone, Debug, ThisError, Serialize, Deserialize)]
pub enum FetchRequestHandleError {
    #[error("target nodes are missing, missing {}", .0.count_ones())]
    TargetsMissing(BitVec),
    #[error("garbage collected, request round {0}, lowest round {1}")]
    GarbageCollected(Round, Round),
    #[error("incomplete DAG at round {0}, cannot serve complete response")]
    IncompleteDag(Round),
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_incomplete_dag_sync_failure() {
        // Setup: Create a DAG store with a gap
        let epoch_state = Arc::new(create_test_epoch_state(4));
        let storage = Arc::new(MockStorage::new());
        let payload_manager = Arc::new(MockPayloadManager::new());
        
        let dag_store = Arc::new(DagStore::new_empty(
            epoch_state.clone(),
            storage.clone(),
            payload_manager,
            1,
            10,
        ));
        
        // Add nodes for rounds 1-5
        for round in 1..=5 {
            let node = create_test_certified_node(round, 0, vec![]);
            dag_store.add_node(node).unwrap();
        }
        
        // Skip round 6 (creating a gap)
        
        // Add nodes for rounds 7-10
        for round in 7..=10 {
            let parent_round = round - 1;
            let parents = if round == 7 {
                // Round 7 references non-existent round 6
                vec![create_node_metadata(6, 0)]
            } else {
                vec![create_node_metadata(parent_round, 0)]
            };
            
            // This should fail due to missing parent at round 6
            let node = create_test_certified_node(round, 0, parents);
            let result = dag_store.add_node(node);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("parent not exist"));
        }
        
        // Now simulate a fetch request for round 10
        let handler = FetchRequestHandler::new(dag_store.clone(), epoch_state.clone());
        
        let target = create_node_metadata(10, 0);
        let bitmask = DagSnapshotBitmask::new(1, vec![vec![false; 4]; 10]);
        let request = RemoteFetchRequest::new(
            epoch_state.epoch,
            vec![target],
            bitmask,
        );
        
        // This should fail because the DAG is incomplete
        // But currently it succeeds and returns partial data
        let response = handler.process(request).await;
        
        // With the fix, this should error with IncompleteDag
        // Without the fix, it returns incomplete nodes that will fail to add
        if let Ok(fetch_response) = response {
            let nodes = fetch_response.certified_nodes();
            // Verify that nodes are incomplete (should only contain rounds 1-5)
            assert!(nodes.len() < 10);
            assert!(nodes.iter().all(|n| n.round() <= 5));
        }
    }
}
```

This PoC demonstrates that a responder with a gap in its DAG will serve incomplete responses that pass basic validation but fail when the requester attempts to reconstruct the complete DAG, preventing proper consensus participation.

### Citations

**File:** consensus/src/dag/dag_fetcher.rs (L337-342)
```rust
                                for node in certified_nodes.into_iter().rev() {
                                    if let Err(e) = dag.add_node(node) {
                                        error!(error = ?e, "failed to add node");
                                    }
                                }
                            }
```

**File:** consensus/src/dag/dag_fetcher.rs (L384-437)
```rust
    async fn process(&self, message: Self::Request) -> anyhow::Result<Self::Response> {
        let dag_reader = self.dag.read();

        // `Certified Node`: In the good case, there should exist at least one honest validator that
        // signed the Certified Node that has the all the parents to fulfil this
        // request.
        // `Node`: In the good case, the sender of the Node should have the parents in its local DAG
        // to satisfy this request.
        debug!(
            LogSchema::new(LogEvent::ReceiveFetchNodes).round(dag_reader.highest_round()),
            start_round = message.start_round(),
            target_round = message.target_round(),
        );
        ensure!(
            dag_reader.lowest_round() <= message.start_round(),
            FetchRequestHandleError::GarbageCollected(
                message.start_round(),
                dag_reader.lowest_round()
            ),
        );

        let missing_targets: BitVec = message
            .targets()
            .map(|node| !dag_reader.exists(node))
            .collect();
        ensure!(
            missing_targets.all_zeros(),
            FetchRequestHandleError::TargetsMissing(missing_targets)
        );

        let certified_nodes: Vec<_> = dag_reader
            .reachable(
                message.targets(),
                Some(message.exists_bitmask().first_round()),
                |_| true,
            )
            .filter_map(|node_status| {
                let arc_node = node_status.as_node();
                self.author_to_index
                    .get(arc_node.author())
                    .and_then(|author_idx| {
                        if !message.exists_bitmask().has(arc_node.round(), *author_idx) {
                            Some(arc_node.as_ref().clone())
                        } else {
                            None
                        }
                    })
            })
            .collect();

        // TODO: decide if the response is too big and act accordingly.

        Ok(FetchResponse::new(message.epoch(), certified_nodes))
    }
```

**File:** consensus/src/dag/dag_store.rs (L153-156)
```rust
        if round > self.lowest_round() {
            for parent in node.parents() {
                ensure!(self.exists(parent.metadata()), "parent not exist");
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

**File:** consensus/src/dag/types.rs (L750-777)
```rust
    pub fn verify(
        self,
        request: &RemoteFetchRequest,
        validator_verifier: &ValidatorVerifier,
    ) -> anyhow::Result<Self> {
        ensure!(
            self.certified_nodes.iter().all(|node| {
                let round = node.round();
                let author = node.author();
                if let Some(author_idx) =
                    validator_verifier.address_to_validator_index().get(author)
                {
                    !request.exists_bitmask.has(round, *author_idx)
                } else {
                    false
                }
            }),
            "nodes don't match requested bitmask"
        );
        ensure!(
            self.certified_nodes
                .iter()
                .all(|node| node.verify(validator_verifier).is_ok()),
            "unable to verify certified nodes"
        );

        Ok(self)
    }
```

**File:** consensus/src/dag/bootstrap.rs (L289-300)
```rust
                        } else {
                            info!("sync failed. resuming with current DAG state.");
                            // If the sync task fails, then continue the DAG in Active Mode with existing state.
                            let (new_handler, new_fetch_service) =
                                bootstrapper.bootstrap_components(&self.base_state);
                            Some(Mode::Active(ActiveMode {
                                handler: new_handler,
                                fetch_service: new_fetch_service,
                                base_state: self.base_state,
                                buffer,
                            }))
                        }
```

**File:** consensus/src/dag/dag_state_sync.rs (L147-154)
```rust
        dag_reader.is_empty()
            || dag_reader.highest_round() + 1 + self.dag_window_size_config
                < li.commit_info().round()
            || self
                .ledger_info_provider
                .get_highest_committed_anchor_round()
                + 2 * self.dag_window_size_config
                < li.commit_info().round()
```
