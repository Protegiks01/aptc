# Audit Report

## Title
Missing Cryptographic Validation on Node Deserialization Enables Consensus Failure from Database Corruption

## Summary
The `NodeSchema` and `CertifiedNodeSchema` deserialization functions do not validate cryptographic signatures or structural integrity when loading nodes from the consensus database. This allows corrupted nodes to be loaded into the DAG consensus protocol, potentially causing consensus divergence, Byzantine behavior, or validator liveness failures.

## Finding Description

The DAG consensus protocol stores `Node` and `CertifiedNode` objects in RocksDB through schema definitions. When deserializing these objects, the code performs only BCS (Binary Canonical Serialization) decoding without any cryptographic validation. [1](#0-0) 

When a validator restarts or recovers from a crash, it loads the pending node to resume broadcasting: [2](#0-1) 

The loaded node is used directly in `broadcast_node()` without any validation. Similarly, when reconstructing the DAG store on startup, certified nodes are loaded from storage: [3](#0-2) 

The `add_node()` function only performs structural validation through `validate_new_node()`, which does NOT verify cryptographic signatures: [4](#0-3) [5](#0-4) 

In contrast, nodes received over the network ARE validated with full signature verification: [6](#0-5) 

The `CertifiedNode::verify()` and `Node::verify()` methods exist but are never called on deserialized data: [7](#0-6) [8](#0-7) 

**Attack Scenarios:**

1. **Database Corruption**: If the RocksDB storage becomes corrupted (disk errors, software bugs, crash during write), a `Node` could have:
   - Invalid digest not matching its content
   - Corrupted parent references pointing to non-existent nodes
   - Inconsistent round/epoch/author combinations

2. **Malicious Database Modification**: If an attacker gains filesystem access, they could modify persisted nodes to:
   - Change transaction payloads
   - Alter parent pointers to fork the DAG
   - Modify digests while maintaining BCS-valid structure

3. **Certified Node Signature Bypass**: Corrupted `CertifiedNode` objects with invalid aggregate signatures would be loaded into the DAG and participate in ordering decisions, violating consensus safety.

When corrupted nodes are loaded, the validator will:
- Broadcast invalid nodes to peers (who will reject them)
- Make ordering decisions based on corrupted DAG structure
- Potentially diverge from honest validators in committed transaction order
- Experience liveness failures if the corrupted state prevents round progression

## Impact Explanation

This vulnerability breaks the **Cryptographic Correctness** and **Consensus Safety** invariants:

- **Consensus Safety Violation**: Corrupted nodes in the DAG can cause different validators to make different ordering decisions, violating the fundamental consensus guarantee that all honest validators agree on transaction order
- **State Inconsistency**: Validators with corrupted storage will have different DAG states than honest validators, requiring manual intervention to recover
- **Byzantine Behavior**: A validator with corrupted storage will broadcast invalid nodes, appearing Byzantine to other validators

**Severity Assessment**: **Medium to High**
- Requires database corruption as a precondition (not directly exploitable without privileged access)
- Can cause consensus divergence requiring manual intervention (Medium per Aptos bounty: "State inconsistencies requiring intervention")
- Could escalate to High if corruption causes validator node slowdowns or significant protocol violations
- Defense-in-depth violation: cryptographically signed data should always be validated, even from trusted storage

## Likelihood Explanation

**Likelihood: Medium**

Database corruption can occur through:
- **Hardware failures**: Disk errors, power loss during writes, memory corruption
- **Software bugs**: RocksDB bugs, kernel bugs, filesystem corruption
- **Crash timing**: Validator crashes during database write operations
- **Malicious access**: Requires privileged filesystem access (less likely but possible through other vulnerabilities)

While database corruption is not a daily occurrence, it is a realistic failure mode for production systems. The lack of validation means the system fails **unsafely** rather than detecting and rejecting corrupted data. This violates defense-in-depth principles: even trusted storage should be validated when it contains cryptographically signed data critical to consensus correctness.

## Recommendation

Add cryptographic validation when deserializing nodes from the database. Implement validation in the deserialization path or immediately after loading:

**Option 1: Validate immediately after deserialization**

```rust
// In consensus/src/dag/adapter.rs
impl DAGStorage for StorageAdapter {
    fn get_pending_node(&self) -> anyhow::Result<Option<Node>> {
        if let Some(node) = self.consensus_db.get::<NodeSchema>(&())? {
            // Validate digest integrity
            ensure!(
                node.digest() == node.calculate_digest(),
                "Pending node has invalid digest - database corruption detected"
            );
            Ok(Some(node))
        } else {
            Ok(None)
        }
    }

    fn get_certified_nodes(&self) -> anyhow::Result<Vec<(HashValue, CertifiedNode)>> {
        let nodes = self.consensus_db.get_all::<CertifiedNodeSchema>()?;
        // Validate each certified node
        for (digest, node) in &nodes {
            node.verify(&self.epoch_state.verifier)
                .context("Certified node signature validation failed - database corruption")?;
            ensure!(
                digest == node.metadata().digest(),
                "Digest mismatch in certified node storage"
            );
        }
        Ok(nodes)
    }
}
```

**Option 2: Validate in dag_driver.rs before use**

```rust
// In consensus/src/dag/dag_driver.rs, line 90-92
let pending_node = storage
    .get_pending_node()
    .expect("should be able to read dag storage");

// Add validation before use
if let Some(node) = &pending_node {
    ensure!(
        node.digest() == node.calculate_digest(),
        "Pending node digest validation failed"
    );
}
```

**Option 3: Add validation to DagStore initialization**

```rust
// In consensus/src/dag/dag_store.rs, line 472
for (digest, certified_node) in all_nodes {
    // Validate cryptographic integrity before adding
    if let Err(e) = certified_node.verify(&epoch_state.verifier) {
        error!("Certified node failed signature verification: {}", e);
        to_prune.push(digest);
        continue;
    }
    
    if let Err(e) = dag.add_node(certified_node) {
        debug!("Delete node after bootstrap due to {}", e);
        to_prune.push(digest);
    }
}
```

The recommended approach is **Option 3** combined with **Option 1** to provide defense-in-depth at both the storage layer and the usage layer.

## Proof of Concept

```rust
// Proof of Concept: Demonstrating that corrupted nodes can be loaded without validation
// This would be a test in consensus/src/dag/tests/

#[tokio::test]
async fn test_corrupted_node_loads_without_validation() {
    use crate::dag::types::{Node, NodeMetadata};
    use crate::consensusdb::{NodeSchema, ConsensusDB};
    use aptos_consensus_types::common::Payload;
    use aptos_crypto::HashValue;
    use tempfile::TempDir;
    
    // Setup: Create a valid node
    let epoch = 1;
    let round = 5;
    let author = Author::random();
    let timestamp = 12345;
    let payload = Payload::empty(false, false);
    let parents = vec![];
    let extensions = Extensions::empty();
    
    let valid_node = Node::new(
        epoch, round, author, timestamp,
        vec![], payload.clone(), parents.clone(), extensions.clone()
    );
    
    // Save the valid node to database
    let tmp_dir = TempDir::new().unwrap();
    let db = ConsensusDB::new(&tmp_dir.path()).unwrap();
    db.put::<NodeSchema>(&(), &valid_node).unwrap();
    
    // Corrupt the node by manually constructing one with wrong digest
    let corrupted_node = Node {
        metadata: NodeMetadata::new_for_test(
            epoch, round, author, timestamp,
            HashValue::random()  // WRONG digest - doesn't match content
        ),
        validator_txns: vec![],
        payload: payload.clone(),
        parents: parents.clone(),
        extensions: extensions.clone(),
    };
    
    // Overwrite with corrupted node
    db.put::<NodeSchema>(&(), &corrupted_node).unwrap();
    
    // Load the corrupted node - THIS SHOULD FAIL BUT DOESN'T
    let loaded_node = db.get::<NodeSchema>(&()).unwrap().unwrap();
    
    // The loaded node has invalid digest
    assert_ne!(loaded_node.digest(), loaded_node.calculate_digest());
    
    // BUT: No validation error occurred during loading!
    // This corrupted node would be used in consensus, causing divergence
}
```

## Notes

This vulnerability represents a **defense-in-depth failure** rather than a direct exploit. While the database is typically trusted storage, cryptographically signed consensus-critical data should always be validated to detect corruption from any source (hardware failure, software bugs, or malicious modification). The lack of validation means the system fails unsafely when corruption occurs, potentially causing consensus divergence rather than gracefully detecting and recovering from the corrupted state.

The fix is straightforward: call the existing `verify()` methods on nodes loaded from storage, just as is done for nodes received over the network.

### Citations

**File:** consensus/src/consensusdb/schema/dag/mod.rs (L40-42)
```rust
    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
```

**File:** consensus/src/dag/dag_driver.rs (L90-128)
```rust
        let pending_node = storage
            .get_pending_node()
            .expect("should be able to read dag storage");
        let highest_strong_links_round =
            dag.read().highest_strong_links_round(&epoch_state.verifier);

        let driver = Self {
            author,
            epoch_state,
            dag,
            payload_client,
            reliable_broadcast,
            time_service,
            rb_handles: Mutex::new(BoundedVecDeque::new(window_size_config as usize)),
            storage,
            order_rule,
            fetch_requester,
            ledger_info_provider,
            round_state,
            window_size_config,
            payload_config,
            health_backoff,
            quorum_store_enabled,
            allow_batches_without_pos_in_proposal,
        };

        // If we were broadcasting the node for the round already, resume it
        if let Some(node) =
            pending_node.filter(|node| node.round() == highest_strong_links_round + 1)
        {
            debug!(
                LogSchema::new(LogEvent::NewRound).round(node.round()),
                "Resume round"
            );
            driver
                .round_state
                .set_current_round(node.round())
                .expect("must succeed");
            driver.broadcast_node(node);
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

**File:** consensus/src/dag/dag_store.rs (L461-477)
```rust
        let mut all_nodes = storage.get_certified_nodes().unwrap_or_default();
        all_nodes.sort_unstable_by_key(|(_, node)| node.round());
        let mut to_prune = vec![];
        // Reconstruct the continuous dag starting from start_round and gc unrelated nodes
        let dag = Self::new_empty(
            epoch_state,
            storage.clone(),
            payload_manager,
            start_round,
            window_size,
        );
        for (digest, certified_node) in all_nodes {
            // TODO: save the storage call in this case
            if let Err(e) = dag.add_node(certified_node) {
                debug!("Delete node after bootstrap due to {}", e);
                to_prune.push(digest);
            }
```

**File:** consensus/src/dag/dag_store.rs (L518-536)
```rust
    pub fn add_node(&self, node: CertifiedNode) -> anyhow::Result<()> {
        self.dag.write().validate_new_node(&node)?;

        // Note on concurrency: it is possible that a prune operation kicks in here and
        // moves the window forward making the `node` stale. Any stale node inserted
        // due to this race will be cleaned up with the next prune operation.

        // mutate after all checks pass
        self.storage.save_certified_node(&node)?;

        debug!("Added node {}", node.id());
        self.payload_manager.prefetch_payload_data(
            node.payload(),
            *node.author(),
            node.metadata().timestamp(),
        );

        self.dag.write().add_validated_node(node)
    }
```

**File:** consensus/src/dag/dag_handler.rs (L99-104)
```rust
                        .and_then(|dag_message: DAGMessage| {
                            monitor!(
                                "dag_message_verify",
                                dag_message.verify(rpc_request.sender, &epoch_state.verifier)
                            )?;
                            Ok(dag_message)
```

**File:** consensus/src/dag/types.rs (L301-345)
```rust
    pub fn verify(&self, sender: Author, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            sender == *self.author(),
            "Author {} doesn't match sender {}",
            self.author(),
            sender
        );
        // TODO: move this check to rpc process logic to delay it as much as possible for performance
        ensure!(self.digest() == self.calculate_digest(), "invalid digest");

        let node_round = self.metadata().round();

        ensure!(node_round > 0, "current round cannot be zero");

        if node_round == 1 {
            ensure!(self.parents().is_empty(), "invalid parents for round 1");
            return Ok(());
        }

        let prev_round = node_round - 1;
        // check if the parents' round is the node's round - 1
        ensure!(
            self.parents()
                .iter()
                .all(|parent| parent.metadata().round() == prev_round),
            "invalid parent round"
        );

        // Verification of the certificate is delayed until we need to fetch it
        ensure!(
            verifier
                .check_voting_power(
                    self.parents()
                        .iter()
                        .map(|parent| parent.metadata().author()),
                    true,
                )
                .is_ok(),
            "not enough parents to satisfy voting power"
        );

        // TODO: validate timestamp

        Ok(())
    }
```

**File:** consensus/src/dag/types.rs (L438-442)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(self.digest() == self.calculate_digest(), "invalid digest");

        Ok(verifier.verify_multi_signatures(self.metadata(), self.signatures())?)
    }
```
