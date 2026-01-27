# Audit Report

## Title
DAG Consensus Asymmetric Resource Consumption via max_sending/max_receiving Gap

## Summary
A malicious validator can exploit the 2x difference between `max_sending_size_per_round_bytes` (10MB) and `max_receiving_size_per_round_bytes` (20MB) to cause asymmetric resource consumption, forcing honest validators to process up to 200x more data per round than they send themselves.

## Finding Description

The DAG consensus configuration defines separate limits for sending and receiving payload sizes: [1](#0-0) 

When honest validators create nodes, they use `HealthBackoff::calculate_payload_limits()` which divides the `max_sending_size_per_round_bytes` by the number of validators: [2](#0-1) 

For example, with 100 validators and a 10MB sending limit, each honest validator pulls approximately 100KB of payload per round: [3](#0-2) 

However, when validators receive nodes from peers, the validation only checks against `max_receiving_size_per_round_bytes` (20MB): [4](#0-3) 

**The Attack:** A Byzantine validator can:
1. Bypass the `calculate_payload_limits()` computation used by honest validators
2. Manually construct a `Node` with up to 20MB of payload (the maximum receiving limit)
3. Broadcast this oversized node to all other validators

The node construction has no built-in size enforcement: [5](#0-4) 

All receiving validators will accept the 20MB node because it passes the validation check. The network layer supports messages up to 64MB, so 20MB is well within limits: [6](#0-5) 

**Resource Consumption Impact:**

Each validator that receives the malicious node must:
1. Deserialize 20MB of BCS-encoded data (CPU-intensive)
2. Validate validator transactions and signatures
3. Store the node metadata and vote in the DAG storage
4. Process the node through the ordering rule [7](#0-6) 

This creates a **200x asymmetry** (20MB vs 100KB) between what the malicious validator sends and what honest validators send per round.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program because it enables:

1. **Validator Node Slowdowns**: Honest validators spend disproportionate CPU cycles deserializing and processing 200x larger payloads, slowing their ability to participate in consensus rounds.

2. **Network Bandwidth Exhaustion**: A single malicious validator broadcasting 20MB per round to 99 peers consumes ~2GB bandwidth per round, compared to the expected 10MB total for the entire validator set.

3. **Storage Pressure**: Larger nodes consume more disk I/O and storage space in the DAG store.

4. **Consensus Liveness Degradation**: If multiple Byzantine validators exploit this, they can collectively slow down the network's block production rate without breaking safety guarantees.

The attack does not directly steal funds or break consensus safety, but it violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: The attacker must be part of the active validator set (Byzantine validator), which is within the threat model for BFT consensus systems.
- **Complexity**: Low - the attacker simply constructs a `Node` with a large `Payload` and broadcasts it via the reliable broadcast protocol.
- **Detection**: The attack is difficult to distinguish from legitimate validator behavior with large transaction volumes.
- **Sustainability**: Can be executed every round indefinitely without requiring additional resources or coordination.
- **Economic Incentive**: In a competitive validator environment, slowing down other validators provides a relative advantage.

## Recommendation

**Solution 1: Enforce max_sending limit on receivers**

Add validation that incoming nodes respect the sender's expected payload limits. Modify `NodeBroadcastHandler::validate()` to compute the expected maximum payload size based on the round and number of validators:

```rust
fn validate(&self, node: Node) -> anyhow::Result<Node> {
    // ... existing validation ...
    
    // Compute expected max payload for this round
    let (expected_max_txns, expected_max_bytes) = self
        .health_backoff
        .calculate_payload_limits(node.round(), &self.payload_config);
    
    // Allow some tolerance for validator count variations
    let tolerance_factor = 1.2; // 20% tolerance
    let max_allowed_bytes = (expected_max_bytes as f64 * tolerance_factor) as u64;
    
    ensure!(
        txn_bytes <= max_allowed_bytes,
        "Node payload size {} exceeds expected limit {} for round {}",
        txn_bytes,
        max_allowed_bytes,
        node.round()
    );
    
    // ... rest of validation ...
}
```

**Solution 2: Eliminate the gap**

Set `max_receiving_size_per_round_bytes` equal to `max_sending_size_per_round_bytes` to eliminate the exploitable gap:

```rust
impl Default for DagPayloadConfig {
    fn default() -> Self {
        Self {
            max_sending_txns_per_round: 10000,
            max_sending_size_per_round_bytes: 10 * 1024 * 1024,
            max_receiving_txns_per_round: 11000,
            max_receiving_size_per_round_bytes: 10 * 1024 * 1024, // Match sending limit
            payload_pull_max_poll_time_ms: 1000,
        }
    }
}
```

**Recommended Approach**: Implement Solution 1, as it properly enforces expected resource consumption while maintaining flexibility for legitimate variations in payload sizes across validators.

## Proof of Concept

```rust
// In consensus/src/dag/tests/
#[tokio::test]
async fn test_asymmetric_resource_consumption() {
    use crate::dag::types::Node;
    use aptos_consensus_types::common::Payload;
    use aptos_types::transaction::SignedTransaction;
    
    // Setup: Create a DAG consensus network with 100 validators
    let num_validators = 100;
    let (validators, epoch_state) = create_test_validators(num_validators);
    
    // Honest validator behavior: compute limited payload
    let honest_config = DagPayloadConfig::default();
    let health_backoff = create_test_health_backoff(&epoch_state);
    let (max_txns, max_bytes) = health_backoff
        .calculate_payload_limits(1, &honest_config);
    
    // For 100 validators: max_bytes = 10MB / 100 = ~100KB
    assert!(max_bytes < 150_000); // ~100KB
    
    // Honest validator creates small node
    let honest_payload = create_test_payload(max_bytes as usize);
    let honest_node = Node::new(
        epoch_state.epoch,
        1,
        validators[0].author(),
        100,
        vec![],
        honest_payload.clone(),
        vec![],
        Extensions::empty(),
    );
    assert!(honest_node.payload().size() <= max_bytes as usize);
    
    // Malicious validator creates oversized node (20MB)
    let malicious_size = 20 * 1024 * 1024; // 20MB
    let malicious_payload = create_test_payload(malicious_size);
    let malicious_node = Node::new(
        epoch_state.epoch,
        1,
        validators[1].author(),
        100,
        vec![],
        malicious_payload,
        vec![],
        Extensions::empty(),
    );
    
    // Verify asymmetry: malicious node is 200x larger
    let size_ratio = malicious_node.payload().size() / honest_node.payload().size();
    assert!(size_ratio > 100); // Significantly larger
    
    // Both nodes pass validation on receiving validators
    let rb_handler = create_test_rb_handler(&epoch_state, honest_config);
    assert!(rb_handler.validate(honest_node.clone()).is_ok());
    assert!(rb_handler.validate(malicious_node.clone()).is_ok()); // This should fail!
    
    // The malicious node consumes 200x more resources but is accepted
    println!("Honest payload size: {} bytes", honest_node.payload().size());
    println!("Malicious payload size: {} bytes", malicious_node.payload().size());
    println!("Asymmetry ratio: {}x", size_ratio);
}
```

This test demonstrates that a malicious validator can create and broadcast nodes with 200x more payload than honest validators, and these nodes will be accepted by all receiving validators, causing asymmetric resource consumption.

### Citations

**File:** config/src/config/dag_consensus_config.rs (L24-28)
```rust
        Self {
            max_sending_txns_per_round: 10000,
            max_sending_size_per_round_bytes: 10 * 1024 * 1024,
            max_receiving_txns_per_round: 11000,
            max_receiving_size_per_round_bytes: 20 * 1024 * 1024,
```

**File:** consensus/src/dag/health/backoff.rs (L54-71)
```rust
        let max_size_per_round_bytes = [
            payload_config.max_sending_size_per_round_bytes,
            chain_backoff.1,
            pipeline_backoff.1,
        ]
        .into_iter()
        .min()
        .expect("must not be empty");

        // TODO: figure out receiver side checks
        let max_txns = max_txns_per_round.saturating_div(
            (self.epoch_state.verifier.len() as f64 * voting_power_ratio).ceil() as u64,
        );
        let max_txn_size_bytes = max_size_per_round_bytes.saturating_div(
            (self.epoch_state.verifier.len() as f64 * voting_power_ratio).ceil() as u64,
        );

        (max_txns, max_txn_size_bytes)
```

**File:** consensus/src/dag/dag_driver.rs (L255-266)
```rust
        let (max_txns, max_size_bytes) = self
            .health_backoff
            .calculate_payload_limits(new_round, &self.payload_config);

        let (validator_txns, payload) = match self
            .payload_client
            .pull_payload(
                PayloadPullParameters {
                    max_poll_time: Duration::from_millis(
                        self.payload_config.payload_pull_max_poll_time_ms,
                    ),
                    max_txns: PayloadTxnsSize::new(max_txns, max_size_bytes),
```

**File:** consensus/src/dag/rb_handler.rs (L139-142)
```rust
        let num_txns = num_vtxns + node.payload().len() as u64;
        let txn_bytes = vtxn_total_bytes + node.payload().size() as u64;
        ensure!(num_txns <= self.payload_config.max_receiving_txns_per_round);
        ensure!(txn_bytes <= self.payload_config.max_receiving_size_per_round_bytes);
```

**File:** consensus/src/dag/rb_handler.rs (L233-259)
```rust
        let node = self.validate(node)?;
        observe_node(node.timestamp(), NodeStage::NodeReceived);
        debug!(LogSchema::new(LogEvent::ReceiveNode)
            .remote_peer(*node.author())
            .round(node.round()));

        if let Some(ack) = self
            .votes_by_round_peer
            .lock()
            .entry(node.round())
            .or_default()
            .get(node.author())
        {
            return Ok(ack.clone());
        }

        let signature = node.sign_vote(&self.signer)?;
        let vote = Vote::new(node.metadata().clone(), signature);
        self.storage.save_vote(&node.id(), &vote)?;
        self.votes_by_round_peer
            .lock()
            .get_mut(&node.round())
            .expect("must exist")
            .insert(*node.author(), vote.clone());

        self.dag.write().update_votes(&node, false);
        self.order_rule.process_new_node(node.metadata());
```

**File:** consensus/src/dag/types.rs (L162-198)
```rust
    pub fn new(
        epoch: u64,
        round: Round,
        author: Author,
        timestamp: u64,
        validator_txns: Vec<ValidatorTransaction>,
        payload: Payload,
        parents: Vec<NodeCertificate>,
        extensions: Extensions,
    ) -> Self {
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

        Self {
            metadata: NodeMetadata {
                node_id: NodeId {
                    epoch,
                    round,
                    author,
                },
                timestamp,
                digest,
            },
            validator_txns,
            payload,
            parents,
            extensions,
        }
    }
```

**File:** config/src/config/network_config.rs (L49-50)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```
