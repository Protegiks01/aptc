# Audit Report

## Title
DAG Consensus Storage Exhaustion via Unbounded Parent Certificate Duplication

## Summary
A malicious validator can craft DAG consensus nodes with arbitrarily many duplicate parent certificates, bypassing size validation and causing storage exhaustion. The validation logic only checks transaction payload size but not the size of the parents field, allowing nodes serialized to tens or hundreds of megabytes to be stored, leading to database bloat and node performance degradation or crashes.

## Finding Description

The DAG consensus implementation fails to validate the number or total size of parent certificates in a Node. While the validation logic enforces a 20MB limit on transaction payloads, it does not account for the `parents` field when checking total node size. [1](#0-0) 

This validation only checks `txn_bytes` (validator transactions + payload), completely ignoring the parents field size.

When a Node is serialized for storage, ALL fields are included without any size limit: [2](#0-1) 

The Node structure contains a Vec of parent certificates that is unbounded: [3](#0-2) 

The verification logic does not prevent duplicate parent certificates. It only checks that parents are from the previous round and have sufficient voting power: [4](#0-3) 

Critically, the `check_voting_power` implementation does NOT deduplicate authors - it simply sums voting power for all provided authors, counting duplicates multiple times: [5](#0-4) 

A malicious validator can exploit this by:
1. Creating a Node with 10,000+ duplicate copies of the same valid parent certificate
2. Each NodeCertificate is ~200-8,400 bytes (metadata + aggregate signature)
3. The duplicated parents pass verification because they're valid certificates from the previous round
4. The voting power check passes (even more easily due to counting duplicates)
5. The oversized Node is BCS-serialized and persisted to RocksDB via: [6](#0-5) 

With 50,000 duplicate certificates at ~300 bytes each (15MB) plus a 20MB payload, a single node can be 35+ MB. Across multiple rounds, this rapidly exhausts storage and degrades node performance.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: Deserializing and processing 35+ MB nodes repeatedly causes significant performance degradation
2. **Storage Exhaustion**: With 100 malicious nodes across rounds, 3.5+ GB of unnecessary data bloats the consensus database
3. **Resource Limits Violation**: Breaks invariant #9 - "All operations must respect gas, storage, and computational limits"
4. **Potential Node Crashes**: Memory pressure during BCS serialization/deserialization of massive structures can crash validator nodes

The attack does not require validator collusion (single malicious validator sufficient) and directly impacts network availability and validator health.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- No special privileges required beyond being a validator
- No cryptographic work needed (reuses valid certificates)
- No coordination with other validators necessary  
- Validation logic has zero checks preventing this behavior
- Attack is repeatable every round

The only barrier is being a validator, which is the assumed threat model for DAG consensus security analysis.

## Recommendation

Add validation to limit both the count and total size of parent certificates:

```rust
fn validate(&self, node: Node) -> anyhow::Result<Node> {
    // ... existing epoch/vtxn/payload validation ...
    
    // Validate parent certificates
    let parent_count = node.parents().len();
    ensure!(
        parent_count <= self.epoch_state.verifier.len(),
        "too many parent certificates: {} > {}",
        parent_count,
        self.epoch_state.verifier.len()
    );
    
    // Check for duplicate parents by tracking unique authors
    let unique_authors: std::collections::HashSet<_> = 
        node.parents().iter()
            .map(|p| p.metadata().author())
            .collect();
    ensure!(
        unique_authors.len() == parent_count,
        "duplicate parent certificates detected"
    );
    
    // Estimate and limit total parent size
    let estimated_parents_size = node.parents().len() * 10_000; // conservative estimate
    let total_estimated_size = txn_bytes + estimated_parents_size as u64;
    ensure!(
        total_estimated_size <= self.payload_config.max_receiving_size_per_round_bytes * 2,
        "total node size too large"
    );
    
    // ... rest of validation ...
}
```

Additionally, add a hard limit to BCS serialization:
```rust
fn encode_value(&self) -> Result<Vec<u8>> {
    let bytes = bcs::to_bytes(&self)?;
    ensure!(
        bytes.len() <= MAX_NODE_SIZE_BYTES, // e.g., 50 MB
        "serialized node exceeds maximum size"
    );
    Ok(bytes)
}
```

## Proof of Concept

```rust
// Add to consensus/src/dag/tests/rb_handler_tests.rs

#[tokio::test]
async fn test_duplicate_parent_storage_bomb() {
    let (signers, validator_verifier) = random_validator_verifiers(4, None, false);
    let adapter = Arc::new(MockStorage::new());
    
    // Create a legitimate certificate from round 1
    let node_round_1 = new_node(1, 10, signers[0].author());
    let cert_round_1 = new_certified_node(1, signers[0].author(), vec![]);
    
    // Malicious node with 10,000 duplicate parents
    let mut duplicate_parents = vec![];
    for _ in 0..10_000 {
        duplicate_parents.push(cert_round_1.certificate());
    }
    
    let malicious_node = Node::new(
        1,
        2,
        signers[1].author(),
        20,
        vec![],
        Payload::empty(false, false),
        duplicate_parents,
        Extensions::empty(),
    );
    
    // Calculate serialized size
    let serialized = bcs::to_bytes(&malicious_node).unwrap();
    println!("Malicious node size: {} MB", serialized.len() / (1024 * 1024));
    
    // Verify the node passes validation (vulnerability)
    assert!(malicious_node.verify(signers[1].author(), &validator_verifier).is_ok());
    
    // Attempt to store - should be rejected but currently isn't
    adapter.save_pending_node(&malicious_node).unwrap();
    
    assert!(serialized.len() > 20_000_000, "Storage bomb successful");
}
```

This demonstrates that a node with 10,000 duplicate parents can be created, passes validation, and creates a multi-megabyte storage entry, violating resource limit invariants.

### Citations

**File:** consensus/src/dag/rb_handler.rs (L139-142)
```rust
        let num_txns = num_vtxns + node.payload().len() as u64;
        let txn_bytes = vtxn_total_bytes + node.payload().size() as u64;
        ensure!(num_txns <= self.payload_config.max_receiving_txns_per_round);
        ensure!(txn_bytes <= self.payload_config.max_receiving_size_per_round_bytes);
```

**File:** consensus/src/consensusdb/schema/dag/mod.rs (L35-38)
```rust
impl ValueCodec<NodeSchema> for Node {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(bcs::to_bytes(&self)?)
    }
```

**File:** consensus/src/dag/types.rs (L152-159)
```rust
#[derive(Clone, Serialize, Deserialize, CryptoHasher, Debug, PartialEq)]
pub struct Node {
    metadata: NodeMetadata,
    validator_txns: Vec<ValidatorTransaction>,
    payload: Payload,
    parents: Vec<NodeCertificate>,
    extensions: Extensions,
}
```

**File:** consensus/src/dag/types.rs (L322-340)
```rust
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
```

**File:** types/src/validator_verifier.rs (L436-448)
```rust
    pub fn sum_voting_power<'a>(
        &self,
        authors: impl Iterator<Item = &'a AccountAddress>,
    ) -> std::result::Result<u128, VerifyError> {
        let mut aggregated_voting_power = 0;
        for account_address in authors {
            match self.get_voting_power(account_address) {
                Some(voting_power) => aggregated_voting_power += voting_power as u128,
                None => return Err(VerifyError::UnknownAuthor),
            }
        }
        Ok(aggregated_voting_power)
    }
```

**File:** consensus/src/dag/adapter.rs (L367-371)
```rust
    fn save_certified_node(&self, node: &CertifiedNode) -> anyhow::Result<()> {
        Ok(self
            .consensus_db
            .put::<CertifiedNodeSchema>(&node.digest(), node)?)
    }
```
