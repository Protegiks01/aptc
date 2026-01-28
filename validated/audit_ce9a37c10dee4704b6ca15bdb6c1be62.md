# Audit Report

## Title
Integer Overflow Panic in SparseMerkleRangeProof Verification Causes Node Crash During State Synchronization

## Summary
The `SparseMerkleRangeProof::verify()` function lacks bounds checking on sibling counts before performing unsigned integer subtraction, allowing an attacker to trigger a deterministic panic in nodes during state synchronization by sending proofs with excessive sibling counts.

## Finding Description

The vulnerability exists in the `SparseMerkleRangeProof::verify()` function which processes Merkle range proofs received from network peers during state synchronization. [1](#0-0) 

**Missing Bounds Validation:**

Unlike `SparseMerkleProof::verify_by_hash_partial()` which explicitly validates that sibling counts do not exceed the hash bit length, [2](#0-1)  the `SparseMerkleRangeProof::verify()` function performs no such validation before the subtraction operation. [3](#0-2) 

**Integer Underflow with Panic:**

The code calculates `num_siblings = left_siblings.len() + self.right_siblings.len()` and then performs `.skip(HashValue::LENGTH_IN_BITS - num_siblings)`. If an attacker crafts a proof with `num_siblings > 256` (e.g., 300 right_siblings + 10 left_siblings = 310 total), the subtraction `256 - 310` will underflow. Since overflow checks are enabled in release builds, [4](#0-3)  this causes a panic rather than wrapping.

**Network Attack Surface:**

The vulnerable function is called during state restoration when processing `StateValueChunkWithProof` data received from network peers. [5](#0-4)  This data flows from the network through the state sync bootstrapper, [6](#0-5)  to the storage synchronizer, [7](#0-6)  and ultimately to the state restore module where verification occurs. [8](#0-7) 

**Exploitation Path:**
1. Attacker crafts a `StateValueChunkWithProof` containing a `SparseMerkleRangeProof` with excessive `right_siblings` (e.g., 300 HashValue elements)
2. The victim node receives this chunk during state synchronization
3. Only the `root_hash` field is validated, not sibling counts
4. The `verify()` function computes `num_siblings > 256`
5. The subtraction triggers an integer overflow panic
6. The node process crashes, halting state synchronization

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria:

**Validator Node Crashes:** The panic directly terminates validator and full node processes during state synchronization. This exceeds the "Validator node slowdowns" criterion—it's an outright crash, not degradation.

**Network Resilience Impact:** New nodes cannot complete initial state sync, and existing nodes attempting state snapshot restoration will crash. This degrades the network's ability to onboard new validators and recover from failures.

**Deterministic Exploitation:** The attack is completely deterministic—any malformed proof with excessive siblings will reliably trigger the crash on all affected nodes.

**No Authentication Barriers:** Any network peer participating in state sync can send malicious proofs. No special privileges are required beyond normal peer-to-peer communication during state synchronization.

This is NOT a traditional network DoS attack (which would be out of scope), but rather a protocol-level bug where malformed proof validation logic causes crashes—analogous to "malformed transaction crashes API nodes" which is explicitly HIGH severity.

## Likelihood Explanation

**Likelihood: High**

**Trivial Attack Complexity:** Creating the malicious proof requires only constructing a `SparseMerkleRangeProof` struct with an excessive vector of `right_siblings` values. This is straightforward for any attacker familiar with Rust serialization.

**Accessible Attack Surface:** The vulnerable code path executes during routine state synchronization, which all nodes must perform when joining the network or catching up after downtime.

**Pre-Validation Bypass:** While the bootstrapper validates the proof's `root_hash` field, it does not validate sibling vector lengths before passing the proof to the verification function.

**Deterministic and Reproducible:** The crash occurs 100% reliably with crafted inputs—there are no timing windows or race conditions.

**Broad Impact:** All node types performing state sync are vulnerable: validators, full nodes, and any light clients using state synchronization.

## Recommendation

Add bounds checking to `SparseMerkleRangeProof::verify()` before the subtraction operation:

```rust
pub fn verify(
    &self,
    expected_root_hash: HashValue,
    rightmost_known_leaf: SparseMerkleLeafNode,
    left_siblings: Vec<HashValue>,
) -> Result<()> {
    let num_siblings = left_siblings.len() + self.right_siblings.len();
    
    // Add bounds check similar to SparseMerkleProof::verify_by_hash_partial
    ensure!(
        num_siblings <= HashValue::LENGTH_IN_BITS,
        "Sparse Merkle Range proof has more than {} ({} left + {} right) siblings.",
        HashValue::LENGTH_IN_BITS,
        left_siblings.len(),
        self.right_siblings.len(),
    );
    
    // ... rest of existing verification logic
}
```

## Proof of Concept

```rust
#[test]
fn test_sparse_merkle_range_proof_excessive_siblings() {
    use aptos_crypto::HashValue;
    use aptos_types::proof::{SparseMerkleRangeProof, SparseMerkleLeafNode};
    
    // Create a proof with excessive right siblings (300 > 256 limit)
    let excessive_siblings: Vec<HashValue> = (0..300)
        .map(|_| HashValue::random())
        .collect();
    
    let malicious_proof = SparseMerkleRangeProof::new(excessive_siblings);
    
    // Create dummy leaf and left siblings
    let leaf = SparseMerkleLeafNode::new(
        HashValue::random(),
        HashValue::random(),
    );
    let left_siblings: Vec<HashValue> = (0..10)
        .map(|_| HashValue::random())
        .collect();
    
    // This will panic with integer overflow in release builds
    // due to: 256 - (300 + 10) = 256 - 310 underflow
    let result = malicious_proof.verify(
        HashValue::random(),
        leaf,
        left_siblings,
    );
    
    // Expected: should return Err with bounds check violation
    // Actual: panics with overflow in current implementation
    assert!(result.is_err());
}
```

**Notes:**
- This vulnerability is a protocol-level bug, not a traditional network DoS attack
- The missing bounds check creates a trivially exploitable crash vector
- All nodes performing state synchronization are affected
- The fix is straightforward: add the same validation present in `SparseMerkleProof::verify_by_hash_partial()`

### Citations

**File:** types/src/proof/definition.rs (L335-341)
```rust
        ensure!(
            self.siblings.len() + root_depth <= HashValue::LENGTH_IN_BITS,
            "Sparse Merkle Tree proof has more than {} ({} + {}) siblings.",
            HashValue::LENGTH_IN_BITS,
            root_depth,
            self.siblings.len(),
        );
```

**File:** types/src/proof/definition.rs (L782-827)
```rust
    pub fn verify(
        &self,
        expected_root_hash: HashValue,
        rightmost_known_leaf: SparseMerkleLeafNode,
        left_siblings: Vec<HashValue>,
    ) -> Result<()> {
        let num_siblings = left_siblings.len() + self.right_siblings.len();
        let mut left_sibling_iter = left_siblings.iter();
        let mut right_sibling_iter = self.right_siblings().iter();

        let mut current_hash = rightmost_known_leaf.hash();
        for bit in rightmost_known_leaf
            .key()
            .iter_bits()
            .rev()
            .skip(HashValue::LENGTH_IN_BITS - num_siblings)
        {
            let (left_hash, right_hash) = if bit {
                (
                    *left_sibling_iter
                        .next()
                        .ok_or_else(|| format_err!("Missing left sibling."))?,
                    current_hash,
                )
            } else {
                (
                    current_hash,
                    *right_sibling_iter
                        .next()
                        .ok_or_else(|| format_err!("Missing right sibling."))?,
                )
            };
            current_hash = SparseMerkleInternalNode::new(left_hash, right_hash).hash();
        }

        ensure!(
            current_hash == expected_root_hash,
            "{}: Root hashes do not match. Actual root hash: {:x}. Expected root hash: {:x}.",
            type_name::<Self>(),
            current_hash,
            expected_root_hash,
        );

        Ok(())
    }
}
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L690-696)
```rust
        proof
            .verify(
                self.expected_root_hash,
                SparseMerkleLeafNode::new(*previous_key, previous_leaf.value_hash()),
                left_siblings,
            )
            .map_err(Into::into)
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1021-1037)
```rust
        if state_value_chunk_with_proof.root_hash != expected_root_hash {
            self.reset_active_stream(Some(NotificationAndFeedback::new(
                notification_id,
                NotificationFeedback::InvalidPayloadData,
            )))
            .await?;
            return Err(Error::VerificationError(format!(
                "The states chunk with proof root hash: {:?} didn't match the expected hash: {:?}!",
                state_value_chunk_with_proof.root_hash, expected_root_hash,
            )));
        }

        // Process the state values chunk and proof
        let last_state_value_index = state_value_chunk_with_proof.last_index;
        if let Err(error) = self
            .storage_synchronizer
            .save_state_values(notification_id, state_value_chunk_with_proof)
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L872-881)
```rust
                StorageDataChunk::States(notification_id, states_with_proof) => {
                    // Commit the state value chunk
                    let all_states_synced = states_with_proof.is_last_chunk();
                    let last_committed_state_index = states_with_proof.last_index;
                    let num_state_values = states_with_proof.raw_values.len();

                    let result = state_snapshot_receiver.add_chunk(
                        states_with_proof.raw_values,
                        states_with_proof.proof.clone(),
                    );
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-244)
```rust
    fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
        let kv_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_add_chunk"]);
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk.clone())
        };

        let tree_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["jmt_add_chunk"]);
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)
```
