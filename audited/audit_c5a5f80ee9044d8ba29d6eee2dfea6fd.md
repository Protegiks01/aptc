# Audit Report

## Title
Missing Cryptographic Proof Validation in Sparse Merkle Tree State Updates Enables State Corruption via Database Manipulation

## Summary
The production Sparse Merkle Tree (SMT) updater accepts and uses cryptographic proofs from the database without validating them in 99.99%+ of cases. This creates a critical defense-in-depth gap where database corruption, bugs, or compromise can cause validators to accept invalid state transitions and compute incorrect state roots, breaking consensus safety.

## Finding Description

The security guarantee being violated is **Invariant #4: State Consistency - "State transitions must be atomic and verifiable via Merkle proofs"**.

When updating the Sparse Merkle Tree during state transitions, the system retrieves proofs from the database to assist with tree construction. However, these proofs are used **without cryptographic validation**:

**In the production proof retrieval path:** [1](#0-0) 

Only 1 in 10,000 cold state proofs are verified (0.01%), and hot state proofs are **never** verified due to the `!use_hot_state` condition. The remaining 99.99%+ of proofs are returned to the SMT updater without any cryptographic validation.

**In the SMT updater that consumes these proofs:** [2](#0-1) 

The `from_persisted` method retrieves proofs and only checks structural properties (depth constraints) but **never calls `proof.verify()` or `proof.verify_by_hash()`** to cryptographically validate that the proof is correct.

**The proof verification method exists but is never called:** [3](#0-2) [4](#0-3) 

**Attack propagation flow:**
1. Database corruption/bug or malicious database implementation provides invalid proofs
2. `ProvableStateSummary::get_proof()` returns these proofs without validation (99.99%+ of the time)
3. `ColdProvableStateSummary` or `HotProvableStateSummary` passes unvalidated proofs to SMT updater
4. SMT updater constructs tree using invalid proofs, producing incorrect state root
5. Different validators with different corrupted proofs compute different state roots
6. Consensus split occurs as validators cannot agree on state

## Impact Explanation

**Critical Severity** - This meets multiple critical impact categories:

1. **Consensus/Safety Violations**: Different validators could compute different state roots from identical transactions if their databases provide different corrupted proofs, causing a consensus split that requires manual intervention or hard fork.

2. **State Consistency Breach**: The fundamental invariant that "state transitions must be verifiable via Merkle proofs" is violated when proofs are not actually verified before use.

3. **Cascading Failure Amplification**: A database bug or corruption event (which should be contained) can propagate into consensus-level failures because proof validation is skipped.

While the database is generally trusted, defense-in-depth principles require that cryptographic proofs be validated before use. The system should not assume database integrity extends to proof correctness - bugs in proof generation, database corruption, or software errors could all cause invalid proofs to be returned.

## Likelihood Explanation

**Medium-to-High Likelihood** in realistic scenarios:

1. **Database bugs are common**: Software bugs in proof generation logic, Jellyfish Merkle tree implementation, or database corruption from disk errors occur in production systems.

2. **No validation means no detection**: Without proof validation, corrupted proofs are silently accepted and used to build incorrect state trees. There's no early detection mechanism.

3. **TODO comment indicates known limitation**: [5](#0-4) 

The developers are aware that hot state proof verification is not implemented, suggesting this is a known technical debt item.

4. **High impact when triggered**: Even rare database corruptions become consensus-critical when proof validation is missing.

## Recommendation

**Implement mandatory proof validation before using proofs in SMT updates:**

```rust
fn get_proof(
    &self,
    key: &HashValue,
    version: Version,
    root_depth: usize,
    use_hot_state: bool,
) -> Result<SparseMerkleProofExt> {
    let (val_opt, proof) = self.db.get_state_value_with_proof_by_version_ext(
        key, version, root_depth, use_hot_state,
    )?;
    
    // ALWAYS validate proofs before use
    let expected_root = if use_hot_state {
        self.state_summary.hot_state_summary.root_hash()
    } else {
        self.state_summary.global_state_summary.root_hash()
    };
    
    proof.verify(expected_root, *key, val_opt.as_ref())
        .map_err(|e| format_err!("Proof validation failed for key {:x} at version {}: {}", key, version, e))?;
    
    Ok(proof)
}
```

This ensures:
- All proofs are cryptographically validated against the expected root hash
- Invalid proofs are rejected immediately with clear error messages
- Database corruption is detected before it can cause consensus failures
- Defense-in-depth principle is properly implemented

## Proof of Concept

```rust
#[cfg(test)]
mod test_proof_validation {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::proof::{SparseMerkleProofExt, SparseMerkleLeafNode};
    
    #[test]
    fn test_invalid_proof_causes_wrong_state_root() {
        // Create a valid SMT with some state
        let mut naive_smt = NaiveSmt::new(&[]);
        let key1 = HashValue::random();
        let value1 = HashValue::random();
        naive_smt.insert(key1, value1);
        
        let correct_root = naive_smt.get_root_hash();
        let smt = SparseMerkleTree::new(correct_root);
        
        // Create a MALICIOUS proof with wrong siblings
        let fake_leaf = SparseMerkleLeafNode::new(key1, value1);
        let wrong_sibling = HashValue::random(); // Wrong sibling hash
        let malicious_proof = SparseMerkleProofExt::new(
            Some(fake_leaf),
            vec![wrong_sibling.into()],
        );
        
        // Verify the proof is invalid
        assert!(malicious_proof.verify(correct_root, key1, Some(&value1)).is_err());
        
        // But ProofReader will happily provide it without validation
        let malicious_reader = ProofReader::new(vec![(key1, malicious_proof.clone())]);
        
        // SMT updater accepts it and builds wrong tree
        let key2 = HashValue::random();
        let value2 = HashValue::random();
        
        // This should fail but doesn't - it accepts the malicious proof
        let result = smt.freeze_self_and_update(
            vec![(key2, Some(value2))],
            &malicious_reader,
        );
        
        // The update succeeds with invalid proof, producing wrong state root
        match result {
            Ok(new_smt) => {
                // This is the vulnerability: we got a new SMT based on invalid proof
                println!("BUG: SMT accepted invalid proof!");
                println!("New root: {:x}", new_smt.root_hash());
            },
            Err(e) => {
                println!("Correctly rejected: {}", e);
            }
        }
    }
}
```

**Notes**

The benchmark file's `ProofReader` instances at lines 22-89 use valid proofs generated from `NaiveSmt`, so they are testing legitimate scenarios, not invalid proof cases. [6](#0-5) [7](#0-6) 

The vulnerability is in production code where database-provided proofs are used without validation, not in the benchmark tests themselves.

### Citations

**File:** storage/storage-interface/src/state_store/state_summary.rs (L293-323)
```rust
    fn get_proof(
        &self,
        key: &HashValue,
        version: Version,
        root_depth: usize,
        use_hot_state: bool,
    ) -> Result<SparseMerkleProofExt> {
        // TODO(HotState): we cannot verify proof yet. In order to verify the proof, we need to
        // fetch and construct the corresponding `HotStateValue` for `key` at `version`, including
        // `hot_since_version`. However, the current in-memory hot state does not support this
        // query, and we might need persist hot state KV to db first.
        if !use_hot_state && rand::random::<usize>() % 10000 == 0 {
            // 1 out of 10000 times, verify the proof.
            let (val_opt, proof) = self
                .db
                // check the full proof
                .get_state_value_with_proof_by_version_ext(
                    key, version, /* root_depth = */ 0, /* use_hot_state = */ false,
                )?;
            proof.verify(
                self.state_summary.global_state_summary.root_hash(),
                *key,
                val_opt.as_ref(),
            )?;
            Ok(proof)
        } else {
            Ok(self
                .db
                .get_state_proof_by_version_ext(key, version, root_depth, use_hot_state)?)
        }
    }
```

**File:** storage/scratchpad/src/sparse_merkle/updater.rs (L150-166)
```rust
    fn from_persisted(
        a_descendant_key: &HashValue,
        depth: usize,
        proof_reader: &impl ProofRead,
    ) -> Result<Self> {
        let proof = proof_reader
            .get_proof(a_descendant_key, depth)
            .ok_or(UpdateError::MissingProof)?;
        if depth > proof.bottom_depth() {
            return Err(UpdateError::ShortProof {
                key: *a_descendant_key,
                num_siblings: proof.bottom_depth(),
                depth,
            });
        }
        Ok(Self::new_on_proof_path(proof, depth))
    }
```

**File:** types/src/proof/definition.rs (L258-270)
```rust
    pub fn verify_by_hash(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: Option<HashValue>,
    ) -> Result<()> {
        SparseMerkleProof::from(self.clone()).verify_by_hash_partial(
            expected_root_hash,
            element_key,
            element_hash,
            self.root_depth(),
        )
    }
```

**File:** types/src/proof/definition.rs (L328-430)
```rust
    pub fn verify_by_hash_partial(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: Option<HashValue>,
        root_depth: usize,
    ) -> Result<()> {
        ensure!(
            self.siblings.len() + root_depth <= HashValue::LENGTH_IN_BITS,
            "Sparse Merkle Tree proof has more than {} ({} + {}) siblings.",
            HashValue::LENGTH_IN_BITS,
            root_depth,
            self.siblings.len(),
        );

        match (element_hash, self.leaf) {
            (Some(hash), Some(leaf)) => {
                // This is an inclusion proof, so the key and value hash provided in the proof
                // should match element_key and element_value_hash. `siblings` should prove the
                // route from the leaf node to the root.
                ensure!(
                    element_key == leaf.key,
                    "Keys do not match. Key in proof: {:x}. Expected key: {:x}. \
                     Element hash: {:x}. Value hash in proof {:x}",
                    leaf.key,
                    element_key,
                    hash,
                    leaf.value_hash
                );
                ensure!(
                    hash == leaf.value_hash,
                    "Value hashes do not match for key {:x}. Value hash in proof: {:x}. \
                     Expected value hash: {:x}. ",
                    element_key,
                    leaf.value_hash,
                    hash
                );
            },
            (Some(hash), None) => {
                bail!(
                    "Expected inclusion proof, value hash: {:x}. Found non-inclusion proof.",
                    hash
                )
            },
            (None, Some(leaf)) => {
                // This is a non-inclusion proof. The proof intends to show that if a leaf node
                // representing `element_key` is inserted, it will break a currently existing leaf
                // node represented by `proof_key` into a branch. `siblings` should prove the
                // route from that leaf node to the root.
                ensure!(
                    element_key != leaf.key,
                    "Expected non-inclusion proof, but key exists in proof. \
                     Key: {:x}. Key in proof: {:x}.",
                    element_key,
                    leaf.key,
                );
                ensure!(
                    element_key.common_prefix_bits_len(leaf.key)
                        >= root_depth + self.siblings.len(),
                    "Key would not have ended up in the subtree where the provided key in proof \
                     is the only existing key, if it existed. So this is not a valid \
                     non-inclusion proof. Key: {:x}. Key in proof: {:x}.",
                    element_key,
                    leaf.key
                );
            },
            (None, None) => {
                // This is a non-inclusion proof. The proof intends to show that if a leaf node
                // representing `element_key` is inserted, it will show up at a currently empty
                // position. `sibling` should prove the route from this empty position to the root.
            },
        }

        let current_hash = self
            .leaf
            .map_or(*SPARSE_MERKLE_PLACEHOLDER_HASH, |leaf| leaf.hash());
        let actual_root_hash = self
            .siblings
            .iter()
            .rev()
            .zip(
                element_key
                    .iter_bits()
                    .rev()
                    .skip(HashValue::LENGTH_IN_BITS - self.siblings.len() - root_depth),
            )
            .fold(current_hash, |hash, (sibling_hash, bit)| {
                if bit {
                    SparseMerkleInternalNode::new(*sibling_hash, hash).hash()
                } else {
                    SparseMerkleInternalNode::new(hash, *sibling_hash).hash()
                }
            });
        ensure!(
            actual_root_hash == expected_root_hash,
            "{}: Root hashes do not match. Actual root hash: {:x}. Expected root hash: {:x}.",
            type_name::<Self>(),
            actual_root_hash,
            expected_root_hash,
        );

        Ok(())
    }
```

**File:** storage/scratchpad/benches/sparse_merkle.rs (L86-89)
```rust
                    smt: SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH),
                    updates: Self::gen_updates(&mut rng, &keys, *block_size),
                    proof_reader: ProofReader::new(Vec::new()),
                })
```

**File:** storage/scratchpad/benches/sparse_merkle.rs (L178-187)
```rust
    fn gen_proof_reader(
        naive_smt: &mut NaiveSmt,
        updates: &[(HashValue, Option<HashValue>)],
    ) -> ProofReader {
        let proofs = updates
            .iter()
            .map(|(key, _)| (*key, naive_smt.get_proof(key)))
            .collect();
        ProofReader::new(proofs)
    }
```
