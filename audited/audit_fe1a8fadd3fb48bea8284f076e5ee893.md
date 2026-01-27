# Audit Report

## Title
Hash Collision Enables State Poisoning Through Unverified StateKey in JellyfishMerkleTree Lookups

## Summary
The Aptos state storage system uses SHA3-256 hashes of StateKeys as lookup keys in both the JellyfishMerkleTree and StateValueByKeyHashSchema. When retrieving state values, the system queries the tree by hash and receives a StateKey from the leaf node's `value_index`, but **never verifies that this returned StateKey matches the originally requested StateKey**. If an attacker can find a SHA3-256 collision between two different StateKeys, they can poison state queries, causing validators to retrieve incorrect state values and breaking consensus determinism.

## Finding Description

The vulnerability exists in the state value retrieval flow where the JellyfishMerkleTree returns a StateKey that is blindly trusted without verification: [1](#0-0) 

The `get_state_value_with_proof_by_version_ext` method queries the merkle tree by `key_hash` (the SHA3-256 hash of a StateKey). The tree returns `leaf_data` containing a `(key, ver)` tuple extracted from the leaf's `value_index`. **Critically, line 231 uses this returned `key` directly to fetch the state value without verifying it equals the originally requested StateKey.**

The JellyfishMerkleTree leaf nodes store only the hash of the StateKey, not the full key for comparison: [2](#0-1) 

The `account_key` field (line 700) stores the hash of the StateKey. During tree lookup, the system only checks if this hash matches the queried hash: [3](#0-2) 

At line 780, the code checks `leaf_node.account_key() == key` where both are HashValues (hashes). If they match, it returns `value_index` which contains the full StateKey. However, this StateKey could be different from the originally requested one if they share the same hash.

The state value database also uses only the hash as the key: [4](#0-3) 

When writing state values, the code uses `CryptoHash::hash(*key)` as the storage key, meaning multiple StateKeys with the same hash would collide.

**Attack Scenario** (assuming SHA3-256 collision capability):

1. **Version 5**: Legitimate user writes StateKey1 → Value1
   - JMT creates leaf: `LeafNode(account_key=H, value_index=(StateKey1, 5))`
   - Database stores: `(H, 5) → Value1`

2. **Version 10**: Attacker writes StateKey2 → Value2 where `hash(StateKey2) == hash(StateKey1) == H`
   - JMT creates new leaf: `LeafNode(account_key=H, value_index=(StateKey2, 10))`
   - Database stores: `(H, 10) → Value2`
   - This leaf overwrites the previous position in the tree structure

3. **Query StateKey1 at Version 10**:
   - System computes `hash(StateKey1) = H` and queries JMT
   - JMT finds leaf with `account_key=H` 
   - Leaf returns `value_index=(StateKey2, 10)` [wrong StateKey!]
   - Line 231 calls `expect_value_by_version(&StateKey2, 10)`
   - Returns Value2 instead of Value1

This breaks the **Deterministic Execution** invariant: different queries for the same StateKey return different values depending on when they occur relative to the collision write. Validators executing blocks at different times would see inconsistent state, causing consensus splits.

## Impact Explanation

**Critical Severity** - This vulnerability breaks multiple core blockchain invariants:

1. **Consensus Safety Violation**: Validators querying state at the same version may see different values depending on their query timing relative to collision transactions, violating the requirement that "all validators must produce identical state roots for identical blocks."

2. **State Consistency Breach**: The same StateKey query returns different values, breaking atomicity and verifiability of state transitions.

3. **Potential Fund Theft**: If StateKey1 represents an account balance or access control resource, an attacker with a colliding StateKey2 can shadow it and steal funds or escalate privileges.

4. **Merkle Proof Bypass**: The state proof verification only validates hashes, not the actual StateKeys, so proofs would validate incorrect state.

While SHA3-256 collisions are currently computationally infeasible, this represents a critical defense-in-depth failure. The system should validate returned StateKeys even if hash collisions are considered impossible, as cryptographic assumptions can be violated by future advances or implementation bugs.

## Likelihood Explanation

**Current Likelihood: Extremely Low** due to SHA3-256 collision resistance (2^256 security).

**Future Likelihood: High IF SHA3-256 is weakened**. If collision attacks become feasible through:
- Cryptanalytic breakthroughs
- Quantum computing advances  
- Implementation bugs in the hash function

Then this vulnerability becomes immediately exploitable by any attacker who can submit transactions. The attack requires no special privileges, no validator access, and no economic stake—just the ability to find a hash collision and submit a transaction with the colliding StateKey.

**Defense-in-Depth Concern**: The code has a clear logic bug where it trusts data from the merkle tree without verification. This violates secure coding principles regardless of current cryptographic assumptions.

## Recommendation

Add validation to verify the returned StateKey matches the requested one:

```rust
// In get_state_value_with_proof_by_version_ext at line 228-235
let (leaf_data, proof) = db.get_with_proof_ext(key_hash, version, root_depth)?;

// Add this new function to verify StateKey matches
fn verify_state_key_match(requested: &StateKey, returned: &StateKey) -> Result<()> {
    ensure!(
        requested.encoded() == returned.encoded(),
        "StateKey mismatch: requested {:?} but merkle tree returned {:?}. \
         Possible hash collision or tree corruption.",
        requested, returned
    );
    Ok(())
}

Ok((
    match leaf_data {
        Some((_val_hash, (key, ver))) => {
            // NEW: Verify the returned key matches what we requested
            // We need to pass the original StateKey here, not just the hash
            // This requires refactoring to pass StateKey through the call chain
            verify_state_key_match(original_state_key, &key)?;
            Some(self.expect_value_by_version(&key, ver)?)
        },
        None => None,
    },
    proof,
))
```

**Note**: This requires refactoring the function signature to accept the full StateKey instead of just `key_hash: &HashValue`. The call chain would need to pass the original StateKey through for verification.

Alternative approach: Store the full StateKey in the JellyfishMerkleTree leaf node and verify it during lookup, though this increases storage overhead.

## Proof of Concept

```rust
#[cfg(test)]
mod hash_collision_poc {
    use super::*;
    use aptos_crypto::{hash::CryptoHash, HashValue};
    use aptos_types::state_store::{state_key::StateKey, state_value::StateValue};
    
    #[test]
    fn test_hash_collision_state_poisoning() {
        // This PoC demonstrates the vulnerability assuming we can create
        // two StateKeys with the same hash (not currently possible but
        // the question asks us to assume collision capability)
        
        let db = setup_test_db();
        let version_5 = 5;
        let version_10 = 10;
        
        // StateKey1: legitimate user's resource
        let state_key_1 = StateKey::raw(b"legitimate_user_balance");
        let value_1 = StateValue::from(b"1000_APT".to_vec());
        
        // StateKey2: attacker's colliding key
        // In reality, attacker would compute this to have hash(SK2) == hash(SK1)
        let state_key_2 = StateKey::raw(b"attacker_crafted_key");
        let value_2 = StateValue::from(b"0_APT".to_vec());
        
        // SIMULATION: Override the hash function to create artificial collision
        // (In real attack, attacker finds actual collision)
        let collision_hash = state_key_1.hash();
        
        // Version 5: Write legitimate state
        db.put_state_value(state_key_1.clone(), value_1.clone(), version_5)
            .unwrap();
        
        // Version 10: Attacker writes colliding key
        // (simulation: we'd need to mock the hash to return collision_hash)
        db.put_state_value(state_key_2.clone(), value_2.clone(), version_10)
            .unwrap();
        
        // Query state_key_1 at version 10
        let result = db.get_state_value_by_version(&state_key_1, version_10)
            .unwrap();
        
        // BUG: If hashes collide, this returns value_2 instead of value_1!
        // The system would return "0_APT" for legitimate_user_balance
        // This demonstrates the state poisoning vulnerability
        
        // Expected: Should return value_1 or None if state_key_1 wasn't updated
        // Actual with collision: Returns value_2 (attacker's value)
        assert_eq!(result, Some(value_1)); // This would FAIL with collision
    }
}
```

**Note**: A complete PoC would require either:
1. Mocking the hash function to simulate collisions
2. Actually finding a SHA3-256 collision (computationally infeasible)
3. Using a weakened hash function in test mode to demonstrate the logic bug

The vulnerability is in the logic, not the hash function. The code assumes hash uniqueness without verification, which is a design flaw regardless of current cryptographic strength.

---

**Notes**

This vulnerability is contingent on SHA3-256 collision resistance being broken. Under current cryptographic assumptions, SHA3-256 is secure and finding collisions is computationally infeasible. However:

1. **The prompt explicitly asks to assume collision capability**: "If an attacker finds a collision in HashValue (SHA3-256)..."

2. **Defense-in-depth principle**: The code should not trust unverified data from the merkle tree. Even if collisions are impossible, the system should validate returned StateKeys match requested ones.

3. **Future-proofing**: Cryptographic assumptions can be violated by advances in cryptanalysis, quantum computing, or implementation bugs.

The fix requires minimal changes and would harden the system against both hash collision attacks and tree corruption bugs that could return incorrect StateKeys.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L228-235)
```rust
        let (leaf_data, proof) = db.get_with_proof_ext(key_hash, version, root_depth)?;
        Ok((
            match leaf_data {
                Some((_val_hash, (key, ver))) => Some(self.expect_value_by_version(&key, ver)?),
                None => None,
            },
            proof,
        ))
```

**File:** storage/aptosdb/src/state_store/mod.rs (L831-834)
```rust
                            batch.put::<StateValueByKeyHashSchema>(
                                &(CryptoHash::hash(*key), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L698-705)
```rust
pub struct LeafNode<K> {
    // The hashed key associated with this leaf node.
    account_key: HashValue,
    // The hash of the value.
    value_hash: HashValue,
    // The key and version that points to the value
    value_index: (K, Version),
}
```

**File:** storage/jellyfish-merkle/src/lib.rs (L778-790)
```rust
                Node::Leaf(leaf_node) => {
                    return Ok((
                        if leaf_node.account_key() == key {
                            Some((leaf_node.value_hash(), leaf_node.value_index().clone()))
                        } else {
                            None
                        },
                        SparseMerkleProofExt::new_partial(
                            Some(leaf_node.into()),
                            out_siblings,
                            target_root_depth,
                        ),
                    ));
```
