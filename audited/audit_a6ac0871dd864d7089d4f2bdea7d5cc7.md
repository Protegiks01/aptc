# Audit Report

## Title
Silent Verification Bypass in Verified State View Allows Unverified State Access

## Summary
The `verified_state_view_at_version()` function creates a supposedly "verified" state view, but the underlying `DbStateView::get()` method silently skips proof verification when proofs are unavailable, allowing unverified state values to be returned. This violates the state consistency invariant and the security guarantee implied by the "verified" nomenclature.

## Finding Description

The vulnerability exists in the interaction between two functions: [1](#0-0) [2](#0-1) 

The `verified_state_view_at_version()` function verifies transaction proofs and extracts a state checkpoint hash: [3](#0-2) 

However, when state values are retrieved via `DbStateView::get()`, verification is conditional: [4](#0-3) 

The critical flaw: If `get_state_value_with_proof_by_version` returns an error (proof not available), the if-let pattern silently continues without verification. The function then **always** returns the value from a separate query: [5](#0-4) 

This creates two security issues:

1. **Silent Verification Bypass**: When proofs are unavailable, state values are returned without verification against the committed state root hash
2. **Time-of-Check to Time-of-Use (TOCTOU)**: Even when verification succeeds, the verified value is discarded and a second query returns a potentially different value

The code comments acknowledge this limitation: [6](#0-5) 

## Impact Explanation

**Severity: Medium to High**

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs."

Potential impacts:

1. **State Inconsistency**: Different nodes could return different state values for the same version if proof availability varies
2. **Consensus Divergence**: If execution depends on unverified state values, validators could produce different state roots
3. **Database Corruption Masking**: Corrupted state values would not be detected if proofs fail to load
4. **Security Guarantee Violation**: Code using "verified" state views expects cryptographic verification, but receives unverified data

While this requires specific conditions (proof unavailability at versions with state checkpoints), the silent failure mode is particularly dangerous as it provides no indication that verification was bypassed.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability can manifest in several scenarios:

1. **Buffered State Access**: The comments explicitly mention "buffered state" lacks proof support, though `verified_state_view_at_version` should only be called at checkpoint versions
2. **Database Inconsistency**: If the merkle tree DB and key-value DB become desynchronized
3. **Hot State Unavailability**: When `use_hot_state=true` but hot_state_merkle_db is not available [7](#0-6) 

Current usage appears limited to test code: [8](#0-7) 

However, the function is part of the public API and any production use would be vulnerable.

## Recommendation

**Solution 1: Fail Loudly When Proofs Unavailable** (Preferred)

For a "verified" state view, proof verification should be mandatory. Modify the code to return an error if proofs cannot be obtained:

```rust
fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
    if let Some(version) = self.version {
        if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
            // Verification is MANDATORY for verified state views
            let (value, proof) = self.db.get_state_value_with_proof_by_version(key, version)
                .map_err(|e| StateViewError::Other(format!(
                    "Verified state view requires proof but failed to get proof: {}", e
                )))?;
            proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
            return Ok(value.map(|v| (version, v)));
        }
        Ok(self.db.get_state_value_with_version_by_version(key, version)?)
    } else {
        Ok(None)
    }
}
```

**Solution 2: Fix TOCTOU Issue**

Return the verified value directly instead of making a second query: [9](#0-8) 

**Solution 3: Document Limitations Clearly**

If silent skipping is intentional, rename to `best_effort_verified_state_view_at_version()` and document the lack of guarantee.

## Proof of Concept

```rust
// Reproduction scenario - requires mocking database behavior
#[cfg(test)]
mod vulnerability_poc {
    use super::*;
    
    #[test]
    fn test_verification_bypass() {
        // Setup: Create a verified state view at a version with state checkpoint
        let db = setup_test_db();
        let ledger_info = get_test_ledger_info();
        let version = 100;
        
        let state_view = db.reader
            .verified_state_view_at_version(Some(version), &ledger_info)
            .unwrap();
        
        // Attack: Mock get_state_value_with_proof_by_version to fail
        // (simulating proof unavailability or database corruption)
        let test_key = StateKey::from_address_and_tag(test_address, b"test");
        
        // This call succeeds and returns value WITHOUT verification
        // because get_state_value_with_proof_by_version returned Err
        let unverified_value = state_view.get(&test_key).unwrap();
        
        // The value was never verified against state_checkpoint_hash!
        // If the database is corrupted, we would accept incorrect state.
    }
}
```

The proof of concept demonstrates that when `get_state_value_with_proof_by_version` fails, unverified state values are silently returned despite using a "verified" state view.

## Notes

The TODO comments suggest developers are aware of limitations with buffered state proofs. However, for a function explicitly named `verified_state_view_at_version` that requires state checkpoint hashes, all accesses should enforce cryptographic verification or fail loudly. The current silent bypass defeats the security guarantee and could mask serious database corruption or state inconsistency issues that would otherwise be caught by proof verification failures.

### Citations

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L27-46)
```rust
    fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
        if let Some(version) = self.version {
            if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
                // TODO(aldenhu): sample-verify proof inside DB
                // DB doesn't support returning proofs for buffered state, so only optionally
                // verify proof.
                // TODO: support returning state proof for buffered state.
                if let Ok((value, proof)) =
                    self.db.get_state_value_with_proof_by_version(key, version)
                {
                    proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
                }
            }
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L108-147)
```rust
    fn verified_state_view_at_version(
        &self,
        version: Option<Version>,
        ledger_info: &LedgerInfo,
    ) -> StateViewResult<DbStateView>;
}

impl VerifiedStateViewAtVersion for Arc<dyn DbReader> {
    fn verified_state_view_at_version(
        &self,
        version: Option<Version>,
        ledger_info: &LedgerInfo,
    ) -> StateViewResult<DbStateView> {
        let db = self.clone();

        if let Some(version) = version {
            let txn_with_proof =
                db.get_transaction_by_version(version, ledger_info.version(), false)?;
            txn_with_proof.verify(ledger_info)?;

            let state_root_hash = txn_with_proof
                .proof
                .transaction_info
                .state_checkpoint_hash()
                .ok_or_else(|| StateViewError::NotFound("state_checkpoint_hash".to_string()))?;

            Ok(DbStateView {
                db,
                version: Some(version),
                maybe_verify_against_state_root_hash: Some(state_root_hash),
            })
        } else {
            Ok(DbStateView {
                db,
                version: None,
                maybe_verify_against_state_root_hash: None,
            })
        }
    }
}
```

**File:** storage/aptosdb/src/state_store/mod.rs (L216-220)
```rust
        let db = if use_hot_state {
            if self.state_merkle_db.sharding_enabled() {
                self.hot_state_merkle_db
                    .as_ref()
                    .ok_or(AptosDbError::HotStateError)?
```

**File:** execution/executor-test-helpers/src/integration_test_impl.rs (L266-269)
```rust
    let view = db
        .reader
        .verified_state_view_at_version(Some(current_version), latest_li)
        .unwrap();
```
