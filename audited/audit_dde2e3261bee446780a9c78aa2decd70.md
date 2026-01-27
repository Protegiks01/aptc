# Audit Report

## Title
Epoch Confusion Vulnerability in JWK Consensus: Missing Epoch Validation in QuorumCertifiedUpdate Processing

## Summary
The `session_key_from_qc()` function in the JWK consensus module does not validate that a `QuorumCertifiedUpdate` belongs to the current epoch before deriving session keys. Combined with missing epoch validation in the execution layer, this allows stale consensus decisions from previous epochs to be applied on-chain if the validator set remains sufficiently similar across epoch boundaries.

## Finding Description

The JWK (JSON Web Key) consensus system in Aptos allows validators to collectively agree on cryptographic key updates. The vulnerability exists across three layers:

**Layer 1: Session Key Derivation** [1](#0-0) 

The `session_key_from_qc()` function extracts the issuer and kid from a `QuorumCertifiedUpdate` without validating which epoch the QC was created for.

**Layer 2: Missing Epoch Metadata** [2](#0-1) 

The `QuorumCertifiedUpdate` struct contains no epoch field, making temporal validation impossible once the QC is created.

**Layer 3: Execution Validation** [3](#0-2) 

The `process_jwk_update_inner` function validates QCs based on version numbers, voting power, and cryptographic signatures against the CURRENT validator set, but never checks if the QC belongs to the current epoch.

**Attack Scenario:**

While the `TxnGuard` mechanism typically cleans up transactions during epoch transitions, there's a critical window where stale QCs can persist: [4](#0-3) 

States are retained across epochs if the on-chain version hasn't changed. Since the validator transaction pool is shared across epochs: [5](#0-4) 

A malicious validator can exploit this by:

1. **Epoch N**: A QC is created for JWK update (issuer=google.com, kid=key123) reflecting observations at time T1
2. **Epoch N→N+1**: Validator set remains similar (same validators or enough overlap for ≥67% threshold)  
3. **Epoch N+1**: At time T2, actual JWK values have changed (e.g., key revocation)
4. **Attack**: Malicious validator resubmits the old QC from epoch N as a `ValidatorTransaction::ObservedJWKUpdate`
5. **Execution**: The QC passes all validations (version check, voting power ≥67%, valid signatures) because the validator set is similar
6. **Impact**: Stale/revoked cryptographic keys are committed on-chain

During observation aggregation, epoch IS validated: [6](#0-5) 

However, this only prevents replaying observation **responses**. A completed QC can be directly submitted as a validator transaction, bypassing this check.

## Impact Explanation

**Severity: High (up to $50,000)**

This vulnerability constitutes a **significant protocol violation** per Aptos bug bounty criteria:

1. **Consensus Integrity Violation**: Different epochs should establish independent consensus. Accepting epoch N consensus in epoch N+1 violates temporal safety.

2. **Cryptographic Security Degradation**: If JWK keys are revoked between epochs (e.g., due to compromise detection), the old QC could resurrect compromised keys on-chain.

3. **Authentication Bypass Potential**: JWKs are used for authentication. Stale keys could allow unauthorized access if the correct keys were updated to revoke access.

4. **State Consistency Break**: The on-chain state no longer reflects current validator consensus, violating the "State Consistency" invariant.

While this doesn't cause direct fund loss or complete network failure (preventing Critical severity), it does compromise the security guarantees of the JWK consensus system.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires specific conditions:

1. **Validator set stability**: Old signatures must still represent ≥67% voting power in the new epoch (common in practice)
2. **Malicious validator participation**: At least one validator must actively resubmit old QCs
3. **Timing window**: On-chain version must not have been incremented yet

However, validator sets often remain stable across consecutive epochs, making conditions (1) and (3) frequently met. The primary barrier is requiring a malicious validator (condition 2).

The epoch checking in observation aggregation prevents passive replay, but doesn't prevent active resubmission of completed QCs.

## Recommendation

**Add epoch validation at multiple layers:**

**1. Add epoch field to QuorumCertifiedUpdate:**
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct QuorumCertifiedUpdate {
    pub epoch: u64,  // ADD THIS
    pub update: ProviderJWKs,
    pub multi_sig: AggregateSignature,
}
```

**2. Validate epoch in session_key_from_qc:**
```rust
fn session_key_from_qc(qc: &QuorumCertifiedUpdate, current_epoch: u64) -> anyhow::Result<(Issuer, KID)> {
    ensure!(
        qc.epoch == current_epoch,
        "QC epoch {} doesn't match current epoch {}",
        qc.epoch,
        current_epoch
    );
    let KeyLevelUpdate { issuer, kid, .. } =
        KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)
            .context("session_key_from_qc failed with repr translation")?;
    Ok((issuer, kid))
}
```

**3. Validate epoch in process_jwk_update_inner:**
```rust
fn process_jwk_update_inner(
    &self,
    resolver: &impl AptosMoveResolver,
    current_epoch: u64,  // ADD THIS PARAMETER
    update: jwks::QuorumCertifiedUpdate,
) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
    // Add epoch validation
    if update.epoch != current_epoch {
        return Err(Expected(IncorrectEpoch));  // New error variant
    }
    
    // ... rest of validation
}
```

**4. Clear validator transaction pool on epoch boundaries** to ensure no cross-epoch contamination.

## Proof of Concept

```rust
// Conceptual PoC - requires full validator test harness

#[test]
fn test_epoch_confusion_attack() {
    // Setup epoch N with validators V1, V2, V3 (70% power)
    let mut test_env = create_test_environment();
    let epoch_n = 5;
    test_env.set_epoch(epoch_n);
    
    // Create QC for JWK update in epoch N
    let qc_epoch_n = test_env.create_jwk_qc(
        issuer: "google.com",
        kid: "key123",
        value: "OLD_KEY_VALUE",
        version: 5 -> 6,
        signers: [V1, V2, V3]  // 70% power
    );
    
    // Transition to epoch N+1 with same validator set
    test_env.transition_to_epoch(epoch_n + 1);
    
    // Malicious validator resubmits old QC
    let result = test_env.submit_validator_txn(
        ValidatorTransaction::ObservedJWKUpdate(qc_epoch_n)
    );
    
    // Expected: Should REJECT due to wrong epoch
    // Actual: ACCEPTS because epoch not validated
    assert!(result.is_err(), "Should reject cross-epoch QC");
    
    // Verify on-chain state has stale value
    let on_chain = test_env.get_jwk("google.com", "key123");
    assert_eq!(on_chain.value, "OLD_KEY_VALUE");  // WRONG!
}
```

## Notes

This vulnerability demonstrates a temporal validation gap in the JWK consensus protocol. While the cryptographic validation (signatures, voting power) is sound, the lack of epoch metadata allows consensus decisions from previous epochs to be applied in new epochs when the validator set remains similar. This violates the principle of epoch isolation that's critical for blockchain security, where each epoch should establish fresh consensus independent of previous epochs.

The fix requires adding epoch tracking to the `QuorumCertifiedUpdate` struct and validating it at both the consensus layer (`session_key_from_qc`) and execution layer (`process_jwk_update_inner`).

### Citations

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L59-64)
```rust
    fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<(Issuer, KID)> {
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)
                .context("session_key_from_qc failed with repr translation")?;
        Ok((issuer, kid))
    }
```

**File:** types/src/jwks/mod.rs (L303-307)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct QuorumCertifiedUpdate {
    pub update: ProviderJWKs,
    pub multi_sig: AggregateSignature,
}
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L100-143)
```rust
    fn process_jwk_update_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        update: jwks::QuorumCertifiedUpdate,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        // Load resources.
        let validator_set =
            ValidatorSet::fetch_config(resolver).ok_or(Expected(MissingResourceValidatorSet))?;
        let observed_jwks =
            ObservedJWKs::fetch_config(resolver).ok_or(Expected(MissingResourceObservedJWKs))?;

        let mut jwks_by_issuer: HashMap<Issuer, ProviderJWKs> =
            observed_jwks.into_providers_jwks().into();
        let issuer = update.update.issuer.clone();
        let on_chain = jwks_by_issuer
            .entry(issuer.clone())
            .or_insert_with(|| ProviderJWKs::new(issuer));
        let verifier = ValidatorVerifier::from(&validator_set);

        let QuorumCertifiedUpdate {
            update: observed,
            multi_sig,
        } = update;

        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }

        let authors = multi_sig.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;

        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;

```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L244-254)
```rust
        self.states_by_key.retain(|(issuer, _), _| {
            new_onchain_jwks
                .get(issuer)
                .map(|jwks| jwks.version)
                .unwrap_or_default()
                == self
                    .onchain_jwks
                    .get(issuer)
                    .map(|jwks| jwks.version)
                    .unwrap_or_default()
        });
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L76-76)
```rust
        vtxn_pool: VTxnPoolState,
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L60-63)
```rust
        ensure!(
            epoch == self.epoch_state.epoch,
            "adding peer observation failed with invalid epoch",
        );
```
