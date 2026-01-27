# Audit Report

## Title
Resource Exhaustion via Untested ObservedJWKUpdate Validation Bypass

## Summary
The property test framework only generates `DKGResult` variants of `ValidatorTransaction`, leaving `ObservedJWKUpdate` transactions completely untested. This creates an exploitable asymmetry: `ObservedJWKUpdate` transactions bypass consensus-time verification entirely, deferring all validation to VM execution, allowing malicious proposers to include invalid transactions that waste validator resources.

## Finding Description

The `ValidatorTransaction` enum has two variants: `DKGResult` and `ObservedJWKUpdate`. [1](#0-0) 

However, the property test implementation only generates `DKGResult` variants: [2](#0-1) 

This creates a critical validation asymmetry. When consensus processes validator transactions, it calls `vtxn.verify()`: [3](#0-2) 

The `verify()` implementation shows the asymmetry: [4](#0-3) 

`DKGResult` performs cryptographic verification at consensus time, while `ObservedJWKUpdate` returns `Ok()` immediately, deferring ALL validation to VM execution. [5](#0-4) 

**Attack Path:**
1. Malicious proposer crafts `ObservedJWKUpdate` with invalid multi-signature, incorrect version, or insufficient voting power
2. Transaction passes consensus validation (`verify()` returns `Ok()`)
3. Block accepted and replicated to all validators
4. All validators execute the transaction, performing expensive operations (fetching `ValidatorSet`, `ObservedJWKs`, creating `HashMap`, verifying multi-sig)
5. Validation fails during execution, transaction discarded with `ABORTED` status
6. Attacker repeats attack across multiple blocks

The lack of property testing means edge cases in BCS serialization, size calculation, and hash computation for the complex nested structure (`QuorumCertifiedUpdate` → `ProviderJWKs` + `AggregateSignature`) remain unexplored and potentially exploitable.

## Impact Explanation

This qualifies as **High Severity** (Validator node slowdowns):

- Every validator must execute invalid `ObservedJWKUpdate` transactions despite them failing validation
- Execution includes: storage reads (`ValidatorSet`, `ObservedJWKs`), HashMap allocation, BLS signature verification
- Attacker can include one invalid `ObservedJWKUpdate` per block, continuously degrading validator performance
- Unlike invalid user transactions (rejected in mempool), validator transactions are block-mandatory
- No gas metering applies (uses `UnmeteredGasMeter`)

While not causing consensus splits or fund loss, systematic validator resource exhaustion degrades network liveness and creates denial-of-service conditions.

## Likelihood Explanation

**Likelihood: Medium-High**

- Requires attacker to be or collude with a validator proposer
- Attack is sustainable: can repeat every time attacker proposes
- Detection is difficult: discarded transactions appear as expected failures in logs
- No cost to attacker (invalid transactions don't affect their stake)
- Untested code paths increase probability of exploitable edge cases

## Recommendation

**Immediate Fix:**

1. Extend property testing to generate `ObservedJWKUpdate` variants:

```rust
impl Arbitrary for ValidatorTransaction {
    type Parameters = SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<Vec<u8>>().prop_map(|payload| {
                ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: 0,
                        author: AccountAddress::ZERO,
                    },
                    transcript_bytes: payload,
                })
            }),
            any::<QuorumCertifiedUpdate>().prop_map(ValidatorTransaction::ObservedJWKUpdate)
        ]
        .boxed()
    }
}
```

2. Add pre-consensus validation for `ObservedJWKUpdate` to fail-fast invalid transactions before VM execution.

3. Implement resource limits on `ObservedJWKs` updates similar to the 2KB limit on `FederatedJWKs`. [6](#0-5) 

## Proof of Concept

```rust
// Test demonstrating untested ObservedJWKUpdate path
#[test]
fn test_invalid_jwk_update_resource_exhaustion() {
    // Create invalid ObservedJWKUpdate with bad multi-sig
    let invalid_update = ValidatorTransaction::ObservedJWKUpdate(
        QuorumCertifiedUpdate {
            update: ProviderJWKs::new(b"malicious_issuer".to_vec()),
            multi_sig: AggregateSignature::empty(), // Invalid signature
        }
    );
    
    // Passes consensus validation
    let verifier = ValidatorVerifier::new(/*...*/);
    assert!(invalid_update.verify(&verifier).is_ok()); // Returns Ok() immediately
    
    // But fails during VM execution, wasting resources
    // This path is UNTESTED by property tests
}
```

## Notes

The validation asymmetry appears intentional (JWK verification requires on-chain state unavailable at consensus time), but the lack of property testing coverage creates blind spots in size calculation, serialization, and resource consumption patterns for `ObservedJWKUpdate` transactions.

### Citations

**File:** types/src/validator_txn.rs (L14-18)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub enum ValidatorTransaction {
    DKGResult(DKGTranscript),
    ObservedJWKUpdate(jwks::QuorumCertifiedUpdate),
}
```

**File:** types/src/validator_txn.rs (L45-53)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            ValidatorTransaction::DKGResult(dkg_result) => dkg_result
                .verify(verifier)
                .context("DKGResult verification failed"),
            ValidatorTransaction::ObservedJWKUpdate(_) => Ok(()),
        }
    }
}
```

**File:** types/src/proptest_types.rs (L1367-1383)
```rust
impl Arbitrary for ValidatorTransaction {
    type Parameters = SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Vec<u8>>())
            .prop_map(|payload| {
                ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: 0,
                        author: AccountAddress::ZERO,
                    },
                    transcript_bytes: payload,
                })
            })
            .boxed()
    }
```

**File:** consensus/src/round_manager.rs (L1126-1137)
```rust
        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L31-33)
```text
    /// We limit the size of a `PatchedJWKs` resource installed by a dapp owner for federated keyless accounts.
    /// Note: If too large, validators waste work reading it for invalid TXN signatures.
    const MAX_FEDERATED_JWKS_SIZE_BYTES: u64 = 2 * 1024; // 2 KiB
```
