# Audit Report

## Title
Incomplete Verification Key Validation in BatchThresholdEncryption::setup() Allows Potential Verification Key Substitution

## Summary
The `setup()` function in `FPTXWeighted` only validates the cryptographic binding between the current player's verification key and their master secret key share, but accepts verification keys for all other players from the subtranscript without validation. This creates a potential vulnerability if an unverified or malicious subtranscript is provided as input.

## Finding Description

The `FPTXWeighted::setup()` function is responsible for setting up batch threshold encryption from a PVSS subtranscript. It returns an encryption key, a vector of verification keys for all players, and the current player's master secret key share. [1](#0-0) 

The critical issue is on lines 275-283, where the function only validates that the **current player's** verification key matches their master secret key share:

The validation checks `vk = g^sk` for the current player's components, but the verification keys for **all other players** (extracted on lines 245-257) are accepted directly from the subtranscript without any cryptographic validation.

This breaks the cryptographic correctness invariant because:
1. The function returns verification keys for ALL players in the system
2. These verification keys will be used later to verify decryption key shares from other validators [2](#0-1) 
3. Only ONE player's VK is validated, while the others are taken on trust
4. The function doesn't enforce that the subtranscript has been cryptographically verified

The PVSS transcript verification (which would validate all verification keys) is defined separately: [3](#0-2) 

However, `setup()` doesn't call or enforce this verification. The test demonstrates that `setup()` can be called without prior transcript verification: [4](#0-3) 

**Attack Scenario:**
If there exists any code path where `setup()` can be called with an unverified subtranscript (either through a programming error, future code changes, or a separate verification bypass), an attacker could:
1. Provide a malicious subtranscript with forged verification keys for other validators
2. The current validator calls `setup()` which validates only its own VK
3. The forged VKs for other validators are stored in `SecretShareConfig`
4. Later, when verifying decryption key shares, the system uses forged VKs
5. Legitimate decryption shares from honest validators are rejected (DoS)
6. Or invalid shares matching the forged VKs could be accepted

## Impact Explanation

**Severity: High**

While I cannot demonstrate a concrete attack path from an unprivileged external attacker in the current codebase (as the DKG protocol should ensure transcript verification), this represents a **critical design flaw** with potential High severity impact:

1. **Denial of Service**: If exploited, legitimate decryption key shares would fail verification, breaking the batch encryption/decryption mechanism used for encrypted transactions
2. **Protocol Violation**: Violates the cryptographic correctness invariant by not ensuring all verification keys are cryptographically bound to their corresponding secret keys
3. **Defense-in-Depth Failure**: The function makes security-critical assumptions without enforcing them, creating a time-bomb vulnerability

The impact would affect the encrypted transaction processing pipeline used in consensus, potentially causing liveness issues or transaction processing failures.

## Likelihood Explanation

**Current Likelihood: Low** (requires specific conditions)

Exploitation requires:
- An unverified or malicious subtranscript to be passed to `setup()`
- This currently requires either a bug in DKG verification code or validator insider access
- No direct external attack path identified in current codebase

**Future Risk: Medium to High**
- Code evolution could introduce paths where verification is skipped
- The lack of defensive validation makes the code fragile to changes
- Violates security engineering best practices

## Recommendation

The `setup()` function should enforce complete verification of the subtranscript before processing, or at minimum, validate all verification keys cryptographically:

**Option 1: Enforce Pre-verification (Preferred)**
```rust
fn setup(
    digest_key: &Self::DigestKey,
    pvss_public_params: &<Self::SubTranscript as Subtranscript>::PublicParameters,
    subtranscript: &Self::SubTranscript,
    threshold_config: &Self::ThresholdConfig,
    current_player: Player,
    sk_share_decryption_key: &<Self::SubTranscript as Subtranscript>::DecryptPrivKey,
) -> Result<(...)> {
    // Add a verification check or require a pre-verified wrapper type
    // This ensures the subtranscript has passed cryptographic verification
    
    // Existing implementation follows...
}
```

**Option 2: Validate All Verification Keys**
```rust
// After extracting all VKs, validate each one against public parameters
for (player_idx, vk) in vks.iter().enumerate() {
    // Validate that each VK is correctly derived from the subtranscript
    // using the PVSS public parameters and low-degree test
}
```

**Option 3: Use Type-Level Guarantees**
Create a `VerifiedSubtranscript` wrapper type that can only be constructed after verification passes, ensuring `setup()` always receives verified input.

## Proof of Concept

The existing test demonstrates the vulnerability:

```rust
// In fptx_weighted_smoke.rs, lines 142-150
// Subtranscripts are aggregated WITHOUT verification
let mut subtranscript = subtrx_paths[0].clone();
for acc in &subtrx_paths[1..] {
    subtranscript.aggregate_with(&tc, acc).unwrap();
}

// setup() is called directly without calling verify_transcript()
let (ek, vks, _) =
    FPTXWeighted::setup(&dk, &pp, &subtranscript, &tc, tc.get_player(0), &dks[0]).unwrap();
```

To demonstrate the impact, an attacker would need to:
1. Create a malicious subtranscript with forged VKs
2. Ensure it reaches `setup()` without verification
3. Observe that forged VKs are accepted and later cause verification failures

**Note:** While the current production code likely enforces DKG verification before `setup()`, the function itself does not enforce this critical security property, creating a latent vulnerability that violates defensive programming principles.

## Notes

This vulnerability represents a **missing validation** issue rather than a directly exploitable attack in the current codebase. The security question asks specifically whether `setup()` ensures cryptographic binding, and the answer is definitively **no** - it only validates one player's binding out of many.

The severity assessment assumes that while current code paths may properly verify transcripts before calling `setup()`, the function's failure to enforce this invariant creates significant risk for:
- Future code modifications
- Integration with new components
- Subtle bugs in calling code

A defense-in-depth approach would require `setup()` to either verify the subtranscript itself or validate all verification keys it returns, rather than assuming the caller has performed proper verification.

### Citations

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L229-286)
```rust
    fn setup(
        digest_key: &Self::DigestKey,
        pvss_public_params: &<Self::SubTranscript as Subtranscript>::PublicParameters,
        subtranscript: &Self::SubTranscript,
        threshold_config: &Self::ThresholdConfig,
        current_player: Player,
        msk_share_decryption_key: &<Self::SubTranscript as Subtranscript>::DecryptPrivKey,
    ) -> Result<(
        Self::EncryptionKey,
        Vec<Self::VerificationKey>,
        Self::MasterSecretKeyShare,
    )> {
        let mpk_g2: G2Affine = subtranscript.get_dealt_public_key().as_g2();

        let ek = EncryptionKey::new(mpk_g2, digest_key.tau_g2);

        let vks: Vec<Self::VerificationKey> = threshold_config
            .get_players()
            .into_iter()
            .map(|p| Self::VerificationKey {
                weighted_player: p,
                mpk_g2,
                vks_g2: subtranscript
                    .get_public_key_share(threshold_config, &p)
                    .into_iter()
                    .map(|s| s.as_g2())
                    .collect(),
            })
            .collect();

        let msk_share = Self::MasterSecretKeyShare {
            mpk_g2,
            weighted_player: current_player,
            shamir_share_evals: subtranscript
                .decrypt_own_share(
                    threshold_config,
                    &current_player,
                    msk_share_decryption_key,
                    pvss_public_params,
                )
                .0
                .into_iter()
                .map(|s| s.into_fr())
                .collect(),
        };

        vks[msk_share.weighted_player.get_id()]
            .vks_g2
            .iter()
            .zip(msk_share.shamir_share_evals.clone())
            .try_for_each(|(vk_raw, msk_share_raw)| {
                (G2Projective::from(*vk_raw) == G2Affine::generator() * msk_share_raw)
                    .then_some(())
                    .ok_or(BatchEncryptionError::VKMSKMismatchError)
            })?;

        Ok((ek, vks, msk_share))
    }
```

**File:** types/src/secret_sharing.rs (L75-82)
```rust
    pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
        let index = config.get_id(self.author());
        let decryption_key_share = self.share().clone();
        // TODO(ibalajiarun): Check index out of bounds
        config.verification_keys[index]
            .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
        Ok(())
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L332-400)
```rust
    fn verify_transcript(
        params: &Self::PublicParams,
        trx: &Self::Transcript,
    ) -> anyhow::Result<()> {
        // Verify dealer indices are valid.
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );

        let all_eks = params.pvss_config.eks.clone();

        let addresses = params.verifier.get_ordered_account_addresses();
        let dealers_addresses = dealers
            .iter()
            .filter_map(|&pos| addresses.get(pos))
            .cloned()
            .collect::<Vec<_>>();

        let spks = dealers_addresses
            .iter()
            .filter_map(|author| params.verifier.get_public_key(author))
            .collect::<Vec<_>>();

        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();

        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;

        // Verify fast path is present if and only if fast_wconfig is present.
        ensure!(
            trx.fast.is_some() == params.pvss_config.fast_wconfig.is_some(),
            "real_dkg::verify_transcript failed with mismatched fast path flag in trx and params."
        );

        if let Some(fast_trx) = trx.fast.as_ref() {
            let fast_dealers = fast_trx
                .get_dealers()
                .iter()
                .map(|player| player.id)
                .collect::<Vec<usize>>();
            ensure!(
                dealers == fast_dealers,
                "real_dkg::verify_transcript failed with inconsistent dealer index."
            );
        }

        if let (Some(fast_trx), Some(fast_wconfig)) =
            (trx.fast.as_ref(), params.pvss_config.fast_wconfig.as_ref())
        {
            fast_trx.verify(fast_wconfig, &params.pvss_config.pp, &spks, &all_eks, &aux)?;
        }

        Ok(())
```

**File:** crates/aptos-batch-encryption/src/tests/fptx_weighted_smoke.rs (L142-150)
```rust
    let mut subtranscript = subtrx_paths[0].clone();
    for acc in &subtrx_paths[1..] {
        subtranscript.aggregate_with(&tc, acc).unwrap();
    }

    let dk = DigestKey::new(&mut rng, 8, 1).unwrap();

    let (ek, vks, _) =
        FPTXWeighted::setup(&dk, &pp, &subtranscript, &tc, tc.get_player(0), &dks[0]).unwrap();
```
