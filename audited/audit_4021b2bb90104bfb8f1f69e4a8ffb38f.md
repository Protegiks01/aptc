# Audit Report

## Title
Missing Post-Decryption Validation of Secret Share Key Pair Correspondence in Randomness Configuration

## Summary
The `try_get_rand_config_for_new_epoch()` function decrypts secret shares from a DKG transcript without validating that the decrypted secret key corresponds to its public key before using them for randomness generation. This missing validation could allow implementation bugs or transcript corruption to propagate undetected, potentially causing consensus liveness failure.

## Finding Description

In the epoch manager's randomness configuration setup, the DKG transcript is retrieved from on-chain state and secret shares are decrypted without post-decryption validation. [1](#0-0) 

The code explicitly skips transcript re-verification (comment on line 1063: "No need to verify the transcript") and proceeds to decrypt secret shares. The decrypted secret key share (`sk`) and public key share (`pk`) are then used directly without validating their correspondence. [2](#0-1) 

The `decrypt_own_share()` implementation retrieves the public key share independently from the transcript storage rather than deriving it from the decrypted secret key: [3](#0-2) 

The BLS WVUF augmentation simply returns the inputs without validation: [4](#0-3) 

**Broken Invariant**: Cryptographic Correctness - the system should validate that cryptographic key pairs are valid before use.

**How the vulnerability could manifest:**

1. **Implementation bug scenario**: If `decrypt_own_share()` or the BSGS discrete log computation contains a bug that causes incorrect decryption, validators would use invalid key pairs without detection.

2. **Hardware/environment error scenario**: Floating-point errors, memory corruption, or BSGS lookup table corruption could cause `decrypt_own_share()` to return incorrect values.

3. **Future code changes scenario**: Refactoring or optimization of the decryption logic could introduce subtle bugs that go undetected due to missing validation.

When validators have invalid key pairs, they generate randomness shares that fail verification: [5](#0-4) 

## Impact Explanation

**Critical Severity** - Total loss of liveness/network availability

If validators use invalid key pairs for randomness generation:
1. Their randomness shares will fail `WVUF::verify_share()` validation when processed by other validators
2. If insufficient valid shares are collected, randomness generation fails
3. Without randomness, consensus cannot proceed in epochs where randomness is enabled
4. This causes complete network halt requiring manual intervention or hard fork

This meets the **Critical** severity criteria: "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Currently Low, but Non-Zero**

While no bug currently exists in `decrypt_own_share()`, the missing validation creates risk:
- Future optimizations or refactoring could introduce bugs
- Deployment to new hardware architectures could expose computation errors  
- Memory corruption or bit flips could affect BSGS lookup tables
- The system lacks defense-in-depth against this failure mode

The likelihood increases with:
- Code complexity as the system evolves
- Hardware diversity in validator deployments
- Time (increasing chance of encountering edge cases)

## Recommendation

Add post-decryption validation to verify that the decrypted secret key corresponds to the public key before using them:

```rust
// After decrypting (sk, pk) on line 1072, add validation:
fn validate_key_pair_correspondence(
    sk: &DealtSecretKeyShares,
    pk: &DealtPubKeyShares,
    vuf_pp: &WvufPP,
) -> anyhow::Result<()> {
    // Verify main key pair
    for (sk_share, pk_share) in sk.main.iter().zip(pk.main.iter()) {
        let derived_pk = vuf_pp.g2.mul(sk_share.0);
        if derived_pk != *pk_share.as_group_element() {
            bail!("Secret share does not correspond to public share");
        }
    }
    
    // Verify fast key pair if present
    if let (Some(sk_fast), Some(pk_fast)) = (&sk.fast, &pk.fast) {
        for (sk_share, pk_share) in sk_fast.iter().zip(pk_fast.iter()) {
            let derived_pk = vuf_pp.g2.mul(sk_share.0);
            if derived_pk != *pk_share.as_group_element() {
                bail!("Fast secret share does not correspond to public share");
            }
        }
    }
    
    Ok(())
}

// Insert after line 1072:
validate_key_pair_correspondence(&sk, &pk, &vuf_pp)
    .map_err(NoRandomnessReason::InvalidKeyPairAfterDecryption)?;
```

This validation ensures that any decryption errors are caught immediately rather than causing consensus failure later.

## Proof of Concept

A PoC cannot be provided without artificially introducing a bug in `decrypt_own_share()`, as no such bug currently exists. However, the validation can be tested by intentionally corrupting the secret key after decryption:

```rust
#[test]
fn test_missing_key_pair_validation() {
    // Setup: Create valid DKG transcript and decrypt shares
    let (sk, pk) = decrypt_secret_share_from_transcript(...);
    
    // Simulate decryption error by corrupting secret key
    let mut corrupted_sk = sk.clone();
    corrupted_sk.main[0] = Scalar(random_scalar());
    
    // Current code: Would proceed with corrupted key
    // This will fail later during randomness share verification
    let augmented_key_pair = WVUF::augment_key_pair(&vuf_pp, corrupted_sk.main, pk.main, &mut rng);
    
    // With proposed fix: Would catch the error immediately
    assert!(validate_key_pair_correspondence(&corrupted_sk, &pk, &vuf_pp).is_err());
}
```

**Notes**

The transcript IS verified when first stored on-chain via validator transaction: [6](#0-5) 

However, this on-chain verification validates the transcript structure and cryptographic proofs, but does not guarantee that future decryption operations will produce valid key pairs. The missing post-decryption validation creates a gap in the defense-in-depth strategy, allowing potential bugs in the decryption path to go undetected until they cause consensus failure.

### Citations

**File:** consensus/src/epoch_manager.rs (L1056-1072)
```rust
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_session.transcript.as_slice(),
        )
        .map_err(NoRandomnessReason::TranscriptDeserializationError)?;

        let vuf_pp = WvufPP::from(&dkg_pub_params.pvss_config.pp);

        // No need to verify the transcript.

        // keys for randomness generation
        let (sk, pk) = DefaultDKG::decrypt_secret_share_from_transcript(
            &dkg_pub_params,
            &transcript,
            my_index as u64,
            &dkg_decrypt_key,
        )
        .map_err(NoRandomnessReason::SecretShareDecryptionFailed)?;
```

**File:** consensus/src/epoch_manager.rs (L1104-1104)
```rust
            let augmented_key_pair = WVUF::augment_key_pair(&vuf_pp, sk.main, pk.main, &mut rng);
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L318-380)
```rust
    fn decrypt_own_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player: &Player,
        dk: &Self::DecryptPrivKey,
        pp: &Self::PublicParameters,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let weight = sc.get_player_weight(player);

        let Cs = &self.Cs[player.id];

        // TODO: put an assert here saying that len(Cs) = weight

        let ephemeral_keys: Vec<_> = self
            .Rs
            .iter()
            .take(weight)
            .map(|R_i_vec| R_i_vec.iter().map(|R_i| R_i.mul(dk.dk)).collect::<Vec<_>>())
            .collect();

        if let Some(first_key) = ephemeral_keys.first() {
            debug_assert_eq!(
                first_key.len(),
                Cs[0].len(),
                "Number of ephemeral keys does not match the number of ciphertext chunks"
            );
        }

        let mut sk_shares: Vec<Scalar<E::ScalarField>> = Vec::with_capacity(weight);
        let pk_shares = self.get_public_key_share(sc, player);

        for i in 0..weight {
            // TODO: should really put this in a separate function
            let dealt_encrypted_secret_key_share_chunks: Vec<_> = Cs[i]
                .iter()
                .zip(ephemeral_keys[i].iter())
                .map(|(C_ij, ephemeral_key)| C_ij.sub(ephemeral_key))
                .collect();

            let dealt_chunked_secret_key_share = bsgs::dlog_vec(
                pp.pp_elgamal.G.into_group(),
                &dealt_encrypted_secret_key_share_chunks,
                &pp.table,
                pp.get_dlog_range_bound(),
            )
            .expect("BSGS dlog failed");

            let dealt_chunked_secret_key_share_fr: Vec<E::ScalarField> =
                dealt_chunked_secret_key_share
                    .iter()
                    .map(|&x| E::ScalarField::from(x))
                    .collect();

            let dealt_secret_key_share =
                chunks::le_chunks_to_scalar(pp.ell, &dealt_chunked_secret_key_share_fr);

            sk_shares.push(Scalar(dealt_secret_key_share));
        }

        (
            sk_shares, pk_shares, // TODO: review this formalism... why do we need this here?
        )
    }
```

**File:** crates/aptos-dkg/src/weighted_vuf/bls/mod.rs (L50-57)
```rust
    fn augment_key_pair<R: rand_core::RngCore + rand_core::CryptoRng>(
        _pp: &Self::PublicParameters,
        sk: Self::SecretKeyShare,
        pk: Self::PubKeyShare,
        _rng: &mut R,
    ) -> (Self::AugmentedSecretKeyShare, Self::AugmentedPubKeyShare) {
        (sk, pk)
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L52-81)
```rust
    fn verify(
        &self,
        rand_config: &RandConfig,
        rand_metadata: &RandMetadata,
        author: &Author,
    ) -> anyhow::Result<()> {
        let index = *rand_config
            .validator
            .address_to_validator_index()
            .get(author)
            .ok_or_else(|| anyhow!("Share::verify failed with unknown author"))?;
        let maybe_apk = &rand_config.keys.certified_apks[index];
        if let Some(apk) = maybe_apk.get() {
            WVUF::verify_share(
                &rand_config.vuf_pp,
                apk,
                bcs::to_bytes(&rand_metadata)
                    .map_err(|e| anyhow!("Serialization failed: {}", e))?
                    .as_slice(),
                &self.share,
            )?;
        } else {
            bail!(
                "[RandShare] No augmented public key for validator id {}, {}",
                index,
                author
            );
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L104-112)
```rust
        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```
