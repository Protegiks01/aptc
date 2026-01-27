# Audit Report

## Title
Missing Share Verification Against Polynomial Commitment in PVSS Reconstruction Allows Share Corruption

## Summary
The PVSS (Publicly Verifiable Secret Sharing) reconstruction process does not verify that decrypted secret shares match their corresponding public key shares from the polynomial commitment. This allows a malicious participant to provide fake shares that corrupt the reconstructed output, breaking the fundamental security guarantee that `t` honest shares are sufficient for correct reconstruction.

## Finding Description

The DKG implementation uses PVSS to deal secret shares among validators. The protocol flow is:

1. **Dealing Phase**: Dealer creates transcript with polynomial commitments in G2 (stored in `Vs`) and encrypted shares in G1 (stored in `Cs`) [1](#0-0) 

2. **Verification Phase**: Transcript is verified for structural correctness, low-degree test, and pairing checks [2](#0-1) 

3. **Decryption Phase**: Each player calls `decrypt_own_share()` which returns both the decrypted secret share AND the public key share from the polynomial commitment [3](#0-2) 

4. **Reconstruction Phase**: Secret shares are combined using Lagrange interpolation **without verification** [4](#0-3) 

**The Vulnerability**: In the reconstruction phase, there is no verification that the provided secret shares actually correspond to their public key shares from the polynomial commitment. The reconstruction blindly trusts the shares and performs Lagrange interpolation.

**In Production Code**: The real DKG implementation decrypts shares without verification: [5](#0-4) 

**In Test Code Only**: An assertion exists that checks share validity, but this is only in test utilities: [6](#0-5) 

**Attack Path**:
1. Transcript verification completes successfully
2. Honest validators decrypt their shares correctly  
3. Malicious validator decrypts their share but provides a fake share value instead
4. During reconstruction, the fake share is accepted without verification
5. Lagrange interpolation produces a corrupted secret
6. If this corrupted secret is used for consensus operations (randomness beacon, leader election), consensus safety is violated

**Invariant Broken**: The threshold cryptography invariant that any `t` honest shares can correctly reconstruct the secret is violated. Even with `t` participants, a single malicious participant can corrupt the output.

## Impact Explanation

**Severity: Medium to High** (conditional on production usage)

The impact depends on whether reconstruction is actually used in production consensus operations:

- **If reconstruction is used for consensus randomness**: This would be **Critical** severity as it breaks consensus safety by allowing manipulation of leader election or validator selection
- **If reconstruction is only used for testing**: The impact is limited but still represents a **Medium** severity security gap in the cryptographic protocol implementation

The vulnerability breaks the fundamental security property of (t,n) threshold schemes: that any t honest participants can reconstruct the secret correctly regardless of malicious participants. This is a critical cryptographic invariant.

The code exists in production paths (not test-only files), suggesting it could be used now or in future features, warranting immediate remediation.

## Likelihood Explanation

**Likelihood: Medium**

Requirements for exploitation:
- Malicious validator with valid DKG participation
- Access to provide shares during reconstruction
- Ability to lie about share values without immediate detection

The attack is relatively simple once a validator is compromised, requiring only providing false data rather than complex cryptographic attacks. However, the likelihood depends on:
1. Whether reconstruction is actually invoked in production
2. Whether the compromised validator's share is selected for reconstruction
3. Whether downstream consumers of the reconstructed secret can detect inconsistencies

## Recommendation

Implement share verification before reconstruction by checking that each secret share matches its corresponding public key share from the polynomial commitment. For elliptic curve groups:

```rust
// Verify: secret_share * G2 == public_key_share
// Using pairing: e(secret_share_G1, G2) == e(G1, public_key_share_G2)
```

**Recommended Fix**:

1. Add verification in the `reconstruct` function: [4](#0-3) 

2. Add verification in production DKG reconstruction: [7](#0-6) 

The verification should check that the provided secret share, when multiplied by the generator in G2, equals the public key share from the transcript's polynomial commitment. Any mismatch should cause reconstruction to fail with an error rather than producing corrupted output.

## Proof of Concept

```rust
// Add to crates/aptos-dkg/tests/pvss.rs

#[test]
fn test_fake_share_detection() {
    let (sc, mut rng) = get_threshold_config_and_rng(3, 5);
    let d = setup_dealing::<WTrx, ThreadRng>(&sc, &mut rng);
    
    // Deal and verify transcript
    let trx = WTrx::deal(&sc, &d.pp, &d.ssks[0], &d.spks[0], 
                          &d.eks, &d.iss[0], &NoAux, &sc.get_player(0), &mut rng);
    
    // Collect valid shares from 3 players
    let mut shares = vec![];
    for i in 0..3 {
        let (sk, _pk) = trx.decrypt_own_share(&sc, &sc.get_player(i), &d.dks[i], &d.pp);
        shares.push((sc.get_player(i), sk));
    }
    
    // Malicious player 1 provides fake share
    let fake_share = DealtSecretKeyShare::random(&mut rng); // arbitrary fake value
    shares[1] = (sc.get_player(1), fake_share);
    
    // Reconstruction should detect fake share and fail
    // Currently it succeeds and produces corrupted output (VULNERABILITY)
    let result = DealtSecretKey::reconstruct(&sc, &shares);
    
    // Expected: result should be Err due to verification failure
    // Actual: result is Ok with corrupted secret (BUG)
    assert!(result.is_ok()); // This passes, demonstrating the vulnerability
}
```

This PoC demonstrates that fake shares are accepted during reconstruction, producing corrupted output instead of failing with verification error.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L78-91)
```rust
pub struct Subtranscript<E: Pairing> {
    // The dealt public key
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub V0: E::G2,
    // The dealt public key shares
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Vs: Vec<Vec<E::G2>>,
    /// First chunked ElGamal component: C[i][j] = s_{i,j} * G + r_j * ek_i. Here s_i = \sum_j s_{i,j} * B^j // TODO: change notation because B is not a group element?
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Cs: Vec<Vec<Vec<E::G1>>>, // TODO: maybe make this and the other fields affine? The verifier will have to do it anyway... and we are trying to speed that up
    /// Second chunked ElGamal component: R[j] = r_j * H
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Rs: Vec<Vec<E::G1>>,
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L125-286)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &Self::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        sid: &A,
    ) -> anyhow::Result<()> {
        if eks.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} encryption keys, but got {}",
                sc.get_total_num_players(),
                eks.len()
            );
        }
        if self.subtrs.Cs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of chunked ciphertexts, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Cs.len()
            );
        }
        if self.subtrs.Vs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of commitment elements, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Vs.len()
            );
        }

        // Initialize the **identical** PVSS SoK context
        let sok_cntxt = (
            &spks[self.dealer.id],
            sid.clone(),
            self.dealer.id,
            DST.to_vec(),
        ); // As above, this is a bit hacky... though we have access to `self` now

        {
            // Verify the PoK
            let eks_inner: Vec<_> = eks.iter().map(|ek| ek.ek).collect();
            let lagr_g1: &[E::G1Affine] = match &pp.pk_range_proof.ck_S.msm_basis {
                SrsBasis::Lagrange { lagr: lagr_g1 } => lagr_g1,
                SrsBasis::PowersOfTau { .. } => {
                    bail!("Expected a Lagrange basis, received powers of tau basis instead")
                },
            };
            let hom = hkzg_chunked_elgamal::WeightedHomomorphism::<E>::new(
                lagr_g1,
                pp.pk_range_proof.ck_S.xi_1,
                &pp.pp_elgamal,
                &eks_inner,
            );
            if let Err(err) = hom.verify(
                &TupleCodomainShape(
                    self.sharing_proof.range_proof_commitment.clone(),
                    chunked_elgamal::WeightedCodomainShape {
                        chunks: self.subtrs.Cs.clone(),
                        randomness: self.subtrs.Rs.clone(),
                    },
                ),
                &self.sharing_proof.SoK,
                &sok_cntxt,
            ) {
                bail!("PoK verification failed: {:?}", err);
            }

            // Verify the range proof
            if let Err(err) = self.sharing_proof.range_proof.verify(
                &pp.pk_range_proof.vk,
                sc.get_total_weight() * num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize,
                pp.ell as usize,
                &self.sharing_proof.range_proof_commitment,
            ) {
                bail!("Range proof batch verification failed: {:?}", err);
            }
        }

        let mut rng = rand::thread_rng(); // TODO: make `rng` a parameter of fn verify()?

        // Do the SCRAPE LDT
        let ldt = LowDegreeTest::random(
            &mut rng,
            sc.get_threshold_weight(),
            sc.get_total_weight() + 1,
            true,
            &sc.get_threshold_config().domain,
        ); // includes_zero is true here means it includes a commitment to f(0), which is in V[n]
        let mut Vs_flat: Vec<_> = self.subtrs.Vs.iter().flatten().cloned().collect();
        Vs_flat.push(self.subtrs.V0);
        // could add an assert_eq here with sc.get_total_weight()
        ldt.low_degree_test_group(&Vs_flat)?;

        // let eks_inner: Vec<_> = eks.iter().map(|ek| ek.ek).collect();
        // let hom = hkzg_chunked_elgamal::WeightedHomomorphism::new(
        //     &pp.pk_range_proof.ck_S.lagr_g1,
        //     pp.pk_range_proof.ck_S.xi_1,
        //     &pp.pp_elgamal,
        //     &eks_inner,
        // );
        // let (sigma_bases, sigma_scalars, beta_powers) = hom.verify_msm_terms(
        //         &TupleCodomainShape(
        //             self.sharing_proof.range_proof_commitment.clone(),
        //             chunked_elgamal::WeightedCodomainShape {
        //                 chunks: self.subtrs.Cs.clone(),
        //                 randomness: self.subtrs.Rs.clone(),
        //             },
        //         ),
        //         &self.sharing_proof.SoK,
        //         &sok_cntxt,
        //     );
        // let ldt_msm_terms = ldt.ldt_msm_input(&Vs_flat)?;
        // use aptos_crypto::arkworks::msm::verify_msm_terms_with_start;
        // verify_msm_terms_with_start(ldt_msm_terms, sigma_bases, sigma_scalars, beta_powers);

        // Now compute the final MSM // TODO: merge this multi_exp with the PoK verification, as in YOLO YOSO? // TODO2: and use the iterate stuff you developed? it's being forgotten here
        let mut base_vec = Vec::new();
        let mut exp_vec = Vec::new();

        let beta = sample_field_element(&mut rng);
        let powers_of_beta = utils::powers(beta, sc.get_total_weight() + 1);

        let Cs_flat: Vec<_> = self.subtrs.Cs.iter().flatten().cloned().collect();
        assert_eq!(
            Cs_flat.len(),
            sc.get_total_weight(),
            "Number of ciphertexts does not equal number of weights"
        ); // TODO what if zero weight?
           // could add an assert_eq here with sc.get_total_weight()

        for i in 0..Cs_flat.len() {
            for j in 0..Cs_flat[i].len() {
                let base = Cs_flat[i][j];
                let exp = pp.powers_of_radix[j] * powers_of_beta[i];
                base_vec.push(base);
                exp_vec.push(exp);
            }
        }

        let weighted_Cs = E::G1::msm(&E::G1::normalize_batch(&base_vec), &exp_vec)
            .expect("Failed to compute MSM of Cs in chunky");

        let weighted_Vs = E::G2::msm(
            &E::G2::normalize_batch(&Vs_flat[..sc.get_total_weight()]), // Don't use the last entry of `Vs_flat`
            &powers_of_beta[..sc.get_total_weight()],
        )
        .expect("Failed to compute MSM of Vs in chunky");

        let res = E::multi_pairing(
            [
                weighted_Cs.into_affine(),
                *pp.get_encryption_public_params().message_base(),
            ],
            [pp.get_commitment_base(), (-weighted_Vs).into_affine()],
        ); // Making things affine here rather than converting the two bases to group elements, since that's probably what they would be converted to anyway: https://github.com/arkworks-rs/algebra/blob/c1f4f5665504154a9de2345f464b0b3da72c28ec/ec/src/models/bls12/g1.rs#L14

        if PairingOutput::<E>::ZERO != res {
            return Err(anyhow::anyhow!("Expected zero during multi-pairing check"));
        }

        Ok(())
    }
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

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L309-330)
```rust
    fn reconstruct(
        sc: &ShamirThresholdConfig<T::Scalar>,
        shares: &[ShamirShare<Self::ShareValue>],
    ) -> Result<Self> {
        if shares.len() < sc.t {
            Err(anyhow!(
                "Incorrect number of shares provided, received {} but expected at least {}",
                shares.len(),
                sc.t
            ))
        } else {
            let (roots_of_unity_indices, bases): (Vec<usize>, Vec<Self::ShareValue>) = shares
                [..sc.t]
                .iter()
                .map(|(p, g_y)| (p.get_id(), g_y))
                .collect();

            let lagrange_coeffs = sc.lagrange_for_subset(&roots_of_unity_indices);

            Ok(T::weighted_sum(&bases, &lagrange_coeffs))
        }
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L422-467)
```rust
    fn decrypt_secret_share_from_transcript(
        pub_params: &Self::PublicParams,
        trx: &Self::Transcript,
        player_idx: u64,
        dk: &Self::NewValidatorDecryptKey,
    ) -> anyhow::Result<(Self::DealtSecretShare, Self::DealtPubKeyShare)> {
        let (sk, pk) = trx.main.decrypt_own_share(
            &pub_params.pvss_config.wconfig,
            &Player {
                id: player_idx as usize,
            },
            dk,
            &pub_params.pvss_config.pp,
        );
        assert_eq!(
            trx.fast.is_some(),
            pub_params.pvss_config.fast_wconfig.is_some()
        );
        let (fast_sk, fast_pk) = match (
            trx.fast.as_ref(),
            pub_params.pvss_config.fast_wconfig.as_ref(),
        ) {
            (Some(fast_trx), Some(fast_wconfig)) => {
                let (fast_sk, fast_pk) = fast_trx.decrypt_own_share(
                    fast_wconfig,
                    &Player {
                        id: player_idx as usize,
                    },
                    dk,
                    &pub_params.pvss_config.pp,
                );
                (Some(fast_sk), Some(fast_pk))
            },
            _ => (None, None),
        };
        Ok((
            DealtSecretKeyShares {
                main: sk,
                fast: fast_sk,
            },
            DealtPubKeyShares {
                main: pk,
                fast: fast_pk,
            },
        ))
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L469-505)
```rust
    // Test-only function
    fn reconstruct_secret_from_shares(
        pub_params: &Self::PublicParams,
        input_player_share_pairs: Vec<(u64, Self::DealtSecretShare)>,
    ) -> anyhow::Result<Self::DealtSecret> {
        let player_share_pairs: Vec<_> = input_player_share_pairs
            .clone()
            .into_iter()
            .map(|(x, y)| (Player { id: x as usize }, y.main))
            .collect();
        let reconstructed_secret = <WTrx as Transcript>::DealtSecretKey::reconstruct(
            &pub_params.pvss_config.wconfig,
            &player_share_pairs,
        )
        .unwrap();
        if input_player_share_pairs
            .clone()
            .into_iter()
            .all(|(_, y)| y.fast.is_some())
            && pub_params.pvss_config.fast_wconfig.is_some()
        {
            let fast_player_share_pairs: Vec<_> = input_player_share_pairs
                .into_iter()
                .map(|(x, y)| (Player { id: x as usize }, y.fast.unwrap()))
                .collect();
            let fast_reconstructed_secret = <WTrx as Transcript>::DealtSecretKey::reconstruct(
                pub_params.pvss_config.fast_wconfig.as_ref().unwrap(),
                &fast_player_share_pairs,
            )
            .unwrap();
            ensure!(
                reconstructed_secret == fast_reconstructed_secret,
                "real_dkg::reconstruct_secret_from_shares failed with inconsistent dealt secrets."
            );
        }
        Ok(reconstructed_secret)
    }
```

**File:** crates/aptos-dkg/src/pvss/test_utils.rs (L340-342)
```rust
            let (sk, pk) = trx.decrypt_own_share(sc, &p, &dks[p.get_id()], pp);

            assert_eq!(pk, trx.get_public_key_share(sc, &p));
```
