# Audit Report

## Title
ElGamal Randomness Reuse in GenericWeighting PVSS Wrapper Exposes Polynomial Evaluation Relationships

## Summary
The `GenericWeighting` wrapper for weighted PVSS duplicates encryption keys and, when combined with underlying PVSS schemes that use single randomness (like `das::unweighted_protocol::Transcript`), creates ciphertexts that leak polynomial evaluation differences. However, this code is explicitly marked as insecure and **not used in production**.

## Finding Description

The `GenericWeighting<T>` generic wrapper transforms unweighted PVSS into weighted PVSS by duplicating encryption keys proportional to player weights. [1](#0-0) 

When `deal()` is called, it passes these duplicated encryption keys to the underlying scheme: [2](#0-1) 

The unweighted DAS protocol uses a **single randomness value** for all ElGamal encryptions: [3](#0-2) 

This combination creates multiple ciphertexts `C[i] = h₁^{f(ωⁱ)} · ek^r` and `C[j] = h₁^{f(ωʲ)} · ek^r` using the same encryption key `ek` and randomness `r`, allowing computation of `C[i]/C[j] = h₁^{f(ωⁱ) - f(ωʲ)}`, revealing polynomial evaluation differences.

**Critical Mitigation**: The developers are aware of this issue. The code contains explicit warnings: [4](#0-3) 

And test files explicitly mark it as insecure: [5](#0-4) 

**Production Uses Secure Implementation**: The production codebase uses `das::WeightedTranscript` which generates **independent randomness for each share**, eliminating the vulnerability: [6](#0-5) 

## Impact Explanation

**Actual Impact: None** - This code is not used in production. The vulnerability only exists in test infrastructure explicitly marked as insecure.

**Hypothetical Impact (if used)**: Would be **Critical** - violates ElGamal semantic security assumptions, potentially enabling threshold reduction attacks on DKG randomness generation, compromising consensus security.

## Likelihood Explanation

**Likelihood: Extremely Low** - The code:
1. Is explicitly documented as insecure
2. Only appears in test files
3. Has production alternatives (`das::WeightedTranscript`) that are used instead
4. Contains TODO comments suggesting removal

For exploitation to occur, a developer would need to ignore explicit warnings and use `GenericWeighting<das::Transcript>` in production code, which is highly unlikely.

## Recommendation

Since this is test/comparison code explicitly marked as insecure:

1. **Add compiler warnings** to prevent accidental production use
2. **Consider removal** as suggested by TODO comments
3. **Make the module private** to prevent external usage
4. **Continue using** `das::WeightedTranscript` for all production DKG operations

No code fix needed as production code is already secure.

## Proof of Concept

Not applicable - this is not an exploitable vulnerability in production code. The issue is already known, documented, and mitigated by using the correct implementation (`das::WeightedTranscript`) in production.

---

## Notes

After thorough investigation, while the cryptographic vulnerability exists in the `GenericWeighting` wrapper as described in the security question, it does **not** constitute an exploitable vulnerability in the Aptos blockchain because:

1. The production DKG implementation uses `das::WeightedTranscript` [7](#0-6)  which uses independent randomness per share
2. `GenericWeighting` is only used in test files with explicit "Insecure" warnings
3. The developers are fully aware of the limitation and have implemented secure alternatives

The security question accurately identifies a cryptographic design flaw, but this flaw exists only in test infrastructure, not in production consensus code.

### Citations

**File:** crates/aptos-dkg/src/pvss/weighted/generic_weighting.rs (L6-7)
```rust
/// WARNING: This will **NOT** necessarily be secure for any PVSS scheme, since it will reuse encryption
/// keys, which might not be safe depending on the PVSS scheme.
```

**File:** crates/aptos-dkg/src/pvss/weighted/generic_weighting.rs (L49-66)
```rust
    fn to_weighted_encryption_keys(
        sc: &WeightedConfigBlstrs,
        eks: &[T::EncryptPubKey],
    ) -> Vec<T::EncryptPubKey> {
        // Re-organize the encryption key vector so that we deal multiple shares to each player,
        // proportional to their weight.
        let mut duplicated_eks = Vec::with_capacity(sc.get_total_weight());

        for (player_id, ek) in eks.iter().enumerate() {
            let player = sc.get_player(player_id);
            let num_shares = sc.get_player_weight(&player);
            for _ in 0..num_shares {
                duplicated_eks.push(ek.clone());
            }
        }

        duplicated_eks
    }
```

**File:** crates/aptos-dkg/src/pvss/weighted/generic_weighting.rs (L97-124)
```rust
    fn deal<A: Serialize + Clone, R: RngCore + CryptoRng>(
        sc: &Self::SecretSharingConfig,
        pp: &Self::PublicParameters,
        ssk: &Self::SigningSecretKey,
        spk: &Self::SigningPubKey,
        eks: &[Self::EncryptPubKey],
        s: &Self::InputSecret,
        aux: &A,
        dealer: &Player,
        rng: &mut R,
    ) -> Self {
        // WARNING: This duplication of encryption keys will NOT be secure in some PVSS schemes.
        let duplicated_eks = GenericWeighting::<T>::to_weighted_encryption_keys(sc, eks);

        GenericWeighting {
            trx: T::deal(
                sc.get_threshold_config(),
                pp,
                ssk,
                spk,
                &duplicated_eks,
                s,
                aux,
                dealer,
                rng,
            ),
        }
    }
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L121-138)
```rust
        let r = random_scalar(&mut rng);
        let g_1 = pp.get_encryption_public_params().pubkey_base();
        let g_2 = pp.get_commitment_base();
        let h_1 = *pp.get_encryption_public_params().message_base();

        let V = (0..sc.n)
            .map(|i| g_2.mul(f_evals[i]))
            .chain([g_2.mul(f[0])])
            .collect::<Vec<G2Projective>>();

        let C = (0..sc.n)
            .map(|i| {
                g1_multi_exp(
                    [h_1, Into::<G1Projective>::into(&eks[i])].as_slice(),
                    [f_evals[i], r].as_slice(),
                )
            })
            .collect::<Vec<G1Projective>>();
```

**File:** crates/aptos-dkg/tests/pvss.rs (L74-80)
```rust
        // Generically-weighted Das
        // WARNING: Insecure, due to encrypting different shares with the same randomness, do not use!
        // TODO: Remove?
        pvss_deal_verify_and_reconstruct::<GenericWeighting<das::Transcript>>(
            &wc,
            seed.to_bytes_le(),
        );
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L114-124)
```rust
    fn deal<A: Serialize + Clone, R: rand_core::RngCore + rand_core::CryptoRng>(
        sc: &Self::SecretSharingConfig,
        pp: &Self::PublicParameters,
        ssk: &Self::SigningSecretKey,
        _spk: &Self::SigningPubKey,
        eks: &[Self::EncryptPubKey],
        s: &Self::InputSecret,
        aux: &A,
        dealer: &Player,
        mut rng: &mut R,
    ) -> Self {
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L134-170)
```rust
        // Pick ElGamal randomness r_j, \forall j \in [W]
        // r[j] = r_{j+1}, \forall j \in [0, W-1]
        let r = random_scalars(W, &mut rng);
        let g_1 = pp.get_encryption_public_params().pubkey_base();
        let g_2 = pp.get_commitment_base();
        let h = *pp.get_encryption_public_params().message_base();

        // NOTE: Recall s_i is the starting index of player i in the vector of shares
        //  - V[s_i + j - 1] = g_2^{f(s_i + j - 1)}
        //  - V[W] = g_2^{f(0)}
        let V = (0..W)
            .map(|k| g_1.mul(f_evals[k]))
            .chain([g_1.mul(f_coeff[0])])
            .collect::<Vec<G1Projective>>();
        let V_hat = (0..W)
            .map(|k| g_2.mul(f_evals[k]))
            .chain([g_2.mul(f_coeff[0])])
            .collect::<Vec<G2Projective>>();

        // R[j] = g_1^{r_{j + 1}},  \forall j \in [0, W-1]
        let R = (0..W).map(|j| g_1.mul(r[j])).collect::<Vec<G1Projective>>();
        let R_hat = (0..W).map(|j| g_2.mul(r[j])).collect::<Vec<G2Projective>>();

        let mut C = Vec::with_capacity(W);
        for i in 0..n {
            let w_i = sc.get_player_weight(&sc.get_player(i));

            let bases = vec![h, Into::<G1Projective>::into(&eks[i])];
            for j in 0..w_i {
                let k = sc.get_share_index(i, j).unwrap();

                C.push(g1_multi_exp(
                    bases.as_slice(),
                    [f_evals[k], r[k]].as_slice(),
                ))
            }
        }
```
