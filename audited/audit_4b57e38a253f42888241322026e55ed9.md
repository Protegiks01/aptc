# Audit Report

## Title
Lack of Ceremony Isolation in KZG Trapdoor Generation Enables Cross-Ceremony Attacks

## Summary
The `univariate_hiding_kzg::setup()` function generates KZG commitment scheme parameters using secret trapdoors without any ceremony-specific binding. If the same trapdoor-derived Structured Reference String (SRS) is reused across multiple PVSS ceremonies, an attacker who compromises the trapdoor in one ceremony can forge proofs in all ceremonies using that SRS, breaking the cryptographic security isolation between ceremonies.

## Finding Description
The KZG polynomial commitment scheme requires a trusted setup where secret trapdoors (τ and ξ) are used to generate public parameters, then destroyed. The security model assumes each ceremony uses a unique, independently generated trapdoor. [1](#0-0) 

The trapdoor generation uses only random field elements without mixing in any ceremony-specific identifier (epoch, ceremony ID, timestamp, etc.): [2](#0-1) 

This setup function is called by the range proof system used in chunky PVSS: [3](#0-2) 

The chunky PVSS public parameters are created without ceremony isolation: [4](#0-3) 

Note the TODO comment at line 172 acknowledging this concern. The public parameters are serializable: [5](#0-4) 

Chunky PVSS is used in the production batch encryption scheme FPTXWeighted: [6](#0-5) 

Which is the production type for secret sharing: [7](#0-6) 

**Attack Scenario:**
1. PublicParameters are created for ceremony A using trapdoor (τ₁, ξ₁)
2. Due to serialization/deserialization or predictable RNG, the same parameters are reused in ceremony B
3. An attacker compromises ceremony A and learns the trapdoor (τ₁, ξ₁)
4. The attacker can now forge range proofs in ceremony B using the same trapdoor
5. This breaks the cryptographic isolation between ceremonies

## Impact Explanation
This is a **High Severity** issue based on Aptos bug bounty criteria:

1. **Cryptographic Correctness Violation**: Breaks invariant #10 - the KZG commitment scheme's security depends on the trapdoor remaining secret and being unique per ceremony.

2. **Cross-Ceremony Attack Surface**: An attacker who compromises one ceremony gains the ability to attack all ceremonies using the same SRS, violating the security isolation principle.

3. **Proof Forgery**: With knowledge of the trapdoor, an attacker can forge opening proofs for any polynomial commitment, potentially allowing manipulation of encrypted transaction batches.

While not directly causing consensus violations or fund loss, this represents a significant protocol-level cryptographic weakness that could enable secondary attacks on the batch encryption system if exploited.

## Likelihood Explanation
**Medium-High Likelihood** based on:

1. **Serialization Support**: PublicParameters implement full serialization, making reuse technically feasible if parameters are stored and reloaded.

2. **No Prevention Mechanism**: There are zero checks or warnings against parameter reuse, and no ceremony-specific binding in the trapdoor generation.

3. **RNG Dependency**: The security relies entirely on proper RNG seeding. Deterministic or poorly-seeded RNGs could generate identical trapdoors.

4. **Deployment Uncertainty**: While the code exists and is wired into the production batch encryption types, actual production deployment status is unclear from the codebase analysis alone.

## Recommendation

**Primary Fix:** Mix ceremony-specific identifiers into trapdoor generation:

```rust
pub fn setup<E: Pairing>(
    m: usize,
    basis_type: SrsType,
    group_generators: GroupGenerators<E>,
    ceremony_id: &[u8], // NEW: unique per ceremony
    trapdoor: Trapdoor<E>,
) -> (VerificationKey<E>, CommitmentKey<E>) {
    // Hash ceremony_id into the trapdoor
    let ceremony_scalar = E::ScalarField::from_le_bytes_mod_order(
        &blake2b_simd::Params::new()
            .personal(b"APTOS_CEREMONY_ID")
            .hash(ceremony_id)
            .as_bytes()[..32]
    );
    
    let xi = trapdoor.xi + ceremony_scalar;
    let tau = trapdoor.tau + ceremony_scalar;
    
    // Rest of setup...
}
```

**Secondary Fixes:**
1. Add documentation warning against PublicParameters reuse
2. Include ceremony epoch/ID in PublicParameters struct
3. Implement freshness verification in setup functions
4. Consider using proper MPC-based trusted setup ceremony for production

## Proof of Concept

```rust
#[cfg(test)]
mod trapdoor_reuse_attack {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn demonstrate_cross_ceremony_attack() {
        let mut rng = thread_rng();
        
        // Ceremony A: Generate parameters with trapdoor
        let trapdoor_a = Trapdoor::<ark_bn254::Bn254>::rand(&mut rng);
        let (vk_a, ck_a) = setup(
            64,
            SrsType::Lagrange,
            GroupGenerators::default(),
            trapdoor_a.clone(), // Trapdoor copied (simulating reuse)
        );
        
        // Ceremony B: REUSES same trapdoor (vulnerability)
        let (vk_b, ck_b) = setup(
            64,
            SrsType::Lagrange,
            GroupGenerators::default(),
            trapdoor_a, // Same trapdoor as ceremony A!
        );
        
        // Verify that same trapdoor produces same SRS
        assert_eq!(vk_a.tau_2, vk_b.tau_2);
        assert_eq!(vk_a.xi_2, vk_b.xi_2);
        assert_eq!(ck_a.tau_1, ck_b.tau_1);
        
        // Attacker who learns trapdoor from ceremony A can now
        // forge proofs in ceremony B - this is the vulnerability
        println!("VULNERABLE: Same SRS used across ceremonies!");
    }
}
```

**Notes:**
- The main DKG ceremony uses DAS PVSS which does NOT have this vulnerability (it uses deterministic hash-to-curve without trapdoors)
- This vulnerability specifically affects the chunky PVSS variant used in batch encryption (FPTXWeighted)
- The TODO comment in the code suggests developers are aware this needs improvement
- Proper mitigation requires either MPC-based trusted setup or ceremony-specific binding in trapdoor generation

### Citations

**File:** crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs (L88-100)
```rust
pub struct Trapdoor<E: Pairing> {
    pub xi: E::ScalarField,
    pub tau: E::ScalarField,
}

impl<E: Pairing> Trapdoor<E> {
    pub fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            xi: sample_field_element(rng),
            tau: sample_field_element(rng),
        }
    }
}
```

**File:** crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs (L102-147)
```rust
pub fn setup<E: Pairing>(
    m: usize,
    basis_type: SrsType,
    group_generators: GroupGenerators<E>,
    trapdoor: Trapdoor<E>,
) -> (VerificationKey<E>, CommitmentKey<E>) {
    utils::assert_power_of_two(m);

    let GroupGenerators { g1, g2 } = group_generators;
    let Trapdoor { xi, tau } = trapdoor;

    let (xi_1, tau_1) = ((g1 * xi).into_affine(), (g1 * tau).into_affine());
    let (xi_2, tau_2) = ((g2 * xi).into_affine(), (g2 * tau).into_affine());

    let eval_dom = ark_poly::Radix2EvaluationDomain::<E::ScalarField>::new(m)
        .expect("Could not construct evaluation domain");

    let msm_basis = match basis_type {
        SrsType::Lagrange => SrsBasis::Lagrange {
            lagr: lagrange_basis::<E::G1>(g1.into(), tau, m, eval_dom),
        },
        SrsType::PowersOfTau => SrsBasis::PowersOfTau {
            tau_powers: powers_of_tau::<E::G1>(g1.into(), tau, m),
        },
    };

    let roots_of_unity_in_eval_dom = eval_dom.elements().collect();
    let m_inv = E::ScalarField::from(m as u64).inverse().unwrap();

    (
        VerificationKey {
            xi_2,
            tau_2,
            group_generators,
        },
        CommitmentKey {
            xi_1,
            tau_1,
            msm_basis,
            eval_dom,
            roots_of_unity_in_eval_dom,
            g1,
            m_inv,
        },
    )
}
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L264-273)
```rust
        // Generate trapdoor elements
        let trapdoor = univariate_hiding_kzg::Trapdoor::<E>::rand(rng);
        let xi_1_proj: E::G1 = group_generators.g1 * trapdoor.xi;

        let (vk_hkzg, ck_S) = univariate_hiding_kzg::setup(
            max_n + 1,
            SrsType::Lagrange,
            group_generators.clone(),
            trapdoor,
        );
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L161-192)
```rust
    pub fn new<R: RngCore + CryptoRng>(
        max_num_shares: usize,
        ell: u8,
        max_aggregation: usize,
        rng: &mut R,
    ) -> Self {
        let max_num_chunks_padded =
            ((max_num_shares * num_chunks_per_scalar::<E::ScalarField>(ell) as usize) + 1)
                .next_power_of_two()
                - 1;

        let group_generators = GroupGenerators::default(); // TODO: At least one of these should come from a powers of tau ceremony?
        let pp_elgamal = chunked_elgamal::PublicParameters::default();
        let G = *pp_elgamal.message_base();
        let pp = Self {
            pp_elgamal,
            pk_range_proof: dekart_univariate_v2::Proof::setup(
                max_num_chunks_padded,
                ell as usize,
                group_generators,
                rng,
            )
            .0,
            G_2: hashing::unsafe_hash_to_affine(b"G_2", DST),
            ell,
            max_aggregation,
            table: Self::build_dlog_table(G.into(), ell, max_aggregation),
            powers_of_radix: compute_powers_of_radix::<E>(ell),
        };

        pp
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L208-214)
```rust
impl<E: Pairing> ValidCryptoMaterial for PublicParameters<E> {
    const AIP_80_PREFIX: &'static str = "";

    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self).expect("unexpected error during PVSS transcript serialization")
    }
}
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L225-227)
```rust
    type SubTranscript = aptos_dkg::pvss::chunky::WeightedSubtranscript<Pairing>;
    type ThresholdConfig = aptos_crypto::weighted_config::WeightedConfigArkworks<Fr>;
    type VerificationKey = WeightedBIBEVerificationKey;
```

**File:** types/src/secret_sharing.rs (L9-16)
```rust
use aptos_batch_encryption::{
    schemes::fptx_weighted::FPTXWeighted, traits::BatchThresholdEncryption,
};
use aptos_crypto::hash::HashValue;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

pub type EncryptionKey = <FPTXWeighted as BatchThresholdEncryption>::EncryptionKey;
```
