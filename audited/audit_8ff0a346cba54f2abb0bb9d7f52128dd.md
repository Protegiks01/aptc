# Audit Report

## Title
Validator Denial of Service via Malformed DKG Sigma Protocol Proof with Asymmetric CodomainShape Dimensions

## Summary
A malicious attacker can crash validator nodes by submitting DKG transcripts containing sigma protocol proofs with mismatched `CodomainShape` dimensions. The verification code in `merge_msm_terms` assumes that the prover's commitment, public statement, and prover's response all have the same number of elements when flattened, but this invariant is not validated before deserialization, allowing a panic during verification.

## Finding Description

The DKG (Distributed Key Generation) system uses weighted PVSS with sigma protocol proofs. The `CodomainShape` struct in [1](#0-0)  wraps a `Vec<Vec<T>>` structure where different rows can have different lengths (asymmetric dimensions) to represent players with different weights.

The `IntoIterator` implementation [2](#0-1)  safely flattens this structure using Rust's `flatten()` method, which is memory-safe and does not cause out-of-bounds access.

However, a critical vulnerability exists in the sigma protocol verification logic. When verifying a proof, the `merge_msm_terms` function [3](#0-2)  performs the following operations:

1. Zips `prover_first_message` with `statement` to collect points for normalization [4](#0-3) 
2. Normalizes these points to create `affine_iter` [5](#0-4) 
3. Iterates over `msm_terms` [6](#0-5) 
4. Inside the loop, calls `affine_iter.next().unwrap()` twice per iteration [7](#0-6) 

The number of elements in `affine_iter` equals `2 * min(|prover_first_message|, |statement|)` due to the zip operation. However, the loop iterates `min(|msm_terms|, |powers_of_beta|)` times, where `|powers_of_beta| = |statement|` [8](#0-7) .

**Attack Path:**
1. Attacker crafts a malicious `SharingProof` where:
   - `proof.z` (prover's response) has the correct weighted structure (e.g., players with weights [3, 4, 2])
   - `proof.first_proof_item.Commitment` has fewer elements (e.g., players with weights [1, 1, 1])
2. Attacker submits this as part of a DKG transcript via `ValidatorTransaction::DKGResult`
3. Validator calls `verify_transcript` [9](#0-8) 
4. This calls `trx.main.verify()` [10](#0-9) 
5. Which calls `hom.verify()` [11](#0-10) 
6. Leading to `merge_msm_terms` with mismatched dimensions
7. The loop tries to call `unwrap()` on an exhausted iterator, causing a **panic**
8. Validator node crashes

The vulnerability exists because there is no validation that `proof.first_proof_item.Commitment` has the same structure as the expected public statement before performing verification.

## Impact Explanation

This vulnerability allows **Denial of Service attacks against validator nodes**. A single malicious DKG transcript can crash any validator that attempts to verify it. This meets the **High Severity** criteria per the Aptos bug bounty program:
- **Validator node crashes** (API crashes)
- **Consensus disruption** if enough validators are affected during DKG ceremony
- **Network availability impact** as DKG cannot complete if validators keep crashing

While this doesn't directly result in fund loss or consensus safety violations, it significantly impacts network liveness and validator operations, which are critical for Aptos's BFT consensus.

## Likelihood Explanation

**Likelihood: High**

- **No authentication required**: Any network participant can submit a `ValidatorTransaction::DKGResult`
- **Easy to exploit**: Attacker only needs to craft a malformed proof with mismatched dimensions
- **No special privileges needed**: Does not require validator keys or insider access
- **Deterministic**: The panic will occur reliably on every affected validator
- **Affects critical path**: DKG transcript verification is part of consensus/epoch transition

The only complexity is understanding the proof structure, but once identified, exploitation is straightforward via BCS deserialization manipulation.

## Recommendation

Add explicit validation that the proof structure matches expected dimensions before calling `merge_msm_terms`. Specifically, in the `verify` method or `msm_terms_for_verify`:

```rust
fn msm_terms_for_verify<Ct: Serialize, H>(
    &self,
    public_statement: &Self::Codomain,
    proof: &Proof<C::ScalarField, H>,
    cntxt: &Ct,
) -> antml:Result<Self::MsmInput>
where
    H: homomorphism::Trait<Domain = Self::Domain, Codomain = Self::Codomain>,
{
    let prover_first_message = match &proof.first_proof_item {
        FirstProofItem::Commitment(A) => A,
        FirstProofItem::Challenge(_) => {
            bail!("Expected commitment, not challenge")
        },
    };

    let number_of_beta_powers = public_statement.clone().into_iter().count();
    
    // VALIDATION: Check structural consistency
    let commitment_count = prover_first_message.clone().into_iter().count();
    ensure!(
        commitment_count == number_of_beta_powers,
        "Proof commitment has {} elements but statement has {} elements",
        commitment_count,
        number_of_beta_powers
    );

    let msm_terms_for_prover_response = self.msm_terms(&proof.z);
    let response_count = msm_terms_for_prover_response.clone().into_iter().count();
    ensure!(
        response_count == number_of_beta_powers,
        "Proof response has {} elements but statement has {} elements",
        response_count,
        number_of_beta_powers
    );

    let (c, powers_of_beta) = self.compute_verifier_challenges(/* ... */);
    
    Ok(Self::merge_msm_terms(/* ... */))
}
```

This ensures all three components have matching element counts before verification proceeds.

## Proof of Concept

```rust
// Conceptual PoC - would need full DKG setup to compile
use aptos_dkg::pvss::chunky::{weighted_transcript, chunked_elgamal};
use aptos_dkg::sigma_protocol::{Proof, FirstProofItem, homomorphism::tuple::TupleCodomainShape};

fn craft_malicious_transcript() -> weighted_transcript::Transcript<E> {
    // 1. Generate a valid transcript
    let valid_trx = weighted_transcript::Transcript::deal(/* valid params */);
    
    // 2. Extract and modify the proof
    let mut malicious_proof = valid_trx.sharing_proof.SoK.clone();
    
    // 3. Replace the commitment with fewer elements
    if let FirstProofItem::Commitment(TupleCodomainShape(hkzg_commit, weighted_shape)) = &mut malicious_proof.first_proof_item {
        // Reduce each player's chunks to single element
        weighted_shape.chunks = weighted_shape.chunks.iter()
            .map(|player_chunks| vec![player_chunks[0].clone()])
            .collect();
        // Keep response z unchanged with full weights
    }
    
    // 4. Create malicious transcript
    weighted_transcript::Transcript {
        dealer: valid_trx.dealer,
        subtrs: valid_trx.subtrs,
        sharing_proof: SharingProof {
            SoK: malicious_proof,
            range_proof: valid_trx.sharing_proof.range_proof,
            range_proof_commitment: valid_trx.sharing_proof.range_proof_commitment,
        },
    }
}

#[test]
fn test_validator_panic_on_malicious_transcript() {
    let malicious_trx = craft_malicious_transcript();
    
    // When validator tries to verify, it will panic
    let result = malicious_trx.verify(/* params */);
    // Expected: panic at unwrap() in merge_msm_terms
    // Actual behavior: validator crashes
}
```

**Note**: The asymmetric dimensions in `CodomainShape` are **by design** for weighted PVSS, but the lack of structural validation during proof verification creates this exploitable denial-of-service vulnerability.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_scalar_mul.rs (L35-36)
```rust
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CodomainShape<T: CanonicalSerialize + CanonicalDeserialize + Clone>(pub Vec<Vec<T>>);
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_scalar_mul.rs (L61-71)
```rust
impl<T> IntoIterator for CodomainShape<T>
where
    T: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    type IntoIter = std::vec::IntoIter<T>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter().flatten().collect::<Vec<_>>().into_iter()
    }
}
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L120-120)
```rust
        let number_of_beta_powers = public_statement.clone().into_iter().count(); // TODO: maybe pass the into_iter version in merge_msm_terms?
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L139-184)
```rust
    fn merge_msm_terms(
        msm_terms: Vec<Self::MsmInput>,
        prover_first_message: &Self::Codomain,
        statement: &Self::Codomain,
        powers_of_beta: &[C::ScalarField],
        c: C::ScalarField,
    ) -> Self::MsmInput
    {
        let mut final_basis = Vec::new();
        let mut final_scalars = Vec::new();

        // Collect all projective points to batch normalize
        // TODO: remove this stuff... we may assume things are deserialised and hence essentially affine, so into_affine() should do
        let mut all_points_to_normalize = Vec::new();
        for (A, P) in prover_first_message.clone().into_iter()
            .zip(statement.clone().into_iter())
        {
            all_points_to_normalize.push(A);
            all_points_to_normalize.push(P);
        }

        let affine_points = C::normalize_batch(&all_points_to_normalize);
        let mut affine_iter = affine_points.into_iter();

        for (term, beta_power) in msm_terms.into_iter().zip(powers_of_beta) {
            let mut bases = term.bases().to_vec();
            let mut scalars = term.scalars().to_vec();

            // Multiply scalars by βᶦ
            for scalar in scalars.iter_mut() {
                *scalar *= beta_power;
            }

            // Add prover + statement contributions
            bases.push(affine_iter.next().unwrap()); // this is the element `A` from the prover's first message
            bases.push(affine_iter.next().unwrap()); // this is the element `P` from the statement, but we'll need `P^c`

            scalars.push(- (*beta_power));
            scalars.push(-c * beta_power);

            final_basis.extend(bases);
            final_scalars.extend(scalars);
        }

        Self::MsmInput::new(final_basis, final_scalars).expect("Something went wrong constructing MSM input")
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L178-190)
```rust
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
```
