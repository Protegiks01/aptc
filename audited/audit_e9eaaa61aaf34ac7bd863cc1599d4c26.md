# Audit Report

## Title
DKG Transcript Verification Panic Due to Unchecked Dimension Mismatch in TupleCodomainShape

## Summary
A malicious validator can crash other validators by submitting a DKG transcript with a malformed sigma protocol proof where the commitment's dimensions don't match the public statement, causing an unwrap panic during verification in `merge_msm_terms`.

## Finding Description

The DKG (Distributed Key Generation) protocol uses sigma protocol proofs to verify the correctness of PVSS (Publicly Verifiable Secret Sharing) transcripts. These proofs involve nested `TupleCodomainShape` structures that combine multiple homomorphism outputs. [1](#0-0) 

The `TupleCodomainShape` constructor is a simple wrapper that does **not validate** that its components have compatible dimensions. When a proof is deserialized, there's no dimension checking to ensure the commitment's structure matches what the homomorphism would actually produce. [2](#0-1) 

During verification, the prover's commitment and the public statement are processed together: [3](#0-2) 

The critical vulnerability occurs in `merge_msm_terms` where dimensions are assumed to match: [4](#0-3) 

**Attack Path:**

1. Malicious validator creates a DKG transcript where `sharing_proof.SoK.first_proof_item` has fewer elements when flattened via `into_iter()` than expected
2. Transcript is deserialized via BCS without dimension validation
3. Verification constructs the public statement with correct dimensions from transcript data
4. In `merge_msm_terms` (lines 153-158), `zip(prover_first_message, statement)` takes the **minimum** of both lengths
5. Normalized points are created only for the zipped pairs (line 160-161)
6. Loop iterates over `msm_terms` which has the **full expected length** (line 163)
7. For each iteration, `affine_iter.next().unwrap()` is called **twice** (lines 173-174)
8. When `affine_iter` is exhausted but iterations continue, `unwrap()` on `None` causes a **panic**

The actual verification entry point is here: [5](#0-4) 

## Impact Explanation

**Severity: HIGH** per Aptos Bug Bounty criteria ("Validator node slowdowns" and "API crashes").

A malicious validator can:
- Crash other validators processing DKG transcripts
- Prevent DKG protocol completion, disrupting randomness generation
- Cause validator nodes to panic during block validation if the malformed transcript is included
- Degrade network availability and consensus participation

This affects the **Consensus Safety** invariant as validators are expected to handle Byzantine inputs gracefully without crashing. A panic in a validator process can lead to loss of liveness and require node restarts.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Requirements**: Must be a validator participating in DKG (within Byzantine assumption of < 1/3 malicious validators)
- **Complexity**: LOW - Simply craft a transcript with mismatched dimensions in the proof structure
- **Detection**: The malformed transcript would be caught during verification, but only after causing a panic
- **Exploitability**: Any malicious validator can trigger this during each DKG epoch

The DKG protocol runs regularly (at epoch boundaries) and accepts transcripts from all validators. A single malicious validator can repeatedly submit malformed transcripts to crash peers.

## Recommendation

Add dimension validation before calling `merge_msm_terms` to ensure the prover's commitment, public statement, and MSM terms all have matching lengths. The verification should fail gracefully with an error rather than panicking.

**Fix in `sigma_protocol/traits.rs`:**

```rust
fn merge_msm_terms(
    msm_terms: Vec<Self::MsmInput>,
    prover_first_message: &Self::Codomain,
    statement: &Self::Codomain,
    powers_of_beta: &[C::ScalarField],
    c: C::ScalarField,
) -> anyhow::Result<Self::MsmInput> // Change return type to Result
{
    // Validate dimensions match
    let commitment_len = prover_first_message.clone().into_iter().count();
    let statement_len = statement.clone().into_iter().count();
    let msm_terms_len = msm_terms.len();
    
    ensure!(
        commitment_len == statement_len && statement_len == msm_terms_len,
        "Dimension mismatch: commitment={}, statement={}, msm_terms={}",
        commitment_len, statement_len, msm_terms_len
    );

    let mut final_basis = Vec::new();
    let mut final_scalars = Vec::new();
    
    // ... rest of function, but use ? instead of unwrap() and return Result
    
    Ok(Self::MsmInput::new(final_basis, final_scalars)?)
}
```

**Alternative fix in `tuple.rs` before calling merge_msm_terms:**

```rust
fn msm_terms_for_verify<Ct: Serialize, H>(
    &self,
    public_statement: &<Self as homomorphism::Trait>::Codomain,
    proof: &Proof<H1::Scalar, H>,
    cntxt: &Ct,
) -> anyhow::Result<(H1::MsmInput, H2::MsmInput)>
{
    // ... existing code ...
    
    // Validate dimensions before merge_msm_terms
    let first_commitment_len = prover_first_message.0.clone().into_iter().count();
    let first_statement_len = public_statement.0.clone().into_iter().count();
    let first_response_len = first_msm_terms_of_response.into_iter().count();
    
    ensure!(
        first_commitment_len == first_statement_len && 
        first_statement_len == first_response_len,
        "First component dimension mismatch"
    );
    
    // Similar check for second component
    
    // ... rest of function
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use aptos_crypto::weighted_config::WeightedConfigArkworks;
    
    #[test]
    #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
    fn test_dimension_mismatch_panic() {
        // Setup DKG parameters
        let mut rng = rand::thread_rng();
        let num_players = 4;
        let threshold = 3;
        
        // Create a valid config
        let sc = WeightedConfigArkworks::<Fr>::new(num_players, vec![1; num_players], threshold);
        
        // Create a malformed proof where first_proof_item has FEWER elements
        let mut proof = hkzg_chunked_elgamal_commit::Proof::<Bls12_381>::generate(
            &sc, 
            4, // number_of_chunks_per_share
            &mut rng
        );
        
        // Manually construct a malformed first_proof_item with truncated dimensions
        // (In real attack, deserialize from crafted bytes)
        let malformed_commitment = TupleCodomainShape(
            TupleCodomainShape(
                TrivialShape(G1::generator()), // Only 1 element instead of expected
                chunked_elgamal::WeightedCodomainShape {
                    chunks: vec![vec![vec![]; num_players - 1]], // Truncated
                    randomness: vec![vec![]], // Truncated
                },
            ),
            chunked_scalar_mul::CodomainShape(vec![vec![]; num_players - 1]), // Truncated
        );
        
        proof.first_proof_item = FirstProofItem::Commitment(malformed_commitment);
        
        // Create homomorphism and public statement with CORRECT dimensions
        let pp = create_public_parameters(&sc);
        let hom = create_homomorphism(&pp, &sc);
        let public_statement = create_correct_statement(&sc); // Full dimensions
        
        // This will panic when merge_msm_terms tries to unwrap exhausted iterator
        hom.verify(&public_statement, &proof, &context).unwrap();
        // PANIC occurs at traits.rs:173-174
    }
}
```

**Notes:**

This vulnerability exists because:
1. `TupleCodomainShape` is a generic wrapper without dimension validation
2. Deserialization doesn't enforce structural consistency between proof components
3. `merge_msm_terms` uses `.unwrap()` instead of returning `Result` for error handling
4. The verification logic assumes dimensions match without explicit validation

The fix should add dimension checking at the earliest possible point (deserialization or verification entry) and use proper error handling instead of panics throughout the sigma protocol verification stack.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal_commit.rs (L37-71)
```rust
impl<'a, E: Pairing> Proof<'a, E> {
    /// Generates a random looking proof (but not a valid one).
    /// Useful for testing and benchmarking.
    pub fn generate<R: rand::Rng + rand::CryptoRng>(
        sc: &WeightedConfigArkworks<E::ScalarField>,
        number_of_chunks_per_share: usize,
        rng: &mut R,
    ) -> Self {
        // or should number_of_chunks_per_share be a const?
        let hkzg_chunked_elgamal::WeightedProof::<E> {
            first_proof_item,
            z,
        } = hkzg_chunked_elgamal::WeightedProof::generate(sc, number_of_chunks_per_share, rng);
        match first_proof_item {
            FirstProofItem::Commitment(first_proof_item_inner) => {
                Self {
                    first_proof_item: FirstProofItem::Commitment(TupleCodomainShape(
                        first_proof_item_inner,
                        chunked_scalar_mul::CodomainShape::<E::G2>(
                            (0..sc.get_total_num_players()) // TODO: make this stuff less complicated!!!
                                .map(|i| {
                                    let w = sc.get_player_weight(&sc.get_player(i)); // TODO: combine these functions...
                                    unsafe_random_points_group(w, rng)
                                })
                                .collect(),
                        ),
                    )),
                    z,
                }
            },
            FirstProofItem::Challenge(_) => {
                panic!("Unexpected Challenge variant!");
            },
        }
    }
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/tuple.rs (L90-95)
```rust
/// A wrapper to combine the codomain shapes of two homomorphisms into a single type.
///
/// This is necessary because Rust tuples do **not** inherit traits like `IntoIterator`,
/// but `fixed_base_msms::CodomainShape<T>` requires them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TupleCodomainShape<A, B>(pub A, pub B);
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/tuple.rs (L325-376)
```rust
    fn msm_terms_for_verify<Ct: Serialize, H>(
        &self,
        public_statement: &<Self as homomorphism::Trait>::Codomain,
        proof: &Proof<H1::Scalar, H>,
        cntxt: &Ct,
    ) -> (H1::MsmInput, H2::MsmInput)
    where
        H: homomorphism::Trait<
            Domain = <Self as homomorphism::Trait>::Domain,
            Codomain = <Self as homomorphism::Trait>::Codomain,
        >, // need this?
    {
        let prover_first_message = match &proof.first_proof_item {
            FirstProofItem::Commitment(A) => A,
            FirstProofItem::Challenge(_) => {
                panic!("Missing implementation - expected commitment, not challenge")
            },
        };
        let c = fiat_shamir_challenge_for_sigma_protocol::<_, H1::Scalar, _>(
            cntxt,
            self,
            public_statement,
            &prover_first_message,
            &self.dst(),
        );

        let mut rng = ark_std::rand::thread_rng(); // TODO: make this part of the function input?
        let beta = H1::Scalar::rand(&mut rng); // verifier-specific challenge
        let len1 = public_statement.0.clone().into_iter().count(); // hmm maybe pass the into_iter version in merge_msm_terms?
        let len2 = public_statement.1.clone().into_iter().count();
        let powers_of_beta = utils::powers(beta, len1 + len2);
        let (first_powers_of_beta, second_powers_of_beta) = powers_of_beta.split_at(len1);

        let (first_msm_terms_of_response, second_msm_terms_of_response) = self.msm_terms(&proof.z);

        let first_input = H1::merge_msm_terms(
            first_msm_terms_of_response.into_iter().collect(),
            &prover_first_message.0,
            &public_statement.0,
            first_powers_of_beta,
            c,
        );
        let second_input = H2::merge_msm_terms(
            second_msm_terms_of_response.into_iter().collect(),
            &prover_first_message.1,
            &public_statement.1,
            second_powers_of_beta,
            c,
        );

        (first_input, second_input)
    }
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L506-529)
```rust
            let hom = hkzg_chunked_elgamal_commit::Homomorphism::<E>::new(
                lagr_g1,
                pp.pk_range_proof.ck_S.xi_1,
                &pp.pp_elgamal,
                &eks_inner,
                pp.get_commitment_base(),
                pp.ell,
            );
            if let Err(err) = hom.verify(
                &TupleCodomainShape(
                    TupleCodomainShape(
                        self.sharing_proof.range_proof_commitment.clone(),
                        chunked_elgamal::WeightedCodomainShape {
                            chunks: self.subtrs.Cs.clone(),
                            randomness: self.subtrs.Rs.clone(),
                        },
                    ),
                    chunked_scalar_mul::CodomainShape(self.subtrs.Vs.clone()),
                ),
                &self.sharing_proof.SoK,
                &sok_cntxt,
            ) {
                bail!("PoK verification failed: {:?}", err);
            }
```
