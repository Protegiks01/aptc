# Audit Report

## Title
DKG Transcript Signature Malleability Allows Entropy Reduction Attack via Unbounded maul_signature()

## Summary
The `maul_signature()` function in the DKG PVSS implementation is documented as "testing-only and benchmarking-only" but lacks `#[cfg(test)]` protection, making it callable in production. Malicious validators can intercept honest dealers' transcripts, call this public method to change the dealer ID and signature while preserving the original proof-of-knowledge, then rebroadcast as their own contribution. This passes all verification checks and causes the aggregation system to double-count the honest validator's randomness while the attacker contributes zero entropy, breaking DKG's cryptographic guarantees.

## Finding Description

The `MalleableTranscript` trait is defined as a public trait with explicit documentation stating it provides "testing-only and benchmarking-only interfaces," yet the trait and all its implementations completely lack `#[cfg(test)]` or feature gate protection. [1](#0-0) 

The production DKG system uses `WeightedTranscript` (aliased as `WTrx`) which implements this vulnerable trait. [2](#0-1)  The implementation modifies only the dealer player ID, commitment reference, and BLS signature in the first `soks` entry, while crucially leaving the original proof-of-knowledge (PoK) unchanged. [3](#0-2) 

**Attack Execution:**

1. Honest validator A generates a legitimate transcript by dealing a random polynomial p_A(X), creates proof-of-knowledge for g^{p_A(0)}, and broadcasts it via `DKGManager::setup_deal_broadcast()` [4](#0-3) 

2. Malicious validator B receives and deserializes A's transcript from network messages [5](#0-4) 

3. B invokes the public `maul_signature()` method with B's signing key, auxiliary data, and player ID, transforming the signature-of-knowledge entry from (A, V_A[n], sig_A, pok_A) to (B, V_A[n], sig_B, pok_A)

4. B re-serializes and broadcasts the mauled transcript claiming to be from B

5. When received, the transcript passes the single-dealer verification because the dealer set extracted from `soks` now contains only B, matching the sender requirement [6](#0-5) 

6. The main transcript verification retrieves B's public key from the validator set and successfully verifies B's signature over the contribution structure [7](#0-6) 

7. The batch PoK verification checks that proofs are mathematically valid for their commitments but does not verify the creator's identity, so A's original PoK remains valid [8](#0-7) 

8. Both transcripts are accepted and aggregated, summing all cryptographic elements: V_agg = V_A + V_A = 2*V_A, C_agg = 2*C_A, etc. [9](#0-8) 

The final aggregated DKG secret is based on 2*p_A(0) instead of p_A(0) + p_B(0), meaning only A's randomness is included (counted twice) while B contributed zero entropy.

## Impact Explanation

This constitutes a **CRITICAL** severity vulnerability under Aptos Bug Bounty criteria as a **Cryptographic Vulnerability**:

1. **DKG Cryptographic Correctness Failure**: The DKG protocol's security model requires at least t independent random contributions from honest dealers to achieve the desired security threshold. This attack allows Byzantine validators to appear as contributors without adding any entropy, causing honest contributions to be double-counted. If multiple Byzantine validators (< n/3) each maul different honest transcripts, the final DKG secret has fewer independent contributions than required for the security threshold.

2. **Consensus Randomness Manipulation Risk**: DKG-generated randomness is used for critical consensus operations including leader election in AptosBFT. Reduced entropy makes this randomness more predictable and potentially manipulable by attackers who can selectively choose which honest transcripts to duplicate, potentially enabling attacks on leader selection fairness.

3. **Cryptographic Security Threshold Violation**: If b Byzantine validators maul b distinct honest transcripts, the system believes it has aggregated f + b contributions but actually has only f independent random inputs. This violates the fundamental cryptographic assumption that each accepted transcript represents an independent contribution to the shared secret.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Requirements**: Only requires being a validator in the network with standard privileges. No majority stake, collusion, or special access required. Within the < 1/3 Byzantine validator threat model.

- **Technical Complexity**: Extremely low. The attack is a simple three-step process: (1) deserialize received transcript bytes using standard BCS deserialization, (2) call the public `maul_signature()` method, (3) re-serialize and broadcast. All required components are exposed through public APIs.

- **Detection Difficulty**: Virtually impossible to detect. The mauled transcript passes all cryptographic verification checks (signature verification, PoK verification, dealer set validation). Network observers cannot distinguish between legitimate transcripts and mauled ones without tracking the underlying cryptographic data, which validators don't do.

- **Attack Window**: Available during every DKG ceremony at each epoch transition, providing recurring opportunities. Epochs transition regularly in Aptos.

- **Economic Incentive**: Malicious validators can appear as legitimate contributors without performing the computational work of generating random polynomials, effectively "free-riding" on honest validators' contributions while potentially gaining reputation or rewards for participation.

## Recommendation

Add `#[cfg(any(test, feature = "testing"))]` attribute to the `MalleableTranscript` trait definition and all its implementations to restrict this functionality to test/benchmark builds only:

```rust
#[cfg(any(test, feature = "testing"))]
pub trait MalleableTranscript: Transcript {
    fn maul_signature<A: Serialize + Clone>(
        &mut self,
        ssk: &Self::SigningSecretKey,
        session_id: &A,
        dealer: &Player,
    );
}
```

Additionally, implement cryptographic binding in the PoK to include the dealer's identity, ensuring that proofs cannot be reused by different dealers. The PoK should commit to both the secret commitment and the dealer's public key.

## Proof of Concept

```rust
// This demonstrates the attack flow (pseudo-code showing the vulnerability)
// In practice, this would be executed by a malicious validator

use aptos_dkg::pvss::das::WeightedTranscript;
use aptos_dkg::pvss::traits::transcript::MalleableTranscript;

fn exploit_dkg_malleability(
    honest_transcript_bytes: &[u8],
    attacker_secret_key: &PrivateKey,
    attacker_player_id: Player,
) -> Vec<u8> {
    // Step 1: Deserialize honest validator's transcript
    let mut transcript: WeightedTranscript = 
        bcs::from_bytes(honest_transcript_bytes).unwrap();
    
    // Step 2: Call the unprotected maul_signature() method
    // This changes dealer ID and signature but preserves the PoK
    transcript.maul_signature(
        attacker_secret_key,
        &(epoch, attacker_addr),
        &attacker_player_id
    );
    
    // Step 3: Serialize and broadcast as own contribution
    // This will pass all verification checks and be aggregated
    bcs::to_bytes(&transcript).unwrap()
}

// The mauled transcript will:
// - Pass verify_transcript_extra() because dealer set = {attacker}
// - Pass signature verification because attacker signed it
// - Pass PoK verification because the original PoK is still valid
// - Be aggregated, doubling the honest validator's contribution
```

**Notes**

This vulnerability exists because a function explicitly documented as "testing-only and benchmarking-only" lacks the standard Rust conditional compilation guards (`#[cfg(test)]`) that would restrict it to test builds. The function is part of a public trait implemented by production DKG types, making it callable by any code that can deserialize a transcript. The verification system validates signatures and proofs individually but fails to detect that the proof-of-knowledge was created by a different dealer than the one claiming authorship in the mauled transcript, enabling the entropy reduction attack.

### Citations

**File:** crates/aptos-dkg/src/pvss/traits/transcript.rs (L321-332)
```rust
/// This traits defines testing-only and benchmarking-only interfaces.
pub trait MalleableTranscript: Transcript {
    /// This is useful for generating many PVSS transcripts from different dealers from a single
    /// PVSS transcript by recomputing its signature. It is used to deal quickly when benchmarking
    /// aggregated PVSS transcript verification
    fn maul_signature<A: Serialize + Clone>(
        &mut self,
        ssk: &Self::SigningSecretKey,
        session_id: &A,
        dealer: &Player,
    );
}
```

**File:** types/src/dkg/real_dkg/mod.rs (L38-38)
```rust
pub type WTrx = pvss::das::WeightedTranscript;
```

**File:** types/src/dkg/real_dkg/mod.rs (L312-316)
```rust
        if ensures_single_dealer.is_some() {
            let expected_dealer_set: HashSet<AccountAddress> =
                ensures_single_dealer.into_iter().collect();
            ensure!(expected_dealer_set == dealer_set);
        }
```

**File:** types/src/dkg/real_dkg/mod.rs (L358-374)
```rust
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
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L522-535)
```rust
impl MalleableTranscript for Transcript {
    fn maul_signature<A: Serialize + Clone>(
        &mut self,
        ssk: &Self::SigningSecretKey,
        aux: &A,
        player: &Player,
    ) {
        let comm = self.V.last().unwrap();
        let sig = Transcript::sign_contribution(ssk, player, aux, comm);
        self.soks[0].0 = *player;
        self.soks[0].1 = *comm;
        self.soks[0].2 = sig;
    }
}
```

**File:** dkg/src/dkg_manager/mod.rs (L332-339)
```rust
        let trx = DKG::generate_transcript(
            &mut rng,
            &public_params,
            &input_secret,
            self.my_index as u64,
            &self.dealer_sk,
            &self.dealer_pk,
        );
```

**File:** dkg/src/transcript_aggregation/mod.rs (L88-90)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L70-76)
```rust
    let poks = soks
        .iter()
        .map(|(_, c, _, pok)| (*c, *pok))
        .collect::<Vec<(Gr, schnorr::PoK<Gr>)>>();

    // TODO(Performance): 128-bit exponents instead of powers of tau
    schnorr::pok_batch_verify::<Gr>(&poks, pk_base, &tau)?;
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L327-338)
```rust
        self.hat_w += other.hat_w;
        self.C_0 += other.C_0;

        for i in 0..sc.n {
            self.C[i] += other.C[i];
            self.V[i] += other.V[i];
        }
        self.V[sc.n] += other.V[sc.n];

        for sok in &other.soks {
            self.soks.push(sok.clone());
        }
```
