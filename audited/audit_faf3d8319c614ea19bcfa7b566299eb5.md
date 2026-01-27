# Audit Report

## Title
Missing Duplicate Dealer Validation in DKG Transcript Verification Allows Dealer Influence Manipulation

## Summary
The DKG (Distributed Key Generation) transcript verification in `verify_transcript()` fails to check for duplicate dealer entries in the `soks` field, allowing transcripts with repeated dealer contributions to pass cryptographic validation. This enables a dealer to gain outsized influence over the shared randomness output, violating the fairness guarantee of the DKG protocol.

## Finding Description

The Transcript struct initialization at lines 146-152 in `unweighted_protocol.rs` creates a new transcript with a single SoK (Signature of Knowledge) entry. However, during aggregation or when deserializing transcript bytes, the `soks` vector can contain duplicate dealer entries. [1](#0-0) 

The `aggregate_with` function blindly appends SoKs from other transcripts without checking for duplicates: [2](#0-1) 

When the VM processes a DKG result, it calls only `verify_transcript()`, which does NOT check for duplicate dealers: [3](#0-2) 

The `verify_transcript()` implementation constructs `spks` and `aux` arrays based on the dealers extracted from the transcript, including any duplicates: [4](#0-3) 

In `batch_verify_soks`, the commitment sum check compares the sum of all commitments (including duplicates) against `pk`, which would also include duplicates if the transcript was crafted consistently: [5](#0-4) 

The BLS aggregate signature verification explicitly allows duplicate messages and public keys due to using proofs-of-possession: [6](#0-5) 

While `verify_transcript_extra()` DOES check for duplicates, it's only called during peer transcript aggregation, not in the VM verification path: [7](#0-6) 

The deserialization path also lacks validation: [8](#0-7) 

**Attack Path:**
1. Attacker obtains or crafts a valid transcript where dealer `i`'s SoK appears multiple times
2. All fields (`V`, `C`, `hat_w`, `C_0`) are adjusted to reflect the duplicate contribution (by "aggregating" the transcript with itself)
3. Transcript is serialized and submitted in a DKG transaction
4. VM deserializes and calls `verify_transcript()`
5. All cryptographic checks pass because BLS allows duplicates and sums are consistent
6. Dealer `i` has 2x (or more) influence on the final shared secret

## Impact Explanation

This vulnerability violates the **Cryptographic Correctness** invariant (#10) and represents a **Medium severity** issue per the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The DKG output is corrupted, affecting randomness generation used for leader selection and other consensus-critical operations
- **Protocol violation**: The DKG protocol's fairness guarantee is broken - each dealer should contribute equally (or proportional to stake in weighted variants)
- **Randomness manipulation**: The shared secret can be biased toward a specific dealer's input, compromising the unpredictability guarantee

While this doesn't directly lead to fund theft, it affects consensus-critical randomness generation and could enable:
- Biased leader election
- Predictable randomness outputs
- Manipulation of any protocol mechanism depending on DKG output

The issue fits the "State inconsistencies requiring intervention" category at **Medium severity (up to $10,000)**.

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability exists in the code, but exploitation requires:

1. **Bypassing normal aggregation flow**: The peer-to-peer aggregation process calls `verify_transcript_extra()` which catches duplicates
2. **Crafting malicious transcript bytes**: The attacker must construct a self-consistent transcript with duplicates
3. **Injecting into VM path**: The attacker must submit a DKG transaction with the malicious transcript

However, the fundamental issue is a **design flaw**: `verify_transcript()` is insufficient for standalone validation, relying on out-of-band checks (`verify_transcript_extra()`) that aren't enforced consistently. This violates the principle of defense in depth.

The vulnerability becomes more likely if:
- There are bugs in the aggregation logic that bypass the duplicate check
- Direct transcript injection is possible through any code path
- Future code changes rely on `verify_transcript()` being sufficient

## Recommendation

Add duplicate dealer validation to `verify_transcript()` to make it self-sufficient for validation:

```rust
// In types/src/dkg/real_dkg/mod.rs, in verify_transcript() function:
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
    
    // ADD THIS CHECK: Ensure no duplicate dealers
    let dealer_set: std::collections::HashSet<usize> = dealers.iter().cloned().collect();
    ensure!(
        dealers.len() == dealer_set.len(),
        "real_dkg::verify_transcript failed with duplicate dealer entries."
    );
    
    // ... rest of verification
}
```

This ensures that `verify_transcript()` is a complete validation function that catches all invalid transcripts, regardless of how they were constructed.

## Proof of Concept

```rust
#[cfg(test)]
mod dkg_duplicate_dealer_test {
    use super::*;
    use aptos_dkg::pvss::{
        das::WeightedTranscript,
        traits::{Transcript, AggregatableTranscript, transcript::Aggregatable},
    };
    
    #[test]
    fn test_duplicate_dealer_passes_verify_transcript() {
        // Setup DKG parameters
        let dkg_session = create_test_dkg_session();
        let pub_params = RealDKG::new_public_params(&dkg_session);
        
        // Create valid transcript from dealer 0
        let mut rng = thread_rng();
        let sk = bls12381::PrivateKey::generate(&mut rng);
        let pk = bls12381::PublicKey::from(&sk);
        let secret = <WeightedTranscript as Transcript>::InputSecret::random(&mut rng);
        
        let trx = WeightedTranscript::deal(
            &pub_params.pvss_config.wconfig,
            &pub_params.pvss_config.pp,
            &sk,
            &pk,
            &pub_params.pvss_config.eks,
            &secret,
            &(pub_params.pvss_config.epoch, test_address()),
            &Player { id: 0 },
            &mut rng,
        );
        
        // Aggregate transcript with itself to create duplicate dealer entry
        let mut malicious_trx = trx.clone();
        malicious_trx.aggregate_with(&pub_params.pvss_config.wconfig, &trx)
            .expect("Aggregation should succeed");
        
        // Check that dealer 0 appears twice
        let dealers = malicious_trx.get_dealers();
        assert_eq!(dealers.len(), 2);
        assert_eq!(dealers[0].id, 0);
        assert_eq!(dealers[1].id, 0);
        
        // This should FAIL but currently PASSES
        let transcripts = Transcripts {
            main: malicious_trx,
            fast: None,
        };
        
        let result = RealDKG::verify_transcript(&pub_params, &transcripts);
        
        // BUG: This passes when it should fail
        assert!(result.is_ok(), "Duplicate dealer transcript passed verification!");
    }
}
```

## Notes

The vulnerability stems from an architectural decision where verification is split between `verify_transcript()` (cryptographic checks) and `verify_transcript_extra()` (semantic checks including duplicate detection). This violates defense in depth principles - each validation function should be self-sufficient.

The peer-to-peer aggregation flow is currently protected, but the VM path and any future code paths that call `verify_transcript()` directly are vulnerable. The fix is simple: add the duplicate check to `verify_transcript()` as shown in the recommendation.

### Citations

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L73-80)
```rust
impl TryFrom<&[u8]> for Transcript {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
    }
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L149-155)
```rust
        Transcript {
            soks: vec![(*dealer, V[sc.n], sig, pok)],
            hat_w: g_2.mul(r),
            V,
            C,
            C_0: g_1.mul(r),
        }
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L336-338)
```rust
        for sok in &other.soks {
            self.soks.push(sok.clone());
        }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L311-311)
```rust
        ensure!(main_trx_dealers.len() == dealer_set.len());
```

**File:** types/src/dkg/real_dkg/mod.rs (L352-366)
```rust
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
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L57-68)
```rust
    let mut c = Gr::identity();
    for (_, c_i, _, _) in soks {
        c.add_assign(c_i)
    }

    if c.ne(pk) {
        bail!(
            "The PoK does not correspond to the dealt secret. Expected {} but got {}",
            pk,
            c
        );
    }
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_sigs.rs (L78-84)
```rust
    /// Verifies an aggregate signature on the messages in `msgs` under the public keys in `pks`.
    /// Specifically, verifies that each `msgs[i]` is signed under `pks[i]`. The messages in `msgs`
    /// do *not* have to be all different, since we use proofs-of-possession (PoPs) to prevent rogue
    /// key attacks.
    ///
    /// WARNING: This function assumes that the public keys have been subgroup-checked by the caller
    /// implicitly when verifying their proof-of-possession (PoP) in `ProofOfPossession::verify`.
```
