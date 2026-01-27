# Audit Report

## Title
DKG Transcript Malleability via Non-Deterministic SoK Ordering in Aggregation

## Summary
The DKG (Distributed Key Generation) transcript format allows multiple semantically equivalent representations that hash to different values, enabling transaction malleability attacks. This occurs because the order of Signatures of Knowledge (SoKs) in aggregated transcripts is non-deterministic and depends on network message arrival timing, yet verification accepts any ordering as valid.

## Finding Description

The vulnerability exists in the DKG transcript aggregation process where transcripts from multiple validators are combined into a single aggregated transcript. The issue manifests through the following code path:

**1. Non-Deterministic Aggregation Order**

When validators contribute individual DKG transcripts, they are aggregated as they arrive from the network: [1](#0-0) 

The aggregation calls the underlying cryptographic aggregation function: [2](#0-1) 

**Critical Issue**: SoKs from the `other` transcript are simply appended to `self.soks` without any canonical ordering. This means the final order depends entirely on the network message arrival sequence, which is non-deterministic.

**2. Order-Dependent Serialization but Order-Agnostic Verification**

The `Transcript` struct containing the SoKs vector derives `Serialize`: [3](#0-2) 

The `ValidatorTransaction` enum wraps DKG transcripts and derives `BCSCryptoHash`, making the transaction hash dependent on SoK ordering: [4](#0-3) 

**3. Verification Reconstructs Order-Dependent Context**

During verification, the system extracts dealers from the transcript's SoK order and constructs verification arrays in that same order: [5](#0-4) 

The verification then checks the aggregate BLS signature using these order-matched arrays: [6](#0-5) 

**Key Insight**: Since `spks`, `aux`, and `msgs` arrays are all derived from the SoK ordering, and the aggregate signature verification checks `messages[i]` against `public_keys[i]`, ANY permutation of SoKs will pass verification as long as the derived arrays maintain their internal consistency.

**Attack Scenario**:
- Validators V1, V2, V3 broadcast transcripts T1, T2, T3
- Node A receives messages in order [T1, T2, T3] → aggregates to transcript with `soks = [sok1, sok2, sok3]`
- Node B receives messages in order [T2, T1, T3] → aggregates to transcript with `soks = [sok2, sok1, sok3]`
- Both nodes verify their respective transcripts as valid
- Both wrap them in `ValidatorTransaction::DKGResult` 
- BCS serialization produces different bytes due to different SoK ordering
- BCSCryptoHash produces different transaction IDs for the same logical DKG result

## Impact Explanation

This is a **Medium Severity** vulnerability under the Aptos Bug Bounty criteria for "State inconsistencies requiring intervention."

**Specific Impacts:**
1. **Transaction Identity Confusion**: The same DKG result can have multiple valid transaction IDs, breaking the assumption that transaction hashes uniquely identify transactions
2. **Consensus Disagreement Risk**: Different validators may disagree on which variant of the DKG transcript to include in blocks, potentially causing consensus liveness issues
3. **Deterministic Execution Violation**: The "Deterministic Execution" invariant is broken - validators processing identical inputs (the same set of individual transcripts) produce different outputs (different aggregated transcript hashes)
4. **State Commitment Inconsistencies**: If different nodes commit different variants to their local state, it could require manual intervention to reconcile
5. **Replay/Deduplication Bypass**: Systems relying on transaction hash for deduplication could be bypassed by reordering SoKs

This does not directly cause fund loss or consensus safety violations (no double-spending or chain splits), but it creates state management issues requiring operational intervention, fitting the Medium severity category.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will manifest naturally in any multi-validator DKG ceremony without requiring attacker action:

1. **Automatic Occurrence**: Network message arrival order is inherently non-deterministic in distributed systems. Different validators WILL receive transcript messages in different orders based on network topology, latency variations, and timing
2. **No Attacker Action Required**: The malleability happens automatically as a byproduct of normal network behavior
3. **Every DKG Ceremony Affected**: Each epoch transition involving DKG will produce multiple valid but different-hashing transcript variants across the network
4. **Observable in Production**: This can be detected by comparing transaction hashes of DKG results across different validator nodes

The issue is not theoretical - it's an inherent property of the current implementation that manifests in every DKG aggregation.

## Recommendation

**Solution**: Enforce canonical ordering of SoKs before serialization or during aggregation.

**Option 1 - Canonical Ordering During Aggregation (Recommended)**:
Modify the aggregation to maintain SoKs in canonical order (e.g., sorted by Player ID):

```rust
// In weighted_protocol.rs aggregate_with function
fn aggregate_with(
    &mut self,
    sc: &WeightedConfig<ThresholdConfigBlstrs>,
    other: &Transcript,
) -> anyhow::Result<()> {
    // ... existing aggregation code ...
    
    // Add SoKs and maintain sorted order
    for sok in &other.soks {
        self.soks.push(sok.clone());
    }
    // Sort by Player ID to ensure canonical ordering
    self.soks.sort_by_key(|(player, _, _, _)| player.id);
    
    Ok(())
}
```

**Option 2 - Normalization Before Serialization**:
Add a normalization step in `DKGTranscript::new()` or before serialization to ensure canonical ordering:

```rust
// In types/src/dkg/mod.rs
impl DKGTranscript {
    pub fn new(epoch: u64, author: AccountAddress, transcript_bytes: Vec<u8>) -> Self {
        // Deserialize, normalize ordering, re-serialize
        let mut transcripts: Transcripts = bcs::from_bytes(&transcript_bytes)
            .expect("Transcript normalization failed");
        
        // Sort SoKs by player ID in both main and fast transcripts
        transcripts.main.normalize_soks();
        if let Some(ref mut fast) = transcripts.fast {
            fast.normalize_soks();
        }
        
        let normalized_bytes = bcs::to_bytes(&transcripts)
            .expect("Transcript re-serialization failed");
        
        Self {
            metadata: DKGTranscriptMetadata { epoch, author },
            transcript_bytes: normalized_bytes,
        }
    }
}
```

**Option 3 - Deterministic Aggregation Order**:
Change the aggregation to use a deterministic order based on validator indices rather than message arrival order (requires protocol changes).

**Recommended Approach**: Option 1 is simplest and maintains backward compatibility for verification while ensuring deterministic serialization.

## Proof of Concept

```rust
#[cfg(test)]
mod dkg_malleability_test {
    use super::*;
    use aptos_crypto::bls12381::PrivateKey;
    use rand::thread_rng;
    
    #[test]
    fn test_transcript_malleability_via_sok_ordering() {
        let mut rng = thread_rng();
        
        // Setup: Create DKG session with 3 validators
        let session_metadata = create_test_session_metadata(3);
        let pub_params = RealDKG::new_public_params(&session_metadata);
        
        // Each validator generates their transcript
        let sk1 = PrivateKey::generate(&mut rng);
        let sk2 = PrivateKey::generate(&mut rng);
        let sk3 = PrivateKey::generate(&mut rng);
        
        let pk1 = bls12381::PublicKey::from(&sk1);
        let pk2 = bls12381::PublicKey::from(&sk2);
        let pk3 = bls12381::PublicKey::from(&sk3);
        
        let trx1 = RealDKG::sample_secret_and_generate_transcript(&mut rng, &pub_params, 0, &sk1, &pk1);
        let trx2 = RealDKG::sample_secret_and_generate_transcript(&mut rng, &pub_params, 1, &sk2, &pk2);
        let trx3 = RealDKG::sample_secret_and_generate_transcript(&mut rng, &pub_params, 2, &sk3, &pk3);
        
        // Aggregate in different orders to simulate different network arrival patterns
        
        // Order A: 1 -> 2 -> 3
        let mut agg_a = trx1.clone();
        RealDKG::aggregate_transcripts(&pub_params, &mut agg_a, trx2.clone());
        RealDKG::aggregate_transcripts(&pub_params, &mut agg_a, trx3.clone());
        
        // Order B: 1 -> 3 -> 2 (different order)
        let mut agg_b = trx1.clone();
        RealDKG::aggregate_transcripts(&pub_params, &mut agg_b, trx3.clone());
        RealDKG::aggregate_transcripts(&pub_params, &mut agg_b, trx2.clone());
        
        // Both should verify successfully
        assert!(RealDKG::verify_transcript(&pub_params, &agg_a).is_ok());
        assert!(RealDKG::verify_transcript(&pub_params, &agg_b).is_ok());
        
        // Serialize both
        let bytes_a = bcs::to_bytes(&agg_a).unwrap();
        let bytes_b = bcs::to_bytes(&agg_b).unwrap();
        
        // VULNERABILITY: Different serializations for semantically equivalent transcripts
        assert_ne!(bytes_a, bytes_b, "Malleability detected: same transcript, different bytes!");
        
        // Wrap in DKGTranscript and ValidatorTransaction
        let dkg_trx_a = DKGTranscript::new(1, AccountAddress::ZERO, bytes_a);
        let dkg_trx_b = DKGTranscript::new(1, AccountAddress::ZERO, bytes_b);
        
        let vtx_a = ValidatorTransaction::DKGResult(dkg_trx_a);
        let vtx_b = ValidatorTransaction::DKGResult(dkg_trx_b);
        
        // Compute hashes using BCSCryptoHash
        use aptos_crypto::HashValue;
        let hash_a = HashValue::sha3_256_of(&bcs::to_bytes(&vtx_a).unwrap());
        let hash_b = HashValue::sha3_256_of(&bcs::to_bytes(&vtx_b).unwrap());
        
        // CRITICAL: Different transaction IDs for the same logical DKG result
        assert_ne!(hash_a, hash_b, "Transaction malleability confirmed: different TX IDs!");
        
        println!("Malleability confirmed:");
        println!("  Hash A: {:?}", hash_a);
        println!("  Hash B: {:?}", hash_b);
        println!("  Both transcripts verify, but hash differently!");
    }
}
```

**Notes**
This vulnerability demonstrates a fundamental issue where cryptographic primitives (BLS aggregate signatures) that are order-agnostic during verification, combined with order-dependent serialization and non-deterministic aggregation order, create malleability at the transaction identity level. The fix requires enforcing canonical ordering either during aggregation or before final serialization to ensure deterministic transaction IDs across all validators.

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L117-121)
```rust
        if let Some(agg_trx) = trx_aggregator.trx.as_mut() {
            S::aggregate_transcripts(&self.dkg_pub_params, agg_trx, transcript);
        } else {
            trx_aggregator.trx = Some(transcript);
        }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L48-72)
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, BCSCryptoHash, CryptoHasher)]
#[allow(non_snake_case)]
pub struct Transcript {
    /// Proofs-of-knowledge (PoKs) for the dealt secret committed in $c = g_2^{p(0)}$.
    /// Since the transcript could have been aggregated from other transcripts with their own
    /// committed secrets in $c_i = g_2^{p_i(0)}$, this is a vector of PoKs for all these $c_i$'s
    /// such that $\prod_i c_i = c$.
    ///
    /// Also contains BLS signatures from each player $i$ on that player's contribution $c_i$, the
    /// player ID $i$ and auxiliary information `aux[i]` provided during dealing.
    soks: Vec<SoK<G1Projective>>,
    /// Commitment to encryption randomness $g_1^{r_j} \in G_1, \forall j \in [W]$
    R: Vec<G1Projective>,
    /// Same as $R$ except uses $g_2$.
    R_hat: Vec<G2Projective>,
    /// First $W$ elements are commitments to the evaluations of $p(X)$: $g_1^{p(\omega^i)}$,
    /// where $i \in [W]$. Last element is $g_1^{p(0)}$ (i.e., the dealt public key).
    V: Vec<G1Projective>,
    /// Same as $V$ except uses $g_2$.
    V_hat: Vec<G2Projective>,
    /// ElGamal encryption of the $j$th share of player $i$:
    /// i.e., $C[s_i+j-1] = h_1^{p(\omega^{s_i + j - 1})} ek_i^{r_j}, \forall i \in [n], j \in [w_i]$.
    /// We sometimes denote $C[s_i+j-1]$ by C_{i, j}.
    C: Vec<G1Projective>,
}
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L405-407)
```rust
        for sok in &other.soks {
            self.soks.push(sok.clone());
        }
```

**File:** types/src/validator_txn.rs (L14-18)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub enum ValidatorTransaction {
    DKGResult(DKGTranscript),
    ObservedJWKUpdate(jwks::QuorumCertifiedUpdate),
}
```

**File:** types/src/dkg/real_dkg/mod.rs (L337-366)
```rust
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
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L28-103)
```rust
pub fn batch_verify_soks<Gr, A>(
    soks: &[SoK<Gr>],
    pk_base: &Gr,
    pk: &Gr,
    spks: &[bls12381::PublicKey],
    aux: &[A],
    tau: &Scalar,
) -> anyhow::Result<()>
where
    Gr: Serialize + HasMultiExp + Display + Copy + Group + for<'a> Mul<&'a Scalar>,
    A: Serialize + Clone,
{
    if soks.len() != spks.len() {
        bail!(
            "Expected {} signing PKs, but got {}",
            soks.len(),
            spks.len()
        );
    }

    if soks.len() != aux.len() {
        bail!(
            "Expected {} auxiliary infos, but got {}",
            soks.len(),
            aux.len()
        );
    }

    // First, the PoKs
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

    let poks = soks
        .iter()
        .map(|(_, c, _, pok)| (*c, *pok))
        .collect::<Vec<(Gr, schnorr::PoK<Gr>)>>();

    // TODO(Performance): 128-bit exponents instead of powers of tau
    schnorr::pok_batch_verify::<Gr>(&poks, pk_base, &tau)?;

    // Second, the signatures
    let msgs = soks
        .iter()
        .zip(aux)
        .map(|((player, comm, _, _), aux)| Contribution::<Gr, A> {
            comm: *comm,
            player: *player,
            aux: aux.clone(),
        })
        .collect::<Vec<Contribution<Gr, A>>>();
    let msgs_refs = msgs
        .iter()
        .map(|c| c)
        .collect::<Vec<&Contribution<Gr, A>>>();
    let pks = spks
        .iter()
        .map(|pk| pk)
        .collect::<Vec<&bls12381::PublicKey>>();
    let sig = bls12381::Signature::aggregate(
        soks.iter()
            .map(|(_, _, sig, _)| sig.clone())
            .collect::<Vec<bls12381::Signature>>(),
    )?;

    sig.verify_aggregate(&msgs_refs[..], &pks[..])?;
    Ok(())
```
