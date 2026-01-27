# Audit Report

## Title
Byzantine Validator CPU Exhaustion via Cryptographically Invalid DKG Transcripts

## Summary
A Byzantine validator can send DKG transcript responses containing syntactically valid but cryptographically invalid data that passes initial BCS deserialization but fails during expensive pairing-based verification. The lack of failure caching combined with reliable broadcast retry logic causes honest validators to repeatedly waste CPU resources on multi-exponentiation and multi-pairing operations that will always fail, potentially delaying or preventing DKG completion.

## Finding Description

The DKG (Distributed Key Generation) protocol in Aptos uses a request-response pattern where validators exchange transcripts. When processing incoming transcript responses in `TranscriptAggregationState::add()`, the validation occurs in two distinct phases:

**Phase 1: Initial Validation (Cheap)** [1](#0-0) 

The initial checks validate epoch, voting power, author matching, and BCS deserialization. The BCS deserialization only verifies that the bytes represent valid elliptic curve points in the correct structure—it does NOT validate cryptographic relationships between these points.

**Phase 2: Cryptographic Verification (Expensive)** [2](#0-1) 

The cryptographic verification performs expensive operations including multi-exponentiations, multi-pairing checks, low-degree polynomial tests, and signature-of-knowledge verification: [3](#0-2) 

**The Critical Gap:**
The deduplication check only prevents re-processing from the same validator AFTER successful verification: [4](#0-3) 

However, if verification fails, the contributor is never added to the set. When reliable broadcast retries the request, the expensive verification runs again: [5](#0-4) 

**Attack Execution:**
1. Byzantine validator generates a `DKGTranscript` with valid elliptic curve points (passes BCS deserialization) but random values that don't satisfy the DKG cryptographic equations
2. Stores this as `my_transcript` in their `DKGManager` state: [6](#0-5) 

3. When honest validators send `TranscriptRequest`, the Byzantine validator responds with the corrupted transcript
4. Each honest validator performs expensive cryptographic operations (hundreds of milliseconds to seconds) that will always fail
5. Reliable broadcast retries with exponential backoff, repeating the expensive verification multiple times
6. No caching or rate limiting prevents repeated verification of the same invalid data

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:
- **Validator Node Slowdowns**: Each verification attempt performs expensive operations (multi-exponentiations over ~1000 points, multi-pairing operations over ~100 validators)
- **Resource Exhaustion**: CPU time wasted on operations guaranteed to fail
- **DKG Disruption**: Multiple Byzantine validators could delay or prevent DKG completion, impacting on-chain randomness generation
- **State Inconsistency**: Failed DKG affects epoch transitions and validator set updates

The transcript structure contains vectors of elliptic curve points that require expensive cryptographic operations: [7](#0-6) 

For a typical validator set of 100 nodes with total weight W=1000, each verification attempt performs:
- ~1000 scalar multiplications for multi-exponentiations
- ~100 pairing operations (each pairing is extremely expensive)
- Signature verification for all dealers
- Low-degree polynomial tests

This can easily consume seconds of CPU time per attempt, multiplied by retry attempts and Byzantine validator count.

## Likelihood Explanation

**High Likelihood:**
- **Low Attacker Requirements**: Any validator in the validator set can mount this attack without requiring collusion or special privileges
- **Simple Exploitation**: Byzantine validator simply needs to generate random but BCS-valid elliptic curve points
- **Guaranteed Trigger**: Every honest validator requesting transcripts will waste resources
- **Amplification**: Reliable broadcast retry mechanism amplifies the impact through repeated verification attempts
- **No Detection**: The attack appears as legitimate verification failures, making it difficult to distinguish from network issues

## Recommendation

Implement failure caching to prevent repeated verification of known-invalid transcripts from the same sender:

```rust
pub struct TranscriptAggregationState<DKG: DKGTrait> {
    start_time: Duration,
    my_addr: AccountAddress,
    valid_peer_transcript_seen: bool,
    trx_aggregator: Mutex<TranscriptAggregator<DKG>>,
    dkg_pub_params: DKG::PublicParams,
    epoch_state: Arc<EpochState>,
    // NEW: Cache failed verification attempts
    failed_verifications: Mutex<HashSet<AccountAddress>>,
}

fn add(
    &self,
    sender: Author,
    dkg_transcript: DKGTranscript,
) -> anyhow::Result<Option<Self::Aggregated>> {
    // ... existing initial checks ...
    
    // NEW: Check if this sender already failed verification
    {
        let failed = self.failed_verifications.lock();
        if failed.contains(&sender) {
            bail!("[DKG] sender previously failed verification");
        }
    }
    
    let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
        anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
    })?;
    
    let mut trx_aggregator = self.trx_aggregator.lock();
    if trx_aggregator.contributors.contains(&metadata.author) {
        return Ok(None);
    }

    let verify_result = S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
        .and_then(|_| S::verify_transcript(&self.dkg_pub_params, &transcript));
    
    // NEW: Cache failures
    if let Err(e) = verify_result {
        self.failed_verifications.lock().insert(sender);
        return Err(e.context("verification failed"));
    }

    // All checks passed. Aggregating.
    // ... rest of aggregation logic ...
}
```

Additionally, consider:
1. **Rate Limiting**: Limit how many verification attempts per sender per time window
2. **Content-Based Hashing**: Hash the transcript bytes and cache failures by content hash to prevent Byzantine validators from sending slightly modified invalid transcripts
3. **Early Size Validation**: Add cheap size bounds checks before expensive deserialization

## Proof of Concept

```rust
#[test]
fn test_byzantine_transcript_cpu_exhaustion() {
    use aptos_crypto::{bls12381::bls12381_keys, Uniform};
    use aptos_types::dkg::{real_dkg::RealDKG, DKGSessionMetadata, DKGTrait, DKGTranscript};
    use std::time::Instant;
    
    // Setup validator set
    let mut rng = thread_rng();
    let num_validators = 100;
    let epoch = 999;
    
    // Generate validator keys and build DKG parameters
    let addrs: Vec<AccountAddress> = (0..num_validators)
        .map(|_| AccountAddress::random())
        .collect();
    let private_keys: Vec<bls12381_keys::PrivateKey> = (0..num_validators)
        .map(|_| bls12381_keys::PrivateKey::generate_for_testing())
        .collect();
    let public_keys: Vec<bls12381_keys::PublicKey> = (0..num_validators)
        .map(|i| bls12381_keys::PublicKey::from(&private_keys[i]))
        .collect();
    
    // ... setup epoch state and pub_params ...
    
    // Byzantine validator generates corrupted transcript
    // Step 1: Generate valid transcript
    let valid_trx = RealDKG::sample_secret_and_generate_transcript(
        &mut rng,
        &pub_params,
        0,
        &private_keys[0],
        &public_keys[0],
    );
    
    // Step 2: Corrupt it by deserializing, modifying random field, re-serializing
    let mut corrupted_trx = valid_trx.clone();
    // Modify one of the elliptic curve points to a random valid point
    corrupted_trx.main.C[0] = G1Projective::random(&mut rng);
    let corrupted_bytes = bcs::to_bytes(&corrupted_trx).unwrap();
    
    // Step 3: Measure CPU time wasted on verification attempts
    let trx_agg_state = Arc::new(TranscriptAggregationState::<RealDKG>::new(
        duration_since_epoch(),
        addrs[1],
        pub_params,
        epoch_state,
    ));
    
    // Simulate multiple retry attempts
    let attempts = 5;
    let mut total_time = Duration::ZERO;
    
    for i in 0..attempts {
        let start = Instant::now();
        let result = trx_agg_state.add(addrs[0], DKGTranscript {
            metadata: DKGTranscriptMetadata {
                epoch: 999,
                author: addrs[0],
            },
            transcript_bytes: corrupted_bytes.clone(),
        });
        let elapsed = start.elapsed();
        total_time += elapsed;
        
        // Each attempt should fail verification
        assert!(result.is_err());
        println!("Attempt {}: verification took {:?}", i, elapsed);
    }
    
    println!("Total CPU time wasted: {:?}", total_time);
    println!("Average per attempt: {:?}", total_time / attempts);
    
    // Demonstrate that legitimate transcripts are blocked
    // while CPU is exhausted processing invalid ones
    assert!(total_time.as_millis() > 500, "Attack should waste significant CPU time");
}
```

**Notes:**
- The vulnerability exploits the gap between cheap syntactic validation (BCS deserialization) and expensive semantic validation (cryptographic verification)
- The lack of failure caching means Byzantine validators can force repeated expensive operations
- Each validator independently wastes resources, multiplying the network-wide impact
- The reliable broadcast retry mechanism amplifies the attack by ensuring multiple verification attempts
- This breaks the Resource Limits invariant by allowing unbounded CPU consumption on invalid data

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L74-90)
```rust
        ensure!(
            metadata.epoch == self.epoch_state.epoch,
            "[DKG] adding peer transcript failed with invalid node epoch",
        );

        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
```

**File:** dkg/src/transcript_aggregation/mod.rs (L91-94)
```rust
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L96-101)
```rust
        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L280-377)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &<Self as traits::Transcript>::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        auxs: &[A],
    ) -> anyhow::Result<()> {
        self.check_sizes(sc)?;
        let n = sc.get_total_num_players();
        if eks.len() != n {
            bail!("Expected {} encryption keys, but got {}", n, eks.len());
        }
        let W = sc.get_total_weight();

        // Deriving challenges by flipping coins: less complex to implement & less likely to get wrong. Creates bad RNG risks but we deem that acceptable.
        let mut rng = rand::thread_rng();
        let extra = random_scalars(2 + W * 3, &mut rng);

        let sok_vrfy_challenge = &extra[W * 3 + 1];
        let g_2 = pp.get_commitment_base();
        let g_1 = pp.get_encryption_public_params().pubkey_base();
        batch_verify_soks::<G1Projective, A>(
            self.soks.as_slice(),
            g_1,
            &self.V[W],
            spks,
            auxs,
            sok_vrfy_challenge,
        )?;

        let ldt = LowDegreeTest::random(
            &mut rng,
            sc.get_threshold_weight(),
            W + 1,
            true,
            sc.get_batch_evaluation_domain(),
        );
        ldt.low_degree_test_on_g1(&self.V)?;

        //
        // Correctness of encryptions check
        //

        let alphas_betas_and_gammas = &extra[0..W * 3 + 1];
        let (alphas_and_betas, gammas) = alphas_betas_and_gammas.split_at(2 * W + 1);
        let (alphas, betas) = alphas_and_betas.split_at(W + 1);
        assert_eq!(alphas.len(), W + 1);
        assert_eq!(betas.len(), W);
        assert_eq!(gammas.len(), W);

        let lc_VR_hat = G2Projective::multi_exp_iter(
            self.V_hat.iter().chain(self.R_hat.iter()),
            alphas_and_betas.iter(),
        );
        let lc_VRC = G1Projective::multi_exp_iter(
            self.V.iter().chain(self.R.iter()).chain(self.C.iter()),
            alphas_betas_and_gammas.iter(),
        );
        let lc_V_hat = G2Projective::multi_exp_iter(self.V_hat.iter().take(W), gammas.iter());
        let mut lc_R_hat = Vec::with_capacity(n);

        for i in 0..n {
            let p = sc.get_player(i);
            let weight = sc.get_player_weight(&p);
            let s_i = sc.get_player_starting_index(&p);

            lc_R_hat.push(g2_multi_exp(
                &self.R_hat[s_i..s_i + weight],
                &gammas[s_i..s_i + weight],
            ));
        }

        let h = pp.get_encryption_public_params().message_base();
        let g_2_neg = g_2.neg();
        let eks = eks
            .iter()
            .map(Into::<G1Projective>::into)
            .collect::<Vec<G1Projective>>();
        // The vector of left-hand-side ($\mathbb{G}_2$) inputs to each pairing in the multi-pairing.
        let lhs = [g_1, &lc_VRC, h].into_iter().chain(&eks);
        // The vector of right-hand-side ($\mathbb{G}_2$) inputs to each pairing in the multi-pairing.
        let rhs = [&lc_VR_hat, &g_2_neg, &lc_V_hat]
            .into_iter()
            .chain(&lc_R_hat);

        let res = multi_pairing(lhs, rhs);
        if res != Gt::identity() {
            bail!(
                "Expected zero during multi-pairing check for {} {}, but got {}",
                sc,
                <Self as traits::Transcript>::scheme_name(),
                res
            );
        }

        return Ok(());
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** dkg/src/dkg_manager/mod.rs (L464-477)
```rust
        let response = match (&self.state, &msg) {
            (InnerState::Finished { my_transcript, .. }, DKGMessage::TranscriptRequest(_))
            | (InnerState::InProgress { my_transcript, .. }, DKGMessage::TranscriptRequest(_)) => {
                Ok(DKGMessage::TranscriptResponse(my_transcript.clone()))
            },
            _ => Err(anyhow!(
                "[DKG] msg {:?} unexpected in state {:?}",
                msg.name(),
                self.state.variant_name()
            )),
        };

        response_sender.send(response);
        Ok(())
```
