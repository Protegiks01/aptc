# Audit Report

## Title
DKG Transcript Aggregation Lock Duration DoS Vulnerability

## Summary
The `TranscriptAggregationState::add()` function in the DKG (Distributed Key Generation) module holds a mutex lock while performing expensive cryptographic verification operations, allowing a malicious validator to cause denial of service by submitting invalid transcripts that monopolize the lock and block other validators from contributing their valid transcripts.

## Finding Description

The vulnerability exists in the transcript aggregation logic where the mutex is acquired before expensive cryptographic operations are performed. [1](#0-0) 

The critical issue is that the mutex `trx_aggregator` is locked at line 91, but remains locked during two expensive cryptographic verification operations:

1. **`verify_transcript_extra()`** at line 96 - This performs dealer set validation, voting power checks, and consistency verification between main and fast path transcripts
2. **`verify_transcript()`** at line 99 - This performs PVSS cryptographic verification including multi-scalar multiplications (MSM) and multi-pairing operations [2](#0-1) [3](#0-2) 

The `verify_transcript()` implementation calls into PVSS cryptographic operations that are computationally expensive. The underlying verification performs multi-pairing operations: [4](#0-3) 

These operations include batch signature verification, low degree tests, multi-scalar multiplications, and multi-pairing checks - all extremely expensive cryptographic operations that can take significant CPU time.

**Attack Scenario:**
1. A malicious validator submits multiple invalid DKG transcripts
2. Each invalid transcript passes initial checks (epoch, sender authentication, deserialization)
3. The mutex is locked and expensive cryptographic verification begins
4. The verification fails (because the transcript is invalid), but only after consuming significant CPU time
5. While the lock is held, other legitimate validators cannot submit their valid transcripts
6. The DKG aggregation process is delayed or fails to reach quorum within the timeout period

The reliable broadcast system calls the `add()` method within spawned executor tasks: [5](#0-4) 

However, because the mutex is held during verification, concurrent calls from different validators are serialized, and invalid transcripts consume lock time unnecessarily.

## Impact Explanation

**Severity: Medium** 

This vulnerability causes **validator node slowdowns** during DKG execution, which falls under High severity ($50,000) in the Aptos bug bounty program. However, I'm classifying this as Medium severity because:

1. **Limited scope**: Only affects DKG transcript aggregation during epoch transitions
2. **Temporary impact**: Does not cause permanent network disruption or fund loss
3. **Requires validator access**: Attacker must be an active validator to submit transcripts

The impact includes:
- Delayed DKG completion during epoch transitions
- Potential failure to generate randomness if DKG doesn't complete in time
- Degraded consensus performance due to CPU exhaustion
- Risk of epoch transition failures requiring manual intervention

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
1. **Validator access**: Attacker must be an active validator (checked at lines 79-83)
2. **Malicious behavior**: Requires deliberate submission of invalid transcripts
3. **Timing window**: Only exploitable during DKG transcript aggregation phase [6](#0-5) 

While the system is designed to tolerate Byzantine validators (up to 1/3), this specific vulnerability allows a single malicious validator to significantly impact the DKG process through resource exhaustion rather than protocol-level attacks.

The likelihood is considered medium because:
- It requires compromised validator credentials
- The attack window is limited to epoch transitions
- The impact is temporary and recoverable

## Recommendation

**Move expensive verification outside the mutex lock:**

The fix is to perform all expensive cryptographic verification operations BEFORE acquiring the mutex lock. The lock should only be held during the actual state modification (checking for duplicates and updating the aggregator).

```rust
fn add(
    &self,
    sender: Author,
    dkg_transcript: DKGTranscript,
) -> anyhow::Result<Option<Self::Aggregated>> {
    let DKGTranscript {
        metadata,
        transcript_bytes,
    } = dkg_transcript;
    
    // Early validation checks (cheap operations)
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
    
    // Deserialize transcript
    let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
        anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
    })?;
    
    // PERFORM EXPENSIVE VERIFICATION BEFORE ACQUIRING LOCK
    S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
        .context("extra verification failed")?;
    S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
        anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
    })?;
    
    // NOW acquire lock only for state modification
    let mut trx_aggregator = self.trx_aggregator.lock();
    
    // Check for duplicate contribution
    if trx_aggregator.contributors.contains(&metadata.author) {
        return Ok(None);
    }
    
    // All checks passed. Aggregating.
    // ... rest of aggregation logic
}
```

This ensures that:
1. Invalid transcripts are rejected quickly without holding the lock
2. Only valid transcripts acquire the lock
3. Lock duration is minimized to only the state modification operations
4. Multiple validators can verify transcripts concurrently

## Proof of Concept

```rust
#[cfg(test)]
mod lock_duration_dos_test {
    use super::*;
    use aptos_crypto::{bls12381::bls12381_keys, Uniform};
    use aptos_infallible::duration_since_epoch;
    use aptos_reliable_broadcast::BroadcastStatus;
    use aptos_types::{
        dkg::{real_dkg::RealDKG, DKGSessionMetadata, DKGTrait, DKGTranscript, DKGTranscriptMetadata},
        epoch_state::EpochState,
        on_chain_config::OnChainRandomnessConfig,
        validator_verifier::{ValidatorConsensusInfo, ValidatorConsensusInfoMoveStruct},
    };
    use move_core_types::account_address::AccountAddress;
    use rand::thread_rng;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use std::time::{Duration, Instant};

    #[test]
    fn test_lock_duration_dos() {
        let mut rng = thread_rng();
        let num_validators = 4;
        let epoch = 999;
        
        // Setup validators
        let addrs: Vec<AccountAddress> = (0..num_validators)
            .map(|_| AccountAddress::random())
            .collect();
        let private_keys: Vec<bls12381_keys::PrivateKey> = (0..num_validators)
            .map(|_| bls12381_keys::PrivateKey::generate_for_testing())
            .collect();
        let public_keys: Vec<bls12381_keys::PublicKey> = private_keys
            .iter()
            .map(|pk| bls12381_keys::PublicKey::from(pk))
            .collect();
        let voting_powers = vec![10, 10, 10, 10];
        let validator_infos: Vec<ValidatorConsensusInfo> = (0..num_validators)
            .map(|i| ValidatorConsensusInfo::new(addrs[i], public_keys[i].clone(), voting_powers[i]))
            .collect();
        let validator_consensus_info_move_structs = validator_infos
            .iter()
            .cloned()
            .map(ValidatorConsensusInfoMoveStruct::from)
            .collect::<Vec<_>>();
        let verifier = ValidatorVerifier::new(validator_infos.clone());
        let pub_params = RealDKG::new_public_params(&DKGSessionMetadata {
            dealer_epoch: epoch,
            randomness_config: OnChainRandomnessConfig::default_enabled().into(),
            dealer_validator_set: validator_consensus_info_move_structs.clone(),
            target_validator_set: validator_consensus_info_move_structs.clone(),
        });
        
        let epoch_state = Arc::new(EpochState::new(epoch, verifier));
        let trx_agg_state = Arc::new(TranscriptAggregationState::<RealDKG>::new(
            duration_since_epoch(),
            addrs[0],
            pub_params.clone(),
            epoch_state.clone(),
        ));
        
        // Generate a valid transcript from validator 0
        let valid_trx = RealDKG::sample_secret_and_generate_transcript(
            &mut rng,
            &pub_params,
            0,
            &private_keys[0],
            &public_keys[0],
        );
        
        // Generate an INVALID transcript by corrupting it
        let mut invalid_trx_bytes = bcs::to_bytes(&valid_trx).unwrap();
        // Corrupt the last byte to make verification fail
        *invalid_trx_bytes.last_mut().unwrap() ^= 0xFF;
        
        let invalid_transcript = DKGTranscript {
            metadata: DKGTranscriptMetadata {
                epoch,
                author: addrs[1],  // validator 1 sends invalid
            },
            transcript_bytes: invalid_trx_bytes,
        };
        
        // Measure time for invalid transcript processing (holds lock during verification)
        let start = Instant::now();
        let result = trx_agg_state.add(addrs[1], invalid_transcript);
        let invalid_duration = start.elapsed();
        
        assert!(result.is_err(), "Invalid transcript should be rejected");
        
        // Now try to add a valid transcript and measure time
        let valid_trx_2 = RealDKG::sample_secret_and_generate_transcript(
            &mut rng,
            &pub_params,
            2,
            &private_keys[2],
            &public_keys[2],
        );
        
        let start = Instant::now();
        let result = trx_agg_state.add(addrs[2], DKGTranscript {
            metadata: DKGTranscriptMetadata {
                epoch,
                author: addrs[2],
            },
            transcript_bytes: bcs::to_bytes(&valid_trx_2).unwrap(),
        });
        let valid_duration = start.elapsed();
        
        assert!(result.is_ok(), "Valid transcript should be accepted");
        
        println!("Invalid transcript verification time (with lock): {:?}", invalid_duration);
        println!("Valid transcript verification time: {:?}", valid_duration);
        
        // The invalid transcript takes significant time even though it fails
        // During this time, the lock is held and blocks other validators
        assert!(invalid_duration > Duration::from_millis(10), 
                "Invalid transcript should take significant time to verify");
    }
}
```

## Notes

This vulnerability demonstrates a classic lock duration DoS pattern where expensive operations are performed while holding a shared lock. While the verification operations themselves are necessary for security, they should be performed before acquiring the lock to prevent resource exhaustion attacks. The fix is straightforward: reorder operations to minimize lock hold time to only the critical section that modifies shared state.

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L74-87)
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
```

**File:** dkg/src/transcript_aggregation/mod.rs (L91-101)
```rust
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L295-329)
```rust
    fn verify_transcript_extra(
        trx: &Self::Transcript,
        verifier: &ValidatorVerifier,
        checks_voting_power: bool,
        ensures_single_dealer: Option<AccountAddress>,
    ) -> anyhow::Result<()> {
        let all_validator_addrs = verifier.get_ordered_account_addresses();
        let main_trx_dealers = trx.main.get_dealers();
        let mut dealer_set = HashSet::with_capacity(main_trx_dealers.len());
        for dealer in main_trx_dealers.iter() {
            if let Some(dealer_addr) = all_validator_addrs.get(dealer.id) {
                dealer_set.insert(*dealer_addr);
            } else {
                bail!("invalid dealer idx");
            }
        }
        ensure!(main_trx_dealers.len() == dealer_set.len());
        if ensures_single_dealer.is_some() {
            let expected_dealer_set: HashSet<AccountAddress> =
                ensures_single_dealer.into_iter().collect();
            ensure!(expected_dealer_set == dealer_set);
        }

        if checks_voting_power {
            verifier
                .check_voting_power(dealer_set.iter(), true)
                .context("not enough power")?;
        }

        if let Some(fast_trx) = &trx.fast {
            ensure!(fast_trx.get_dealers() == main_trx_dealers);
            ensure!(trx.main.get_dealt_public_key() == fast_trx.get_dealt_public_key());
        }
        Ok(())
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L332-401)
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

**File:** crates/reliable-broadcast/src/lib.rs (L171-180)
```rust
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
```
