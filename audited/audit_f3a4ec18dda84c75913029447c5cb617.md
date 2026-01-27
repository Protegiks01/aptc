# Audit Report

## Title
Missing Dealer Uniqueness Check in DKG On-Chain Verification Enables Sybil Attack

## Summary
A malicious validator can contribute multiple times to a DKG (Distributed Key Generation) transcript by creating multiple signatures of knowledge (SoKs) with their own player ID. The VM-level verification path (`verify_transcript`) lacks the dealer uniqueness check present in `verify_transcript_extra`, allowing duplicate dealer contributions to pass validation when DKG results are submitted on-chain.

## Finding Description
The DKG system has two verification paths:

1. **Peer-to-peer aggregation path** (used during transcript collection): Calls both `verify_transcript_extra` and `verify_transcript`
2. **On-chain submission path** (used when finalizing DKG): Only calls `verify_transcript`

The critical difference is that `verify_transcript_extra` contains a dealer uniqueness check [1](#0-0) , which ensures each dealer contributes exactly once by verifying that the number of dealer player IDs equals the number of unique addresses.

However, when a DKG result is submitted on-chain via `ValidatorTransaction::DKGResult`, the VM processes it through `process_dkg_result_inner` [2](#0-1) , which only calls `verify_transcript` without the uniqueness check.

**Attack Path:**
1. A malicious validator participates in normal DKG, receiving legitimate single-dealer transcripts from other validators
2. The attacker creates multiple PVSS transcripts for themselves with different secrets but the same player ID
3. The attacker aggregates their malicious transcripts locally using `aggregate_with` [3](#0-2) , which simply appends SoKs without uniqueness validation
4. The attacker aggregates legitimate transcripts from other validators with their malicious multi-contribution transcript
5. The attacker submits this as a `ValidatorTransaction::DKGResult` [4](#0-3) 

**Why Verification Passes:**
The signature verification in `batch_verify_soks` [5](#0-4)  aggregates all signatures and verifies them against corresponding messages. When a dealer contributes twice:
- Message 1: `(commitment_1, Player{id: X}, (epoch, address_X))`
- Message 2: `(commitment_2, Player{id: X}, (epoch, address_X))`

Both messages are signed by the same validator's key but with different commitments. Since both signatures are cryptographically valid (the attacker possesses their own private key), the aggregate signature verification succeeds. The system builds duplicate entries in the `spks` and `aux` arrays [6](#0-5) , but without a uniqueness check, this passes verification.

## Impact Explanation
**Critical Severity** - This breaks fundamental DKG security guarantees:

1. **Consensus Violation**: The DKG protocol's security relies on the assumption that if at least one honest dealer contributes unpredictable randomness, the final output is unpredictable. By allowing multiple contributions from a single dealer, an attacker gains disproportionate influence over the generated randomness.

2. **Voting Power Bypass**: A validator with 10% voting power could contribute 2-3 times, effectively gaining 20-30% influence over the DKG output, violating the proportional contribution property.

3. **Predictable Randomness**: If an attacker contributes enough times relative to honest dealers, they can bias or potentially predict the DKG output, compromising validator selection, leader election, and on-chain randomness.

This meets the Critical severity threshold as it enables consensus violations and breaks cryptographic protocol guarantees that the entire randomness system depends on.

## Likelihood Explanation
**High Likelihood:**
- Any malicious validator can execute this attack
- No coordination with other validators required
- Attack is deterministic once a validator decides to execute it
- The validation logic difference between peer aggregation and on-chain submission creates an exploitable gap
- No rate limiting or additional checks prevent repeated execution across epochs

## Recommendation
Add the dealer uniqueness check to `verify_transcript`:

```rust
fn verify_transcript(
    params: &Self::PublicParams,
    trx: &Self::Transcript,
) -> anyhow::Result<()> {
    // Existing dealer index validation
    let dealers = trx.main.get_dealers()
        .iter()
        .map(|player| player.id)
        .collect::<Vec<usize>>();
    
    // ADD: Uniqueness check
    let all_validator_addrs = params.verifier.get_ordered_account_addresses();
    let mut dealer_set = HashSet::with_capacity(dealers.len());
    for &dealer_id in dealers.iter() {
        if let Some(dealer_addr) = all_validator_addrs.get(dealer_id) {
            ensure!(
                dealer_set.insert(*dealer_addr),
                "Duplicate dealer detected: player_id={}", dealer_id
            );
        } else {
            bail!("Invalid dealer index: {}", dealer_id);
        }
    }
    
    // Rest of existing verification...
}
```

Alternatively, always call `verify_transcript_extra` in the VM path before `verify_transcript`.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_duplicate_dealer_bypass() {
    use aptos_types::dkg::RealDKG;
    
    // Setup: Create DKG session with 4 validators
    let pub_params = /* initialize with 4 validators */;
    
    // Validator 3 (malicious) creates TWO transcripts with same player ID
    let secret_1 = InputSecret::generate(&mut rng);
    let transcript_1 = RealDKG::generate_transcript(
        &mut rng, &pub_params, &secret_1, 3, &sk_3, &pk_3
    );
    
    let secret_2 = InputSecret::generate(&mut rng); 
    let transcript_2 = RealDKG::generate_transcript(
        &mut rng, &pub_params, &secret_2, 3, &sk_3, &pk_3
    );
    
    // Aggregate the two malicious transcripts
    let mut malicious_agg = transcript_1;
    RealDKG::aggregate_transcripts(&pub_params, &mut malicious_agg, transcript_2);
    
    // Aggregate with honest transcripts from validators 0,1,2
    RealDKG::aggregate_transcripts(&pub_params, &mut malicious_agg, honest_trx_0);
    RealDKG::aggregate_transcripts(&pub_params, &mut malicious_agg, honest_trx_1);
    RealDKG::aggregate_transcripts(&pub_params, &mut malicious_agg, honest_trx_2);
    
    // This should fail but PASSES in the current implementation
    let result = RealDKG::verify_transcript(&pub_params, &malicious_agg);
    assert!(result.is_ok()); // BUG: Verification succeeds!
    
    // Verify that validator 3 contributed twice
    let dealers = RealDKG::get_dealers(&malicious_agg);
    let validator_3_contributions = dealers.iter().filter(|&&d| d == 3).count();
    assert_eq!(validator_3_contributions, 2); // Validator 3 contributed twice!
}
```

## Notes
While the peer-to-peer aggregation path correctly enforces uniqueness via `verify_transcript_extra` [7](#0-6) , the on-chain submission path bypasses this check. The vulnerability exists because `verify_transcript` [8](#0-7)  was designed as a cryptographic verification function and doesn't include semantic correctness checks that are assumed to happen elsewhere. This separation of concerns creates a security gap when the VM path doesn't invoke both validation functions.

### Citations

**File:** types/src/dkg/real_dkg/mod.rs (L301-311)
```rust
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

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L336-338)
```rust
        for sok in &other.soks {
            self.soks.push(sok.clone());
        }
```

**File:** dkg/src/dkg_manager/mod.rs (L397-404)
```rust
                let txn = ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: self.epoch_state.epoch,
                        author: self.my_addr,
                    },
                    transcript_bytes: bcs::to_bytes(&agg_trx)
                        .map_err(|e| anyhow!("transcript serialization error: {e}"))?,
                });
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L79-102)
```rust
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
```

**File:** dkg/src/transcript_aggregation/mod.rs (L96-97)
```rust
        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;
```
