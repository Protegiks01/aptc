# Audit Report

## Title
Byzantine Validator DKG Transcript Equivocation Enables Single-Validator DKG Denial of Service

## Summary
A single Byzantine validator can cause complete DKG failure by sending different valid transcripts to different honest validators during the transcript aggregation phase, violating the expected 1/3 Byzantine fault tolerance and causing network-wide liveness failure.

## Finding Description

The DKG protocol aggregates transcripts from validators through an RPC-based reliable broadcast mechanism. However, there is no cryptographic or consensus-based enforcement that ensures all honest validators receive identical transcripts from each dealer.

**Attack Flow:**

1. A Byzantine validator generates multiple valid DKG transcripts, each with different random secrets and corresponding chunked values [1](#0-0) 

2. When honest validators request the Byzantine validator's transcript via RPC, the Byzantine validator responds with different transcripts to different requesters [2](#0-1) 

3. Each transcript passes individual verification independently, as they are all cryptographically valid with proper proofs [3](#0-2) 

4. The transcript aggregation only checks if a transcript from the same author was already added to that specific aggregator, but doesn't verify consistency across different validators' aggregators [4](#0-3) 

5. Different honest validators aggregate different transcripts from the Byzantine validator, resulting in different final aggregated DKG results

6. When validators attempt to reach consensus on the DKG result, they cannot form a quorum because each has a different aggregated transcript

7. DKG fails completely, preventing epoch transitions and causing total network liveness failure

**Broken Invariants:**
- **Consensus Safety/Liveness**: Different honest validators compute different DKG results, preventing consensus
- **Byzantine Fault Tolerance**: A single Byzantine validator (<<1/3) causes complete DKG failure, violating the expected 1/3 Byzantine tolerance

## Impact Explanation

**Critical Severity** - This meets the "Total loss of liveness/network availability" criterion from the Aptos bug bounty program.

A single Byzantine validator can:
- Prevent all DKG sessions from completing
- Block epoch transitions indefinitely
- Cause complete network halt until the Byzantine validator is removed
- Affect 100% of validators and users
- Require off-chain coordination or hardfork to resolve

The attack breaks the fundamental assumption that the system tolerates up to 1/3 Byzantine validators. A single malicious validator (potentially <1% of stake) can halt the entire network.

## Likelihood Explanation

**High Likelihood:**
- Requires only one compromised validator node
- No special timing or network conditions required
- Attack is deterministic and repeatable
- No cryptographic barriers to overcome
- Simple implementation: modify the RPC response handler to randomize or target specific transcripts to specific peers
- DKG runs regularly during epoch transitions, providing repeated attack opportunities

**Low Barrier to Entry:**
- Any validator can become Byzantine through compromise or malicious intent
- No stake threshold beyond being in the validator set
- Attack code is straightforward to implement

## Recommendation

Implement a consensus-based DKG transcript commitment mechanism:

1. **Two-Phase DKG Protocol:**
   - **Phase 1 - Commitment**: Each dealer broadcasts a cryptographic commitment (hash) of their transcript through consensus. All validators must agree on the set of commitments before proceeding.
   - **Phase 2 - Reveal**: Dealers reveal their actual transcripts. Validators verify that revealed transcripts match the committed hashes and reject any dealer whose transcript doesn't match.

2. **Implementation Steps:**
   - Add a `DKGCommitment` message type containing `hash(transcript)` and dealer signature
   - Modify DKG flow to collect commitments via consensus before transcript exchange
   - Add verification in `TranscriptAggregationState::add` to check received transcripts against committed hashes
   - Reject aggregation if any transcript doesn't match its commitment

3. **Alternative: Gossip-Based Verification:**
   - After receiving a transcript, validators gossip received transcript hashes to peers
   - If inconsistent hashes are detected for the same dealer, all validators reject that dealer's contribution
   - Requires additional network round but provides equivocation detection

## Proof of Concept

```rust
// Malicious validator modification to dkg_manager.rs process_peer_rpc_msg()

async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest {
        msg,
        sender,  // Added to get sender info
        mut response_sender,
        ..
    } = req;
    
    ensure!(
        msg.epoch() == self.epoch_state.epoch,
        "[DKG] msg not for current epoch"
    );
    
    let response = match (&self.state, &msg) {
        (InnerState::Finished { my_transcript, .. }, DKGMessage::TranscriptRequest(_))
        | (InnerState::InProgress { my_transcript, .. }, DKGMessage::TranscriptRequest(_)) => {
            // ATTACK: Generate different transcript for each peer
            let equivocated_transcript = if sender.as_slice()[0] % 2 == 0 {
                // Send original transcript to half the validators
                my_transcript.clone()
            } else {
                // Generate and send alternative transcript to other half
                let mut rng = StdRng::from_seed(sender.into_bytes());
                let alt_secret = DKG::InputSecret::generate(&mut rng);
                let alt_trx = DKG::generate_transcript(
                    &mut rng,
                    &self.public_params,
                    &alt_secret,
                    self.my_index as u64,
                    &self.dealer_sk,
                    &self.dealer_pk,
                );
                DKGTranscript::new(
                    self.epoch_state.epoch,
                    self.my_addr,
                    bcs::to_bytes(&alt_trx).unwrap(),
                )
            };
            
            Ok(DKGMessage::TranscriptResponse(equivocated_transcript))
        },
        _ => Err(anyhow!("...")),
    };

    response_sender.send(response);
    Ok(())
}

// Result: Honest validators receive different transcripts, aggregate to different
// results, fail to reach consensus on DKG output, DKG session fails permanently.
```

**Validation Steps:**
1. Deploy modified validator node as one validator in a test network
2. Initiate DKG session
3. Observe that different honest validators aggregate different DKG results
4. Observe that consensus fails on DKG validator transaction
5. Confirm DKG session timeout and network halt

## Notes

This vulnerability exploits the gap between individual transcript verification (which is cryptographically sound) and cross-validator consistency verification (which is absent). The reliable broadcast mechanism assumes honest responses but doesn't enforce it cryptographically. The fix requires adding a consensus or gossip layer to detect equivocation before transcripts are aggregated.

### Citations

**File:** dkg/src/dkg_manager/mod.rs (L330-339)
```rust
        let input_secret = DKG::InputSecret::generate(&mut rng);

        let trx = DKG::generate_transcript(
            &mut rng,
            &public_params,
            &input_secret,
            self.my_index as u64,
            &self.dealer_sk,
            &self.dealer_pk,
        );
```

**File:** dkg/src/dkg_manager/mod.rs (L464-478)
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

**File:** dkg/src/transcript_aggregation/mod.rs (L92-94)
```rust
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }
```
