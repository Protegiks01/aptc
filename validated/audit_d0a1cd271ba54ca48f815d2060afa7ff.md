# Audit Report

## Title
DKG Protocol Lacks Commit-Reveal Scheme Allowing Last-Revealer Information Advantage

## Summary
The Aptos DKG protocol does not implement a commit-reveal scheme, enabling a malicious validator to observe other validators' public key commitments before submitting their own transcript, thereby biasing the final threshold key used for randomness generation.

## Finding Description

The DKG protocol generates threshold signature keys for the randomness beacon through a multi-validator process. The vulnerability exists because the protocol lacks cryptographic commitment before revelation of contributions.

**Attack Execution Path:**

When a `DKGStartEvent` is emitted, honest validators immediately execute `setup_deal_broadcast()` which generates a random input secret and creates a transcript containing public key commitments. [1](#0-0) 

The transcript structure contains public key commitments `V_hat[W]` representing `g_2^{p(0)}` where `p(0)` is the dealt secret: [2](#0-1) 

**Critical Vulnerability**: When validators request transcripts from peers, the responding validator does NOT verify that the requester has already generated their own transcript: [3](#0-2) 

A malicious validator can:
1. Receive `DKGStartEvent` but delay calling `setup_deal_broadcast()`
2. Send `DKGTranscriptRequest` messages to other validators
3. Receive transcripts containing public key commitments `V_hat[W]`
4. Observe partial aggregated public key from threshold-1 validators
5. Calculate a biased input secret to influence the final aggregated key
6. Generate their transcript with the chosen input secret

The aggregation is additive, directly summing all contributions: [4](#0-3) 

Since `final_V_hat[W] = Σ(V_hat_i[W])`, the last contributor can bias properties of the final threshold public key used for randomness generation.

## Impact Explanation

**Severity: Medium** (up to $10,000)

This qualifies as "Limited Protocol Violations" and "State inconsistencies requiring manual intervention":

1. **Breaks Randomness Unpredictability**: The fundamental security guarantee that the randomness beacon output is unpredictable is violated when a validator can influence the threshold key generation based on observing other validators' contributions.

2. **Enables Secondary Exploitation**: Biased randomness enables:
   - MEV extraction through predictable leader election
   - Gaming randomness-dependent smart contracts
   - Strategic advantages in validator selection
   - Unfair protocol manipulation

3. **Limited but Real Damage**: The attacker cannot fully control the randomness output (only bias it) and cannot directly steal funds. However, the unpredictability guarantee is fundamentally broken, requiring protocol-level intervention to fix.

## Likelihood Explanation

**Likelihood: Medium**

- Requires a malicious validator with modified node software (significant but not insurmountable barrier)
- Does NOT require collusion (single actor < 1/3 Byzantine threshold)
- Technically feasible - no cryptographic or protocol-level prevention exists
- Clear economic incentive through MEV and strategic advantages
- Attack is deterministic once prerequisites are met

## Recommendation

Implement a commit-reveal scheme for DKG transcript generation:

**Phase 1 - Commitment:**
- Validators generate their input secrets and transcripts
- Compute cryptographic hash commitment: `H(transcript || nonce)`
- Broadcast commitments via reliable broadcast
- Wait for threshold commitments before proceeding

**Phase 2 - Reveal:**
- After receiving threshold commitments, broadcast actual transcripts
- Verify each transcript matches its prior commitment
- Reject transcripts without valid commitments
- Proceed with aggregation only after verification

This ensures no validator can observe others' contributions before committing to their own, preserving unpredictability.

## Proof of Concept

The vulnerability is demonstrated through code inspection showing:

1. **No commitment enforcement** in transcript generation: [5](#0-4) 

2. **Unrestricted transcript responses** without requester validation: [6](#0-5) 

3. **Additive aggregation** enabling final-contributor bias: [7](#0-6) 

4. **No timing constraints** preventing delayed participation: [8](#0-7) 

A malicious validator can exploit this by modifying their node to delay `setup_deal_broadcast()`, actively request peer transcripts, extract `V_hat[W]` values, compute a biasing input secret, and complete DKG with their chosen contribution.

## Notes

This vulnerability represents a fundamental protocol design issue rather than an implementation bug. While the PVSS implementation itself is cryptographically sound, the lack of a commit-reveal wrapper around the DKG protocol allows information asymmetry that breaks the unpredictability guarantee required for secure randomness generation. The attack requires Byzantine validator behavior (< 1/3 threshold), which is within the standard BFT threat model for blockchain consensus systems.

### Citations

**File:** dkg/src/dkg_manager/mod.rs (L293-375)
```rust
    async fn setup_deal_broadcast(
        &mut self,
        start_time_us: u64,
        dkg_session_metadata: &DKGSessionMetadata,
    ) -> Result<()> {
        ensure!(
            matches!(&self.state, InnerState::NotStarted),
            "transcript already dealt"
        );
        let dkg_start_time = Duration::from_micros(start_time_us);
        let deal_start = duration_since_epoch();
        let secs_since_dkg_start = deal_start.as_secs_f64() - dkg_start_time.as_secs_f64();
        DKG_STAGE_SECONDS
            .with_label_values(&[self.my_addr.to_hex().as_str(), "deal_start"])
            .observe(secs_since_dkg_start);
        info!(
            epoch = self.epoch_state.epoch,
            my_addr = self.my_addr,
            secs_since_dkg_start = secs_since_dkg_start,
            "[DKG] Deal transcript started.",
        );
        let public_params = DKG::new_public_params(dkg_session_metadata);
        if let Some(summary) = public_params.rounding_summary() {
            info!(
                epoch = self.epoch_state.epoch,
                "Rounding summary: {:?}", summary
            );
            ROUNDING_SECONDS
                .with_label_values(&[summary.method.as_str()])
                .observe(summary.exec_time.as_secs_f64());
        }

        let mut rng = if cfg!(feature = "smoke-test") {
            StdRng::from_seed(self.my_addr.into_bytes())
        } else {
            StdRng::from_rng(thread_rng()).unwrap()
        };
        let input_secret = DKG::InputSecret::generate(&mut rng);

        let trx = DKG::generate_transcript(
            &mut rng,
            &public_params,
            &input_secret,
            self.my_index as u64,
            &self.dealer_sk,
            &self.dealer_pk,
        );

        let my_transcript = DKGTranscript::new(
            self.epoch_state.epoch,
            self.my_addr,
            bcs::to_bytes(&trx).map_err(|e| anyhow!("transcript serialization error: {e}"))?,
        );

        let deal_finish = duration_since_epoch();
        let secs_since_dkg_start = deal_finish.as_secs_f64() - dkg_start_time.as_secs_f64();
        DKG_STAGE_SECONDS
            .with_label_values(&[self.my_addr.to_hex().as_str(), "deal_finish"])
            .observe(secs_since_dkg_start);
        info!(
            epoch = self.epoch_state.epoch,
            my_addr = self.my_addr,
            secs_since_dkg_start = secs_since_dkg_start,
            "[DKG] Deal transcript finished.",
        );

        let abort_handle = self.agg_trx_producer.start_produce(
            dkg_start_time,
            self.my_addr,
            self.epoch_state.clone(),
            public_params.clone(),
            self.agg_trx_tx.clone(),
        );

        // Switch to the next stage.
        self.state = InnerState::InProgress {
            start_time: dkg_start_time,
            my_transcript,
            abort_handle,
        };

        Ok(())
    }
```

**File:** dkg/src/dkg_manager/mod.rs (L454-478)
```rust
    async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
        let IncomingRpcRequest {
            msg,
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L148-151)
```rust
        let V_hat = (0..W)
            .map(|k| g_2.mul(f_evals[k]))
            .chain([g_2.mul(f_coeff[0])])
            .collect::<Vec<G2Projective>>();
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L394-397)
```rust
        for i in 0..self.V.len() {
            self.V[i] += other.V[i];
            self.V_hat[i] += other.V_hat[i];
        }
```

**File:** types/src/dkg/real_dkg/mod.rs (L403-420)
```rust
    fn aggregate_transcripts(
        params: &Self::PublicParams,
        accumulator: &mut Self::Transcript,
        element: Self::Transcript,
    ) {
        accumulator
            .main
            .aggregate_with(&params.pvss_config.wconfig, &element.main)
            .expect("Transcript aggregation failed");
        if let (Some(acc), Some(ele), Some(config)) = (
            accumulator.fast.as_mut(),
            element.fast.as_ref(),
            params.pvss_config.fast_wconfig.as_ref(),
        ) {
            acc.aggregate_with(config, ele)
                .expect("Transcript aggregation failed");
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-40)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
    }
```
