# Audit Report

## Title
DKG Protocol Lacks Commit-Reveal Scheme Allowing Last-Revealer Information Advantage

## Summary
The Aptos DKG (Distributed Key Generation) protocol does not implement a commit-reveal scheme, allowing a malicious validator to observe other validators' public key commitments before submitting their own transcript, potentially biasing the final randomness beacon output.

## Finding Description

The DKG protocol in Aptos is used to generate threshold signature keys for the randomness beacon. The protocol flow is: [1](#0-0) 

Each validator generates a transcript containing public key commitments (V0, Vs) and encrypted shares: [2](#0-1) 

The critical vulnerability is that the protocol **does not enforce cryptographic commitment before revelation**. While honest validators generate random input secrets immediately: [3](#0-2) 

A malicious validator can modify their node to:
1. Delay calling `setup_deal_broadcast()`
2. Request transcripts from other validators via the reliable broadcast mechanism
3. Observe partial public key commitments (V0 values) from threshold-1 validators
4. Calculate a chosen input secret to bias the final aggregated public key
5. Generate their transcript with the chosen input
6. Complete the aggregation

The aggregation is performed additively: [4](#0-3) 

Since V0_final = sum(V0_i) for all validators, the last validator seeing V0_partial can choose their V0_last to influence properties of V0_final, breaking the unpredictability guarantee required for secure randomness generation.

The final randomness is derived from this threshold key via WVUF evaluation and used throughout the system including leader election: [5](#0-4) 

## Impact Explanation

This vulnerability has **Medium severity** impact:

1. **Breaks Randomness Unpredictability**: The security guarantee that randomness is unpredictable is violated when a validator can influence the threshold key generation.

2. **Enables Secondary Attacks**: Biased randomness could enable:
   - MEV (Maximal Extractable Value) extraction through predictable leader election
   - Gaming of randomness-dependent smart contracts
   - Unfair advantages in validator selection

3. **Limited Direct Damage**: The attacker cannot fully control the output (only influence it) and cannot directly steal funds, qualifying as "State inconsistencies requiring intervention" under Medium severity.

## Likelihood Explanation

**Likelihood: Medium**

- Requires a malicious validator with modified node software (high barrier)
- Does not require collusion with other validators (single malicious actor)
- The attack is technically feasible and provides clear economic incentive
- No cryptographic commitment prevents this behavior at the protocol level

## Recommendation

Implement a two-phase commit-reveal scheme for DKG:

**Phase 1 - Commitment:**
- Each validator computes `commitment = H(transcript || nonce)` where H is a cryptographic hash
- Validators broadcast and collect commitments
- Wait until threshold commitments are received

**Phase 2 - Revelation:**
- Validators reveal their full transcripts and nonces
- Verify that `H(revealed_transcript || nonce) == commitment`
- Only aggregate transcripts that match their commitments
- Reject late submissions after revelation phase begins

Add a timeout mechanism to the reliable broadcast to enforce phase transitions: [6](#0-5) 

Modify the `DKGMessage` enum to support commitment and revelation phases: [7](#0-6) 

## Proof of Concept

```rust
// Malicious validator exploitation path
// This PoC demonstrates the attack conceptually

use aptos_dkg::pvss::traits::Transcript;
use aptos_types::dkg::DefaultDKG;

// Malicious validator delays transcript generation
async fn malicious_dkg_behavior() {
    // Step 1: Start collecting transcripts without generating own
    let mut collected_transcripts = Vec::new();
    
    // Step 2: Request transcripts from all other validators
    for peer in other_validators {
        let transcript = request_transcript(peer).await;
        collected_transcripts.push(transcript);
        
        // Stop when we have threshold - 1
        if collected_transcripts.len() >= threshold - 1 {
            break;
        }
    }
    
    // Step 3: Calculate partial aggregation
    let partial_pk = aggregate_public_keys(&collected_transcripts);
    
    // Step 4: Choose input to bias final result
    // Attacker can grind for favorable properties
    let chosen_input = calculate_biasing_input(partial_pk, desired_properties);
    
    // Step 5: Generate transcript with chosen input
    let malicious_transcript = DefaultDKG::generate_transcript(
        &mut rng,
        &params,
        &chosen_input,  // Chosen, not random!
        my_index,
        &sk,
        &pk,
    );
    
    // Step 6: Broadcast and complete aggregation
    broadcast_transcript(malicious_transcript);
}
```

**Notes:**

The vulnerability stems from the protocol's assumption that validators will generate transcripts with random inputs immediately upon DKG start. However, there is no cryptographic mechanism forcing this behavior - no signature over a commitment, no time-locked revelation, and no penalty for late submission. A rational malicious validator can deviate from the protocol to gain information advantage, breaking the fundamental unpredictability property required for secure randomness generation in distributed systems.

### Citations

**File:** dkg/src/dkg_manager/mod.rs (L288-375)
```rust
    /// Calculate DKG config. Deal a transcript. Start broadcasting the transcript.
    /// Called when a DKG start event is received, or when the node is restarting.
    ///
    /// NOTE: the dealt DKG transcript does not have to be persisted:
    /// it is ok for a validator to equivocate on its DKG transcript, as long as the transcript is valid.
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L63-91)
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transcript<E: Pairing> {
    dealer: Player,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    /// This is the aggregatable subtranscript
    pub subtrs: Subtranscript<E>,
    /// Proof (of knowledge) showing that the s_{i,j}'s in C are base-B representations (of the s_i's in V, but this is not part of the proof), and that the r_j's in R are used in C
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sharing_proof: SharingProof<E>,
}

#[allow(non_snake_case)]
#[derive(
    CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct Subtranscript<E: Pairing> {
    // The dealt public key
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub V0: E::G2,
    // The dealt public key shares
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Vs: Vec<Vec<E::G2>>,
    /// First chunked ElGamal component: C[i][j] = s_{i,j} * G + r_j * ek_i. Here s_i = \sum_j s_{i,j} * B^j // TODO: change notation because B is not a group element?
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Cs: Vec<Vec<Vec<E::G1>>>, // TODO: maybe make this and the other fields affine? The verifier will have to do it anyway... and we are trying to speed that up
    /// Second chunked ElGamal component: R[j] = r_j * H
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Rs: Vec<Vec<E::G1>>,
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L386-417)
```rust
    #[allow(non_snake_case)]
    fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
        debug_assert_eq!(self.Cs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Vs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Cs.len(), other.Cs.len());
        debug_assert_eq!(self.Rs.len(), other.Rs.len());
        debug_assert_eq!(self.Vs.len(), other.Vs.len());

        // Aggregate the V0s
        self.V0 += other.V0;

        for i in 0..sc.get_total_num_players() {
            for j in 0..self.Vs[i].len() {
                // Aggregate the V_{i,j}s
                self.Vs[i][j] += other.Vs[i][j];
                for k in 0..self.Cs[i][j].len() {
                    // Aggregate the C_{i,j,k}s
                    self.Cs[i][j][k] += other.Cs[i][j][k];
                }
            }
        }

        for j in 0..self.Rs.len() {
            for (R_jk, other_R_jk) in self.Rs[j].iter_mut().zip(&other.Rs[j]) {
                // Aggregate the R_{j,k}s
                *R_jk += other_R_jk;
            }
        }

        Ok(())
    }
}
```

**File:** consensus/src/liveness/proposer_election.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_consensus_types::common::{Author, Round};
use aptos_fallible::copy_from_slice::copy_slice_to_vec;
use num_traits::CheckedAdd;
use std::cmp::Ordering;

/// ProposerElection incorporates the logic of choosing a leader among multiple candidates.
pub trait ProposerElection {
    /// If a given author is a valid candidate for being a proposer, generate the info,
    /// otherwise return None.
    /// Note that this function is synchronous.
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }

    /// Return the valid proposer for a given round (this information can be
    /// used by e.g., voters for choosing the destinations for sending their votes to).
    fn get_valid_proposer(&self, round: Round) -> Author;

    /// Return the chain health: a ratio of voting power participating in the consensus.
    fn get_voting_power_participation_ratio(&self, _round: Round) -> f64 {
        1.0
    }

    fn get_valid_proposer_and_voting_power_participation_ratio(
        &self,
        round: Round,
    ) -> (Author, f64) {
        (
            self.get_valid_proposer(round),
            self.get_voting_power_participation_ratio(round),
        )
    }
}

// next consumes seed and returns random deterministic u64 value in [0, max) range
fn next_in_range(state: Vec<u8>, max: u128) -> u128 {
    // hash = SHA-3-256(state)
    let hash = aptos_crypto::HashValue::sha3_256_of(&state).to_vec();
    let mut temp = [0u8; 16];
    copy_slice_to_vec(&hash[..16], &mut temp).expect("next failed");
    // return hash[0..16]
    u128::from_le_bytes(temp) % max
}

// chose index randomly, with given weight distribution
pub(crate) fn choose_index(mut weights: Vec<u128>, state: Vec<u8>) -> usize {
    let mut total_weight = 0;
```

**File:** dkg/src/agg_trx_producer.rs (L17-43)
```rust
/// A sub-process of the whole DKG process.
/// Once invoked by `DKGManager` to `start_produce`,
/// it starts producing an aggregated transcript and returns an abort handle.
/// Once an aggregated transcript is available, it is sent back via channel `agg_trx_tx`.
pub trait TAggTranscriptProducer<S: DKGTrait>: Send + Sync {
    fn start_produce(
        &self,
        start_time: Duration,
        my_addr: AccountAddress,
        epoch_state: Arc<EpochState>,
        dkg_config: S::PublicParams,
        agg_trx_tx: Option<Sender<(), S::Transcript>>,
    ) -> AbortHandle;
}

/// The real implementation of `AggTranscriptProducer` that broadcasts a `NodeRequest`, collects and verifies nodes from network.
pub struct AggTranscriptProducer {
    reliable_broadcast: Arc<ReliableBroadcast<DKGMessage, ExponentialBackoff>>,
}

impl AggTranscriptProducer {
    pub fn new(reliable_broadcast: ReliableBroadcast<DKGMessage, ExponentialBackoff>) -> Self {
        Self {
            reliable_broadcast: Arc::new(reliable_broadcast),
        }
    }
}
```

**File:** dkg/src/types.rs (L24-45)
```rust
/// The DKG network message.
#[derive(Clone, Serialize, Deserialize, Debug, EnumConversion, PartialEq)]
pub enum DKGMessage {
    TranscriptRequest(DKGTranscriptRequest),
    TranscriptResponse(DKGTranscript),
}

impl DKGMessage {
    pub fn epoch(&self) -> u64 {
        match self {
            DKGMessage::TranscriptRequest(request) => request.dealer_epoch,
            DKGMessage::TranscriptResponse(response) => response.metadata.epoch,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            DKGMessage::TranscriptRequest(_) => "DKGTranscriptRequest",
            DKGMessage::TranscriptResponse(_) => "DKGTranscriptResponse",
        }
    }
}
```
