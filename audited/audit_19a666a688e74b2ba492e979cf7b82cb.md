# Audit Report

## Title
DKG Free-Rider Attack: Validators Can Avoid Computation by Delaying Participation

## Summary
Validators can delay processing `DKGStartEvent` and avoid the expensive transcript generation computation, relying on other validators to reach quorum. This creates a free-rider problem where rational validators can skip participation without penalty, potentially causing DKG failures if too many attempt this strategy.

## Finding Description
The DKG (Distributed Key Generation) protocol in Aptos requires validators to generate cryptographic transcripts and exchange them to establish shared randomness for the next epoch. The protocol completes when 2f+1 validators (quorum) contribute valid transcripts.

**The vulnerability exists in the participation enforcement mechanism:**

When `DKGStartEvent` is emitted on-chain, validators should immediately process it by calling `setup_deal_broadcast`, which performs the expensive `DKG::generate_transcript` computation. [1](#0-0) 

However, there is **no enforcement mechanism** requiring validators to process this event promptly. A rational, selfish validator can:

1. Receive the `DKGStartEvent` but deliberately delay calling `setup_deal_broadcast`
2. Stay in `NotStarted` state, avoiding the expensive transcript generation
3. When honest validators send `TranscriptRequest` messages, return an error since the validator cannot respond without a transcript [2](#0-1) 
4. If enough honest validators participate (reaching the 2f+1 quorum threshold), the DKG completes successfully
5. The free-riding validator benefits from the DKG result without having performed any computation

**Key vulnerability points:**

The quorum threshold is calculated as `total_voting_power * 2 / 3 + 1`, meaning up to f validators (approximately 1/3) can avoid participation while the protocol still succeeds. [3](#0-2) 

The `add()` function in transcript aggregation checks if quorum is reached and completes once sufficient transcripts are collected. [4](#0-3) 

When DKG doesn't complete due to insufficient participation, incomplete sessions are simply cleared during epoch transitions with no penalties. [5](#0-4) 

**No economic penalties exist:** My search revealed no slashing, reward reduction, or any penalty mechanism tied to DKG participation or non-participation.

## Impact Explanation
**Medium Severity** ($10,000 bounty range):

1. **Computational Cost Avoidance**: Validators that successfully free-ride avoid the expensive cryptographic transcript generation cost while still benefiting from the protocol
2. **Tragedy of the Commons**: If this behavior becomes widespread, it creates a coordination problem where too many validators attempt to free-ride simultaneously
3. **DKG Liveness Risk**: If more than f validators (>1/3) attempt to free-ride, quorum cannot be reached, causing DKG to fail and requiring manual intervention
4. **Protocol Integrity**: Creates perverse economic incentives misaligned with protocol goals, where rational validators are incentivized to minimize participation

This qualifies as Medium severity because it represents "state inconsistencies requiring intervention" when DKG fails, and creates systematic participation issues in a critical protocol component.

## Likelihood Explanation
**High Likelihood:**

1. **No Technical Barriers**: Any validator can implement this strategy by simply delaying `process_dkg_start_event` without modifying core protocol code
2. **Economic Rationality**: The strategy is economically rational for individual validators (save computation costs, no penalties)
3. **Observable State**: Validators can observe network activity to estimate if others are participating
4. **No Detection**: The protocol cannot distinguish intentional delay from temporary network issues or node problems
5. **Existing Byzantine Tolerance**: Since the protocol already tolerates f Byzantine validators, free-riding within this threshold appears "normal" to the system

The primary barrier is coordination: if too many validators attempt this simultaneously (>f), DKG fails. However, even with failures, validators face no penalties, making the strategy low-risk.

## Recommendation
Implement **economic penalties** and **participation enforcement**:

1. **Track DKG Participation**: Record which validators submitted valid transcripts during each DKG session on-chain

2. **Performance-Based Rewards**: Extend the existing validator performance tracking system to include DKG participation. Modify the reward distribution in `stake.move` to penalize validators who fail to participate in DKG:

```rust
// In stake.move on_new_epoch function
// Add DKG participation check alongside proposal success tracking
if !participated_in_dkg(&validator_address) {
    // Reduce or eliminate rewards for non-participating validators
    reward_amount = reward_amount / 2; // or zero rewards
}
```

3. **Timeout Mechanism**: Implement a deadline for DKG completion. If a validator doesn't respond within a reasonable timeframe (e.g., 30 seconds), mark it as non-participating:

```rust
// In DKGManager
const DKG_PARTICIPATION_DEADLINE: Duration = Duration::from_secs(30);

// Track response time and penalize late responses
if duration_since_dkg_start > DKG_PARTICIPATION_DEADLINE {
    // Mark validator as late/non-participating
    record_late_participation(validator_address);
}
```

4. **Minimum Participation Threshold**: Rather than accepting the minimum quorum (2f+1), require a higher threshold (e.g., 90% participation) before completing DKG, with penalties for validators not meeting this threshold.

## Proof of Concept

```rust
// Simulated free-rider validator behavior
// This demonstrates the attack without modifying core protocol code

pub struct FreeRiderValidator {
    dkg_manager: DKGManager<DKG>,
    participation_strategy: ParticipationStrategy,
}

enum ParticipationStrategy {
    AlwaysParticipate,
    FreeRide, // Only participate if necessary
}

impl FreeRiderValidator {
    async fn handle_dkg_start_event(&mut self, event: DKGStartEvent) -> Result<()> {
        match self.participation_strategy {
            ParticipationStrategy::AlwaysParticipate => {
                // Normal behavior: immediately process event
                self.dkg_manager.process_dkg_start_event(event).await
            },
            ParticipationStrategy::FreeRide => {
                // Free-rider behavior: delay and monitor
                info!("Received DKGStartEvent, delaying participation...");
                
                // Wait to see if others reach quorum
                tokio::time::sleep(Duration::from_secs(30)).await;
                
                // Check if DKG already completed via other validators
                if self.check_dkg_completed().await {
                    info!("DKG completed without my participation - successfully free-rode!");
                    Ok(())
                } else {
                    // If not complete, now participate (but might be too late)
                    warn!("DKG not complete, participating now...");
                    self.dkg_manager.process_dkg_start_event(event).await
                }
            }
        }
    }
    
    async fn check_dkg_completed(&self) -> bool {
        // Check if DKG result transaction exists in mempool or on-chain
        // This demonstrates observability of DKG progress
        self.query_dkg_state().await.is_complete()
    }
}

// Impact demonstration:
// - If 33% of validators use FreeRide strategy: DKG completes, free-riders save computation
// - If >33% of validators use FreeRide strategy: DKG fails, requires manual intervention
// - No penalties applied to free-riding validators in either case
```

**Notes:**
- The vulnerability exploits the lack of participation enforcement rather than any cryptographic or consensus bug
- The protocol design tolerates Byzantine behavior up to f validators, but economic incentives amplify the problem beyond typical Byzantine assumptions  
- Line 105's `valid_peer_transcript_seen` flag is never updated (initialized at line 52, never set to true), representing a separate metrics bug but not directly exploitable for the free-rider attack
- The free-rider cannot monitor transcripts without generating their own first (must be in InProgress state to respond to requests), but can avoid participation entirely by not processing the DKGStartEvent

### Citations

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

**File:** dkg/src/dkg_manager/mod.rs (L464-473)
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
```

**File:** types/src/validator_verifier.rs (L211-211)
```rust
            total_voting_power * 2 / 3 + 1
```

**File:** dkg/src/transcript_aggregation/mod.rs (L122-134)
```rust
        let threshold = self.epoch_state.verifier.quorum_voting_power();
        let power_check_result = self
            .epoch_state
            .verifier
            .check_voting_power(trx_aggregator.contributors.iter(), true);
        let new_total_power = match &power_check_result {
            Ok(x) => Some(*x),
            Err(VerifyError::TooLittleVotingPower { voting_power, .. }) => Some(*voting_power),
            _ => None,
        };
        let maybe_aggregated = power_check_result
            .ok()
            .map(|_| trx_aggregator.trx.clone().unwrap());
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-48)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
```
