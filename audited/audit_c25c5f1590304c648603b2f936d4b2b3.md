# Audit Report

## Title
Timeout Certificate Epoch Validation Bypass Enables Cross-Epoch Consensus Manipulation

## Summary
Timeout certificates from epoch N can be replayed and accepted in epoch N+1 due to missing epoch validation in the `verify_tc()` function, allowing Byzantine validators to manipulate consensus safety rules with stale timeout information.

## Finding Description

The Aptos consensus protocol fails to validate the epoch of timeout certificates when they are presented in voting and timeout signing operations. The critical vulnerability exists in the `SafetyRules::verify_tc()` function: [1](#0-0) 

This function verifies timeout certificate signatures using the current epoch's validator verifier but **does not check** whether `tc.epoch()` matches the current epoch stored in `epoch_state.epoch`. 

The timeout certificate structure contains an epoch field: [2](#0-1) 

However, when `TwoChainTimeoutCertificate::verify()` is called, it only validates:
1. Timeout round > HQC round
2. Quorum certificate validity  
3. Signature correctness for timeout messages
4. Consistency between HQC round and max signed round [3](#0-2) 

Notably absent: any validation that the timeout certificate's epoch matches the expected epoch.

**Attack Path:**

1. A Byzantine validator participates in epoch N and obtains a valid timeout certificate `TC_N` for round R
2. The blockchain transitions from epoch N to epoch N+1 with an unchanged or minimally changed validator set
3. In epoch N+1 at round < R, the Byzantine validator presents `TC_N` in a `VoteProposal` or timeout message
4. When other validators process this message, they call `verify_tc(TC_N)`: [4](#0-3) 

5. Since the validator set didn't change significantly, signatures from epoch N validators remain valid under epoch N+1's `ValidatorVerifier`
6. The stale `TC_N` passes verification and influences consensus decisions via `safe_to_vote()` and `safe_to_timeout()`: [5](#0-4) 

7. These safety functions use `tc.round()` without considering that the TC is from a different epoch, potentially causing validators to:
   - Accept votes for blocks at incorrect rounds (violating `round == next_round(tc_round)?`)
   - Time out at incorrect rounds based on stale epoch state

While the recovery path properly filters stale timeout certificates by epoch: [6](#0-5) 

This protection **only applies during node recovery**, not during normal real-time consensus operation.

## Impact Explanation

This vulnerability constitutes a **High Severity** consensus safety violation per Aptos bug bounty criteria:

**Consensus Safety Impact:**
- Byzantine validators can manipulate the 2-chain safety rules by injecting stale timeout certificates from previous epochs
- Validators may incorrectly vote for blocks or time out at wrong rounds based on cross-epoch timeout information
- Violates the epoch boundary invariant: consensus state from epoch N should not influence epoch N+1 decisions

**Attack Feasibility:**
- Requires 1+ Byzantine validator(s) present in both epochs (within BFT threat model)
- Most effective when validator sets remain stable across epochs (common in practice)
- The stale TC gets persisted to storage via `insert_2chain_timeout_certificate()`, making the corruption persistent: [7](#0-6) 

This meets **High Severity** criteria for "Significant protocol violations" that affect consensus correctness.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Required conditions:
1. Validator set remains unchanged or minimally changed between epochs (common in stable networks)
2. At least one Byzantine validator participates in consecutive epochs (standard BFT assumption)
3. Epoch transition occurs (happens regularly in Aptos)

The attack is straightforward to execute once conditions are met - a Byzantine validator simply reuses stored timeout certificates from the previous epoch. No complex cryptographic attacks or timing exploits are needed.

## Recommendation

Add explicit epoch validation to `verify_tc()`:

```rust
fn verify_tc(&self, tc: &TwoChainTimeoutCertificate) -> Result<(), Error> {
    let epoch_state = self.epoch_state()?;
    
    // Validate TC epoch matches current epoch
    if tc.epoch() != epoch_state.epoch {
        return Err(Error::IncorrectEpoch(tc.epoch(), epoch_state.epoch));
    }

    if !self.skip_sig_verify {
        tc.verify(&epoch_state.verifier)
            .map_err(|e| Error::InvalidTimeoutCertificate(e.to_string()))?;
    }
    Ok(())
}
```

**Additional Hardening:**
- Add epoch validation to `SyncInfo::verify()` when checking TC consistency (currently checks epoch equality with HQC but should explicitly validate against expected epoch)
- Add explicit epoch checks when processing `RoundTimeoutMsg` before insertion into pending votes
- Consider adding epoch fields to the signing format to cryptographically bind timeout signatures to specific epochs

## Proof of Concept

**Scenario Setup:**
1. Epoch N: validator set `{V1, V2, V3, V4}` at round 10
2. Validators time out at round 10, creating `TC_10` with `epoch=N, round=10`
3. Epoch transitions to N+1 with **same validator set**
4. Byzantine validator V1 stores `TC_10` and replays it in epoch N+1

**Verification Path (demonstrates missing epoch check):**

```rust
// In epoch N+1, Byzantine V1 sends VoteProposal with TC_10 from epoch N
// RoundManager receives the proposal and processes it:

pub async fn process_vote_msg(&mut self, vote_msg: VoteMsg) -> anyhow::Result<()> {
    // ... sync_up happens first
    self.process_vote(vote_msg.vote()).await
}

async fn process_vote(&mut self, vote: &Vote) -> anyhow::Result<()> {
    // Vote contains TC_10 from epoch N
    // SafetyRules is called to verify:
    
    pub(crate) fn guarded_construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>, // <- TC_10 from epoch N
    ) -> Result<Vote, Error> {
        self.signer()?;
        
        let vote_data = self.verify_proposal(vote_proposal)?; // Checks proposal epoch = N+1 ✓
        
        if let Some(tc) = timeout_cert { // TC_10 present
            self.verify_tc(tc)?; // <- MISSING EPOCH CHECK!
            // Only verifies signatures, not that tc.epoch() == current_epoch
        }
        
        // Safety rule now uses stale TC_10 from epoch N
        self.safe_to_vote(proposed_block, timeout_cert)?;
        // Accepts blocks based on: round == next_round(tc.round())
        // But tc.round() is from EPOCH N, not epoch N+1!
        ...
    }
}
```

**Expected Result:** Validator accepts stale `TC_10` from epoch N in epoch N+1, potentially voting for blocks at incorrect rounds.

**Actual Behavior:** No epoch validation occurs in `verify_tc()`, allowing cross-epoch timeout certificate replay.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L62-64)
```rust
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L147-166)
```rust
    /// Core safety voting rule for 2-chain protocol. Return success if 1 or 2 is true
    /// 1. block.round == block.qc.round + 1
    /// 2. block.round == tc.round + 1 && block.qc.round >= tc.highest_hqc.round
    fn safe_to_vote(
        &self,
        block: &Block,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<(), Error> {
        let round = block.round();
        let qc_round = block.quorum_cert().certified_block().round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        let hqc_round = maybe_tc.map_or(0, |tc| tc.highest_hqc_round());
        if round == next_round(qc_round)?
            || (round == next_round(tc_round)? && qc_round >= hqc_round)
        {
            Ok(())
        } else {
            Err(Error::NotSafeToVote(round, qc_round, tc_round, hqc_round))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L180-188)
```rust
    fn verify_tc(&self, tc: &TwoChainTimeoutCertificate) -> Result<(), Error> {
        let epoch_state = self.epoch_state()?;

        if !self.skip_sig_verify {
            tc.verify(&epoch_state.verifier)
                .map_err(|e| Error::InvalidTimeoutCertificate(e.to_string()))?;
        }
        Ok(())
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L22-32)
```rust
/// This structure contains all the information necessary to construct a signature
/// on the equivalent of a AptosBFT v4 timeout message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TwoChainTimeout {
    /// Epoch number corresponds to the set of validators that are active for this round.
    epoch: u64,
    /// The consensus protocol executes proposals (blocks) in rounds, which monotonically increase per epoch.
    round: Round,
    /// The highest quorum cert the signer has seen.
    quorum_cert: QuorumCert,
}
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L141-183)
```rust
    pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
        let hqc_round = self.timeout.hqc_round();
        // Verify the highest timeout validity.
        let (timeout_result, sig_result) = rayon::join(
            || self.timeout.verify(validators),
            || {
                let timeout_messages: Vec<_> = self
                    .signatures_with_rounds
                    .get_voters_and_rounds(
                        &validators
                            .get_ordered_account_addresses_iter()
                            .collect_vec(),
                    )
                    .into_iter()
                    .map(|(_, round)| TimeoutSigningRepr {
                        epoch: self.timeout.epoch(),
                        round: self.timeout.round(),
                        hqc_round: round,
                    })
                    .collect();
                let timeout_messages_ref: Vec<_> = timeout_messages.iter().collect();
                validators.verify_aggregate_signatures(
                    &timeout_messages_ref,
                    self.signatures_with_rounds.sig(),
                )
            },
        );
        timeout_result?;
        sig_result?;
        let signed_hqc = self
            .signatures_with_rounds
            .rounds()
            .iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("Empty rounds"))?;
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
        Ok(())
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L414-417)
```rust
            highest_2chain_timeout_certificate: match highest_2chain_timeout_cert {
                Some(tc) if tc.epoch() == epoch => Some(tc),
                _ => None,
            },
```

**File:** consensus/src/block_storage/block_store.rs (L560-575)
```rust
    pub fn insert_2chain_timeout_certificate(
        &self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
        self.storage
            .save_highest_2chain_timeout_cert(tc.as_ref())
            .context("Timeout certificate insert failed when persisting to DB")?;
        self.inner.write().replace_2chain_timeout_cert(tc);
        Ok(())
    }
```
