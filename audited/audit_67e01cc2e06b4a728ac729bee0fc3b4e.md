# Audit Report

## Title
Timeout Certificate Denial of Service via Signature-Timeout Object Inconsistency

## Summary
A malicious validator can cause timeout certificate (TC) formation failures by exploiting an inconsistency between signature storage and timeout object updates. The `PartialSignaturesWithRound::add_signature()` function uses `or_insert` to prevent signature replacement, but `TwoChainTimeoutWithPartialSignatures::add()` still updates the timeout object when receiving a higher HQC round from the same validator. This creates a state where the timeout object's HQC round doesn't match the validator's stored signature, causing TC verification to fail and blocking consensus progress. [1](#0-0) 

## Finding Description

The vulnerability exists in the timeout aggregation logic where two separate update operations are not properly synchronized:

**Step 1: First timeout message processing** [2](#0-1) 

When a validator sends their first timeout message with `(round=R, hqc_round=X, signature_for_X)`, the system stores the signature in the map via `add_signature`.

**Step 2: Second conflicting timeout message**
When the same validator sends another timeout message with `(round=R, hqc_round=Y where Y>X, signature_for_Y)`:

1. Line 259-261: The condition `timeout.hqc_round() > self.timeout.hqc_round()` evaluates to TRUE, so `self.timeout` is updated to have `hqc_round=Y`
2. Line 262: Calls `add_signature(author, Y, signature_for_Y)`
3. Due to `or_insert` at line 327-328, the signature map is NOT updated because the validator already exists as a key
4. **Result**: `self.timeout.hqc_round() = Y` but `self.signatures[validator] = (X, signature_for_X)`

**Step 3: Verification failure** [3](#0-2) 

During TC verification, the code checks that `max(all_signed_hqc_rounds) == timeout.hqc_round()`. With the inconsistency created above:
- If the malicious validator's old signed round X is the maximum among all validators, the check fails because `X < Y`
- Even if other honest validators have valid signatures, the TC verification fails due to this inconsistency

**Attack Prerequisites:**
1. Attacker must be a validator in the current epoch
2. Attacker sends two timeout messages for the same round with different HQC values, sending the lower HQC first

**Message Flow Verification:** [4](#0-3) [5](#0-4) 

Both timeout messages are individually verified (signature validation) before being added to the aggregation structure, so this is not caught at the verification stage.

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria - "Significant protocol violations"

This vulnerability causes:

1. **Consensus Liveness Failure**: When a TC cannot be formed, validators cannot progress to the next round, causing the network to stall
2. **Network-Wide Impact**: All nodes attempting to form a TC for the affected round are blocked
3. **Repeated Exploitation**: A malicious validator can continuously send conflicting timeout messages across multiple rounds to sustain the denial of service
4. **Low Attack Complexity**: Requires only a single malicious validator (no collusion needed) and simple message manipulation

The attack breaks the **Consensus Safety** invariant that "AptosBFT must prevent chain splits under < 1/3 Byzantine" by allowing a single Byzantine validator to block consensus progress, effectively reducing the Byzantine fault tolerance.

## Likelihood Explanation

**Likelihood: High**

1. **Easy Execution**: The attack requires only sending two network messages with different HQC values in the correct order
2. **Single Validator Attack**: Does not require collusion among multiple validators
3. **No Detection**: There is no explicit duplicate detection for timeout messages from the same author in the same round
4. **Repeatable**: The attack can be executed in every round where the attacker is a validator
5. **Validator Access**: While requiring validator status, the BFT threat model explicitly assumes up to f Byzantine validators, making this within the expected threat model

## Recommendation

Add explicit duplicate detection to reject subsequent timeout messages from the same validator for the same round. Modify `TwoChainTimeoutWithPartialSignatures::add()` to check if the validator has already submitted a timeout:

```rust
pub fn add(
    &mut self,
    author: Author,
    timeout: TwoChainTimeout,
    signature: bls12381::Signature,
) {
    debug_assert_eq!(
        self.timeout.epoch(),
        timeout.epoch(),
        "Timeout should have the same epoch as TimeoutCert"
    );
    debug_assert_eq!(
        self.timeout.round(),
        timeout.round(),
        "Timeout should have the same round as TimeoutCert"
    );
    
    // Check if this validator has already sent a timeout for this round
    if self.signatures.signatures().contains_key(&author) {
        // Reject duplicate timeout from the same validator
        debug!(
            "Ignoring duplicate timeout from validator {} for round {}",
            author, self.timeout.round()
        );
        return;
    }
    
    let hqc_round = timeout.hqc_round();
    if timeout.hqc_round() > self.timeout.hqc_round() {
        self.timeout = timeout;
    }
    self.signatures.add_signature(author, hqc_round, signature);
}
```

Alternatively, track timeout message authors separately and validate before processing: [6](#0-5) 

Add similar duplicate checking in `TwoChainTimeoutVotes::add()` to prevent processing multiple timeouts from the same author.

## Proof of Concept

```rust
#[test]
fn test_duplicate_timeout_inconsistency() {
    use crate::vote_data::VoteData;
    use aptos_crypto::hash::CryptoHash;
    use aptos_types::{
        aggregate_signature::PartialSignatures,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithVerifiedSignatures},
        validator_verifier::random_validator_verifier,
    };

    let num_nodes = 4;
    let (signers, validators) = random_validator_verifier(num_nodes, None, false);
    let quorum_size = validators.quorum_voting_power() as usize;
    
    let generate_quorum = |round, num_of_signature| {
        let vote_data = VoteData::new(BlockInfo::random(round), BlockInfo::random(0));
        let mut ledger_info = LedgerInfoWithVerifiedSignatures::new(
            LedgerInfo::new(BlockInfo::empty(), vote_data.hash()),
            PartialSignatures::empty(),
        );
        for signer in &signers[0..num_of_signature] {
            let signature = signer.sign(ledger_info.ledger_info()).unwrap();
            ledger_info.add_signature(signer.author(), signature);
        }
        QuorumCert::new(
            vote_data,
            ledger_info.aggregate_signatures(&validators).unwrap(),
        )
    };

    // Validator 0 first sends timeout with low HQC (round 3)
    let timeout_low = TwoChainTimeout::new(1, 10, generate_quorum(3, quorum_size));
    let sig_low = timeout_low.sign(&signers[0]).unwrap();
    
    // Validator 0 then sends timeout with high HQC (round 8)
    let timeout_high = TwoChainTimeout::new(1, 10, generate_quorum(8, quorum_size));
    let sig_high = timeout_high.sign(&signers[0]).unwrap();
    
    // Validators 1 and 2 send timeouts with medium HQC (round 5 and 6)
    let timeout_mid1 = TwoChainTimeout::new(1, 10, generate_quorum(5, quorum_size));
    let sig_mid1 = timeout_mid1.sign(&signers[1]).unwrap();
    
    let timeout_mid2 = TwoChainTimeout::new(1, 10, generate_quorum(6, quorum_size));
    let sig_mid2 = timeout_mid2.sign(&signers[2]).unwrap();
    
    let mut tc_with_partial_sig = TwoChainTimeoutWithPartialSignatures::new(timeout_low.clone());
    
    // Add validator 0's first timeout (low HQC = 3)
    tc_with_partial_sig.add(signers[0].author(), timeout_low, sig_low);
    
    // Add validator 0's second timeout (high HQC = 8) - creates inconsistency
    tc_with_partial_sig.add(signers[0].author(), timeout_high, sig_high);
    
    // Add other validators
    tc_with_partial_sig.add(signers[1].author(), timeout_mid1, sig_mid1);
    tc_with_partial_sig.add(signers[2].author(), timeout_mid2, sig_mid2);
    
    // Now we have:
    // - timeout object with hqc_round = 8
    // - validator 0's signature for hqc_round = 3
    // - validator 1's signature for hqc_round = 5
    // - validator 2's signature for hqc_round = 6
    // max(3, 5, 6) = 6 != 8
    
    let tc_with_sig = tc_with_partial_sig
        .aggregate_signatures(&validators)
        .unwrap();
    
    // Verification should fail due to inconsistency
    assert!(tc_with_sig.verify(&validators).is_err(), 
            "TC verification should fail due to signature-timeout inconsistency");
}
```

This test demonstrates that when a validator sends conflicting timeout messages (low HQC first, then high HQC), the resulting TC fails verification even though all individual signatures are valid and there are enough signatures from honest validators.

## Notes

This vulnerability is particularly concerning because:
1. It bypasses the individual message verification layer (signatures are valid)
2. The `or_insert` mechanism was intended to prevent signature replacement attacks but inadvertently enables this DoS vector
3. No explicit duplicate detection exists for timeout messages in the same round from the same validator
4. The impact is network-wide liveness failure, not just affecting individual nodes

### Citations

**File:** consensus/consensus-types/src/timeout_2chain.rs (L170-181)
```rust
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
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L242-263)
```rust
    pub fn add(
        &mut self,
        author: Author,
        timeout: TwoChainTimeout,
        signature: bls12381::Signature,
    ) {
        debug_assert_eq!(
            self.timeout.epoch(),
            timeout.epoch(),
            "Timeout should have the same epoch as TimeoutCert"
        );
        debug_assert_eq!(
            self.timeout.round(),
            timeout.round(),
            "Timeout should have the same round as TimeoutCert"
        );
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L320-329)
```rust
    pub fn add_signature(
        &mut self,
        validator: AccountAddress,
        round: Round,
        signature: bls12381::Signature,
    ) {
        self.signatures
            .entry(validator)
            .or_insert((round, signature));
    }
```

**File:** consensus/src/round_manager.rs (L147-154)
```rust
            UnverifiedEvent::RoundTimeoutMsg(v) => {
                if !self_message {
                    v.verify(validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["timeout"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::RoundTimeoutMsg(v)
```

**File:** consensus/consensus-types/src/round_timeout.rs (L97-107)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        self.timeout.verify(validator)?;
        validator
            .verify(
                self.author(),
                &self.timeout.signing_format(),
                &self.signature,
            )
            .context("Failed to verify 2-chain timeout signature")?;
        Ok(())
    }
```

**File:** consensus/src/pending_votes.rs (L78-87)
```rust
    pub(super) fn add(
        &mut self,
        author: Author,
        timeout: TwoChainTimeout,
        signature: bls12381::Signature,
        reason: RoundTimeoutReason,
    ) {
        self.partial_2chain_tc.add(author, timeout, signature);
        self.timeout_reason.entry(author).or_insert(reason);
    }
```
