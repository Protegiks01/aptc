# Audit Report

## Title
Byzantine Validator Can Invalidate Timeout Certificates Through HQC Round Manipulation

## Summary
A Byzantine validator can exploit the `TwoChainTimeoutWithPartialSignatures::add()` function to create invalid timeout certificates by sending multiple timeout messages with incrementally higher HQC rounds. The function updates the timeout object to the highest HQC round but fails to update the validator's signature, creating an inconsistency that causes verification to fail and prevents consensus progress.

## Finding Description

The vulnerability exists in the signature aggregation logic for two-chain timeout certificates. When a Byzantine validator sends multiple timeout messages with different HQC (Highest Quorum Certificate) rounds, the system creates an inconsistent state that violates the timeout certificate verification invariant. [1](#0-0) 

The `add()` function performs two critical operations:
1. Updates `self.timeout` to use the timeout with the highest HQC round (lines 259-261)
2. Adds the validator's signature with `add_signature()` (line 262)

However, the `add_signature()` implementation uses `.or_insert()`, which only adds a signature if the validator doesn't already exist in the map: [2](#0-1) 

**Attack Scenario:**
1. Byzantine validator V1 sends a timeout message with HQC round 100, properly signed for `TimeoutSigningRepr {epoch, round, hqc_round: 100}`
2. Honest validators H1, H2 send timeout messages with HQC round 100
3. Before quorum is reached, V1 sends another timeout message with HQC round 200, properly signed for `TimeoutSigningRepr {epoch, round, hqc_round: 200}`
4. The `add()` function updates `self.timeout` to HQC round 200, but V1's signature remains associated with round 100
5. When quorum is reached and the timeout certificate is aggregated, it contains:
   - `timeout` object with HQC round 200
   - V1's signature associated with round 100

When this timeout certificate is verified, it fails the consistency check: [3](#0-2) 

The verification checks that `timeout.hqc_round()` equals the maximum of all signed HQC rounds. In the attack scenario:
- `hqc_round` = 200 (from the timeout object)
- `max(signed_hqc)` = 100 (highest signed round, if no honest validator has round 200)
- Check fails: 200 ≠ 100

The timeout certificate is inserted into the block store without verification: [4](#0-3) 

However, when validators attempt to use this timeout certificate (e.g., for voting on blocks or signing new timeouts), the verification fails: [5](#0-4) 

This prevents validators from making progress, causing a **total loss of liveness**.

## Impact Explanation

This vulnerability falls under **Critical Severity** per the Aptos bug bounty program, specifically:
- **Total loss of liveness/network availability** - The entire network cannot make progress when an invalid timeout certificate is created
- **Non-recoverable network partition (requires hardfork)** - Once an invalid TC is stored and propagated, validators cannot vote or sign timeouts, requiring manual intervention

The impact affects all honest validators in the network. A single Byzantine validator (representing less than 1/3 of voting power) can:
1. Prevent timeout certificate formation during consensus rounds
2. Force validators to be unable to vote on proposals or sign timeouts
3. Cause complete network stall until the invalid TC is manually removed

This breaks the fundamental liveness guarantee of AptosBFT consensus.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **Low Attack Complexity**: The Byzantine validator only needs to send two valid timeout messages with different HQC rounds - no cryptographic breaks or complex timing attacks required
2. **Realistic Scenario**: Network delays naturally occur during consensus, providing a window where the Byzantine validator can send the second timeout before quorum is reached
3. **No Special Privileges Required**: Any validator (even with minimal stake) can execute this attack
4. **Difficult to Detect**: The timeout messages are individually valid and properly signed, making the attack indistinguishable from normal network behavior until verification fails

The attack succeeds whenever:
- The Byzantine validator's second timeout arrives before enough honest signatures are collected to form a quorum
- No honest validator has an HQC round equal to or greater than the Byzantine validator's second HQC round

## Recommendation

Fix the `add_signature()` function to update the signature when the same validator sends a timeout with a different HQC round, or reject subsequent timeouts from the same validator:

**Option 1: Update the signature (recommended)**
```rust
pub fn add_signature(
    &mut self,
    validator: AccountAddress,
    round: Round,
    signature: bls12381::Signature,
) {
    // Always update the signature, even if validator already exists
    self.signatures.insert(validator, (round, signature));
}
```

**Option 2: Reject duplicate timeouts from the same validator**
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
    
    // Reject if validator already has a signature with different HQC round
    if let Some((existing_round, _)) = self.signatures.signatures().get(&author) {
        if *existing_round != timeout.hqc_round() {
            // Validator trying to change their HQC round - reject or log warning
            return;
        }
    }
    
    let hqc_round = timeout.hqc_round();
    if timeout.hqc_round() > self.timeout.hqc_round() {
        self.timeout = timeout;
    }
    self.signatures.add_signature(author, hqc_round, signature);
}
```

Additionally, add verification before inserting the timeout certificate into the block store:

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
    
    // Verify the TC before storing it
    tc.verify(&self.get_epoch_state().verifier)?;
    
    self.storage
        .save_highest_2chain_timeout_cert(tc.as_ref())
        .context("Timeout certificate insert failed when persisting to DB")?;
    self.inner.write().replace_2chain_timeout_cert(tc);
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_byzantine_hqc_round_manipulation() {
    use crate::{
        quorum_cert::QuorumCert,
        timeout_2chain::{TwoChainTimeout, TwoChainTimeoutWithPartialSignatures},
        vote_data::VoteData,
    };
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
    
    // Byzantine validator sends timeout with HQC round 1
    let timeout_round1 = TwoChainTimeout::new(1, 4, generate_quorum(1, quorum_size));
    let mut tc_with_partial_sig = TwoChainTimeoutWithPartialSignatures::new(timeout_round1.clone());
    
    // Add Byzantine validator's first timeout (HQC round 1)
    let byzantine_timeout_1 = timeout_round1.clone();
    let byzantine_sig_1 = byzantine_timeout_1.sign(&signers[0]).unwrap();
    tc_with_partial_sig.add(
        signers[0].author(),
        byzantine_timeout_1,
        byzantine_sig_1,
    );
    
    // Add honest validators
    let timeout_h1 = TwoChainTimeout::new(1, 4, generate_quorum(1, quorum_size));
    let sig_h1 = timeout_h1.sign(&signers[1]).unwrap();
    tc_with_partial_sig.add(signers[1].author(), timeout_h1, sig_h1);
    
    let timeout_h2 = TwoChainTimeout::new(1, 4, generate_quorum(1, quorum_size));
    let sig_h2 = timeout_h2.sign(&signers[2]).unwrap();
    tc_with_partial_sig.add(signers[2].author(), timeout_h2, sig_h2);
    
    // Byzantine validator sends another timeout with HQC round 100
    let timeout_round100 = TwoChainTimeout::new(1, 4, generate_quorum(100, quorum_size));
    let byzantine_sig_100 = timeout_round100.sign(&signers[0]).unwrap();
    tc_with_partial_sig.add(
        signers[0].author(),
        timeout_round100,
        byzantine_sig_100,
    );
    
    // Aggregate signatures
    let tc_with_sig = tc_with_partial_sig
        .aggregate_signatures(&validators)
        .unwrap();
    
    // Verification should fail because:
    // - timeout.hqc_round() = 100
    // - max(signed rounds) = max(1, 1, 1) = 1
    // - 100 != 1
    assert!(tc_with_sig.verify(&validators).is_err());
}
```

**Notes**

The vulnerability exploits a race condition in the signature aggregation logic where the timeout object and signatures become desynchronized. The fix should ensure that either:
1. Signatures are updated when validators send new timeouts with different HQC rounds, OR
2. Subsequent timeouts from the same validator with different HQC rounds are rejected

The current implementation's use of `.or_insert()` creates a dangerous inconsistency that Byzantine validators can weaponize to halt network progress. This is particularly severe because it affects liveness rather than safety - the network cannot recover without manual intervention to remove the invalid timeout certificate.

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
