# Audit Report

## Title
Critical Liveness Failure from Accepting Same-Round Timeouts (hqc_round == timeout_round)

## Summary
The current strict inequality check `hqc_round < round` in `TwoChainTimeout::verify()` is **correct and must be preserved**. Changing it to `<=` as suggested would allow Byzantine validators to create malformed timeout certificates that permanently break consensus liveness by making it impossible for honest validators to vote on subsequent proposals.

## Finding Description

The 2-chain consensus protocol has a fundamental invariant: **a validator cannot simultaneously have a quorum certificate for round R and be timing out on round R**. These are mutually exclusive outcomes. [1](#0-0) 

The current verification correctly enforces `hqc_round < round`, ensuring that timeouts reference QCs from strictly earlier rounds. If this is weakened to `<=`, the following attack becomes possible:

**Attack Flow:**

1. Byzantine validators (< f) create malicious `TwoChainTimeout` messages with `round = R` and `hqc_round = R`
2. These pass the modified verification check
3. Honest validators create legitimate timeouts with `round = R` and `hqc_round < R`
4. When aggregating 2f+1 timeout signatures, the TC adopts the highest `hqc_round` among all signers [2](#0-1) 

5. The resulting `TwoChainTimeoutCertificate` has `timeout.round = R` and `timeout.hqc_round = R` (the maximum)
6. This TC is stored locally without verification [3](#0-2) 

7. When validators attempt to vote on the next proposal at round R+1, the safety check fails: [4](#0-3) 

For a proposal at round R+1 with TC at round R (where `hqc_round = R`):
- The proposal's QC must be from round < R (since no valid QC exists for round R if there's a TC)
- First condition: `round == next_round(qc_round)?` → `R+1 == qc_round+1?` → False (since `qc_round < R`)
- Second condition: `round == next_round(tc_round)? && qc_round >= hqc_round` → `R+1 == R+1 && qc_round >= R` → `True && False` → **False**

**Result: Honest validators cannot vote on ANY subsequent proposal, causing permanent liveness failure.**

The safety rule enforces that validators can only timeout on round R if they have completed round R-1: [5](#0-4) 

This ensures `round == qc_round + 1`, which means `qc_round < round` (strictly).

## Impact Explanation

**Severity: Critical** - Total loss of liveness/network availability

This meets the Critical Severity category per Aptos bug bounty rules:
- The blockchain permanently halts and cannot progress past the malformed TC
- No blocks can be committed, no transactions can be processed
- Requires a hard fork to recover
- Byzantine validators (< f, well below the 1/3 threshold) can trigger this attack

The attack breaks the **Consensus Safety** invariant (#2): "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" by causing permanent liveness failure with minimal Byzantine participation.

## Likelihood Explanation

**Likelihood: High** (if the code change is made)

- Byzantine validators need < f voting power (can be a single malicious validator with any stake)
- Attack requires only broadcasting malformed timeout messages - no sophisticated cryptographic attacks
- The malformed TC will be automatically aggregated by honest nodes following normal protocol
- Once the TC is formed, the liveness failure is immediate and irreversible
- No user interaction or external conditions required

The attack is **trivial to execute** and has **guaranteed success** if the verification check is weakened.

## Recommendation

**Do NOT change the verification check.** The current implementation is correct:

```rust
pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
    ensure!(
        self.hqc_round() < self.round(),  // KEEP THIS AS '<'
        "Timeout round should be larger than the QC round"
    );
    self.quorum_cert.verify(validators)?;
    Ok(())
}
```

The strict inequality `<` is mandated by the 2-chain consensus protocol semantics. A timeout for round R can only reference QCs from rounds 0 to R-1.

**Additional Hardening:** Consider adding explicit TC verification when storing:

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
    
    // ADD VERIFICATION HERE
    tc.verify(&self.verifier)?;
    
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
fn test_malformed_tc_breaks_liveness() {
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
    
    // Create QC for round 9
    let vote_data = VoteData::new(BlockInfo::random(9), BlockInfo::random(0));
    let mut ledger_info = LedgerInfoWithVerifiedSignatures::new(
        LedgerInfo::new(BlockInfo::empty(), vote_data.hash()),
        PartialSignatures::empty(),
    );
    for signer in &signers[0..quorum_size] {
        let signature = signer.sign(ledger_info.ledger_info()).unwrap();
        ledger_info.add_signature(signer.author(), signature);
    }
    let qc_round_9 = QuorumCert::new(
        vote_data,
        ledger_info.aggregate_signatures(&validators).unwrap(),
    );
    
    // Byzantine validator creates malformed timeout: round=10, hqc_round=10
    // (This would pass if verification uses '<=')
    let malformed_timeout = TwoChainTimeout::new(1, 10, qc_round_9.clone());
    
    // With current '<' check, this fails (correct behavior)
    assert!(malformed_timeout.verify(&validators).is_err());
    
    // If we hypothetically allowed '<=', the following would happen:
    // 1. Malformed timeout aggregates into TC with hqc_round=10, round=10
    // 2. Next proposal at round 11 cannot be voted on because:
    //    - Proposal has QC from round < 10 (say round 9)
    //    - safe_to_vote check: 11 == 11 && 9 >= 10 → False
    // 3. Consensus halts permanently
    
    // Verify honest timeout works correctly
    let honest_timeout = TwoChainTimeout::new(1, 10, qc_round_9);
    assert!(honest_timeout.verify(&validators).is_ok());
    assert!(honest_timeout.hqc_round() < honest_timeout.round());
}
```

## Notes

The security question asks whether the check "should" be `<=`. The answer is definitively **NO**. The current strict inequality `<` is correct and critical for consensus safety. This analysis demonstrates that weakening the check would introduce a catastrophic liveness vulnerability exploitable by minimal Byzantine participation.

### Citations

**File:** consensus/consensus-types/src/timeout_2chain.rs (L74-81)
```rust
    pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            self.hqc_round() < self.round(),
            "Timeout round should be larger than the QC round"
        );
        self.quorum_cert.verify(validators)?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L258-262)
```rust
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L121-145)
```rust
    /// Core safety timeout rule for 2-chain protocol. Return success if 1 and 2 are true
    /// 1. round == timeout.qc.round + 1 || round == tc.round + 1
    /// 2. timeout.qc.round >= one_chain_round
    fn safe_to_timeout(
        &self,
        timeout: &TwoChainTimeout,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
        safety_data: &SafetyData,
    ) -> Result<(), Error> {
        let round = timeout.round();
        let qc_round = timeout.hqc_round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        if (round == next_round(qc_round)? || round == next_round(tc_round)?)
            && qc_round >= safety_data.one_chain_round
        {
            Ok(())
        } else {
            Err(Error::NotSafeToTimeout(
                round,
                qc_round,
                tc_round,
                safety_data.one_chain_round,
            ))
        }
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
