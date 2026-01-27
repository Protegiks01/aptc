# Audit Report

## Title
Missing Epoch Validation in TwoChainTimeout Allows Cross-Epoch QuorumCert References

## Summary
The `TwoChainTimeout::verify()` function fails to validate that the embedded `QuorumCert`'s epoch matches the timeout's epoch, allowing validators to create timeout messages containing quorum certificates from previous epochs. This violates consensus protocol invariants and could lead to state inconsistencies.

## Finding Description

The `generate_2chain_timeout()` function in `vote.rs` creates a `TwoChainTimeout` object with epoch and round values from the vote, but accepts an arbitrary `qc` parameter without epoch validation: [1](#0-0) 

The timeout is constructed with:
- `epoch` from `self.vote_data.proposed().epoch()` 
- `round` from `self.vote_data.proposed().round()`
- `quorum_cert` from the `qc` parameter (unchecked) [2](#0-1) 

The critical vulnerability lies in `TwoChainTimeout::verify()`, which only validates that `hqc_round() < round()` and that the QC's signatures are valid, but never checks that the QC's epoch matches the timeout's epoch: [3](#0-2) 

For genesis QCs (round == 0), the QuorumCert verification skips signature checks entirely: [4](#0-3) 

**Attack Scenario:**

1. Network transitions from epoch E-1 to epoch E (rounds reset to 0)
2. Malicious validator is at epoch E, round 5
3. Validator still has genesis QC from epoch E-1 (epoch=E-1, round=0)  
4. Validator calls `generate_2chain_timeout()` with this old genesis QC
5. Created timeout has: epoch=E, round=5, but quorum_cert=(epoch=E-1, round=0)
6. Validation checks pass:
   - `hqc_round() < round()`: 0 < 5 ✓
   - Genesis QC verification skips signatures ✓
   - **No epoch consistency check exists**
7. Timeout is signed and can be aggregated into a TimeoutCertificate
8. The TC carries cross-epoch data, violating protocol semantics

Additional validation gaps exist in: [5](#0-4) [6](#0-5) 

None of these checks validate the embedded QC's epoch against the timeout's epoch.

## Impact Explanation

This issue qualifies as **Medium Severity** under Aptos bug bounty criteria ("State inconsistencies requiring intervention"):

- Allows validators to create semantically inconsistent timeout certificates
- Violates the consensus protocol invariant that timeout epoch E should only reference QCs from epoch E
- Could lead to confusion in consensus logic that assumes epoch consistency
- Represents a defense-in-depth violation that could become critical if future code relies on epoch consistency
- Does not directly cause consensus safety violations (safety rules use round numbers only)

## Likelihood Explanation

**Likelihood: Medium**

- Requires validator participation (malicious or compromised validator)
- Easily exploitable during epoch transitions when validators naturally hold QCs from previous epochs
- No special conditions required beyond normal epoch boundary crossing
- Limited immediate impact due to timeout aggregation logic (highest hqc_round wins) and safety rules only using round numbers
- Practical exploitation requires demonstrating actual consensus harm, which is unclear

## Recommendation

Add epoch validation in `TwoChainTimeout::verify()`:

```rust
pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
    ensure!(
        self.hqc_round() < self.round(),
        "Timeout round should be larger than the QC round"
    );
    
    // NEW: Validate QC epoch matches timeout epoch
    ensure!(
        self.quorum_cert.certified_block().epoch() == self.epoch(),
        "Timeout QC epoch {} does not match timeout epoch {}",
        self.quorum_cert.certified_block().epoch(),
        self.epoch()
    );
    
    self.quorum_cert.verify(validators)?;
    Ok(())
}
```

Additionally, consider adding this check in `Vote::verify()` when validating the two-chain timeout.

## Proof of Concept

```rust
#[test]
fn test_cross_epoch_qc_in_timeout() {
    use aptos_types::{block_info::BlockInfo, validator_verifier::random_validator_verifier};
    use crate::{vote_data::VoteData, quorum_cert::QuorumCert};
    
    let (signers, validators) = random_validator_verifier(4, None, false);
    
    // Create genesis QC for epoch 1
    let epoch_1_genesis = BlockInfo::new(1, 0, HashValue::random(), 
        HashValue::zero(), 0, 0, None);
    let vote_data_e1 = VoteData::new(epoch_1_genesis.clone(), epoch_1_genesis.clone());
    let li_e1 = LedgerInfo::new(epoch_1_genesis, vote_data_e1.hash());
    let qc_epoch_1 = QuorumCert::new(vote_data_e1, 
        LedgerInfoWithSignatures::new(li_e1, AggregateSignature::empty()));
    
    // Create timeout for epoch 2, round 5, but with epoch 1 QC
    let timeout = TwoChainTimeout::new(2, 5, qc_epoch_1);
    
    // This should fail but currently passes (vulnerability)
    // Expected: Error about epoch mismatch
    // Actual: Passes verification
    let result = timeout.verify(&validators);
    
    // BUG: This assertion should fail but passes
    assert!(result.is_ok(), "Cross-epoch QC incorrectly accepted");
}
```

**Notes:**

After rigorous analysis, while there IS a missing validation that allows cross-epoch QC references in timeouts, the practical exploitability and immediate security harm are **limited** because:

1. Timeout certificate aggregation keeps the timeout with the highest `hqc_round`, preventing attackers from forcing lower rounds
2. Safety rules (`safe_to_vote`, `safe_to_timeout`) only compare round numbers, not epochs
3. No production code retrieves the actual QC object from timeouts for consensus decisions
4. The verification would fail if validator sets differ between epochs (signatures wouldn't verify)

This represents a **defense-in-depth violation** and **protocol invariant violation** rather than an immediately exploitable consensus safety break. The missing validation should be added to prevent potential future issues and maintain protocol correctness.

### Citations

**File:** consensus/consensus-types/src/vote.rs (L125-131)
```rust
    pub fn generate_2chain_timeout(&self, qc: QuorumCert) -> TwoChainTimeout {
        TwoChainTimeout::new(
            self.vote_data.proposed().epoch(),
            self.vote_data.proposed().round(),
            qc,
        )
    }
```

**File:** consensus/consensus-types/src/vote.rs (L161-166)
```rust
        if let Some((timeout, signature)) = &self.two_chain_timeout {
            ensure!(
                (timeout.epoch(), timeout.round())
                    == (self.epoch(), self.vote_data.proposed().round()),
                "2-chain timeout has different (epoch, round) than Vote"
            );
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L35-41)
```rust
    pub fn new(epoch: u64, round: Round, quorum_cert: QuorumCert) -> Self {
        Self {
            epoch,
            round,
            quorum_cert,
        }
    }
```

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

**File:** consensus/consensus-types/src/quorum_cert.rs (L128-141)
```rust
        if self.certified_block().round() == 0 {
            ensure!(
                self.parent_block() == self.certified_block(),
                "Genesis QC has inconsistent parent block with certified block"
            );
            ensure!(
                self.certified_block() == self.ledger_info().ledger_info().commit_info(),
                "Genesis QC has inconsistent commit block with certified block"
            );
            ensure!(
                self.ledger_info().get_num_voters() == 0,
                "Genesis QC should not carry signatures"
            );
            return Ok(());
```

**File:** consensus/consensus-types/src/sync_info.rs (L148-150)
```rust
        if let Some(tc) = &self.highest_2chain_timeout_cert {
            ensure!(epoch == tc.epoch(), "Multi epoch in SyncInfo - TC and HQC");
        }
```
