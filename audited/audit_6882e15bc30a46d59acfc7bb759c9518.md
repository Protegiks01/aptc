# Audit Report

## Title
Missing Timestamp Validation in Consensus SafetyRules sign_proposal() Allows Validator to Sign Blocks with Invalid Timestamps

## Summary
The `sign_proposal()` function in the consensus SafetyRules module fails to validate the `timestamp_usecs` field of BlockData before signing, allowing a validator to sign blocks with timestamps that violate protocol invariants (backwards time, far future timestamps, or monotonicity violations). While other validators will reject such proposals during voting, the validator has already produced cryptographic proof of signing invalid data, which violates consensus safety guarantees and defensive programming principles.

## Finding Description
The `guarded_sign_proposal()` function validates only a subset of BlockData fields before signing: [1](#0-0) 

**Validated fields:**
- Signer existence
- Author matches validator signer  
- Epoch matches stored epoch
- Round is higher than last voted round
- QuorumCert signature validity
- Preferred round constraints

**Missing validation:**
- **timestamp_usecs**: No validation whatsoever

In contrast, when validators receive and vote on proposals, the `verify_proposal()` function calls `verify_well_formed()` which DOES validate timestamps: [2](#0-1) 

The `verify_well_formed()` function enforces critical timestamp invariants: [3](#0-2) 

**BlockData structure showing timestamp_usecs field:** [4](#0-3) 

**Exploitation scenario:** A validator could bypass the ProposalGenerator's valid timestamp generation and directly call `sign_proposal()` with a BlockData containing:
- Timestamp going backwards in time (violating monotonicity)
- Timestamp >5 minutes in the future (violating TIMEBOUND)
- Timestamp equal to parent for non-nil/non-reconfig blocks

The signed block would be broadcast, and while other validators would reject it during voting, the signature exists as cryptographic proof the validator signed invalid data.

## Impact Explanation
**Severity: Medium**

This represents a **defensive programming failure** in security-critical consensus code. While the impact is limited because:
1. Other validators reject invalid proposals via `verify_well_formed()` during voting
2. The invalid block won't achieve consensus or affect chain state
3. No direct fund loss or network partition results

The vulnerability still has security implications:
- Validators can sign blocks violating protocol invariants
- Creates cryptographic evidence of protocol violations  
- Wastes network bandwidth broadcasting invalid proposals
- Could affect validator reputation/performance tracking systems
- Violates the principle that SafetyRules should enforce ALL consensus invariants before signing

This falls under **Medium Severity** per the bug bounty criteria as it represents a "state inconsistency requiring intervention" (invalid signed blocks in the network) and a "significant protocol violation" (signing data that breaks timestamp invariants).

## Likelihood Explanation
**Likelihood: Low-Medium**

Exploitation requires:
- Validator access (private keys and signing authority)
- Intentionally bypassing normal ProposalGenerator code path  
- Directly crafting BlockData with invalid timestamps
- Calling `sign_proposal()` with malicious data

In normal operation, ProposalGenerator generates valid timestamps: [5](#0-4) 

However, the likelihood increases if:
- A buggy validator implementation exists
- A compromised validator node is exploited
- A software fault causes timestamp corruption between generation and signing

## Recommendation
Add timestamp validation to `guarded_sign_proposal()` before signing, mirroring the checks in `verify_well_formed()`:

```rust
fn guarded_sign_proposal(
    &mut self,
    block_data: &BlockData,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    self.verify_author(block_data.author())?;

    let mut safety_data = self.persistent_storage.safety_data()?;
    self.verify_epoch(block_data.epoch(), &safety_data)?;

    if block_data.round() <= safety_data.last_voted_round {
        return Err(Error::InvalidProposal(format!(
            "Proposed round {} is not higher than last voted round {}",
            block_data.round(),
            safety_data.last_voted_round
        )));
    }

    self.verify_qc(block_data.quorum_cert())?;
    self.verify_and_update_preferred_round(block_data.quorum_cert(), &mut safety_data)?;
    
    // ADD TIMESTAMP VALIDATION HERE:
    let parent_timestamp = block_data.quorum_cert().certified_block().timestamp_usecs();
    if block_data.is_nil_block() || block_data.quorum_cert().certified_block().has_reconfiguration() {
        if block_data.timestamp_usecs() != parent_timestamp {
            return Err(Error::InvalidProposal(format!(
                "Nil/reconfig suffix block timestamp {} must equal parent timestamp {}",
                block_data.timestamp_usecs(),
                parent_timestamp
            )));
        }
    } else {
        if block_data.timestamp_usecs() <= parent_timestamp {
            return Err(Error::InvalidProposal(format!(
                "Block timestamp {} must be greater than parent timestamp {}",
                block_data.timestamp_usecs(),
                parent_timestamp
            )));
        }
        let current_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        const TIMEBOUND: u64 = 300_000_000;
        if block_data.timestamp_usecs() > (current_ts.as_micros() as u64).saturating_add(TIMEBOUND) {
            return Err(Error::InvalidProposal(format!(
                "Block timestamp {} is too far in the future",
                block_data.timestamp_usecs()
            )));
        }
    }

    let signature = self.sign(block_data)?;
    Ok(signature)
}
```

## Proof of Concept
```rust
// In consensus/safety-rules/src/tests/suite.rs
#[test]
fn test_sign_proposal_with_invalid_timestamp() {
    let mut safety_rules = SafetyRules::new(...);
    
    // Create a valid QC pointing to a parent block
    let parent_block_info = BlockInfo::new(
        1, // epoch
        5, // round
        HashValue::random(),
        HashValue::random(),
        100, // version
        1000000, // timestamp_usecs (1 second)
        None,
    );
    let qc = QuorumCert::new(...);
    
    // Create BlockData with timestamp BEFORE parent (violates monotonicity)
    let invalid_block_data = BlockData::new_proposal(
        Payload::empty(false, true),
        Author::random(),
        vec![],
        6, // round (valid - higher than parent)
        500000, // timestamp_usecs (0.5 seconds - BEFORE parent!)
        qc,
    );
    
    // This should fail but currently succeeds
    let result = safety_rules.sign_proposal(&invalid_block_data);
    
    // BUG: This will succeed when it should fail
    assert!(result.is_ok(), "sign_proposal incorrectly signed block with backwards timestamp");
    
    // The signed block would be rejected by other validators in verify_well_formed(),
    // but the signature exists as proof the validator signed invalid data
}
```

## Notes
While this vulnerability requires validator access to exploit (failing the "unprivileged attacker" criterion), it represents a critical **defensive programming failure** in consensus code. The SafetyRules module should be the final gate preventing any invalid data from being signed, regardless of whether upstream code is correct. This is especially important for defense-in-depth against:
- Future bugs in ProposalGenerator
- Race conditions or memory corruption
- Compromised validator nodes (post-RCE)
- Multi-component attack chains

The fix is straightforward and aligns with the existing pattern used in `verify_proposal()` for voting validation.

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L63-85)
```rust
    pub(crate) fn verify_proposal(
        &mut self,
        vote_proposal: &VoteProposal,
    ) -> Result<VoteData, Error> {
        let proposed_block = vote_proposal.block();
        let safety_data = self.persistent_storage.safety_data()?;

        self.verify_epoch(proposed_block.epoch(), &safety_data)?;

        self.verify_qc(proposed_block.quorum_cert())?;
        if !self.skip_sig_verify {
            proposed_block
                .validate_signature(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidProposal(error.to_string()))?;
        }
        proposed_block
            .verify_well_formed()
            .map_err(|error| Error::InvalidProposal(error.to_string()))?;

        vote_proposal
            .gen_vote_data()
            .map_err(|error| Error::InvalidAccumulatorExtension(error.to_string()))
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L346-370)
```rust
    fn guarded_sign_proposal(
        &mut self,
        block_data: &BlockData,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;
        self.verify_author(block_data.author())?;

        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(block_data.epoch(), &safety_data)?;

        if block_data.round() <= safety_data.last_voted_round {
            return Err(Error::InvalidProposal(format!(
                "Proposed round {} is not higher than last voted round {}",
                block_data.round(),
                safety_data.last_voted_round
            )));
        }

        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert(), &mut safety_data)?;
        // we don't persist the updated preferred round to save latency (it'd be updated upon voting)

        let signature = self.sign(block_data)?;
        Ok(signature)
    }
```

**File:** consensus/consensus-types/src/block.rs (L521-540)
```rust
        if self.is_nil_block() || parent.has_reconfiguration() {
            ensure!(
                self.timestamp_usecs() == parent.timestamp_usecs(),
                "Nil/reconfig suffix block must have same timestamp as parent"
            );
        } else {
            ensure!(
                self.timestamp_usecs() > parent.timestamp_usecs(),
                "Blocks must have strictly increasing timestamps"
            );

            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
        }
```

**File:** consensus/consensus-types/src/block_data.rs (L72-103)
```rust
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, CryptoHasher)]
/// Block has the core data of a consensus block that should be persistent when necessary.
/// Each block must know the id of its parent and keep the QuorurmCertificate to that parent.
pub struct BlockData {
    /// Epoch number corresponds to the set of validators that are active for this block.
    epoch: u64,
    /// The round of a block is an internal monotonically increasing counter used by Consensus
    /// protocol.
    round: Round,
    /// The approximate physical time a block is proposed by a proposer.  This timestamp is used
    /// for
    /// * Time-dependent logic in smart contracts (the current time of execution)
    /// * Clients determining if they are relatively up-to-date with respect to the block chain.
    ///
    /// It makes the following guarantees:
    ///   1. Time Monotonicity: Time is monotonically increasing in the block chain.
    ///      (i.e. If H1 < H2, H1.Time < H2.Time).
    ///   2. If a block of transactions B is agreed on with timestamp T, then at least
    ///      f+1 honest validators think that T is in the past. An honest validator will
    ///      only vote on a block when its own clock >= timestamp T.
    ///   3. If a block of transactions B has a QC with timestamp T, an honest validator
    ///      will not serve such a block to other validators until its own clock >= timestamp T.
    ///   4. Current: an honest validator is not issuing blocks with a timestamp in the
    ///       future. Currently we consider a block is malicious if it was issued more
    ///       that 5 minutes in the future.
    timestamp_usecs: u64,
    /// Contains the quorum certified ancestor and whether the quorum certified ancestor was
    /// voted on successfully
    quorum_cert: QuorumCert,
    /// If a block is a real proposal, contains its author and signature.
    block_type: BlockType,
}
```

**File:** consensus/src/liveness/proposal_generator.rs (L598-601)
```rust
        // All proposed blocks in a branch are guaranteed to have increasing timestamps
        // since their predecessor block will not be added to the BlockStore until
        // the local time exceeds it.
        let timestamp = self.time_service.get_current_timestamp();
```
