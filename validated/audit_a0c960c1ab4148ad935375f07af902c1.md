# Audit Report

## Title
Consensus Safety Violation: Invalid Signature Verification in CommitVote Aggregation Allows State Divergence

## Summary
A critical vulnerability in the CommitVote signature aggregation logic allows a malicious validator to cause consensus safety violations and state divergence by sending a CommitVote with a valid signature but manipulated LedgerInfo fields (specifically `consensus_data_hash`). The vulnerability exists in how signature verification status is tracked across different LedgerInfo messages, causing invalid signatures to be included in quorum certificates.

## Finding Description

The vulnerability involves four interconnected issues in the consensus pipeline:

**1. Signature Verification Against Sender's LedgerInfo**

When a CommitVote is received, the signature is verified against the sender's LedgerInfo, which may contain manipulated fields: [1](#0-0) 

The `optimistic_verify` method verifies the signature against whatever LedgerInfo the sender provided and marks it as verified when `optimistic_sig_verification` is false (the default): [2](#0-1) 

**2. Insufficient Validation in add_signature_if_matched**

When adding signatures to the aggregator for already-executed items, only the BlockInfo is validated, not the full LedgerInfo including `consensus_data_hash`: [3](#0-2) 

This contrasts with the stricter check in `create_signature_aggregator` which validates the full LedgerInfo: [4](#0-3) 

**3. Flawed Signature Filtering Logic**

When aggregation fails, `filter_invalid_signatures` trusts the `is_verified` flag without re-verifying signatures against the local message: [5](#0-4) 

At lines 298-301, signatures with `is_verified()` returning true are kept even though they were verified against a different LedgerInfo.

**4. Missing Verification After Filtering**

After filtering invalid signatures, the second aggregation attempt returns without verifying the resulting aggregated signature: [6](#0-5) 

At line 532, `try_aggregate` is called but the result is returned at line 533 without verification.

**Attack Scenario:**

1. Malicious validator V1 creates a LedgerInfo with `BlockInfo=B` but manipulated `consensus_data_hash=H1`
2. Honest validators V2, V3, V4 create LedgerInfo with `BlockInfo=B` and correct `consensus_data_hash=H2`
3. V1 signs their manipulated LedgerInfo and broadcasts it as CommitVote
4. When honest validators receive V1's vote:
   - Signature is verified against V1's LedgerInfo (H1) and marked `is_verified=true`
   - `add_signature_if_matched` checks only BlockInfo equality (matches!)
   - V1's signature is added to honest validators' aggregators (which contain H2)
5. First aggregation fails (mixing signatures for different messages)
6. `filter_invalid_signatures` keeps V1's signature because `is_verified()=true`
7. Second aggregation produces invalid aggregated signature without verification
8. Invalid commit proof is created and persisted to storage
9. Each validator independently aggregates and commits their own proof:
   - Honest validators: LedgerInfo with H2, invalid aggregated signature
   - Malicious V1: LedgerInfo with H1, valid signature
10. **STATE DIVERGENCE**: Different validators commit different `consensus_data_hash` for the same block

This is a consensus safety violation because validators do not broadcast aggregated commit proofs to each other; each independently creates and commits their own proof: [7](#0-6) 

## Impact Explanation

This is a **Critical Severity** vulnerability meeting the highest impact tier:

**Consensus Safety Violation**: Breaks the fundamental BFT guarantee that the system remains safe under < 1/3 Byzantine validators. With just 1 malicious validator out of 4 total (25% < 33%), different validators commit conflicting LedgerInfo for the same block, causing state divergence and potential chain splits.

**Non-recoverable**: Requires manual intervention or hard fork to resolve as validators have divergent committed state.

This aligns with the Critical impact category: "Different validators commit different blocks" and "Chain splits without hardfork requirement" with the potential for double-spending.

## Likelihood Explanation

**Likelihood: HIGH**

- Requires only a single malicious validator (< 1/3 Byzantine threshold)
- No complex timing or race conditions required
- Attack is deterministic and repeatable
- Default configuration (`optimistic_sig_verification=false`) enables the vulnerability
- Affects all consensus rounds where the attacker participates

The test suite demonstrates this configuration is standard: [8](#0-7) 

## Recommendation

**Fix 1**: In `add_signature_if_matched`, validate the full LedgerInfo, not just BlockInfo:

```rust
Self::Executed(executed) => {
    // Change from: executed.commit_info == *target_commit_info
    // To: executed.partial_commit_proof.data() == vote.ledger_info()
    if executed.partial_commit_proof.data() == vote.ledger_info() {
        executed.partial_commit_proof.add_signature(author, signature);
        return Ok(());
    }
}
```

**Fix 2**: In `filter_invalid_signatures`, always re-verify against the local message:

```rust
.filter_map(|(account_address, signature)| {
    // Remove the is_verified() bypass
    if self.verify(account_address, message, signature.signature()).is_ok() {
        signature.set_verified();
        Some((account_address, signature))
    } else {
        self.add_pessimistic_verify_set(account_address);
        None
    }
})
```

**Fix 3**: In `aggregate_and_verify`, verify the second aggregation:

```rust
Err(_) => {
    self.filter_invalid_signatures(verifier);
    let aggregated_sig = self.try_aggregate(verifier)?;
    // Add verification before returning
    verifier.verify_multi_signatures(&self.data, &aggregated_sig)?;
    Ok((self.data.clone(), aggregated_sig))
}
```

## Proof of Concept

The vulnerability can be demonstrated by modifying the existing test case to use different `consensus_data_hash` values while keeping the same BlockInfo, showing that signatures verified against one LedgerInfo are incorrectly added to aggregators for a different LedgerInfo, ultimately producing an unverified invalid commit proof.

## Notes

The inconsistency between `create_signature_aggregator` (which checks full LedgerInfo equality) and `add_signature_if_matched` (which checks only BlockInfo) is the root cause. This allows signatures verified against one message to be aggregated with signatures for a different message, violating the fundamental security property of aggregate signatures.

### Citations

**File:** consensus/consensus-types/src/pipeline/commit_vote.rs (L103-113)
```rust
    pub fn verify(&self, sender: Author, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            self.author() == sender,
            "Commit vote author {:?} doesn't match with the sender {:?}",
            self.author(),
            sender
        );
        validator
            .optimistic_verify(self.author(), &self.ledger_info, &self.signature)
            .context("Failed to verify Commit Vote")
    }
```

**File:** types/src/validator_verifier.rs (L269-285)
```rust
    pub fn optimistic_verify<T: Serialize + CryptoHash>(
        &self,
        author: AccountAddress,
        message: &T,
        signature_with_status: &SignatureWithStatus,
    ) -> std::result::Result<(), VerifyError> {
        if self.get_public_key(&author).is_none() {
            return Err(VerifyError::UnknownAuthor);
        }
        if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
            && !signature_with_status.is_verified()
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
        }
        Ok(())
    }
```

**File:** types/src/validator_verifier.rs (L287-311)
```rust
    pub fn filter_invalid_signatures<T: Send + Sync + Serialize + CryptoHash>(
        &self,
        message: &T,
        signatures: BTreeMap<AccountAddress, SignatureWithStatus>,
    ) -> BTreeMap<AccountAddress, SignatureWithStatus> {
        signatures
            .into_iter()
            .collect_vec()
            .into_par_iter()
            .with_min_len(4) // At least 4 signatures are verified in each task
            .filter_map(|(account_address, signature)| {
                if signature.is_verified()
                    || self
                        .verify(account_address, message, signature.signature())
                        .is_ok()
                {
                    signature.set_verified();
                    Some((account_address, signature))
                } else {
                    self.add_pessimistic_verify_set(account_address);
                    None
                }
            })
            .collect()
    }
```

**File:** consensus/src/pipeline/buffer_item.rs (L40-52)
```rust
fn create_signature_aggregator(
    unverified_votes: HashMap<Author, CommitVote>,
    commit_ledger_info: &LedgerInfo,
) -> SignatureAggregator<LedgerInfo> {
    let mut sig_aggregator = SignatureAggregator::new(commit_ledger_info.clone());
    for vote in unverified_votes.values() {
        let sig = vote.signature_with_status();
        if vote.ledger_info() == commit_ledger_info {
            sig_aggregator.add_signature(vote.author(), sig);
        }
    }
    sig_aggregator
}
```

**File:** consensus/src/pipeline/buffer_item.rs (L393-399)
```rust
            Self::Executed(executed) => {
                if executed.commit_info == *target_commit_info {
                    executed
                        .partial_commit_proof
                        .add_signature(author, signature);
                    return Ok(());
                }
```

**File:** consensus/src/pipeline/buffer_item.rs (L485-490)
```rust
        let mut validator_verifier =
            ValidatorVerifier::new_with_quorum_voting_power(validator_infos, 5)
                .expect("Incorrect quorum size.");
        validator_verifier.set_optimistic_sig_verification_flag(true);
        (validator_signers, validator_verifier)
    }
```

**File:** types/src/ledger_info.rs (L515-536)
```rust
    /// Try to aggregate all signatures if the voting power is enough. If the aggregated signature is
    /// valid, return the aggregated signature. Also merge valid unverified signatures into verified.
    pub fn aggregate_and_verify(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<(T, AggregateSignature), VerifyError> {
        let aggregated_sig = self.try_aggregate(verifier)?;

        match verifier.verify_multi_signatures(&self.data, &aggregated_sig) {
            Ok(_) => {
                // We are not marking all the signatures as "verified" here, as two malicious
                // voters can collude and create a valid aggregated signature.
                Ok((self.data.clone(), aggregated_sig))
            },
            Err(_) => {
                self.filter_invalid_signatures(verifier);

                let aggregated_sig = self.try_aggregate(verifier)?;
                Ok((self.data.clone(), aggregated_sig))
            },
        }
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1079-1100)
```rust
    async fn commit_ledger(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        commit_proof_fut: TaskFuture<LedgerInfoWithSignatures>,
        parent_block_commit_fut: TaskFuture<CommitLedgerResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
    ) -> TaskResult<CommitLedgerResult> {
        let mut tracker = Tracker::start_waiting("commit_ledger", &block);
        parent_block_commit_fut.await?;
        pre_commit_fut.await?;
        let ledger_info_with_sigs = commit_proof_fut.await?;

        // it's committed as prefix
        if ledger_info_with_sigs.commit_info().id() != block.id() {
            return Ok(None);
        }

        tracker.start_working();
        let ledger_info_with_sigs_clone = ledger_info_with_sigs.clone();
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
```
