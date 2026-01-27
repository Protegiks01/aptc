# Audit Report

## Title
Insufficient Block Info Validation in QuorumCert Merge Operation Enables State Inconsistency Amplification

## Summary
The `create_merged_with_executed_state()` function in `quorum_cert.rs` uses `match_ordered_only()` for validation, which only checks ordering-related fields (epoch, round, id, timestamp) but fails to validate critical execution state fields (executed_state_id, version, next_epoch_state). This incomplete validation can amplify state inconsistencies if Byzantine validators or execution bugs produce conflicting execution results. [1](#0-0) 

## Finding Description

The vulnerability lies in the validation logic at line 157. The `match_ordered_only()` method only compares:
- epoch
- round  
- id
- timestamp (with special handling for reconfiguration) [2](#0-1) 

It explicitly does NOT check:
- **executed_state_id**: Transaction accumulator hash (line 37)
- **version**: Ledger version number (line 39)
- **next_epoch_state**: Validator set for next epoch (line 43) [3](#0-2) 

**Attack Scenario:**

When `commit_callback()` merges a finality proof with a commit decision, if the commit decision contains a different execution state (due to non-deterministic execution or Byzantine behavior), the validation passes: [4](#0-3) 

This creates a QuorumCert with:
- Original vote_data (certified block at round N)
- Inconsistent signed_ledger_info (different executed_state_id, version, or next_epoch_state)

The function's verify() method checks consensus_data_hash but not the consistency between commit_info fields: [5](#0-4) 

## Impact Explanation

This qualifies as **HIGH severity** under Aptos bug bounty criteria:

1. **Consensus Safety Violation**: Different validators could commit different execution states for the same block, violating the "Deterministic Execution" invariant
2. **Validator Set Manipulation**: If `next_epoch_state` differs, nodes transition to different validator sets, causing network partition
3. **State Divergence**: Different `executed_state_id` values mean incompatible state roots, breaking state consistency

However, exploitation requires:
- Byzantine validators with quorum (2f+1) to sign conflicting states, OR
- Execution engine bugs causing non-deterministic results, OR  
- Storage corruption providing inconsistent ledger info

The vulnerability acts as an **amplifier** rather than a standalone exploit - it fails to catch inconsistencies that should be rejected.

## Likelihood Explanation

**Likelihood: MEDIUM-LOW**

While the validation bypass is trivial (matching ordering fields with different execution state), actual exploitation requires:

1. **Execution non-determinism**: Would need a separate bug in the Move VM or execution engine
2. **Byzantine quorum**: Requires 2f+1 malicious validators to sign incorrect execution states
3. **Network message manipulation**: Requires validator credentials to send malicious commit decisions

The function is called in trusted contexts (commit_callback, storage recovery), making direct external exploitation difficult. However, if any upstream bug produces inconsistent execution results, this function would fail to detect and reject them.

## Recommendation

Add comprehensive validation of ALL BlockInfo fields, not just ordering fields:

```rust
pub fn create_merged_with_executed_state(
    &self,
    executed_ledger_info: LedgerInfoWithSignatures,
) -> anyhow::Result<QuorumCert> {
    let self_commit_info = self.commit_info();
    let executed_commit_info = executed_ledger_info.ledger_info().commit_info();
    
    // Validate ordering fields
    ensure!(
        self_commit_info.match_ordered_only(executed_commit_info),
        "Block info from QC and executed LI need to match, {:?} and {:?}",
        self_commit_info,
        executed_commit_info
    );
    
    // NEW: If both have real execution state, validate it matches
    if !self_commit_info.is_ordered_only() && !executed_commit_info.is_ordered_only() {
        ensure!(
            self_commit_info.executed_state_id() == executed_commit_info.executed_state_id(),
            "Executed state ID mismatch: {:?} vs {:?}",
            self_commit_info.executed_state_id(),
            executed_commit_info.executed_state_id()
        );
        ensure!(
            self_commit_info.version() == executed_commit_info.version(),
            "Version mismatch: {} vs {}",
            self_commit_info.version(),
            executed_commit_info.version()
        );
        ensure!(
            self_commit_info.next_epoch_state() == executed_commit_info.next_epoch_state(),
            "Next epoch state mismatch"
        );
    }
    
    Ok(Self::new(self.vote_data.clone(), executed_ledger_info))
}
```

Apply the same fix to `WrappedLedgerInfo::create_merged_with_executed_state()`: [6](#0-5) 

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::block_info::BlockInfo;
    use aptos_crypto::{HashValue, hash::ACCUMULATOR_PLACEHOLDER_HASH};
    
    #[test]
    fn test_merge_inconsistent_execution_state() {
        // Create two BlockInfo with same ordering fields but different execution state
        let block_info_1 = BlockInfo::new(
            1,  // epoch
            10, // round
            HashValue::random(), // id - same in both
            HashValue::random(), // executed_state_id - DIFFERENT
            100, // version - DIFFERENT
            1000000, // timestamp
            None, // next_epoch_state
        );
        
        let block_id = block_info_1.id();
        
        let block_info_2 = BlockInfo::new(
            1,  // epoch - SAME
            10, // round - SAME
            block_id, // id - SAME
            HashValue::random(), // executed_state_id - DIFFERENT!
            200, // version - DIFFERENT!
            1000000, // timestamp - SAME
            None,
        );
        
        // match_ordered_only() passes despite execution state differences
        assert!(block_info_1.match_ordered_only(&block_info_2));
        
        // But the blocks represent different execution outcomes
        assert_ne!(block_info_1.executed_state_id(), block_info_2.executed_state_id());
        assert_ne!(block_info_1.version(), block_info_2.version());
        
        // This inconsistency would not be caught by create_merged_with_executed_state()
    }
}
```

## Notes

While this is technically a validation bypass, its exploitability depends on other system components being compromised. The vulnerability primarily represents a **defense-in-depth failure** - the function should validate all critical fields to prevent state inconsistencies even if they originate from bugs elsewhere in execution or consensus. This incomplete validation could allow consensus safety violations to propagate undetected when combined with execution non-determinism or Byzantine behavior.

### Citations

**File:** consensus/consensus-types/src/quorum_cert.rs (L119-148)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let vote_hash = self.vote_data.hash();
        ensure!(
            self.ledger_info().ledger_info().consensus_data_hash() == vote_hash,
            "Quorum Cert's hash mismatch LedgerInfo"
        );
        // Genesis's QC is implicitly agreed upon, it doesn't have real signatures.
        // If someone sends us a QC on a fake genesis, it'll fail to insert into BlockStore
        // because of the round constraint.
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
        }
        self.ledger_info()
            .verify_signatures(validator)
            .context("Fail to verify QuorumCert")?;
        self.vote_data.verify()?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L150-163)
```rust
    pub fn create_merged_with_executed_state(
        &self,
        executed_ledger_info: LedgerInfoWithSignatures,
    ) -> anyhow::Result<QuorumCert> {
        let self_commit_info = self.commit_info();
        let executed_commit_info = executed_ledger_info.ledger_info().commit_info();
        ensure!(
            self_commit_info.match_ordered_only(executed_commit_info),
            "Block info from QC and executed LI need to match, {:?} and {:?}",
            self_commit_info,
            executed_commit_info
        );
        Ok(Self::new(self.vote_data.clone(), executed_ledger_info))
    }
```

**File:** types/src/block_info.rs (L29-44)
```rust
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
}
```

**File:** types/src/block_info.rs (L196-204)
```rust
    pub fn match_ordered_only(&self, executed_block_info: &BlockInfo) -> bool {
        self.epoch == executed_block_info.epoch
            && self.round == executed_block_info.round
            && self.id == executed_block_info.id
            && (self.timestamp_usecs == executed_block_info.timestamp_usecs
            // executed block info has changed its timestamp because it's a reconfiguration suffix
                || (self.timestamp_usecs > executed_block_info.timestamp_usecs
                    && executed_block_info.has_reconfiguration()))
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L567-580)
```rust
    pub fn commit_callback(
        &mut self,
        storage: Arc<dyn PersistentLivenessStorage>,
        block_id: HashValue,
        block_round: Round,
        finality_proof: WrappedLedgerInfo,
        commit_decision: LedgerInfoWithSignatures,
        window_size: Option<u64>,
    ) {
        let current_round = self.commit_root().round();
        let committed_round = block_round;
        let commit_proof = finality_proof
            .create_merged_with_executed_state(commit_decision)
            .expect("Inconsistent commit proof and evaluation decision, cannot commit block");
```

**File:** consensus/consensus-types/src/wrapped_ledger_info.rs (L110-123)
```rust
    pub fn create_merged_with_executed_state(
        &self,
        executed_ledger_info: LedgerInfoWithSignatures,
    ) -> anyhow::Result<WrappedLedgerInfo> {
        let self_commit_info = self.commit_info();
        let executed_commit_info = executed_ledger_info.ledger_info().commit_info();
        ensure!(
            self_commit_info.match_ordered_only(executed_commit_info),
            "Block info from QC and executed LI need to match, {:?} and {:?}",
            self_commit_info,
            executed_commit_info
        );
        Ok(Self::new(self.vote_data.clone(), executed_ledger_info))
    }
```
