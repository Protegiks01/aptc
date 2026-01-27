# Audit Report

## Title
NIL Block State Inconsistency in OrderVoteProposal Lacks Validation

## Summary
The `OrderVoteProposal` constructor lacks validation to ensure that NIL blocks (blocks with no transactions) cannot claim non-zero state changes in their `block_info`. While safety rules validate QC consistency, there is no check enforcing the invariant that NIL blocks must preserve their parent's state unchanged, creating a potential vector for consensus confusion if Byzantine validators sign malicious block information.

## Finding Description

The vulnerability exists in the validation gap between block type and block information consistency. [1](#0-0) 

The constructor accepts any combination of `Block`, `BlockInfo`, and `QuorumCert` without validating their semantic consistency. Specifically, it does not verify that if `block.is_nil_block()` returns true, the `block_info` must reflect no state changes. [2](#0-1) 

NIL blocks are defined as having no payload and are used to advance rounds without transactions: [3](#0-2) 

The safety rules validation only checks QC-to-BlockInfo consistency and ID matching: [4](#0-3) 

However, it does not validate that for NIL blocks, the BlockInfo must preserve the parent's `version` and `executed_state_id`. The version validation in `VoteData::verify()` allows any increase: [5](#0-4) 

This permits NIL blocks to claim version increments despite having no transactions. While the test suite demonstrates the correct behavior (NIL blocks should inherit parent state): [6](#0-5) 

This invariant is not enforced in production code.

## Impact Explanation

**Severity: Medium** 

This issue creates state inconsistencies requiring manual intervention. If Byzantine validators (within the <1/3 threshold) sign a QC for a malicious BlockInfo claiming state changes for a NIL block, honest validators processing this OrderVoteProposal would:

1. Accept it through safety rules (QC validation passes)
2. Create ledger records with incorrect state information
3. Potentially diverge in their view of blockchain state [7](#0-6) 

The LedgerInfo created from the malicious `block_info` would be signed and propagated, causing confusion about whether the NIL block executed transactions or not. This violates the **Deterministic Execution** invariant (validators must produce identical state roots for identical blocks) since the NIL block has no transactions but claims state changes.

## Likelihood Explanation

**Likelihood: Low-Medium**

Exploitation requires:
1. Byzantine validators (< 1/3 of stake) to collude
2. These validators must sign a QC for a BlockInfo with incorrect state for a NIL block
3. The malicious OrderVoteProposal must be broadcast to honest validators

While this requires Byzantine behavior, it's within the fault tolerance model (< 1/3 Byzantine). The lack of validation creates an attack surface that shouldn't exist - honest code should reject semantically invalid proposals regardless of QC signatures.

## Recommendation

Add validation in `OrderVoteProposal::new()` or in `verify_order_vote_proposal()` to enforce the NIL block invariant:

```rust
// In OrderVoteProposal::new() or as a separate validate() method
pub fn new(block: Block, block_info: BlockInfo, quorum_cert: Arc<QuorumCert>) -> Result<Self, Error> {
    // Validate NIL block invariant
    if block.is_nil_block() {
        let parent_block_info = quorum_cert.certified_block();
        anyhow::ensure!(
            block_info.version() == parent_block_info.version(),
            "NIL block must preserve parent version: expected {}, got {}",
            parent_block_info.version(),
            block_info.version()
        );
        anyhow::ensure!(
            block_info.executed_state_id() == parent_block_info.executed_state_id(),
            "NIL block must preserve parent executed_state_id"
        );
    }
    
    Ok(Self {
        block,
        block_info,
        quorum_cert,
    })
}
```

Alternatively, add this check in `SafetyRules::verify_order_vote_proposal()`: [8](#0-7) 

Add before line 109:
```rust
// Validate NIL blocks don't claim state changes
if proposed_block.is_nil_block() {
    let parent = qc.certified_block();
    if order_vote_proposal.block_info().version() != parent.version() ||
       order_vote_proposal.block_info().executed_state_id() != parent.executed_state_id() {
        return Err(Error::InvalidNilBlockState);
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_malicious_nil_block_order_vote_proposal() {
    use consensus_types::{block::Block, order_vote_proposal::OrderVoteProposal};
    use aptos_types::block_info::BlockInfo;
    
    // Create a NIL block
    let genesis_qc = certificate_for_genesis();
    let nil_block = Block::new_nil(1, genesis_qc.clone(), vec![]);
    
    // Create malicious BlockInfo claiming state changes
    let parent_info = genesis_qc.certified_block();
    let malicious_block_info = BlockInfo::new(
        nil_block.epoch(),
        nil_block.round(),
        nil_block.id(),
        HashValue::random(), // Different from parent - claims state change!
        parent_info.version() + 10, // Claims version increment!
        nil_block.timestamp_usecs(),
        None,
    );
    
    // This should fail but doesn't - no validation!
    let malicious_proposal = OrderVoteProposal::new(
        nil_block.clone(),
        malicious_block_info.clone(),
        Arc::new(genesis_qc.clone()),
    );
    
    // Verify the NIL block has no transactions
    assert!(nil_block.payload().is_none());
    assert!(nil_block.is_nil_block());
    
    // But BlockInfo claims state changes
    assert_ne!(malicious_block_info.version(), parent_info.version());
    assert_ne!(malicious_block_info.executed_state_id(), parent_info.executed_state_id());
    
    // This semantic inconsistency is not caught
}
```

## Notes

The legitimate execution flow uses `StateComputeResult::new_dummy()` with version=0 and `ACCUMULATOR_PLACEHOLDER_HASH` as markers for "not yet executed" blocks: [9](#0-8) [10](#0-9) 

The system is designed with decoupled execution where blocks are ordered first (with dummy values) then executed later. However, this design doesn't excuse the lack of semantic validation for NIL blocks - even with dummy values, a NIL block's BlockInfo should never claim state changes relative to its parent when used in consensus voting.

### Citations

**File:** consensus/consensus-types/src/order_vote_proposal.rs (L24-31)
```rust
impl OrderVoteProposal {
    pub fn new(block: Block, block_info: BlockInfo, quorum_cert: Arc<QuorumCert>) -> Self {
        Self {
            block,
            block_info,
            quorum_cert,
        }
    }
```

**File:** consensus/consensus-types/src/block_data.rs (L40-45)
```rust
    NilBlock {
        /// Failed authors from the parent's block to this block (including this block)
        /// I.e. the list of consecutive proposers from the
        /// immediately preceeding rounds that didn't produce a successful block.
        failed_authors: Vec<(Round, Author)>,
    },
```

**File:** consensus/consensus-types/src/block_data.rs (L215-217)
```rust
    pub fn is_nil_block(&self) -> bool {
        matches!(self.block_type, BlockType::NilBlock { .. })
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L87-111)
```rust
    pub(crate) fn verify_order_vote_proposal(
        &mut self,
        order_vote_proposal: &OrderVoteProposal,
    ) -> Result<(), Error> {
        let proposed_block = order_vote_proposal.block();
        let safety_data = self.persistent_storage.safety_data()?;

        self.verify_epoch(proposed_block.epoch(), &safety_data)?;

        let qc = order_vote_proposal.quorum_cert();
        if qc.certified_block() != order_vote_proposal.block_info() {
            return Err(Error::InvalidOneChainQuorumCertificate(
                qc.certified_block().id(),
                order_vote_proposal.block_info().id(),
            ));
        }
        if qc.certified_block().id() != proposed_block.id() {
            return Err(Error::InvalidOneChainQuorumCertificate(
                qc.certified_block().id(),
                proposed_block.id(),
            ));
        }
        self.verify_qc(qc)?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/vote_data.rs (L72-78)
```rust
        anyhow::ensure!(
            // if decoupled execution is turned on, the versions are dummy values (0),
            // but the genesis block per epoch uses the ground truth version number,
            // so we bypass the version check here.
            self.proposed.version() == 0 || self.parent.version() <= self.proposed.version(),
            "Proposed version is less than parent version",
        );
```

**File:** consensus/consensus-types/src/block_test.rs (L60-64)
```rust
        nil_block.gen_block_info(
            parent_block_info.executed_state_id(),
            parent_block_info.version(),
            parent_block_info.next_epoch_state().cloned(),
        ),
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L113-114)
```rust
        let ledger_info =
            LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L394-398)
```rust
    pub fn new_ordered(block: Block, window: OrderedBlockWindow) -> Self {
        let input_transactions = Vec::new();
        let state_compute_result = StateComputeResult::new_dummy();
        Self::new(block, input_transactions, state_compute_result).with_block_window(window)
    }
```

**File:** execution/executor-types/src/state_compute_result.rs (L74-76)
```rust
    pub fn new_dummy() -> Self {
        Self::new_dummy_with_root_hash(*ACCUMULATOR_PLACEHOLDER_HASH)
    }
```
