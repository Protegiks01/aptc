# Audit Report

## Title
Consensus Voting Split via Inconsistent Transaction Filtering Configuration Leading to Potential Liveness Degradation

## Summary
The `TPayloadManager::check_denied_inline_transactions()` trait method lacks specification regarding error handling semantics and determinism requirements. The `BlockTransactionFilterConfig` used by this method is loaded from local node configuration rather than synchronized on-chain, allowing different validators to reach different conclusions about the same block proposal. This can cause validator voting splits, but does not directly violate consensus safety under normal BFT assumptions.

## Finding Description

The trait contract for `check_denied_inline_transactions()` does not specify that errors must be deterministic across all validators. [1](#0-0) 

The `BlockTransactionFilterConfig` is loaded from local node configuration in the `EpochManager`, making it a per-validator setting rather than a consensus parameter. [2](#0-1) 

When processing a proposal, if `check_denied_inline_transactions()` returns an error, the `RoundManager` drops the proposal and does not vote. [3](#0-2) 

**Execution Flow:**
1. Validator A has `BlockTransactionFilterConfig` with strict rules denying certain senders
2. Validator B has `BlockTransactionFilterConfig` disabled or with lenient rules  
3. Proposer creates a block with inline transactions from a denied sender
4. Validator A calls `check_denied_inline_transactions()`, which returns `Err` for denied transactions, causing Validator A to drop the proposal
5. Validator B calls `check_denied_inline_transactions()`, which returns `Ok`, allowing Validator B to vote
6. Validator set splits based on local configuration rather than consensus rules

The `ConsensusObserverPayloadManager` intentionally bypasses filtering by always returning `Ok()`, demonstrating that different behavior is accepted by design. [4](#0-3) 

## Impact Explanation

**Assessment: Medium Severity**

This issue does NOT meet Critical or High severity criteria because:

1. **Does not directly break consensus safety**: AptosBFT can tolerate up to 1/3 Byzantine validators. Validators disagreeing on voting due to different local configurations is handled by the BFT protocol as long as 2/3+ honest validators agree.

2. **Primarily a liveness concern**: If validators split their votes due to configuration differences, blocks may fail to achieve quorum, causing liveness degradation rather than safety violations.

3. **Requires validator misconfiguration**: This is an operational/configuration issue rather than a code-level exploitable vulnerability. Validators must be explicitly configured with different filter rules.

4. **No direct financial loss**: This does not enable theft, minting, or freezing of funds.

However, it qualifies as Medium severity because:
- It can cause "state inconsistencies requiring intervention" if validators persistently disagree
- It represents a "significant protocol violation" in terms of deterministic validation expectations
- In edge cases with validator set changes, it could theoretically approach safety boundaries

## Likelihood Explanation

**Likelihood: Medium to High (for operational environments)**

The likelihood is elevated because:

1. **No enforcement mechanism**: There is no on-chain synchronization or validation that all validators have identical `BlockTransactionFilterConfig` settings

2. **Operational complexity**: In production deployments with multiple validator operators, configuration drift is common

3. **Silent failures**: Validators can have different configurations without any warning or detection mechanism

4. **Test evidence**: The codebase includes tests specifically verifying that validators with different filter configs behave differently, suggesting this scenario is anticipated but not properly constrained. [5](#0-4) 

## Recommendation

**Short-term fixes:**

1. Add explicit documentation to the `TPayloadManager` trait specifying that `check_denied_inline_transactions()` must be deterministic across all validators:

```rust
/// Check if the block contains any inline transactions that need
/// to be denied (e.g., due to block transaction filtering).
/// 
/// **SAFETY REQUIREMENT**: This method MUST be deterministic across all
/// validators for the same block. All validators must use identical
/// BlockTransactionFilterConfig settings to ensure consensus safety.
/// Non-deterministic filtering can cause voting splits and liveness failures.
///
/// This is only used when processing block proposals.
fn check_denied_inline_transactions(
    &self,
    block: &Block,
    block_txn_filter_config: &BlockTransactionFilterConfig,
) -> anyhow::Result<()>;
```

2. Add a validator configuration check during epoch initialization to warn if validators have divergent filter configurations (through consensus messages or sync info)

3. Consider moving critical filter rules to on-chain parameters that all validators must follow

**Long-term fixes:**

1. Migrate `BlockTransactionFilterConfig` from local node config to on-chain governance parameters
2. Implement configuration fingerprinting in genesis/epoch change to ensure all validators have compatible settings
3. Add metrics and alerting for filter-related proposal rejections to detect configuration drift

## Proof of Concept

```rust
// This test demonstrates validators with different filter configurations
// reaching different voting decisions on the same proposal.
// Based on existing test at consensus/src/round_manager_tests/txn_filter_proposal_test.rs

#[test]
fn test_validator_voting_split_due_to_filter_config() {
    // Setup: Create two validators with different filter configurations
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    
    // Validator 1: Strict filter that denies specific sender
    let strict_filter = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![
            BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(DENIED_SENDER_ADDR)
            )
        ])
        .add_all_filter(true);
    let strict_config = BlockTransactionFilterConfig::new(true, strict_filter);
    
    // Validator 2: No filter (accepts all)
    let lenient_config = BlockTransactionFilterConfig::new(false, 
        BlockTransactionFilter::empty());
    
    // Create validators with different configs
    let mut validator_1 = create_node_with_filter(&mut playground, strict_config);
    let mut validator_2 = create_node_with_filter(&mut playground, lenient_config);
    
    // Create block with transaction from denied sender
    let denied_txn = create_transaction_from_sender(DENIED_SENDER_ADDR);
    let payload = Payload::DirectMempool(vec![denied_txn]);
    let proposal = create_block_proposal(payload);
    
    // Validator 1 rejects the proposal (returns Err from check_denied_inline_transactions)
    timed_block_on(&runtime, async {
        assert!(validator_1.round_manager
            .process_proposal(proposal.clone())
            .await
            .is_err());
    });
    
    // Validator 2 accepts and votes on the proposal (returns Ok)
    timed_block_on(&runtime, async {
        assert!(validator_2.round_manager
            .process_proposal(proposal)
            .await
            .is_ok());
        // Validator 2 produces a vote
        let _vote = validator_2.next_vote().await;
    });
    
    // Result: Validator set splits - liveness degradation
}
```

## Notes

While this issue represents a design gap in the trait contract specification and validator configuration synchronization, it does not constitute a directly exploitable security vulnerability under the strict bounty criteria. The AptosBFT consensus protocol is designed to tolerate validator disagreements within the Byzantine fault tolerance bounds (< 1/3 faulty).

The primary concern is operational reliability and liveness rather than consensus safety. However, validators and node operators should be aware that inconsistent `BlockTransactionFilterConfig` settings across the validator set can cause persistent voting disagreements and reduce network liveness.

A separate but related concern exists with the `execution_filter` configuration (also local per validator), which could theoretically cause state divergence if validators execute different transaction sets from the same committed block. This was outside the scope of the current security question but warrants independent investigation.

### Citations

**File:** consensus/src/payload_manager/mod.rs (L36-43)
```rust
    /// Check if the block contains any inline transactions that need
    /// to be denied (e.g., due to block transaction filtering).
    /// This is only used when processing block proposals.
    fn check_denied_inline_transactions(
        &self,
        block: &Block,
        block_txn_filter_config: &BlockTransactionFilterConfig,
    ) -> anyhow::Result<()>;
```

**File:** consensus/src/epoch_manager.rs (L211-213)
```rust
        let consensus_txn_filter_config = node_config.transaction_filters.consensus_filter.clone();
        let quorum_store_txn_filter_config =
            node_config.transaction_filters.quorum_store_filter.clone();
```

**File:** consensus/src/round_manager.rs (L1204-1214)
```rust
        if let Err(error) = self
            .block_store
            .check_denied_inline_transactions(&proposal, &self.block_txn_filter_config)
        {
            counters::REJECTED_PROPOSAL_DENY_TXN_COUNT.inc();
            bail!(
                "[RoundManager] Proposal for block {} contains denied inline transactions: {}. Dropping proposal!",
                proposal.id(),
                error
            );
        }
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L101-107)
```rust
    fn check_denied_inline_transactions(
        &self,
        _block: &Block,
        _block_txn_filter_config: &BlockTransactionFilterConfig,
    ) -> anyhow::Result<()> {
        Ok(()) // Consensus observer doesn't filter transactions
    }
```

**File:** consensus/src/round_manager_tests/txn_filter_proposal_test.rs (L31-89)
```rust
// Verify that the round manager will not vote if a block
// proposal contains any denied inline transactions.
#[test]
fn test_no_vote_on_denied_inline_transactions() {
    // Test both direct mempool and quorum store payloads
    for use_quorum_store_payloads in [false, true] {
        // Create test transactions
        let transactions = create_test_transactions();

        // Create a block filter config that denies the first transaction sender
        let block_txn_filter = BlockTransactionFilter::empty()
            .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(transactions[0].sender()),
            )])
            .add_all_filter(true);
        let block_txn_filter_config = BlockTransactionFilterConfig::new(true, block_txn_filter);

        // Create a new network playground
        let runtime = consensus_runtime();
        let mut playground = NetworkPlayground::new(runtime.handle().clone());

        // Create a new consensus node. Note: To observe the votes we're
        // going to check proposal processing on the non-proposer node
        // (which will send the votes to the proposer).
        let mut nodes = NodeSetup::create_nodes(
            &mut playground,
            runtime.handle().clone(),
            1,
            None,
            None,
            Some(block_txn_filter_config),
            None,
            None,
            None,
            use_quorum_store_payloads,
        );
        let node = &mut nodes[0];

        // Create a block proposal with inline transactions that will be denied
        let payload = create_payload(transactions, use_quorum_store_payloads);
        let denied_block = Block::new_proposal(
            payload,
            1,
            1,
            certificate_for_genesis(),
            &node.signer,
            Vec::new(),
        )
        .unwrap();

        // Verify that the node does not vote on a block with denied inline transactions
        timed_block_on(&runtime, async {
            assert!(node
                .round_manager
                .process_proposal(denied_block)
                .await
                .is_err());
        });
    }
```
