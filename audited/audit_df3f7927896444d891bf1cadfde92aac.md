# Audit Report

## Title
Consensus Liveness Degradation via Inconsistent Transaction Filter Configurations in DirectMempool Block Proposals

## Summary
Validators with inconsistent `BlockTransactionFilterConfig` settings can cause consensus delays when proposers broadcast blocks containing transactions that pass their own filters but fail validation on other validators, leading to insufficient votes and round timeouts.

## Finding Description

The consensus layer implements a transaction filtering mechanism through `BlockTransactionFilterConfig` that allows validators to reject block proposals containing denied transactions. However, this filter configuration is loaded from each validator's local node configuration and is not synchronized across the network, creating a consensus liveness vulnerability. [1](#0-0) 

When a validator acts as proposer, the `ProposalGenerator` creates block proposals without validating them against the local transaction filter: [2](#0-1) 

The proposer generates the block and broadcasts it without calling `check_denied_inline_transactions()`. However, when other validators receive the proposal, they validate it against their own filter configuration: [3](#0-2) 

If a receiving validator's filter denies any transactions in the proposal, that validator drops the proposal entirely and refuses to vote, incrementing the `REJECTED_PROPOSAL_DENY_TXN_COUNT` counter.

The validation logic in `DirectMempoolPayloadManager` checks inline transactions against the configured filter: [4](#0-3) 

**Attack Scenario:**
1. Validator A has `filter_enabled: false` (default configuration) or permissive filter rules
2. Validators B, C, D have `filter_enabled: true` with strict rules denying transactions from address X
3. Validator A is elected as proposer and creates a DirectMempool block containing transactions from address X
4. Validator A broadcasts the proposal (passes its own disabled/permissive filter)
5. Validators B, C, D receive the proposal and invoke `check_denied_inline_transactions()`
6. All three validators reject the proposal because their filters deny the transactions
7. Only Validator A votes for its own proposal (after receiving it via self-send)
8. Quorum (>2/3 voting power) cannot be reached
9. The round times out and consensus must retry with a new proposer

This breaks the consensus liveness guarantee, as the filter configuration is local and not coordinated: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for "Validator node slowdowns" and "Significant protocol violations." 

The impact includes:
- **Consensus delays**: Failed rounds require timeout periods before new proposers can attempt
- **Wasted validator resources**: Validators process and reject invalid proposals repeatedly
- **Network degradation**: Repeated proposal rejections reduce effective throughput
- **Potential liveness failure**: If multiple consecutive proposers have mismatched configurations, consensus could stall for extended periods

While this does not violate consensus safety (no forks or double-spends occur), it significantly degrades the network's liveness properties, which are essential for a functional blockchain.

## Likelihood Explanation

**Likelihood: Medium to High** depending on deployment practices.

The vulnerability can manifest in two scenarios:

1. **Accidental misconfiguration** (Higher likelihood):
   - Default configuration has filters disabled
   - Some operators enable filters for compliance/policy reasons
   - No validation ensures consistency across validators
   - Configuration drift during upgrades or maintenance
   
2. **Malicious exploitation** (Lower likelihood but possible):
   - Requires compromised or malicious validator
   - Attacker needs knowledge of other validators' filter configurations
   - Must be elected as proposer to execute attack
   - Can deliberately craft proposals to maximize rejection

The likelihood increases if:
- Filters are actively used in production (currently disabled by default)
- Validator operators independently modify configurations
- Network undergoes configuration changes or upgrades
- Documentation doesn't emphasize the need for filter consistency

## Recommendation

**Immediate Fix**: Add pre-proposal validation to ensure proposers don't broadcast blocks that violate their own filters:

```rust
// In consensus/src/round_manager.rs, modify generate_proposal:
async fn generate_proposal(
    epoch_state: Arc<EpochState>,
    new_round_event: NewRoundEvent,
    sync_info: SyncInfo,
    proposal_generator: Arc<ProposalGenerator>,
    safety_rules: Arc<Mutex<MetricsSafetyRules>>,
    proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    block_txn_filter_config: &BlockTransactionFilterConfig, // Add this parameter
) -> anyhow::Result<ProposalMsg> {
    let proposal = proposal_generator
        .generate_proposal(new_round_event.round, proposer_election)
        .await?;
    
    // Add validation before signing
    let temp_block = Block::new_proposal_from_block_data(proposal.clone());
    if let Err(error) = DirectMempoolPayloadManager::new()
        .check_denied_inline_transactions(&temp_block, block_txn_filter_config)
    {
        bail!("Proposed block contains denied transactions: {}", error);
    }
    
    let signature = safety_rules.lock().sign_proposal(&proposal)?;
    let signed_proposal = Block::new_proposal_from_block_data_and_signature(proposal, signature);
    // ... rest of function
}
```

**Long-term Solutions**:

1. **Synchronize filter configurations on-chain**: Move `BlockTransactionFilterConfig` to `OnChainConsensusConfig` to ensure all validators use identical rules

2. **Add configuration validation**: Implement startup checks that warn operators if their filter configuration differs from the majority of validators

3. **Expose metrics**: Add monitoring for proposal rejections due to filter mismatches to detect configuration drift

4. **Documentation**: Clearly document that filter configurations must be consistent across all validators if enabled

## Proof of Concept

The existing test demonstrates the vulnerability mechanism: [6](#0-5) 

To reproduce the full attack scenario with mismatched configurations:

```rust
// Add to consensus/src/round_manager_tests/txn_filter_proposal_test.rs

#[test]
fn test_consensus_stall_on_filter_mismatch() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    
    // Create transactions including one from a specific sender
    let transactions = create_test_transactions();
    let denied_sender = transactions[0].sender();
    
    // Create proposer (node 0) with filter DISABLED
    let proposer_filter = BlockTransactionFilterConfig::new(false, BlockTransactionFilter::empty());
    
    // Create voters (nodes 1-3) with filter ENABLED that denies the first transaction
    let voter_filter = BlockTransactionFilterConfig::new(
        true,
        BlockTransactionFilter::empty()
            .add_multiple_matchers_filter(false, vec![
                BlockTransactionMatcher::Transaction(TransactionMatcher::Sender(denied_sender))
            ])
            .add_all_filter(true)
    );
    
    // Set up 4 validators: 1 proposer with disabled filter, 3 voters with enabled filter
    let mut nodes = NodeSetup::create_nodes_with_different_configs(
        &mut playground,
        runtime.handle().clone(),
        4,
        vec![proposer_filter, voter_filter.clone(), voter_filter.clone(), voter_filter],
        false, // DirectMempool
    );
    
    // Proposer creates block with all transactions (including denied one)
    let payload = Payload::DirectMempool(transactions);
    let proposal = Block::new_proposal(
        payload,
        1,
        1,
        certificate_for_genesis(),
        &nodes[0].signer,
        Vec::new(),
    ).unwrap();
    
    // Simulate proposal broadcast
    timed_block_on(&runtime, async {
        // Proposer processes their own proposal - should succeed
        assert!(nodes[0].round_manager.process_proposal(proposal.clone()).await.is_ok());
        
        // Voters process the proposal - should all fail
        for i in 1..4 {
            assert!(nodes[i].round_manager.process_proposal(proposal.clone()).await.is_err());
        }
        
        // Only proposer votes, insufficient for quorum (need 3/4)
        // Consensus stalls and round times out
    });
}
```

## Notes

This vulnerability exists at the boundary between configuration management and consensus protocol implementation. While filter configurations are intentionally local (likely for operational flexibility), the lack of:
1. Pre-proposal validation on the proposer side
2. Consistency checking mechanisms
3. On-chain synchronization

creates a scenario where validators can unknowingly or deliberately cause consensus delays. The issue is exacerbated by the fact that the proposer does broadcast the proposal to itself (via `self_sender`), but this happens after network broadcast, making it impossible to prevent invalid proposals from propagating.

The vulnerability is particularly concerning because it can manifest through both accidental misconfiguration and deliberate exploitation, and there are no built-in safeguards or warnings to operators about the need for configuration consistency.

### Citations

**File:** consensus/src/epoch_manager.rs (L211-211)
```rust
        let consensus_txn_filter_config = node_config.transaction_filters.consensus_filter.clone();
```

**File:** consensus/src/round_manager.rs (L668-692)
```rust
    async fn generate_proposal(
        epoch_state: Arc<EpochState>,
        new_round_event: NewRoundEvent,
        sync_info: SyncInfo,
        proposal_generator: Arc<ProposalGenerator>,
        safety_rules: Arc<Mutex<MetricsSafetyRules>>,
        proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    ) -> anyhow::Result<ProposalMsg> {
        let proposal = proposal_generator
            .generate_proposal(new_round_event.round, proposer_election)
            .await?;
        let signature = safety_rules.lock().sign_proposal(&proposal)?;
        let signed_proposal =
            Block::new_proposal_from_block_data_and_signature(proposal, signature);
        observe_block(signed_proposal.timestamp_usecs(), BlockStage::SIGNED);
        info!(
            Self::new_log_with_round_epoch(
                LogEvent::Propose,
                new_round_event.round,
                epoch_state.epoch
            ),
            "{}", signed_proposal
        );
        Ok(ProposalMsg::new(signed_proposal, sync_info))
    }
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

**File:** consensus/src/payload_manager/direct_mempool_payload_manager.rs (L30-70)
```rust
    fn check_denied_inline_transactions(
        &self,
        block: &Block,
        block_txn_filter_config: &BlockTransactionFilterConfig,
    ) -> anyhow::Result<()> {
        // If the filter is disabled, return early
        if !block_txn_filter_config.is_enabled() {
            return Ok(());
        }

        // Get the inline transactions for the block proposal. Note: all
        // transactions in a direct mempool payload are inline transactions.
        let (inline_transactions, _, _) = get_transactions_from_block(block)?;
        if inline_transactions.is_empty() {
            return Ok(());
        }

        // Fetch the block metadata
        let block_id = block.id();
        let block_author = block.author();
        let block_epoch = block.epoch();
        let block_timestamp = block.timestamp_usecs();

        // Identify any denied inline transactions
        let block_transaction_filter = block_txn_filter_config.block_transaction_filter();
        let denied_inline_transactions = block_transaction_filter.get_denied_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp,
            inline_transactions,
        );
        if !denied_inline_transactions.is_empty() {
            return Err(anyhow::anyhow!(
                "Inline transactions for DirectMempoolPayload denied by block transaction filter: {:?}",
                denied_inline_transactions
            ));
        }

        Ok(()) // No transactions were denied
    }
```

**File:** config/src/config/transaction_filters_config.rs (L116-123)
```rust
impl Default for BlockTransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                                     // Disable the filter
            block_transaction_filter: BlockTransactionFilter::empty(), // Use an empty filter
        }
    }
}
```

**File:** consensus/src/round_manager_tests/txn_filter_proposal_test.rs (L34-90)
```rust
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
}
```
