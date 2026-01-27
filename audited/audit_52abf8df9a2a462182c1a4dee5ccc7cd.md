# Audit Report

## Title
State Machine Divergence via Inconsistent Execution-Time Transaction Filtering

## Summary
The Aptos transaction filtering system contains a critical vulnerability where the `execution_filter` (`BlockTransactionFilter`) is applied during block preparation for execution using validator-local configurations. This allows different validators to execute different subsets of transactions from the same committed block, directly violating the deterministic execution invariant and causing state machine divergence.

## Finding Description
While investigating the `BatchTransactionFilter` system, I discovered that Aptos implements multiple transaction filtering layers with different scopes:

1. **Quorum Store Filter** (`quorum_store_filter`) - Filters batches before they enter the local batch store
2. **Consensus Filter** (`consensus_filter`) - Checks inline transactions during block voting  
3. **Execution Filter** (`execution_filter`) - **Applied during block execution** ← **THE VULNERABILITY**

The critical vulnerability exists in the execution filtering path: [1](#0-0) 

Each validator loads its own execution filter configuration from the local node config: [2](#0-1) 

This filter is then passed to the `BlockPreparer` and applied during block preparation: [3](#0-2) 

The `filter_block_transactions` function removes transactions based on the local filter rules: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. All validators reach consensus on Block B containing transactions [T1, T2, T3, T4]
2. Block B receives 2/3+ votes and is committed by consensus
3. Validator A has `execution_filter` configured to deny transactions from sender X
4. Validator B has no execution filter (or different rules)
5. During execution preparation:
   - Validator A filters out T2 (from sender X) → executes [T1, T3, T4]
   - Validator B executes all → executes [T1, T2, T3, T4]
6. **Result**: Validator A reaches state root R1, Validator B reaches state root R2
7. **Consensus safety violation**: Validators permanently diverge on the canonical state

## Impact Explanation
This vulnerability achieves **Critical Severity** under the Aptos bug bounty program as it constitutes a **Consensus/Safety violation**:

- **Breaks Deterministic Execution Invariant**: The fundamental requirement that "all validators must produce identical state roots for identical blocks" is violated
- **Causes State Machine Divergence**: Validators execute different transaction sets for the same block, producing different state roots
- **Requires Hardfork**: Once validators diverge, the network cannot automatically recover without manual intervention
- **Undermines Consensus Guarantees**: The AptosBFT consensus protocol's safety guarantee is nullified if execution is non-deterministic

This falls squarely under "Consensus/Safety violations" worth up to $1,000,000 in the Critical Severity category.

## Likelihood Explanation
**Likelihood: High** given the current architecture:

- **No Configuration Enforcement**: The system has no mechanism to verify that all validators use identical execution filter configurations
- **Local Configuration Loading**: Each validator independently loads filters from local files with no validation
- **Silent Failure Mode**: Divergence manifests as state root mismatches without clear error messages
- **Operator Error Prone**: Validators may inadvertently deploy with inconsistent configurations during upgrades or troubleshooting

The vulnerability doesn't require malicious intent - simple operational mistakes or misconfigurations trigger it. However, it could also be deliberately exploited by:
- Compromised validator operators applying selective filters
- Social engineering to trick operators into deploying specific filter rules
- Supply chain attacks modifying default configurations

## Recommendation
**Immediate Fix**: Remove execution-time filtering entirely or enforce strict configuration validation.

**Option 1 - Remove Execution Filtering (Recommended)**:
The execution filter should be removed from the block execution path. Filtering should only occur at pre-consensus stages (mempool, quorum store, block voting). Once consensus commits a block, all validators must execute it identically.

Modify `BlockPreparer::prepare_block`:

```rust
pub async fn prepare_block(
    &self,
    block: &Block,
    txns: Vec<SignedTransaction>,
    max_txns_from_block_to_execute: Option<u64>,
    block_gas_limit: Option<u64>,
) -> (Vec<SignedTransaction>, Option<u64>) {
    // REMOVED: execution-time filtering
    // All validators must execute the same transactions post-consensus
    
    let txn_deduper = self.txn_deduper.clone();
    let txn_shuffler = self.txn_shuffler.clone();
    
    let result = tokio::task::spawn_blocking(move || {
        let deduped_txns = txn_deduper.dedup(txns); // Only dedup, no filter
        let mut shuffled_txns = txn_shuffler.shuffle(deduped_txns);
        
        if let Some(max_txns) = max_txns_from_block_to_execute {
            shuffled_txns.truncate(max_txns as usize);
        }
        shuffled_txns
    }).await.expect("Failed to spawn blocking task");
    
    (result, block_gas_limit)
}
```

**Option 2 - Enforce Uniform Configuration**:
If execution filtering is deemed necessary, enforce that all validators use identical filter configurations via on-chain configuration:

1. Store filter rules in on-chain configuration (similar to `OnChainConsensusConfig`)
2. Validate filter configuration hash during epoch initialization
3. Reject blocks from validators with mismatched filter configs

## Proof of Concept
Since this is a configuration-based vulnerability, a full PoC requires multi-validator setup:

**Setup**:
1. Deploy 4 validators in a test network
2. Configure Validator 1 and 2 with `execution_filter` denying sender `0xBEEF`
3. Configure Validator 3 and 4 with empty execution filter

**Exploitation**:
```rust
// Test scenario demonstrating divergence
#[tokio::test]
async fn test_execution_filter_causes_divergence() {
    // 1. Create block with transaction from filtered sender
    let sender = AccountAddress::from_hex_literal("0xBEEF").unwrap();
    let txn = create_test_transaction(sender);
    let block = create_block_with_txns(vec![txn]);
    
    // 2. All validators vote and commit the block
    assert!(block_reaches_consensus(&validators));
    
    // 3. Execute on validator with filter
    let filtered_config = BlockTransactionFilterConfig::new(
        true,
        BlockTransactionFilter::new(vec![
            BlockTransactionRule::Deny(vec![
                BlockTransactionMatcher::Transaction(
                    TransactionMatcher::Sender(sender)
                )
            ])
        ])
    );
    let state_root_1 = execute_block_with_filter(&block, filtered_config);
    
    // 4. Execute on validator without filter  
    let empty_config = BlockTransactionFilterConfig::default();
    let state_root_2 = execute_block_with_filter(&block, empty_config);
    
    // 5. Assert divergence
    assert_ne!(state_root_1, state_root_2, "State machine divergence!");
}
```

**Expected Result**: The test demonstrates that validators with different execution filter configurations produce different state roots for the same committed block, violating consensus safety.

## Notes
While the original question referenced `batch_transaction_filter.rs`, the investigation revealed that the `BatchTransactionFilter` itself does not cause state divergence - it only affects which batches are stored locally before consensus. During execution, validators fetch missing batches from peers, ensuring they execute the same transactions.

The actual vulnerability exists in the **execution-time filtering** (`execution_filter`) which uses `BlockTransactionFilter` in a fundamentally unsafe way - filtering transactions AFTER consensus agreement but BEFORE execution. This represents a critical design flaw where the execution layer violates the consensus layer's decisions.

### Citations

**File:** config/src/config/transaction_filters_config.rs (L10-18)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFiltersConfig {
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
}
```

**File:** consensus/src/consensus_provider.rs (L65-72)
```rust
    let execution_proxy = ExecutionProxy::new(
        Arc::new(BlockExecutor::<AptosVMBlockExecutor>::new(aptos_db)),
        txn_notifier,
        state_sync_notifier,
        node_config.transaction_filters.execution_filter.clone(),
        node_config.consensus.enable_pre_commit,
        None,
    );
```

**File:** consensus/src/block_preparer.rs (L89-98)
```rust
        // Transaction filtering, deduplication and shuffling are CPU intensive tasks, so we run them in a blocking task.
        let result = tokio::task::spawn_blocking(move || {
            let filtered_txns = filter_block_transactions(
                txn_filter_config,
                block_id,
                block_author,
                block_epoch,
                block_timestamp_usecs,
                txns,
            );
```

**File:** consensus/src/block_preparer.rs (L122-146)
```rust
/// Filters transactions in a block based on the filter configuration
fn filter_block_transactions(
    txn_filter_config: Arc<BlockTransactionFilterConfig>,
    block_id: HashValue,
    block_author: Option<AccountAddress>,
    block_epoch: u64,
    block_timestamp_usecs: u64,
    txns: Vec<SignedTransaction>,
) -> Vec<SignedTransaction> {
    // If the transaction filter is disabled, return early
    if !txn_filter_config.is_enabled() {
        return txns;
    }

    // Otherwise, filter the transactions
    txn_filter_config
        .block_transaction_filter()
        .filter_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp_usecs,
            txns,
        )
}
```

**File:** crates/aptos-transaction-filters/src/block_transaction_filter.rs (L92-113)
```rust
    /// Filters the transactions in the given block and returns only those that are allowed
    pub fn filter_block_transactions(
        &self,
        block_id: HashValue,
        block_author: Option<AccountAddress>,
        block_epoch: u64,
        block_timestamp_usecs: u64,
        transactions: Vec<SignedTransaction>,
    ) -> Vec<SignedTransaction> {
        transactions
            .into_iter()
            .filter(|txn| {
                self.allows_transaction(
                    block_id,
                    block_author,
                    block_epoch,
                    block_timestamp_usecs,
                    txn,
                )
            })
            .collect()
    }
```
