# Audit Report

## Title
Inconsistent Execution Filter Configuration Across Validators Causes Network Halt and Consensus Failure

## Summary
The `execution_filter` configuration is loaded from local node configuration files and can differ across validators. When validators execute certified blocks with different filter configurations, they compute different state roots. This prevents commit vote aggregation, causing either total network halt or network partition requiring manual intervention.

## Finding Description

Aptos implements the `execution_filter` as a `BlockTransactionFilterConfig` loaded from local node configuration. [1](#0-0) 

The filter is passed to `ExecutionProxy` during consensus initialization: [2](#0-1) 

During block execution, `BlockPreparer` applies this filter in the `prepare` phase: [3](#0-2) 

The filtering occurs after consensus certification but before execution: [4](#0-3) 

The filter logic conditionally returns all or filtered transactions: [5](#0-4) 

**Attack Scenario:**

Configuration:
- Validator A: `execution_filter` disabled (default)
- Validator B: `execution_filter` configured to deny transactions from address X
- Both validators have >1/3 stake each

Execution Flow:
1. Block containing transaction T from address X gets certified with QC
2. During execution phase:
   - Validator A executes all transactions including T → State Root R1
   - Validator B filters out transaction T → State Root R2
3. Each validator generates block info with their computed state root: [6](#0-5) 
4. Each validator signs commit vote with their state root: [7](#0-6) 
5. When aggregating commit votes, votes are rejected if commit_info doesn't match: [8](#0-7) 
6. Mismatched votes return error: [9](#0-8) 
7. **Result**: Validators cannot aggregate 2f+1 signatures → Network halt or partition

The default configuration has filters disabled: [10](#0-9) 

However, there is no mechanism to enforce consistency across validators or detect configuration mismatches.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical severity criteria:

1. **Total Loss of Liveness/Network Availability**: If validators with different configurations collectively hold >1/3 stake but no subset with matching configs holds >2/3 stake, the network completely halts as commit votes cannot be aggregated.

2. **Non-recoverable Network Partition**: If a subset of validators with matching configurations holds >2/3 stake, they can proceed while others are left behind, creating a permanent network split requiring manual coordination to resolve.

3. **Consensus/Safety Violations**: Breaks the fundamental invariant that all honest validators must produce identical state roots for identical blocks.

This violates AptosBFT consensus guarantees with 0 Byzantine validators - purely through operational misconfiguration by honest validators.

## Likelihood Explanation

**Medium-to-High Likelihood**

**Realistic Trigger Scenarios:**
- Configuration management errors during validator software upgrades
- Copy-paste mistakes in configuration files
- Different operational policies between independent validator operators
- Test configurations accidentally deployed to production
- Configuration drift over time across validator fleet

**No Safeguards Present:**
- No runtime validation that validators use identical execution filters
- No on-chain configuration to enforce consistency
- No warnings or detection mechanisms
- Configuration is per-node local file with no coordination

While the default configuration is safe (filters disabled), operators can enable filters without coordination, and the system provides zero protection against this misconfiguration.

## Recommendation

**Immediate Fix:**
1. Remove `execution_filter` from local configuration
2. If transaction filtering during execution is required, enforce it through on-chain configuration that all validators must follow
3. Add startup validation that compares critical configuration parameters across validators

**Long-term Fix:**
1. Move all consensus-critical configuration to on-chain parameters
2. Add configuration hash to commit votes so mismatches are detected early
3. Implement configuration consistency checks in the consensus protocol
4. Add monitoring/alerting for configuration drift across validators

**Code Fix Approach:**
```rust
// Remove execution_filter from ExecutionProxy initialization
// OR enforce it comes from on-chain config only
pub fn new(
    executor: Arc<dyn BlockExecutorTrait>,
    txn_notifier: Arc<dyn TxnNotifier>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    // Remove: txn_filter_config: BlockTransactionFilterConfig,
    enable_pre_commit: bool,
    secret_share_config: Option<SecretShareConfig>,
) -> Self {
    Self {
        executor,
        txn_notifier,
        state_sync_notifier,
        write_mutex: AsyncMutex::new(LogicalTime::new(0, 0)),
        // Use on-chain config or disable entirely
        txn_filter_config: Arc::new(BlockTransactionFilterConfig::default()),
        state: RwLock::new(None),
        enable_pre_commit,
        secret_share_config,
    }
}
```

## Proof of Concept

Due to the nature of this vulnerability requiring a multi-validator testnet with different configurations, a full PoC would require:

1. Start 4 validators with equal stake (25% each)
2. Configure validators 1-2 with `execution_filter` disabled
3. Configure validators 3-4 with `execution_filter` denying address 0xABCD
4. Submit transaction from address 0xABCD
5. Observe that validators compute different state roots
6. Observe that commit vote aggregation fails
7. Observe network halt

**Configuration for Validator 3-4:**
```yaml
transaction_filters:
  execution_filter:
    filter_enabled: true
    block_transaction_filter:
      sender_filters:
        - address: "0xABCD"
          match_type: "Deny"
```

The vulnerability is evident from the code flow where filtered transactions lead to different execution results, and commit vote aggregation explicitly requires matching commit_info containing the state root.

## Notes

The actual failure mode depends on stake distribution:
- If no subset with matching configs has >2/3 stake: **Total network halt**
- If a subset with matching configs has >2/3 stake: **Network partition** where that subset proceeds while others are excluded

Both outcomes are Critical severity requiring manual intervention. The vulnerability is particularly insidious because it can occur through honest operational mistakes rather than malicious action, yet has catastrophic impact on network operation.

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

**File:** consensus/src/state_computer.rs (L104-109)
```rust
        let block_preparer = Arc::new(BlockPreparer::new(
            payload_manager.clone(),
            self.txn_filter_config.clone(),
            transaction_deduper.clone(),
            transaction_shuffler.clone(),
        ));
```

**File:** consensus/src/block_preparer.rs (L91-98)
```rust
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L1009-1013)
```rust
        let mut block_info = block.gen_block_info(
            compute_result.root_hash(),
            compute_result.last_version_or_0(),
            compute_result.epoch_state().clone(),
        );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1022-1029)
```rust
        let ledger_info = LedgerInfo::new(block_info, consensus_data_hash);
        info!("[Pipeline] Signed ledger info {ledger_info}");
        let signature = signer.sign(&ledger_info).expect("Signing should succeed");
        let commit_vote = CommitVote::new_with_signature(signer.author(), ledger_info, signature);
        network_sender
            .broadcast_commit_vote(commit_vote.clone())
            .await;
        Ok(commit_vote)
```

**File:** consensus/src/pipeline/buffer_item.rs (L393-400)
```rust
            Self::Executed(executed) => {
                if executed.commit_info == *target_commit_info {
                    executed
                        .partial_commit_proof
                        .add_signature(author, signature);
                    return Ok(());
                }
            },
```

**File:** consensus/src/pipeline/buffer_item.rs (L415-416)
```rust
        Err(anyhow!("Inconsistent commit info."))
    }
```
