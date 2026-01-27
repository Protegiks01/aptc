# Audit Report

## Title
Non-Deterministic Block Execution Due to Unsynchronized Transaction Filter Configurations Leading to Network Liveness Failure

## Summary
The transaction filter system applies filters at the execution stage using local node configurations that are not synchronized across validators. If validators configure different `execution_filter` rules, they will filter different transactions from the same block, execute different transaction sets, compute different state roots, and fail to aggregate commit votes, resulting in complete network liveness failure.

## Finding Description

The Aptos consensus pipeline has multiple transaction filter application points defined in `TransactionFiltersConfig`: [1](#0-0) 

The critical `execution_filter` is loaded from local node configuration and applied during block preparation: [2](#0-1) [3](#0-2) 

This filter is applied in `BlockPreparer::prepare_block()` which filters transactions AFTER consensus has agreed on the block: [4](#0-3) 

The filtered transactions are then executed: [5](#0-4) 

Each validator computes their own `StateComputeResult` with their own `root_hash` based on the transactions they executed: [6](#0-5) 

When validators receive commit votes from peers, they check if the `commit_info` matches their local execution result: [7](#0-6) 

**Critical Flow:**
1. Consensus agrees on Block X containing transactions [T1, T2, T3, T4]
2. Validator A has `execution_filter` that removes T2 → executes [T1, T3, T4] → produces root_hash_A
3. Validator B has `execution_filter` that removes T3 → executes [T1, T2, T4] → produces root_hash_B
4. Validator A signs CommitVote with root_hash_A
5. Validator B signs CommitVote with root_hash_B
6. When A receives B's vote, the check `executed.commit_info == *target_commit_info` fails (line 394)
7. Signatures are not added to aggregator
8. Network cannot form 2f+1 quorum → **LIVENESS FAILURE**

This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

This qualifies as **Critical Severity** per Aptos bug bounty criteria:
- **Total loss of liveness/network availability**: The network cannot progress as validators cannot aggregate commit votes
- **Non-recoverable network partition**: Would require coordinated configuration fix or hardfork to recover

The impact is catastrophic - complete network halt affecting all users, transactions, and dependent systems.

## Likelihood Explanation

**Likelihood: LOW**

This vulnerability requires specific conditions:
1. Transaction filters must be explicitly enabled (disabled by default)
2. Multiple validators must configure DIFFERENT filter rules in their local `NodeConfig`
3. A block must contain transactions that trigger divergent filtering behavior

However, the likelihood increases when:
- Validators independently configure filters for operational/compliance reasons
- Configuration updates are rolled out non-atomically across the network
- Filters are used for regulatory compliance (different jurisdictions may filter different transaction types)

The bug is NOT exploitable by external attackers - it requires validator operator configuration changes. However, it represents a critical design flaw that makes the system unsafe under legitimate operational scenarios.

## Recommendation

**Immediate Fix: Add Configuration Validation**

1. Make `execution_filter` an on-chain synchronized configuration rather than local config:

```rust
// Add to on-chain config
pub struct OnChainExecutionFilterConfig {
    pub filter_rules: Vec<BlockTransactionRule>,
    pub filter_enabled: bool,
}
```

2. Add startup validation that warns/fails if `execution_filter` is enabled:

```rust
// In EpochManager::new()
if node_config.transaction_filters.execution_filter.is_enabled() {
    error!("CRITICAL: execution_filter is enabled. This will cause consensus failure if validators have different configs!");
    panic!("execution_filter must be disabled or synchronized on-chain");
}
```

3. Alternative: Move filtering to a pre-consensus stage where all validators apply the same rules before block proposal:

```rust
// Apply filters in payload manager before block creation
// Ensure all validators see the same filtered transaction set
```

**Long-term Fix: On-Chain Filter Synchronization**

Implement filters as on-chain governance-controlled configuration that all validators fetch during reconfiguration events, ensuring deterministic execution across all nodes.

## Proof of Concept

```rust
// Reproduction Steps (requires multi-validator testnet setup):

// 1. Configure Validator A with execution_filter that denies address 0x1
let validator_a_config = NodeConfig {
    transaction_filters: TransactionFiltersConfig {
        execution_filter: BlockTransactionFilterConfig::new(
            true,
            BlockTransactionFilter::new(vec![
                BlockTransactionRule::Deny(vec![
                    BlockTransactionMatcher::Transaction(
                        TransactionMatcher::Sender(AccountAddress::from_hex_literal("0x1").unwrap())
                    )
                ])
            ])
        ),
        ..Default::default()
    },
    ..Default::default()
};

// 2. Configure Validator B with execution_filter that denies address 0x2
let validator_b_config = NodeConfig {
    transaction_filters: TransactionFiltersConfig {
        execution_filter: BlockTransactionFilterConfig::new(
            true,
            BlockTransactionFilter::new(vec![
                BlockTransactionRule::Deny(vec![
                    BlockTransactionMatcher::Transaction(
                        TransactionMatcher::Sender(AccountAddress::from_hex_literal("0x2").unwrap())
                    )
                ])
            ])
        ),
        ..Default::default()
    },
    ..Default::default()
};

// 3. Submit block containing transactions from both 0x1 and 0x2
// 4. Observe that validators cannot aggregate commit votes
// 5. Network halts - no new blocks can be committed

// Expected outcome: LIVENESS FAILURE - network stops processing transactions
```

**Notes:**

The vulnerability is critical in impact but requires validator operator configuration changes rather than external exploitation. This represents a design flaw in the transaction filter system that breaks the deterministic execution invariant when validators have divergent configurations. The issue is exacerbated under high throughput where the large transaction volume makes configuration-induced divergence more likely to manifest.

### Citations

**File:** config/src/config/transaction_filters_config.rs (L12-18)
```rust
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

**File:** consensus/src/state_computer.rs (L54-63)
```rust
pub struct ExecutionProxy {
    executor: Arc<dyn BlockExecutorTrait>,
    txn_notifier: Arc<dyn TxnNotifier>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    write_mutex: AsyncMutex<LogicalTime>,
    txn_filter_config: Arc<BlockTransactionFilterConfig>,
    state: RwLock<Option<MutableState>>,
    enable_pre_commit: bool,
    secret_share_config: Option<SecretShareConfig>,
}
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L787-826)
```rust
    async fn execute(
        prepare_fut: TaskFuture<PrepareResult>,
        parent_block_execute_fut: TaskFuture<ExecuteResult>,
        rand_check: TaskFuture<RandResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
        validator: Arc<[AccountAddress]>,
        onchain_execution_config: BlockExecutorConfigFromOnchain,
        persisted_auxiliary_info_version: u8,
    ) -> TaskResult<ExecuteResult> {
        let mut tracker = Tracker::start_waiting("execute", &block);
        parent_block_execute_fut.await?;
        let (user_txns, block_gas_limit) = prepare_fut.await?;
        let onchain_execution_config =
            onchain_execution_config.with_block_gas_limit_override(block_gas_limit);

        let (rand_result, _has_randomness) = rand_check.await?;

        tracker.start_working();
        // if randomness is disabled, the metadata skips DKG and triggers immediate reconfiguration
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
        let txns = [
            vec![SignatureVerifiedTransaction::from(Transaction::from(
                metadata_txn,
            ))],
            block
                .validator_txns()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(Transaction::ValidatorTransaction)
                .map(SignatureVerifiedTransaction::from)
                .collect(),
            user_txns.as_ref().clone(),
        ]
        .concat();
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1009-1025)
```rust
        let mut block_info = block.gen_block_info(
            compute_result.root_hash(),
            compute_result.last_version_or_0(),
            compute_result.epoch_state().clone(),
        );
        if let Some(timestamp) = epoch_end_timestamp {
            info!(
                "[Pipeline] update block timestamp from {} to epoch end timestamp {}",
                block_info.timestamp_usecs(),
                timestamp
            );
            block_info.change_timestamp(timestamp);
        }
        let ledger_info = LedgerInfo::new(block_info, consensus_data_hash);
        info!("[Pipeline] Signed ledger info {ledger_info}");
        let signature = signer.sign(&ledger_info).expect("Signing should succeed");
        let commit_vote = CommitVote::new_with_signature(signer.author(), ledger_info, signature);
```

**File:** consensus/src/pipeline/buffer_item.rs (L374-416)
```rust
    pub fn add_signature_if_matched(&mut self, vote: CommitVote) -> anyhow::Result<()> {
        let target_commit_info = vote.commit_info();
        let author = vote.author();
        let signature = vote.signature_with_status();
        match self {
            Self::Ordered(ordered) => {
                if ordered
                    .ordered_proof
                    .commit_info()
                    .match_ordered_only(target_commit_info)
                {
                    // we optimistically assume the vote will be valid in the future.
                    // when advancing to executed item, we will check if the sigs are valid.
                    // each author at most stores a single sig for each item,
                    // so an adversary will not be able to flood our memory.
                    ordered.unverified_votes.insert(author, vote);
                    return Ok(());
                }
            },
            Self::Executed(executed) => {
                if executed.commit_info == *target_commit_info {
                    executed
                        .partial_commit_proof
                        .add_signature(author, signature);
                    return Ok(());
                }
            },
            Self::Signed(signed) => {
                if signed.partial_commit_proof.data().commit_info() == target_commit_info {
                    signed.partial_commit_proof.add_signature(author, signature);
                    return Ok(());
                }
            },
            Self::Aggregated(aggregated) => {
                // we do not need to do anything for aggregated
                // but return true is helpful to stop the outer loop early
                if aggregated.commit_proof.commit_info() == target_commit_info {
                    return Ok(());
                }
            },
        }
        Err(anyhow!("Inconsistent commit info."))
    }
```
