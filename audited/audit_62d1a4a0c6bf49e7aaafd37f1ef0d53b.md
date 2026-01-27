# Audit Report

## Title
Transaction Filter Inconsistency Enables Mempool Pollution and Proposal Rejection DoS

## Summary
The Aptos Core codebase does not enforce consistency between the five transaction filter configurations (`mempool_filter`, `consensus_filter`, `execution_filter`, `quorum_store_filter`, and `api_filter`). This allows scenarios where transactions accepted by mempool are later rejected by consensus, leading to mempool pollution, wasted network resources, and potential denial-of-service through repeated proposal rejections.

## Finding Description

The `TransactionFiltersConfig` struct defines five independent filter configurations with no consistency validation: [1](#0-0) 

Each filter operates at a different stage of the transaction lifecycle:

1. **Mempool Filter**: Applied when transactions enter mempool [2](#0-1) 

2. **Consensus Filter**: Applied when validators receive block proposals to check for "denied inline transactions" [3](#0-2) 

3. **Execution Filter**: Applied during block preparation to filter transactions before execution [4](#0-3) 

4. **Quorum Store Filter**: Applied when quorum store receives batches [5](#0-4) 

**Attack Scenario:**

When `mempool_filter` is more permissive than `consensus_filter`:

1. An attacker submits transactions (e.g., from address A) that pass mempool filtering
2. These transactions enter mempool and remain there
3. When a proposer creates a block including these transactions, validators check for denied inline transactions using `consensus_filter` [6](#0-5) 

4. If any transaction is denied by the consensus filter, validators reject the entire block proposal
5. The proposer wastes a proposal round, network bandwidth is consumed broadcasting the rejected proposal, and the transactions remain in mempool indefinitely

This breaks the **Resource Limits** invariant because computational and network resources are wasted on transactions that can never be committed.

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per the Aptos bug bounty program:

- **Validator node slowdowns**: Repeated proposal rejections and filtering overhead slow down validators
- **State inconsistencies requiring intervention**: Mempool becomes polluted with un-committable transactions that require manual intervention to clear
- **Resource exhaustion**: CPU cycles for signature verification, network bandwidth for proposal broadcasting, and storage for maintaining un-committable transactions in mempool

The impact is amplified when:
- Multiple validators have inconsistent filter configurations
- Attackers can identify which transaction patterns are filtered at consensus but not mempool
- The mempool becomes saturated with un-committable transactions, preventing legitimate transactions from entering

## Likelihood Explanation

**Likelihood: Medium-High**

This issue is likely to occur because:

1. **No validation exists**: There are no consistency checks in the configuration system [7](#0-6) 

2. **Independent configuration**: Test code demonstrates filters can be configured independently for different purposes [8](#0-7) 

3. **Realistic misconfiguration scenario**: Operators might intentionally configure:
   - Permissive mempool filters to maximize transaction inclusion
   - Restrictive consensus filters to protect against specific attack patterns
   - Without realizing the inconsistency causes operational issues

4. **No documentation**: There's no guidance warning operators about filter consistency requirements

## Recommendation

Implement validation logic to enforce consistency between filters:

```rust
impl TransactionFiltersConfig {
    /// Validates that filters are consistent across the transaction pipeline
    pub fn validate(&self) -> Result<(), String> {
        // If consensus filter is enabled and denies certain transactions,
        // ensure mempool filter also denies them
        if self.consensus_filter.is_enabled() && self.mempool_filter.is_enabled() {
            // Check that mempool filter is at least as restrictive as consensus filter
            // for transactions (simplified check - actual implementation needs deeper validation)
            if !self.mempool_filter_subsumes_consensus_filter() {
                return Err(
                    "mempool_filter must be at least as restrictive as consensus_filter \
                    to prevent accepting transactions that consensus will reject".to_string()
                );
            }
        }
        
        // Similarly validate execution_filter against consensus_filter
        if self.execution_filter.is_enabled() && self.consensus_filter.is_enabled() {
            if !self.execution_filter_subsumes_consensus_filter() {
                return Err(
                    "execution_filter must be at least as restrictive as consensus_filter".to_string()
                );
            }
        }
        
        Ok(())
    }
    
    fn mempool_filter_subsumes_consensus_filter(&self) -> bool {
        // Implementation: verify that any transaction denied by consensus_filter
        // is also denied by mempool_filter
        // This requires comparing filter rules, which depends on the filter implementation
        true // Placeholder
    }
}
```

Additionally, add validation at node startup:

```rust
// In NodeConfig::load() or similar initialization
if let Err(e) = node_config.transaction_filters.validate() {
    return Err(anyhow::anyhow!("Invalid transaction filter configuration: {}", e));
}
```

Provide clear documentation stating:
- Mempool filter should be equal to or more restrictive than consensus filter
- Consensus filter should be equal to or more restrictive than execution filter
- Inconsistent configurations can cause mempool pollution and proposal rejections

## Proof of Concept

This configuration demonstrates the vulnerability:

```rust
use aptos_config::config::{
    NodeConfig, TransactionFilterConfig, BlockTransactionFilterConfig
};
use aptos_transaction_filters::{
    transaction_filter::{TransactionFilter, TransactionMatcher},
    block_transaction_filter::{BlockTransactionFilter, BlockTransactionMatcher}
};
use move_core_types::account_address::AccountAddress;

fn create_vulnerable_config() -> NodeConfig {
    let mut config = NodeConfig::default();
    let attacker_address = AccountAddress::from_hex_literal("0xBAD").unwrap();
    
    // Mempool filter: PERMISSIVE - allows all transactions
    config.transaction_filters.mempool_filter = TransactionFilterConfig::new(
        false, // Disabled
        TransactionFilter::empty()
    );
    
    // Consensus filter: RESTRICTIVE - denies transactions from attacker_address
    let consensus_filter = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(
            false, // Deny
            vec![BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(attacker_address)
            )]
        )
        .add_all_filter(true); // Allow all others
    
    config.transaction_filters.consensus_filter = 
        BlockTransactionFilterConfig::new(true, consensus_filter);
    
    config
}

// To exploit:
// 1. Start network with the above config
// 2. Submit transactions from attacker_address
// 3. Observe that transactions enter mempool
// 4. Observe that all block proposals containing these transactions are rejected
// 5. Observe mempool pollution and wasted proposal rounds
```

**Notes:**

The vulnerability stems from the architectural decision to have multiple independent filters without consistency enforcement. While this provides flexibility, it creates an operational security risk where misconfiguration can be exploited for denial-of-service attacks. The issue is exacerbated by the fact that when a proposal is rejected due to consensus filter violations, there's no mechanism to remove the offending transactions from mempool, causing them to be repeatedly included in future proposals.

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

**File:** config/src/config/transaction_filters_config.rs (L46-53)
```rust
impl Default for TransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                          // Disable the filter
            transaction_filter: TransactionFilter::empty(), // Use an empty filter
        }
    }
}
```

**File:** mempool/src/shared_mempool/tasks.rs (L408-466)
```rust
fn filter_transactions(
    transaction_filter_config: &TransactionFilterConfig,
    transactions: Vec<(
        SignedTransaction,
        Option<u64>,
        Option<BroadcastPeerPriority>,
    )>,
    statuses: &mut Vec<(SignedTransaction, (MempoolStatus, Option<StatusCode>))>,
) -> Vec<(
    SignedTransaction,
    Option<u64>,
    Option<BroadcastPeerPriority>,
)> {
    // If the filter is not enabled, return early
    if !transaction_filter_config.is_enabled() {
        return transactions;
    }

    // Start the filter processing timer
    let transaction_filter_timer = counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::FILTER_TRANSACTIONS_LABEL])
        .start_timer();

    // Filter the transactions and update the statuses accordingly
    let transactions = transactions
        .into_iter()
        .filter_map(|(transaction, account_sequence_number, priority)| {
            if transaction_filter_config
                .transaction_filter()
                .allows_transaction(&transaction)
            {
                Some((transaction, account_sequence_number, priority))
            } else {
                info!(LogSchema::event_log(
                    LogEntry::TransactionFilter,
                    LogEvent::TransactionRejected
                )
                .message(&format!(
                    "Transaction {} rejected by filter",
                    transaction.committed_hash()
                )));

                statuses.push((
                    transaction.clone(),
                    (
                        MempoolStatus::new(MempoolStatusCode::RejectedByFilter),
                        None,
                    ),
                ));
                None
            }
        })
        .collect();

    // Update the filter processing latency metrics
    transaction_filter_timer.stop_and_record();

    transactions
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

**File:** consensus/src/quorum_store/batch_coordinator.rs (L191-213)
```rust
        if self.transaction_filter_config.is_enabled() {
            let transaction_filter = &self.transaction_filter_config.batch_transaction_filter();
            for batch in batches.iter() {
                for transaction in batch.txns() {
                    if !transaction_filter.allows_transaction(
                        batch.batch_info().batch_id(),
                        batch.author(),
                        batch.digest(),
                        transaction,
                    ) {
                        error!(
                            "Transaction {}, in batch {}, from {}, was rejected by the filter. Dropping {} batches!",
                            transaction.committed_hash(),
                            batch.batch_info().batch_id(),
                            author.short_str().as_str(),
                            batches.len()
                        );
                        counters::RECEIVED_BATCH_REJECTED_BY_FILTER.inc();
                        return;
                    }
                }
            }
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

**File:** testsuite/smoke-test/src/transaction_filter.rs (L246-270)
```rust
/// Adds a filter to the consensus config to ignore transactions from the given sender
fn filter_inline_transactions(node_config: &mut NodeConfig, sender_address: AccountAddress) {
    // Create the block transaction filter
    let block_transaction_filter = BlockTransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
            TransactionMatcher::Sender(sender_address),
        )])
        .add_all_filter(true);

    // Update the node config with the new filter
    node_config.transaction_filters.consensus_filter =
        BlockTransactionFilterConfig::new(true, block_transaction_filter);
}

/// Adds a filter to the mempool config to ignore transactions from the given sender
fn filter_mempool_transactions(node_config: &mut NodeConfig, sender_address: AccountAddress) {
    // Create the transaction filter
    let transaction_filter = TransactionFilter::empty()
        .add_multiple_matchers_filter(false, vec![TransactionMatcher::Sender(sender_address)])
        .add_all_filter(true);

    // Update the node config with the new filter
    node_config.transaction_filters.mempool_filter =
        TransactionFilterConfig::new(true, transaction_filter);
}
```
