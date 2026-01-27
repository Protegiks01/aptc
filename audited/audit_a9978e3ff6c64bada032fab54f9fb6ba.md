# Audit Report

## Title
Mempool Filter Bypass via Independent Consensus Filter Configuration Allows Execution of Rejected Transactions

## Summary
When a transaction is rejected by a node's mempool filter with `RejectedByFilter(7)` status, an attacker can bypass this protection by submitting the transaction to a different validator with a permissive mempool filter. The transaction will be included in a consensus block proposal and executed by the original node if its consensus filter is not configured with matching rules, despite being explicitly rejected from its mempool.

## Finding Description

The Aptos transaction filtering system implements **five independent filters** configured separately in `TransactionFiltersConfig`: `api_filter`, `consensus_filter`, `execution_filter`, `mempool_filter`, and `quorum_store_filter`. [1](#0-0) 

The mempool filter is applied during transaction submission to prevent unwanted transactions from entering a node's local mempool: [2](#0-1) [3](#0-2) 

When a transaction violates the mempool filter rules, it returns `MempoolStatusCode::RejectedByFilter`: [4](#0-3) 

However, during consensus, a **separate and independent** consensus filter is used to validate block proposals: [5](#0-4) [6](#0-5) [7](#0-6) 

**Attack Scenario:**
1. Operator configures Node A with `mempool_filter` enabled to deny transactions from sender address X
2. Operator does NOT configure `consensus_filter` (defaults to disabled)
3. Attacker submits transaction from address X to Node A → rejected with `RejectedByFilter`
4. Attacker submits same transaction to Node B (validator with disabled/permissive `mempool_filter`)
5. Node B accepts transaction into its mempool and includes it in a block proposal
6. Node A receives the block proposal during consensus
7. Node A's `check_denied_inline_transactions()` uses `consensus_filter` (NOT `mempool_filter`)
8. Since Node A's `consensus_filter` is disabled, the check passes
9. Node A votes for and executes the block containing the filtered transaction
10. **Result:** Transaction that was explicitly rejected by Node A's mempool filter is executed on Node A

Both filters default to **disabled**: [8](#0-7) [9](#0-8) 

This creates a security gap where operators may believe their mempool filter protects them from malicious transactions, but those transactions can bypass the filter through consensus blocks.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program as it represents a **significant protocol violation**:

- **Filter Policy Bypass**: Security controls explicitly configured by node operators can be circumvented
- **DoS Attack Vector**: Transactions intended to cause resource exhaustion that are filtered at mempool can still execute
- **Compliance Violation**: Transactions from sanctioned addresses that operators filter can still be processed
- **Operator Trust Violation**: Operators may incorrectly assume mempool filters provide complete protection

The vulnerability affects **all validators** that configure mempool filters without matching consensus filters, which is likely the majority given the default disabled state and complexity of the 5-filter system.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Default Configuration Vulnerability**: Both filters default to disabled, requiring operators to explicitly configure BOTH
2. **Complexity**: The 5-filter system (api, consensus, execution, mempool, quorum_store) is complex and non-obvious
3. **Documentation Gap**: Operators may not understand they need identical rules in both mempool AND consensus filters
4. **Attacker Accessibility**: Any transaction sender can exploit this by submitting to validators with permissive filters
5. **No Special Privileges Required**: No validator access or insider position needed
6. **Network Diversity**: In a real network, validators inevitably have different filter configurations, making bypass trivial

## Recommendation

**Immediate Fix:**
1. Document clearly that `mempool_filter` and `consensus_filter` must be configured with **identical rules** for effective protection
2. Add validation during node startup that warns/errors if mempool_filter is enabled but consensus_filter is not
3. Consider defaulting `consensus_filter` to match `mempool_filter` automatically if not explicitly configured

**Long-term Architecture Fix:**
Refactor the filtering system to use a single unified filter that applies at all checkpoints (mempool submission, consensus validation, execution). This eliminates configuration complexity and prevents bypass attacks.

```rust
// In config/src/config/transaction_filters_config.rs
impl TransactionFiltersConfig {
    /// Validates that mempool and consensus filters are consistent
    pub fn validate_consistency(&self) -> Result<(), String> {
        if self.mempool_filter.is_enabled() && !self.consensus_filter.is_enabled() {
            return Err(
                "Security Warning: mempool_filter is enabled but consensus_filter is disabled. \
                Transactions rejected by mempool can still execute via consensus blocks. \
                Configure consensus_filter with matching rules.".to_string()
            );
        }
        Ok(())
    }
}
```

## Proof of Concept

This PoC demonstrates the vulnerability using the existing Aptos smoke test framework:

```rust
#[tokio::test]
async fn test_mempool_filter_bypass_via_consensus() {
    // Generate a sender address to be filtered
    let (private_key, filtered_address) = create_sender_account();

    // Create a 3-validator swarm where:
    // - Validator 0 (victim): Has mempool_filter enabled, consensus_filter disabled
    // - Validator 1 (bypass): Has both filters disabled
    // - Validator 2: Has both filters disabled
    let mut swarm = SwarmBuilder::new_local(3)
        .with_aptos()
        .with_init_config(Arc::new(move |idx, config, _| {
            if idx == 0 {
                // Victim node: Mempool filter enabled, consensus filter disabled (DEFAULT)
                let transaction_filter = TransactionFilter::empty()
                    .add_sender_filter(false, filtered_address);
                config.transaction_filters.mempool_filter =
                    TransactionFilterConfig::new(true, transaction_filter);
                // consensus_filter remains at default (disabled)
            }
            // Other validators have all filters disabled (default)
        }))
        .with_init_genesis_config(Arc::new(|genesis_config| {
            // Disable quorum store to use DirectMempool
            genesis_config.consensus_config = OnChainConsensusConfig::V4 {
                alg: ConsensusAlgorithmConfig::default_with_quorum_store_disabled(),
                vtxn: ValidatorTxnConfig::default_for_genesis(),
                window_size: DEFAULT_WINDOW_SIZE,
            };
        }))
        .build()
        .await;

    // Create and fund the filtered account
    create_account_with_funds(&private_key.public_key(), filtered_address, &mut swarm).await;
    
    // Create a receiver account
    let mut aptos_public_info = swarm.aptos_public_info();
    let receiver = aptos_public_info.random_account();
    create_account_with_funds(receiver.public_key(), receiver.address(), &mut swarm).await;

    // Step 1: Try to submit transaction to victim node (validator 0)
    let victim_client = swarm.validators().nth(0).unwrap().rest_client();
    let txn1 = create_signed_transaction_from_sender(
        private_key.clone(), 
        filtered_address, 
        receiver.clone(), 
        &mut swarm
    ).await;
    
    let result = victim_client.submit_and_wait(&txn1).await;
    // Verify it was rejected by mempool filter
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("RejectedByFilter"));

    // Step 2: Submit the SAME transaction to bypass node (validator 1)
    let bypass_client = swarm.validators().nth(1).unwrap().rest_client();
    let txn2 = create_signed_transaction_from_sender(
        private_key, 
        filtered_address, 
        receiver, 
        &mut swarm
    ).await;
    
    // This succeeds because bypass node has no mempool filter
    let result = bypass_client.submit_and_wait(&txn2).await;
    assert!(result.is_ok()); // Transaction executes successfully
    
    // Step 3: Verify the transaction was executed on the victim node
    // even though it was rejected by its mempool filter
    let account_info = victim_client
        .get_account(filtered_address)
        .await
        .unwrap()
        .into_inner();
    
    // Sequence number increased, proving transaction executed on victim node
    assert_eq!(account_info.sequence_number, 1);
    
    // VULNERABILITY CONFIRMED: Transaction rejected by victim's mempool filter
    // was executed on victim node via consensus block from bypass node
}
```

**Test Execution:**
```bash
cd testsuite/smoke-test
cargo test test_mempool_filter_bypass_via_consensus -- --nocapture
```

**Expected Result:** The test passes, confirming that a transaction rejected by the mempool filter (step 1) successfully executes on the same node when submitted through a different validator (step 2), demonstrating the filter bypass vulnerability.

## Notes

The vulnerability exists because the filtering architecture treats mempool and consensus as separate validation stages with independent filter configurations. While this provides flexibility, it creates a security gap where operators must understand to configure both filters identically—a requirement that is not obvious, not enforced, and not documented prominently.

The test file `testsuite/smoke-test/src/transaction_filter.rs` demonstrates proper filtering but does not test the bypass scenario where filters are configured inconsistently across mempool and consensus layers: [10](#0-9) [11](#0-10)

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

**File:** mempool/src/shared_mempool/tasks.rs (L318-326)
```rust
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);

    // If there are no transactions left after filtering, return early
    if transactions.is_empty() {
        return statuses;
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

**File:** types/src/mempool_status.rs (L66-67)
```rust
    // The transaction filter has rejected the transaction
    RejectedByFilter = 7,
```

**File:** consensus/src/epoch_manager.rs (L211-211)
```rust
        let consensus_txn_filter_config = node_config.transaction_filters.consensus_filter.clone();
```

**File:** consensus/src/round_manager.rs (L315-315)
```rust
    block_txn_filter_config: BlockTransactionFilterConfig,
```

**File:** consensus/src/round_manager.rs (L1202-1214)
```rust
        // If the proposal contains any inline transactions that need to be denied
        // (e.g., due to filtering) drop the message and do not vote for the block.
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

**File:** testsuite/smoke-test/src/transaction_filter.rs (L79-113)
```rust
async fn test_mempool_transaction_filter() {
    // Generate a new key pair and sender address
    let (private_key, sender_address) = create_sender_account();

    // Create a new swarm with a mempool filter that denies transactions from the sender
    let mut swarm = SwarmBuilder::new_local(3)
        .with_aptos()
        .with_init_config(Arc::new(move |_, config, _| {
            filter_mempool_transactions(config, sender_address);
        }))
        .build()
        .await;

    // Execute a few regular transactions and verify that they are processed correctly
    execute_test_transactions(&mut swarm).await;

    // Prepare a transaction from the sender address
    let transaction = create_transaction_from_sender(private_key, sender_address, &mut swarm).await;

    // Submit the transaction and wait for it to be processed
    let aptos_public_info = swarm.aptos_public_info();
    let response = aptos_public_info
        .client()
        .submit_and_wait(&transaction)
        .await;

    // Verify the transaction was rejected by the mempool filter
    let error = response.unwrap_err();
    assert!(error
        .to_string()
        .contains("API error Error(RejectedByFilter)"));

    // Execute a few more transactions and verify that they are processed correctly
    execute_test_transactions(&mut swarm).await;
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
