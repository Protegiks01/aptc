# Audit Report

## Title
Filter Bypass via Transaction Simulation Enabling Cost-Free Security Policy Probing

## Summary
The `simulate_transaction()` API endpoint uses a separate transaction filter (`api_filter`) from the mempool submission path (`mempool_filter`). When these filters are configured differently or one is disabled, attackers can probe security policies, test malicious transaction payloads, and discover filter rules without incurring costs, rate limits, or actual submission.

## Finding Description

The Aptos transaction filtering system implements two independently configurable filters for different pipeline stages: [1](#0-0) 

The simulation endpoint checks only the `api_filter`: [2](#0-1) 

Meanwhile, actual transaction submission checks the `mempool_filter`: [3](#0-2) [4](#0-3) 

Both filters default to disabled state: [5](#0-4) 

**Attack Scenarios:**

1. **Default Configuration (both filters disabled)**: An operator enables `mempool_filter` to block malicious senders but forgets to enable `api_filter`. Attackers freely simulate transactions to test execution paths, gas costs, and VM behavior without triggering filters.

2. **Misaligned Filter Rules**: `api_filter` blocks sender A while `mempool_filter` blocks sender B. Sender B can simulate transactions to probe VM behavior, discover exploitable entry functions, and optimize attack payloads before attempting submission.

3. **Filter Rule Discovery**: Attackers systematically test various senders, modules, and functions via simulation to map security policies, identifying which accounts or contracts are being filtered and adjusting attack strategies accordingly.

Test code demonstrates independent filter configuration: [6](#0-5) [7](#0-6) 

## Impact Explanation

This is a **Low Severity** vulnerability per Aptos bug bounty criteria:

- **Information Disclosure**: Attackers learn which transactions are filtered without cost or detection
- **Security Policy Bypass**: Simulation bypasses intended security controls when filters are misaligned
- **Cost-Free Attack Testing**: Malicious actors test payloads without paying gas fees or triggering mempool rate limits
- **No Direct Fund Loss**: Does not enable theft or minting of tokens
- **No Consensus Impact**: Does not affect chain safety or liveness
- **Requires Misconfiguration**: Only exploitable when filters differ (though default state enables this)

The vulnerability enables reconnaissance and policy evasion but does not directly compromise funds or consensus integrity.

## Likelihood Explanation

**High Likelihood** of occurrence:

1. **Default Configuration**: Both filters disabled by default, making it easy for operators to enable only one
2. **Independent Configuration**: No enforcement or warning when filters diverge
3. **Operational Complexity**: Managing two separate filter configurations increases chance of misalignment
4. **Common Use Case**: Operators might intentionally restrict mempool but leave simulation open for developer testing, unknowingly enabling reconnaissance

The attack requires only:
- API access (publicly available on full nodes)
- Knowledge of target addresses/functions to test
- No special credentials or validator access

## Recommendation

**Option 1: Unified Filter (Preferred)**
Enforce that simulation uses the same filter as mempool to prevent policy bypass:

```rust
// In simulate_transaction(), replace api_filter check with mempool_filter
let mempool_filter = &context.node_config.transaction_filters.mempool_filter;
if mempool_filter.is_enabled()
    && !mempool_filter
        .transaction_filter()
        .allows_transaction(&signed_transaction)
{
    return Err(SubmitTransactionError::forbidden_with_code(
        "Transaction not allowed by mempool filter",
        AptosErrorCode::InvalidInput,
        &ledger_info,
    ));
}
```

**Option 2: Validation Check**
Add startup validation that warns or errors if filters are configured differently:

```rust
// In NodeConfig validation
pub fn validate_transaction_filters(&self) -> Result<(), Error> {
    if self.transaction_filters.api_filter.is_enabled() 
        != self.transaction_filters.mempool_filter.is_enabled() {
        warn!("API filter and mempool filter have different enabled states. \
               This may allow filter bypass via simulation.");
    }
    Ok(())
}
```

**Option 3: Documentation**
At minimum, document that these filters should be kept synchronized to prevent information disclosure.

## Proof of Concept

```rust
// Reproduction steps (integration test)
#[tokio::test]
async fn test_filter_bypass_via_simulation() {
    let (private_key, attacker_address) = create_sender_account();
    
    // Scenario: Operator blocks attacker in mempool but forgets API filter
    let mut node_config = NodeConfig::default();
    
    // Enable mempool filter to block attacker
    let mempool_filter = TransactionFilter::empty()
        .add_sender_filter(false, attacker_address);  // Deny attacker
    node_config.transaction_filters.mempool_filter = 
        TransactionFilterConfig::new(true, mempool_filter);
    
    // API filter remains disabled (default)
    // node_config.transaction_filters.api_filter = default (disabled)
    
    let mut swarm = SwarmBuilder::new_local(1)
        .with_aptos()
        .with_init_config(Arc::new(move |_, config, _| {
            *config = node_config.clone();
        }))
        .build()
        .await;
    
    // Create attacker account with funds
    create_account_with_funds(&private_key.public_key(), attacker_address, &mut swarm).await;
    
    let receiver = swarm.aptos_public_info().random_account();
    let transaction = create_signed_transaction_from_sender(
        private_key, attacker_address, receiver, &mut swarm
    ).await;
    
    // SIMULATION SUCCEEDS (bypasses filter) - attacker learns execution details
    let client = swarm.aptos_public_info().client();
    let simulation_result = client
        .simulate(&transaction)
        .await;
    assert!(simulation_result.is_ok());  // ✓ Simulation passes
    
    // ACTUAL SUBMISSION FAILS (mempool filter blocks it)
    let submission_result = client
        .submit_and_wait(&transaction)
        .await;
    assert!(submission_result.is_err());  // ✓ Submission blocked
    assert!(submission_result.unwrap_err()
        .to_string()
        .contains("RejectedByFilter"));  // ✓ Correctly filtered
    
    // VULNERABILITY: Attacker learned execution details via simulation
    // without paying fees or triggering mempool filter
}
```

The proof of concept demonstrates that with misaligned filters, an attacker blocked by mempool can freely simulate transactions to probe VM behavior, gas costs, and execution paths—information that can be used to refine attacks or discover exploitable patterns.

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

**File:** api/src/transactions.rs (L619-631)
```rust
            // Confirm the API simulation filter allows the transaction
            let api_filter = &context.node_config.transaction_filters.api_filter;
            if api_filter.is_enabled()
                && !api_filter
                    .transaction_filter()
                    .allows_transaction(&signed_transaction)
            {
                return Err(SubmitTransactionError::forbidden_with_code(
                    "Transaction not allowed by simulation filter",
                    AptosErrorCode::InvalidInput,
                    &ledger_info,
                ));
            }
```

**File:** mempool/src/shared_mempool/tasks.rs (L318-321)
```rust
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);
```

**File:** mempool/src/shared_mempool/tasks.rs (L408-460)
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
```

**File:** api/src/tests/transactions_test.rs (L2711-2741)
```rust
async fn test_simulation_filter_deny(
    use_txn_payload_v2_format: bool,
    use_orderless_transactions: bool,
) {
    let mut node_config = NodeConfig::default();

    // Blocklist the balance function.
    let transaction_filter = TransactionFilter::empty().add_all_filter(false);
    let transaction_filter_config = TransactionFilterConfig::new(true, transaction_filter);
    node_config.transaction_filters.api_filter = transaction_filter_config;

    let mut context = new_test_context_with_config(
        current_function_name!(),
        node_config,
        use_txn_payload_v2_format,
        use_orderless_transactions,
    );

    let admin0 = context.root_account().await;

    let resp = context.simulate_transaction(&admin0, json!({
        "type": "script_payload",
        "code": {
            "bytecode": "a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102",
        },
        "type_arguments": [],
        "arguments": [],
    }), 403).await;

    context.check_golden_output(resp);
}
```

**File:** testsuite/smoke-test/src/transaction_filter.rs (L260-270)
```rust
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
