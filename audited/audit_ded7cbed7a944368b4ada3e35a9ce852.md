# Audit Report

## Title
Information Disclosure via Differential Filter Analysis Between Simulation and Submission

## Summary
The `simulate_transaction()` endpoint applies the `api_filter` while actual transaction submission applies the `mempool_filter`. When these filters are configured differently, attackers can use simulation to probe which transactions would be rejected by mempool without actually submitting them, creating an information disclosure vulnerability.

## Finding Description

The Aptos Core codebase implements two independent transaction filtering mechanisms with different enforcement points:

1. **API Filter (Simulation)**: The `simulate_transaction()` function checks transactions against `api_filter` [1](#0-0) 

2. **Mempool Filter (Submission)**: The mempool enforces `mempool_filter` when transactions are submitted [2](#0-1)  and applied during transaction processing [3](#0-2) 

These are configured as separate, independent filters [4](#0-3) 

When `api_filter` is more permissive than `mempool_filter`, an attacker can:
1. Call `/transactions/simulate` with test transactions
2. Observe which simulations succeed (pass `api_filter`)
3. Attempt actual submission of the same transactions
4. Identify which get rejected with `RejectedByFilter` status [5](#0-4) 
5. Map out the `mempool_filter` rules through differential analysis

This allows probing filter policies (blocked addresses, transaction patterns) without paying gas fees or leaving traces in mempool.

## Impact Explanation

This qualifies as **Low Severity** per the Aptos bug bounty criteria for "Minor information leaks." The impact is limited to:
- Disclosure of node filtering policies
- Privacy violation for operators using filters for security/anonymity
- No funds loss, consensus violation, or availability impact
- Filters remain enforced on actual submission

## Likelihood Explanation

**High likelihood** - The attack is trivial to execute:
- No special privileges required
- Public API endpoints accessible to all users
- Automated differential analysis is straightforward
- Commonly occurs when operators configure different security policies for simulation vs. submission

## Recommendation

Enforce consistent filtering across simulation and submission by applying **both** filters during simulation:

```rust
// In simulate_transaction(), after line 631
// Also check mempool filter to prevent information disclosure
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

Alternatively, document this behavior clearly and advise operators to keep `api_filter` and `mempool_filter` synchronized if information disclosure is a concern.

## Proof of Concept

The existing test infrastructure demonstrates the separate filter enforcement [6](#0-5)  and [7](#0-6) 

To demonstrate the vulnerability:
1. Configure a node with `api_filter` disabled but `mempool_filter` blocking a specific address
2. Simulate a transaction from the blocked address - it succeeds
3. Submit the same transaction - it fails with `RejectedByFilter`
4. Attacker learns the address is blocked without the transaction entering mempool

**Notes**

This is a design issue where separation of concerns (API vs. mempool filtering) creates an information leak. While rated Low severity, it violates the principle that security policies should not be discoverable through side-channels. Node operators using transaction filters for privacy or security should ensure both filters are configured identically to prevent this disclosure.

### Citations

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

**File:** mempool/src/shared_mempool/runtime.rs (L53-53)
```rust
    let transaction_filter_config = config.transaction_filters.mempool_filter.clone();
```

**File:** mempool/src/shared_mempool/tasks.rs (L321-321)
```rust
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);
```

**File:** mempool/src/shared_mempool/tasks.rs (L450-456)
```rust
                statuses.push((
                    transaction.clone(),
                    (
                        MempoolStatus::new(MempoolStatusCode::RejectedByFilter),
                        None,
                    ),
                ));
```

**File:** config/src/config/transaction_filters_config.rs (L13-16)
```rust
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
```

**File:** api/src/tests/transactions_test.rs (L2711-2740)
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
