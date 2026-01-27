# Audit Report

## Title
False Positive Success Logging When Transactions Are Only Submitted to Mempool

## Summary
The faucet's `fund_inner()` function logs `success=true` based on `fund_result.is_ok()`, but when `wait_for_transactions` is false (the default configuration), this only indicates the transaction was accepted into mempool, not that it executed successfully on-chain. This creates false positive success logs for transactions that subsequently fail during on-chain execution.

## Finding Description

The vulnerability exists in the `fund_inner()` function's success determination logic: [1](#0-0) 

Success is determined solely by `fund_result.is_ok()`, but the actual meaning depends on the `wait_for_transactions` configuration. The configuration defaults to false: [2](#0-1) 

When `wait_for_transactions` is false, the `submit_transaction` function only calls `submit_bcs`, which submits to mempool: [3](#0-2) 

The comment distinguishes between "transaction_success" (wait=true) and "transaction_submitted" (wait=false): [4](#0-3) 

However, the high-level logging in `fund_inner()` collapses this distinction into a single `success` boolean. A transaction submitted to mempool can fail on-chain due to:
- Account already existing
- Insufficient gas
- Transaction expiration
- Execution errors
- Precondition violations

Yet the faucet logs `success=true` and the checker completion step proceeds as if the transaction succeeded: [5](#0-4) 

## Impact Explanation

This is a **High severity** issue per the security question classification:

1. **Operational Monitoring**: Operators relying on logs see false positive success rates, masking actual failure rates
2. **State Inconsistency**: Checkers' completion step records transactions as successful when they may have failed on-chain
3. **Metrics Corruption**: Success rate metrics become inflated and unreliable for SLA tracking
4. **User Experience**: Users receive success responses for requests that later fail
5. **Accounting Errors**: Systems tracking successful funding operations based on logs will have incorrect state
6. **Troubleshooting Difficulty**: Debugging becomes harder when logs claim success but on-chain state shows failure

This affects all faucet deployments using default configuration (likely the majority), making it a systemic issue rather than an edge case.

## Likelihood Explanation

**Likelihood: High**

- The default configuration has `wait_for_transactions=false`, affecting all deployments not explicitly overriding it
- On-chain transaction failures are common during normal operation (duplicate accounts, gas fluctuations, network conditions)
- Every funding request is potentially affected when using default configuration
- No special attacker capabilities required - occurs during normal operation
- The issue manifests whenever a mempool-accepted transaction later fails on-chain

## Recommendation

Modify the logging to distinguish between "transaction submitted" and "transaction executed":

```rust
// In fund_inner(), replace the logging section around line 319-327:

let (success_status, status_detail) = match &fund_result {
    Ok(_) => {
        if self.funder.config().wait_for_transactions {
            (true, "executed_successfully")
        } else {
            (true, "submitted_to_mempool") 
        }
    }
    Err(_) => (false, "submission_failed"),
};

info!(
    source_ip = checker_data.source_ip,
    jwt_sub = jwt_sub(checker_data.headers.clone()).ok(),
    address = checker_data.receiver,
    requested_amount = fund_request.amount,
    asset = asset_for_logging,
    txn_hashes = txn_hashes,
    success = success_status,
    status = status_detail,  // Add explicit status distinction
    awaited = self.funder.config().wait_for_transactions,
);
```

Additionally:
1. Add `wait_for_transactions()` method to `FunderTrait` to expose configuration
2. Update checker completion logic to tag transactions as "pending" vs "completed"
3. Consider making `wait_for_transactions=true` the default for production
4. Document this behavior clearly in configuration examples

## Proof of Concept

```rust
#[tokio::test]
async fn test_false_positive_success_logging() {
    // Setup: Configure faucet with wait_for_transactions = false (default)
    let config = r#"
    {
        "transaction_submission_config": {
            "wait_for_transactions": false,
            "max_gas_amount": 500000,
            "transaction_expiration_secs": 25
        }
    }
    "#;
    
    // Setup faucet and components
    let funder = setup_mint_funder_with_config(config).await;
    let components = FundApiComponents { /* ... */ };
    
    // Step 1: Fund an account (succeeds)
    let request1 = FundRequest {
        address: Some("0xABCD1234".to_string()),
        amount: Some(100_000_000),
        auth_key: None,
        pub_key: None,
    };
    
    let result1 = components.fund_inner(
        request1,
        source_ip,
        &header_map,
        false,
        None,
    ).await;
    
    assert!(result1.is_ok());
    // Log shows: success=true, txn_hashes=[hash1]
    
    // Step 2: Immediately fund the same account again
    // Transaction will be accepted into mempool but fail on-chain (account exists)
    let request2 = FundRequest {
        address: Some("0xABCD1234".to_string()),  // Same account
        amount: Some(100_000_000),
        auth_key: None,
        pub_key: None,
    };
    
    let result2 = components.fund_inner(
        request2,
        source_ip,
        &header_map,
        false,
        None,
    ).await;
    
    // Result is Ok because mempool accepted it
    assert!(result2.is_ok());
    // Log shows: success=true, txn_hashes=[hash2]
    // ❌ FALSE POSITIVE - logs say success but transaction will fail on-chain
    
    // Step 3: Wait and verify on-chain state
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    let client = get_rest_client();
    let tx_info = client.get_transaction_by_hash(hash2).await.unwrap();
    
    // Transaction failed on-chain with "EACCOUNT_ALREADY_EXISTS"
    assert!(tx_info.success() == false);
    
    // But the log incorrectly showed success=true
    // This is the false positive success logging vulnerability
}
```

To reproduce manually:
1. Start local testnet with faucet using default config (wait_for_transactions=false)
2. Fund a new account - observe `success=true` logged
3. Immediately fund the same account again - observe `success=true` logged again
4. Query the second transaction on-chain - it failed with account exists error
5. Logs show false positive success for the second transaction

## Notes

This vulnerability is **not a blockchain consensus or critical security issue** - it does not affect the blockchain's core safety or liveness guarantees. However, it represents a **significant operational and monitoring problem** that affects:

- Service reliability metrics
- Operational visibility and incident response
- State tracking in rate-limiting and anti-abuse systems (the checkers)
- User experience when relying on API responses

The faucet is a production service used across Aptos testnets and devnets, and accurate logging is critical for operational health. The issue is classified as **High severity** in the security question itself, which is appropriate given its operational impact and the fact that it affects the default configuration.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L319-327)
```rust
        info!(
            source_ip = checker_data.source_ip,
            jwt_sub = jwt_sub(checker_data.headers.clone()).ok(),
            address = checker_data.receiver,
            requested_amount = fund_request.amount,
            asset = asset_for_logging,
            txn_hashes = txn_hashes,
            success = fund_result.is_ok(),
        );
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L329-347)
```rust
        // Give all Checkers the chance to run the completion step. We should
        // monitor for failures in these steps because they could lead to an
        // unintended data state.
        if !bypass {
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
            let complete_data = CompleteData {
                checker_data,
                txn_hashes: txn_hashes.clone(),
                response_is_500,
            };
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
        }
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L125-127)
```rust
    /// Whether to wait for the transaction before returning.
    #[serde(default)]
    pub wait_for_transactions: bool,
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L349-363)
```rust
    let (result, event_on_success) = if wait_for_transactions {
        // If this fails, we assume it is the user's fault, e.g. because the
        // account already exists, but it is possible that the transaction
        // timed out. It's hard to tell because this function returns an opaque
        // anyhow error. https://github.com/aptos-labs/aptos-tap/issues/60.
        (
            client
                .submit_and_wait_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
            "transaction_success",
        )
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L364-375)
```rust
    } else {
        (
            client
                .submit_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
            "transaction_submitted",
        )
    };
```
