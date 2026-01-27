# Audit Report

## Title
Rate Limit Inconsistency in Faucet: Transaction Timeouts Incorrectly Treated as Client Errors

## Summary
The Aptos Faucet's `fund_inner()` function incorrectly classifies transaction timeout errors as client errors (HTTP 403) instead of server errors (HTTP 500), causing rate limit counters to unfairly penalize users when transactions time out. This creates a data consistency issue where the rate limiting state doesn't accurately reflect whether users successfully received funds.

## Finding Description
The vulnerability exists in the transaction submission flow when `wait_for_transactions` is enabled. The `submit_transaction()` function maps all errors from `client.submit_and_wait_bcs()` to `AptosTapErrorCode::TransactionFailed`, which returns HTTP 403 (FORBIDDEN). [1](#0-0) 

This means transaction timeouts (which should be server errors) are misclassified as client errors. The code even acknowledges this issue in a comment: [2](#0-1) 

In `fund_inner()`, the `response_is_500` flag is determined solely by checking if the error status is a server error: [3](#0-2) 

Since `TransactionFailed` maps to HTTP 403, timeouts result in `response_is_500 = false`: [4](#0-3) 

Both rate limiting implementations only decrement counters for server errors: [5](#0-4) [6](#0-5) 

**Exploitation Scenario:**
1. User requests funds from faucet
2. Transaction is submitted to blockchain (gets transaction hash)
3. Faucet times out waiting for confirmation
4. Error returned as `TransactionFailed` (403) instead of `TransactionTimedOut` (500)
5. Rate limiter treats this as client error and doesn't decrement counter
6. User's rate limit quota is consumed even though they may not have received funds
7. User cannot retry because they've hit their limit

## Impact Explanation
This is a **Medium Severity** issue per the Aptos bug bounty criteria, falling under "State inconsistencies requiring intervention" and potentially "Limited funds loss or manipulation."

**Impact on Users:**
- Legitimate users are unfairly penalized when network congestion or infrastructure issues cause timeouts
- Users may be locked out of the faucet even though their transactions failed
- In high-load scenarios, many users could simultaneously hit this issue, effectively creating a denial of service

**Scope Limitation:**
This vulnerability is limited to the **Aptos Faucet service** (used for testnet/devnet token distribution) and does NOT affect:
- Consensus mechanisms
- Move VM execution
- On-chain state management  
- Mainnet validator operations
- Core blockchain security

However, the faucet is a critical developer tool, and its rate limiting integrity matters for fair resource distribution.

## Likelihood Explanation
**High Likelihood** - This occurs automatically whenever:
- Network latency increases
- Blockchain is under high load
- Faucet infrastructure experiences delays
- Transaction processing takes longer than the configured timeout

The issue is systematic rather than requiring attacker sophistication. It affects normal operations during degraded performance conditions.

## Recommendation
Distinguish between transaction failures and timeouts by properly using the `TransactionTimedOut` error code:

```rust
// In crates/aptos-faucet/core/src/funder/common.rs
let (result, event_on_success) = if wait_for_transactions {
    (
        match client.submit_and_wait_bcs(&signed_transaction).await {
            Ok(response) => Ok(()),
            Err(e) => {
                // Check if this is a timeout vs actual transaction failure
                let error_msg = format!("{:#}", e);
                if error_msg.contains("timeout") || error_msg.contains("deadline exceeded") {
                    Err(AptosTapError::new_with_error_code(
                        e, 
                        AptosTapErrorCode::TransactionTimedOut
                    ))
                } else {
                    Err(AptosTapError::new_with_error_code(
                        e,
                        AptosTapErrorCode::TransactionFailed
                    ))
                }
            }
        },
        "transaction_success",
    )
} else {
    // ... existing code
}
```

Additionally, consider including transaction hashes in error responses when transactions were submitted:

```rust
// In crates/aptos-faucet/core/src/funder/common.rs
Err(e) => {
    faucet_account.write().await.decrement_sequence_number();
    let txn_hash = signed_transaction.committed_hash().to_hex();
    Err(e.txn_hashes(vec![txn_hash]))
}
```

## Proof of Concept
```rust
// Test case demonstrating the issue
#[tokio::test]
async fn test_timeout_rate_limit_inconsistency() {
    // Setup faucet with rate limiting enabled
    let faucet = setup_test_faucet_with_rate_limits().await;
    let test_address = AccountAddress::random();
    
    // Configure faucet to wait for transactions with short timeout
    // This simulates a timeout scenario
    
    // Make first request
    let request = FundRequest {
        amount: Some(100_000_000),
        address: Some(test_address.to_hex_literal()),
        auth_key: None,
        pub_key: None,
    };
    
    // Induce timeout by delaying blockchain response
    // (would need to mock the client to simulate this)
    let result = faucet.fund_inner(request, source_ip, headers, false, None).await;
    
    // Verify:
    // 1. Error is TransactionFailed (403), not TransactionTimedOut (500)
    assert!(matches!(result, Err(e) if e.error_code == AptosTapErrorCode::TransactionFailed));
    
    // 2. Rate limit counter was NOT decremented
    // User cannot retry even though they didn't receive funds
    let retry_result = faucet.fund_inner(request, source_ip, headers, false, None).await;
    assert!(matches!(retry_result, Err(e) if e.error_code == AptosTapErrorCode::Rejected));
    // User is rejected due to rate limit even though first request timed out
}
```

## Notes
While this vulnerability is limited in scope to the faucet service and doesn't affect core blockchain operations, it represents a genuine data consistency issue in the rate limiting subsystem. The `TransactionTimedOut` error code already exists but is never used, suggesting this was an oversight in the implementation. The issue can cause legitimate user frustration and unfair resource distribution in testnet/devnet environments.

### Citations

**File:** crates/aptos-faucet/core/src/funder/common.rs (L349-362)
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
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L333-336)
```rust
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L174-180)
```rust
            AptosTapErrorCode::InvalidRequest
            | AptosTapErrorCode::AccountDoesNotExist
            | AptosTapErrorCode::EndpointNotEnabled => StatusCode::BAD_REQUEST,
            AptosTapErrorCode::Rejected
            | AptosTapErrorCode::SourceIpMissing
            | AptosTapErrorCode::TransactionFailed
            | AptosTapErrorCode::AuthTokenInvalid => StatusCode::FORBIDDEN,
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L93-102)
```rust
    async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
        if data.response_is_500 {
            *self
                .ip_to_requests_today
                .lock()
                .await
                .get_or_insert_mut(data.checker_data.source_ip, || 1) -= 1;
        }
        Ok(())
    }
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L308-311)
```rust
    async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
        if !data.response_is_500 {
            return Ok(());
        }
```
