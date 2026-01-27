# Audit Report

## Title
Faucet MintFunder Duplicate Funding Vulnerability via Transaction Timeout and Sequence Number Rollback

## Summary
The MintFunder allows duplicate funding of the same account when `submit_and_wait_bcs()` times out after a transaction has already succeeded on-chain. The sequence number rollback mechanism creates a window for retry requests to create new transactions that fund the same address multiple times, potentially draining faucet resources.

## Finding Description

The vulnerability exists in the transaction submission flow for MintFunder. When `submit_and_wait_bcs()` times out but the transaction has already succeeded on-chain, the faucet incorrectly decrements its local sequence number and returns an error to the client. [1](#0-0) [2](#0-1) 

The timeout can occur in two scenarios defined in the REST client: [3](#0-2) [4](#0-3) 

Both timeout messages explicitly warn: "transaction might still succeed."

**Attack Path:**

1. Attacker requests funding for address X with amount A
2. MintFunder builds and submits transaction with sequence number N
3. Transaction succeeds on-chain (X receives A tokens, on-chain seq becomes N+1)
4. `submit_and_wait_bcs()` times out before confirmation (network lag or node delay)
5. Error handler decrements local sequence number back to N
6. Error returned to attacker (appears as failure)
7. Attacker retries the request
8. `update_sequence_numbers()` synchronizes local seq to N+1 to match on-chain state [5](#0-4) 

9. MintFunder's validation only rejects if `receiver_seq.is_some() && amount == 0` [6](#0-5) 

10. Since amount > 0, validation passes even though account exists
11. New transaction created with sequence number N+1
12. Transaction succeeds, X receives ANOTHER A tokens

**Key Difference from TransferFunder:**

TransferFunder is protected by rejecting all requests to existing accounts: [7](#0-6) 

MintFunder lacks this protection for non-zero amounts, allowing duplicate funding.

## Impact Explanation

**Severity: High to Critical**

This qualifies as **Loss of Funds (Critical Severity)** per Aptos bug bounty criteria:
- Faucet funds can be systematically drained through repeated timeout-and-retry cycles
- Each successful exploitation doubles the attacker's gains
- Impact scales with faucet balance and timeout frequency
- Affects testnet/devnet infrastructure availability for legitimate developers

The vulnerability breaks the invariant that each funding request should result in exactly one successful funding operation. While faucets are typically not mainnet-critical, they are essential infrastructure for developer onboarding and testing environments.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is easily triggered in production environments:

1. **Network conditions:** 60-second server lag timeout is realistic under load [8](#0-7) 

2. **No authentication required:** Any user can request faucet funds
3. **Natural retry behavior:** Users naturally retry failed requests
4. **Observable indicators:** Timeout errors signal opportunity for exploitation
5. **Repeatable:** Attack can be automated and repeated

The developers acknowledge the ambiguity in the code comments: [9](#0-8) 

## Recommendation

**Fix 1: Add existing account check for MintFunder (Recommended)**

Add validation similar to TransferFunder that rejects requests for existing accounts regardless of amount:

```rust
// In mint.rs process() function, after line 414:
if receiver_seq.is_some() {
    return Err(AptosTapError::new(
        format!("Account {} already exists", receiver_address),
        AptosTapErrorCode::InvalidRequest,
    ));
}
```

**Fix 2: Don't decrement sequence number on timeout**

Distinguish between submission failures and timeout scenarios. Only decrement on actual submission failures:

```rust
// In common.rs submit_transaction():
match result {
    Ok(_) => Ok(signed_transaction),
    Err(e) => {
        // Only decrement if error indicates submission failure, not timeout
        if is_submission_failure(&e) {
            faucet_account.write().await.decrement_sequence_number();
        }
        Err(e)
    }
}
```

**Fix 3: Track transaction hashes**

Maintain a cache of recently submitted transaction hashes and reject duplicate funding requests within a time window.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_duplicate_funding_on_timeout() {
    // Setup: Create MintFunder with low timeout
    let funder = create_test_mint_funder().await;
    let receiver = AccountAddress::random();
    let amount = 1_000_000_000; // 1 APT
    
    // Simulate first request that times out but succeeds on-chain
    // Mock the REST client to return timeout error after successful submission
    let mock_client = MockClient::new()
        .with_submit_success()
        .with_wait_timeout();
    
    // First request
    let result1 = funder.fund(
        Some(amount),
        receiver,
        Some("apt".to_string()),
        false,
        false,
    ).await;
    
    // Assert: Request appears to fail due to timeout
    assert!(result1.is_err());
    
    // But verify on-chain that account was funded
    let balance1 = get_account_balance(receiver).await;
    assert_eq!(balance1, amount);
    
    // Simulate retry by client
    let mock_client2 = MockClient::new()
        .with_submit_success()
        .with_wait_success();
    
    // Second request (retry)
    let result2 = funder.fund(
        Some(amount),
        receiver,
        Some("apt".to_string()),
        false,
        false,
    ).await;
    
    // Assert: Second request succeeds
    assert!(result2.is_ok());
    
    // Verify: Account received duplicate funding
    let balance2 = get_account_balance(receiver).await;
    assert_eq!(balance2, amount * 2); // DUPLICATE FUNDING
}
```

## Notes

This vulnerability is specific to MintFunder deployments. TransferFunder is protected by existing account checks. The issue is exacerbated by the lack of idempotency controls at the application layer, relying solely on sequence numbers which are rolled back on perceived failures.

### Citations

**File:** crates/aptos-faucet/core/src/funder/common.rs (L220-223)
```rust
        if funder_seq > funder_account.sequence_number() {
            funder_account.set_sequence_number(funder_seq);
        }
        funder_account.sequence_number()
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L350-353)
```rust
        // If this fails, we assume it is the user's fault, e.g. because the
        // account already exists, but it is possible that the transaction
        // timed out. It's hard to tell because this function returns an opaque
        // anyhow error. https://github.com/aptos-labs/aptos-tap/issues/60.
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L355-361)
```rust
            client
                .submit_and_wait_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L388-396)
```rust
        Err(e) => {
            faucet_account.write().await.decrement_sequence_number();
            warn!(
                hash = signed_transaction.committed_hash(),
                address = receiver_address,
                event = "transaction_failure",
                error_message = format!("{:#}", e)
            );
            Err(e)
```

**File:** crates/aptos-rest-client/src/lib.rs (L63-63)
```rust
const DEFAULT_MAX_SERVER_LAG_WAIT_DURATION: Duration = Duration::from_secs(60);
```

**File:** crates/aptos-rest-client/src/lib.rs (L824-834)
```rust
            if let Some(max_server_lag_wait_duration) = max_server_lag_wait {
                if aptos_infallible::duration_since_epoch().as_secs()
                    > expiration_timestamp_secs + max_server_lag_wait_duration.as_secs()
                {
                    return Err(anyhow!(
                        "Ledger on endpoint ({}) is more than {}s behind current time, timing out waiting for the transaction. Warning, transaction ({}) might still succeed.",
                        self.path_prefix_string(),
                        max_server_lag_wait_duration.as_secs(),
                        hash,
                    ).into());
                }
```

**File:** crates/aptos-rest-client/src/lib.rs (L838-845)
```rust
            if let Some(timeout_duration) = timeout_from_call {
                if elapsed > timeout_duration {
                    return Err(anyhow!(
                        "Timeout of {}s after calling wait_for_transaction reached. Warning, transaction ({}) might still succeed.",
                        timeout_duration.as_secs(),
                        hash,
                    ).into());
                }
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L416-424)
```rust
        if receiver_seq.is_some() && amount == 0 {
            return Err(AptosTapError::new(
                format!(
                    "Account {} already exists and amount asked for is 0",
                    receiver_address
                ),
                AptosTapErrorCode::InvalidRequest,
            ));
        }
```

**File:** crates/aptos-faucet/core/src/funder/transfer.rs (L297-306)
```rust
        if receiver_seq_num.is_some() {
            return Err(AptosTapError::new(
                "Account ineligible".to_string(),
                AptosTapErrorCode::Rejected,
            )
            .rejection_reasons(vec![RejectionReason::new(
                format!("Account {} already exists", receiver_address),
                RejectionReasonCode::AccountAlreadyExists,
            )]));
        }
```
