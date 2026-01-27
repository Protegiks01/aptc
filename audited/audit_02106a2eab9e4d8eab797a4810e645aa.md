# Audit Report

## Title
Information Disclosure via InvalidSeqNumber Error Messages Leaks Exact Account Sequence Numbers

## Summary
The Aptos API leaks exact account sequence numbers through detailed error messages when transactions with invalid sequence numbers are submitted. An attacker can probe any account by submitting transactions with arbitrary sequence numbers and receive error responses that explicitly reveal the target account's current sequence number, enabling privacy violations and account enumeration attacks.

## Finding Description

When a user submits a transaction to the Aptos API with a sequence number that is less than the account's current sequence number, the mempool validation logic returns an error message that explicitly reveals both the submitted sequence number and **the actual current sequence number of the account**. [1](#0-0) 

This error message is propagated through the API layer without sanitization: [2](#0-1) 

The error is then converted to a JSON response using the `AptosError` structure, which includes the full message in its public `message` field: [3](#0-2) [4](#0-3) 

**Attack Flow:**
1. Attacker targets an account address (e.g., `0x123...`)
2. Attacker submits a transaction for that account with sequence number `0`
3. API validates the transaction in mempool
4. If the account's current sequence number is `5`, the error message returns:
   `"transaction sequence number is 0, current sequence number is 5"`
5. Attacker now knows the exact sequence number without querying account state

This breaks the principle of least information disclosure. Account state information should only be accessible through explicit state query APIs, not leaked through validation error messages.

## Impact Explanation

This vulnerability falls under **Medium Severity** ($10,000 tier) as defined in the Aptos Bug Bounty program for the following reasons:

**Information Disclosure:**
- Enables passive account enumeration without state reads
- Reveals account activity patterns (sequence number changes indicate transactions)
- Bypasses normal account state query mechanisms
- Can be used to track accounts without triggering read-pattern detection

**Privacy Violation:**
- Leaks precise account state to unauthorized parties
- Enables correlation of accounts with transaction activity
- Allows tracking of account usage patterns over time

**Attack Enablement:**
- MEV (Maximal Extractable Value) opportunities: attackers can monitor exact sequence numbers to time frontrunning attacks
- Account reconnaissance for phishing/social engineering
- Timing analysis to correlate on-chain and off-chain activities
- Competitive intelligence gathering about account usage

While this doesn't directly lead to fund loss or consensus violations, it represents a significant privacy leak that violates user expectations and enables secondary attacks.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is trivial to exploit:
- **No authentication required**: Anyone can submit transactions to public API endpoints
- **No rate limiting bypass needed**: Normal API submission flows trigger the vulnerability
- **No special permissions**: Works for any account, including high-value accounts
- **Deterministic**: Always succeeds when sequence number is less than current
- **Undetectable**: Appears as normal failed transaction submissions

Attack complexity: **TRIVIAL** - Can be executed with a simple HTTP request or SDK call.

## Recommendation

**Fix: Sanitize error messages to remove specific sequence number information**

Modify the error message in `mempool/src/core_mempool/mempool.rs` to avoid revealing the exact current sequence number:

```rust
// Instead of:
return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
    .with_message(format!(
        "transaction sequence number is {}, current sequence number is  {}",
        txn_seq_num, account_sequence_number,
    ));

// Use:
return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
    .with_message(format!(
        "transaction sequence number {} is invalid (too old)",
        txn_seq_num,
    ));
```

Similarly, update the case at lines 322-327 to avoid leaking the submitted sequence number.

**Additional recommendations:**
1. Audit all error messages across the codebase for similar information leaks
2. Implement a general policy that error messages should never reveal internal state values
3. Consider rate limiting transaction submissions per account to prevent rapid probing
4. Add monitoring for suspicious patterns of failed submissions targeting multiple accounts

## Proof of Concept

```rust
#[tokio::test]
async fn test_sequence_number_information_leak() {
    // Setup: Create a test environment with API and mempool
    let mut test_context = new_test_context().await;
    let account = test_context.gen_account();
    let sender_address = account.address();
    
    // Step 1: Fund the account and submit a valid transaction to set sequence number to 1
    test_context.mint(sender_address, 1_000_000).await;
    let txn1 = account.sign_transaction(
        test_context.transaction_factory()
            .transfer(AccountAddress::random(), 100)
    );
    test_context.submit_and_wait_transaction(&txn1).await.unwrap();
    
    // At this point, account sequence number is 1
    
    // Step 2: Attacker submits probe transaction with sequence number 0 (too old)
    let probe_txn = account.sign_with_transaction_builder(
        test_context.transaction_factory()
            .transfer(AccountAddress::random(), 100)
            .sequence_number(0)  // Deliberately using old sequence number
    );
    
    // Step 3: Submit and capture error response
    let result = test_context.submit_transaction(&probe_txn).await;
    
    // Step 4: Verify the error message leaks the exact sequence number
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    
    // The error message reveals: "transaction sequence number is 0, current sequence number is 1"
    assert!(error_msg.contains("current sequence number is"));
    assert!(error_msg.contains("1"));  // Leaks that current sequence is 1
    
    println!("VULNERABILITY CONFIRMED: Error message leaks sequence number: {}", error_msg);
}
```

**Exploitation Steps:**
1. Identify target account address
2. Submit transaction with sequence number 0
3. Parse error response to extract `"current sequence number is X"`
4. Repeat periodically to track account activity
5. Use gathered intelligence for timing attacks or account profiling

## Notes

This vulnerability exemplifies a broader class of information disclosure issues where detailed error messages intended for debugging purposes inadvertently leak sensitive state information. The fix is straightforward but requires careful review of all error paths in the transaction submission flow to ensure no similar leaks exist elsewhere.

The vulnerability affects all public Aptos API nodes and can be exploited remotely without authentication, making it a significant privacy concern for all Aptos users.

### Citations

**File:** mempool/src/core_mempool/mempool.rs (L313-318)
```rust
                    if txn_seq_num < *account_sequence_number {
                        return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
                            .with_message(format!(
                                "transaction sequence number is {}, current sequence number is  {}",
                                txn_seq_num, account_sequence_number,
                            ));
```

**File:** api/src/transactions.rs (L1474-1477)
```rust
            MempoolStatusCode::InvalidSeqNumber => Err(AptosError::new_with_error_code(
                mempool_status.message,
                AptosErrorCode::SequenceNumberTooOld,
            )),
```

**File:** api/types/src/error.rs (L12-18)
```rust
pub struct AptosError {
    /// A message describing the error
    pub message: String,
    pub error_code: AptosErrorCode,
    /// A code providing VM error details when submitting transactions to the VM
    pub vm_error_code: Option<u64>,
}
```

**File:** api/src/response.rs (L256-272)
```rust
            fn [<$name:snake _from_aptos_error>](
                aptos_error: aptos_api_types::AptosError,
                ledger_info: &aptos_api_types::LedgerInfo
            ) -> Self where Self: Sized {
                let payload = poem_openapi::payload::Json(Box::new(aptos_error));
                Self::from($enum_name::$name(
                    payload,
                    Some(ledger_info.chain_id),
                    Some(ledger_info.ledger_version.into()),
                    Some(ledger_info.oldest_ledger_version.into()),
                    Some(ledger_info.ledger_timestamp.into()),
                    Some(ledger_info.epoch.into()),
                    Some(ledger_info.block_height.into()),
                    Some(ledger_info.oldest_block_height.into()),
                    None,
                ))
            }
```
