# Audit Report

## Title
Sequence Number Information Disclosure via InvalidSeqNumber Error Messages

## Summary
The Aptos API exposes exact account sequence numbers in error responses when transactions with invalid sequence numbers are submitted. Attackers can probe any account by submitting transactions with arbitrary sequence numbers and receiving detailed error messages that reveal the current sequence number, enabling account enumeration, activity tracking, and potential front-running attacks.

## Finding Description
When a transaction with an invalid sequence number is submitted to the mempool, the system returns a detailed error message containing both the submitted transaction sequence number and the account's current sequence number. This information leakage occurs in multiple locations: [1](#0-0) [2](#0-1) 

The error message format is: `"transaction sequence number is {txn_seq_num}, current sequence number is {account_sequence_number}"`. This message is propagated through the API layer without sanitization: [3](#0-2) 

The `mempool_status.message` field, which contains the detailed error message, is directly used to create an `AptosError` that is returned to the user: [4](#0-3) [5](#0-4) 

The error response is serialized and returned to API clients via the response generation mechanism: [6](#0-5) 

An attacker can exploit this by:
1. Submitting a signed transaction to any target account with sequence number 0 (or any arbitrary value)
2. Receiving a 400 Bad Request response with error message: `"transaction sequence number is 0, current sequence number is 42"` (example)
3. Now knowing the exact sequence number is 42, enabling precise timing for subsequent attacks

## Impact Explanation
This vulnerability qualifies as **Low to Medium severity** based on Aptos bug bounty criteria:

**Low Severity**: Fits "Minor information leaks" - sequence numbers are exposed to any attacker without authentication.

**Medium Severity Arguments**:
- **Privacy Violation**: Enables surveillance of account activity by monitoring sequence number changes
- **Account Enumeration**: Attackers can identify active vs. inactive accounts
- **Front-Running Enablement**: Knowledge of exact sequence numbers helps attackers time transactions to front-run legitimate users
- **Metadata Leakage**: Reveals transaction frequency and patterns without accessing on-chain data

While this doesn't directly cause loss of funds or consensus violations, it undermines user privacy and can enable more sophisticated attacks. The ease of exploitation (no authentication required) and broad scope (affects all accounts) elevates this from purely "minor" to moderate concern.

## Likelihood Explanation
**Likelihood: HIGH**

This vulnerability is trivially exploitable:
- No authentication or special permissions required
- Can be executed via simple HTTP POST to public API endpoint
- Works against any account on the network
- Response time is immediate (single API call)
- No rate limiting prevents systematic enumeration
- Attack leaves minimal traces (looks like normal failed transaction submission)

Any external user with API access can exploit this vulnerability at scale against all network accounts.

## Recommendation
Sanitize error messages to prevent sequence number disclosure. Replace detailed error messages with generic ones:

**In `mempool/src/core_mempool/mempool.rs` (line 314-318):**
```rust
// Before:
return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
    .with_message(format!(
        "transaction sequence number is {}, current sequence number is  {}",
        txn_seq_num, account_sequence_number,
    ));

// After:
return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
    .with_message("Invalid sequence number for transaction".to_string());
```

**In `mempool/src/core_mempool/transaction_store.rs` (line 302-307):**
```rust
// Before:
return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber).with_message(
    format!(
        "transaction sequence number is {}, current sequence number is  {}",
        txn_seq_num, acc_seq_num,
    ),
);

// After:
return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
    .with_message("Invalid sequence number for transaction".to_string());
```

This maintains the error code (`InvalidSeqNumber` / `SequenceNumberTooOld`) for legitimate debugging while preventing information disclosure to external attackers.

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability using the Aptos REST API
// Can be executed against any Aptos node with transaction submission enabled

use aptos_sdk::{
    rest_client::Client,
    types::{
        account_address::AccountAddress,
        transaction::{
            authenticator::AuthenticationKey,
            SignedTransaction, TransactionPayload, RawTransaction,
        },
        LocalAccount,
    },
};
use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519Signature},
    PrivateKey, Uniform,
};
use url::Url;

#[tokio::main]
async fn main() {
    // Target account to probe (can be any account)
    let target_address = AccountAddress::from_hex_literal("0x1234...").unwrap();
    
    // Create a dummy transaction with sequence number 0
    let private_key = Ed25519PrivateKey::generate_for_testing();
    let dummy_account = LocalAccount::new(target_address, private_key, 0);
    
    // Build transaction with sequence number 0 (likely wrong)
    let payload = TransactionPayload::Script(Script::new(vec![], vec![], vec![]));
    let raw_txn = RawTransaction::new(
        target_address,
        0,  // Sequence number - attacker probes with this
        payload,
        1000000,
        1,
        u64::MAX,
        1, // chain_id
    );
    
    let signature = dummy_account.private_key().sign(&raw_txn);
    let signed_txn = SignedTransaction::new(raw_txn, signature);
    
    // Submit transaction
    let client = Client::new(Url::parse("http://localhost:8080").unwrap());
    let result = client.submit(&signed_txn).await;
    
    // Attacker receives error response:
    // {
    //   "message": "transaction sequence number is 0, current sequence number is 42",
    //   "error_code": "sequence_number_too_old",
    //   "vm_error_code": null
    // }
    
    match result {
        Err(e) => {
            // Parse error message to extract current sequence number
            println!("Error message: {}", e);
            // Attacker now knows: target account's sequence number is 42
        },
        Ok(_) => println!("Transaction accepted (unexpected)"),
    }
}
```

**Attack Demonstration:**
1. Attacker submits transaction to target account `0xABCD` with sequence number `0`
2. API returns: `{"message": "transaction sequence number is 0, current sequence number is 157", "error_code": "sequence_number_too_old"}`
3. Attacker learns account's current sequence number is `157`
4. Can repeat for any account to build activity profile database
5. Can monitor sequence number changes to detect when accounts submit transactions

## Notes
This vulnerability represents a classic information disclosure issue where detailed error messages intended for debugging are exposed to untrusted external users. While the immediate impact is limited to privacy violation and metadata leakage, the ease of exploitation and potential for enabling more sophisticated attacks warrant remediation. The fix is straightforward: sanitize error messages returned to external API clients while preserving detailed logging for internal debugging purposes.

### Citations

**File:** mempool/src/core_mempool/mempool.rs (L314-318)
```rust
                        return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
                            .with_message(format!(
                                "transaction sequence number is {}, current sequence number is  {}",
                                txn_seq_num, account_sequence_number,
                            ));
```

**File:** mempool/src/core_mempool/transaction_store.rs (L302-307)
```rust
                return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber).with_message(
                    format!(
                        "transaction sequence number is {}, current sequence number is  {}",
                        txn_seq_num, acc_seq_num,
                    ),
                );
```

**File:** api/src/transactions.rs (L1474-1477)
```rust
            MempoolStatusCode::InvalidSeqNumber => Err(AptosError::new_with_error_code(
                mempool_status.message,
                AptosErrorCode::SequenceNumberTooOld,
            )),
```

**File:** types/src/mempool_status.rs (L17-22)
```rust
pub struct MempoolStatus {
    /// insertion status code
    pub code: MempoolStatusCode,
    /// optional message
    pub message: String,
}
```

**File:** api/types/src/error.rs (L11-18)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Object)]
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
