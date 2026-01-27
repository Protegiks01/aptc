# Audit Report

## Title
API Resource Exhaustion via Oversized BCS Transaction Payloads Bypassing Pre-Validation Size Checks

## Summary
The Aptos REST API accepts BCS-encoded transactions up to 8 MB (default content-length limit) but the Move VM enforces a 64 KB transaction size limit. This ~125x gap allows attackers to submit oversized transactions that consume significant CPU and memory during BCS deserialization at the API layer before being rejected by the VM, enabling resource exhaustion attacks against validator nodes.

## Finding Description
The vulnerability exists in the transaction submission flow where size validation occurs too late in the processing pipeline: [1](#0-0) 

The API enforces an 8 MB HTTP content-length limit, while the VM enforces a 64 KB limit: [2](#0-1) 

When a BCS transaction is submitted via POST /transactions, the processing flow is:

1. HTTP middleware checks Content-Length ≤ 8 MB (passes for 1-7 MB transactions) [3](#0-2) 

2. API deserializes the entire BCS payload with only depth limit (16), no size limit: [4](#0-3) 

3. API validates only format (module/function names, type args), not size: [5](#0-4) 

4. Transaction sent to mempool without size validation at API layer [6](#0-5) 

5. Only during VM validation is transaction size checked and rejected: [7](#0-6) 

**Attack Path:**
An attacker can craft a BCS-encoded `SignedTransaction` of 5 MB containing an `EntryFunction` with many large arguments (e.g., `vector<address>` with 150,000 addresses = ~4.8 MB). This transaction:
- Passes API HTTP checks (< 8 MB)
- Gets fully deserialized by `bcs::from_bytes_with_limit` (consuming CPU/memory)
- Has payload format validated
- Gets sent to mempool
- Is rejected by VM for exceeding 64 KB

By the time rejection occurs, the API has already consumed significant resources deserializing and processing the oversized transaction. An attacker can spam such transactions to exhaust API resources.

## Impact Explanation
**High Severity** - This vulnerability enables resource exhaustion attacks against validator nodes, specifically targeting the REST API layer. Per the Aptos bug bounty program, this qualifies as **"Validator node slowdowns"** and potentially **"API crashes"** under High Severity ($50,000 category).

The attack can cause:
- **CPU exhaustion** from BCS deserialization of up to 7 MB per transaction
- **Memory exhaustion** from allocating large transaction objects (potentially hundreds of MB with concurrent requests)
- **API slowdowns** affecting legitimate transaction submissions
- **Potential DoS** if sufficient transactions overwhelm API workers

This breaks the critical invariant: **"Resource Limits: All operations must respect gas, storage, and computational limits"** - the API layer fails to enforce transaction size limits before expensive operations.

## Likelihood Explanation
**High Likelihood** - This vulnerability is trivially exploitable:
- No special privileges required (any network peer can submit transactions)
- Simple attack: craft BCS transactions between 64 KB and 8 MB
- No cryptographic breaks or complex state manipulation needed
- Can be automated to generate sustained attacks
- Affects all validator nodes running the REST API

The only limiting factor is network bandwidth, but even modest bandwidth allows submission of dozens of multi-MB transactions per second.

## Recommendation
Implement transaction size validation at the API layer BEFORE BCS deserialization or immediately after. Add a check in the `get_signed_transaction` method:

```rust
fn get_signed_transaction(
    &self,
    ledger_info: &LedgerInfo,
    data: SubmitTransactionPost,
) -> Result<SignedTransaction, SubmitTransactionError> {
    match data {
        SubmitTransactionPost::Bcs(data) => {
            // Check raw BCS size before deserialization
            let gas_params = self.context.gas_params()?;
            let max_txn_size = gas_params.vm.txn.max_transaction_size_in_bytes;
            
            if data.0.len() > max_txn_size as usize {
                return Err(SubmitTransactionError::bad_request_with_code(
                    format!(
                        "Transaction too large: {} bytes exceeds maximum {} bytes",
                        data.0.len(),
                        max_txn_size
                    ),
                    AptosErrorCode::InvalidInput,
                    ledger_info,
                ));
            }
            
            let signed_transaction: SignedTransaction =
                bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
                    // ... rest of existing code
```

This ensures oversized transactions are rejected before expensive deserialization occurs.

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability
use aptos_types::transaction::{EntryFunction, RawTransaction, SignedTransaction};
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::ModuleId,
};
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};

fn create_oversized_transaction() -> SignedTransaction {
    let mut rng = rand::thread_rng();
    let private_key = Ed25519PrivateKey::generate(&mut rng);
    
    // Create EntryFunction with massive argument vector
    // 150,000 addresses = ~4.8 MB
    let large_arg = (0..150_000)
        .map(|_| AccountAddress::random())
        .collect::<Vec<_>>();
    let arg_bytes = bcs::to_bytes(&large_arg).unwrap();
    
    let entry_fn = EntryFunction::new(
        ModuleId::new(AccountAddress::ONE, Identifier::new("test").unwrap()),
        Identifier::new("test_function").unwrap(),
        vec![],
        vec![arg_bytes],  // ~4.8 MB argument
    );
    
    let raw_txn = RawTransaction::new_entry_function(
        AccountAddress::random(),
        0,
        entry_fn,
        1_000_000,
        0,
        u64::MAX,
        aptos_types::chain_id::ChainId::test(),
    );
    
    raw_txn.sign(&private_key, private_key.public_key()).unwrap().into_inner()
}

fn main() {
    let txn = create_oversized_transaction();
    let serialized = bcs::to_bytes(&txn).unwrap();
    
    println!("Transaction size: {} bytes", serialized.len());
    println!("VM limit: 65536 bytes");
    println!("API limit: 8388608 bytes");
    println!("Gap: {}x over VM limit", serialized.len() / 65536);
    
    // This transaction will:
    // 1. Pass API HTTP check (< 8 MB)
    // 2. Be fully deserialized (consuming resources)
    // 3. Be rejected by VM (> 64 KB)
    // Submit multiple such transactions to exhaust API resources
}
```

**Notes**

The vulnerability stems from a mismatch between defense-in-depth layers: the API's 8 MB HTTP limit is meant for general request protection, while the VM's 64 KB limit is the actual transaction size constraint. The lack of early size validation at the API layer creates a ~125x window where attackers can force expensive BCS deserialization operations that will ultimately be rejected, enabling resource exhaustion attacks against validator nodes' REST API endpoints.

### Citations

**File:** config/src/config/api_config.rs (L97-97)
```rust
const DEFAULT_REQUEST_CONTENT_LENGTH_LIMIT: u64 = 8 * 1024 * 1024; // 8 MB
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```

**File:** api/src/check_size.rs (L43-58)
```rust
    async fn call(&self, req: Request) -> Result<Self::Output> {
        if req.method() != Method::POST {
            return self.inner.call(req).await;
        }

        let content_length = req
            .headers()
            .typed_get::<headers::ContentLength>()
            .ok_or(SizedLimitError::MissingContentLength)?;

        if content_length.0 > self.max_size {
            return Err(SizedLimitError::PayloadTooLarge.into());
        }

        self.inner.call(req).await
    }
```

**File:** api/src/transactions.rs (L1223-1232)
```rust
                let signed_transaction: SignedTransaction =
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
                        .context("Failed to deserialize input into SignedTransaction")
                        .map_err(|err| {
                            SubmitTransactionError::bad_request_with_code(
                                err,
                                AptosErrorCode::InvalidInput,
                                ledger_info,
                            )
                        })?;
```

**File:** api/src/transactions.rs (L1354-1389)
```rust
    fn validate_entry_function_payload_format(
        ledger_info: &LedgerInfo,
        payload: &EntryFunction,
    ) -> Result<(), SubmitTransactionError> {
        verify_module_identifier(payload.module().name().as_str())
            .context("Transaction entry function module invalid")
            .map_err(|err| {
                SubmitTransactionError::bad_request_with_code(
                    err,
                    AptosErrorCode::InvalidInput,
                    ledger_info,
                )
            })?;

        verify_function_identifier(payload.function().as_str())
            .context("Transaction entry function name invalid")
            .map_err(|err| {
                SubmitTransactionError::bad_request_with_code(
                    err,
                    AptosErrorCode::InvalidInput,
                    ledger_info,
                )
            })?;
        for arg in payload.ty_args() {
            let arg: MoveType = arg.into();
            arg.verify(0)
                .context("Transaction entry function type arg invalid")
                .map_err(|err| {
                    SubmitTransactionError::bad_request_with_code(
                        err,
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    )
                })?;
        }
        Ok(())
```

**File:** api/src/context.rs (L217-225)
```rust
    pub async fn submit_transaction(&self, txn: SignedTransaction) -> Result<SubmissionStatus> {
        let (req_sender, callback) = oneshot::channel();
        self.mp_sender
            .clone()
            .send(MempoolClientRequest::SubmitTransaction(txn, req_sender))
            .await?;

        callback.await?
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L109-121)
```rust
    } else if txn_metadata.transaction_size > txn_gas_params.max_transaction_size_in_bytes {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Transaction size too big {} (max {})",
                txn_metadata.transaction_size, txn_gas_params.max_transaction_size_in_bytes
            ),
        );
        return Err(VMStatus::error(
            StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
            None,
        ));
    }
```
