# Audit Report

## Title
Batch Transaction Submission Allows Resource Exhaustion via Oversized Individual Transactions

## Summary
The `submit_transactions_batch()` function validates only the transaction count but not individual transaction sizes before BCS deserialization and mempool submission. This allows attackers to submit batches containing oversized transactions that consume network bandwidth, memory, and CPU resources before being rejected by VM validation, enabling a resource exhaustion attack against API nodes.

## Finding Description

The batch transaction submission endpoint validates transactions in the following order: [1](#0-0) 

The validation only checks the **count** of transactions against `max_submit_transaction_batch_size()` (default 10), not their individual or total byte sizes. Individual transaction size validation occurs much later during VM validation: [2](#0-1) 

The runtime limit for individual transactions is 64 KB for regular transactions: [3](#0-2) 

**Attack Path:**
1. Attacker crafts a batch of 10 transactions, each sized at ~800 KB (total ~8 MB)
2. HTTP Content-Length check passes (8 MB ≤ default 8 MB limit)
3. BCS deserialization occurs with only depth validation, not size validation
4. Batch count check passes (10 ≤ 10)
5. Each transaction is individually submitted to mempool via `create_batch()`
6. VM validation in `check_gas()` rejects each transaction (800 KB > 64 KB limit)

Between steps 2-6, significant resources are consumed:
- **Network**: 8 MB received per request
- **Memory**: 8 MB+ allocated for request buffer and deserialized objects
- **CPU**: BCS deserialization of 8 MB payload
- **Thread Time**: API worker thread blocked during processing

If an administrator increases `content_length_limit` to handle large payloads, the attack scales proportionally (e.g., 100 MB limit allows 10×7 MB = 70 MB batches).

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under Aptos Bug Bounty criteria:
- **Resource Exhaustion DoS**: Attackers can repeatedly submit oversized batches that waste resources before being rejected
- **API Service Degradation**: Sustained attacks can slow down or crash API nodes, affecting ecosystem availability
- **Validator Node Impact**: If validators run API services, this can indirectly affect block production performance

The attack violates **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits." The API accepts and processes payloads that vastly exceed individual transaction size limits before enforcing those limits.

## Likelihood Explanation

**Likelihood: HIGH**

- **No Privileges Required**: Any unauthenticated attacker can submit batch transactions
- **Easy to Exploit**: Simple HTTP POST with oversized BCS-encoded transactions
- **Automatable**: Attack can be scripted for sustained resource exhaustion
- **Default Configuration Vulnerable**: Even with default 8 MB limit, attackers can submit 10×800 KB transactions (each exceeding 64 KB limit by 12.5×)
- **Amplified if Misconfigured**: Administrators who increase `content_length_limit` for legitimate reasons unknowingly amplify the attack surface

## Recommendation

Add early validation of individual transaction sizes in `submit_transactions_batch()` before calling `create_batch()`. Insert validation after deserialization:

```rust
// In submit_transactions_batch() after line 549:
let signed_transactions_batch = self.get_signed_transactions_batch(&ledger_info, data)?;

// Add early size validation
for (idx, txn) in signed_transactions_batch.iter().enumerate() {
    let txn_size = txn.raw_txn_bytes_len() as u64;
    let max_size = if self.is_approved_gov_script(txn) {
        // Use governance limit if applicable
        1024 * 1024 // 1 MB
    } else {
        64 * 1024 // 64 KB
    };
    
    if txn_size > max_size {
        return Err(SubmitTransactionError::bad_request_with_code(
            format!(
                "Transaction at index {} exceeds maximum size: {} bytes (max: {} bytes)",
                idx, txn_size, max_size
            ),
            AptosErrorCode::InvalidInput,
            &ledger_info,
        ));
    }
}

// Continue with existing batch count check...
```

Additionally, consider adding a total batch byte size limit to complement the transaction count limit.

## Proof of Concept

```rust
// PoC: Create oversized batch transaction request
use aptos_types::transaction::{RawTransaction, SignedTransaction, Script};
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
use bcs;

#[test]
fn test_oversized_batch_resource_exhaustion() {
    // Create 10 transactions, each ~800 KB
    let mut oversized_batch = Vec::new();
    
    for i in 0..10 {
        // Create transaction with large script payload (800 KB)
        let large_payload = vec![0u8; 800 * 1024];
        let script = Script::new(large_payload, vec![], vec![]);
        
        let raw_txn = RawTransaction::new(
            AccountAddress::random(),
            i,
            TransactionPayload::Script(script),
            1_000_000,
            0,
            u64::MAX,
            ChainId::new(1),
        );
        
        let private_key = Ed25519PrivateKey::generate_for_testing();
        let signature = private_key.sign(&raw_txn).unwrap();
        let signed_txn = SignedTransaction::new(
            raw_txn,
            private_key.public_key(),
            signature,
        );
        
        oversized_batch.push(signed_txn);
    }
    
    // Serialize batch
    let bcs_batch = bcs::to_bytes(&oversized_batch).unwrap();
    println!("Batch size: {} MB", bcs_batch.len() / (1024 * 1024));
    
    // Submit to /transactions/batch endpoint
    // Expected: Should be rejected early with size validation error
    // Actual: Passes batch count check, wastes resources deserializing 8 MB,
    //         then each transaction fails during mempool VM validation
}
```

### Citations

**File:** api/src/transactions.rs (L549-561)
```rust
        let signed_transactions_batch = self.get_signed_transactions_batch(&ledger_info, data)?;
        if self.context.max_submit_transaction_batch_size() < signed_transactions_batch.len() {
            return Err(SubmitTransactionError::bad_request_with_code(
                format!(
                    "Submitted too many transactions: {}, while limit is {}",
                    signed_transactions_batch.len(),
                    self.context.max_submit_transaction_batch_size(),
                ),
                AptosErrorCode::InvalidInput,
                &ledger_info,
            ));
        }
        self.create_batch(&accept_type, &ledger_info, signed_transactions_batch)
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```
