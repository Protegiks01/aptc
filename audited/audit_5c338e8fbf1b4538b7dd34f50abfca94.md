# Audit Report

## Title
Indexer Transaction Filter Silently Bypasses Payload Filters for Script and WriteSet Transactions

## Summary
The `get_entry_function_payload_from_transaction_payload()` function in the indexer-grpc transaction filter uses a wildcard pattern that returns `None` for `ScriptPayload` and `WriteSetPayload` types. This causes the payload filter to be silently bypassed, allowing transactions with non-matching payload types to pass through filters that should reject them. No logging or error handling alerts operators to this filtering failure. [1](#0-0) 

## Finding Description
The filtering logic contains a critical flaw in how it handles transaction payloads. The protobuf `transaction_payload::Payload` enum includes four variants: `EntryFunctionPayload`, `ScriptPayload`, `WriteSetPayload`, and `MultisigPayload`. [2](#0-1) 

When a user sets up a filter specifying both sender and payload criteria (e.g., "transactions from address 0xABCD calling function 0x1::coin::transfer"), the `matches()` method attempts to validate both conditions. However, when the transaction payload is a `ScriptPayload` or `WriteSetPayload`, the extraction function returns `None` instead of rejecting the transaction. [3](#0-2) 

The critical flaw is at line 106: when `entry_function_payload` is `None` (due to the wildcard pattern), the code skips the payload validation check entirely and proceeds to return `true` at line 114, causing the transaction to match despite not satisfying the payload filter criteria.

**Exploitation Scenario:**
1. Indexer client creates filter: sender=0xMalicious AND function=0x1::coin::transfer
2. Attacker sends Script transaction from 0xMalicious that drains a vulnerable contract
3. Filter matches on sender (0xMalicious), but returns `None` for payload extraction
4. Payload validation is skipped, transaction incorrectly matches filter
5. Client application receives and processes Script transaction thinking it matched the coin::transfer filter
6. Application makes incorrect security/accounting decisions based on bad data

Script transactions are still actively supported on Aptos, as evidenced by test cases: [4](#0-3) 

## Impact Explanation
This vulnerability has **Medium** severity with application-level security implications:

**Data Integrity Violation:** Indexer clients receive transactions they explicitly filtered out, violating the semantic contract of the filtering API. Applications that rely on filtered data for security decisions (monitoring systems, compliance tools, DeFi frontends) will operate on incorrect datasets.

**Observability Gap:** The silent failure mode (no logging, no errors) means:
- Operators cannot detect when filtering fails
- Debug and audit trails are incomplete
- Malicious Script transactions could evade detection by monitoring systems

**Application-Level Security Risk:** While this does not directly compromise consensus or execution layers, applications built on the indexer may make security-critical decisions based on filtered data. For example:
- Auditing systems tracking specific entry functions miss Script-based attacks
- Compliance monitoring systems fail to capture regulated operations
- Frontend applications display incorrect transaction history

This does **not** meet Critical or High severity because it does not affect consensus, validator operations, or blockchain protocol execution. However, it qualifies as Medium severity under "State inconsistencies requiring intervention" as it causes persistent data integrity issues in the indexer layer that applications depend upon.

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability will trigger whenever:
1. An indexer client specifies a payload filter (common use case)
2. A Script or WriteSet transaction matches the sender filter
3. The transaction is processed through the filter

Script transactions are less common than EntryFunction transactions but are still supported and used on Aptos. The `ALLOW_SERIALIZED_SCRIPT_ARGS` feature flag controls certain Script transaction behaviors but does not disable them entirely. Any application relying on payload-based filtering is affected.

The silent nature of the bug increases likelihood of impact, as developers won't realize their filters are ineffective until data inconsistencies surface.

## Recommendation
Add explicit handling for non-EntryFunction payload types with appropriate logging and rejection logic:

```rust
fn get_entry_function_payload_from_transaction_payload(
    payload: &TransactionPayload,
) -> Option<&EntryFunctionPayload> {
    if let Some(payload) = &payload.payload {
        match payload {
            transaction_payload::Payload::EntryFunctionPayload(ef_payload) => Some(ef_payload),
            transaction_payload::Payload::MultisigPayload(ms_payload) => ms_payload
                .transaction_payload
                .as_ref()
                .and_then(|tp| tp.payload.as_ref())
                .map(|payload| match payload {
                    multisig_transaction_payload::Payload::EntryFunctionPayload(ef_payload) => {
                        ef_payload
                    },
                }),
            transaction_payload::Payload::ScriptPayload(_) => {
                // Log but return None - Script payloads don't have entry functions
                None
            },
            transaction_payload::Payload::WriteSetPayload(_) => {
                // Log but return None - WriteSet payloads don't have entry functions  
                None
            },
        }
    } else {
        None
    }
}
```

Additionally, modify the filter matching logic to explicitly reject transactions when a payload filter is specified but the payload type is unsupported:

```rust
if let Some(payload_filter) = &self.payload {
    let entry_function_payload = user_request
        .payload
        .as_ref()
        .and_then(get_entry_function_payload_from_transaction_payload);
    
    match entry_function_payload {
        Some(payload) => {
            if !payload_filter.matches(payload) {
                return false;
            }
        },
        None => {
            // If payload filter specified but no entry function found, reject
            // This handles Script/WriteSet payloads explicitly
            return false;
        }
    }
}
```

## Proof of Concept
The following test demonstrates the vulnerability:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::transaction::v1::{
        transaction, transaction_payload, Transaction, UserTransaction,
        UserTransactionRequest, ScriptPayload, TransactionPayload as ProtoPayload,
    };

    #[test]
    fn test_script_payload_bypasses_entry_function_filter() {
        // Create filter for specific entry function
        let filter = UserTransactionFilterBuilder::default()
            .sender("0x1")
            .payload(
                UserTransactionPayloadFilterBuilder::default()
                    .function(
                        EntryFunctionFilterBuilder::default()
                            .address("0x1")
                            .module("coin")
                            .function("transfer")
                            .build()
                            .unwrap()
                    )
                    .build()
                    .unwrap()
            )
            .build()
            .unwrap();

        // Create transaction with Script payload (not entry function)
        let txn = Transaction {
            txn_data: Some(transaction::TxnData::User(UserTransaction {
                request: Some(UserTransactionRequest {
                    sender: "0x1".to_string(),
                    payload: Some(ProtoPayload {
                        r#type: transaction_payload::Type::ScriptPayload as i32,
                        payload: Some(transaction_payload::Payload::ScriptPayload(
                            ScriptPayload { 
                                code: vec![],
                                type_arguments: vec![],
                                arguments: vec![],
                            }
                        )),
                        extra_config: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        // BUG: This should return false (script doesn't match entry function filter)
        // but returns true due to silent bypass
        assert_eq!(filter.matches(&txn), true); // SHOULD BE FALSE
    }
}
```

**Notes**

This vulnerability exists in the **indexer-grpc subsystem**, not in the core consensus, execution, or state management layers. While it does not compromise blockchain protocol security, it creates data integrity issues that can lead to security vulnerabilities in applications built on top of the indexer. The lack of logging exacerbates the issue by making it difficult to detect and debug filtering failures.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L100-112)
```rust
        if let Some(payload_filter) = &self.payload {
            // Get the entry_function_payload from both UserPayload and MultisigPayload
            let entry_function_payload = user_request
                .payload
                .as_ref()
                .and_then(get_entry_function_payload_from_transaction_payload);
            if let Some(payload) = entry_function_payload {
                // Here we have an actual EntryFunctionPayload
                if !payload_filter.matches(payload) {
                    return false;
                }
            }
        }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L275-295)
```rust
fn get_entry_function_payload_from_transaction_payload(
    payload: &TransactionPayload,
) -> Option<&EntryFunctionPayload> {
    if let Some(payload) = &payload.payload {
        match payload {
            transaction_payload::Payload::EntryFunctionPayload(ef_payload) => Some(ef_payload),
            transaction_payload::Payload::MultisigPayload(ms_payload) => ms_payload
                .transaction_payload
                .as_ref()
                .and_then(|tp| tp.payload.as_ref())
                .map(|payload| match payload {
                    multisig_transaction_payload::Payload::EntryFunctionPayload(ef_payload) => {
                        ef_payload
                    },
                }),
            _ => None,
        }
    } else {
        None
    }
}
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L627-636)
```rust
    pub enum Payload {
        #[prost(message, tag="2")]
        EntryFunctionPayload(super::EntryFunctionPayload),
        #[prost(message, tag="3")]
        ScriptPayload(super::ScriptPayload),
        #[prost(message, tag="5")]
        WriteSetPayload(super::WriteSetPayload),
        #[prost(message, tag="6")]
        MultisigPayload(super::MultisigPayload),
    }
```

**File:** aptos-move/e2e-move-tests/src/tests/scripts.rs (L105-119)
```rust
    let status = h.run(txn);
    assert_success!(status);

    h.enable_features(vec![], vec![FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS]);

    let txn = TransactionBuilder::new(alice.clone())
        .script(script.clone())
        .sequence_number(14)
        .max_gas_amount(1_000_000)
        .gas_unit_price(1)
        .sign();

    let status = h.run(txn);
    assert!(status.is_discarded());
}
```
