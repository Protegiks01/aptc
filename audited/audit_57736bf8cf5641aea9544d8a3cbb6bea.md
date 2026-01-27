# Audit Report

## Title
Panic-Induced Denial of Service in Indexer-GRPC Transaction Filter Due to Unchecked Enum Conversion

## Summary
The `TransactionRootFilter::matches()` function contains a type conversion vulnerability where invalid i32 transaction type values can trigger a panic, crashing the indexer-grpc service. The code uses `.expect()` on a fallible `TryFrom<i32>` conversion without proper error handling. [1](#0-0) 

## Finding Description

The vulnerability exists in the transaction filtering logic where protobuf-deserialized transactions are checked against user-defined filters. The `TransactionType` enum has valid discriminant values (0, 1, 2, 3, 4, 20, 21), but when transactions are deserialized from external storage, the protobuf library accepts ANY i32 value for the `r#type` field without validation. [2](#0-1) 

The transaction type is defined as an i32 enum: [3](#0-2) 

When transactions are loaded from file storage and filtered, the code path is: [4](#0-3) 

Transactions are deserialized using `Transaction::decode()` which accepts any i32 value: [5](#0-4) 

**Attack Path:**
1. Attacker corrupts or manipulates file storage to include transactions with invalid type values (e.g., -1, 5, 100)
2. Indexer service loads transactions from file storage
3. Filter is applied via `filter.matches(t)`
4. The `try_from` conversion fails for invalid values
5. `.expect()` triggers a panic, crashing the indexer service task

## Impact Explanation

**Severity: Low to Medium** 

This vulnerability causes a Denial of Service (DoS) against the indexer-grpc service. However, critical limitations reduce its severity:

1. **Not consensus-critical**: The indexer-grpc is ecosystem tooling, not a consensus node. No blockchain state or validator operations are affected.

2. **Limited attack surface**: Exploitation requires either:
   - Write access to the GCS storage bucket (insider threat)
   - Pre-existing data corruption in storage
   - A bug in older code that wrote invalid transaction types

3. **No financial impact**: No funds can be stolen, minted, or frozen.

4. **Recoverable**: The service can be restarted, and the corrupted data can be identified and fixed.

Under Aptos bug bounty criteria, this falls between **Low** (non-critical implementation bug) and **Medium** (service disruption requiring intervention), but leans toward Low due to exploitation difficulty.

## Likelihood Explanation

**Likelihood: Very Low**

- **Normal operation**: Transactions from the fullnode are converted using `convert_transaction()` which always sets valid transaction types: [6](#0-5) [7](#0-6) 

- **File storage**: Controlled by Aptos Foundation, not accessible to unprivileged attackers
- **Data corruption**: GCS provides integrity guarantees, making corruption unlikely
- **Pre-existing bugs**: Would have been caught during testing and normal operations

## Recommendation

Replace the `.expect()` with proper error handling to prevent panics:

```rust
if let Some(txn_type) = &self.txn_type {
    match TransactionType::try_from(item.r#type) {
        Ok(actual_type) => {
            if txn_type != &actual_type {
                return false;
            }
        }
        Err(_) => {
            // Log the error and conservatively filter out invalid transactions
            warn!("Invalid transaction type encountered: {}", item.r#type);
            return false; // Or true, depending on filtering policy
        }
    }
}
```

Alternatively, add validation after deserialization to reject transactions with invalid types before filtering is applied.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::transaction::v1::Transaction;

    #[test]
    #[should_panic(expected = "Invalid transaction type")]
    fn test_invalid_transaction_type_causes_panic() {
        let filter = TransactionRootFilter {
            success: None,
            txn_type: Some(TransactionType::User),
        };

        // Create a transaction with an invalid type value
        let mut transaction = Transaction::default();
        transaction.r#type = 999; // Invalid transaction type

        // This will panic due to .expect() on failed try_from
        filter.matches(&transaction);
    }
}
```

---

**Notes:**

While this is a valid code quality issue that should be fixed, it **fails the exploitability criterion** for a bug bounty submission because:

1. It requires insider access to storage infrastructure or pre-existing data corruption
2. An unprivileged external attacker cannot trigger this vulnerability
3. The impact is limited to a service disruption of non-consensus infrastructure

The code should be fixed as a defensive programming measure, but this does not constitute a bounty-eligible security vulnerability under the strict validation criteria provided.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs (L67-73)
```rust
        if let Some(txn_type) = &self.txn_type {
            if txn_type
                != &TransactionType::try_from(item.r#type).expect("Invalid transaction type")
            {
                return false;
            }
        }
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L40-57)
```rust
pub struct Transaction {
    #[prost(message, optional, tag="1")]
    pub timestamp: ::core::option::Option<super::super::util::timestamp::Timestamp>,
    #[prost(uint64, tag="2")]
    pub version: u64,
    #[prost(message, optional, tag="3")]
    pub info: ::core::option::Option<TransactionInfo>,
    #[prost(uint64, tag="4")]
    pub epoch: u64,
    #[prost(uint64, tag="5")]
    pub block_height: u64,
    #[prost(enumeration="transaction::TransactionType", tag="6")]
    pub r#type: i32,
    #[prost(message, optional, tag="22")]
    pub size_info: ::core::option::Option<TransactionSizeInfo>,
    #[prost(oneof="transaction::TxnData", tags="7, 8, 9, 10, 21, 23")]
    pub txn_data: ::core::option::Option<transaction::TxnData>,
}
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L59-71)
```rust
pub mod transaction {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum TransactionType {
        Unspecified = 0,
        Genesis = 1,
        BlockMetadata = 2,
        StateCheckpoint = 3,
        User = 4,
        /// values 5-19 skipped for no reason
        Validator = 20,
        BlockEpilogue = 21,
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L140-142)
```rust
                if let Some(ref filter) = filter {
                    transactions.retain(|t| filter.matches(t));
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L142-157)
```rust
    pub fn into_transaction(self) -> Transaction {
        match self {
            CacheEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                Transaction::decode(decompressed.as_slice()).expect("proto deserialization failed.")
            },
            CacheEntry::Base64UncompressedProto(bytes) => {
                let bytes: Vec<u8> = base64::decode(bytes).expect("base64 decoding failed.");
                Transaction::decode(bytes.as_slice()).expect("proto deserialization failed.")
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L835-851)
```rust
    let txn_type = match transaction {
        Transaction::UserTransaction(_) => transaction::transaction::TransactionType::User,
        Transaction::GenesisTransaction(_) => transaction::transaction::TransactionType::Genesis,
        Transaction::BlockMetadataTransaction(_) => {
            transaction::transaction::TransactionType::BlockMetadata
        },
        Transaction::StateCheckpointTransaction(_) => {
            transaction::transaction::TransactionType::StateCheckpoint
        },
        Transaction::BlockEpilogueTransaction(_) => {
            transaction::transaction::TransactionType::BlockEpilogue
        },
        Transaction::PendingTransaction(_) => panic!("PendingTransaction is not supported"),
        Transaction::ValidatorTransaction(_) => {
            transaction::transaction::TransactionType::Validator
        },
    };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L944-944)
```rust
        r#type: txn_type as i32,
```
