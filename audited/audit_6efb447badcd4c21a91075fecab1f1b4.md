# Audit Report

## Title
Missing Transaction Version Validation in Indexer File Store Read Path Enables Data Integrity Attacks

## Summary
The `FileEntry::into_transactions_in_storage()` function in the indexer-grpc compression utility lacks validation to ensure decoded transaction versions are sequential and match the expected starting version. An attacker with access to the file store (GCS bucket) can inject malicious transaction files with arbitrary version numbers, causing the indexer service to serve corrupted historical data to clients.

## Finding Description

The vulnerability exists in the transaction deserialization path for the legacy `JsonBase64UncompressedProto` storage format. When reading transaction files from storage, the system decodes transactions without validating their version numbers. [1](#0-0) 

The code decodes transactions from base64 at line 282 and creates a `TransactionsInStorage` object at lines 286-289, but performs **no validation** that:
1. Transaction versions are sequential (no gaps or duplicates)
2. Transaction versions start at the `starting_version` from line 287
3. Transaction versions match expected values

In contrast, the write path DOES validate version sequentiality: [2](#0-1) 

The downstream historical data service directly trusts these version numbers without validation: [3](#0-2) [4](#0-3) 

**Attack Path:**
1. Attacker compromises GCS service account credentials or is a malicious operator
2. Attacker uploads a malicious transaction file (e.g., `files/1000.json`) with:
   - `starting_version: 1000`
   - Transactions with arbitrary versions: `[500, 1500, 2000, 1000]` (non-sequential, wrong range)
3. When `FileEntry::into_transactions_in_storage()` reads this file, it accepts the malicious data
4. The historical data service serves these transactions to clients with incorrect version numbers
5. Clients receive corrupted historical data with missing, duplicated, or misordered transactions

## Impact Explanation

This is a **Medium Severity** data integrity vulnerability affecting the indexer-grpc service:

- **State Inconsistencies**: Clients consuming indexer data receive incorrect historical transactions, leading to wrong state reconstruction
- **Application Logic Errors**: DApps and wallets relying on complete transaction history may make incorrect decisions
- **Financial Impact**: Applications using indexer data for balance calculations or transaction tracking could operate on corrupted data

This does NOT affect:
- Core consensus (validators use canonical state, not indexer)
- Blockchain state (canonical state on validators is unaffected)
- Validator operations (indexer is separate infrastructure)

Per Aptos bug bounty criteria, this qualifies as **Medium Severity**: "State inconsistencies requiring intervention" - specifically, indexer service state inconsistencies affecting downstream applications.

## Likelihood Explanation

**Likelihood: Medium-Low**

**Required Conditions:**
- Attacker must compromise GCS service account credentials (medium difficulty)
- OR attacker is a malicious insider operator (excluded by trust model but possible via credential theft)
- Target indexer must be using legacy `JsonBase64UncompressedProto` format (newer deployments use `Lz4CompressedProto`)

**Mitigating Factors:**
- GCS buckets are typically well-secured with IAM policies
- Write path validation (file_store_operator.rs) prevents normal operations from creating bad files
- Most production deployments use the newer `Lz4CompressedProto` format
- Operators monitor for data anomalies

**Amplifying Factors:**
- No cryptographic verification of file contents
- Legacy files could exist from migrations
- Compromised credentials are a realistic threat

## Recommendation

Add validation in `FileEntry::into_transactions_in_storage()` to verify transaction version sequentiality and correctness:

```rust
pub fn into_transactions_in_storage(self) -> TransactionsInStorage {
    match self {
        FileEntry::Lz4CompressionProto(bytes) => {
            // ... existing code ...
        },
        FileEntry::JsonBase64UncompressedProto(bytes) => {
            let file: TransactionsLegacyFile =
                serde_json::from_slice(bytes.as_slice()).expect("json deserialization failed.");
            let transactions = file
                .transactions_in_base64
                .into_iter()
                .map(|base64| {
                    let bytes: Vec<u8> =
                        base64::decode(base64).expect("base64 decoding failed.");
                    Transaction::decode(bytes.as_slice())
                        .expect("proto deserialization failed.")
                })
                .collect::<Vec<Transaction>>();
            
            // Add validation
            if !transactions.is_empty() {
                let starting_version = file.starting_version;
                for (i, txn) in transactions.iter().enumerate() {
                    let expected_version = starting_version + i as u64;
                    if txn.version != expected_version {
                        panic!(
                            "Transaction version mismatch: expected {}, got {} at index {}",
                            expected_version, txn.version, i
                        );
                    }
                }
            }
            
            TransactionsInStorage {
                starting_version: Some(file.starting_version),
                transactions,
            }
        },
    }
}
```

Additionally:
1. Add cryptographic signatures/hashes to verify file integrity
2. Implement monitoring for version discontinuities
3. Rotate and audit GCS service account credentials regularly
4. Migrate all legacy format files to the newer validated format

## Proof of Concept

```rust
#[test]
fn test_malicious_transaction_file_injection() {
    use crate::compression_util::{FileEntry, StorageFormat, TransactionsLegacyFile};
    use aptos_protos::transaction::v1::Transaction;
    
    // Create a malicious file with non-sequential versions
    let malicious_transactions = vec![
        Transaction { version: 500, ..Default::default() },   // Should be 1000
        Transaction { version: 1500, ..Default::default() },  // Should be 1001
        Transaction { version: 2000, ..Default::default() },  // Should be 1002
    ];
    
    let transactions_in_base64 = malicious_transactions
        .into_iter()
        .map(|txn| {
            let mut bytes = Vec::new();
            txn.encode(&mut bytes).unwrap();
            base64::encode(bytes)
        })
        .collect::<Vec<String>>();
    
    let malicious_file = TransactionsLegacyFile {
        starting_version: 1000,  // Claims to start at 1000
        transactions_in_base64,
    };
    
    let json = serde_json::to_vec(&malicious_file).unwrap();
    let file_entry = FileEntry::JsonBase64UncompressedProto(json);
    
    // This should fail but currently succeeds
    let result = file_entry.into_transactions_in_storage();
    
    // Verify the bug: transactions have wrong versions
    assert_eq!(result.starting_version, Some(1000));
    assert_eq!(result.transactions[0].version, 500);  // Wrong! Should be 1000
    assert_eq!(result.transactions[1].version, 1500); // Wrong! Should be 1001
    assert_eq!(result.transactions[2].version, 2000); // Wrong! Should be 1002
    
    // With the fix, this test should panic at version validation
}
```

This PoC demonstrates that malicious files with arbitrary transaction versions are accepted without validation, enabling the data integrity attack described above.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L273-290)
```rust
            FileEntry::JsonBase64UncompressedProto(bytes) => {
                let file: TransactionsLegacyFile =
                    serde_json::from_slice(bytes.as_slice()).expect("json deserialization failed.");
                let transactions = file
                    .transactions_in_base64
                    .into_iter()
                    .map(|base64| {
                        let bytes: Vec<u8> =
                            base64::decode(base64).expect("base64 decoding failed.");
                        Transaction::decode(bytes.as_slice())
                            .expect("proto deserialization failed.")
                    })
                    .collect::<Vec<Transaction>>();
                TransactionsInStorage {
                    starting_version: Some(file.starting_version),
                    transactions,
                }
            },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs (L50-55)
```rust
        ensure!(
            self.version == transaction.version,
            "Gap is found when buffering transaction, expected: {}, actual: {}",
            self.version,
            transaction.version,
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L183-190)
```rust
            while let Some((
                transactions,
                batch_size_bytes,
                timestamp,
                (first_processed_version, last_processed_version),
            )) = rx.recv().await
            {
                next_version = last_processed_version + 1;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L131-134)
```rust
                let mut processed_range = (
                    transactions.first().unwrap().version,
                    transactions.last().unwrap().version,
                );
```
