# Audit Report

## Title
Missing Size Validation in FileEntry::from_transactions() Allows Resource Exhaustion via Large Transaction Batches

## Summary
The `FileEntry::from_transactions()` function in the indexer-grpc compression utility lacks size validation when encoding `TransactionsInStorage` protobuf messages. This allows batches of up to 1000 large transactions to be encoded in-memory without bounds checking, potentially creating files approaching 1 GB in size and causing memory exhaustion or disk space issues in indexer nodes. [1](#0-0) 

## Finding Description
The vulnerability exists in the file store operator's transaction encoding pipeline. When the v1 file store operators (GCS and Local) upload transaction batches, they enforce exactly 1000 transactions per file but perform no size validation: [2](#0-1) 

Individual transactions on Aptos can be up to 64 KB for regular transactions or 1 MB for governance transactions: [3](#0-2) 

**Exploitation Path:**
1. Governance process approves multiple large (1 MB) governance transactions for legitimate network upgrades
2. These transactions are executed and propagate through the network
3. Indexer's file store processor fetches batches of 1000 transactions
4. If a batch contains many large governance transactions, `FileEntry::from_transactions()` encodes them without size checks
5. Worst case: 1000 × 1 MB = ~1 GB of data encoded in-memory
6. This causes memory exhaustion or creates unexpectedly large files on disk

The v1 file store operators are actively used: [4](#0-3) [5](#0-4) 

## Impact Explanation
This issue qualifies as **Medium severity** per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Indexer nodes experiencing OOM crashes create gaps in historical data availability
- **Limited service disruption**: While not affecting consensus, indexers are critical infrastructure for dApps, wallets, and explorers
- **Resource exhaustion attack surface**: Even without malicious intent, legitimate governance activity can trigger resource exhaustion

The indexer is not consensus-critical, so this does NOT threaten blockchain safety or fund security. However, it violates **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation
**Likelihood: Low to Medium**

- **Low** because governance transactions are rare and require pre-approval through `ApprovedExecutionHashes`
- **Medium** because when major network upgrades occur (framework updates, parameter changes), multiple large governance transactions may be batched together legitimately
- The issue manifests without malicious intent during normal governance operations
- No attacker privileges required beyond normal transaction submission (governance approval is a protocol feature, not an attack) [6](#0-5) 

## Recommendation
Add size validation to `FileEntry::from_transactions()` to prevent encoding excessively large transaction batches:

```rust
pub fn from_transactions(
    transactions: Vec<Transaction>,
    storage_format: StorageFormat,
) -> Result<Self, anyhow::Error> {
    // Calculate total size before encoding
    let total_size: usize = transactions
        .iter()
        .map(|t| t.encoded_len())
        .sum();
    
    const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB limit
    anyhow::ensure!(
        total_size <= MAX_FILE_SIZE,
        "Transaction batch too large: {} bytes exceeds {} bytes limit",
        total_size,
        MAX_FILE_SIZE
    );
    
    let mut bytes = Vec::with_capacity(total_size);
    // ... rest of existing code
}
```

Additionally, enforce size limits in the v1 file store operators before calling `from_transactions()`, similar to the v2 implementation's approach: [7](#0-6) 

## Proof of Concept
```rust
#[test]
fn test_large_transaction_batch_memory_exhaustion() {
    use aptos_protos::transaction::v1::Transaction;
    use aptos_indexer_grpc_utils::compression_util::{FileEntry, StorageFormat};
    
    // Create 1000 large transactions simulating governance transactions
    let mut transactions = Vec::new();
    for version in 0..1000 {
        let mut transaction = Transaction::default();
        transaction.version = version;
        // Simulate a 1 MB governance transaction
        transaction.payload = Some(vec![0u8; 1024 * 1024]);
        transactions.push(transaction);
    }
    
    // This will attempt to encode ~1 GB in memory without validation
    // May cause OOM in constrained environments
    let result = std::panic::catch_unwind(|| {
        FileEntry::from_transactions(transactions, StorageFormat::Lz4CompressedProto)
    });
    
    // In production, this could crash the indexer service
    assert!(result.is_ok(), "Large transaction batch should be handled safely");
}
```

## Notes
While the newer FileStoreOperatorV2 implementation includes size-based buffering with `MAX_SIZE_PER_FILE` (50 MB), the older v1 operators still rely only on transaction count limits. The lack of size validation at the encoding layer creates a defense-in-depth gap that should be addressed regardless of upstream controls.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L191-214)
```rust
    pub fn from_transactions(
        transactions: Vec<Transaction>,
        storage_format: StorageFormat,
    ) -> Self {
        let mut bytes = Vec::new();
        let starting_version = transactions
            .first()
            .expect("Cannot build empty file")
            .version;
        match storage_format {
            StorageFormat::Lz4CompressedProto => {
                let t = TransactionsInStorage {
                    starting_version: Some(transactions.first().unwrap().version),
                    transactions,
                };
                t.encode(&mut bytes).expect("proto serialization failed.");
                let mut compressed = EncoderBuilder::new()
                    .level(0)
                    .build(Vec::new())
                    .expect("Lz4 compression failed.");
                compressed
                    .write_all(&bytes)
                    .expect("Lz4 compression failed.");
                FileEntry::Lz4CompressionProto(compressed.finish().0)
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L207-226)
```rust
    async fn upload_transaction_batch(
        &mut self,
        _chain_id: u64,
        transactions: Vec<Transaction>,
    ) -> anyhow::Result<(u64, u64)> {
        let start_version = transactions.first().unwrap().version;
        let end_version = transactions.last().unwrap().version;
        let batch_size = transactions.len();
        anyhow::ensure!(
            start_version % FILE_ENTRY_TRANSACTION_COUNT == 0,
            "Starting version has to be a multiple of BLOB_STORAGE_SIZE."
        );
        anyhow::ensure!(
            batch_size == FILE_ENTRY_TRANSACTION_COUNT as usize,
            "The number of transactions to upload has to be multiplier of BLOB_STORAGE_SIZE."
        );
        let start_time = std::time::Instant::now();
        let bucket_name = self.bucket_name.clone();
        let file_entry = FileEntry::from_transactions(transactions, self.storage_format);
        let file_entry_key_path = self.get_file_entry_key_path(start_version);
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-80)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L61-61)
```rust
        let mut file_store_operator: Box<dyn FileStoreOperator> = file_store_config.create();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L183-186)
```rust
                    let (start, end) = file_store_operator_clone
                        .upload_transaction_batch(chain_id, transactions)
                        .await
                        .unwrap();
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L286-302)
```rust
fn is_approved_gov_script(
    resolver: &impl ConfigStorage,
    txn: &SignedTransaction,
    txn_metadata: &TransactionMetadata,
) -> bool {
    if let Ok(TransactionExecutableRef::Script(_script)) = txn.payload().executable_ref() {
        match ApprovedExecutionHashes::fetch_config(resolver) {
            Some(approved_execution_hashes) => approved_execution_hashes
                .entries
                .iter()
                .any(|(_, hash)| hash == &txn_metadata.script_hash),
            None => false,
        }
    } else {
        false
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs (L43-64)
```rust
    pub async fn buffer_and_maybe_dump_transactions_to_file(
        &mut self,
        transaction: Transaction,
        tx: Sender<(Vec<Transaction>, BatchMetadata, bool)>,
    ) -> Result<()> {
        let end_batch = (transaction.version + 1) % self.num_txns_per_folder == 0;
        let size_bytes = transaction.encoded_len();
        ensure!(
            self.version == transaction.version,
            "Gap is found when buffering transaction, expected: {}, actual: {}",
            self.version,
            transaction.version,
        );
        self.buffer.push(transaction);
        self.buffer_size_in_bytes += size_bytes;
        self.version += 1;
        if self.buffer_size_in_bytes >= self.max_size_per_file || end_batch {
            self.dump_transactions_to_file(end_batch, tx).await?;
        }

        Ok(())
    }
```
