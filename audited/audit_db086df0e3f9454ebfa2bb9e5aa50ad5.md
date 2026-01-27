# Audit Report

## Title
Insecure File Permissions in LocalFileStore Expose Transaction Data to Local Users

## Summary
The `upload_transaction_batch()` function in `LocalFileStoreOperator` creates transaction data files without explicitly setting restrictive file permissions, making them world-readable on Unix systems. This exposes sensitive transaction data to any local user on the system.

## Finding Description

The `upload_transaction_batch()` function uses `tokio::fs::write()` to persist transaction batches to disk without setting secure file permissions. [1](#0-0) 

On Unix systems, `tokio::fs::write()` creates files with default permissions determined by the process umask, typically resulting in mode `0o644` (rw-r--r--), making them readable by all users on the system.

The transaction data stored in these files includes sensitive information defined in the Transaction protobuf: [2](#0-1) 

This includes:
- User addresses and signatures [3](#0-2) 
- Transaction payloads with arguments [4](#0-3) 
- Events and state changes [5](#0-4) 

The LocalFileStore is documented as "[TEST ONLY]" for local development: [6](#0-5) 

However, there is no technical enforcement preventing production deployment, and it is configured as the default file store option: [7](#0-6) 

## Impact Explanation

This constitutes a **Medium severity** information disclosure vulnerability:

1. **Information Disclosure**: Transaction data containing user addresses, signatures, payloads, and state changes is exposed to unauthorized local users
2. **Scope**: Limited to multi-user systems where the indexer-grpc service runs
3. **Data Sensitivity**: While blockchain data is eventually public, premature exposure at the file system level violates the principle of least privilege and could reveal transaction patterns or timing information

This does not meet Critical or High severity criteria as it:
- Does not cause fund loss or theft
- Does not affect consensus safety
- Does not impact network availability
- Requires local system access (not remotely exploitable)

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered when:
1. LocalFileStore is deployed on a multi-user system (despite being marked TEST ONLY)
2. The indexer-grpc process runs with a permissive umask (common default: 0o022)
3. Other local users have shell access to the system

Factors increasing likelihood:
- LocalFileStore is the default configuration
- No technical safeguards prevent production use
- Users may ignore the TEST ONLY warning in documentation
- Shared development/testing environments often have multiple users

## Recommendation

**Fix 1: Explicit Permission Setting (Primary)**

Use `std::fs::OpenOptions` with explicit permissions instead of `tokio::fs::write()`:

```rust
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

// Replace line 185
#[cfg(unix)]
let file = tokio::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600) // Owner read/write only
    .open(&txns_path)
    .await?;

#[cfg(not(unix))]
let file = tokio::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(&txns_path)
    .await?;

tokio::io::AsyncWriteExt::write_all(&mut file, &file_entry.into_inner()).await?;
```

Similarly, set directory permissions when creating parent directories: [8](#0-7) 

```rust
#[cfg(unix)]
{
    tokio::fs::create_dir_all(parent_dir).await?;
    tokio::fs::set_permissions(parent_dir, std::fs::Permissions::from_mode(0o700)).await?;
}
```

**Fix 2: Runtime Validation**

Add a startup check that fails if LocalFileStore is used outside of test/development environments.

**Fix 3: Documentation Enhancement**

Add prominent warnings in code comments at the LocalFileStoreOperator implementation about the security implications.

## Proof of Concept

**Setup:**
1. Deploy indexer-grpc with LocalFileStore configuration on a multi-user Unix system
2. Ensure the service writes transaction batches to `/tmp/indexer_data/`

**Attack Steps:**
```bash
# As unprivileged local user (not the indexer-grpc service user)
$ ls -la /tmp/indexer_data/compressed_files/lz4/
-rw-r--r-- 1 indexer indexer 45678 Dec 10 10:00 abc123_0.bin

# World-readable - any user can read
$ cat /tmp/indexer_data/compressed_files/lz4/abc123_0.bin > stolen_transactions.bin

# Decompress and parse the protobuf data to extract transaction information
$ lz4 -d stolen_transactions.bin - | protoc --decode=aptos.transaction.v1.TransactionsInStorage transaction.proto
```

**Expected Result:** Attacker successfully reads transaction data including user addresses, signatures, and payloads.

**Verification:**
```rust
// Unit test to verify default permissions
#[cfg(unix)]
#[tokio::test]
async fn test_file_permissions_vulnerability() {
    use std::os::unix::fs::PermissionsExt;
    
    let temp_dir = tempfile::tempdir().unwrap();
    let test_file = temp_dir.path().join("test.bin");
    
    tokio::fs::write(&test_file, b"test data").await.unwrap();
    
    let metadata = tokio::fs::metadata(&test_file).await.unwrap();
    let mode = metadata.permissions().mode();
    
    // On typical Unix systems with umask 0o022, this will be 0o644
    assert_eq!(mode & 0o777, 0o644, "File is world-readable!");
}
```

## Notes

While LocalFileStore is documented as TEST ONLY, the lack of technical enforcement and its presence as the default configuration makes this a valid security concern. Production deployments should use GcsFileStore, but defense-in-depth principles require secure file handling even in test code that could be inadvertently deployed.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L174-178)
```rust
            let parent_dir = txns_path.parent().unwrap();
            if !parent_dir.exists() {
                tracing::debug!("Creating parent dir: {parent_dir:?}.");
                tokio::fs::create_dir_all(parent_dir).await?;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L185-185)
```rust
                match tokio::fs::write(txns_path, file_entry.into_inner()).await {
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L40-72)
```text
message Transaction {
  aptos.util.timestamp.Timestamp timestamp = 1;
  uint64 version = 2 [jstype = JS_STRING];
  TransactionInfo info = 3;
  uint64 epoch = 4 [jstype = JS_STRING];
  uint64 block_height = 5 [jstype = JS_STRING];

  enum TransactionType {
    TRANSACTION_TYPE_UNSPECIFIED = 0;
    TRANSACTION_TYPE_GENESIS = 1;
    TRANSACTION_TYPE_BLOCK_METADATA = 2;
    TRANSACTION_TYPE_STATE_CHECKPOINT = 3;
    TRANSACTION_TYPE_USER = 4;
    // values 5-19 skipped for no reason
    TRANSACTION_TYPE_VALIDATOR = 20;
    TRANSACTION_TYPE_BLOCK_EPILOGUE = 21;
  }

  TransactionType type = 6;

  oneof txn_data {
    BlockMetadataTransaction block_metadata = 7;
    GenesisTransaction genesis = 8;
    StateCheckpointTransaction state_checkpoint = 9;
    UserTransaction user = 10;
    // value 11-19 skipped for no reason
    ValidatorTransaction validator = 21;
    // value 22 is used up below (all Transaction fields have to have different index), so going to 23
    BlockEpilogueTransaction block_epilogue = 23;
  }

  TransactionSizeInfo size_info = 22;
}
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L169-179)
```text
message TransactionInfo {
  bytes hash = 1;
  bytes state_change_hash = 2;
  bytes event_root_hash = 3;
  optional bytes state_checkpoint_hash = 4;
  uint64 gas_used = 5 [jstype = JS_STRING];
  bool success = 6;
  string vm_status = 7;
  bytes accumulator_root_hash = 8;
  repeated WriteSetChange changes = 9;
}
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L186-194)
```text
message UserTransactionRequest {
  string sender = 1;
  uint64 sequence_number = 2 [jstype = JS_STRING];
  uint64 max_gas_amount = 3 [jstype = JS_STRING];
  uint64 gas_unit_price = 4 [jstype = JS_STRING];
  aptos.util.timestamp.Timestamp expiration_timestamp_secs = 5;
  TransactionPayload payload = 6;
  Signature signature = 7;
}
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L328-333)
```text
message EntryFunctionPayload {
  EntryFunctionId function = 1;
  repeated MoveType type_arguments = 2;
  repeated string arguments = 3;
  string entry_function_id_str = 4;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/README.md (L43-56)
```markdown
## [TEST ONLY] Run it with a local filestore

For developing and testing locally, it might be easier to use a local filestore.

Create a local directory to store the filestore: `mkdir test_indexer_grpc_filestore`

Then in your config:
```yaml
...
server_config:
    file_store_config:
      file_store_type: LocalFileStore
      local_file_store_path: test_indexer_grpc_filestore
```
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/config.rs (L37-44)
```rust
impl Default for IndexerGrpcFileStoreConfig {
    fn default() -> Self {
        IndexerGrpcFileStoreConfig::LocalFileStore(LocalFileStore {
            local_file_store_path: std::env::current_dir().unwrap(),
            enable_compression: false,
        })
    }
}
```
