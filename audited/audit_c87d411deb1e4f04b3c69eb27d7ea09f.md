# Audit Report

## Title
Critical Storage Errors Masked as Transaction Failures Leading to Consensus Divergence

## Summary
The conversion of all `anyhow::Error` to `StateViewError::Other(String)` at line 19 in `types/src/state_store/errors.rs` masks critical infrastructure failures (RocksDB corruption, disk full, permission denied) that should trigger validator shutdown. Instead, these errors are treated as benign transaction failures, allowing validators with corrupted storage to continue participating in consensus and producing divergent execution results. [1](#0-0) 

## Finding Description

**Error Masking Chain:**

1. **RocksDB Layer**: Critical errors like `ErrorKind::Corruption` and `ErrorKind::IOError` (which includes disk full and permission denied) are converted to generic string messages: [2](#0-1) 

2. **Storage Interface**: These RocksDB errors become `AptosDbError::OtherRocksDbError(String)`, which then converts to `StateViewError::Other(String)`, losing all type information: [3](#0-2) 

3. **Critical Conversion**: The questioned line converts any `anyhow::Error` to `StateViewError::Other(String)`, further masking error types: [1](#0-0) 

4. **VM Layer**: All storage errors become generic `STORAGE_ERROR` status codes: [4](#0-3) 

5. **Transaction Execution**: Storage errors during state reads are treated as transaction failures rather than node failures: [5](#0-4) 

**Consensus Impact:**

When execution results diverge due to storage errors, the system only logs errors but continues operating: [6](#0-5) 

The chunk executor only panics if there's a pending pre-commit, but not during normal transaction execution: [7](#0-6) 

**Invariant Violation:**

This breaks **Deterministic Execution** (Invariant #1): Validators with corrupted storage will produce different state roots for identical blocks, causing consensus divergence without triggering automatic node shutdown.

## Impact Explanation

**High Severity** - This qualifies under "Significant protocol violations" because:

1. **Silent Consensus Divergence**: A validator with corrupted RocksDB continues executing blocks and voting, producing different state roots than healthy validators without any automatic remediation.

2. **Liveness Degradation**: If multiple validators experience storage issues simultaneously (e.g., from a common disk fill scenario due to log growth), consensus can stall as insufficient validators produce matching execution results.

3. **Delayed Detection**: The issue manifests as transaction execution failures and error logs rather than obvious node crashes, making it difficult for operators to identify the root cause quickly.

4. **No Automatic Recovery**: Unlike epoch sync failures which trigger panic, storage errors during normal execution allow faulty validators to remain in the active set. [8](#0-7) 

## Likelihood Explanation

**High Likelihood** in production environments:

1. **Common Operational Scenarios**: Disk full conditions are frequent in blockchain nodes due to log accumulation, state growth, and pruning configuration issues.

2. **Silent Failures**: Storage corruption can occur from hardware failures, improper shutdowns, or filesystem issues without immediate detection.

3. **Cascading Impact**: Once one validator experiences storage issues, the consensus message load increases on remaining validators, potentially causing resource exhaustion.

## Recommendation

Implement explicit detection and handling for critical storage errors:

```rust
// In types/src/state_store/errors.rs
impl From<anyhow::Error> for StateViewError {
    fn from(error: anyhow::Error) -> Self {
        // Check if this is a critical storage error that should panic
        if let Some(db_err) = error.downcast_ref::<AptosDbError>() {
            match db_err {
                AptosDbError::OtherRocksDbError(msg) 
                    if msg.contains("Corruption") 
                    || msg.contains("IO error") 
                    || msg.contains("No space left") 
                    || msg.contains("Permission denied") => {
                    panic!("Critical storage error detected: {}. Validator shutting down to prevent consensus divergence.", msg);
                },
                _ => {}
            }
        }
        Self::Other(format!("{}", error))
    }
}
```

Additionally, enhance RocksDB error handling to preserve error types:

```rust
// In storage/schemadb/src/lib.rs
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Corruption => {
            panic!("RocksDB corruption detected: {}. Shutting down to prevent consensus divergence.", rocksdb_err);
        },
        ErrorKind::IOError => {
            // Check for disk full or permission issues
            let err_str = rocksdb_err.to_string();
            if err_str.contains("No space left") || err_str.contains("Permission denied") {
                panic!("Critical I/O error: {}. Shutting down validator.", rocksdb_err);
            }
            AptosDbError::OtherRocksDbError(rocksdb_err.to_string())
        },
        // ... rest of error handling
    }
}
```

## Proof of Concept

**Scenario Reproduction:**

1. **Setup**: Deploy a test validator network with 4 validators
2. **Trigger Condition**: Fill the disk on validator-1 by disabling log rotation
3. **Observe**: 
   - Validator-1's RocksDB write operations fail with "No space left on device"
   - Error converts through chain: IOError → AptosDbError → StateViewError → STORAGE_ERROR
   - Validator-1 continues executing blocks but produces different state roots
   - Consensus logs show "Re-inserting execution result with different root hash" errors
   - Validator-1 remains in active set, continues voting with divergent state
   - Network experiences partial liveness degradation as validator-1's votes don't match quorum

**Expected Behavior**: Validator-1 should panic immediately upon detecting critical storage failure, trigger automatic removal from active validator set, and alert operators.

**Actual Behavior**: Validator-1 continues operating with corrupted state, silently causing consensus issues.

**Test Implementation** (Rust integration test):
```rust
// This would require modifying the test harness to inject storage failures
// and verify panic behavior vs current silent continuation
```

**Notes**

This vulnerability is particularly concerning because:
- It affects the core consensus safety guarantee of deterministic execution
- Detection requires monitoring error logs rather than obvious node failures  
- Multiple validators could simultaneously experience disk-full conditions from log growth
- The BFT assumption of < 1/3 Byzantine validators could be violated if storage issues affect multiple nodes

The current error handling philosophy appears to prioritize availability over safety in storage error scenarios, which is inappropriate for a consensus-critical blockchain where divergent execution is catastrophic.

### Citations

**File:** types/src/state_store/errors.rs (L17-21)
```rust
impl From<anyhow::Error> for StateViewError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(format!("{}", error))
    }
}
```

**File:** storage/schemadb/src/lib.rs (L389-408)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
}
```

**File:** storage/storage-interface/src/errors.rs (L69-76)
```rust
impl From<AptosDbError> for StateViewError {
    fn from(error: AptosDbError) -> Self {
        match error {
            AptosDbError::NotFound(msg) => StateViewError::NotFound(msg),
            AptosDbError::Other(msg) => StateViewError::Other(msg),
            _ => StateViewError::Other(format!("{}", error)),
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/resolver.rs (L245-250)
```rust
fn map_storage_error<E: std::fmt::Debug>(state_key: &StateKey, e: E) -> PartialVMError {
    PartialVMError::new(StatusCode::STORAGE_ERROR).with_message(format!(
        "Unexpected storage error for resource at {:?}: {:?}",
        state_key, e
    ))
}
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L40-46)
```rust
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L319-324)
```rust
            } else {
                error!(
                    "Re-inserting execution result with different root hash: from {:?} to {:?}",
                    previous, execution_summary
                );
            }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L96-105)
```rust
        let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
        f(inner).map_err(|error| {
            if has_pending_pre_commit {
                panic!(
                    "Hit error with pending pre-committed ledger, panicking. {:?}",
                    error,
                );
            }
            error
        })
```

**File:** consensus/src/epoch_manager.rs (L558-565)
```rust
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");
```
