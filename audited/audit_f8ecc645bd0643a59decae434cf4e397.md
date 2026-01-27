# Audit Report

## Title
Information Disclosure Through Unsanitized Storage Error Messages in Transaction Simulation API

## Summary
The `module_storage_error!` macro does not sanitize error information before exposing it through the transaction simulation API. Storage errors containing internal implementation details (file paths, database structure, RocksDB error messages) are leaked to unauthenticated users via the public `/v1/transactions/simulate` endpoint.

## Finding Description

The vulnerability exists in a chain of error propagation from the storage layer through the Move VM to the API response:

**Step 1: Error Creation**
In `fetch_module_bytes()`, storage errors are wrapped using the `module_storage_error!` macro: [1](#0-0) 

**Step 2: Unsanitized Debug Formatting**
The macro uses `{:?}` debug formatting which preserves all error details: [2](#0-1) 

**Step 3: Error Propagation from Storage**
RocksDB errors are converted to strings containing internal details: [3](#0-2) 

**Step 4: Conversion to StateViewError**
AptosDbError (containing RocksDB details) is converted to StateViewError: [4](#0-3) 

**Step 5: API Exposure**
The simulation API extracts the error message and returns it to users: [5](#0-4) 

**Attack Vector:**
An attacker can call the public simulation endpoint without authentication. If they craft a transaction that triggers a storage error during module loading, the detailed error message is returned in the `vm_status` field.

Potential leaked information includes:
- Internal file system paths (e.g., "/var/lib/aptos/db/...")
- RocksDB column family names revealing database structure
- Database error codes and internal state information
- Storage pruning details (e.g., "Missing state root node at version X, probably pruned") [6](#0-5) 

## Impact Explanation

This is classified as **Low Severity** according to Aptos bug bounty criteria as a "Minor information leak". While the vulnerability is real and exploitable, it does not:
- Enable theft or manipulation of funds
- Violate consensus safety or deterministic execution
- Cause state inconsistencies or availability issues
- Break any of the 10 critical invariants

The leaked information provides reconnaissance value but does not directly enable protocol-level attacks.

## Likelihood Explanation

**Likelihood: Low to Medium**

Exploitation requires triggering actual storage errors, which may occur under specific conditions:
- Accessing pruned state
- Database I/O failures
- Race conditions during state synchronization
- System resource exhaustion

While the simulation API is publicly accessible without authentication, triggering meaningful storage errors under normal operation is non-trivial.

## Recommendation

Sanitize error messages before exposing them through public APIs:

```rust
// In third_party/move/move-vm/types/src/code/errors.rs
#[macro_export]
macro_rules! module_storage_error {
    ($addr:expr, $name:expr, $err:ident) => {
        move_binary_format::errors::PartialVMError::new(
            move_core_types::vm_status::StatusCode::STORAGE_ERROR,
        )
        .with_message(format!(
            "Unexpected storage error for module {}::{}",
            $addr, $name
            // Remove the {:?} formatting of $err to prevent leaking internal details
        ))
        .finish(move_binary_format::errors::Location::Undefined)
    };
}
```

Additionally, implement error sanitization at the API boundary in the simulation endpoint to ensure no internal details leak through any error path.

## Proof of Concept

```rust
// This is a conceptual PoC - actual reproduction requires specific storage conditions

#[test]
fn test_storage_error_information_leak() {
    // 1. Create a mock StateView that returns a detailed error
    struct LeakyStateView;
    
    impl TStateView for LeakyStateView {
        type Key = StateKey;
        
        fn get_state_value_bytes(&self, _key: &StateKey) -> StateViewResult<Option<Bytes>> {
            // Simulate a RocksDB error with file path
            Err(StateViewError::Other(
                "AptosDB RocksDB Error: IO error: /var/lib/aptos/db/state_merkle_db/000123.sst: No such file or directory".to_string()
            ))
        }
        
        fn get_usage(&self) -> StateViewResult<StateStorageUsage> {
            Ok(StateStorageUsage::zero())
        }
    }
    
    // 2. Call fetch_module_bytes which will trigger the macro
    let adapter = StateViewAdapter {
        environment: &test_environment,
        state_view: &LeakyStateView,
    };
    
    let result = adapter.fetch_module_bytes(
        &AccountAddress::ONE,
        ident_str!("test_module")
    );
    
    // 3. The error message will contain the full RocksDB error including file path
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("/var/lib/aptos/db/state_merkle_db"));
}
```

**Notes**

While this vulnerability represents a real security issue with a clear exploitation path, it falls under **Low Severity** ("Minor information leaks") rather than Medium severity per the Aptos bug bounty program criteria. The leaked information does not directly compromise funds, consensus, or system availability, but provides reconnaissance value that could aid in developing more sophisticated attacks.

### Citations

**File:** aptos-move/aptos-vm-types/src/module_and_script_storage/state_view_adapter.rs (L56-65)
```rust
    fn fetch_module_bytes(
        &self,
        address: &AccountAddress,
        module_name: &IdentStr,
    ) -> VMResult<Option<Bytes>> {
        let state_key = StateKey::module(address, module_name);
        self.state_view
            .get_state_value_bytes(&state_key)
            .map_err(|e| module_storage_error!(address, module_name, e))
    }
```

**File:** third_party/move/move-vm/types/src/code/errors.rs (L5-15)
```rust
macro_rules! module_storage_error {
    ($addr:expr, $name:expr, $err:ident) => {
        move_binary_format::errors::PartialVMError::new(
            move_core_types::vm_status::StatusCode::STORAGE_ERROR,
        )
        .with_message(format!(
            "Unexpected storage error for module {}::{}: {:?}",
            $addr, $name, $err
        ))
        .finish(move_binary_format::errors::Location::Undefined)
    };
```

**File:** storage/schemadb/src/lib.rs (L390-407)
```rust
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
```

**File:** storage/storage-interface/src/errors.rs (L18-19)
```rust
    #[error("Missing state root node at version {0}, probably pruned.")]
    MissingRootError(u64),
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

**File:** api/src/transactions.rs (L1745-1755)
```rust
                            match &vm_status {
                                VMStatus::Error {
                                    message: Some(msg), ..
                                }
                                | VMStatus::ExecutionFailure {
                                    message: Some(msg), ..
                                } => {
                                    user_txn.info.vm_status +=
                                        format!("\nExecution failed with message: {}", msg)
                                            .as_str();
                                },
```
