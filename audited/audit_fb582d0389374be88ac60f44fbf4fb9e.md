# Audit Report

## Title
State View Error Messages Expose Internal Database and System Configuration Details to External API Clients

## Summary
API endpoints in `api/src/state.rs` expose raw `StateViewError` messages that contain sensitive internal information including database file paths, RocksDB error details, and system configuration. External clients can trigger these errors through normal API requests and receive detailed error messages revealing validator storage structure, database implementation details, and file system paths.

## Finding Description
The vulnerability exists in the error handling flow from the storage layer through to the API response layer:

1. **Database errors contain sensitive details**: When RocksDB operations fail (corruption, IO errors, missing files), the errors are converted to `AptosDbError` variants that preserve the full error message including file paths and internal details. [1](#0-0) 

2. **Error conversion preserves messages**: `AptosDbError` is converted to `StateViewError::Other` with the complete error message intact. [2](#0-1) 

3. **StateViewError structure allows arbitrary strings**: The `StateViewError` enum contains `NotFound(String)` and `Other(String)` variants that can carry any error message, and the `From<anyhow::Error>` implementation formats the entire error. [3](#0-2) 

4. **API layer exposes error messages**: In `api/src/state.rs`, when database operations fail, errors are wrapped with context and converted to `AptosError` using alternative formatting (`{:#}`) which expands the full error chain. [4](#0-3) 

5. **AptosError serializes message field**: The `AptosError` struct has a public `message` field that is serialized in JSON API responses, exposing the complete error chain to external clients. [5](#0-4) 

Information that can be leaked includes:
- Database file paths (e.g., `/opt/aptos/data/db/state_kv_db/shard_0`)
- RocksDB error details (corruption messages, version incompatibilities)
- System configuration (shard IDs, database structure)
- Storage implementation details (hot state vs. regular state paths)

## Impact Explanation
This vulnerability is classified as **Low Severity** according to the Aptos bug bounty criteria. It constitutes a "minor information leak" that exposes internal implementation details but does not directly lead to:
- Loss of funds or asset manipulation
- Consensus safety violations
- State inconsistencies
- Network availability issues

However, the leaked information could aid attackers in:
- Reconnaissance for targeting specific validators
- Understanding system architecture for crafting other attacks
- Identifying potential misconfigurations

## Likelihood Explanation
**Likelihood: High**

This vulnerability is easily exploitable:
- Any external client can make API requests to public endpoints
- No authentication or special privileges required
- Errors can be triggered naturally through invalid requests or during transient database issues
- Multiple API endpoints are affected (resource queries, table lookups, raw state value requests)

## Recommendation
Implement sanitized error messages for external API responses:

1. **Create an error sanitization layer** that maps internal errors to generic messages:
```rust
// In api/src/state.rs or a new error handling module
fn sanitize_storage_error(err: anyhow::Error) -> String {
    // Log the full error internally for debugging
    aptos_logger::error!("Storage error: {:#}", err);
    
    // Return generic message to client
    "Failed to retrieve state from storage".to_string()
}
```

2. **Update error handlers** in `api/src/state.rs` to use sanitized messages:
```rust
.context("Failed to query DB")
.map_err(|err| {
    BasicErrorWith404::internal_with_code(
        sanitize_storage_error(err),
        AptosErrorCode::InternalError,
        &ledger_info,
    )
})?
```

3. **Retain detailed logging** for operators while protecting external exposure.

## Proof of Concept
```bash
# Query a non-existent resource to trigger a database lookup
curl -X GET "https://fullnode.mainnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::account::NonExistentResource" \
  -H "Accept: application/json"

# The response may contain detailed error messages like:
# "Failed to query DB to check for StateKey(AccessPath { address: 0x1, path: ... }): 
#  RocksDB error: Corruption: corrupted compressed block contents at /opt/aptos/data/db/..."

# Similarly, triggering table item queries with invalid parameters:
curl -X POST "https://fullnode.mainnet.aptoslabs.com/v1/tables/0x1/item" \
  -H "Content-Type: application/json" \
  -d '{"key_type": "address", "value_type": "u64", "key": "0x999"}' 

# May expose database paths in error responses during transient DB failures
```

## Notes
While this is a valid information disclosure vulnerability, it is classified as **Low Severity** per the Aptos bug bounty criteria ("Minor information leaks"). The vulnerability does not meet the Medium severity threshold which requires "State inconsistencies requiring intervention" or "Limited funds loss or manipulation."

The recommended fix maintains security logging for operators while preventing external reconnaissance through error message analysis.

### Citations

**File:** storage/schemadb/src/lib.rs (L389-407)
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

**File:** types/src/state_store/errors.rs (L6-21)
```rust
#[derive(Debug, Error)]
pub enum StateViewError {
    #[error("{0} not found.")]
    NotFound(String),
    /// Other non-classified error.
    #[error("{0}")]
    Other(String),
    #[error(transparent)]
    BcsError(#[from] bcs::Error),
}

impl From<anyhow::Error> for StateViewError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(format!("{}", error))
    }
}
```

**File:** api/src/state.rs (L289-303)
```rust
        let bytes = state_view
            .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
            .find_resource(&state_view, address, &tag)
            .context(format!(
                "Failed to query DB to check for {} at {}",
                tag.to_canonical_string(),
                address
            ))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &ledger_info,
                )
            })?
```

**File:** api/types/src/error.rs (L28-38)
```rust
impl AptosError {
    pub fn new_with_error_code<ErrorType: std::fmt::Display>(
        error: ErrorType,
        error_code: AptosErrorCode,
    ) -> AptosError {
        Self {
            message: format!("{:#}", error),
            error_code,
            vm_error_code: None,
        }
    }
```
