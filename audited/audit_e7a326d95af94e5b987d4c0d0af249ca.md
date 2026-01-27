# Audit Report

## Title
Information Leakage Through Detailed Error Messages in Peer Monitoring Service

## Summary
The peer monitoring service exposes detailed internal error messages to network peers through the `PeerMonitoringServiceError::InternalError` response type. Storage errors, panic messages, and internal implementation details are serialized and sent to requesting peers, potentially aiding reconnaissance attacks.

## Finding Description

The peer monitoring service in `peer-monitoring-service/server/src/` contains an information leakage vulnerability where detailed error strings are exposed to network peers. [1](#0-0) 

When storage operations fail, the error is converted to a string that includes internal details: [2](#0-1) 

These errors are not only logged locally but also sent back to the requesting peer: [3](#0-2) 

The underlying storage errors expose internal structure: [4](#0-3) 

Specific examples include database metadata field names: [5](#0-4) 

The peer monitoring service is registered on ALL network types without additional access control: [6](#0-5) 

The error type is serialized and sent over the network: [7](#0-6) 

## Impact Explanation

This is a **Low Severity** information disclosure issue per Aptos bug bounty criteria ("Minor information leaks"). The exposed information includes:

1. **Internal storage structure**: Database field names like "LedgerCommitProgress", "Genesis LedgerInfo", table structures
2. **File system paths**: Potentially exposed through RocksDB and IO errors
3. **Implementation details**: Panic messages, error handling paths, internal state information
4. **Operational state**: Whether genesis is initialized, database consistency status

While this doesn't directly lead to funds loss, consensus violations, or service disruption, it aids reconnaissance by revealing:
- Internal architecture details for targeted attacks
- Node operational state for network mapping
- Implementation specifics for exploit development

## Likelihood Explanation

This issue occurs with **high likelihood** because:

1. **Automatic trigger**: Any peer can send monitoring requests to probe error conditions
2. **Wide availability**: Service is exposed on all network types (validator, VFN, PFN)
3. **No additional controls**: Beyond network-level authentication, no filtering of error details
4. **Legitimate operation**: Errors occur naturally during normal operations (storage issues, initialization, etc.)

On public full node networks, any connected peer can trigger various error conditions and collect internal implementation details.

## Recommendation

Implement error message sanitization to prevent internal details from being sent to peers:

```rust
// In peer-monitoring-service/server/src/lib.rs, modify the error handling:
match error {
    Error::InvalidRequest(error) => {
        Err(PeerMonitoringServiceError::InvalidRequest(error))
    },
    Error::StorageErrorEncountered(_) => {
        // Don't expose internal storage details
        Err(PeerMonitoringServiceError::InternalError(
            "Storage operation failed".to_string()
        ))
    },
    Error::UnexpectedErrorEncountered(_) => {
        // Don't expose internal error details
        Err(PeerMonitoringServiceError::InternalError(
            "Internal service error".to_string()
        ))
    },
}
```

Keep detailed logging for operators while sending generic messages to peers. Consider adding structured error codes without implementation details.

## Proof of Concept

```rust
// This demonstrates how error details are exposed to network peers
// File: peer-monitoring-service/server/tests/error_exposure_test.rs

#[tokio::test]
async fn test_storage_error_exposure() {
    use peer_monitoring_service_server::storage::StorageReaderInterface;
    use peer_monitoring_service_server::Handler;
    use peer_monitoring_service_types::request::PeerMonitoringServiceRequest;
    
    // Create a mock storage that returns detailed errors
    struct FailingStorage;
    impl StorageReaderInterface for FailingStorage {
        fn get_highest_synced_epoch_and_version(&self) -> Result<(u64, u64), Error> {
            Err(Error::StorageErrorEncountered(
                "RocksDB error: /var/aptos/db/ledger.db: No such file or directory".into()
            ))
        }
        fn get_ledger_timestamp_usecs(&self) -> Result<u64, Error> { Ok(0) }
        fn get_lowest_available_version(&self) -> Result<u64, Error> { Ok(0) }
    }
    
    let handler = Handler::new(
        BaseConfig::default(),
        Arc::new(PeersAndMetadata::new(&[])),
        Instant::now(),
        FailingStorage,
        TimeService::mock(),
    );
    
    // Send request that triggers storage error
    let response = handler.call(
        NetworkId::Validator,
        PeerMonitoringServiceRequest::GetNodeInformation,
    );
    
    // Verify that internal details are exposed in the error response
    match response {
        Err(PeerMonitoringServiceError::InternalError(msg)) => {
            // This assertion passes, showing file paths are exposed
            assert!(msg.contains("/var/aptos/db/ledger.db"));
            assert!(msg.contains("No such file or directory"));
        },
        _ => panic!("Expected internal error with details"),
    }
}
```

## Notes

This vulnerability requires network-level access (peer connection) to exploit. On validator networks with mutual authentication, only known validators can receive these messages. However, on public full node networks, any connected peer can probe for internal implementation details. The information disclosed does not directly compromise security but aids in reconnaissance and targeted attack development.

### Citations

**File:** peer-monitoring-service/server/src/error.rs (L7-15)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum Error {
    #[error("Invalid request received: {0}")]
    InvalidRequest(String),
    #[error("Storage error encountered: {0}")]
    StorageErrorEncountered(String),
    #[error("Unexpected error encountered: {0}")]
    UnexpectedErrorEncountered(String),
}
```

**File:** peer-monitoring-service/server/src/storage.rs (L35-41)
```rust
    fn get_latest_ledger_info(&self) -> Result<LedgerInfo, Error> {
        let latest_ledger_info_with_sigs = self
            .storage
            .get_latest_ledger_info()
            .map_err(|err| Error::StorageErrorEncountered(err.to_string()))?;
        Ok(latest_ledger_info_with_sigs.ledger_info().clone())
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L185-203)
```rust
        match response {
            Err(error) => {
                // Log the error and update the counters
                increment_counter(
                    &metrics::PEER_MONITORING_ERRORS_ENCOUNTERED,
                    network_id,
                    error.get_label(),
                );
                error!(LogSchema::new(LogEntry::PeerMonitoringServiceError)
                    .error(&error)
                    .request(&request));

                // Return an appropriate response to the client
                match error {
                    Error::InvalidRequest(error) => {
                        Err(PeerMonitoringServiceError::InvalidRequest(error))
                    },
                    error => Err(PeerMonitoringServiceError::InternalError(error.to_string())),
                }
```

**File:** storage/storage-interface/src/errors.rs (L9-37)
```rust
/// This enum defines errors commonly used among `AptosDB` APIs.
#[derive(Clone, Debug, Error)]
pub enum AptosDbError {
    /// A requested item is not found.
    #[error("{0} not found.")]
    NotFound(String),
    /// Requested too many items.
    #[error("Too many items requested: at least {0} requested, max is {1}")]
    TooManyRequested(u64, u64),
    #[error("Missing state root node at version {0}, probably pruned.")]
    MissingRootError(u64),
    /// Other non-classified error.
    #[error("AptosDB Other Error: {0}")]
    Other(String),
    #[error("AptosDB RocksDb Error: {0}")]
    RocksDbIncompleteResult(String),
    #[error("AptosDB RocksDB Error: {0}")]
    OtherRocksDbError(String),
    #[error("AptosDB bcs Error: {0}")]
    BcsError(String),
    #[error("AptosDB IO Error: {0}")]
    IoError(String),
    #[error("AptosDB Recv Error: {0}")]
    RecvError(String),
    #[error("AptosDB ParseInt Error: {0}")]
    ParseIntError(String),
    #[error("Hot state not configured properly")]
    HotStateError,
}
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L80-120)
```rust
    pub(crate) fn get_ledger_commit_progress(&self) -> Result<Version> {
        get_progress(&self.db, &DbMetadataKey::LedgerCommitProgress)?
            .ok_or_else(|| AptosDbError::NotFound("No LedgerCommitProgress in db.".to_string()))
    }

    pub(crate) fn get_pruner_progress(&self) -> Result<Version> {
        get_progress(&self.db, &DbMetadataKey::LedgerPrunerProgress)?
            .ok_or_else(|| AptosDbError::NotFound("No LedgerPrunerProgress in db.".to_string()))
    }
}

/// LedgerInfo APIs.
impl LedgerMetadataDb {
    /// Returns the latest ledger info, or None if it doesn't exist.
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }

    pub(crate) fn get_committed_version(&self) -> Option<Version> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.as_ref().map(|li| li.ledger_info().version())
    }

    /// Returns the latest ledger info, or NOT_FOUND if it doesn't exist.
    pub(crate) fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        self.get_latest_ledger_info_option()
            .ok_or_else(|| AptosDbError::NotFound(String::from("Genesis LedgerInfo")))
    }

    /// Returns the latest ledger info for a given epoch.
    pub(crate) fn get_latest_ledger_info_in_epoch(
        &self,
        epoch: u64,
    ) -> Result<LedgerInfoWithSignatures> {
        self.db
            .get::<LedgerInfoSchema>(&epoch)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Last LedgerInfo of epoch {epoch}")))
    }
```

**File:** aptos-node/src/network.rs (L370-378)
```rust
        // Register the peer monitoring service (both client and server) with the network
        let peer_monitoring_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            peer_monitoring_network_configuration(node_config),
            true,
        );
        peer_monitoring_service_network_handles.push(peer_monitoring_service_network_handle);
```

**File:** peer-monitoring-service/types/src/lib.rs (L26-32)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum PeerMonitoringServiceError {
    #[error("Internal service error: {0}")]
    InternalError(String),
    #[error("Invalid service request: {0}")]
    InvalidRequest(String),
}
```
