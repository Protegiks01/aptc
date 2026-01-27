# Audit Report

## Title
Storage Service Initialization Race Condition Allows Incorrect Request Rejection During Startup Window

## Summary
A race condition exists in the Storage Service Server where `validate_request()` can be called before the `cached_storage_server_summary` is properly initialized from storage, causing the validator to use a default/empty summary that incorrectly rejects all legitimate data requests during the startup window (typically 0-100ms).

## Finding Description

The vulnerability exists in the initialization sequence of the Storage Service Server: [1](#0-0) 

When `StorageServiceServer::new()` is called, the cached storage summary is initialized with a default value: [2](#0-1) 

This default `StorageServerSummary` contains a `DataSummary` where all fields are `None`: [3](#0-2) 

The `RequestModerator` is immediately created with this default summary: [4](#0-3) 

The server then starts accepting network requests: [5](#0-4) 

However, the actual storage summary refresh happens asynchronously in a background task with a ticker interval: [6](#0-5) 

The default refresh interval is 100 milliseconds: [7](#0-6) 

During request validation, the moderator loads the cached summary: [8](#0-7) 

With the default summary (all data ranges are `None`), the `can_service()` method rejects all data requests except `GetServerProtocolVersion` and `GetStorageServerSummary`: [9](#0-8) 

When requests are rejected, the peer's invalid request counter is incremented: [10](#0-9) 

If a peer accumulates 500 invalid requests (the default maximum), it will be ignored for 5 minutes on public networks: [11](#0-10) 

## Impact Explanation

While this issue exists and is exploitable, the actual security impact is **lower than initially categorized**. Based on the Aptos Bug Bounty severity criteria:

- **NOT Critical**: Does not cause loss of funds, consensus violations, permanent network partitions, or RCE
- **NOT High**: Does not cause significant validator slowdowns or protocol violations (the 100ms window is too brief)
- **Borderline Medium-Low**: Causes temporary service degradation during a narrow startup window

The race window is extremely short (100ms by default) and self-correcting. For a peer to be incorrectly ignored for 5 minutes, it would need to send 500+ requests within the 100ms window (5,000 requests/second), which is unrealistic for normal operation.

## Likelihood Explanation

**Occurrence**: Happens on every Storage Service Server startup (100% likelihood)

**Exploitation Requirements**: 
- An attacker would need to detect when nodes are starting up
- Send sustained high-volume requests (5,000+ req/s) during the brief window
- Only affects public network peer relationships (validators/VFNs are unaffected)

**Practical Impact**: Very low - the window is too short and the conditions too specific for meaningful exploitation.

## Recommendation

Perform a synchronous initial refresh of the storage summary before starting to accept network requests:

```rust
pub async fn start(mut self) {
    // Perform initial synchronous refresh before accepting requests
    refresh_cached_storage_summary(
        self.cached_storage_server_summary.clone(),
        self.storage.clone(),
        self.storage_service_config,
        vec![], // No notifiers needed for initial sync
    );
    
    // Spawn the continuously running tasks
    self.spawn_continuous_storage_summary_tasks().await;
    
    // Now handle storage requests...
    while let Some(network_request) = self.network_requests.next().await {
        // ... request handling ...
    }
}
```

## Proof of Concept

The following test demonstrates the race condition:

```rust
#[tokio::test]
async fn test_initialization_race_condition() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::{
        DataRequest, StorageServiceRequest, TransactionsWithProofRequest,
    };
    use aptos_types::PeerId;
    
    // Create a mock storage with actual data
    let mut mock_storage = MockStorageReader::new();
    mock_storage.expect_get_data_summary()
        .returning(|| {
            Ok(DataSummary {
                synced_ledger_info: Some(create_test_ledger_info(100)),
                transactions: Some(CompleteDataRange::new(0, 100).unwrap()),
                // ... other fields populated ...
            })
        });
    
    // Create server (simulating new())
    let config = StorageServiceConfig::default();
    let cached_summary = Arc::new(ArcSwap::from(Arc::new(StorageServerSummary::default())));
    let moderator = Arc::new(RequestModerator::new(
        config.aptos_data_client,
        cached_summary.clone(),
        peers_and_metadata,
        config,
        TimeService::real(),
    ));
    
    // Create a valid request that should be serviceable
    let request = StorageServiceRequest {
        data_request: DataRequest::GetTransactionsWithProof(
            TransactionsWithProofRequest {
                start_version: 0,
                end_version: 50,
                proof_version: 100,
                include_events: false,
            }
        ),
        use_compression: false,
    };
    
    let peer_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Before refresh, the request should be rejected
    let result = moderator.validate_request(&peer_id, &request);
    assert!(result.is_err()); // This proves the race condition
    
    // After manual refresh, the same request should succeed
    refresh_cached_storage_summary(cached_summary, mock_storage, config, vec![]);
    let result = moderator.validate_request(&peer_id, &request);
    assert!(result.is_ok()); // Now it works
}
```

---

**Notes**: 

After thorough investigation, while this race condition **does exist** and is **technically valid**, the actual security impact falls below the threshold for High severity and arguably even Medium severity based on the Aptos Bug Bounty criteria. The issue is:

1. **Extremely short-lived** (100ms default window)
2. **Self-correcting** without intervention
3. **Limited practical exploitability** (requires 5,000+ req/s to cause peer ignoring)
4. **Does not affect consensus, funds, or validator operations meaningfully**

This appears to be a **Low severity** implementation quality issue rather than a security vulnerability meeting the High/Medium thresholds defined in the bounty program.

### Citations

**File:** state-sync/storage-service/server/src/lib.rs (L105-106)
```rust
        let cached_storage_server_summary =
            Arc::new(ArcSwap::from(Arc::new(StorageServerSummary::default())));
```

**File:** state-sync/storage-service/server/src/lib.rs (L110-116)
```rust
        let request_moderator = Arc::new(RequestModerator::new(
            aptos_data_client_config,
            cached_storage_server_summary.clone(),
            peers_and_metadata,
            storage_service_config,
            time_service.clone(),
        ));
```

**File:** state-sync/storage-service/server/src/lib.rs (L181-217)
```rust
        self.runtime.spawn(async move {
            // Create a ticker for the refresh interval
            let duration = Duration::from_millis(config.storage_summary_refresh_interval_ms);
            let ticker = time_service.interval(duration);
            futures::pin_mut!(ticker);

            // Continuously refresh the cache
            loop {
                futures::select! {
                    _ = ticker.select_next_some() => {
                        // Refresh the cache periodically
                        refresh_cached_storage_summary(
                            cached_storage_server_summary.clone(),
                            storage.clone(),
                            config,
                            cache_update_notifiers.clone(),
                        )
                    },
                    notification = storage_service_listener.select_next_some() => {
                        trace!(LogSchema::new(LogEntry::ReceivedCommitNotification)
                            .message(&format!(
                                "Received commit notification for highest synced version: {:?}.",
                                notification.highest_synced_version
                            ))
                        );

                        // Refresh the cache because of a commit notification
                        refresh_cached_storage_summary(
                            cached_storage_server_summary.clone(),
                            storage.clone(),
                            config,
                            cache_update_notifiers.clone(),
                        )
                    },
                }
            }
        });
```

**File:** state-sync/storage-service/server/src/lib.rs (L384-420)
```rust
    pub async fn start(mut self) {
        // Spawn the continuously running tasks
        self.spawn_continuous_storage_summary_tasks().await;

        // Handle the storage requests as they arrive
        while let Some(network_request) = self.network_requests.next().await {
            // All handler methods are currently CPU-bound and synchronous
            // I/O-bound, so we want to spawn on the blocking thread pool to
            // avoid starving other async tasks on the same runtime.
            let storage = self.storage.clone();
            let config = self.storage_service_config;
            let cached_storage_server_summary = self.cached_storage_server_summary.clone();
            let optimistic_fetches = self.optimistic_fetches.clone();
            let subscriptions = self.subscriptions.clone();
            let lru_response_cache = self.lru_response_cache.clone();
            let request_moderator = self.request_moderator.clone();
            let time_service = self.time_service.clone();
            self.runtime.spawn_blocking(move || {
                Handler::new(
                    cached_storage_server_summary,
                    optimistic_fetches,
                    lru_response_cache,
                    request_moderator,
                    storage,
                    subscriptions,
                    time_service,
                )
                .process_request_and_respond(
                    config,
                    network_request.peer_network_id,
                    network_request.protocol_id,
                    network_request.storage_service_request,
                    network_request.response_sender,
                );
            });
        }
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L612-616)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageServerSummary {
    pub protocol_metadata: ProtocolMetadata,
    pub data_summary: DataSummary,
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L666-686)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataSummary {
    /// The ledger info corresponding to the highest synced version in storage.
    /// This indicates the highest version and epoch that storage can prove.
    pub synced_ledger_info: Option<LedgerInfoWithSignatures>,
    /// The range of epoch ending ledger infos in storage, e.g., if the range
    /// is [(X,Y)], it means all epoch ending ledger infos for epochs X->Y
    /// (inclusive) are held.
    pub epoch_ending_ledger_infos: Option<CompleteDataRange<Epoch>>,
    /// The range of states held in storage, e.g., if the range is
    /// [(X,Y)], it means all states are held for every version X->Y
    /// (inclusive).
    pub states: Option<CompleteDataRange<Version>>,
    /// The range of transactions held in storage, e.g., if the range is
    /// [(X,Y)], it means all transactions for versions X->Y (inclusive) are held.
    pub transactions: Option<CompleteDataRange<Version>>,
    /// The range of transaction outputs held in storage, e.g., if the range
    /// is [(X,Y)], it means all transaction outputs for versions X->Y
    /// (inclusive) are held.
    pub transaction_outputs: Option<CompleteDataRange<Version>>,
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L688-808)
```rust
impl DataSummary {
    /// Returns true iff the request can be serviced
    pub fn can_service(
        &self,
        aptos_data_client_config: &AptosDataClientConfig,
        time_service: TimeService,
        request: &StorageServiceRequest,
    ) -> bool {
        match &request.data_request {
            GetServerProtocolVersion | GetStorageServerSummary => true,
            GetEpochEndingLedgerInfos(request) => {
                let desired_range =
                    match CompleteDataRange::new(request.start_epoch, request.expected_end_epoch) {
                        Ok(desired_range) => desired_range,
                        Err(_) => return false,
                    };
                self.epoch_ending_ledger_infos
                    .map(|range| range.superset_of(&desired_range))
                    .unwrap_or(false)
            },
            GetNewTransactionOutputsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNewTransactionsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNewTransactionsOrOutputsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNumberOfStatesAtVersion(version) => self
                .states
                .map(|range| range.contains(*version))
                .unwrap_or(false),
            GetStateValuesWithProof(request) => {
                let proof_version = request.version;

                let can_serve_states = self
                    .states
                    .map(|range| range.contains(request.version))
                    .unwrap_or(false);

                let can_create_proof = self
                    .synced_ledger_info
                    .as_ref()
                    .map(|li| li.ledger_info().version() >= proof_version)
                    .unwrap_or(false);

                can_serve_states && can_create_proof
            },
            GetTransactionOutputsWithProof(request) => self
                .can_service_transaction_outputs_with_proof(
                    request.start_version,
                    request.end_version,
                    request.proof_version,
                ),
            GetTransactionsWithProof(request) => self.can_service_transactions_with_proof(
                request.start_version,
                request.end_version,
                request.proof_version,
            ),
            GetTransactionsOrOutputsWithProof(request) => self
                .can_service_transactions_or_outputs_with_proof(
                    request.start_version,
                    request.end_version,
                    request.proof_version,
                ),
            SubscribeTransactionOutputsWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            SubscribeTransactionsOrOutputsWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            SubscribeTransactionsWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),

            // Transaction data v2 requests (transactions with auxiliary data)
            GetTransactionDataWithProof(request) => match request.transaction_data_request_type {
                TransactionDataRequestType::TransactionData(_) => self
                    .can_service_transactions_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
                TransactionDataRequestType::TransactionOutputData => self
                    .can_service_transaction_outputs_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
                TransactionDataRequestType::TransactionOrOutputData(_) => self
                    .can_service_transactions_or_outputs_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
            },
            GetNewTransactionDataWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            SubscribeTransactionDataWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
        }
    }
```

**File:** config/src/config/state_sync_config.rs (L215-215)
```rust
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
```

**File:** state-sync/storage-service/server/src/moderator.rs (L54-68)
```rust
        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
            // TODO: at some point we'll want to terminate the connection entirely

            // Start ignoring the peer
            self.ignore_start_time = Some(self.time_service.now());

            // Log the fact that we're now ignoring the peer
            warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                .peer_network_id(peer_network_id)
                .message("Ignoring peer due to too many invalid requests!"));
        }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L152-159)
```rust
            let storage_server_summary = self.cached_storage_server_summary.load();

            // Verify the request is serviceable using the current storage server summary
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
```

**File:** state-sync/storage-service/server/src/moderator.rs (L161-184)
```rust
                let mut unhealthy_peer_state = self
                    .unhealthy_peer_states
                    .entry(*peer_network_id)
                    .or_insert_with(|| {
                        // Create a new unhealthy peer state (this is the first invalid request)
                        let max_invalid_requests =
                            self.storage_service_config.max_invalid_requests_per_peer;
                        let min_time_to_ignore_peers_secs =
                            self.storage_service_config.min_time_to_ignore_peers_secs;
                        let time_service = self.time_service.clone();

                        UnhealthyPeerState::new(
                            max_invalid_requests,
                            min_time_to_ignore_peers_secs,
                            time_service,
                        )
                    });
                unhealthy_peer_state.increment_invalid_request_count(peer_network_id);

                // Return the validation error
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
```
