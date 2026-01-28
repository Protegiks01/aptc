# Audit Report

## Title
Unauthenticated Storage Server Summary Bypass Enables State Sync Denial of Service

## Summary
The state synchronization layer accepts `StorageServerSummary` responses from peers without cryptographic verification of the embedded `LedgerInfoWithSignatures`. Malicious peers can craft fake summaries with fabricated ledger info, manipulating peer selection and causing validator node slowdowns through resource exhaustion and failed sync attempts.

## Finding Description

The Aptos state synchronization system uses `StorageServerSummary` messages to determine peer capabilities for serving data requests. Each summary contains a `DataSummary` with a `synced_ledger_info` field (type `LedgerInfoWithSignatures`) that should be cryptographically signed by a quorum of validators. However, **no signature verification is performed** when these summaries are received.

**Attack Flow:**

1. **Polling without verification**: When the data client polls peers for storage summaries, responses are stored directly without any cryptographic validation. [1](#0-0) 

2. **Unverified storage**: The summary is stored in peer state with no validation of the `LedgerInfoWithSignatures`. [2](#0-1) [3](#0-2) 

3. **Capability checks rely on unverified data**: The `ProtocolMetadata.can_service()` check unconditionally returns true. [4](#0-3) 

4. **Timestamp-based freshness without verification**: The `DataSummary.can_service()` method uses the unverified `synced_ledger_info` timestamp to determine if peers can serve optimistic fetches and subscriptions. [5](#0-4) 

**Exploitation:**

A malicious peer can forge a `StorageServerSummary` containing:
- Fabricated `LedgerInfoWithSignatures` with recent timestamps and high versions
- Fake data ranges claiming complete historical state
- Invalid or missing BLS signatures (never verified)

The victim node will:
- Accept and store the fake summary
- Prioritize the malicious peer for data requests based on advertised freshness
- Waste CPU and network resources when requests timeout or fail verification
- Experience state sync delays as legitimate peers are deprioritized

**Broken Invariant**: The system assumes honest peer advertisements without cryptographic enforcement. While actual transaction data received later IS verified [6](#0-5) , the damage occurs during peer selection before any data is fetched.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty category "Validator Node Slowdowns":

1. **State Sync Disruption**: Validators attempting to sync repeatedly select malicious peers advertising fake fresh data, causing delays and retries
2. **Resource Exhaustion**: CPU cycles and network bandwidth wasted on timeout cycles and failed verification attempts  
3. **Liveness Degradation**: With sufficient malicious peers, honest nodes struggle to find reliable data sources, significantly slowing network synchronization
4. **Persistent Impact**: Malicious peers continue being polled for summaries even after being ignored for data requests [7](#0-6) , allowing repeated attacks

**Why Not Critical:**
- Actual transaction data verification prevents consensus safety violations
- No fund theft or permanent network damage
- Peer scoring system provides partial mitigation [8](#0-7) 
- System recovers through retries with honest peers

## Likelihood Explanation

**Likelihood: High**

This attack is:
- **Trivial to execute**: Any network peer can send arbitrary `StorageServerSummary` messages through standard P2P protocols
- **Zero cost**: No staking, validator status, or computational resources required
- **Persistent**: Even with low reputation scores, peers continue receiving polling requests, allowing ongoing attacks
- **Amplifiable**: Multiple coordinated malicious peers exponentially increase impact on state sync performance

The peer scoring system reduces but does not eliminate the threat, as ignored peers are only excluded from data request serving, not from summary polling.

## Recommendation

Implement cryptographic verification of `LedgerInfoWithSignatures` in storage summaries:

1. When receiving a `StorageServerSummary`, verify the `synced_ledger_info` signatures against known validator sets
2. Reject summaries with invalid or unverifiable signatures
3. For epochs ahead of the local node's known state, either reject or mark as unverified with reduced trust
4. Add verification in the `update_peer_storage_summary` path before storing

Example verification location:
```rust
// In state-sync/aptos-data-client/src/client.rs update_peer_storage_summary
pub fn update_peer_storage_summary(&self, peer: PeerNetworkId, summary: StorageServerSummary) {
    // Verify synced_ledger_info signatures if present
    if let Some(ledger_info) = &summary.data_summary.synced_ledger_info {
        if let Err(e) = self.verify_ledger_info(ledger_info) {
            warn!("Rejecting storage summary from {:?} due to invalid signatures: {:?}", peer, e);
            self.peer_states.update_score_error(peer, ErrorType::Malicious);
            return;
        }
    }
    self.peer_states.update_summary(peer, summary)
}
```

## Proof of Concept

The vulnerability can be demonstrated by creating a malicious peer that sends fake storage summaries:

1. Connect to an Aptos node as a regular peer
2. Respond to `GetStorageServerSummary` requests with a crafted response containing:
   - `synced_ledger_info` with fabricated signatures and recent timestamp  
   - High version number (e.g., current_version + 1000000)
   - Complete data ranges for all types
3. Observe the victim node selecting the malicious peer for data requests
4. Measure increased timeout rates and sync delays as requests fail

The attack succeeds because there is no verification path in the codebase for storage summary ledger infos, as confirmed by the absence of any `verify_signatures` calls on `synced_ledger_info` in the polling and storage paths.

### Citations

**File:** state-sync/aptos-data-client/src/poller.rs (L406-439)
```rust
        let data_request = DataRequest::GetStorageServerSummary;
        let use_compression = data_summary_poller.data_client_config.use_compression;
        let storage_request = StorageServiceRequest::new(data_request, use_compression);

        // Fetch the storage summary for the peer and stop the timer
        let request_timeout = data_summary_poller.data_client_config.response_timeout_ms;
        let result: crate::error::Result<StorageServerSummary> = data_summary_poller
            .data_client
            .send_request_to_peer_and_decode(peer, storage_request, request_timeout)
            .await
            .map(Response::into_payload);

        // Mark the in-flight poll as now complete
        data_summary_poller.in_flight_request_complete(&peer);

        // Check the storage summary response
        let storage_summary = match result {
            Ok(storage_summary) => storage_summary,
            Err(error) => {
                warn!(
                    (LogSchema::new(LogEntry::StorageSummaryResponse)
                        .event(LogEvent::PeerPollingError)
                        .message("Error encountered when polling peer!")
                        .error(&error)
                        .peer(&peer))
                );
                return;
            },
        };

        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L152-174)
```rust
    fn is_ignored(&self) -> bool {
        // Only ignore peers if the config allows it
        if !self.data_client_config.ignore_low_score_peers {
            return false;
        }

        // Otherwise, ignore peers with a low score
        self.score <= IGNORE_PEER_THRESHOLD
    }

    /// Updates the score of the peer according to a successful operation
    fn update_score_success(&mut self) {
        self.score = f64::min(self.score + SUCCESSFUL_RESPONSE_DELTA, MAX_SCORE);
    }

    /// Updates the score of the peer according to an error
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L177-179)
```rust
    fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
        self.storage_summary = Some(storage_summary);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L325-330)
```rust
    pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
        self.peer_to_state
            .entry(peer)
            .or_insert(PeerState::new(self.data_client_config.clone()))
            .update_storage_summary(storage_summary);
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L644-651)
```rust
impl ProtocolMetadata {
    /// We deem all requests serviceable, even if the requested chunk
    /// sizes are larger than the maximum sizes that can be served (the
    /// response will simply be truncated on the server side).
    pub fn can_service(&self, _request: &StorageServiceRequest) -> bool {
        true // TODO: figure out if should eventually remove this
    }
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L892-934)
```rust
/// Returns true iff an optimistic data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_optimistic_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_optimistic_fetch_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff a subscription data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_subscription_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff the synced ledger info timestamp
/// is within the given lag (in seconds).
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
}
```

**File:** state-sync/state-sync-driver/src/utils.rs (L100-110)
```rust
    /// Verifies the given ledger info with signatures against the current epoch state
    pub fn verify_ledger_info_with_signatures(
        &mut self,
        ledger_info_with_signatures: &LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        self.epoch_state
            .verify(ledger_info_with_signatures)
            .map_err(|error| {
                Error::VerificationError(format!("Ledger info failed verification: {:?}", error))
            })
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L603-625)
```rust
    pub fn get_priority_and_regular_peers(
        &self,
    ) -> crate::error::Result<(HashSet<PeerNetworkId>, HashSet<PeerNetworkId>), Error> {
        // Get all connected peers
        let all_connected_peers = self.get_all_connected_peers()?;

        // Gather the priority and regular peers
        let mut priority_peers = hashset![];
        let mut regular_peers = hashset![];
        for peer in all_connected_peers {
            if priority::is_high_priority_peer(
                self.base_config.clone(),
                self.get_peers_and_metadata(),
                &peer,
            ) {
                priority_peers.insert(peer);
            } else {
                regular_peers.insert(peer);
            }
        }

        Ok((priority_peers, regular_peers))
    }
```
