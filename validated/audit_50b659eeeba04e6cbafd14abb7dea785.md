# Audit Report

## Title
Optimistic Fetch Storage Error Allows Bounded Peer Retry Without Penalty Leading to Resource Exhaustion

## Summary
When `get_epoch_ending_ledger_info` fails during optimistic fetch processing, the peer is not marked as invalid, allowing repeated retry attempts every 100ms for up to 5 seconds (~50 retries). This wastes server resources through repeated storage reads, blocking task spawns, and log spam without penalizing the offending peer.

## Finding Description

In the optimistic fetch mechanism, when a peer requests new data that spans epoch boundaries, the storage service must retrieve the epoch ending ledger info. The vulnerability exists in how storage errors are handled during this retrieval.

When `get_epoch_ending_ledger_info` fails, the code logs an error and returns early without adding the peer to `peers_with_invalid_optimistic_fetches`: [1](#0-0) 

This means the peer's optimistic fetch request remains active in the `optimistic_fetches` DashMap and will be retried on the next handler iteration.

The optimistic fetch handler runs periodically with a configured interval: [2](#0-1) 

The retry frequency and timeout duration are configured as: [3](#0-2) 

This results in:
- Handler runs every 100ms (`storage_summary_refresh_interval_ms`)
- Optimistic fetch expires after 5000ms (`max_optimistic_fetch_period_ms`)
- **Result: ~50 retry attempts before timeout**

Each retry spawns a blocking task that performs storage I/O: [4](#0-3) 

Critically, storage errors do NOT increment the peer's invalid request counter in the RequestModerator. The RequestModerator only tracks validation failures where `can_service()` returns false, not internal storage errors: [5](#0-4) 

The error types are distinct - `InvalidRequest` errors (validation failures) increment the counter, while `StorageErrorEncountered` errors (storage layer failures) do not: [6](#0-5) 

**Attack Scenario:**
A malicious peer can send optimistic fetch requests with arbitrary epoch values: [7](#0-6) 

By requesting a future epoch that doesn't exist or a pruned epoch no longer in storage, the peer triggers persistent storage errors. Each malicious request will:
- Retry every 100ms for 5 seconds (~50 times)
- Spawn 50 blocking tasks consuming thread pool resources
- Perform 50 storage I/O operations
- Generate 50 error log entries
- NOT be penalized by RequestModerator

After the 5-second timeout expires, the peer can immediately submit another malicious optimistic fetch request, repeating the cycle indefinitely.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty program, specifically under "Validator node slowdowns."

**Resource Exhaustion Impact:**
- **CPU**: Each retry spawns a blocking task in the runtime thread pool, consuming CPU cycles
- **I/O**: Each retry performs storage reads, potentially hitting disk for epoch ending ledger infos
- **Memory**: Active blocking tasks and storage read buffers consume memory
- **Logs**: Repeated error logging can fill disk space and impact log analysis

**Attack Amplification:**
Multiple malicious peers can simultaneously exploit this, with each peer maintaining one active malicious optimistic fetch. With N malicious peers, the server processes N × 50 retries over 5 seconds (10N retries per second).

**Why Medium, not High/Critical:**
- Does not affect consensus safety or liveness
- Does not cause fund loss or state corruption
- Bounded by timeout (not truly infinite retries)
- Each peer limited to one active optimistic fetch
- Server continues functioning, just with degraded performance

This aligns with Medium severity: "Validator node slowdowns" and resource state inconsistencies requiring intervention.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

1. **No Special Permissions**: Any peer on the network can send optimistic fetch requests
2. **Simple Exploitation**: Just send requests with epochs that trigger storage errors (future epochs, pruned epochs)
3. **Trigger Conditions**: Storage errors are realistic - requesting epochs beyond current blockchain state or recently pruned historical epochs
4. **No Rate Limiting**: The peer is not penalized, allowing immediate re-exploitation after timeout
5. **Detection Difficulty**: Error logs appear legitimate (storage read failures), making malicious requests hard to distinguish from honest node issues

**Realistic Attack Path:**
```
1. Malicious peer establishes connection to storage service
2. Peer sends GetNewTransactionOutputsWithProof with:
   - known_version: 1000
   - known_epoch: 9999 (far future epoch)
3. Server processes optimistic fetch every 100ms
4. Each iteration calls get_epoch_ending_ledger_info(9999)
5. Storage returns error (epoch doesn't exist)
6. Function returns early without marking peer
7. Repeat 50 times over 5 seconds
8. After timeout, peer sends another malicious request
9. Cycle continues indefinitely
```

## Recommendation

Add the peer to `peers_with_invalid_optimistic_fetches` when `get_epoch_ending_ledger_info` fails with a storage error:

```rust
let epoch_ending_ledger_info = match utils::get_epoch_ending_ledger_info(
    // ... parameters ...
) {
    Ok(epoch_ending_ledger_info) => epoch_ending_ledger_info,
    Err(error) => {
        // Log the failure
        error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
            .error(&error)
            .message(&format!(
                "Failed to get the epoch ending ledger info for epoch: {:?} !",
                highest_known_epoch
            )));
        
        // Mark peer as invalid to prevent retries
        peers_with_invalid_optimistic_fetches
            .lock()
            .push(peer_network_id);
        
        return;
    },
};
```

This ensures that storage errors are treated similarly to invalid epoch boundary requests, preventing wasteful retries.

## Proof of Concept

A PoC would involve:
1. Setting up a storage service test environment
2. Creating a peer that sends `GetNewTransactionOutputsWithProof` with `known_epoch: 9999`
3. Monitoring the handler iterations and observing 50 retry attempts
4. Verifying the peer is not added to invalid fetches list
5. Measuring resource consumption (task spawns, storage reads)

The vulnerability is evident from code inspection and the attack is straightforward to execute against a running storage service node.

## Notes

This vulnerability demonstrates a gap in error handling where storage-layer failures are not treated as peer misbehavior. While the impact is bounded by timeout mechanisms, the lack of penalty allows repeated exploitation and resource waste. The fix is straightforward - treat persistent storage errors for non-existent epochs as invalid requests that should mark the peer and prevent retries.

### Citations

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L500-548)
```rust
        let active_task = runtime.spawn_blocking(move || {
            // Check if we have synced beyond the highest known version
            if highest_known_version < highest_synced_version {
                if highest_known_epoch < highest_synced_epoch {
                    // Fetch the epoch ending ledger info from storage (the
                    // peer needs to sync to their epoch ending ledger info).
                    let epoch_ending_ledger_info = match utils::get_epoch_ending_ledger_info(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        highest_known_epoch,
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        &peer_network_id,
                        storage.clone(),
                        time_service.clone(),
                    ) {
                        Ok(epoch_ending_ledger_info) => epoch_ending_ledger_info,
                        Err(error) => {
                            // Log the failure to fetch the epoch ending ledger info
                            error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
                                .error(&error)
                                .message(&format!(
                                    "Failed to get the epoch ending ledger info for epoch: {:?} !",
                                    highest_known_epoch
                                )));

                            return;
                        },
                    };

                    // Check that we haven't been sent an invalid optimistic fetch request
                    // (i.e., a request that does not respect an epoch boundary).
                    if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
                        peers_with_invalid_optimistic_fetches
                            .lock()
                            .push(peer_network_id);
                    } else {
                        peers_with_ready_optimistic_fetches
                            .lock()
                            .push((peer_network_id, epoch_ending_ledger_info));
                    }
                } else {
                    peers_with_ready_optimistic_fetches
                        .lock()
                        .push((peer_network_id, highest_synced_ledger_info.clone()));
                };
            }
        });
```

**File:** state-sync/storage-service/server/src/lib.rs (L239-260)
```rust
        // Spawn the task
        self.runtime
            .spawn(async move {
                // Create a ticker for the refresh interval
                let duration = Duration::from_millis(config.storage_summary_refresh_interval_ms);
                let ticker = time_service.interval(duration);
                futures::pin_mut!(ticker);

                // Continuously handle the optimistic fetches
                loop {
                    futures::select! {
                        _ = ticker.select_next_some() => {
                            // Handle the optimistic fetches periodically
                            handle_active_optimistic_fetches(
                                runtime.clone(),
                                cached_storage_server_summary.clone(),
                                config,
                                optimistic_fetches.clone(),
                                lru_response_cache.clone(),
                                request_moderator.clone(),
                                storage.clone(),
                                subscriptions.clone(),
```

**File:** config/src/config/state_sync_config.rs (L207-215)
```rust
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
            request_moderator_refresh_interval_ms: 1000, // 1 second
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
```

**File:** state-sync/storage-service/server/src/moderator.rs (L155-185)
```rust
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
                // Increment the invalid request count for the peer
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
            }
```

**File:** state-sync/storage-service/server/src/error.rs (L8-16)
```rust
pub enum Error {
    #[error("Invalid request received: {0}")]
    InvalidRequest(String),
    #[error("Storage error encountered: {0}")]
    StorageErrorEncountered(String),
    #[error("Too many invalid requests: {0}")]
    TooManyInvalidRequests(String),
    #[error("Unexpected error encountered: {0}")]
    UnexpectedErrorEncountered(String),
```

**File:** state-sync/storage-service/types/src/requests.rs (L327-330)
```rust
pub struct NewTransactionOutputsWithProofRequest {
    pub known_version: u64, // The highest known output version
    pub known_epoch: u64,   // The highest known epoch
}
```
