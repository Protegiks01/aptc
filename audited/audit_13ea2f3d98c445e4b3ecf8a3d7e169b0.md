# Audit Report

## Title
Malicious Peer Can DoS State Synchronization Through Unvalidated Advertised Ledger Info Versions

## Summary
A malicious peer can advertise a fraudulent `synced_ledger_info` with an arbitrarily high version number in their storage summary. This unvalidated data is incorporated into the global data summary and causes subscription streams to repeatedly detect irrecoverable lag, leading to continuous task abortion and preventing nodes from successfully synchronizing state.

## Finding Description

The vulnerability exists in the state synchronization subsystem where peer-advertised storage summaries are not validated before being aggregated into the global data summary.

**Attack Flow:**

1. A malicious peer connects to a victim node and responds to storage summary polls with a fraudulent `StorageServerSummary` containing a `synced_ledger_info` with an extremely high version number (e.g., `u64::MAX`). [1](#0-0) 

2. The storage summary is stored without any signature verification or validity checks on the advertised ledger info: [2](#0-1) 

3. This fraudulent ledger info is aggregated into the global data summary where it becomes the highest advertised version: [3](#0-2) [4](#0-3) 

4. When subscription streams process legitimate responses, they check for lag against this fraudulent high version: [5](#0-4) 

5. The calculated lag is massive, and after `max_subscription_stream_lag_secs`, the stream is deemed beyond recovery: [6](#0-5) 

6. This triggers `notify_new_data_request_error()` which calls `clear_sent_data_requests_queue()`: [7](#0-6) 

7. All spawned tasks are aborted: [8](#0-7) 

8. The subscription stream is reset, but when a new subscription is created, it faces the same fraudulent advertised version, creating a continuous DoS loop: [9](#0-8) [10](#0-9) 

**Critical Issue:** The malicious peer is NOT penalized because advertising high versions in storage summaries is not detected as malicious behavior. The peer scoring mechanism only triggers on bad responses, not on fraudulent advertisements: [11](#0-10) 

## Impact Explanation

This vulnerability constitutes **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: Affected nodes experience continuous task abortion cycles, preventing them from successfully synchronizing state and catching up to the network. This directly impacts validator availability and network participation.

2. **Significant Protocol Violations**: The state synchronization protocol's fundamental assumption—that advertised data reflects actual available data—is violated. This breaks the trust model for peer discovery and data availability.

3. **Availability Impact**: While the attack doesn't cause permanent network failure, it creates sustained operational disruption requiring manual intervention (peer disconnection or network reconfiguration).

The attack does not directly threaten consensus safety or cause fund loss, but it significantly degrades network availability for affected nodes.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack Complexity: Low** - The attacker only needs to connect as a regular peer and respond to storage summary polls with crafted data. No sophisticated cryptographic attacks or race conditions are required.

- **Privilege Required: None** - Any network peer can execute this attack without special permissions or validator access.

- **Attack Persistence: High** - The fraudulent data persists in the global data summary as long as the malicious peer remains connected. The attack automatically repeats every `max_subscription_stream_lag_secs` (configurable, typically 60-300 seconds).

- **Detection Difficulty: Medium** - While logs would show repeated subscription stream failures, attributing this to a specific malicious peer requires careful analysis of the global data summary and peer advertisements.

- **Mitigation Bypass: Easy** - The peer scoring system does not penalize peers for advertising high versions, so the malicious peer maintains a good score and continues to influence the global data summary.

## Recommendation

**Immediate Fix:** Validate `LedgerInfoWithSignatures` in storage summaries before incorporating them into the global data summary. Verify that:

1. The signatures are valid against the current or recent epoch validator set
2. The advertised version is reasonable relative to known synced state
3. The ledger info is not fraudulently ahead of network consensus

**Code Fix Location:** `state-sync/aptos-data-client/src/peer_states.rs`

```rust
fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
    // Validate synced_ledger_info before accepting
    if let Some(ref synced_ledger_info) = storage_summary.data_summary.synced_ledger_info {
        // Verify signatures against known validator set
        // Verify version is within reasonable bounds
        // If validation fails, penalize peer and reject summary
        if !self.validate_synced_ledger_info(synced_ledger_info) {
            self.update_score_error(ErrorType::Malicious);
            return; // Reject the fraudulent summary
        }
    }
    self.storage_summary = Some(storage_summary);
}

fn validate_synced_ledger_info(&self, ledger_info: &LedgerInfoWithSignatures) -> bool {
    // Implementation should verify:
    // 1. Signatures are valid
    // 2. Version is not impossibly high
    // 3. Epoch is consistent with known state
    // Return false if any validation fails
}
```

**Additional Mitigations:**

1. Implement bounds checking on advertised versions relative to local synced state
2. Add metrics to detect anomalously high advertised versions
3. Consider using median instead of maximum when determining highest advertised version to reduce impact of outliers
4. Enhance peer scoring to penalize peers whose advertisements are significantly out of sync with network majority

## Proof of Concept

**Rust Reproduction Steps:**

```rust
// Conceptual PoC - demonstrates the attack flow
// In a test environment with aptos-data-client:

use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use aptos_storage_service_types::responses::{StorageServerSummary, DataSummary};

#[tokio::test]
async fn test_malicious_advertised_version_dos() {
    // Setup: Create a victim node with data streaming service
    let (data_client, streaming_service) = setup_test_environment();
    
    // Attack Step 1: Malicious peer advertises fraudulent high version
    let malicious_peer = PeerNetworkId::random();
    let fraudulent_ledger_info = create_fraudulent_ledger_info(u64::MAX); // Impossibly high version
    
    let malicious_summary = StorageServerSummary {
        protocol_metadata: ProtocolMetadata::default(),
        data_summary: DataSummary {
            synced_ledger_info: Some(fraudulent_ledger_info),
            ..Default::default()
        },
    };
    
    // Simulate peer poll response
    data_client.update_peer_storage_summary(malicious_peer, malicious_summary);
    data_client.update_global_summary_cache().unwrap();
    
    // Attack Step 2: Victim's subscription stream receives legitimate data
    // but appears to be massively lagging due to fraudulent advertised version
    let legitimate_response_version = 1000; // Current network version
    
    // Verify the global data summary contains the fraudulent high version
    let global_summary = data_client.get_global_data_summary();
    let highest_advertised = global_summary.advertised_data
        .highest_synced_ledger_info()
        .unwrap()
        .ledger_info()
        .version();
    
    assert_eq!(highest_advertised, u64::MAX); // Fraudulent version is used!
    
    // Attack Step 3: Process subscription response - triggers lag detection
    // After max_subscription_stream_lag_secs, stream is terminated and tasks aborted
    // The cycle repeats, causing continuous DoS
    
    // Verification: Observe repeated task abortion and stream restarts
    // in metrics and logs
}

fn create_fraudulent_ledger_info(version: u64) -> LedgerInfoWithSignatures {
    // Create a ledger info with invalid/no signatures but high version
    // Real attacker would send this in storage summary response
    LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(/* high version */, /* ... */),
            /* ... */
        ),
        AggregateSignature::empty(), // Invalid signatures
    )
}
```

**Observable Symptoms:**
- Metrics show `CREATE_SUBSCRIPTION_STREAM` repeatedly incrementing
- Logs show repeated "Subscription stream is beyond recovery" messages
- All subscription data request tasks are repeatedly aborted
- Node fails to make state sync progress despite available data from honest peers
- Attack persists until malicious peer is manually disconnected

**Notes**

This vulnerability is particularly concerning because:
1. It bypasses the peer reputation system entirely
2. A single malicious peer can disrupt state sync for multiple victims
3. The attack is self-sustaining once the fraudulent data enters the global summary
4. Nodes with subscription streaming enabled (common configuration) are vulnerable
5. The fix requires signature verification infrastructure that should have been present from the start

The root cause is the violation of the principle that **untrusted peer data must be cryptographically verified before use in protocol-critical decisions**. The `LedgerInfoWithSignatures` type includes signatures specifically for verification, but this verification is not performed when processing storage summaries.

### Citations

**File:** state-sync/aptos-data-client/src/poller.rs (L422-439)
```rust
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L168-174)
```rust
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L374-378)
```rust
            if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
            }
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L184-198)
```rust
    pub fn highest_synced_ledger_info(&self) -> Option<LedgerInfoWithSignatures> {
        let highest_synced_position = self
            .synced_ledger_infos
            .iter()
            .map(|ledger_info_with_sigs| ledger_info_with_sigs.ledger_info().version())
            .position_max();

        if let Some(highest_synced_position) = highest_synced_position {
            self.synced_ledger_infos
                .get(highest_synced_position)
                .cloned()
        } else {
            None
        }
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L176-184)
```rust
    pub fn clear_sent_data_requests_queue(&mut self) {
        // Clear all pending data requests
        if let Some(sent_data_requests) = self.sent_data_requests.as_mut() {
            sent_data_requests.clear();
        }

        // Abort all spawned tasks
        self.abort_spawned_tasks();
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L586-597)
```rust
        // Get the highest advertised version
        let highest_advertised_version = global_data_summary
            .advertised_data
            .highest_synced_ledger_info()
            .map(|ledger_info| ledger_info.ledger_info().version())
            .ok_or_else(|| {
                aptos_data_client::error::Error::UnexpectedErrorEncountered(
                    "The highest synced ledger info is missing from the global data summary!"
                        .into(),
                )
            })?;

```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L606-618)
```rust
        let current_stream_lag =
            highest_advertised_version.saturating_sub(highest_response_version);
        if let Some(mut subscription_stream_lag) = self.subscription_stream_lag.take() {
            // Check if the stream lag is beyond recovery
            if subscription_stream_lag
                .is_beyond_recovery(self.streaming_service_config, current_stream_lag)
            {
                return Err(
                    aptos_data_client::error::Error::SubscriptionStreamIsLagging(format!(
                        "The subscription stream is beyond recovery! Current lag: {:?}, last lag: {:?},",
                        current_stream_lag, subscription_stream_lag.version_lag
                    )),
                );
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L634-645)
```rust
    fn notify_new_data_request_error(
        &mut self,
        client_request: &DataClientRequest,
        error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // Notify the stream engine and clear the requests queue
        self.stream_engine
            .notify_new_data_request_error(client_request, error)?;
        self.clear_sent_data_requests_queue();

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L938-953)
```rust
    fn handle_subscription_error(
        &mut self,
        client_request: &DataClientRequest,
        request_error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // We should only receive an error notification if we have an active stream
        if self.active_subscription_stream.is_none() {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Received a subscription notification error but no active subscription stream exists! Error: {:?}, request: {:?}",
                request_error, client_request
            )));
        }

        // Reset the active subscription stream and update the metrics
        self.active_subscription_stream = None;
        update_terminated_subscription_metrics(request_error.get_label());
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1271-1278)
```rust
            if self.data_streaming_config.enable_subscription_streaming {
                // Start a new subscription stream and send the first set of requests
                self.start_active_subscription_stream(unique_id_generator)?;
                self.create_subscription_stream_requests(
                    max_number_of_requests,
                    max_in_flight_requests,
                    num_in_flight_requests,
                )?
```
