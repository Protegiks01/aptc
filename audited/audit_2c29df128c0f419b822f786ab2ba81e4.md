# Audit Report

## Title
Bootstrap Indefinite Hang When No Peers Advertise Historical State Data

## Summary
When `lowest_state_version()` returns `None` due to an empty `states` vector in `AdvertisedData`, nodes performing fast sync bootstrap cannot create state value streams and become stuck in an infinite retry loop, preventing successful node initialization.

## Finding Description
The vulnerability occurs in the state synchronization bootstrap flow when no network peers advertise historical state data. This breaks the **availability invariant** by preventing nodes from completing bootstrap.

**Attack Flow:**

1. **Empty State Advertisement**: When all peers have aggressively pruned historical state or no archival nodes exist, the `AdvertisedData.states` vector becomes empty [1](#0-0) 

2. **None Return**: The `lowest_state_version()` function returns `None` when called on an empty states vector [2](#0-1) 

3. **Stream Creation Failure**: During fast sync bootstrap, the node calls `get_all_state_values()` to fetch state snapshots [3](#0-2) 

4. **Availability Check**: The stream creation process calls `ensure_data_is_available()` which invokes `is_remaining_data_available()` on the `StateStreamEngine` [4](#0-3) 

5. **Contains Range Failure**: The `StateStreamEngine` checks if states are available using `AdvertisedData::contains_range()` with the empty states vector [5](#0-4) 

6. **False Return**: `contains_range()` returns `false` for empty advertised ranges because no range can contain the requested version [6](#0-5) 

7. **DataIsUnavailable Error**: Stream creation fails with `Error::DataIsUnavailable` [7](#0-6) 

8. **Error Propagation**: The error propagates through `fetch_missing_state_values()` → `fetch_missing_state_snapshot_data()` → `initialize_active_data_stream()` → `drive_progress()`

9. **Infinite Retry Loop**: The driver logs the error but continues retrying indefinitely with no timeout or maximum retry count [8](#0-7) 

**Scenario Trigger Conditions:**
- Initial node bootstrap from genesis when all reachable peers have pruned historical state
- Network partitions where bootstrapping nodes can only connect to non-archival peers
- After network-wide aggressive state pruning with no archival nodes remaining

## Impact Explanation
This qualifies as **Medium severity** under the Aptos bug bounty program criteria:

**State Inconsistencies Requiring Intervention**: The node cannot complete bootstrap and remains non-operational indefinitely. This requires manual intervention (connecting to archival nodes or changing sync mode).

**Availability Impact**:
- **Validators**: Cannot participate in consensus, reducing network decentralization and fault tolerance
- **Full Nodes**: Cannot serve RPC queries, degrading application availability
- **Network Health**: New nodes cannot join the network, preventing network growth

The issue does not directly cause fund loss or consensus safety violations, but severely impacts network availability and operational reliability, meeting the Medium severity threshold.

## Likelihood Explanation
**Likelihood: Medium-High**

This issue is increasingly likely to occur in production due to:

1. **Aggressive Pruning Defaults**: Many node operators enable aggressive state pruning to reduce storage costs
2. **Limited Archival Nodes**: The network may have few archival nodes that maintain full historical state
3. **Network Partitions**: Bootstrapping nodes may be isolated from archival nodes during network issues
4. **Growing Chain History**: As chain history grows, more operators will prune aggressively

The vulnerability requires specific network conditions (no state advertisers reachable) but these conditions are realistic and becoming more common as the network matures.

## Recommendation
Implement a fallback mechanism for fast sync bootstrap when state data is unavailable:

1. **Add Bootstrap Timeout**: Implement a configurable timeout for bootstrap attempts in fast sync mode
2. **Fallback to Transaction Sync**: After timeout, automatically switch to `ExecuteTransactionsFromGenesis` or `ApplyTransactionOutputsFromGenesis` mode
3. **Clear Error Messages**: Provide actionable error messages directing operators to configure archival node connections
4. **Retry with Exponential Backoff**: Add exponential backoff with a maximum retry count before fallback

**Example Fix** (add to `bootstrapper.rs`):

```rust
// Add timeout tracking to Bootstrapper struct
bootstrap_start_time: Option<Instant>,
bootstrap_retry_count: u64,

// In drive_progress(), before calling initialize_active_data_stream():
if let Some(start_time) = self.bootstrap_start_time {
    let elapsed = start_time.elapsed();
    if elapsed > self.driver_configuration.config.max_bootstrap_duration 
        || self.bootstrap_retry_count > self.driver_configuration.config.max_bootstrap_retries {
        warn!("Bootstrap timeout or max retries exceeded. Falling back to transaction sync mode.");
        return self.fallback_to_transaction_sync().await;
    }
    self.bootstrap_retry_count += 1;
}
```

## Proof of Concept

**Rust Reproduction Steps:**

1. **Setup Environment**: Start a local testnet with 3 validator nodes, all configured with aggressive state pruning
2. **Prune Historical State**: Let the network run for N epochs, then prune all historical state before epoch N-1 on all nodes
3. **Bootstrap New Node**: Attempt to bootstrap a new fullnode in fast sync mode from genesis
4. **Observe Failure**: Monitor logs for repeated `BOOTSTRAPPER_ERRORS` with error label "data_is_unavailable"
5. **Verify Hang**: Confirm the node never completes bootstrap and remains stuck indefinitely

**Expected Log Output:**
```
[state_sync::driver] Error found when checking the bootstrapper progress! Error: DataIsUnavailable("Unable to satisfy stream engine: StateStreamEngine { ... }, with advertised data: AdvertisedData { states: [] }")
```

**Metrics Observation:**
The `aptos_state_sync_bootstrapper_errors{error_label="data_is_unavailable"}` counter will continuously increment while `aptos_state_sync_version{type="synced"}` remains at 0.

## Notes

This vulnerability specifically affects **fast sync mode** (snapshot synchronization). The `ExecuteOrApplyFromGenesis` modes have an `OutputFallbackHandler` that provides some resilience, but fast sync has no such fallback mechanism when state data is unavailable.

The `lowest_state_version()` returning `None` is itself not the vulnerability—it's a correct signal that no state is advertised. The vulnerability is the **lack of fallback handling** in the bootstrap logic when this condition occurs, leading to an infinite retry loop rather than graceful degradation or mode switching.

### Citations

**File:** state-sync/aptos-data-client/src/global_summary.rs (L74-74)
```rust
    pub states: Vec<CompleteDataRange<Version>>,
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L151-173)
```rust
    /// Returns true iff all data items (`lowest` to `highest`, inclusive) can
    /// be found in the given `advertised_ranges`.
    pub fn contains_range(
        lowest: u64,
        highest: u64,
        advertised_ranges: &[CompleteDataRange<u64>],
    ) -> bool {
        for item in lowest..=highest {
            let mut item_exists = false;

            for advertised_range in advertised_ranges {
                if advertised_range.contains(item) {
                    item_exists = true;
                    break;
                }
            }

            if !item_exists {
                return false;
            }
        }
        true
    }
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L200-203)
```rust
    /// Returns the lowest advertised version containing all states
    pub fn lowest_state_version(&self) -> Option<Version> {
        get_lowest_version_from_range_set(&self.states)
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L720-725)
```rust
            self.streaming_client
                .get_all_state_values(
                    target_ledger_info_version,
                    Some(next_state_index_to_process),
                )
                .await?
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L866-877)
```rust
    pub fn ensure_data_is_available(&self, advertised_data: &AdvertisedData) -> Result<(), Error> {
        if !self
            .stream_engine
            .is_remaining_data_available(advertised_data)?
        {
            return Err(Error::DataIsUnavailable(format!(
                "Unable to satisfy stream engine: {:?}, with advertised data: {:?}",
                self.stream_engine, advertised_data
            )));
        }
        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L287-293)
```rust
    fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
        Ok(AdvertisedData::contains_range(
            self.request.version,
            self.request.version,
            &advertised_data.states,
        ))
    }
```

**File:** state-sync/data-streaming-service/src/error.rs (L10-11)
```rust
    #[error("The requested data is unavailable and cannot be found in the network! Error: {0}")]
    DataIsUnavailable(String),
```

**File:** state-sync/state-sync-driver/src/driver.rs (L711-719)
```rust
        } else if let Err(error) = self.bootstrapper.drive_progress(&global_data_summary).await {
            sample!(
                    SampleRate::Duration(Duration::from_secs(DRIVER_ERROR_LOG_FREQ_SECS)),
                    warn!(LogSchema::new(LogEntry::Driver)
                        .error(&error)
                        .message("Error found when checking the bootstrapper progress!"));
            );
            metrics::increment_counter(&metrics::BOOTSTRAPPER_ERRORS, error.get_label());
        };
```
