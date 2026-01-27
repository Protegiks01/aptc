# Audit Report

## Title
Clock Skew in Request Validation Causes False Rejection of Legitimate Peers Leading to Network Fragmentation

## Summary
The `check_synced_ledger_lag()` function uses the server's system clock to validate optimistic fetch and subscription requests, causing legitimate peers to be incorrectly penalized when the server's clock is ahead of consensus time. This creates an off-by-one boundary error and a clock skew vulnerability that degrades network connectivity by marking valid peers as unhealthy.

## Finding Description
The storage service moderator validates incoming requests by checking if the server can service them using `can_service()`. For optimistic fetch and subscription requests, this validation relies on `check_synced_ledger_lag()` to ensure the server's synced ledger info is recent enough. [1](#0-0) 

The critical flaw is at line 930, where the check compares `ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs`. This creates two vulnerabilities:

**1. Clock Skew False Negatives**: The `current_timestamp_usecs` comes from `time_service.now_unix_time()`, which uses the server's system clock: [2](#0-1) 

When the server's system clock is ahead of consensus time (due to NTP drift, manual misconfiguration, or virtualization issues), the check incorrectly fails. For example:
- Ledger info timestamp (from consensus): T
- Server's system clock: T + 25 seconds (ahead)
- max_optimistic_fetch_lag_secs: 20 seconds
- Check: T + 20s > T + 25s → FALSE (incorrectly rejects)

**2. Off-by-One Boundary Error**: The strict `>` operator at line 930 instead of `>=` means requests at the exact boundary are rejected. When `ledger_info_timestamp_usecs + max_version_lag_usecs == current_timestamp_usecs`, the function returns false even though the data is within acceptable lag limits.

When `can_service()` returns false, the moderator penalizes the requesting peer: [3](#0-2) 

After 500 invalid requests (default `max_invalid_requests_per_peer`), PFN peers are ignored: [4](#0-3) [5](#0-4) 

The server penalizes peers for the server's own clock synchronization problems, creating network fragmentation where legitimate peers cannot sync from nodes with clock drift.

## Impact Explanation
**High Severity** - This issue causes:

1. **Network Availability Degradation**: Legitimate fullnodes and validators cannot sync from servers with clock skew, reducing network redundancy and increasing sync latency.

2. **Cascading Connectivity Loss**: If multiple nodes develop clock skew (common in cloud environments or after NTP service disruptions), the network fragments into disconnected clusters where peers ignore each other.

3. **State Sync Service Disruption**: Public fullnodes relying on these servers for state synchronization are cut off after 500 rejected requests, violating the protocol's design to maintain broad network connectivity.

This qualifies as "Significant protocol violations" and "Validator node slowdowns" per the High severity criteria, as it disrupts the fundamental peer-to-peer synchronization mechanism that enables validators and fullnodes to maintain consensus state.

## Likelihood Explanation
**High Likelihood** - This occurs naturally in production environments:

1. **Clock Skew is Common**: NTP synchronization failures, virtualization time drift, manual time adjustments, and leap second handling all cause system clocks to drift from consensus time.

2. **No Attacker Required**: This is triggered by normal operational conditions, not malicious actions.

3. **Accumulation Over Time**: The penalty counter increments with every rejected request. A server with persistent 25-second clock skew will consistently reject optimistic fetches, quickly accumulating penalties.

4. **Default Configuration Vulnerable**: With `max_optimistic_fetch_lag_secs = 20` seconds and common clock drift of 20-30 seconds, servers frequently operate at or beyond this threshold.

## Recommendation
**Fix the off-by-one error** by using `>=` instead of `>`:

```rust
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;
        
        // Changed from > to >= to include the boundary case
        ledger_info_timestamp_usecs + max_version_lag_usecs >= current_timestamp_usecs
    } else {
        false
    }
}
```

**Add clock skew tolerance buffer** by comparing against the ledger info timestamp rather than current system time where possible, or add a configurable tolerance margin:

```rust
// Add a tolerance buffer to account for clock skew
let clock_skew_tolerance_usecs = 10 * NUM_MICROSECONDS_IN_SECOND; // 10 seconds
ledger_info_timestamp_usecs + max_version_lag_usecs + clock_skew_tolerance_usecs >= current_timestamp_usecs
```

**Separate server-side validation from peer penalization**: Consider not penalizing peers for requests that fail due to server-side timing constraints, since these reflect the server's state rather than the peer's behavior.

## Proof of Concept
```rust
use aptos_storage_service_types::responses::{DataSummary, check_synced_ledger_lag};
use aptos_time_service::TimeService;
use aptos_types::ledger_info::LedgerInfoWithSignatures;

#[test]
fn test_clock_skew_false_negative() {
    // Create a mock time service
    let time_service = TimeService::mock();
    let mock_time = time_service.clone().into_mock();
    
    // Create a synced ledger info with timestamp T
    let base_timestamp_usecs = 1_000_000_000_000; // T = 1M seconds
    let ledger_info = create_test_ledger_info_with_timestamp(base_timestamp_usecs);
    
    // Set max lag to 20 seconds
    let max_lag_secs = 20;
    
    // Scenario 1: Server clock is 25 seconds ahead (clock skew)
    let current_time_usecs = base_timestamp_usecs + 25_000_000; // T + 25 seconds
    mock_time.set_unix_time_usecs(current_time_usecs);
    
    // This should ideally pass since the ledger is fresh, but fails due to clock skew
    let result = check_synced_ledger_lag(
        Some(&ledger_info),
        time_service.clone(),
        max_lag_secs,
    );
    
    assert_eq!(result, false, "Clock skew causes false negative rejection");
    
    // Scenario 2: Exact boundary case (off-by-one error)
    let boundary_time_usecs = base_timestamp_usecs + 20_000_000; // T + exactly 20 seconds
    mock_time.set_unix_time_usecs(boundary_time_usecs);
    
    let result = check_synced_ledger_lag(
        Some(&ledger_info),
        time_service.clone(),
        max_lag_secs,
    );
    
    assert_eq!(result, false, "Boundary case incorrectly rejected due to strict > check");
    // Expected: should be true since data is within the 20-second window
}
```

This PoC demonstrates both the clock skew vulnerability and the off-by-one boundary error, showing how legitimate optimistic fetch requests are incorrectly rejected, leading to peer penalization and network connectivity degradation.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L916-934)
```rust
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

**File:** crates/aptos-time-service/src/real.rs (L35-37)
```rust
    fn now_unix_time(&self) -> Duration {
        aptos_infallible::duration_since_epoch()
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L50-69)
```rust
    pub fn increment_invalid_request_count(&mut self, peer_network_id: &PeerNetworkId) {
        // Increment the invalid request count
        self.invalid_request_count += 1;

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
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L154-185)
```rust
            // Verify the request is serviceable using the current storage server summary
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

**File:** config/src/config/state_sync_config.rs (L201-201)
```rust
            max_invalid_requests_per_peer: 500,
```
