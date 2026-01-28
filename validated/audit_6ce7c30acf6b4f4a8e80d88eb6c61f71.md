# Audit Report

## Title
Missing Epoch Boundary Validation in Response Processing Allows State Desynchronization via Malicious Peer Responses

## Summary
The epoch ending ledger info response handling in the data streaming service fails to validate that received epochs match the requested range. A malicious network peer can send extra epochs beyond the requested boundary, causing desynchronization between the stream engine's epoch tracking and the bootstrapper's verified epoch state, leading to subsequent verification failures that prevent nodes from completing synchronization.

## Finding Description

The vulnerability exists in the response validation logic where the stream engine and bootstrapper handle epoch ending ledger info responses differently, creating a state desynchronization attack vector.

**Stream Engine Behavior:**
The stream engine creates requests with specific epoch ranges defined by `start_epoch` and `end_epoch` parameters. When processing responses, it extracts the last epoch from the response and silently clamps it using `bound_by_range()` [1](#0-0) , which bounds the value to the requested range for tracking purposes rather than rejecting invalid responses [2](#0-1) . The stream engine then updates `next_stream_epoch` based on this bounded value [3](#0-2) .

However, the stream engine passes the **entire** `client_response_payload` (containing all epoch ending ledger infos) to create the data notification [4](#0-3) , which is then forwarded to the bootstrapper without any truncation.

**Bootstrapper Behavior:**
The bootstrapper receives the notification and processes **ALL** epoch ending ledger infos present in the response [5](#0-4) . For each ledger info, it performs cryptographic verification using `latest_epoch_state.verify()` [6](#0-5)  and then updates `latest_epoch_state` to the next epoch's state [7](#0-6) .

**Insufficient Validation:**
The only validation performed on responses is a type check that confirms the payload type matches the request type, with an explicit comment stating "No other sanity checks are done" [8](#0-7) . The validation function that checks for missing data only verifies if fewer epochs were received than requested, but does not reject responses containing more epochs than requested [9](#0-8) .

**Attack Scenario:**
1. Stream engine requests epochs 6-10, setting `next_request_epoch = 11`
2. Malicious peer (running modified software that bypasses its own validation) sends epochs 6-13 (4 extra epochs)
3. Stream engine bounds last epoch: `bound_by_range(13, 6, 10) = 10`, updates `next_stream_epoch = 11`
4. Bootstrapper receives all epochs 6-13 in the notification and processes them sequentially
5. Bootstrapper's `latest_epoch_state` advances from epoch 5 to epoch 13
6. Stream engine creates next request for epochs 11-15 (based on its bounded tracking)
7. When epoch 11 arrives, bootstrapper attempts verification using epoch 13's validator set
8. `EpochState.verify()` fails because it requires exact epoch match: `11 != 13` [10](#0-9) 
9. Bootstrapper sends `PayloadProofFailed` feedback [11](#0-10) , causing stream reset
10. Attack is repeatable, preventing successful synchronization

## Impact Explanation

**Severity: High**

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's criteria:

**Validator Node Slowdowns:** Affected nodes cannot complete epoch transitions and become stuck in perpetual failed verification loops. Validator nodes unable to sync cannot participate in consensus, directly degrading network performance and availability.

**Widespread Attack Surface:** Any malicious network peer can execute this attack against syncing nodes. Attackers can target multiple nodes simultaneously using different peer identities to evade reputation-based defenses.

**Not Critical Severity:** While severe, this vulnerability:
- Does not enable fund theft or unauthorized token minting
- Does not cause consensus safety violations (no double-spending or chain splits)
- Does not result in permanent state corruption
- Affects availability rather than safety properties

The attack prevents nodes from syncing but does not compromise the integrity of the blockchain state or enable theft of assets, aligning with High rather than Critical severity.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is readily exploitable because:

**Low Barrier to Entry:**
- Any actor can run a network peer node without special privileges or stake requirements
- Attacker runs modified node software that bypasses server-side validation checks in their own implementation
- No cryptographic breaks or signature forgeries required

**Readily Available Attack Materials:**
- Historical epoch ending ledger infos are public blockchain data available to all network participants
- These ledger infos are already cryptographically signed by validators, requiring no modification
- Attack leverages legitimate, validly-signed blockchain data in an out-of-order manner

**Repeatable Attack Vector:**
- Attack succeeds multiple times (3-4 iterations) before peer reputation system reduces attacker's score below the ignore threshold
- Peer reputation scoring exists [12](#0-11)  but malicious responses only multiply score by 0.8 per incident
- Attackers can use multiple peer identities to evade reputation system and extend attack duration
- Target nodes attempting to sync are continuously vulnerable during their synchronization window

**Realistic Attack Scenario:**
- Occurs during normal network operations when nodes perform epoch synchronization
- No precise timing requirements or coordination needed
- Can be executed persistently to prevent nodes from completing bootstrapping

## Recommendation

Implement strict response boundary validation to ensure epoch ending ledger infos match the requested range:

1. **Add Response Count Validation:** After receiving epoch ending ledger infos, verify that the number of epochs received matches exactly what was requested, rejecting responses with extra epochs.

2. **Truncate Excess Data:** Alternatively, truncate the response payload to match the requested range before passing it to the bootstrapper, ensuring stream engine and bootstrapper remain synchronized.

3. **Enhanced Peer Scoring:** Apply more severe reputation penalties for responses that violate expected boundaries, accelerating malicious peer detection and banning.

**Example Fix Location:** In `transform_client_response_into_notification` for `EpochEndingStreamEngine`, add validation before creating the notification:

```rust
// After extracting ledger_infos from client_response_payload
// Verify the response doesn't contain more epochs than requested
let expected_count = request.end_epoch - request.start_epoch + 1;
if ledger_infos.len() > expected_count as usize {
    // Truncate to requested range or reject the response
    ledger_infos.truncate(expected_count as usize);
}
```

## Proof of Concept

While a complete PoC requires setting up a malicious network peer, the vulnerability can be demonstrated by tracing the code paths:

1. **Setup:** Node requests epoch ending ledger infos with `start_epoch=6, end_epoch=10`
2. **Malicious Response:** Peer sends ledger infos for epochs 6-13 (7 ledger infos instead of 5)
3. **Stream Engine Processing:** `bound_by_range(13, 6, 10)` returns 10, `next_stream_epoch` becomes 11
4. **Bootstrapper Processing:** Iterates through all 7 ledger infos, advancing `latest_epoch_state` to 13
5. **Desynchronization:** Stream engine expects epoch 11 next, but bootstrapper expects epoch 14
6. **Verification Failure:** When epoch 11 arrives, `EpochState.verify()` fails with epoch mismatch error
7. **Stream Reset:** Bootstrapper sends `PayloadProofFailed` feedback, triggering stream reset and preventing progress

The core issue is that `bound_by_range()` silently clamps the tracking value without validating or truncating the actual data payload forwarded to the bootstrapper, creating an exploitable divergence in state tracking.

## Notes

This vulnerability represents a protocol-level validation gap rather than a network-level DoS attack. The issue stems from insufficient coordination between the stream engine's epoch tracking (which uses bounded values) and the bootstrapper's epoch processing (which processes all received data). While peer reputation scoring provides partial mitigation, it does not fully prevent the attack, especially when attackers use multiple peer identities or target nodes during their initial synchronization phase.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1622-1623)
```rust
                let last_received_epoch =
                    bound_by_range(last_received_epoch, request.start_epoch, request.end_epoch);
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1626-1628)
```rust
                self.next_stream_epoch = last_received_epoch.checked_add(1).ok_or_else(|| {
                    Error::IntegerOverflow("Next stream epoch has overflown!".into())
                })?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1636-1642)
```rust
                let data_notification = create_data_notification(
                    notification_id_generator,
                    client_response_payload,
                    None,
                    self.clone().into(),
                )?;
                Ok(Some(data_notification))
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2002-2007)
```rust
/// Bounds the given number by the specified min and max values, inclusive.
/// If the number is less than the min, the min is returned. If the number is
/// greater than the max, the max is returned. Otherwise, the number is returned.
pub(crate) fn bound_by_range(number: u64, min: u64, max: u64) -> u64 {
    number.clamp(min, max)
}
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L104-108)
```rust
        self.latest_epoch_state
            .verify(epoch_ending_ledger_info)
            .map_err(|error| {
                Error::VerificationError(format!("Ledger info failed verification: {:?}", error))
            })?;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L111-114)
```rust
        if let Some(next_epoch_state) = epoch_ending_ledger_info.ledger_info().next_epoch_state() {
            self.highest_fetched_epoch_ending_version =
                epoch_ending_ledger_info.ledger_info().version();
            self.latest_epoch_state = next_epoch_state.clone();
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1094-1106)
```rust
        for epoch_ending_ledger_info in epoch_ending_ledger_infos {
            if let Err(error) = self.verified_epoch_states.update_verified_epoch_states(
                &epoch_ending_ledger_info,
                &self.driver_configuration.waypoint,
            ) {
                self.reset_active_stream(Some(NotificationAndFeedback::new(
                    notification_id,
                    NotificationFeedback::PayloadProofFailed,
                )))
                .await?;
                return Err(error);
            }
        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1082-1095)
```rust
            if num_received_ledger_infos < num_requested_ledger_infos {
                let start_epoch = request
                    .start_epoch
                    .checked_add(num_received_ledger_infos)
                    .ok_or_else(|| Error::IntegerOverflow("Start epoch has overflown!".into()))?;
                Ok(Some(DataClientRequest::EpochEndingLedgerInfos(
                    EpochEndingLedgerInfosRequest {
                        start_epoch,
                        end_epoch: request.end_epoch,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1290-1292)
```rust
/// Returns true iff the data client response payload type matches the
/// expected type of the original request. No other sanity checks are done.
fn sanity_check_client_response_type(
```

**File:** types/src/epoch_state.rs (L42-47)
```rust
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    global_summary::{AdvertisedData, GlobalDataSummary, OptimalChunkSizes},
    interface::ResponseError,
    logging::{LogEntry, LogEvent, LogSchema},
    metrics,
};
use aptos_config::{
    config::AptosDataClientConfig,
    network_id::{NetworkId, PeerNetworkId},
};
use aptos_logger::prelude::*;
use aptos_storage_service_types::{
    requests::StorageServiceRequest, responses::StorageServerSummary,
};
use aptos_time_service::TimeService;
use dashmap::DashMap;
use std::{
    cmp::min,
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Duration,
};

// Useful constants
const LOGS_FREQUENCY_SECS: u64 = 120; // 2 minutes
const METRICS_FREQUENCY_SECS: u64 = 15; // 15 seconds
const NUM_PEER_BUCKETS_FOR_METRICS: u8 = 4; // To avoid metric explosion, we bucket peers into groups

/// Scores for peer rankings based on preferences and behavior.
const MAX_SCORE: f64 = 100.0;
const MIN_SCORE: f64 = 0.0;
const STARTING_SCORE: f64 = 50.0;
/// Add this score on a successful response.
const SUCCESSFUL_RESPONSE_DELTA: f64 = 1.0;
/// Not necessarily a malicious response, but not super useful.
const NOT_USEFUL_MULTIPLIER: f64 = 0.95;
/// Likely to be a malicious response.
const MALICIOUS_MULTIPLIER: f64 = 0.8;
/// Ignore a peer when their score dips below this threshold.
const IGNORE_PEER_THRESHOLD: f64 = 25.0;

pub enum ErrorType {
    /// A response or error that's not actively malicious but also doesn't help
    /// us make progress, e.g., timeouts, remote errors, invalid data, etc...
    NotUseful,
    /// A response or error that appears to be actively hindering progress or
    /// attempting to deceive us, e.g., invalid proof.
```
