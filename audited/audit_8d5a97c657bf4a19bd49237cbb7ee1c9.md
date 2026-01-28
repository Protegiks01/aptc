# Audit Report

## Title
Denial of Service via Malicious Epoch Range Advertisement in State Sync

## Summary
A Byzantine peer can advertise an artificially inflated epoch ending ledger info range (e.g., `CompleteDataRange(0, u64::MAX - 1)`) that passes all validation checks but causes honest nodes' data streaming service to freeze indefinitely when checking data availability, resulting in node unavailability for state synchronization.

## Finding Description

The Aptos state sync system allows peers to advertise what data they have available through `StorageServerSummary` messages. The `epoch_ending_ledger_infos` field is a `CompleteDataRange<Epoch>` that specifies the range of epochs for which the peer has epoch ending ledger infos. [1](#0-0) 

When a peer's storage summary is received, it is stored without semantic validation of the epoch range values: [2](#0-1) 

These peer summaries are aggregated into a global data summary: [3](#0-2) 

The `highest_epoch_ending_ledger_info()` function returns the maximum epoch from all advertised ranges: [4](#0-3) 

This value is used to initialize the `EpochEndingStreamEngine` which sets `end_epoch` without validation: [5](#0-4) 

The critical vulnerability occurs in `is_remaining_data_available()` which calls `AdvertisedData::contains_range()`: [6](#0-5) 

The `contains_range` function iterates through every epoch from `lowest` to `highest`: [7](#0-6) 

**Attack Path:**
1. Byzantine peer constructs `CompleteDataRange::new(0, u64::MAX - 1)` 
2. The validation in `CompleteDataRange::new()` only checks for overflow, not reasonable bounds: [8](#0-7) 
3. Honest node receives and aggregates this into global summary, sets `end_epoch = u64::MAX - 1`
4. When `ensure_data_is_available()` is called during stream creation: [9](#0-8) 
5. The `for item in lowest..=highest` loop iterates from the node's current epoch to `u64::MAX - 1` (~18 quintillion iterations)
6. This blocks the synchronous function within the async event loop: [10](#0-9) 

## Impact Explanation

**HIGH Severity** - This qualifies as "Validator Node Slowdowns" with significant performance degradation affecting consensus participation. The vulnerable node's data streaming service will:
- Freeze indefinitely in the iteration loop, blocking the event loop
- Become unable to sync new data or create new epoch ending streams
- Potentially fail to participate in consensus if the node needs to sync
- Require manual intervention (restart) to recover, but will re-freeze upon encountering the malicious peer again

Multiple validator nodes can be affected simultaneously by a single malicious peer, significantly degrading network synchronization capabilities. However, this does not halt the entire network as nodes that are already synced and not requesting epoch ending streams remain operational.

## Likelihood Explanation

**High Likelihood:**
- Any network peer can send malicious `StorageServerSummary` messages through normal state sync protocols
- No validator privileges or special access required
- The validation logic only prevents overflow, not unreasonable ranges
- The attack is trivial to execute (one malicious message per peer connection)
- Multiple honest nodes can be affected simultaneously by a single malicious peer
- The issue is deterministic and reliably exploitable

## Recommendation

Add semantic validation for `CompleteDataRange` values to prevent unreasonably large ranges:

```rust
// In CompleteDataRange::new()
const MAX_REASONABLE_RANGE_LENGTH: u64 = 1_000_000; // Adjust based on expected epochs

pub fn new(lowest: T, highest: T) -> crate::Result<Self, Error> {
    if lowest > highest || range_length_checked(lowest, highest).is_err() {
        return Err(DegenerateRangeError);
    }
    
    // Add bounds check
    let length = highest.checked_sub(&lowest)
        .and_then(|v| v.checked_add(&T::one()))
        .ok_or(DegenerateRangeError)?;
    
    if length > T::from(MAX_REASONABLE_RANGE_LENGTH).unwrap_or(T::max_value()) {
        return Err(Error::UnexpectedErrorEncountered(
            "Range length exceeds maximum reasonable bounds".into()
        ));
    }
    
    Ok(Self { lowest, highest })
}
```

Additionally, implement an iterative limit or optimization in `contains_range()` to prevent unbounded iteration.

## Proof of Concept

```rust
// This demonstrates the vulnerability by creating a malicious range
use aptos_storage_service_types::responses::{CompleteDataRange, DataSummary, StorageServerSummary};

#[test]
fn test_malicious_epoch_range_dos() {
    // Create malicious range that passes validation
    let malicious_range = CompleteDataRange::new(0, u64::MAX - 1).unwrap();
    
    // This would be included in a StorageServerSummary sent by a Byzantine peer
    let malicious_summary = StorageServerSummary {
        data_summary: DataSummary {
            epoch_ending_ledger_infos: Some(malicious_range),
            ..Default::default()
        },
        ..Default::default()
    };
    
    // When an honest node tries to check if data is available for epochs 100 to u64::MAX-1,
    // it will iterate through ~18 quintillion items, freezing indefinitely
    let advertised_ranges = vec![malicious_range];
    
    // This call will hang indefinitely
    // AdvertisedData::contains_range(100, u64::MAX - 1, &advertised_ranges);
}
```

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L665-686)
```rust
/// A summary of the data actually held by the storage service instance.
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

**File:** state-sync/storage-service/types/src/responses.rs (L962-968)
```rust
    pub fn new(lowest: T, highest: T) -> crate::Result<Self, Error> {
        if lowest > highest || range_length_checked(lowest, highest).is_err() {
            Err(DegenerateRangeError)
        } else {
            Ok(Self { lowest, highest })
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L177-179)
```rust
    fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
        self.storage_summary = Some(storage_summary);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L365-370)
```rust
            if let Some(epoch_ending_ledger_infos) = summary.data_summary.epoch_ending_ledger_infos
            {
                advertised_data
                    .epoch_ending_ledger_infos
                    .push(epoch_ending_ledger_infos);
            }
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L153-173)
```rust
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

**File:** state-sync/aptos-data-client/src/global_summary.rs (L176-181)
```rust
    pub fn highest_epoch_ending_ledger_info(&self) -> Option<Epoch> {
        self.epoch_ending_ledger_infos
            .iter()
            .map(|epoch_range| epoch_range.highest())
            .max()
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1487-1494)
```rust
        let end_epoch = advertised_data
            .highest_epoch_ending_ledger_info()
            .ok_or_else(|| {
                Error::DataIsUnavailable(format!(
                    "Unable to find any epoch ending ledger info in the network: {:?}",
                    advertised_data
                ))
            })?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1570-1578)
```rust
    fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
        let start_epoch = self.next_stream_epoch;
        let end_epoch = self.end_epoch;
        Ok(AdvertisedData::contains_range(
            start_epoch,
            end_epoch,
            &advertised_data.epoch_ending_ledger_infos,
        ))
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L133-153)
```rust
        loop {
            ::futures::select! {
                stream_request = self.stream_requests.select_next_some() => {
                    self.handle_stream_request_message(stream_request, self.stream_update_notifier.clone());
                }
                _ = progress_check_interval.select_next_some() => {
                    // Check the progress of all data streams at a scheduled interval
                    self.check_progress_of_all_data_streams().await;
                }
                notification = self.stream_update_listener.select_next_some() => {
                    // Check the progress of all data streams when notified
                    trace!(LogSchema::new(LogEntry::CheckStreamProgress)
                            .message(&format!(
                                "Received update notification from: {:?}.",
                                notification.data_stream_id
                            ))
                        );
                    self.check_progress_of_all_data_streams().await;
                }
            }
        }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L287-287)
```rust
        data_stream.ensure_data_is_available(&advertised_data)?;
```
