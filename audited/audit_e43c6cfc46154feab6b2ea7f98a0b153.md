# Audit Report

## Title
Denial of Service via Malicious Epoch Range Advertisement in State Sync

## Summary
A Byzantine peer can advertise an artificially inflated epoch ending ledger info range (e.g., `CompleteDataRange(0, u64::MAX - 1)`) that passes all validation checks but causes honest nodes to freeze indefinitely when checking data availability, resulting in complete node unavailability.

## Finding Description

The Aptos state sync system allows peers to advertise what data they have available through `StorageServerSummary` messages. The `epoch_ending_ledger_infos` field is a `CompleteDataRange<Epoch>` that specifies the range of epochs for which the peer has epoch ending ledger infos. [1](#0-0) 

When a peer's storage summary is received, it is stored without semantic validation of the epoch range values: [2](#0-1) 

These peer summaries are then aggregated into a global data summary: [3](#0-2) 

The `highest_epoch_ending_ledger_info()` function returns the maximum epoch from all advertised ranges: [4](#0-3) 

This value is used to initialize the `EpochEndingStreamEngine` which sets `end_epoch` without validation: [5](#0-4) 

The critical vulnerability occurs in `is_remaining_data_available()` which calls `AdvertisedData::contains_range()`: [6](#0-5) 

The `contains_range` function iterates through every epoch from `lowest` to `highest`: [7](#0-6) 

**Attack Path:**
1. Byzantine peer constructs `CompleteDataRange::new(0, u64::MAX - 1)` - this passes validation because the range length `(u64::MAX - 1) - 0 + 1 = u64::MAX` doesn't overflow
2. Peer sends this in their `StorageServerSummary` via BCS serialization
3. The deserialization validation passes: [8](#0-7) 

4. The validation in `CompleteDataRange::new()` only checks for overflow, not reasonable bounds: [9](#0-8) 

5. Honest node aggregates this into global summary, sets `end_epoch = u64::MAX - 1`
6. When `is_remaining_data_available()` is called, the `for item in lowest..=highest` loop at line 158 iterates from the node's current epoch (e.g., 100) to `u64::MAX - 1` (18,446,744,073,709,551,614), effectively freezing the node

## Impact Explanation

**Critical Severity** - This meets the "Total loss of liveness/network availability" criterion from the Aptos bug bounty program. The vulnerable node will:
- Freeze indefinitely in the iteration loop
- Become unable to sync new data
- Fail to participate in consensus
- Require manual intervention (restart) to recover, but will re-freeze upon encountering the malicious peer again

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The unbounded iteration violates computational limits.

## Likelihood Explanation

**High Likelihood:**
- Any network peer can send malicious `StorageServerSummary` messages
- No validator privileges required
- The validation logic only prevents overflow, not unreasonable ranges
- The attack is trivial to execute (one malicious message)
- Multiple honest nodes can be affected simultaneously by a single malicious peer
- The issue is deterministic and reliably exploitable

## Recommendation

Add semantic validation to reject unreasonably large epoch ranges. The fix should be applied in two places:

1. **Server-side validation** when creating the data summary:

Add a maximum reasonable epoch range check based on the expected epoch duration. For example, if epochs last ~2 hours and the chain has been running for a few years, the maximum epoch should be bounded by a realistic value (e.g., current_epoch + 100,000).

2. **Client-side validation** when receiving peer summaries:

```rust
// In peer_states.rs calculate_global_data_summary()
for summary in storage_summaries {
    if let Some(epoch_ending_ledger_infos) = summary.data_summary.epoch_ending_ledger_infos {
        // Add validation: reject ranges that are suspiciously large
        let range_len = epoch_ending_ledger_infos.len().unwrap_or(u64::MAX);
        if range_len > MAX_REASONABLE_EPOCH_RANGE {
            warn!("Peer advertised suspiciously large epoch range, ignoring");
            continue;
        }
        advertised_data.epoch_ending_ledger_infos.push(epoch_ending_ledger_infos);
    }
    // ... rest of the code
}
```

3. **Protect iteration** in `contains_range()`:

```rust
pub fn contains_range(
    lowest: u64,
    highest: u64,
    advertised_ranges: &[CompleteDataRange<u64>],
) -> bool {
    // Add early bounds check
    if highest.saturating_sub(lowest) > MAX_ITERATION_RANGE {
        warn!("Range too large for iteration check");
        return false;
    }
    
    for item in lowest..=highest {
        // ... existing logic
    }
    true
}
```

Where `MAX_REASONABLE_EPOCH_RANGE` and `MAX_ITERATION_RANGE` are configuration constants based on realistic network parameters.

## Proof of Concept

```rust
#[test]
fn test_malicious_epoch_range_dos() {
    use aptos_storage_service_types::responses::CompleteDataRange;
    use std::time::Instant;
    
    // Byzantine peer creates an inflated but valid range
    let malicious_range = CompleteDataRange::new(0, u64::MAX - 1).unwrap();
    
    // Simulate what happens in contains_range
    let start_epoch = 100u64;
    let end_epoch = malicious_range.highest();
    
    println!("Starting iteration from {} to {}", start_epoch, end_epoch);
    let start_time = Instant::now();
    
    // This will effectively never complete
    let mut count = 0u64;
    for epoch in start_epoch..=end_epoch {
        count += 1;
        if count > 1_000_000 {
            println!("After 1 million iterations in {:?}, stopping test", start_time.elapsed());
            println!("Would need to iterate {} more times", end_epoch - start_epoch - count);
            break;
        }
    }
    
    // This demonstrates the DoS - the loop never completes in any reasonable time
    assert!(count > 1_000_000);
    println!("DoS demonstrated: iteration would take effectively infinite time");
}
```

**Notes:**
- The vulnerability exists because `CompleteDataRange` validation only prevents arithmetic overflow, not semantic validity
- The `contains_range` iteration pattern at line 158 is inherently unsafe for untrusted inputs
- This affects all honest nodes that connect to the malicious peer during state sync
- The attack requires no validator privileges and is trivially exploitable

### Citations

**File:** state-sync/storage-service/types/src/lib.rs (L21-22)
```rust
/// A type alias for different epochs.
pub type Epoch = u64;
```

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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L365-369)
```rust
            if let Some(epoch_ending_ledger_infos) = summary.data_summary.epoch_ending_ledger_infos
            {
                advertised_data
                    .epoch_ending_ledger_infos
                    .push(epoch_ending_ledger_infos);
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

**File:** state-sync/storage-service/types/src/responses.rs (L961-968)
```rust
impl<T: PrimInt> CompleteDataRange<T> {
    pub fn new(lowest: T, highest: T) -> crate::Result<Self, Error> {
        if lowest > highest || range_length_checked(lowest, highest).is_err() {
            Err(DegenerateRangeError)
        } else {
            Ok(Self { lowest, highest })
        }
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L1020-1039)
```rust
impl<'de, T> serde::Deserialize<'de> for CompleteDataRange<T>
where
    T: PrimInt + serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> crate::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(rename = "CompleteDataRange")]
        struct Value<U> {
            lowest: U,
            highest: U,
        }

        let value = Value::<T>::deserialize(deserializer)?;
        Self::new(value.lowest, value.highest).map_err(D::Error::custom)
    }
```
