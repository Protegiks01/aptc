# Audit Report

## Title
CPU Exhaustion via O(n*m) Nested Loop in `contains_range()` During State Sync Stream Creation

## Summary
The `AdvertisedData::contains_range()` function uses an inefficient O(n*m) nested loop algorithm that can be exploited by malicious network peers to cause CPU exhaustion on validator nodes. When peers advertise large data ranges and the node attempts to sync over large version ranges, the function iterates through billions of items, causing significant delays during stream creation that can impact consensus participation. [1](#0-0) 

## Finding Description
The vulnerability exists in the data availability checking logic used by the state synchronization system. The attack flow is:

1. **Malicious Peer Advertisement**: Attackers connect as network peers and advertise `StorageServerSummary` containing large `CompleteDataRange` values (e.g., transactions from 0 to u64::MAX-1). The `CompleteDataRange::new()` validation only checks that `lowest <= highest` and that the range doesn't overflow, so extremely large ranges are accepted. [2](#0-1) 

2. **Range Aggregation**: The victim node aggregates all peers' advertised ranges into a `GlobalDataSummary` via `calculate_global_data_summary()`, which simply pushes each peer's ranges into vectors without validation or deduplication. [3](#0-2) 

3. **Stream Creation**: When the node needs to sync (e.g., during bootstrap or catching up), it creates a data stream by calling `ensure_data_is_available()`, which validates that advertised data covers the requested range. [4](#0-3) 

4. **CPU Exhaustion**: For transaction or epoch ending streams, `is_remaining_data_available()` calls `contains_range()` with the full sync range (potentially billions of versions) and the aggregated advertised ranges from all peers. [5](#0-4) 

5. **O(n*m) Nested Loop**: The vulnerable function iterates through every item in the range (outer loop, n iterations) and for each item checks all advertised ranges (inner loop, m iterations). With n=1,000,000,000 versions and m=50 malicious peers, this results in 50 billion iterations.

**Concrete Example:**
- 50 malicious peers each advertise transactions range (0, u64::MAX-1)
- Victim node bootstrapping needs to sync transactions from version 0 to 1,000,000,000
- `contains_range(0, 1_000_000_000, advertised_ranges)` executes
- Outer loop: 1 billion iterations
- Inner loop per iteration: 50 checks
- Total: 50 billion iterations
- At ~10 nanoseconds per iteration (optimistic): 500 seconds = 8+ minutes of CPU blocking

This breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation
This qualifies as **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns."

**Impact on Validators:**
- Stream creation is synchronous and blocks the streaming service
- During the 8+ minute delay, the validator cannot create new sync streams
- If the validator falls behind during this time, it may miss proposing/voting in consensus rounds
- Multiple malicious peers can sustain this attack continuously

**Impact on Network:**
- If multiple validators are affected simultaneously, overall network throughput degrades
- In extreme cases with many affected validators, could approach liveness threshold

**Impact Scope:**
- All nodes (validators, fullnodes, VFNs) running state sync are vulnerable
- Most critical during node bootstrap or when catching up after downtime
- Attack requires no special privileges—any network peer can execute it

## Likelihood Explanation
**Likelihood: High**

**Attacker Requirements:**
- Connect to victim as a network peer (trivial on public networks)
- Send a `StorageServerSummary` with large advertised ranges (single message)
- No computational cost to attacker—just advertise false data
- No stake or validator status required

**Trigger Conditions:**
- Node performs bootstrapping from genesis (common)
- Node catches up after being offline (frequent)
- Node syncs large historical ranges (normal operation)

**Attack Sustainability:**
- Attacker can sustain indefinitely by reconnecting with different peer IDs
- Each stream creation re-checks against current advertised data
- Peer scoring system takes time to penalize and doesn't prevent initial attack

**Realistic Scenario:** A node bootstrapping on mainnet with 30+ malicious peers advertising maximum ranges would experience 5-10 minute delays per stream creation, severely impacting initial sync time and validator participation.

## Recommendation
Replace the O(n*m) nested loop with an O(m) range intersection algorithm:

```rust
pub fn contains_range(
    lowest: u64,
    highest: u64,
    advertised_ranges: &[CompleteDataRange<u64>],
) -> bool {
    if advertised_ranges.is_empty() {
        return false;
    }
    
    // Sort ranges by lowest bound for efficient checking
    let mut sorted_ranges: Vec<_> = advertised_ranges.iter().collect();
    sorted_ranges.sort_by_key(|r| r.lowest());
    
    let mut current_covered = lowest;
    
    for range in sorted_ranges {
        // If there's a gap before this range, we can't cover it
        if range.highest() < current_covered {
            continue; // This range is before our uncovered region
        }
        
        if range.lowest() > current_covered {
            return false; // Gap found - range not fully covered
        }
        
        // This range covers from current_covered onwards
        current_covered = range.highest().saturating_add(1);
        
        // If we've covered up to or past highest, we're done
        if current_covered > highest {
            return true;
        }
    }
    
    false // Didn't cover all the way to highest
}
```

**Additional Mitigations:**
1. **Limit advertised range sizes**: Reject ranges larger than a reasonable threshold (e.g., 1 billion versions)
2. **Deduplicate ranges**: Merge overlapping ranges from different peers before checking
3. **Cache results**: Cache the last `contains_range()` check result per stream type
4. **Early termination**: Add a maximum iteration limit with graceful degradation

## Proof of Concept

**Rust Integration Test:**

```rust
#[test]
fn test_contains_range_cpu_exhaustion() {
    use std::time::Instant;
    use aptos_data_client::global_summary::AdvertisedData;
    use aptos_storage_service_types::responses::CompleteDataRange;
    
    // Simulate 50 malicious peers each advertising max ranges
    let mut advertised_ranges = vec![];
    for _ in 0..50 {
        advertised_ranges.push(
            CompleteDataRange::new(0, u64::MAX - 1).unwrap()
        );
    }
    
    // Victim tries to check availability for 100 million versions
    // (reduced from 1 billion to keep test time reasonable)
    let start = Instant::now();
    let result = AdvertisedData::contains_range(
        0,
        100_000_000,
        &advertised_ranges,
    );
    let duration = start.elapsed();
    
    println!("contains_range() took: {:?}", duration);
    println!("Result: {}", result);
    
    // With O(n*m): 100M * 50 = 5B iterations
    // Expected to take multiple seconds
    assert!(duration.as_secs() > 1, 
        "Should take significant time due to O(n*m) complexity");
}
```

**Attack Simulation Steps:**
1. Set up malicious peer that advertises `StorageServerSummary` with transaction range (0, u64::MAX-1)
2. Connect 30-50 such malicious peers to victim validator
3. Trigger victim node to bootstrap or sync large transaction range
4. Observe stream creation delays in logs: `"Stream created for request"` message delayed by minutes
5. Monitor CPU usage spike on single thread during `ensure_data_is_available()` call
6. Verify validator misses consensus rounds during the delay

**Verification:** Add logging in `contains_range()` to count iterations, demonstrating billions of loop executions for realistic sync scenarios.

---

**Notes**

This vulnerability is particularly dangerous because:
1. It affects the critical path of node synchronization
2. Attack cost is negligible (just advertising false data)
3. No effective rate limiting exists in current implementation
4. The peer scoring system doesn't prevent the initial attack impact
5. Affects all node types including validators, potentially impacting consensus

The fix should prioritize replacing the naive nested loop with an efficient range intersection algorithm, as this is a fundamental algorithmic issue rather than just a parameter tuning problem.

### Citations

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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L339-394)
```rust
    pub fn calculate_global_data_summary(&self) -> GlobalDataSummary {
        // Gather all storage summaries, but exclude peers that are ignored
        let storage_summaries: Vec<StorageServerSummary> = self
            .peer_to_state
            .iter()
            .filter_map(|peer_state| {
                peer_state
                    .value()
                    .get_storage_summary_if_not_ignored()
                    .cloned()
            })
            .collect();

        // If we have no peers, return an empty global summary
        if storage_summaries.is_empty() {
            return GlobalDataSummary::empty();
        }

        // Calculate the global data summary using the advertised peer data
        let mut advertised_data = AdvertisedData::empty();
        let mut max_epoch_chunk_sizes = vec![];
        let mut max_state_chunk_sizes = vec![];
        let mut max_transaction_chunk_sizes = vec![];
        let mut max_transaction_output_chunk_sizes = vec![];
        for summary in storage_summaries {
            // Collect aggregate data advertisements
            if let Some(epoch_ending_ledger_infos) = summary.data_summary.epoch_ending_ledger_infos
            {
                advertised_data
                    .epoch_ending_ledger_infos
                    .push(epoch_ending_ledger_infos);
            }
            if let Some(states) = summary.data_summary.states {
                advertised_data.states.push(states);
            }
            if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
            }
            if let Some(transactions) = summary.data_summary.transactions {
                advertised_data.transactions.push(transactions);
            }
            if let Some(transaction_outputs) = summary.data_summary.transaction_outputs {
                advertised_data
                    .transaction_outputs
                    .push(transaction_outputs);
            }

            // Collect preferred max chunk sizes
            max_epoch_chunk_sizes.push(summary.protocol_metadata.max_epoch_chunk_size);
            max_state_chunk_sizes.push(summary.protocol_metadata.max_state_chunk_size);
            max_transaction_chunk_sizes.push(summary.protocol_metadata.max_transaction_chunk_size);
            max_transaction_output_chunk_sizes
                .push(summary.protocol_metadata.max_transaction_output_chunk_size);
        }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L286-287)
```rust
        // Verify the data stream can be fulfilled using the currently advertised data
        data_stream.ensure_data_is_available(&advertised_data)?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1862-1866)
```rust
        Ok(AdvertisedData::contains_range(
            self.next_stream_version,
            request_end_version,
            advertised_ranges,
        ))
```
