# Audit Report

## Title
State Sync Denial of Service via Unvalidated Zero Chunk Sizes in Global Data Summary

## Summary
The state-sync system can enter a permanent liveness failure when malicious peers advertise zero chunk sizes in their `ProtocolMetadata`. The validation exists in the data-streaming-service layer but not in the aptos-data-client layer where chunk sizes are aggregated, and the streaming-service cache is initialized to an invalid empty state with zero chunk sizes. This allows attackers controlling a majority of a victim node's peer connections to prevent the node from synchronizing with the blockchain.

## Finding Description

The vulnerability exists in the state-sync chunk size optimization system across multiple components: [1](#0-0) 

The `OptimalChunkSizes::empty()` initializes all chunk sizes to zero, which is used as the initial cached value. [2](#0-1) 

The data-streaming-service initializes its cached `global_data_summary` to the empty state with zero chunk sizes. [3](#0-2) 

The `calculate_optimal_chunk_sizes` function uses the median of peer-advertised chunk sizes capped by config maximums. When malicious peers advertise zero chunk sizes, and they represent the majority of connected peers, the median calculation produces zero. [4](#0-3) 

The `median_or_max` function returns `min(median, max_value)`. When the median is zero, it returns zero regardless of the configured maximum. [5](#0-4) 

The aptos-data-client's `update_global_summary_cache` stores the calculated chunk sizes WITHOUT validation. Zero chunk sizes are accepted and cached. [6](#0-5) 

Validation exists in `verify_optimal_chunk_sizes` but only in the data-streaming-service layer. When validation fails due to zero chunk sizes, the streaming-service cache is not updated, leaving it in the initial invalid empty state. [7](#0-6) 

When `create_data_client_request_batch` is called with `optimal_chunk_size = 0`, the calculation at line 2072 results in `num_items_to_fetch = 0`. At lines 2076-2079, when `num_items_to_fetch` is zero and added to `request_start_index` then subtracted by 1, it produces either an integer underflow error (if start_index is 0) or an invalid request where `request_end_index < request_start_index` (if start_index > 0). Line 2056 catches the latter case and returns an empty vector, but this means no progress is ever made.

**Attack Path:**
1. Attacker controls a majority of peers in the victim node's connection set (eclipse attack-like scenario)
2. Malicious peers advertise `ProtocolMetadata` with all `max_*_chunk_size` fields set to 0
3. Victim node's aptos-data-client aggregates these values and calculates optimal_chunk_sizes as 0 (median of zeros)
4. This is stored in the data-client cache without validation
5. Data-streaming-service fetches this and validation detects the zeros
6. Validation error prevents cache update, leaving streaming-service cache at initial empty state (also zeros)
7. All stream engines attempting to create requests receive zero chunk sizes
8. Request batch creation either fails with integer underflow or returns empty request lists
9. Streams cannot progress, node cannot sync, achieving denial of service

## Impact Explanation

This vulnerability represents a **High Severity** availability issue per Aptos bug bounty criteria. A node affected by this attack cannot synchronize with the blockchain network, effectively causing "Validator node slowdowns" and potentially broader liveness issues. While not a complete network-wide failure (since it requires per-node eclipse conditions), it can prevent:

- New nodes from joining and syncing with the network
- Existing nodes from recovering after downtime
- Validator nodes from maintaining consensus participation

The attack does not directly cause consensus safety violations or fund loss, but prolonged inability to sync can lead to validators being removed from the active set, indirectly affecting network security and decentralization.

## Likelihood Explanation

The likelihood is **Medium** because:

**Factors Increasing Likelihood:**
- Zero is a valid `u64` value that can be serialized and transmitted
- No validation exists in the aptos-data-client where aggregation occurs
- The initial cache state is vulnerable (zero chunk sizes)
- Malicious peers can advertise arbitrary `ProtocolMetadata` values

**Factors Decreasing Likelihood:**
- Requires attacker to control majority of victim's connected peers (eclipse attack scenario)
- Peer scoring system eventually detects and ignores misbehaving peers [8](#0-7) 
- Most production networks have diverse peer connections reducing eclipse attack success
- The issue would be noticed during initial network connection when many peers are involved

However, the attack window exists during node startup or network partition recovery when peer sets are being established.

## Recommendation

Implement validation at multiple defensive layers:

**1. Add validation in aptos-data-client before caching:**
```rust
pub fn update_global_summary_cache(&self) -> crate::error::Result<(), Error> {
    self.garbage_collect_peer_states()?;
    
    let global_data_summary = self.peer_states.calculate_global_data_summary();
    
    // ADDED: Validate chunk sizes before caching
    if global_data_summary.optimal_chunk_sizes.state_chunk_size == 0
        || global_data_summary.optimal_chunk_sizes.epoch_chunk_size == 0
        || global_data_summary.optimal_chunk_sizes.transaction_chunk_size == 0
        || global_data_summary.optimal_chunk_sizes.transaction_output_chunk_size == 0
    {
        return Err(Error::DataIsUnavailable(
            "Invalid optimal chunk sizes (zero detected)".into()
        ));
    }
    
    self.global_summary_cache.store(Arc::new(global_data_summary));
    Ok(())
}
```

**2. Initialize cache with safe defaults instead of zeros:** [9](#0-8) 

```rust
impl OptimalChunkSizes {
    pub fn empty() -> Self {
        // Use configured defaults instead of zeros
        OptimalChunkSizes {
            epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            state_chunk_size: MAX_STATE_CHUNK_SIZE,
            transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
        }
    }
}
```

**3. Add minimum bounds checking in median_or_max:**
```rust
fn median_or_max<T: Ord + Copy>(mut values: Vec<T>, max_value: T) -> T {
    values.sort_unstable();
    let idx = values.len() / 2;
    let median = values.get(idx).copied();
    
    let result = min(median.unwrap_or(max_value), max_value);
    
    // ADDED: Never allow zero, use a reasonable minimum (10% of max)
    if result == T::default() {  // Assumes T has Default trait
        max_value / 10  // Use 10% of max as minimum
    } else {
        result
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::config::AptosDataClientConfig;
    
    #[test]
    fn test_zero_chunk_size_dos() {
        let config = AptosDataClientConfig::default();
        
        // Simulate all malicious peers advertising zero chunk sizes
        let malicious_chunk_sizes = vec![0u64, 0, 0, 0, 0];
        
        // Calculate optimal chunk sizes
        let result = calculate_optimal_chunk_sizes(
            &config,
            malicious_chunk_sizes.clone(),
            malicious_chunk_sizes.clone(),
            malicious_chunk_sizes.clone(),
            malicious_chunk_sizes,
        );
        
        // All chunk sizes are zero
        assert_eq!(result.epoch_chunk_size, 0);
        assert_eq!(result.state_chunk_size, 0);
        assert_eq!(result.transaction_chunk_size, 0);
        assert_eq!(result.transaction_output_chunk_size, 0);
        
        // Attempt to create request batch with zero chunk size
        let batch_result = create_data_client_request_batch(
            0,    // start_index
            100,  // end_index
            10,   // max_requests
            0,    // optimal_chunk_size (ZERO)
            StreamEngine::StateStreamEngine(/* ... */),
        );
        
        // This will cause integer underflow error or empty request batch
        match batch_result {
            Err(Error::IntegerOverflow(_)) => {
                // Integer underflow occurred at start_index=0
                println!("DoS confirmed: Integer underflow with zero chunk size");
            },
            Ok(requests) => {
                // Empty request list at start_index>0
                assert_eq!(requests.len(), 0);
                println!("DoS confirmed: No requests created with zero chunk size");
            }
        }
    }
}
```

**Notes:**
- The vulnerability combines a logic error (validation placement) with an initialization flaw (zero defaults)
- The median aggregation approach is sound but needs bounds enforcement
- The peer scoring system provides partial mitigation but doesn't prevent the initial attack window
- Production impact depends on network topology and peer discovery mechanisms

### Citations

**File:** state-sync/aptos-data-client/src/global_summary.rs (L52-60)
```rust
impl OptimalChunkSizes {
    pub fn empty() -> Self {
        OptimalChunkSizes {
            epoch_chunk_size: 0,
            state_chunk_size: 0,
            transaction_chunk_size: 0,
            transaction_output_chunk_size: 0,
        }
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L102-114)
```rust
        Self {
            data_client_config,
            streaming_service_config,
            aptos_data_client,
            global_data_summary: Arc::new(ArcSwap::new(Arc::new(GlobalDataSummary::empty()))),
            data_streams: HashMap::new(),
            stream_requests,
            stream_update_notifier,
            stream_update_listener,
            stream_id_generator: U64IdGenerator::new(),
            notification_id_generator: Arc::new(U64IdGenerator::new()),
            time_service,
        }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L476-491)
```rust
/// Verifies that all optimal chunk sizes are valid (i.e., not zero). Returns an
/// error if a chunk size is 0.
fn verify_optimal_chunk_sizes(optimal_chunk_sizes: &OptimalChunkSizes) -> Result<(), Error> {
    if optimal_chunk_sizes.state_chunk_size == 0
        || optimal_chunk_sizes.epoch_chunk_size == 0
        || optimal_chunk_sizes.transaction_chunk_size == 0
        || optimal_chunk_sizes.transaction_output_chunk_size == 0
    {
        Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Found at least one optimal chunk size of zero: {:?}",
            optimal_chunk_sizes
        )))
    } else {
        Ok(())
    }
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L341-350)
```rust
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
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L419-443)
```rust
pub(crate) fn calculate_optimal_chunk_sizes(
    config: &AptosDataClientConfig,
    max_epoch_chunk_sizes: Vec<u64>,
    max_state_chunk_sizes: Vec<u64>,
    max_transaction_chunk_sizes: Vec<u64>,
    max_transaction_output_chunk_size: Vec<u64>,
) -> OptimalChunkSizes {
    let epoch_chunk_size = median_or_max(max_epoch_chunk_sizes, config.max_epoch_chunk_size);
    let state_chunk_size = median_or_max(max_state_chunk_sizes, config.max_state_chunk_size);
    let transaction_chunk_size = median_or_max(
        max_transaction_chunk_sizes,
        config.max_transaction_chunk_size,
    );
    let transaction_output_chunk_size = median_or_max(
        max_transaction_output_chunk_size,
        config.max_transaction_output_chunk_size,
    );

    OptimalChunkSizes {
        epoch_chunk_size,
        state_chunk_size,
        transaction_chunk_size,
        transaction_output_chunk_size,
    }
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L448-456)
```rust
fn median_or_max<T: Ord + Copy>(mut values: Vec<T>, max_value: T) -> T {
    // Calculate median
    values.sort_unstable();
    let idx = values.len() / 2;
    let median = values.get(idx).copied();

    // Return median or max
    min(median.unwrap_or(max_value), max_value)
}
```

**File:** state-sync/aptos-data-client/src/client.rs (L217-231)
```rust
    /// Recompute and update the global data summary cache
    pub fn update_global_summary_cache(&self) -> crate::error::Result<(), Error> {
        // Before calculating the summary, we should garbage collect
        // the peer states (to handle disconnected peers).
        self.garbage_collect_peer_states()?;

        // Calculate the global data summary
        let global_data_summary = self.peer_states.calculate_global_data_summary();

        // Update the cached data summary
        self.global_summary_cache
            .store(Arc::new(global_data_summary));

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2048-2099)
```rust
/// Creates a batch of data client requests for the given stream engine
fn create_data_client_request_batch(
    start_index: u64,
    end_index: u64,
    max_number_of_requests: u64,
    optimal_chunk_size: u64,
    stream_engine: StreamEngine,
) -> Result<Vec<DataClientRequest>, Error> {
    if start_index > end_index {
        return Ok(vec![]);
    }

    // Calculate the total number of items left to satisfy the stream
    let mut total_items_to_fetch = end_index
        .checked_sub(start_index)
        .and_then(|e| e.checked_add(1)) // = end_index - start_index + 1
        .ok_or_else(|| Error::IntegerOverflow("Total items to fetch has overflown!".into()))?;

    // Iterate until we've requested all transactions or hit the maximum number of requests
    let mut data_client_requests = vec![];
    let mut num_requests_made = 0;
    let mut next_index_to_request = start_index;
    while total_items_to_fetch > 0 && num_requests_made < max_number_of_requests {
        // Calculate the number of items to fetch in this request
        let num_items_to_fetch = cmp::min(total_items_to_fetch, optimal_chunk_size);

        // Calculate the start and end indices for the request
        let request_start_index = next_index_to_request;
        let request_end_index = request_start_index
            .checked_add(num_items_to_fetch)
            .and_then(|e| e.checked_sub(1)) // = request_start_index + num_items_to_fetch - 1
            .ok_or_else(|| Error::IntegerOverflow("End index to fetch has overflown!".into()))?;

        // Create the data client requests
        let data_client_request =
            create_data_client_request(request_start_index, request_end_index, &stream_engine)?;
        data_client_requests.push(data_client_request);

        // Update the local loop state
        next_index_to_request = request_end_index
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next index to request has overflown!".into()))?;
        total_items_to_fetch = total_items_to_fetch
            .checked_sub(num_items_to_fetch)
            .ok_or_else(|| Error::IntegerOverflow("Total items to fetch has overflown!".into()))?;
        num_requests_made = num_requests_made.checked_add(1).ok_or_else(|| {
            Error::IntegerOverflow("Number of payload requests has overflown!".into())
        })?;
    }

    Ok(data_client_requests)
}
```

**File:** config/src/config/state_sync_config.rs (L24-27)
```rust
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```
