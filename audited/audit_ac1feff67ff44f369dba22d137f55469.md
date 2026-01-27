# Audit Report

## Title
State Synchronization Performance DoS via Malicious Optimal Chunk Size Manipulation

## Summary
Malicious peers can advertise artificially low chunk sizes in their `StorageServerSummary` responses, which are aggregated via median calculation to determine optimal chunk sizes used across the network for state synchronization. With >=50% malicious peers, attackers can force the optimal chunk size to extremely low values (e.g., 1), causing severe performance degradation as nodes must issue millions of tiny requests instead of thousands of appropriately-sized batches.

## Finding Description

The vulnerability exists in the state synchronization chunk size calculation mechanism. When peers are polled for their storage summaries, they respond with `ProtocolMetadata` containing their advertised maximum chunk sizes: [1](#0-0) 

These peer-provided values are collected and aggregated to calculate "optimal chunk sizes" via median calculation: [2](#0-1) 

The `calculate_optimal_chunk_sizes` function uses `median_or_max` which takes the median of all peer-provided values and caps it at a configured maximum: [3](#0-2) 

**Critical Issue**: The median calculation provides NO lower bound validation. While it caps values at the maximum, it allows the median to be as low as 1 (only zero values are rejected): [4](#0-3) 

These optimal chunk sizes directly control batch sizes during synchronization: [5](#0-4) 

**Attack Scenario:**

1. Attacker controls >=50% of non-ignored peers in the network
2. Malicious peers return valid `StorageServerSummary` responses with all chunk sizes set to 1
3. These peers receive **positive** scores for successful responses (no penalty for low values): [6](#0-5) 
4. The median calculation produces optimal_chunk_size = min(1, MAX_CONFIGURED) = 1
5. All nodes now fetch only 1 item per request during synchronization
6. To sync 1 million transactions requires 1 million requests instead of ~333 requests (at default 3000 chunk size)

**Why This Works:**
- No minimum chunk size validation exists
- Advertising low chunk sizes does NOT trigger malicious peer detection
- Malicious peers get SUCCESS scores, not penalties
- Only requires 50% of peers to control the median

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program category "Validator node slowdowns":

- **Performance DoS**: Forces nodes to issue millions of tiny requests, each with network overhead, instead of efficient batched requests
- **State Sync Failure**: Nodes may be unable to catch up to the network tip due to severe slowdown (1/3000th of normal speed)
- **Network Congestion**: Massive increase in request volume overwhelms both client and server nodes
- **Availability Impact**: New validators or recovering nodes cannot sync in reasonable time
- **No Funds Lost**: Does not affect consensus safety or steal funds
- **Reversible**: Can be mitigated by updating peer connections, but requires operator intervention

The default maximum chunk sizes are: [7](#0-6) 

An attacker forcing chunk_size=1 reduces throughput by 200-4000x depending on data type.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Control >=50% of non-ignored peers visible to target nodes
- Ability to respond to storage summary requests
- No privileged access needed

**Ease of Execution:**
- Simple: Just return modified `ProtocolMetadata` in storage summary responses
- No complex cryptographic attacks required
- Works against all nodes simultaneously

**Persistence:**
- Attack persists until malicious peers are manually removed or network topology changes
- No automatic detection/mitigation exists in current code
- Peer scoring system doesn't penalize low chunk sizes

**Real-World Feasibility:**
- In a permissionless p2p network, attacker could spin up many malicious nodes
- Sybil attack potential if peer selection isn't sufficiently diverse
- More feasible during network bootstrap or when legitimate peer count is low

## Recommendation

Implement minimum chunk size validation in the `calculate_optimal_chunk_sizes` function:

```rust
fn median_or_max<T: Ord + Copy>(mut values: Vec<T>, max_value: T, min_value: T) -> T {
    values.sort_unstable();
    let idx = values.len() / 2;
    let median = values.get(idx).copied();
    
    // Clamp median between min and max values
    let result = median.unwrap_or(max_value);
    cmp::max(cmp::min(result, max_value), min_value)
}
```

And update the call sites: [8](#0-7) 

Add minimum constants to the config:
```rust
const MIN_EPOCH_CHUNK_SIZE: u64 = 10;
const MIN_STATE_CHUNK_SIZE: u64 = 100;
const MIN_TRANSACTION_CHUNK_SIZE: u64 = 100;
const MIN_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 100;
```

Additionally, consider:
1. **Outlier Detection**: Flag peers advertising suspiciously low values (<10% of median) as potentially malicious
2. **Weighted Median**: Use peer scores to weight the median calculation, reducing malicious peer influence
3. **Progressive Penalties**: Reduce scores for peers with chunk sizes far from the honest majority

## Proof of Concept

```rust
#[cfg(test)]
mod chunk_size_manipulation_test {
    use super::*;
    use aptos_config::config::AptosDataClientConfig;

    #[test]
    fn test_malicious_low_chunk_sizes() {
        // Setup config with reasonable defaults
        let config = AptosDataClientConfig::default();
        
        // Simulate honest peers advertising normal chunk sizes
        let honest_epoch_chunks = vec![200, 190, 200, 195];
        let honest_transaction_chunks = vec![3000, 2900, 3000, 2950];
        
        // Malicious peers advertise extremely low chunk sizes
        let malicious_epoch_chunks = vec![1, 1, 1, 1, 1];
        let malicious_transaction_chunks = vec![1, 1, 1, 1, 1];
        
        // Combine: 5 malicious, 4 honest (malicious majority)
        let mut all_epoch_chunks = honest_epoch_chunks.clone();
        all_epoch_chunks.extend(malicious_epoch_chunks);
        
        let mut all_transaction_chunks = honest_transaction_chunks.clone();
        all_transaction_chunks.extend(malicious_transaction_chunks);
        
        // Calculate optimal chunk sizes
        let optimal = calculate_optimal_chunk_sizes(
            &config,
            all_epoch_chunks.clone(),
            vec![4000; 9], // states
            all_transaction_chunks.clone(),
            vec![3000; 9], // outputs
        );
        
        // With 5/9 malicious peers, median becomes 1
        assert_eq!(optimal.epoch_chunk_size, 1);
        assert_eq!(optimal.transaction_chunk_size, 1);
        
        // This passes zero-check but causes severe performance degradation
        println!("Attack successful! Chunk sizes reduced to 1");
        println!("Performance degradation: 200x for epochs, 3000x for transactions");
    }
}
```

**Notes:**
- The vulnerability is exploitable without any privileged access
- No consensus invariant is broken, but availability is severely impacted
- The median calculation creates a 50% threshold for attack success
- Current peer scoring provides no defense against this attack vector

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L636-642)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolMetadata {
    pub max_epoch_chunk_size: u64, // The max number of epochs the server can return in a single chunk
    pub max_state_chunk_size: u64, // The max number of states the server can return in a single chunk
    pub max_transaction_chunk_size: u64, // The max number of transactions the server can return in a single chunk
    pub max_transaction_output_chunk_size: u64, // The max number of transaction outputs the server can return in a single chunk
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L162-165)
```rust
    /// Updates the score of the peer according to a successful operation
    fn update_score_success(&mut self) {
        self.score = f64::min(self.score + SUCCESSFUL_RESPONSE_DELTA, MAX_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L339-408)
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

        // Calculate optimal chunk sizes based on the advertised data
        let optimal_chunk_sizes = calculate_optimal_chunk_sizes(
            &self.data_client_config,
            max_epoch_chunk_sizes,
            max_state_chunk_sizes,
            max_transaction_chunk_sizes,
            max_transaction_output_chunk_sizes,
        );
        GlobalDataSummary {
            advertised_data,
            optimal_chunk_sizes,
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L419-456)
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

/// Calculates the median of the given set of values (if it exists)
/// and returns the median or the specified max value, whichever is
/// lower.
fn median_or_max<T: Ord + Copy>(mut values: Vec<T>, max_value: T) -> T {
    // Calculate median
    values.sort_unstable();
    let idx = values.len() / 2;
    let median = values.get(idx).copied();

    // Return median or max
    min(median.unwrap_or(max_value), max_value)
}
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L478-490)
```rust
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
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2066-2098)
```rust
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
```

**File:** config/src/config/state_sync_config.rs (L23-27)
```rust
// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```
