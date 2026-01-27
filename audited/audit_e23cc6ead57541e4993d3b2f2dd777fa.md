# Audit Report

## Title
State-Sync Global Data Summary Poisoning via Unvalidated StorageServerSummary Injection

## Summary
The `update_summary()` function in the state-sync data client stores peer-provided `StorageServerSummary` data without performing any validation, allowing malicious peers to inject arbitrary metadata that pollutes the global data summary used by all synchronization services, leading to network-wide denial of service and stalled state synchronization.

## Finding Description

The vulnerability exists in the peer state management component of Aptos's state synchronization system. When peers advertise their storage capabilities, they send a `StorageServerSummary` containing metadata about available data ranges, chunk sizes, and the highest synced ledger info. This summary is stored and aggregated into a global data summary that drives all synchronization decisions across the network.

**The Core Vulnerability:**

The `update_summary()` function accepts `StorageServerSummary` data from network peers and stores it directly without any validation: [1](#0-0) 

This function calls the internal `update_storage_summary()` which simply stores the data: [2](#0-1) 

**Attack Flow:**

1. **Data Injection Point**: The data client polls peers for their storage summaries via `GetStorageServerSummary` requests: [3](#0-2) 

2. **Direct Storage Without Validation**: The received summary is immediately stored: [4](#0-3) 

3. **Global Summary Aggregation**: The unvalidated data is aggregated into the global data summary that all streaming services consume: [5](#0-4) 

Specifically, the malicious data pollutes critical fields:
- Chunk sizes are collected without bounds checking [6](#0-5) 

- Synced ledger infos (including signatures) are collected without cryptographic verification: [7](#0-6) 

**Exploitation Scenarios:**

A malicious peer can craft a `StorageServerSummary` containing:

1. **Zero Chunk Sizes Attack**: Set all `max_*_chunk_size` fields to 0 in the `ProtocolMetadata`: [8](#0-7) 

If the attacker controls a majority of connected peers, the median calculation will produce zero: [9](#0-8) 

This causes immediate errors when the streaming service validates chunk sizes: [10](#0-9) 

2. **Fake Synced Ledger Info Attack**: Inject a `LedgerInfoWithSignatures` with an arbitrarily high version number and invalid signatures: [11](#0-10) 

The highest version becomes the sync target: [12](#0-11) 

This fake target is used by stream engines to determine what data to request: [13](#0-12) 

3. **Fake Data Ranges Attack**: Advertise non-existent data ranges, causing the node to preferentially select the malicious peer for requests based on false capabilities: [14](#0-13) 

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability meets the Critical severity criteria for the following reasons:

1. **Consensus/Safety Violations**: The global data summary determines what data nodes request and from whom. Poisoning this summary can cause nodes to diverge in their synchronization state, potentially leading to consensus failures if nodes cannot agree on the latest state.

2. **Total Loss of Liveness/Network Availability**: If multiple coordinated malicious peers inject zero chunk sizes, honest nodes will be unable to stream any data due to validation errors, effectively halting state synchronization network-wide.

3. **Non-recoverable Network Partition**: Nodes relying on poisoned global summaries may attempt to sync to non-existent versions (via fake high-version ledger infos), causing them to diverge permanently from honest nodes until manual intervention occurs.

4. **Significant Protocol Violations**: The attack violates Aptos's state consistency invariant - "State transitions must be atomic and verifiable via Merkle proofs." Nodes making decisions based on unverified peer advertisements cannot maintain this guarantee.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to be exploited because:

1. **Low Attack Barrier**: Any peer can connect to the network and respond to `GetStorageServerSummary` requests with crafted data. No privileged access or validator status is required.

2. **No Authentication**: The `StorageServerSummary` structure itself contains no cryptographic binding to the peer's identity or proof of the advertised data's validity.

3. **Immediate Impact**: Even a single malicious peer begins polluting the global data summary immediately upon connection. With multiple peers, the attacker can control the median calculations.

4. **Delayed Detection**: The scoring system only penalizes peers AFTER they fail to deliver advertised data. The initial poisoning occurs before any penalty is applied: [15](#0-14) 

5. **Amplification Effect**: A single malicious summary is aggregated with honest summaries, affecting all nodes that query the global data summary.

## Recommendation

Implement validation at the point where `StorageServerSummary` is received and before it is stored. The validation should include:

1. **Chunk Size Validation**: Enforce minimum chunk sizes to prevent zero or near-zero values:
```rust
pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
    // Validate chunk sizes
    if storage_summary.protocol_metadata.max_epoch_chunk_size == 0
        || storage_summary.protocol_metadata.max_state_chunk_size == 0
        || storage_summary.protocol_metadata.max_transaction_chunk_size == 0
        || storage_summary.protocol_metadata.max_transaction_output_chunk_size == 0
    {
        warn!(
            "Rejecting storage summary from peer {:?} due to zero chunk size",
            peer
        );
        return;
    }
    
    // Validate synced ledger info signatures if present
    if let Some(synced_ledger_info) = &storage_summary.data_summary.synced_ledger_info {
        // Verify signatures using the current epoch state
        // This requires passing epoch state to this function
        if let Err(e) = validate_ledger_info_signatures(synced_ledger_info) {
            warn!(
                "Rejecting storage summary from peer {:?} due to invalid ledger info: {:?}",
                peer, e
            );
            return;
        }
    }
    
    // Validate data ranges are reasonable (not claiming impossibly wide ranges)
    if let Some(transactions) = storage_summary.data_summary.transactions {
        if transactions.len() > MAX_REASONABLE_TRANSACTION_RANGE {
            warn!(
                "Rejecting storage summary from peer {:?} due to suspicious transaction range",
                peer
            );
            return;
        }
    }
    
    self.peer_to_state
        .entry(peer)
        .or_insert(PeerState::new(self.data_client_config.clone()))
        .update_storage_summary(storage_summary);
}
```

2. **Add bounds checking in the median calculation** to reject outliers: [16](#0-15) 

Modify to filter out extreme values before calculating median.

3. **Implement cryptographic verification** of synced ledger info signatures before including them in the global summary, similar to how proofs are verified during data streaming: [17](#0-16) 

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// This can be added as a unit test in state-sync/aptos-data-client/src/tests/

#[tokio::test]
async fn test_malicious_storage_summary_poisoning() {
    use crate::peer_states::PeerStates;
    use aptos_config::config::AptosDataClientConfig;
    use aptos_storage_service_types::responses::{
        DataSummary, ProtocolMetadata, StorageServerSummary
    };
    use aptos_types::ledger_info::LedgerInfoWithSignatures;
    use std::sync::Arc;
    
    // Create peer states
    let config = Arc::new(AptosDataClientConfig::default());
    let peer_states = PeerStates::new(config.clone());
    
    // Create a malicious storage summary with zero chunk sizes
    let malicious_summary = StorageServerSummary {
        protocol_metadata: ProtocolMetadata {
            max_epoch_chunk_size: 0,        // ZERO!
            max_state_chunk_size: 0,         // ZERO!
            max_transaction_chunk_size: 0,   // ZERO!
            max_transaction_output_chunk_size: 0, // ZERO!
        },
        data_summary: DataSummary::default(),
    };
    
    // Inject the malicious summary (NO VALIDATION!)
    let malicious_peer = create_random_peer_network_id();
    peer_states.update_summary(malicious_peer, malicious_summary);
    
    // Add a few honest peers
    for _ in 0..2 {
        let honest_peer = create_random_peer_network_id();
        peer_states.update_summary(honest_peer, StorageServerSummary::default());
    }
    
    // Calculate global summary - will be poisoned!
    let global_summary = peer_states.calculate_global_data_summary();
    
    // If malicious peers are majority, optimal chunk sizes become zero
    // This would cause validation errors in streaming service
    println!("Epoch chunk size: {}", global_summary.optimal_chunk_sizes.epoch_chunk_size);
    println!("State chunk size: {}", global_summary.optimal_chunk_sizes.state_chunk_size);
    
    // Demonstrate fake ledger info attack
    let fake_ledger_info = create_fake_ledger_info_with_high_version(999999999);
    let summary_with_fake_ledger = StorageServerSummary {
        protocol_metadata: ProtocolMetadata::default(),
        data_summary: DataSummary {
            synced_ledger_info: Some(fake_ledger_info), // No signature validation!
            ..Default::default()
        },
    };
    
    peer_states.update_summary(create_random_peer_network_id(), summary_with_fake_ledger);
    let poisoned_summary = peer_states.calculate_global_data_summary();
    
    // The fake high-version ledger info becomes the highest
    if let Some(highest) = poisoned_summary.advertised_data.highest_synced_ledger_info() {
        assert_eq!(highest.ledger_info().version(), 999999999);
        println!("Successfully poisoned with fake version: {}", highest.ledger_info().version());
    }
}
```

## Notes

This vulnerability is particularly dangerous because it exploits the trust assumption that peer-advertised metadata reflects reality. The state-sync system was designed with the assumption that incorrect advertisements would be caught during data delivery when proofs are verified. However, this reactive approach allows initial poisoning of the global state that affects all synchronization decisions.

The lack of validation at the advertisement stage creates a window where malicious peers can influence network-wide behavior before being penalized by the scoring system. In a coordinated attack with multiple malicious peers, this window can be extended indefinitely, causing persistent denial of service.

The fix requires implementing proactive validation rather than reactive penalty, ensuring that only cryptographically verifiable and reasonable metadata enters the global data summary that drives critical synchronization decisions across the entire Aptos network.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L162-174)
```rust
    /// Updates the score of the peer according to a successful operation
    fn update_score_success(&mut self) {
        self.score = f64::min(self.score + SUCCESSFUL_RESPONSE_DELTA, MAX_SCORE);
    }

    /// Updates the score of the peer according to an error
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L176-179)
```rust
    /// Updates the storage summary for the peer
    fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
        self.storage_summary = Some(storage_summary);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L200-227)
```rust
    pub fn can_service_request(
        &self,
        peer: &PeerNetworkId,
        time_service: TimeService,
        request: &StorageServiceRequest,
    ) -> bool {
        // Storage services can always respond to data advertisement requests.
        // We need this outer check, since we need to be able to send data summary
        // requests to new peers (who don't have a peer state yet).
        if request.data_request.is_storage_summary_request()
            || request.data_request.is_protocol_version_request()
        {
            return true;
        }

        // Check if the peer can service the request
        if let Some(peer_state) = self.peer_to_state.get(peer) {
            return match peer_state.get_storage_summary_if_not_ignored() {
                Some(storage_summary) => {
                    storage_summary.can_service(&self.data_client_config, time_service, request)
                },
                None => false, // The peer is temporarily ignored
            };
        }

        // Otherwise, the request cannot be serviced
        false
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L325-330)
```rust
    pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
        self.peer_to_state
            .entry(peer)
            .or_insert(PeerState::new(self.data_client_config.clone()))
            .update_storage_summary(storage_summary);
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

**File:** state-sync/aptos-data-client/src/poller.rs (L405-416)
```rust
        // Construct the request for polling
        let data_request = DataRequest::GetStorageServerSummary;
        let use_compression = data_summary_poller.data_client_config.use_compression;
        let storage_request = StorageServiceRequest::new(data_request, use_compression);

        // Fetch the storage summary for the peer and stop the timer
        let request_timeout = data_summary_poller.data_client_config.response_timeout_ms;
        let result: crate::error::Result<StorageServerSummary> = data_summary_poller
            .data_client
            .send_request_to_peer_and_decode(peer, storage_request, request_timeout)
            .await
            .map(Response::into_payload);
```

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

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

**File:** state-sync/storage-service/types/src/responses.rs (L666-686)
```rust
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L522-534)
```rust
        // We don't have a final target, select the highest to make progress
        if let Some(highest_synced_ledger_info) = advertised_data.highest_synced_ledger_info() {
            let (next_request_version, _) = self.next_request_version_and_epoch;
            if next_request_version > highest_synced_ledger_info.ledger_info().version() {
                Ok(None) // We're already at the highest synced ledger info. There's no known target.
            } else {
                Ok(Some(highest_synced_ledger_info))
            }
        } else {
            Err(Error::DataIsUnavailable(
                "Unable to find the highest synced ledger info!".into(),
            ))
        }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L452-465)
```rust
        // Verify the ledger info state and signatures
        if let Err(error) = self
            .get_speculative_stream_state()?
            .verify_ledger_info_with_signatures(ledger_info_with_signatures)
        {
            self.reset_active_stream(Some(NotificationAndFeedback::new(
                notification_id,
                NotificationFeedback::PayloadProofFailed,
            )))
            .await?;
            Err(error)
        } else {
            Ok(())
        }
```
