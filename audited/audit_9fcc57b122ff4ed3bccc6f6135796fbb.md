# Audit Report

## Title
Unvalidated Peer Advertisement Enables State Sync Denial of Service via False Epoch Range Claims

## Summary
Malicious peers can advertise false `epoch_ending_ledger_infos` ranges in their `StorageServerSummary` without validation, causing victim nodes to create data streams that will inevitably fail. This blocks state synchronization progress during retry cycles and wastes network resources.

## Finding Description

The state synchronization subsystem relies on peers advertising their available data ranges through `StorageServerSummary` messages. These advertisements are aggregated into a global view (`AdvertisedData`) which is used to determine if requested data ranges are available before creating data streams.

**The vulnerability exists because advertised data ranges are accepted without validation:** [1](#0-0) 

When a peer sends a `StorageServerSummary`, the receiving node simply stores it without verifying that the advertised `epoch_ending_ledger_infos` range is consistent with the `synced_ledger_info` or any cryptographic proof.

**Attack Flow:**

1. **False Advertisement**: A malicious peer advertises `epoch_ending_ledger_infos` range [0, 1000] when it only possesses epochs [0, 100]

2. **Global Aggregation**: The victim node aggregates this false data into its global summary: [2](#0-1) 

3. **Stream Creation Check Passes**: When the victim needs epochs [500, 600], `is_remaining_data_available()` checks pass because the advertised range includes this: [3](#0-2) 

4. **Peer Selection**: The malicious peer is selected to service requests because `can_service()` checks only against advertised ranges: [4](#0-3) 

5. **Request Failure**: When the actual request is made, the peer's database validation fails: [5](#0-4) 

6. **Retry Loop**: Failed requests trigger exponential backoff retries, blocking state sync progress until `max_request_retry` is exceeded.

7. **Delayed Recovery**: Only after repeated failures does peer scoring eventually ignore the malicious peer: [6](#0-5) 

**Security Guarantee Violated**: This breaks the availability guarantee of state synchronization. Nodes cannot efficiently sync to the latest state when malicious peers pollute the advertised data with false ranges.

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty criteria)

This vulnerability causes **temporary state synchronization blocking**:

- **Immediate Impact**: State sync stalls during retry cycles (exponential backoff delays)
- **Resource Waste**: Network bandwidth consumed by failing requests
- **Cascade Effect**: Multiple malicious peers can sustain the attack, prolonging unavailability
- **Detection Delay**: Peer scoring takes multiple failures before ignoring malicious peers (score starts at 50.0, drops to < 25.0 threshold via 0.95x multiplier)

**Why Not Higher Severity:**
- Not permanent (eventually peers are ignored and state sync recovers)
- Doesn't directly affect consensus safety or cause fund loss
- Requires continuous presence of malicious peers

**Why Not Lower Severity:**
- Directly impacts protocol availability (state sync is critical for node operation)
- Low attack complexity (any peer can exploit)
- Can affect multiple nodes simultaneously
- Requires manual intervention or waiting for timeouts to recover

## Likelihood Explanation

**Likelihood: High**

**Attack Complexity: Low**
- No special privileges required (any network peer can participate)
- No cryptographic bypasses needed
- Simple to execute: send false `StorageServerSummary` during polling

**Attacker Requirements:**
- Establish peer connection to victim node
- Respond to `GetStorageServerSummary` requests
- No need to pass authentication beyond basic P2P connection

**Detection Difficulty:**
- False advertisements are not detected until actual data requests fail
- No immediate validation prevents the attack
- Logs may only show generic "request failure" messages

**Persistence:**
- Attacker can rejoin with new peer identities after being ignored
- Multiple colluding peers can sustain prolonged attacks
- Attack effectiveness increases with network position (if attacker controls many peer connections)

## Recommendation

**Add validation of advertised data ranges against cryptographic proofs:**

1. **Validate epoch ranges against `synced_ledger_info`**: When receiving a `StorageServerSummary`, verify that the advertised `epoch_ending_ledger_infos` range is consistent with the epoch in `synced_ledger_info`:

```rust
fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
    // Validate epoch_ending_ledger_infos consistency
    if let Some(synced_ledger_info) = &storage_summary.data_summary.synced_ledger_info {
        let synced_epoch = synced_ledger_info.ledger_info().epoch();
        
        if let Some(epoch_range) = storage_summary.data_summary.epoch_ending_ledger_infos {
            // The highest advertised epoch should not exceed the synced epoch
            if epoch_range.highest() > synced_epoch {
                warn!("Peer advertised invalid epoch range: {:?} > synced epoch {}",
                      epoch_range, synced_epoch);
                return; // Reject invalid summary
            }
        }
    }
    
    self.storage_summary = Some(storage_summary);
}
```

2. **Add peer reputation penalty for false advertisements**: When data requests fail due to unavailability from a peer that claimed to have the data, apply a **Malicious** error type instead of **NotUseful**:

```rust
// In client.rs, when handling epoch ending ledger info request failures
if let Err(Error::InvalidRequest(_)) = response {
    // Check if peer advertised this range but couldn't deliver
    if peer_advertised_this_range(peer, request) {
        self.notify_bad_response(id, peer, request, ErrorType::Malicious);
    }
}
```

3. **Require periodic re-validation**: Implement periodic spot-checks where nodes request small data samples to verify advertised ranges are accurate.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_storage_service_types::responses::{
        CompleteDataRange, DataSummary, StorageServerSummary, ProtocolMetadata
    };
    use aptos_types::ledger_info::LedgerInfoWithSignatures;
    
    #[test]
    fn test_false_epoch_advertisement_attack() {
        // Setup: Create data client config and peer states
        let config = Arc::new(AptosDataClientConfig::default());
        let peer_states = PeerStates::new(config.clone());
        let malicious_peer = PeerNetworkId::random();
        
        // Attacker: Create a false storage summary claiming epochs 0-1000
        // but with synced_ledger_info only at epoch 100
        let synced_ledger_info = create_ledger_info_at_epoch(100);
        let false_epoch_range = CompleteDataRange::new(0, 1000).unwrap();
        
        let malicious_summary = StorageServerSummary {
            protocol_metadata: ProtocolMetadata::default(),
            data_summary: DataSummary {
                synced_ledger_info: Some(synced_ledger_info),
                epoch_ending_ledger_infos: Some(false_epoch_range), // FALSE!
                states: None,
                transactions: None,
                transaction_outputs: None,
            },
        };
        
        // Victim: Accepts the false summary without validation
        peer_states.update_summary(malicious_peer, malicious_summary);
        
        // Calculate global summary - includes false data
        let global_summary = peer_states.calculate_global_data_summary();
        
        // Victim attempts to create stream for epochs 500-600
        let advertised_data = global_summary.advertised_data;
        
        // Check passes (incorrectly!)
        let result = AdvertisedData::contains_range(
            500, 
            600, 
            &advertised_data.epoch_ending_ledger_infos
        );
        
        assert!(result, "False advertisement causes check to pass");
        
        // But actual request to malicious peer will fail at database layer
        // when check_epoch_ending_ledger_infos_request validates:
        // end_epoch (600) > latest_epoch (100) 
        // This failure blocks state sync during retry cycles
    }
    
    fn create_ledger_info_at_epoch(epoch: u64) -> LedgerInfoWithSignatures {
        // Create minimal ledger info for testing
        // (implementation details omitted for brevity)
        unimplemented!("Test helper for PoC")
    }
}
```

**Notes:**
- The vulnerability stems from the trust-without-verify design in peer advertisement handling
- The `synced_ledger_info` contains cryptographic proof (signatures) but is not used to validate advertised ranges
- Recovery requires waiting for peer scoring to take effect (multiple request failures)
- The impact scales with the number of malicious peers in the network

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L177-179)
```rust
    fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
        self.storage_summary = Some(storage_summary);
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

**File:** state-sync/storage-service/types/src/responses.rs (L698-707)
```rust
            GetEpochEndingLedgerInfos(request) => {
                let desired_range =
                    match CompleteDataRange::new(request.start_epoch, request.expected_end_epoch) {
                        Ok(desired_range) => desired_range,
                        Err(_) => return false,
                    };
                self.epoch_ending_ledger_infos
                    .map(|range| range.superset_of(&desired_range))
                    .unwrap_or(false)
            },
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1027-1032)
```rust
        ensure!(
            end_epoch <= latest_epoch,
            "Unable to provide epoch change ledger info for still open epoch. asked upper bound: {}, last sealed epoch: {}",
            end_epoch,
            latest_epoch - 1,  // okay to -1 because genesis LedgerInfo has .next_block_epoch() == 1
        );
```

**File:** state-sync/aptos-data-client/src/client.rs (L865-866)
```rust
                self.notify_bad_response(id, peer, &request, ErrorType::NotUseful);
                Err(client_error)
```
