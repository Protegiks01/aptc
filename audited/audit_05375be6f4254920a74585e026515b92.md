# Audit Report

## Title
Missing Data Range Consistency Validation in Peer Storage Summaries Enables State Sync Disruption

## Summary
The `update_summary()` function in `peer_states.rs` accepts and stores peer-advertised data ranges without validating their consistency with the peer's `synced_ledger_info`. Malicious peers can advertise data ranges (transactions, states, outputs) that far exceed their provable committed version, causing nodes to waste network resources requesting unavailable data and significantly slowing down state synchronization.

## Finding Description

When a node receives a `StorageServerSummary` from a peer during the data summary polling process, the ranges advertised in `DataSummary` are stored without validation in the `update_summary()` function. [1](#0-0) 

The function directly stores the received summary without checking whether the advertised data ranges are logically consistent with the peer's `synced_ledger_info`. The `DataSummary` structure contains: [2](#0-1) 

A critical invariant is that all advertised data ranges must be bounded by the `synced_ledger_info.version()`, since this represents the highest version for which the peer can provide cryptographic proof. However, this invariant is not enforced.

**Attack Scenario:**

1. A malicious peer sends a `StorageServerSummary` where:
   - `synced_ledger_info` is at version 100 (with valid signatures)
   - `transactions` range claims (0, 10000)
   - `states` range claims (0, 10000)
   - `transaction_outputs` range claims (0, 10000)

2. The node receives this in the polling loop: [3](#0-2) 

3. These inflated ranges are aggregated into the global data summary: [4](#0-3) 

4. Other nodes believe data at versions 101-10000 is available from this peer and send requests that will fail, wasting network bandwidth and time until the peer's score drops below the ignore threshold: [5](#0-4) 

The vulnerability is that **proactive validation is missing**, forcing the system to rely on reactive scoring penalties. During the period before a malicious peer is penalized, significant resources are wasted. If multiple coordinated malicious peers advertise false ranges, the disruption is amplified.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:

- **Validator node slowdowns**: State synchronization can be significantly delayed when nodes waste time requesting unavailable data from malicious peers advertising inflated ranges
- **Network resource exhaustion**: Bandwidth and CPU cycles wasted on invalid requests
- **Coordination attack amplification**: Multiple malicious peers can coordinate to pollute the global data summary before being penalized

While the peer scoring system eventually mitigates individual malicious peers, the lack of upfront validation means resources are wasted during initial interactions, and coordinated attacks can sustain disruption longer. This directly impacts network availability and node operational efficiency.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Ease of exploitation**: Any network peer can send malicious storage summaries; no special privileges required
- **Attack complexity**: Low - simply craft a `StorageServerSummary` with inflated ranges
- **Detection resistance**: The attack appears as legitimate peer data until requests fail
- **Amplification potential**: Multiple coordinated malicious peers increase impact
- **Economic incentive**: Attackers can slow down competitor validators or disrupt the network

The attack is straightforward to execute and can cause measurable harm before reactive defenses activate.

## Recommendation

Add proactive validation in the `update_summary()` or `update_storage_summary()` functions to verify that all advertised data ranges are consistent with the `synced_ledger_info` version:

```rust
fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
    // Validate range consistency with synced_ledger_info
    if let Some(synced_ledger_info) = storage_summary.data_summary.synced_ledger_info.as_ref() {
        let synced_version = synced_ledger_info.ledger_info().version();
        let synced_epoch = synced_ledger_info.ledger_info().epoch();
        
        // Validate transactions range
        if let Some(txn_range) = storage_summary.data_summary.transactions {
            if txn_range.highest() > synced_version {
                warn!("Peer advertised transaction range exceeding synced version");
                return; // Reject invalid summary
            }
        }
        
        // Validate transaction_outputs range
        if let Some(output_range) = storage_summary.data_summary.transaction_outputs {
            if output_range.highest() > synced_version {
                warn!("Peer advertised output range exceeding synced version");
                return;
            }
        }
        
        // Validate states range
        if let Some(state_range) = storage_summary.data_summary.states {
            if state_range.highest() > synced_version {
                warn!("Peer advertised state range exceeding synced version");
                return;
            }
        }
        
        // Validate epoch_ending_ledger_infos range
        if let Some(epoch_range) = storage_summary.data_summary.epoch_ending_ledger_infos {
            let max_epoch = if synced_ledger_info.ledger_info().ends_epoch() {
                synced_epoch
            } else if synced_epoch > 0 {
                synced_epoch - 1
            } else {
                return; // No epoch endings yet
            };
            
            if epoch_range.highest() > max_epoch {
                warn!("Peer advertised epoch range exceeding synced epoch");
                return;
            }
        }
    }
    
    self.storage_summary = Some(storage_summary);
}
```

Additionally, penalize peers that submit invalid summaries to discourage repeated attacks.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_config::config::AptosDataClientConfig;
    use aptos_storage_service_types::responses::{
        CompleteDataRange, DataSummary, ProtocolMetadata, StorageServerSummary,
    };
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };
    use aptos_crypto::hash::HashValue;
    use std::sync::Arc;

    #[test]
    fn test_inconsistent_data_ranges_accepted() {
        // Create peer states
        let config = Arc::new(AptosDataClientConfig::default());
        let peer_states = PeerStates::new(config.clone());
        let peer = PeerNetworkId::random();

        // Create a synced_ledger_info at version 100
        let ledger_info = LedgerInfo::new(
            BlockInfo::new(0, 0, HashValue::zero(), HashValue::zero(), 100, 0, None),
            HashValue::zero(),
        );
        let synced_ledger_info = LedgerInfoWithSignatures::new(
            ledger_info,
            AggregateSignature::empty(),
        );

        // Create malicious data summary with ranges exceeding synced version
        let malicious_summary = StorageServerSummary {
            protocol_metadata: ProtocolMetadata::default(),
            data_summary: DataSummary {
                synced_ledger_info: Some(synced_ledger_info),
                epoch_ending_ledger_infos: Some(CompleteDataRange::new(0, 50).unwrap()),
                states: Some(CompleteDataRange::new(0, 10000).unwrap()), // WAY beyond version 100!
                transactions: Some(CompleteDataRange::new(0, 10000).unwrap()), // WAY beyond version 100!
                transaction_outputs: Some(CompleteDataRange::new(0, 10000).unwrap()), // WAY beyond version 100!
            },
        };

        // This should reject the summary but currently accepts it
        peer_states.update_summary(peer, malicious_summary.clone());

        // Verify the inconsistent summary was stored (demonstrating the vulnerability)
        let stored_summary = peer_states
            .peer_to_state
            .get(&peer)
            .unwrap()
            .get_storage_summary()
            .unwrap();
            
        assert_eq!(stored_summary.data_summary.transactions.unwrap().highest(), 10000);
        assert_eq!(stored_summary.data_summary.synced_ledger_info.unwrap().ledger_info().version(), 100);
        
        // This demonstrates that ranges far exceeding synced_ledger_info are accepted
        println!("VULNERABILITY: Accepted transaction range (0, 10000) despite synced_ledger_info at version 100");
    }
}
```

This test demonstrates that the system accepts and stores data summaries where advertised ranges exceed the provable committed version, enabling the attack described above.

## Notes

The vulnerability exists because the code prioritizes availability (accepting peer summaries quickly) over correctness (validating consistency). While the reactive peer scoring system provides some mitigation, proactive validation is essential to prevent resource waste and maintain network efficiency during state synchronization. The fix is straightforward and should be implemented in the storage summary update path.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L152-160)
```rust
    fn is_ignored(&self) -> bool {
        // Only ignore peers if the config allows it
        if !self.data_client_config.ignore_low_score_peers {
            return false;
        }

        // Otherwise, ignore peers with a low score
        self.score <= IGNORE_PEER_THRESHOLD
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L363-386)
```rust
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
```

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

**File:** state-sync/aptos-data-client/src/poller.rs (L410-439)
```rust
        // Fetch the storage summary for the peer and stop the timer
        let request_timeout = data_summary_poller.data_client_config.response_timeout_ms;
        let result: crate::error::Result<StorageServerSummary> = data_summary_poller
            .data_client
            .send_request_to_peer_and_decode(peer, storage_request, request_timeout)
            .await
            .map(Response::into_payload);

        // Mark the in-flight poll as now complete
        data_summary_poller.in_flight_request_complete(&peer);

        // Check the storage summary response
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
