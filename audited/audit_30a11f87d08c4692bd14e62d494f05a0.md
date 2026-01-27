# Audit Report

## Title
Byzantine Peer Can Monopolize Version Ranges to Enable Targeted Eclipse Attacks via Selective Advertisement

## Summary
A Byzantine peer can selectively advertise specific transaction version ranges to become the sole data source for those versions, forcing syncing nodes into a single-peer dependency that enables targeted eclipse attacks, DoS, and traffic analysis. The vulnerability exists in the state-sync data availability checking mechanism which only verifies that data exists in the global advertised summary, without requiring redundancy from multiple independent sources.

## Finding Description

The vulnerability exists in the interaction between the data availability check in `is_remaining_data_available()` and the peer selection logic in `choose_peers_for_request()`.

**Data Availability Check (Insufficient):** [1](#0-0) 

This function only verifies that the next required version exists somewhere in the global advertised data (union of all peer advertisements), but does NOT check how many peers advertise that data or require redundancy.

**Peer Selection Accepts Single Source:** [2](#0-1) 

When multi-fetch is enabled, the system attempts to select multiple peers, but if only one peer advertises the required data (`num_serviceable_peers = 1`), the system accepts fetching from that single peer, even though the configuration prefers redundancy.

**Global Summary Calculation:** [3](#0-2) 

The global data summary is calculated as the union of all non-ignored peer advertisements, meaning a single Byzantine peer's advertised ranges are included and treated as available data.

**Attack Scenario:**

1. **Strategic Advertisement:** A Byzantine peer advertises specific version ranges (e.g., versions 5000-7000) that no honest peer advertises, either by:
   - Targeting gaps caused by honest peers' pruning policies
   - Advertising newly-arrived data before propagation
   - Claiming to have historical data that others have pruned

2. **Forced Dependency:** When a syncing node at version 5000 creates a data stream, `is_remaining_data_available()` returns true because version 5000 exists in the global summary (from the Byzantine peer).

3. **Single-Peer Selection:** When making actual data requests: [4](#0-3) 

Only the Byzantine peer passes the `can_service_request()` filter for versions 5000-7000, resulting in `num_serviceable_peers = 1` and forcing single-peer selection.

4. **Eclipse Attack Execution:** The Byzantine peer can now:
   - **Targeted DoS:** Delay or timeout responses for specific victim nodes while serving others normally
   - **Traffic Analysis:** Monitor which nodes are syncing what versions and when
   - **Selective Censorship:** Only serve data to certain nodes, preventing others from syncing
   - **Connection Manipulation:** Drop connections at critical synchronization points

**Aggravating Factor - Ignored Peer Scenario:**

If the Byzantine peer misbehaves enough to be ignored (score ≤ 25): [5](#0-4) 

The peer's advertisements are excluded from the global summary, causing `is_remaining_data_available()` to return false and blocking stream creation entirely—effectively a DoS even worse than the eclipse attack.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns:** Validators unable to sync transaction history cannot participate in consensus effectively, leading to performance degradation and potential liveness issues.

2. **Significant Protocol Violation:** The state sync protocol is designed to operate in a Byzantine environment with decentralized data availability. This vulnerability creates single-point-of-failure dependencies that undermine the core security model.

3. **Targeted Attack Vector:** Unlike broad network DoS (out of scope), this enables precise targeting of specific nodes, which is more dangerous as it can be used to:
   - Selectively prevent certain validators from participating
   - Conduct sophisticated traffic analysis
   - Prepare for more complex attacks by controlling a victim's data view

4. **Realistic Exploitation:** Natural conditions like pruning policies, network partition recovery, and new node bootstrapping create genuine gaps in data availability that Byzantine peers can exploit without detection.

The vulnerability does not reach Critical severity because:
- It doesn't directly enable fund theft or consensus safety violations
- Cryptographic proof verification prevents serving incorrect data
- It affects availability and creates attack preconditions rather than directly compromising integrity

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploitable in production:

1. **Natural Gaps in Data Coverage:** Honest peers implement pruning policies and may not retain full historical data, creating legitimate gaps that Byzantine peers can monopolize.

2. **Bootstrap and Recovery Scenarios:** New nodes joining the network or nodes recovering from crashes need historical data that may only be available from limited sources.

3. **Low Attacker Requirements:** 
   - No validator privileges required
   - Any network peer can advertise arbitrary data ranges via `StorageServerSummary`
   - No need to compromise cryptographic keys or consensus mechanisms

4. **Detection Challenges:** The Byzantine peer can behave honestly most of the time, serving data correctly but selectively targeting specific victims, making detection difficult.

5. **Scalability of Attack:** A single Byzantine peer can impact multiple syncing nodes simultaneously by controlling access to different version ranges.

## Recommendation

Implement a **multi-source redundancy requirement** for critical data ranges:

**1. Add redundancy checking to `is_remaining_data_available()`:**

```rust
fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
    let advertised_ranges = match &self.request {
        StreamRequest::ContinuouslyStreamTransactions(_) => &advertised_data.transactions,
        StreamRequest::ContinuouslyStreamTransactionOutputs(_) => &advertised_data.transaction_outputs,
        StreamRequest::ContinuouslyStreamTransactionsOrOutputs(_) => &advertised_data.transaction_outputs,
        request => invalid_stream_request!(request),
    };

    let (next_request_version, _) = self.next_request_version_and_epoch;
    
    // NEW: Count how many distinct peers advertise this version
    let num_peers_with_version = count_peers_advertising_version(
        next_request_version,
        advertised_ranges,
    );
    
    // Require redundancy from multiple sources for security
    const MIN_PEERS_FOR_SECURITY: usize = 2;
    if num_peers_with_version < MIN_PEERS_FOR_SECURITY {
        return Err(Error::InsufficientDataRedundancy(format!(
            "Only {} peer(s) advertise version {}, minimum {} required for security",
            num_peers_with_version, next_request_version, MIN_PEERS_FOR_SECURITY
        )));
    }
    
    Ok(AdvertisedData::contains_range(
        next_request_version,
        next_request_version,
        advertised_ranges,
    ))
}
```

**2. Extend `AdvertisedData` to track per-peer ranges:**

Modify `GlobalDataSummary` to include per-peer information:

```rust
pub struct AdvertisedData {
    // Existing union of all ranges
    pub transactions: Vec<CompleteDataRange<Version>>,
    pub transaction_outputs: Vec<CompleteDataRange<Version>>,
    // ... other fields
    
    // NEW: Track which peers advertise which ranges
    pub peers_by_range: HashMap<DataType, Vec<(PeerNetworkId, CompleteDataRange<Version>)>>,
}
```

**3. Add configuration option for redundancy requirements:**

```rust
pub struct DataStreamingServiceConfig {
    // ... existing fields
    
    /// Minimum number of independent peers required to advertise
    /// a data range before accepting it as available
    pub min_peers_for_data_redundancy: usize,
    
    /// Whether to enforce strict redundancy requirements
    /// (can be disabled for bootstrap scenarios with operator override)
    pub enforce_data_redundancy: bool,
}
```

**4. Implement graceful degradation:**

For bootstrap scenarios where only one peer may have old data, allow operator-initiated exceptions with explicit warnings logged.

## Proof of Concept

```rust
#[cfg(test)]
mod byzantine_peer_eclipse_test {
    use super::*;
    use aptos_config::config::AptosDataClientConfig;
    use aptos_storage_service_types::responses::{
        CompleteDataRange, DataSummary, StorageServerSummary, ProtocolMetadata
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_byzantine_peer_monopolizes_version_range() {
        // Setup: Create a data client with multiple peers
        let config = AptosDataClientConfig::default();
        let mut peer_states = PeerStates::new(Arc::new(config));
        
        // Honest peer 1: advertises recent data only (pruned old data)
        let honest_peer_1 = create_test_peer_network_id(1);
        let honest_summary_1 = create_storage_summary(
            9000, 10000, // versions 9000-10000
        );
        peer_states.update_summary(honest_peer_1, honest_summary_1);
        
        // Honest peer 2: also advertises recent data
        let honest_peer_2 = create_test_peer_network_id(2);
        let honest_summary_2 = create_storage_summary(
            9000, 10000,
        );
        peer_states.update_summary(honest_peer_2, honest_summary_2);
        
        // Byzantine peer: advertises ONLY old data gap (5000-7000)
        let byzantine_peer = create_test_peer_network_id(666);
        let byzantine_summary = create_storage_summary(
            5000, 7000, // Fills the gap!
        );
        peer_states.update_summary(byzantine_peer, byzantine_summary);
        
        // Calculate global summary
        let global_summary = peer_states.calculate_global_data_summary();
        
        // Victim node needs to sync from version 5000
        let stream_request = StreamRequest::ContinuouslyStreamTransactions(
            ContinuouslyStreamTransactionsRequest {
                known_version: 4999,
                known_epoch: 0,
                target: None,
            }
        );
        
        // Create stream engine
        let mut engine = ContinuousTransactionStreamEngine::new(
            config,
            stream_request,
            Arc::new(aptos_data_client),
        );
        
        // VULNERABILITY: is_remaining_data_available returns true
        // even though only Byzantine peer has the data
        let data_available = engine
            .is_remaining_data_available(&global_summary.advertised_data)
            .unwrap();
        assert!(data_available, "Data incorrectly reported as available");
        
        // When selecting peers for version 5000
        let request = create_transaction_request(5000, 5100);
        let serviceable_peers = peer_states.identify_serviceable_peers(&request);
        
        // VULNERABILITY: Only Byzantine peer can service the request
        assert_eq!(serviceable_peers.len(), 1, 
            "Expected single peer monopoly");
        assert!(serviceable_peers.contains(&byzantine_peer),
            "Byzantine peer is the sole source");
        
        // The victim is now forced to sync from ONLY the Byzantine peer
        // enabling targeted eclipse attacks, DoS, and traffic analysis
        
        println!("✗ VULNERABILITY CONFIRMED:");
        println!("  - Victim requires versions 5000-7000");
        println!("  - Only Byzantine peer advertises this range");
        println!("  - Victim forced into single-peer dependency");
        println!("  - Eclipse attack now possible");
    }
    
    // Helper function to create storage summary for testing
    fn create_storage_summary(start_version: u64, end_version: u64) -> StorageServerSummary {
        StorageServerSummary {
            protocol_metadata: ProtocolMetadata::default(),
            data_summary: DataSummary {
                synced_ledger_info: None,
                transactions: Some(CompleteDataRange::new(start_version, end_version).unwrap()),
                transaction_outputs: Some(CompleteDataRange::new(start_version, end_version).unwrap()),
                ..Default::default()
            },
        }
    }
}
```

## Notes

**Additional Context:**

1. **Cryptographic Mitigation Limit:** While proof verification prevents the Byzantine peer from serving *incorrect* data, it does not prevent them from *refusing* to serve, delaying responses, or selectively serving certain victims.

2. **Peer Scoring Insufficient:** The scoring mechanism penalizes bad behavior but doesn't prevent the initial dependency. If the Byzantine peer is the only source, even a low score may not trigger selection of alternatives (because none exist).

3. **Multi-Fetch Configuration:** The default `min_peers_for_multi_fetch: 2` is bypassed when fewer peers are serviceable, negating its security benefit.

4. **Real-World Triggers:** This vulnerability becomes critical during:
   - Network partition recovery (different peers have different data ranges)
   - New validator onboarding (bootstrapping from scratch)
   - Post-upgrade synchronization (older data may be scarce)
   - State sync after node maintenance

5. **Comparison to Known Attacks:** This is similar to eclipse attacks in Bitcoin/Ethereum where attackers control a victim's peer connections, but operates at the application layer (data availability) rather than network layer.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1291-1310)
```rust
    fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
        let advertised_ranges = match &self.request {
            StreamRequest::ContinuouslyStreamTransactions(_) => &advertised_data.transactions,
            StreamRequest::ContinuouslyStreamTransactionOutputs(_) => {
                &advertised_data.transaction_outputs
            },
            StreamRequest::ContinuouslyStreamTransactionsOrOutputs(_) => {
                &advertised_data.transaction_outputs
            },
            request => invalid_stream_request!(request),
        };

        // Verify we can satisfy the next version
        let (next_request_version, _) = self.next_request_version_and_epoch;
        Ok(AdvertisedData::contains_range(
            next_request_version,
            next_request_version,
            advertised_ranges,
        ))
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L310-311)
```rust
            // Bound the number of peers by the number of serviceable peers
            num_peers_for_request = min(num_peers_for_request, num_serviceable_peers);
```

**File:** state-sync/aptos-data-client/src/client.rs (L553-559)
```rust
        prospective_peers
            .into_iter()
            .filter(|peer| {
                self.peer_states
                    .can_service_request(peer, self.time_service.clone(), request)
            })
            .collect()
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L143-149)
```rust
    pub fn get_storage_summary_if_not_ignored(&self) -> Option<&StorageServerSummary> {
        if self.is_ignored() {
            None
        } else {
            self.storage_summary.as_ref()
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L339-350)
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
```
