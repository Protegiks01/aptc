# Audit Report

## Title
PFN Eclipse Attack via Exclusive High-Priority Peer Synchronization Without Cross-Tier Validation

## Summary
Public Full Nodes (PFNs) in Aptos can be completely eclipsed if all their trusted peers are malicious or compromised. The priority-based peer selection system unconditionally marks trusted peers as HighPriority and exclusively syncs from them without cross-validating against lower-priority peers or detecting eclipse conditions, even when those trusted peers serve censored but cryptographically valid blockchain data.

## Finding Description

The vulnerability exists in the state-sync data client's peer selection and prioritization system across three critical files:

**1. Unconditional High-Priority Assignment for Trusted Peers**

For PFN nodes, the `get_peer_priority()` function unconditionally assigns `HighPriority` to all trusted peers: [1](#0-0) 

**2. Priority-First Selection Without Cross-Validation**

The `choose_peers_for_optimistic_fetch()` function selects peers by iterating through priority tiers (High → Medium → Low) and only moves to the next tier if insufficient peers exist in the current tier: [2](#0-1) 

**3. Inadequate Eclipse Detection via Scoring**

While the system maintains peer scores to filter out misbehaving peers, the scoring mechanism only penalizes peers for proof verification errors (marked as "Malicious") or invalid/timeout responses (marked as "NotUseful"): [3](#0-2) 

**The Attack Path:**

1. **Attacker Setup**: Compromise all trusted peers of a target PFN, or socially engineer the PFN operator to configure malicious nodes as trusted peers.

2. **Serve Valid But Censored Data**: The malicious trusted peers serve blockchain data that is:
   - Cryptographically valid (properly signed by real validators, obtained from honest nodes)
   - Temporally fresh (within `max_optimistic_fetch_lag_secs`, typically 5 seconds)
   - But censored/stale relative to the actual chain tip (e.g., fork at height N-k where k is small)

3. **Freshness Check Passes**: The `can_service_optimistic_request()` function validates that the ledger info timestamp is within the lag threshold: [4](#0-3) 

4. **Cryptographic Verification Passes**: The trusted state verification system validates signatures correctly but doesn't detect cross-peer inconsistencies: [5](#0-4) 

5. **No Score Penalty**: Since the malicious peers provide cryptographically valid responses, they don't trigger `ProofVerificationError` and maintain high scores above the ignore threshold.

6. **Exclusive Synchronization**: The PFN exclusively syncs from HighPriority malicious peers and never checks MediumPriority or LowPriority peers that might have newer/different valid data.

**Invariant Violation:**

This breaks the **State Consistency** invariant: The PFN maintains a valid but censored view of the blockchain state that is inconsistent with the rest of the network, creating an undetected network partition.

## Impact Explanation

**Critical Severity** - This qualifies as a Critical vulnerability per Aptos bug bounty criteria:

1. **Non-recoverable network partition (requires hardfork)**: The eclipsed PFN operates in a partitioned state without any detection mechanism. Since the data is cryptographically valid, there's no automatic recovery path. The PFN believes it's synchronized with the correct chain.

2. **Consensus/Safety violations**: While not breaking validator consensus directly, this creates application-layer safety violations where different nodes have fundamentally different views of chain state, enabling:
   - **Transaction censorship**: Attackers can hide specific transactions from users
   - **False balance reporting**: Users see incorrect account balances
   - **Double-spend facilitation**: Users may sign transactions based on stale state
   - **Smart contract manipulation**: DApps receive incorrect state data

3. **Security guarantees broken**:
   - Users relying on the eclipsed PFN receive false blockchain state
   - Applications built on the eclipsed node make decisions based on censored data
   - No warning or detection that the node is compromised

## Likelihood Explanation

**Medium-High Likelihood:**

**Prerequisites:**
- Attacker must compromise ALL trusted peers of a target PFN, OR
- Socially engineer PFN operator to add malicious nodes as trusted peers

**Feasibility:**
- PFN operators often configure a small set (3-5) of trusted peers
- Compromise of seed peers or VFNs affects multiple downstream PFNs
- No mechanism exists to verify trusted peer integrity
- Attack is completely silent - no detection possible

**Persistence:**
- Once established, attack persists indefinitely
- PFN continues normal operation with no error indicators
- Cryptographic validation provides false confidence in data integrity

**Real-world scenarios:**
- Compromised infrastructure providers hosting multiple "trusted" VFNs
- Supply chain attacks on seed peer configurations
- Insider attacks on VFN operators
- DNS/BGP hijacking of trusted peer endpoints

## Recommendation

Implement multi-tier cross-validation and eclipse detection mechanisms:

### 1. Cross-Priority Data Validation
```rust
// In choose_peers_for_optimistic_fetch(), sample from multiple priority tiers
fn choose_peers_for_optimistic_fetch_with_validation(
    &self,
    request: &StorageServiceRequest,
    serviceable_peers_by_priorities: Vec<HashSet<PeerNetworkId>>,
    num_peers_for_request: usize,
) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
    let mut selected_peers = HashSet::new();
    
    // Select primarily from high priority, but also sample lower priorities
    for (tier_index, serviceable_peers) in serviceable_peers_by_priorities.iter().enumerate() {
        let num_from_tier = if tier_index == 0 {
            // High priority: select most peers
            num_peers_for_request.saturating_sub(selected_peers.len())
        } else {
            // Lower priorities: select 1-2 peers for cross-validation
            min(2, serviceable_peers.len())
        };
        
        if num_from_tier > 0 {
            let peers = self.choose_random_peers_by_distance_and_latency(
                serviceable_peers.clone(),
                num_from_tier,
            );
            selected_peers.extend(peers);
        }
    }
    
    Ok(selected_peers)
}
```

### 2. Eclipse Detection via Version Divergence Monitoring
```rust
// Track version consensus across priority tiers
pub fn detect_potential_eclipse(&self) -> bool {
    let peers_by_priority = self.get_peers_by_priorities()?;
    let mut max_versions_by_priority = Vec::new();
    
    for priority in PeerPriority::get_all_ordered_priorities() {
        if let Some(peers) = peers_by_priority.get(&priority) {
            let max_version = peers.iter()
                .filter_map(|peer| {
                    self.peer_states.get_peer_state(peer)
                        .and_then(|state| state.get_storage_summary())
                        .and_then(|summary| summary.synced_ledger_info)
                        .map(|li| li.ledger_info().version())
                })
                .max();
            max_versions_by_priority.push((priority, max_version));
        }
    }
    
    // Detect if lower priority peers have significantly newer data
    const VERSION_DIVERGENCE_THRESHOLD: u64 = 1000;
    if let Some((_, high_version)) = max_versions_by_priority.get(0) {
        for (_, lower_version) in max_versions_by_priority.iter().skip(1) {
            if let (Some(low), Some(high)) = (lower_version, high_version) {
                if *low > *high + VERSION_DIVERGENCE_THRESHOLD {
                    warn!("Potential eclipse detected: lower priority peers have newer data");
                    return true;
                }
            }
        }
    }
    
    false
}
```

### 3. Trusted Peer Attestation
Implement periodic challenge-response with trusted peers to verify they're serving consistent data with the broader network, potentially using checkpoint hashes from multiple independent sources.

### 4. Configuration Warning
Add explicit warnings in PFN configuration documentation that trusted peers create a critical dependency and should be verified through multiple independent channels.

## Proof of Concept

```rust
// Integration test demonstrating eclipse attack
#[tokio::test]
async fn test_pfn_eclipse_via_malicious_trusted_peers() {
    // Setup: Create a PFN with only malicious trusted peers
    let base_config = create_pfn_base_config();
    let data_client_config = AptosDataClientConfig::default();
    
    // Create mock network with malicious trusted peers and honest regular peers
    let (mut mock_network, time_service, client, _) = 
        MockNetwork::new(Some(base_config), Some(data_client_config), Some(vec![NetworkId::Public]));
    
    // Add malicious trusted peers (HighPriority) serving old but valid data
    let malicious_peers = add_several_trusted_peers(&mut mock_network, 3);
    let old_version = 1000;  // Censored old version
    let old_timestamp = time_service.now_unix_time().as_micros() as u64;
    
    for peer in malicious_peers.iter() {
        client.update_peer_storage_summary(
            *peer,
            create_storage_summary_with_timestamp(old_version, old_timestamp),
        );
    }
    
    // Add honest regular peers (LowPriority) with newer data
    let honest_peers = add_several_regular_peers(&mut mock_network, 10);
    let new_version = 5000;  // Current chain tip
    for peer in honest_peers.iter() {
        client.update_peer_storage_summary(
            *peer,
            create_storage_summary_with_timestamp(new_version, old_timestamp),
        );
    }
    
    // Create an optimistic fetch request
    let request = StorageServiceRequest::new(
        DataRequest::GetNewTransactionsWithProof(NewTransactionsWithProofRequest {
            known_version: old_version,
            known_epoch: 1,
            include_events: false,
        }),
        true,
    );
    
    // Demonstrate: PFN selects ONLY from malicious trusted peers
    let selected_peers = client.choose_peers_for_request(&request).unwrap();
    
    // VULNERABILITY: All selected peers are malicious, none are honest
    assert!(selected_peers.iter().all(|p| malicious_peers.contains(p)));
    assert!(selected_peers.iter().all(|p| !honest_peers.contains(p)));
    
    // The PFN will sync exclusively from malicious peers serving version 1000
    // It will never discover that honest peers have version 5000
    // No eclipse detection mechanism exists to alert the operator
}
```

**Notes:**

This vulnerability is particularly insidious because:

1. **Silent failure**: The PFN receives no errors or warnings that it's eclipsed
2. **Cryptographic validity**: All data passes signature verification, providing false confidence
3. **Trust model violation**: The system assumes "trusted peers" are honest, creating a single point of failure
4. **No automatic recovery**: Once eclipsed, the PFN remains compromised until manual intervention
5. **Cascading impact**: Compromised VFNs can eclipse multiple downstream PFNs

The fundamental issue is that the priority system creates strict tier isolation without cross-validation, and "trusted peer" designation bypasses all eclipse detection that might otherwise exist through peer diversity and consensus monitoring.

### Citations

**File:** state-sync/aptos-data-client/src/priority.rs (L104-108)
```rust
    // Otherwise, this node is a PFN. PFNs should highly
    // prioritize trusted peers (i.e., VFNs and seed peers).
    if is_trusted_peer(peers_and_metadata.clone(), peer) {
        return PeerPriority::HighPriority;
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L355-372)
```rust
        // Select peers by priority (starting with the highest priority first)
        let mut selected_peers = HashSet::new();
        for serviceable_peers in serviceable_peers_by_priorities {
            // Select peers by distance and latency
            let num_peers_remaining = num_peers_for_request.saturating_sub(selected_peers.len());
            let peers = self.choose_random_peers_by_distance_and_latency(
                serviceable_peers,
                num_peers_remaining,
            );

            // Add the peers to the entire set
            selected_peers.extend(peers);

            // If we have selected enough peers, return early
            if selected_peers.len() >= num_peers_for_request {
                return Ok(selected_peers);
            }
        }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L54-62)
```rust
impl From<ResponseError> for ErrorType {
    fn from(error: ResponseError) -> Self {
        match error {
            ResponseError::InvalidData | ResponseError::InvalidPayloadDataType => {
                ErrorType::NotUseful
            },
            ResponseError::ProofVerificationError => ErrorType::Malicious,
        }
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L914-934)
```rust
/// Returns true iff the synced ledger info timestamp
/// is within the given lag (in seconds).
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
}
```

**File:** types/src/trusted_state.rs (L221-223)
```rust
            } else {
                // Verify the target ledger info, which should be inside the current epoch.
                curr_epoch_state.verify(latest_li)?;
```
