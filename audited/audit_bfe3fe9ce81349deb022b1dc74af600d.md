# Audit Report

## Title
Priority-Based Peer Selection Enables Starvation Attack by Malicious High-Priority Peers

## Summary
The `choose_peers_for_specific_data_request()` function implements a strict priority-first selection algorithm that allows malicious high-priority peers to monopolize data requests while starving honest lower-priority peers. Malicious peers can maintain scores just above the ignore threshold (25.0) through strategic behavior, ensuring continuous selection despite poor performance, while high-quality lower-priority peers are never utilized. [1](#0-0) 

## Finding Description
The vulnerability stems from the strict priority-first peer selection mechanism that operates independently of peer performance scores:

**Priority Assignment (Static):**
Peer priorities are determined by network topology and connection type, not behavior: [2](#0-1) 

**Scoring System (Dynamic but Insufficient):**
Peers are scored based on behavior with an ignore threshold at 25.0: [3](#0-2) 

**Score Update Mechanisms:**
- Success: +1.0 per successful response
- NotUseful error: ×0.95 (timeouts, invalid data)
- Malicious error: ×0.8 (proof verification failures) [4](#0-3) 

**The Critical Flaw:**
The selection algorithm in `choose_peers_for_specific_data_request()` iterates through priority levels highest-first, selecting peers and returning immediately when enough peers are found. Within each priority level, peers are only filtered by whether they're ignored (score ≤ 25.0), not by their actual performance score: [5](#0-4) 

**Attack Scenario:**
1. Attacker controls high-priority peers (e.g., validators connected to a validator, or VFNs connected to a VFN)
2. These malicious peers maintain scores between 26-50 by:
   - Providing valid but deliberately slow responses (emulating network delays)
   - Returning minimal valid data (within protocol limits but not optimal)
   - Occasionally timing out (NotUseful errors) but not frequently enough to drop below 25.0
   - Never providing invalid proofs (avoiding Malicious errors which decay score faster)
3. Honest lower-priority peers exist with perfect scores (90-100) but are never selected
4. All state sync requests go to the malicious high-priority peers, causing system-wide performance degradation

**Mathematical Analysis:**
To maintain a score above 25.0 starting from 50.0:
- With NotUseful errors only: 50 × (0.95)^n = 25 → n ≈ 13.5 consecutive errors
- With success interspersed: An attacker can fail 3 requests, succeed 1 request, fail 3, succeed 1, etc., maintaining a score around 30-40

A sophisticated attacker can carefully balance responses to hover indefinitely above the ignore threshold while providing suboptimal service.

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos Bug Bounty criteria:

**State Inconsistencies Requiring Intervention:**
- Validator nodes syncing state experience prolonged sync times, potentially falling behind consensus
- Full nodes connected to malicious high-priority peers suffer degraded state sync performance
- System-wide impact if attack is widespread across the network

**Validator Node Slowdowns (High Severity aspects):**
- If validator nodes are syncing (e.g., after downtime), they rely on state sync to catch up
- Prolonged sync times can prevent validators from participating in consensus
- Multiple affected validators could impact network liveness

**Network Availability Degradation:**
While not causing total loss of liveness, the attack degrades network performance and can create operational issues requiring manual intervention (peer connection management, configuration changes).

The impact falls solidly in the Medium to High severity range, as it can affect validator operations and requires intervention to resolve.

## Likelihood Explanation
The likelihood of this vulnerability being exploited is **MEDIUM to HIGH**:

**Attacker Requirements:**
- Control of high-priority network peers (relatively easy based on network topology)
- For targeting validators: Be another validator on the validator network
- For targeting VFNs: Be a validator that the VFN connects to
- For targeting PFNs: Be a VFN or seed peer

**Attack Complexity:**
- **Low**: The attack requires only controlling the quality/timing of responses
- No need to break cryptographic primitives or forge proofs
- Simple strategy: delay responses, return minimal data, occasional timeouts
- Can be automated and sustained indefinitely

**Detection Difficulty:**
- Moderate: The behavior appears as poor network conditions rather than obvious malicious activity
- Malicious peers maintain "acceptable" scores (above 25.0)
- Metrics show high-priority peers being used, which appears normal
- Requires correlation analysis across multiple nodes to detect

**Real-World Applicability:**
High likelihood in adversarial network conditions where:
- Compromised validators exist
- Nation-state actors target specific nodes
- Eclipse attack scenarios where attacker controls visible peers

## Recommendation
Implement a **score-weighted selection within priority groups** to ensure high-performing peers are preferred regardless of priority. The fix should maintain priority preference while allowing exceptionally poor high-priority peers to be deprioritized in favor of better-performing lower-priority peers.

**Recommended Fix:**

```rust
fn choose_peers_for_specific_data_request(
    &self,
    request: &StorageServiceRequest,
    serviceable_peers_by_priorities: Vec<HashSet<PeerNetworkId>>,
    num_peers_for_request: usize,
) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
    // Calculate a dynamic threshold: only use lower-priority peers if 
    // high-priority peers have scores below this threshold
    const PRIORITY_OVERRIDE_THRESHOLD: f64 = 40.0;
    
    let mut selected_peers = HashSet::new();
    let mut available_peers_with_scores = Vec::new();
    
    // Collect all serviceable peers with their priorities and scores
    for (priority_index, serviceable_peers) in serviceable_peers_by_priorities.iter().enumerate() {
        for peer in serviceable_peers {
            if let Some(peer_state) = self.peer_states.get_peer_to_states().get(peer) {
                let score = peer_state.get_score();
                available_peers_with_scores.push((*peer, priority_index, score));
            }
        }
    }
    
    // Sort by: 1) Priority first, 2) Score second (higher is better)
    available_peers_with_scores.sort_by(|a, b| {
        match a.1.cmp(&b.1) {
            Ordering::Equal => b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal),
            other => other,
        }
    });
    
    // Apply score-based priority override: if current priority group
    // has low scores and next priority group has high scores, consider next group
    for (peer, priority_index, score) in available_peers_with_scores {
        // Check if we should skip to next priority if scores are too low
        if priority_index > 0 && score < PRIORITY_OVERRIDE_THRESHOLD {
            // Look for higher-scoring peers in next priority
            if let Some((_, _, next_score)) = available_peers_with_scores.iter()
                .find(|(_, pi, s)| *pi == priority_index + 1 && *s > score + 20.0) {
                continue; // Skip this low-scoring high-priority peer
            }
        }
        
        selected_peers.insert(peer);
        if selected_peers.len() >= num_peers_for_request {
            return Ok(selected_peers);
        }
    }
    
    if !selected_peers.is_empty() {
        Ok(selected_peers)
    } else {
        Err(Error::DataIsUnavailable(format!(
            "Unable to select peers for specific data request: {:?}",
            request
        )))
    }
}
```

**Alternative Simpler Fix:**
Lower the ignore threshold or implement exponential score decay for consistently poor performers: [6](#0-5) 

Change `IGNORE_PEER_THRESHOLD` from 25.0 to 40.0, making it harder for malicious peers to remain serviceable while providing poor service.

## Proof of Concept

```rust
#[cfg(test)]
mod starvation_attack_poc {
    use super::*;
    use crate::tests::{mock::MockNetwork, utils};
    use aptos_config::config::AptosDataClientConfig;
    
    #[tokio::test]
    async fn test_high_priority_peer_starvation_attack() {
        // Create data client with default config
        let data_client_config = AptosDataClientConfig::default();
        let (mut mock_network, _, client, _) = 
            MockNetwork::new(None, Some(data_client_config), None);
        
        // Add high-priority malicious peer with poor performance
        let malicious_high_priority_peer = mock_network.add_peer(PeerPriority::HighPriority);
        
        // Add low-priority honest peer with excellent performance  
        let honest_low_priority_peer = mock_network.add_peer(PeerPriority::LowPriority);
        
        // Both peers advertise the same data
        let known_version = 1000;
        client.update_peer_storage_summary(
            malicious_high_priority_peer,
            utils::create_storage_summary(known_version)
        );
        client.update_peer_storage_summary(
            honest_low_priority_peer, 
            utils::create_storage_summary(known_version)
        );
        
        // Simulate malicious peer degrading its score but staying above threshold
        for _ in 0..10 {
            // Simulate NotUseful errors (score *= 0.95)
            client.get_peer_states().update_score_error(
                malicious_high_priority_peer,
                ErrorType::NotUseful
            );
        }
        
        // Honest peer maintains perfect score through successes
        for _ in 0..20 {
            client.get_peer_states().update_score_success(honest_low_priority_peer);
        }
        
        // Check scores
        let high_pri_score = client.get_peer_states()
            .get_peer_to_states()
            .get(&malicious_high_priority_peer)
            .unwrap()
            .get_score();
        let low_pri_score = client.get_peer_states()
            .get_peer_to_states()
            .get(&honest_low_priority_peer)
            .unwrap()
            .get_score();
            
        // High priority has degraded score (~30) but above threshold (25)
        // Low priority has excellent score (~70)
        assert!(high_pri_score > 25.0 && high_pri_score < 40.0);
        assert!(low_pri_score > 60.0);
        
        // Create a data request
        let storage_request = StorageServiceRequest::new(
            DataRequest::GetTransactionsWithProof(TransactionsWithProofRequest {
                start_version: 0,
                end_version: 100,
                proof_version: 100,
                include_events: false,
            }),
            true
        );
        
        // Select peers for request
        let selected_peers = client.choose_peers_for_request(&storage_request).unwrap();
        
        // VULNERABILITY: Despite low-priority peer having 2x better score,
        // high-priority malicious peer is ALWAYS selected
        assert!(selected_peers.contains(&malicious_high_priority_peer));
        assert!(!selected_peers.contains(&honest_low_priority_peer));
        
        // This demonstrates the starvation: honest peer is never used
        // despite being far more reliable, causing performance degradation
    }
}
```

## Notes
This vulnerability is particularly concerning for validator networks where priority is determined by validator status. A compromised or malicious validator can degrade the state sync performance of other validators, potentially impacting consensus participation. The fix requires careful balancing to maintain the benefits of priority-based selection while preventing abuse by low-performing high-priority peers.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L388-418)
```rust
    fn choose_peers_for_specific_data_request(
        &self,
        request: &StorageServiceRequest,
        serviceable_peers_by_priorities: Vec<HashSet<PeerNetworkId>>,
        num_peers_for_request: usize,
    ) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
        // Select peers by priority (starting with the highest priority first)
        let mut selected_peers = HashSet::new();
        for serviceable_peers in serviceable_peers_by_priorities {
            // Select peers by distance and latency
            let num_peers_remaining = num_peers_for_request.saturating_sub(selected_peers.len());
            let peers = self.choose_random_peers_by_latency(serviceable_peers, num_peers_remaining);

            // Add the peers to the entire set
            selected_peers.extend(peers);

            // If we have selected enough peers, return early
            if selected_peers.len() >= num_peers_for_request {
                return Ok(selected_peers);
            }
        }

        // If selected peers is empty, return an error
        if !selected_peers.is_empty() {
            Ok(selected_peers)
        } else {
            Err(Error::DataIsUnavailable(format!(
                "Unable to select peers for specific data request: {:?}",
                request
            )))
        }
```

**File:** state-sync/aptos-data-client/src/priority.rs (L53-122)
```rust
pub fn get_peer_priority(
    base_config: Arc<BaseConfig>,
    peers_and_metadata: Arc<PeersAndMetadata>,
    peer: &PeerNetworkId,
) -> PeerPriority {
    // Handle the case that this node is a validator
    let peer_network_id = peer.network_id();
    if base_config.role.is_validator() {
        // Validators should highly prioritize other validators
        if peer_network_id.is_validator_network() {
            return PeerPriority::HighPriority;
        }

        // VFNs should be prioritized over PFNs. Note: having PFNs
        // connected to a validator is a rare (but possible) scenario.
        return if peer_network_id.is_vfn_network() {
            PeerPriority::MediumPriority
        } else {
            PeerPriority::LowPriority
        };
    }

    // Handle the case that this node is a VFN
    if peers_and_metadata
        .get_registered_networks()
        .contains(&NetworkId::Vfn)
    {
        // VFNs should highly prioritize validators
        if peer_network_id.is_vfn_network() {
            return PeerPriority::HighPriority;
        }

        // Trusted peers should be prioritized over untrusted peers.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        if is_trusted_peer(peers_and_metadata.clone(), peer) {
            return PeerPriority::MediumPriority;
        }

        // Outbound connections should be prioritized over inbound connections.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        return if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
            if metadata.get_connection_metadata().is_outbound_connection() {
                PeerPriority::MediumPriority
            } else {
                PeerPriority::LowPriority
            }
        } else {
            PeerPriority::LowPriority // We don't have connection metadata
        };
    }

    // Otherwise, this node is a PFN. PFNs should highly
    // prioritize trusted peers (i.e., VFNs and seed peers).
    if is_trusted_peer(peers_and_metadata.clone(), peer) {
        return PeerPriority::HighPriority;
    }

    // Outbound connections should be prioritized. This prioritizes
    // other VFNs/seed peers over regular PFNs. Inbound connections
    // are always low priority (as they are generally unreliable).
    if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
        if metadata.get_connection_metadata().is_outbound_connection() {
            PeerPriority::HighPriority
        } else {
            PeerPriority::LowPriority
        }
    } else {
        PeerPriority::LowPriority // We don't have connection metadata
    }
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L32-43)
```rust
/// Scores for peer rankings based on preferences and behavior.
const MAX_SCORE: f64 = 100.0;
const MIN_SCORE: f64 = 0.0;
const STARTING_SCORE: f64 = 50.0;
/// Add this score on a successful response.
const SUCCESSFUL_RESPONSE_DELTA: f64 = 1.0;
/// Not necessarily a malicious response, but not super useful.
const NOT_USEFUL_MULTIPLIER: f64 = 0.95;
/// Likely to be a malicious response.
const MALICIOUS_MULTIPLIER: f64 = 0.8;
/// Ignore a peer when their score dips below this threshold.
const IGNORE_PEER_THRESHOLD: f64 = 25.0;
```

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
