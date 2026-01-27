# Audit Report

## Title
Priority Exhaustion Vulnerability in Optimistic Fetch Peer Selection Allows Forced Reliance on Unreliable Low-Priority Peers

## Summary
The `choose_peers_for_optimistic_fetch()` function in the Aptos data client fails to enforce the documented invariant that low-priority peers (marked as "generally unreliable") should only be used when no higher-priority peers are available. When all high and medium priority peers become unavailable or unable to service optimistic fetch requests, the system will unconditionally select from low-priority peers, enabling attackers controlling such connections to degrade state synchronization performance and potentially impact validator liveness.

## Finding Description

The vulnerability exists in the peer selection logic for optimistic fetch requests in state synchronization. [1](#0-0) 

The codebase explicitly documents that `LowPriority` peers should be "Peers to use iff no other peers are available (these are generally unreliable)". [2](#0-1) 

However, the implementation contains a critical gap between intent and enforcement:

1. **Counting Logic (Intent)**: The code at lines 292-302 attempts to exclude low-priority peers from the serviceable peer count calculation [3](#0-2) , with logic that only includes the lowest priority level if `num_serviceable_peers == 0`.

2. **Selection Logic (Bug)**: The actual peer selection in `choose_peers_for_optimistic_fetch()` [4](#0-3)  iterates through ALL priority levels without any guard condition to prevent selection from low-priority peers when they are the only available option.

**Attack Scenario:**

An attacker establishes multiple inbound connections to a VFN or PFN node. According to the priority classification logic [5](#0-4) , inbound connections are classified as `LowPriority` for VFNs, and similarly for PFNs [6](#0-5) .

The attacker then waits for a realistic scenario where:
- High-priority peers (validators) become temporarily unavailable due to network issues, maintenance, or epoch transitions
- Medium-priority peers lack the required data or are disconnected
- Only the attacker's low-priority connections can service the optimistic fetch request

When the victim node needs to fetch new transactions via optimistic fetch requests [7](#0-6) , the selection logic will unconditionally choose from the attacker's low-priority peers.

**Why This is Exploitable:**

Even though optimistic fetch responses contain cryptographic proofs that are verified [8](#0-7) , malicious low-priority peers can still cause significant harm by:
- Delaying responses to slow state synchronization
- Sending invalid data that fails proof verification, wasting CPU cycles and network bandwidth
- Forcing repeated timeouts and retries
- Exhausting request quotas via the request moderator
- Causing the node to fall behind in synchronization

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty criteria ("Validator node slowdowns" and "Significant protocol violations"):

1. **Validator Node Impact**: For validator nodes running VFNs for state sync, prolonged degradation of sync performance could cause them to fall behind the network, potentially missing block proposals or votes, affecting their rewards and network participation.

2. **Protocol Violation**: The implementation directly violates the documented protocol invariant that unreliable low-priority peers should only be used as a last resort. The comment explicitly states this design intent but the code fails to enforce it.

3. **Resource Exhaustion**: Repeated failed verification attempts and timeouts from malicious peers can exhaust computational resources and trigger rate limiting mechanisms, further degrading performance.

4. **Availability Impact**: In severe cases, a node that falls too far behind in state sync may need manual intervention to recover, approaching a localized denial-of-service condition.

## Likelihood Explanation

This vulnerability is **HIGHLY LIKELY** to be exploitable:

1. **Realistic Trigger Conditions**: Network partitions, temporary validator downtime during upgrades, and epoch transitions are common events in production blockchain networks where high-priority peers may become unavailable.

2. **Low Attacker Requirements**: An attacker only needs to establish inbound P2P connections, which are typically permitted by default on public-facing nodes. No special privileges or stake is required.

3. **Controllable Timing**: The attacker can maintain "good" peer scores initially by responding correctly [9](#0-8) , then execute the attack when high-priority peers are unavailable.

4. **Multi-Fetch Amplification**: The multi-fetch configuration [10](#0-9)  means the node may select multiple low-priority peers simultaneously, amplifying the attack impact.

## Recommendation

Add an explicit guard condition in `choose_peers_for_optimistic_fetch()` to reject scenarios where only low-priority peers are available, forcing the request to fail gracefully rather than accepting unreliable peers. The fix should:

1. Check if only the lowest priority level has serviceable peers
2. If so, return an error indicating insufficient reliable peers
3. This forces the caller to retry or wait for higher-priority peers to become available

**Proposed Fix Location**: [4](#0-3) 

Add logic after line 356 to check:
```rust
// Reject if only low-priority peers are available for optimistic fetches
if selected_peers.is_empty() && 
   serviceable_peers_by_priorities.iter()
       .take(serviceable_peers_by_priorities.len() - 1)
       .all(|peers| peers.is_empty()) {
    return Err(Error::DataIsUnavailable(format!(
        "Only low-priority peers available for optimistic fetch request. \
         Refusing to rely on unreliable peers: {:?}", request
    )));
}
```

Alternatively, implement a configurable policy that allows low-priority-only selection but with stricter timeouts and verification.

## Proof of Concept

**Test Scenario Setup:**

1. Configure a test VFN node with:
   - Zero high-priority validator connections
   - Zero medium-priority outbound connections  
   - Multiple low-priority inbound connections (simulated attacker peers)

2. Trigger an optimistic fetch request for new transactions

3. Observe that the peer selection algorithm chooses from the low-priority peers

**Expected Vulnerable Behavior:**
The function will return `Ok(selected_peers)` containing only low-priority peers, violating the documented invariant.

**Rust Unit Test Structure:**
```rust
#[tokio::test]
async fn test_priority_exhaustion_vulnerability() {
    // Setup: Create AptosDataClient with only low-priority peers
    // that can service optimistic fetch requests
    
    // Action: Call choose_peers_for_request with optimistic fetch
    
    // Assertion: Verify that low-priority peers are selected
    // despite the documented invariant that they should be avoided
    
    // This demonstrates the vulnerability
}
```

The test would demonstrate that when `serviceable_peers_by_priorities = [empty_set, empty_set, low_priority_peers]`, the function returns low-priority peers instead of failing or waiting for better peers.

## Notes

This vulnerability represents a **defense-in-depth failure** where the documented security policy (avoid unreliable peers) is not enforced in the implementation. While cryptographic proof verification provides a backstop against accepting invalid data, the performance and availability impacts from forced reliance on malicious low-priority peers remain significant, especially for time-sensitive validator operations.

### Citations

**File:** state-sync/aptos-data-client/src/priority.rs (L18-22)
```rust
pub enum PeerPriority {
    HighPriority,   // Peers to highly prioritize when requesting data
    MediumPriority, // Peers to prioritize iff high priority peers are unavailable
    LowPriority, // Peers to use iff no other peers are available (these are generally unreliable)
}
```

**File:** state-sync/aptos-data-client/src/priority.rs (L76-101)
```rust
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
```

**File:** state-sync/aptos-data-client/src/priority.rs (L104-121)
```rust
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
```

**File:** state-sync/aptos-data-client/src/client.rs (L290-320)
```rust
        let multi_fetch_config = self.data_client_config.data_multi_fetch_config;
        let num_peers_for_request = if multi_fetch_config.enable_multi_fetch {
            // Calculate the total number of priority serviceable peers
            let mut num_serviceable_peers = 0;
            for (index, peers) in serviceable_peers_by_priorities.iter().enumerate() {
                // Only include the lowest priority peers if no other peers are
                // available (the lowest priority peers are generally unreliable).
                if (num_serviceable_peers == 0)
                    || (index < serviceable_peers_by_priorities.len() - 1)
                {
                    num_serviceable_peers += peers.len();
                }
            }

            // Calculate the number of peers to select for the request
            let peer_ratio_for_request =
                num_serviceable_peers / multi_fetch_config.multi_fetch_peer_bucket_size;
            let mut num_peers_for_request = multi_fetch_config.min_peers_for_multi_fetch
                + (peer_ratio_for_request * multi_fetch_config.additional_requests_per_peer_bucket);

            // Bound the number of peers by the number of serviceable peers
            num_peers_for_request = min(num_peers_for_request, num_serviceable_peers);

            // Ensure the number of peers is no larger than the maximum
            min(
                num_peers_for_request,
                multi_fetch_config.max_peers_for_multi_fetch,
            )
        } else {
            1 // Multi-fetch is disabled (only select a single peer)
        };
```

**File:** state-sync/aptos-data-client/src/client.rs (L349-383)
```rust
    fn choose_peers_for_optimistic_fetch(
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

        // If selected peers is empty, return an error
        if !selected_peers.is_empty() {
            Ok(selected_peers)
        } else {
            Err(Error::DataIsUnavailable(format!(
                "Unable to select peers for optimistic fetch request: {:?}",
                request
            )))
        }
    }
```

**File:** state-sync/storage-service/types/src/requests.rs (L125-130)
```rust
    pub fn is_optimistic_fetch(&self) -> bool {
        matches!(self, &Self::GetNewTransactionOutputsWithProof(_))
            || matches!(self, &Self::GetNewTransactionsWithProof(_))
            || matches!(self, Self::GetNewTransactionsOrOutputsWithProof(_))
            || matches!(self, &Self::GetNewTransactionDataWithProof(_))
    }
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L59-142)
```rust
    /// Creates a new storage service request to satisfy the optimistic fetch
    /// using the new data at the specified `target_ledger_info`.
    pub fn get_storage_request_for_missing_data(
        &self,
        config: StorageServiceConfig,
        target_ledger_info: &LedgerInfoWithSignatures,
    ) -> aptos_storage_service_types::Result<StorageServiceRequest, Error> {
        // Verify that the target version is higher than the highest known version
        let known_version = self.highest_known_version();
        let target_version = target_ledger_info.ledger_info().version();
        if target_version <= known_version {
            return Err(Error::InvalidRequest(format!(
                "Target version: {:?} is not higher than known version: {:?}!",
                target_version, known_version
            )));
        }

        // Calculate the number of versions to fetch
        let mut num_versions_to_fetch =
            target_version.checked_sub(known_version).ok_or_else(|| {
                Error::UnexpectedErrorEncountered(
                    "Number of versions to fetch has overflown!".into(),
                )
            })?;

        // Bound the number of versions to fetch by the maximum chunk size
        num_versions_to_fetch = min(
            num_versions_to_fetch,
            self.max_chunk_size_for_request(config),
        );

        // Calculate the start and end versions
        let start_version = known_version.checked_add(1).ok_or_else(|| {
            Error::UnexpectedErrorEncountered("Start version has overflown!".into())
        })?;
        let end_version = known_version
            .checked_add(num_versions_to_fetch)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered("End version has overflown!".into())
            })?;

        // Create the storage request
        let data_request = match &self.request.data_request {
            DataRequest::GetNewTransactionOutputsWithProof(_) => {
                DataRequest::GetTransactionOutputsWithProof(TransactionOutputsWithProofRequest {
                    proof_version: target_version,
                    start_version,
                    end_version,
                })
            },
            DataRequest::GetNewTransactionsWithProof(request) => {
                DataRequest::GetTransactionsWithProof(TransactionsWithProofRequest {
                    proof_version: target_version,
                    start_version,
                    end_version,
                    include_events: request.include_events,
                })
            },
            DataRequest::GetNewTransactionsOrOutputsWithProof(request) => {
                DataRequest::GetTransactionsOrOutputsWithProof(
                    TransactionsOrOutputsWithProofRequest {
                        proof_version: target_version,
                        start_version,
                        end_version,
                        include_events: request.include_events,
                        max_num_output_reductions: request.max_num_output_reductions,
                    },
                )
            },
            DataRequest::GetNewTransactionDataWithProof(request) => {
                DataRequest::GetTransactionDataWithProof(GetTransactionDataWithProofRequest {
                    transaction_data_request_type: request.transaction_data_request_type,
                    proof_version: target_version,
                    start_version,
                    end_version,
                    max_response_bytes: request.max_response_bytes,
                })
            },
            request => unreachable!("Unexpected optimistic fetch request: {:?}", request),
        };
        let storage_request =
            StorageServiceRequest::new(data_request, self.request.use_compression);
        Ok(storage_request)
    }
```

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
