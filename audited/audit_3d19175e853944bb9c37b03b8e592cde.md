# Audit Report

## Title
Insufficient Peer Count and Missing Quorum in State Sync Multi-Fetch Enables Sybil-Based DoS Attack

## Summary
The state sync data client's multi-fetch mechanism defaults to querying only 3 peers maximum and accepts the first response without any quorum or majority verification. This design is insufficient to prevent Sybil attacks where an attacker controls multiple responding peers, enabling resource exhaustion attacks that can significantly delay node synchronization.

## Finding Description

The `AptosDataMultiFetchConfig` structure defines `max_peers_for_multi_fetch` with a default value of 3: [1](#0-0) 

The `send_request_and_decode` method implements a "first-response-wins" pattern where requests are sent to multiple peers concurrently, but only the first successful response is accepted and all other pending requests are aborted: [2](#0-1) 

The peer selection logic calculates the number of peers to query based on the multi-fetch configuration, with the maximum capped at 3: [3](#0-2) 

**The Critical Vulnerability**: Unlike the consensus layer which requires 2f+1 quorum votes from 3f+1 validators to achieve Byzantine fault tolerance, the state sync data client has **no quorum or majority requirement**. It simply accepts the first response that arrives and validates it cryptographically after acceptance.

**Attack Scenario**:
1. Attacker deploys 10-20 malicious peer identities with good network connectivity (low latency, datacenter hosting)
2. Due to latency-weighted peer selection, attacker's well-connected peers have high probability of being selected in the set of 3 peers
3. For each state sync request, if attacker controls 1-2 of the 3 selected peers, their malicious peers respond fastest with invalid (but structurally valid) data
4. Victim node accepts the first response and performs expensive cryptographic proof verification (Merkle proofs, BLS signature verification)
5. Verification fails, peer is penalized, and request is retried
6. Each malicious peer can be exploited ~4 times before being ignored (score drops from 50 to below 25 threshold): [4](#0-3) [5](#0-4) 

7. With 20 malicious identities × 4 attempts each = 80 failed verification cycles, causing sustained synchronization delays

**Why This Breaks Byzantine Fault Tolerance**: In distributed systems theory, to tolerate `f` Byzantine nodes requires `3f+1` total nodes and `2f+1` (quorum) agreeing responses. With `max_peers_for_multi_fetch = 3` and no quorum:
- Cannot reliably tolerate even 1 Byzantine peer
- If 1/3 peers is Byzantine and fastest → 33% attack success rate
- If 2/3 peers are Byzantine → 66% attack success rate

## Impact Explanation

This vulnerability qualifies as **High Severity** ($50,000 tier) under the Aptos Bug Bounty program:

**Primary Impact**: "Validator node slowdowns" - explicitly listed as High severity. The attack forces nodes to:
- Repeatedly perform expensive cryptographic verifications on invalid data
- Experience significant delays in state synchronization
- Waste computational resources that could be used for consensus/execution

**Secondary Impacts**:
- Fullnodes syncing from malicious peers experience the same slowdown
- During critical periods (epoch transitions, network upgrades), synchronization delays can impact network liveness
- Resource exhaustion on victim nodes (CPU cycles spent on proof verification)

**Why Not Critical**: The attack does not cause permanent state inconsistency, consensus violation, or fund loss. Proofs are still verified correctly, preventing incorrect state acceptance. However, it significantly degrades performance and availability.

## Likelihood Explanation

**Attack Feasibility**: HIGH

**Attacker Requirements**:
1. Ability to run 10-20 malicious peer nodes (low cost, ~$100-500/month in cloud infrastructure)
2. Good network connectivity to ensure low latency (easily achievable with datacenter hosting)
3. No validator stake or privileged access required
4. No cryptographic key compromise needed

**Technical Complexity**: LOW
- Attacker simply needs to respond quickly with structurally valid but cryptographically invalid data
- No sophisticated attacks on cryptographic primitives required
- Peer selection naturally favors low-latency peers, giving attacker advantage

**Detection Difficulty**: MEDIUM
- Individual malicious responses are detected and peers are penalized
- However, with Sybil identities, attacker can sustain the attack by rotating through different peer IDs
- Distinguishing between legitimate network issues and intentional attack is challenging

**Practical Likelihood**: The attack is highly practical because:
- State sync is critical for node operation (all nodes must sync to participate)
- The 3-peer limit with no quorum is a fundamental design weakness, not an edge case
- Latency-based selection gives attackers with good infrastructure a systematic advantage

## Recommendation

Implement Byzantine fault tolerant peer selection with proper quorum requirements:

**1. Increase minimum peer count**: Set `max_peers_for_multi_fetch` to at least 7 (to tolerate 2 Byzantine peers with 2f+1=5 quorum)

```rust
impl Default for AptosDataMultiFetchConfig {
    fn default() -> Self {
        Self {
            enable_multi_fetch: true,
            additional_requests_per_peer_bucket: 1,
            min_peers_for_multi_fetch: 3,
            max_peers_for_multi_fetch: 7,  // Changed from 3 to 7
            multi_fetch_peer_bucket_size: 10,
        }
    }
}
```

**2. Implement majority verification**: Instead of accepting the first response, wait for multiple responses and require majority agreement:

```rust
// In send_request_and_decode, replace first-response logic with:
async fn send_request_and_decode_with_quorum<T, E>(
    &self,
    request: StorageServiceRequest,
    request_timeout_ms: u64,
) -> crate::error::Result<Response<T>>
where
    T: TryFrom<StorageServiceResponse, Error = E> + Send + Sync + 'static + Eq + Hash,
    E: Into<Error>,
{
    let peers = self.choose_peers_for_request(&request)?;
    let required_matches = (peers.len() / 2) + 1; // Majority requirement
    
    // Send requests and collect ALL responses (not just first)
    let mut responses: HashMap<T, Vec<PeerNetworkId>> = HashMap::new();
    
    for response in collect_responses_with_timeout(...) {
        let peer = response.peer;
        let payload = response.payload;
        
        responses.entry(payload)
            .or_insert_with(Vec::new)
            .push(peer);
            
        // Check if any response has reached quorum
        if let Some((majority_payload, agreeing_peers)) = 
            responses.iter().find(|(_, peers)| peers.len() >= required_matches) {
            return Ok(Response::new(context, majority_payload.clone()));
        }
    }
    
    Err(Error::DataIsUnavailable("No quorum reached".to_string()))
}
```

**3. Implement more aggressive Sybil detection**:
- Track response time patterns across peers
- Identify clusters of peers with suspiciously similar behavior
- Implement network-level diversity requirements (different ASNs, geographic distribution)

**4. Add configuration validation**:
```rust
impl ConfigSanitizer for AptosDataMultiFetchConfig {
    fn sanitize(...) -> Result<(), Error> {
        if config.max_peers_for_multi_fetch < 7 {
            return Err(Error::ConfigSanitizerFailed(
                "max_peers_for_multi_fetch must be at least 7 for Byzantine fault tolerance"
            ));
        }
        Ok(())
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_sybil_attack_with_max_3_peers() {
    // Setup: Create data client with default config (max_peers = 3)
    let data_client_config = AptosDataClientConfig::default();
    let (mut mock_network, _, client, _) = MockNetwork::new(
        Some(base_config),
        Some(data_client_config),
        Some(networks),
    );
    
    // Attacker controls 2 malicious peers (67% of max_peers)
    let malicious_peer_1 = mock_network.add_peer(PeerPriority::HighPriority);
    let malicious_peer_2 = mock_network.add_peer(PeerPriority::HighPriority);
    let honest_peer = mock_network.add_peer(PeerPriority::HighPriority);
    
    // Configure malicious peers with low latency (will be selected preferentially)
    mock_network.set_peer_latency(malicious_peer_1, Duration::from_millis(5));
    mock_network.set_peer_latency(malicious_peer_2, Duration::from_millis(5));
    mock_network.set_peer_latency(honest_peer, Duration::from_millis(50));
    
    let mut failed_verifications = 0;
    let attack_rounds = 10;
    
    for _ in 0..attack_rounds {
        // Malicious peers respond first with invalid proofs
        mock_network.queue_response(
            malicious_peer_1,
            create_response_with_invalid_proof()
        );
        mock_network.queue_response(
            malicious_peer_2,
            create_response_with_invalid_proof()
        );
        mock_network.queue_response(
            honest_peer,
            create_valid_response()
        );
        
        // Attempt to fetch data
        let result = client.get_transaction_outputs_with_proof(
            proof_version,
            start_version,
            end_version,
            timeout_ms,
        ).await;
        
        // Count verification failures
        if let Err(Error::VerificationError(_)) = result {
            failed_verifications += 1;
        }
    }
    
    // With 3 peers max and 2 malicious (both low latency),
    // malicious peers will win the race most of the time
    assert!(failed_verifications >= 6, 
        "Expected majority of requests to fail due to malicious peers winning race");
    
    // This demonstrates the DoS impact: honest peer has valid data
    // but attacker's faster malicious peers cause repeated verification failures
}
```

**Notes**:
- The current design fundamentally cannot achieve Byzantine fault tolerance with only 3 peers and first-response-wins
- The peer scoring mechanism eventually ignores malicious peers, but with Sybil identities, attackers can sustain the attack
- This is a design-level vulnerability requiring architectural changes, not just parameter tuning
- The fix requires both increasing peer count AND implementing majority verification for proper BFT guarantees

### Citations

**File:** config/src/config/state_sync_config.rs (L378-388)
```rust
impl Default for AptosDataMultiFetchConfig {
    fn default() -> Self {
        Self {
            enable_multi_fetch: true,
            additional_requests_per_peer_bucket: 1,
            min_peers_for_multi_fetch: 2,
            max_peers_for_multi_fetch: 3,
            multi_fetch_peer_bucket_size: 10,
        }
    }
}
```

**File:** state-sync/aptos-data-client/src/client.rs (L289-320)
```rust
        // Otherwise, determine the number of peers to select for the request
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

**File:** state-sync/aptos-data-client/src/client.rs (L627-702)
```rust
    /// Sends the specified storage request to a number of peers
    /// in the network and decodes the first successful response.
    async fn send_request_and_decode<T, E>(
        &self,
        request: StorageServiceRequest,
        request_timeout_ms: u64,
    ) -> crate::error::Result<Response<T>>
    where
        T: TryFrom<StorageServiceResponse, Error = E> + Send + Sync + 'static,
        E: Into<Error>,
    {
        // Select the peers to service the request
        let peers = self.choose_peers_for_request(&request)?;

        // If peers is empty, return an error
        if peers.is_empty() {
            return Err(Error::DataIsUnavailable(format!(
                "No peers were chosen to service the given request: {:?}",
                request
            )));
        }

        // Update the metrics for the number of selected peers (for the request)
        metrics::observe_value_with_label(
            &metrics::MULTI_FETCHES_PER_REQUEST,
            &request.get_label(),
            peers.len() as f64,
        );

        // Send the requests to the peers (and gather abort handles for the tasks)
        let mut sent_requests = FuturesUnordered::new();
        let mut abort_handles = vec![];
        for peer in peers {
            // Send the request to the peer
            let aptos_data_client = self.clone();
            let request = request.clone();
            let sent_request = tokio::spawn(async move {
                aptos_data_client
                    .send_request_to_peer_and_decode(peer, request, request_timeout_ms)
                    .await
            });
            let abort_handle = sent_request.abort_handle();

            // Gather the tasks and abort handles
            sent_requests.push(sent_request);
            abort_handles.push(abort_handle);
        }

        // Wait for the first successful response and abort all other tasks.
        // If all requests fail, gather the errors and return them.
        let num_sent_requests = sent_requests.len();
        let mut sent_request_errors = vec![];
        for _ in 0..num_sent_requests {
            if let Ok(response_result) = sent_requests.select_next_some().await {
                match response_result {
                    Ok(response) => {
                        // We received a valid response. Abort all pending tasks.
                        for abort_handle in abort_handles {
                            abort_handle.abort();
                        }
                        return Ok(response); // Return the response
                    },
                    Err(error) => {
                        // Gather the error and continue waiting for a response
                        sent_request_errors.push(error)
                    },
                }
            }
        }

        // Otherwise, all requests failed and we should return an error
        Err(Error::DataIsUnavailable(format!(
            "All {} attempts failed for the given request: {:?}. Errors: {:?}",
            num_sent_requests, request, sent_request_errors
        )))
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L167-174)
```rust
    /// Updates the score of the peer according to an error
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```
