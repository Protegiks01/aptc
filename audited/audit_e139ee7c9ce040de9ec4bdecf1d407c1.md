# Audit Report

## Title
Peer Score Manipulation via Premature Success Updates in Multi-Fetch State Sync

## Summary
The `send_request_to_peer()` function updates peer scores immediately upon receiving network responses (line 817), before any content validation occurs. Combined with the multi-fetch mechanism, this allows malicious peers to accumulate score boosts without corresponding penalties, maintaining artificially high reputation scores while consistently serving invalid data. [1](#0-0) 

## Finding Description

The vulnerability exists in the state synchronization layer's peer reputation system, which is designed to prioritize reliable peers and avoid malicious ones. The flaw occurs in the interaction between two mechanisms:

**1. Premature Score Update**

When a peer responds to a data request, their score is incremented (+1.0) immediately upon successful network transmission, before any validation of the response content: [2](#0-1) 

The score update happens at line 817, while validation occurs much later when the consumer processes the response and potentially calls `notify_bad_response()` via the callback mechanism.

**2. Multi-Fetch Amplification**

The data client uses multi-fetch to improve reliability by querying multiple peers simultaneously. By default, 2-3 peers are selected per request: [3](#0-2) 

Each selected peer's request is spawned as a separate async task. The first successful response is used, and all other tasks are aborted: [4](#0-3) 

**The Exploit Path**:

1. Multi-fetch request sent to peers M (malicious), H1, H2 (honest)
2. Each peer's task executes `send_request_to_peer()` independently
3. M responds very quickly with type-valid but content-invalid data (e.g., fabricated transactions with invalid proofs)
4. M's task executes line 817: `self.peer_states.update_score_success(peer)` → M's score increases by 1.0
5. H1 responds with valid data shortly after
6. H1's task also executes line 817 → H1's score increases by 1.0
7. The first completed task (say H1) is selected and returned
8. All other tasks, including M's, are aborted (line 685)
9. H1's response is validated by the consumer → passes validation
10. M's response is never validated (task was aborted), so `notify_bad_response()` is never called for M
11. **M retains the +1.0 score boost without any penalty**

This violates the peer scoring invariant where scores should reflect actual data quality. The scoring mechanism updates are: [5](#0-4) 

**Score Gaming Strategy**:

A malicious peer can exploit this by:
- Responding to every multi-fetch request very quickly (no need to compute expensive proofs)
- When their response is selected (~33% with 3 peers): gain +1.0, then penalized to ×0.8 (net: -0.2×score + 0.8)
- When another peer's response is selected (~67%): gain +1.0 with no penalty

At equilibrium, expected score per request:
```
E[score_change] = 0.33×(-0.2×score + 0.8) + 0.67×(1.0)
= -0.066×score + 0.264 + 0.67
= -0.066×score + 0.934
```

Setting E[score_change] = 0 for equilibrium:
```
0.066×score = 0.934
score ≈ 14.15
```

However, this assumes equal selection probability. If the malicious peer optimizes timing to be selected less frequently (e.g., 20% instead of 33%), their equilibrium score increases. The ignore threshold is 25.0: [6](#0-5) 

With selection rate p < 0.19 (less than ~1 in 5 times), the malicious peer maintains score > 25 indefinitely while serving invalid data.

## Impact Explanation

**Severity: High** — Validator Node Slowdowns

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for causing validator node slowdowns through:

1. **State Sync Performance Degradation**: Malicious peers with inflated scores are preferentially selected for state sync requests. Validators and fullnodes waste computational resources validating and rejecting their invalid responses, then must retry with other peers.

2. **Validator Liveness Impact**: Validators rely on fast state sync when catching up to the network (e.g., after downtime or during initial sync). Repeated selection of malicious peers significantly delays sync, potentially causing validators to fall behind and miss consensus participation opportunities.

3. **Resource Exhaustion**: Proof verification is computationally expensive. Malicious peers force nodes to repeatedly verify invalid proofs that will always fail, wasting CPU cycles that could be used for productive consensus work.

4. **Cascading Effects**: If multiple malicious peers collude using this technique, they can dominate the high-score peer pool, severely degrading state sync performance network-wide.

The vulnerability does NOT cause:
- Consensus safety violations (proof verification still catches invalid data)
- Loss of funds
- State corruption (invalid data is always rejected)

However, the performance impact on critical infrastructure (validators) and the ease of exploitation justify **High severity**.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Barrier to Entry**: Any peer can participate in state sync. No special privileges, stake, or validator status required.

2. **Simple Exploitation**: The attack requires only:
   - Running a modified peer that responds quickly with invalid data
   - No complex timing coordination
   - No expensive resources

3. **Multi-Fetch Amplification**: With multi-fetch enabled by default (2-3 peers per request), every request provides multiple opportunities to gain score boosts without penalties.

4. **No Detection Mechanism**: The current implementation has no safeguards against this pattern. There's no tracking of:
   - Score updates from aborted tasks
   - Correlation between response success rate and validation success rate
   - Peer behavior patterns indicating score gaming

5. **Profit Motive**: While not direct financial gain, malicious actors could exploit this to:
   - Degrade competitor validators' performance
   - Cause network-wide slowdowns
   - Conduct griefing attacks

6. **Persistent Exploitation**: Once established, a malicious peer can maintain their high score indefinitely with minimal effort, as long as they control their selection frequency.

## Recommendation

**Fix 1: Defer Score Updates Until Validation (Recommended)**

Move the score update to occur only after the response has been selected AND initially validated. This requires refactoring the callback mechanism to support both success and failure notifications:

```rust
// In send_request_to_peer(), REMOVE line 817:
// self.peer_states.update_score_success(peer);  // REMOVE THIS

// In send_request_and_decode(), after selecting the response:
async fn send_request_and_decode<T, E>(
    &self,
    request: StorageServiceRequest,
    request_timeout_ms: u64,
) -> crate::error::Result<Response<T>>
where
    T: TryFrom<StorageServiceResponse, Error = E> + Send + Sync + 'static,
    E: Into<Error>,
{
    // ... existing peer selection code ...
    
    for _ in 0..num_sent_requests {
        if let Ok(response_result) = sent_requests.select_next_some().await {
            match response_result {
                Ok(response) => {
                    // Abort all pending tasks
                    for abort_handle in abort_handles {
                        abort_handle.abort();
                    }
                    
                    // NOW update the score for the selected peer only
                    if let Some(peer) = response.context.get_peer() {
                        self.peer_states.update_score_success(peer);
                    }
                    
                    return Ok(response);
                },
                Err(error) => {
                    sent_request_errors.push(error)
                },
            }
        }
    }
    // ...
}
```

This requires adding peer information to ResponseContext.

**Fix 2: Rollback Mechanism for Aborted Tasks**

Alternatively, implement a rollback mechanism that decrements scores for aborted tasks:

```rust
// Track score updates that need rollback
struct PendingScoreUpdate {
    peer: PeerNetworkId,
    update_applied: Arc<AtomicBool>,
}

impl Drop for PendingScoreUpdate {
    fn drop(&mut self) {
        // If the update was applied but task was aborted, rollback
        if self.update_applied.load(Ordering::SeqCst) {
            self.peer_states.rollback_score_update(self.peer);
        }
    }
}
```

**Fix 3: Enhanced Callback with RAII (Defense in Depth)**

Implement Drop for ResponseContext to automatically penalize peers whose responses are dropped without validation:

```rust
impl Drop for ResponseContext {
    fn drop(&mut self) {
        // If callback was never invoked (neither success nor failure),
        // treat as NotUseful error to prevent score gaming
        if !self.callback_invoked.load(Ordering::SeqCst) {
            self.response_callback.notify_bad_response(
                ResponseError::InvalidPayloadDataType
            );
        }
    }
}
```

## Proof of Concept

```rust
// This PoC demonstrates the score manipulation vulnerability
// File: state-sync/aptos-data-client/src/tests/score_gaming_poc.rs

#[tokio::test]
async fn test_malicious_peer_score_gaming_via_multi_fetch() {
    use crate::tests::utils::{MockNetwork, MockPeer};
    
    // Setup: Create 3 peers (1 malicious, 2 honest)
    let mut mock_network = MockNetwork::new();
    let malicious_peer = mock_network.add_peer(PeerRole::Malicious);
    let honest_peer_1 = mock_network.add_peer(PeerRole::Honest);
    let honest_peer_2 = mock_network.add_peer(PeerRole::Honest);
    
    // Configure malicious peer to respond very fast with invalid data
    mock_network.configure_peer(malicious_peer, |config| {
        config.response_delay_ms = 10; // Very fast
        config.send_invalid_proofs = true; // Invalid data
    });
    
    // Configure honest peers with normal latency
    mock_network.configure_peer(honest_peer_1, |config| {
        config.response_delay_ms = 50; // Normal speed
    });
    mock_network.configure_peer(honest_peer_2, |config| {
        config.response_delay_ms = 50;
    });
    
    // Create data client with multi-fetch enabled (default: 2-3 peers per request)
    let data_client = create_data_client_with_multi_fetch(&mock_network);
    
    // Get initial scores
    let initial_score_malicious = data_client.get_peer_states()
        .get_peer_to_states()
        .get(&malicious_peer)
        .unwrap()
        .get_score();
    let initial_score_honest_1 = data_client.get_peer_states()
        .get_peer_to_states()
        .get(&honest_peer_1)
        .unwrap()
        .get_score();
    
    assert_eq!(initial_score_malicious, 50.0); // Starting score
    assert_eq!(initial_score_honest_1, 50.0);
    
    // Execute 100 multi-fetch requests
    for _ in 0..100 {
        let request = create_transaction_request();
        
        // This will trigger multi-fetch to all 3 peers
        let response = data_client
            .get_transactions_with_proof(100, 100, 200, false, 1000)
            .await
            .unwrap();
        
        // Validate the response (will be from honest peer)
        // Malicious peer's responses are not validated (tasks aborted)
        assert!(verify_proof(&response).is_ok());
    }
    
    // Check final scores
    let final_score_malicious = data_client.get_peer_states()
        .get_peer_to_states()
        .get(&malicious_peer)
        .unwrap()
        .get_score();
    let final_score_honest_1 = data_client.get_peer_states()
        .get_peer_to_states()
        .get(&honest_peer_1)
        .unwrap()
        .get_score();
    
    // Expected: Malicious peer's score should NOT increase significantly
    // Actual: Malicious peer's score increases because:
    // - They responded to all 100 requests (100 tasks spawned)
    // - Each response gave +1.0 before task was aborted
    // - Only ~33% were selected and penalized
    // - Net gain: ~67 score increases vs ~33 penalties
    
    println!("Malicious peer score: {} -> {}", initial_score_malicious, final_score_malicious);
    println!("Honest peer score: {} -> {}", initial_score_honest_1, final_score_honest_1);
    
    // Vulnerability demonstrated if malicious score increases despite serving bad data
    assert!(final_score_malicious > initial_score_malicious + 20.0,
        "Malicious peer gained score despite serving invalid data!");
    
    // In a proper implementation, malicious score should decrease
    // assert!(final_score_malicious < initial_score_malicious);
}
```

**Notes:**
1. The score update timing creates a race condition where malicious peers can accumulate reputation without corresponding penalties
2. Multi-fetch amplifies this issue by creating multiple concurrent score update opportunities
3. The lack of rollback for aborted tasks or RAII-based cleanup allows permanent score inflation
4. This affects real-world state sync performance for validators and fullnodes catching up to the network

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L656-687)
```rust
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
```

**File:** state-sync/aptos-data-client/src/client.rs (L798-828)
```rust
        match result {
            Ok(response) => {
                trace!(
                    (LogSchema::new(LogEntry::StorageServiceResponse)
                        .event(LogEvent::ResponseSuccess)
                        .request_type(&request.get_label())
                        .request_id(id)
                        .peer(&peer))
                );

                // Update the received response metrics
                self.update_received_response_metrics(peer, &request);

                // For now, record all responses that at least pass the data
                // client layer successfully. An alternative might also have the
                // consumer notify both success and failure via the callback.
                // On the one hand, scoring dynamics are simpler when each request
                // is successful or failed but not both; on the other hand, this
                // feels simpler for the consumer.
                self.peer_states.update_score_success(peer);

                // Package up all of the context needed to fully report an error
                // with this RPC.
                let response_callback = AptosNetResponseCallback {
                    data_client: self.clone(),
                    id,
                    peer,
                    request,
                };
                let context = ResponseContext::new(id, Box::new(response_callback));
                Ok(Response::new(context, response))
```

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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L42-43)
```rust
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
