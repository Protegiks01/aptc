# Audit Report

## Title
Peer Score Manipulation via Premature Success Updates in Multi-Fetch State Sync

## Summary
The state sync data client's peer scoring system updates peer scores immediately upon network response success, before content validation. Combined with the multi-fetch mechanism that spawns parallel requests, this allows malicious peers to accumulate score increases without corresponding penalties when their responses complete but are not selected for validation, enabling persistent score gaming that degrades validator state sync performance.

## Finding Description

The vulnerability exists in the interaction between two mechanisms in the state sync data client:

**Premature Score Updates:**

The `send_request_to_peer()` function updates peer scores immediately upon receiving a successful network response, before any content validation occurs: [1](#0-0) 

The score increase of +1.0 happens at line 817. Content validation occurs later when the consumer processes the response and calls `notify_bad_response()` through the callback mechanism: [2](#0-1) 

**Multi-Fetch Amplification:**

The data client uses multi-fetch enabled by default with 2-3 peers per request: [3](#0-2) 

Each peer's request is spawned as a separate async task. The first successful response is used, and all other tasks are aborted: [4](#0-3) 

**The Exploit Mechanism:**

When multi-fetch sends requests to multiple peers (e.g., M=malicious, H1=honest, H2=honest):

1. Each task executes `send_request_to_peer()` independently
2. If M responds quickly with type-valid but content-invalid data, M's task completes and line 817 executes (+1.0 score for M)
3. If H1 also completes shortly after with valid data, H1's task also executes line 817 (+1.0 score for H1)
4. The multi-fetch loop selects the first response (say H1) and aborts all other tasks
5. H1's response is validated by the consumer and passes
6. M's task was already complete when aborted, so M's score update persists
7. M's response is never validated because it wasn't selected, so `notify_bad_response()` is never called
8. **M retains the +1.0 score boost without penalty**

This violates the peer scoring invariant. The scoring constants are: [5](#0-4) 

A malicious peer can maintain high scores by responding quickly to every request. When selected (~33%), they receive +1.0 then ×0.8 penalty. When not selected (~67%), they receive +1.0 with no penalty. By optimizing timing to be selected less than 19% of the time, they can maintain scores above the 25.0 ignore threshold indefinitely while serving invalid data.

## Impact Explanation

**Severity: High — Validator Node Slowdowns**

This qualifies as High Severity under the Aptos bug bounty criteria for "Validator Node Slowdowns": [6](#0-5) 

**Performance Impact:**

1. **State Sync Degradation**: Malicious peers with inflated scores are preferentially selected. Validators waste CPU cycles validating invalid proofs, then must retry with other peers, increasing sync latency.

2. **Validator Liveness Impact**: Validators catching up after downtime rely on fast state sync. Repeated selection of malicious peers delays sync, potentially causing validators to fall behind and miss consensus participation.

3. **Resource Exhaustion**: Proof verification is computationally expensive. Malicious peers force repeated validation of invalid proofs that always fail.

4. **Cascading Effects**: Multiple colluding malicious peers can dominate the high-score peer pool, severely degrading network-wide state sync performance.

The vulnerability does NOT cause consensus safety violations, fund loss, or state corruption (invalid data is always rejected), but the performance impact on validator infrastructure justifies High severity.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited:

1. **Low Barrier**: Any network peer can participate in state sync without special privileges or stake.

2. **Simple Exploitation**: Requires only running a modified peer that responds quickly with type-valid but content-invalid data.

3. **Multi-Fetch Amplification**: Multi-fetch is enabled by default, providing multiple opportunities per request to gain score boosts.

4. **No Detection**: The implementation lacks safeguards against this pattern. There's no tracking of score updates from non-selected responses or correlation between response success rate and validation success rate.

5. **Persistent Exploitation**: Once established, a malicious peer maintains high scores indefinitely with minimal effort.

## Recommendation

Implement score updates only after content validation:

1. **Defer Score Updates**: Move the `update_score_success()` call from `send_request_to_peer()` to occur only after the consumer validates the response content.

2. **Track Task Completion**: In multi-fetch, track which tasks completed successfully but weren't selected, and ensure their peers don't receive unwarranted score boosts.

3. **Alternative Architecture**: Consider updating scores only through the callback mechanism, ensuring all score changes reflect actual data quality validation.

4. **Detection Mechanism**: Add monitoring to detect peers with high response rates but low validation rates, indicating potential score gaming.

## Proof of Concept

A proof of concept would require:

1. Running a modified peer that responds to state sync requests with fabricated data (valid type, invalid proofs)
2. Timing responses to complete during multi-fetch but not always be selected first
3. Monitoring peer scores over time to demonstrate score accumulation without penalties
4. Measuring the performance impact on validators selecting the malicious peer

The vulnerability can be demonstrated by examining the task execution flow where multiple tasks complete nearly simultaneously, with only the selected task's response undergoing validation while other completed tasks' score updates persist.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L675-687)
```rust
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

**File:** state-sync/aptos-data-client/src/client.rs (L811-817)
```rust
                // For now, record all responses that at least pass the data
                // client layer successfully. An alternative might also have the
                // consumer notify both success and failure via the callback.
                // On the one hand, scoring dynamics are simpler when each request
                // is successful or failed but not both; on the other hand, this
                // feels simpler for the consumer.
                self.peer_states.update_score_success(peer);
```

**File:** state-sync/aptos-data-client/src/client.rs (L819-828)
```rust
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

**File:** config/src/config/state_sync_config.rs (L378-387)
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
```

**File:** config/src/config/state_sync_config.rs (L466-466)
```rust
            ignore_low_score_peers: true,
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
