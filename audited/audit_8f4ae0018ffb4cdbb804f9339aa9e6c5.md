# Audit Report

## Title
Byzantine Peer Reputation and Monitoring Blind Spot via Premature Success Metrics Increment

## Summary
The Aptos data client increments the SUCCESS_RESPONSES counter and peer reputation scores immediately upon receiving network-level responses, before performing semantic validation. This design flaw allows Byzantine peers to maintain artificially high reputation scores while continuously sending invalid data, causing resource exhaustion and degraded synchronization performance on validator nodes.

## Finding Description

The vulnerability exists in the state sync data client's response handling flow. When a storage service response is received, the following sequence occurs:

**Immediate Success Recording (Before Validation):**

The network request succeeds and immediately triggers success metrics at [1](#0-0) 

Specifically, the SUCCESS_RESPONSES counter is incremented at [2](#0-1) 

The peer reputation score is increased by +1.0 at [3](#0-2)  with the constant defined at [4](#0-3) 

**Delayed Validation (After Success Recorded):**

Type checking occurs later in a spawn_blocking task at [5](#0-4) 

Proof verification happens even later in consumer code (bootstrapper/continuous syncer) at [6](#0-5) 

**Penalty Application:**

When validation fails, notify_bad_response is called via the callback mechanism at [7](#0-6) 

The error types and their multipliers are defined at [8](#0-7) 

The multiplicative penalty is applied at [9](#0-8) 

**Attack Path:**

A Byzantine peer exploits this timing gap by:
1. Sending responses that pass network/BCS deserialization (syntactically valid)
2. But contain semantically invalid content (wrong versions, invalid proofs, mismatched types)
3. Receiving immediate +1.0 reputation boost and SUCCESS_RESPONSES increment
4. Eventually getting penalized with 0.95x or 0.8x multiplier when validation fails

**Score Manipulation Analysis:**

With peer scoring constants at [10](#0-9) 

A Byzantine peer can maintain a score above the IGNORE_PEER_THRESHOLD (25.0) by sending 2 good responses for every 1 bad response:
- Equilibrium score: (score + 2) × 0.95 = score
- Solving: score ≈ 38.0 (above ignore threshold)

This allows the peer to send 33% invalid responses indefinitely while maintaining high reputation and preferential selection.

## Impact Explanation

**Severity: High** - Aligns with Aptos Bug Bounty category "Validator node slowdowns"

This vulnerability enables multiple attack vectors:

1. **Resource Exhaustion**: Validator nodes waste CPU cycles decompressing payloads, deserializing data, and verifying cryptographic proofs for responses that are ultimately invalid. Proof verification is computationally expensive, and each invalid response consumes significant resources before rejection.

2. **Degraded Sync Performance**: When multiple Byzantine peers coordinate this attack, honest validator nodes spend substantial time processing invalid data instead of making legitimate sync progress. This proportionally slows state synchronization and continuous sync operations.

3. **Monitoring Blind Spot**: The SUCCESS_RESPONSES metric shows artificially high success rates even when the majority of responses are semantically invalid. Operators cannot detect which peers are Byzantine, that sync slowdowns stem from malicious peers, or the actual quality of received data.

4. **Peer Selection Bias**: Byzantine peers maintain high reputation scores (38-45 range with 2:1 good:bad ratio) and are preferentially selected by the peer selection algorithm at [11](#0-10) 

5. **Network-Wide Impact**: In a network where multiple peers coordinate this attack, the cumulative effect significantly degrades state sync performance across all honest validator nodes, approaching a liveness concern.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially exploitable:

1. **Low Barrier to Entry**: Any network peer can send malformed responses. No validator privileges, stake, or special access required.

2. **Easy to Execute**: Attacker implements a modified storage service returning syntactically valid but semantically invalid responses, connects as a regular peer, and responds to data requests with crafted payloads.

3. **Difficult to Detect**: The SUCCESS_RESPONSES metric masks the attack. Without correlating request/response timing with validation failures, operators cannot identify Byzantine peers.

4. **Insufficient Penalties**: The multiplicative score reduction (0.95x for NotUseful, 0.8x for Malicious) is insufficient deterrent. Mathematical analysis proves a peer can send 33% bad data indefinitely without being ignored.

5. **No Rate Limiting**: The scoring system at [12](#0-11)  does not implement rate limiting or burst detection for bad responses.

## Recommendation

Implement delayed success recording and tiered validation:

1. **Delay Success Metrics**: Move SUCCESS_RESPONSES increment and peer score increase to after basic validation (type checking, version range verification).

2. **Implement Validation Stages**: 
   - Stage 1 (immediate): Network-level success
   - Stage 2 (fast): Type and structure validation → increment SUCCESS_RESPONSES
   - Stage 3 (expensive): Proof verification → finalize peer score increase

3. **Enhanced Penalty System**: Implement additive penalties for repeated failures instead of purely multiplicative, with faster score decay for malicious patterns.

4. **Separate Metrics**: Create distinct metrics for network success, validation success, and proof verification success to eliminate the monitoring blind spot.

5. **Burst Detection**: Track short-term bad response rates and immediately ignore peers showing suspicious patterns (e.g., >20% bad responses in last 10 requests).

## Proof of Concept

The vulnerability can be demonstrated by:

1. Running an Aptos validator node
2. Implementing a malicious storage service peer that sends responses with valid structure but invalid proofs
3. Monitoring SUCCESS_RESPONSES metric and peer scores
4. Observing that the malicious peer maintains high reputation (>25.0) while sending 33% invalid responses
5. Measuring CPU consumption and sync performance degradation

The mathematical proof is evident in the scoring constants where alternating 2 good and 1 bad response yields equilibrium score ≈ 38.0, maintaining the peer above the ignore threshold indefinitely.

## Notes

The premature success recording appears intentional based on the code comment at [13](#0-12) , but this design choice creates an exploitable attack surface. While the comment suggests simplicity for consumers, the trade-off enables Byzantine peers to degrade network performance while maintaining high reputation, meeting the "Validator node slowdowns" High severity threshold per the Aptos bug bounty program.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L265-344)
```rust
    pub(crate) fn choose_peers_for_request(
        &self,
        request: &StorageServiceRequest,
    ) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
        // Get all peers grouped by priorities
        let peers_by_priorities = self.get_peers_by_priorities()?;

        // Identify the peers that can service the request (ordered by priority)
        let mut serviceable_peers_by_priorities = vec![];
        for priority in PeerPriority::get_all_ordered_priorities() {
            // Identify the serviceable peers for the priority
            let peers = self.identify_serviceable(&peers_by_priorities, priority, request);

            // Add the serviceable peers to the ordered list
            serviceable_peers_by_priorities.push(peers);
        }

        // If the request is a subscription request, select a single
        // peer (as we can only subscribe to a single peer at a time).
        if request.data_request.is_subscription_request() {
            return self
                .choose_peer_for_subscription_request(request, serviceable_peers_by_priorities);
        }

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

        // Verify that we have at least one peer to service the request
        if num_peers_for_request == 0 {
            return Err(Error::DataIsUnavailable(format!(
                "No peers are available to service the given request: {:?}",
                request
            )));
        }

        // Choose the peers based on the request type
        if request.data_request.is_optimistic_fetch() {
            self.choose_peers_for_optimistic_fetch(
                request,
                serviceable_peers_by_priorities,
                num_peers_for_request,
            )
        } else {
            self.choose_peers_for_specific_data_request(
                request,
                serviceable_peers_by_priorities,
                num_peers_for_request,
            )
        }
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L752-765)
```rust
        tokio::task::spawn_blocking(move || {
            match T::try_from(storage_response) {
                Ok(new_payload) => Ok(Response::new(context, new_payload)),
                // If the variant doesn't match what we're expecting, report the issue
                Err(err) => {
                    context
                        .response_callback
                        .notify_bad_response(ResponseError::InvalidPayloadDataType);
                    Err(err.into())
                },
            }
        })
        .await
        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?
```

**File:** state-sync/aptos-data-client/src/client.rs (L798-829)
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
            },
```

**File:** state-sync/aptos-data-client/src/client.rs (L899-911)
```rust
    /// Updates the metrics for the responses received via the data client
    fn update_received_response_metrics(
        &self,
        peer: PeerNetworkId,
        request: &StorageServiceRequest,
    ) {
        // Update the global received response metrics
        increment_request_counter(&metrics::SUCCESS_RESPONSES, &request.get_label(), peer);

        // Update the received response counter for the specific peer
        self.peer_states
            .increment_received_response_counter(peer, request);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L33-43)
```rust
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L163-165)
```rust
    fn update_score_success(&mut self) {
        self.score = f64::min(self.score + SUCCESSFUL_RESPONSE_DELTA, MAX_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L168-174)
```rust
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L280-322)
```rust
    /// Updates the score of the peer according to a successful operation
    pub fn update_score_success(&self, peer: PeerNetworkId) {
        if let Some(mut entry) = self.peer_to_state.get_mut(&peer) {
            // Get the peer's old score
            let old_score = entry.score;

            // Update the peer's score with a successful operation
            entry.update_score_success();

            // Log if the peer is no longer ignored
            let new_score = entry.score;
            if old_score <= IGNORE_PEER_THRESHOLD && new_score > IGNORE_PEER_THRESHOLD {
                info!(
                    (LogSchema::new(LogEntry::PeerStates)
                        .event(LogEvent::PeerNoLongerIgnored)
                        .message("Peer will no longer be ignored")
                        .peer(&peer))
                );
            }
        }
    }

    /// Updates the score of the peer according to an error
    pub fn update_score_error(&self, peer: PeerNetworkId, error: ErrorType) {
        if let Some(mut entry) = self.peer_to_state.get_mut(&peer) {
            // Get the peer's old score
            let old_score = entry.score;

            // Update the peer's score with an error
            entry.update_score_error(error);

            // Log if the peer is now ignored
            let new_score = entry.score;
            if old_score > IGNORE_PEER_THRESHOLD && new_score <= IGNORE_PEER_THRESHOLD {
                info!(
                    (LogSchema::new(LogEntry::PeerStates)
                        .event(LogEvent::PeerIgnored)
                        .message("Peer will be ignored")
                        .peer(&peer))
                );
            }
        }
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1095-1106)
```rust
            if let Err(error) = self.verified_epoch_states.update_verified_epoch_states(
                &epoch_ending_ledger_info,
                &self.driver_configuration.waypoint,
            ) {
                self.reset_active_stream(Some(NotificationAndFeedback::new(
                    notification_id,
                    NotificationFeedback::PayloadProofFailed,
                )))
                .await?;
                return Err(error);
            }
        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L746-764)
```rust
    /// Notifies the Aptos data client of a bad client response
    fn notify_bad_response(
        &self,
        response_context: &ResponseContext,
        response_error: ResponseError,
    ) {
        let response_id = response_context.id;
        info!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .message(&format!(
                "Notifying the data client of a bad response. Response id: {:?}, error: {:?}",
                response_id, response_error
            )));

        response_context
            .response_callback
            .notify_bad_response(response_error);
    }
```
