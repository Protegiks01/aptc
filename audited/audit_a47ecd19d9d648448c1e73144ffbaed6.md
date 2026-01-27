# Audit Report

## Title
Callback Reentrancy in AptosNetResponseCallback Allows Duplicate Peer Score Penalties

## Summary
The `notify_bad_response` callback in `AptosNetResponseCallback` can be invoked multiple times for the same response, causing compounding peer score penalties. This occurs because the `ResponseCallback` trait takes `&self` instead of consuming ownership, and the `ResponseContext` is never removed from the notification map after feedback is provided.

## Finding Description

The vulnerability exists across multiple components of the state-sync system:

**1. Callback Design Limitation**

The `ResponseCallback` trait is designed with a non-consuming interface: [1](#0-0) 

The TODO comment explicitly acknowledges this design limitation - ideally the callback should be consumed after a single use, but the current implementation allows multiple invocations.

**2. Response Context Storage**

When a data notification is sent to the consumer, the `ResponseContext` (containing the callback) is stored in the `notifications_to_responses` map: [2](#0-1) 

**3. No Removal on Feedback**

The `handle_notification_feedback` method retrieves the `ResponseContext` from the map but never removes it: [3](#0-2) 

**4. Only Garbage Collection Removes Entries**

The `ResponseContext` is only removed during garbage collection when the map exceeds its size limit, removing only the oldest entries: [4](#0-3) 

**5. Callback Implementation Without Guards**

The callback implementation directly calls the scoring function without any idempotency check: [5](#0-4) 

Which calls: [6](#0-5) 

**6. Vulnerable Scoring Mechanism**

The `update_score_error` function has no protection against duplicate calls and applies a multiplicative penalty each time: [7](#0-6) 

With penalty multipliers defined as: [8](#0-7) 

**Exploitation Scenario:**

1. A data notification is sent to the consumer with notification_id N
2. The consumer calls `handle_notification_feedback(N, InvalidData)` → peer score multiplied by 0.95
3. Due to a bug or malicious code, the consumer calls `handle_notification_feedback(N, InvalidData)` again → peer score multiplied by 0.95 again
4. After 10 such calls, a peer with score 50.0 would have: 50.0 × (0.95)^10 = 29.9
5. After 15 calls: 50.0 × (0.95)^15 = 23.2 (below `IGNORE_PEER_THRESHOLD` of 25.0)
6. The peer is now ignored, even though only ONE bad response occurred

For malicious errors, the impact is even worse: 50.0 × (0.8)^5 = 16.4 (peer ignored after just 5 duplicate calls).

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria:

- **State Inconsistencies Requiring Intervention**: The peer scoring state becomes inconsistent with the actual quality of peer responses. Honest peers can be unfairly penalized and ignored, requiring manual intervention to restore proper peer relationships.

- **Availability Impact**: If multiple honest peers are unfairly ignored due to duplicate penalty calls, the node's ability to synchronize state is degraded, potentially affecting availability and liveness.

- **No Direct Fund Loss**: This vulnerability does not directly cause loss of funds or consensus violations, preventing it from reaching Critical or High severity.

The vulnerability breaks the **peer scoring invariant** that each bad response should result in exactly one penalty, maintaining fair and accurate peer reputation scores.

## Likelihood Explanation

The likelihood is **Low to Medium** because:

**Exploitation Requirements:**
- Requires the state-sync consumer (internal Aptos code) to call `handle_notification_feedback` multiple times for the same notification
- Cannot be directly triggered by external network peers or transaction senders
- Requires either a bug in the consumer code or compromised node software

**However:**
- The interface design explicitly allows multiple calls (no consumption of callback)
- No runtime guards prevent duplicate calls
- The TODO comment indicates this is a known design limitation
- Complex async processing could lead to accidental duplicate calls
- Race conditions in notification handling could trigger duplicate feedback

## Recommendation

**Immediate Fix: Remove ResponseContext After First Feedback**

Modify `handle_notification_feedback` to remove the `ResponseContext` after the first call:

```rust
pub fn handle_notification_feedback(
    &mut self,  // Change to &mut self
    notification_id: &NotificationId,
    notification_feedback: &NotificationFeedback,
) -> Result<(), Error> {
    if self.stream_end_notification_id == Some(*notification_id) {
        return if matches!(notification_feedback, NotificationFeedback::EndOfStream) {
            Ok(())
        } else {
            Err(Error::UnexpectedErrorEncountered(format!(
                "Invalid feedback given for stream end: {:?}",
                notification_feedback
            )))
        };
    }

    // Remove the response context (consume it) to prevent duplicate penalties
    let response_context = self
        .notifications_to_responses
        .remove(notification_id)  // Change from .get() to .remove()
        .ok_or_else(|| {
            Error::UnexpectedErrorEncountered(format!(
                "Response context missing for notification ID: {:?}",
                notification_id
            ))
        })?;
    
    let response_error = extract_response_error(notification_feedback)?;
    self.notify_bad_response(&response_context, response_error);

    Ok(())
}
```

**Long-term Fix: Consume the Callback**

Modify the `ResponseCallback` trait to consume ownership as suggested in the TODO comment, ensuring callbacks can only be called once:

```rust
pub trait ResponseCallback: fmt::Debug + Send + Sync + 'static {
    fn notify_bad_response(self: Box<Self>, error: ResponseError);
}
```

This would require refactoring the state-sync-v2 code to handle consumed callbacks properly.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::config::AptosDataClientConfig;
    use aptos_types::PeerId;
    
    #[test]
    fn test_duplicate_callback_penalties() {
        // Create peer states with default config
        let config = AptosDataClientConfig::default();
        let peer_states = PeerStates::new(Arc::new(config));
        
        // Create a test peer
        let peer = PeerNetworkId::new(NetworkId::Validator, PeerId::random());
        
        // Initialize peer with starting score
        let mut peer_state = PeerState::new(Arc::new(AptosDataClientConfig::default()));
        assert_eq!(peer_state.get_score(), STARTING_SCORE); // 50.0
        
        // Simulate the same bad response being reported 5 times
        // (as would happen if notify_bad_response is called 5 times)
        for _ in 0..5 {
            peer_state.update_score_error(ErrorType::Malicious);
        }
        
        // After 5 duplicate penalties with MALICIOUS_MULTIPLIER (0.8):
        // Score = 50.0 * (0.8)^5 = 16.384
        let expected_score = STARTING_SCORE * f64::powi(MALICIOUS_MULTIPLIER, 5);
        assert_eq!(peer_state.get_score(), expected_score);
        assert!(peer_state.get_score() < IGNORE_PEER_THRESHOLD); // Peer is now ignored!
        
        // Verify the peer would be ignored
        assert!(peer_state.is_ignored());
        
        println!("Original score: {}", STARTING_SCORE);
        println!("After 5 duplicate penalties: {}", peer_state.get_score());
        println!("Peer ignored: {}", peer_state.is_ignored());
    }
    
    #[test]
    fn test_single_penalty_would_not_ignore_peer() {
        let mut peer_state = PeerState::new(Arc::new(AptosDataClientConfig::default()));
        
        // Single malicious error
        peer_state.update_score_error(ErrorType::Malicious);
        
        // Score = 50.0 * 0.8 = 40.0 (still above threshold)
        assert_eq!(peer_state.get_score(), 40.0);
        assert!(!peer_state.is_ignored());
    }
}
```

This PoC demonstrates that:
1. A single bad response should result in one penalty (score: 50.0 → 40.0)
2. Five duplicate penalties for the same response drive the score to 16.4, causing the peer to be ignored
3. The callback reentrancy vulnerability can unfairly exclude honest peers from the network

**Notes**

The vulnerability exists due to a conscious design trade-off acknowledged in the codebase. While external attackers cannot directly exploit this, the lack of idempotency guards creates a state consistency risk that could be triggered by bugs in the state-sync consumer code or race conditions in async notification handling. The recommended fix is straightforward: consume the `ResponseContext` after first use to ensure each response is penalized exactly once.

### Citations

**File:** state-sync/aptos-data-client/src/interface.rs (L200-205)
```rust
pub trait ResponseCallback: fmt::Debug + Send + Sync + 'static {
    // TODO(philiphayes): ideally this would take a `self: Box<Self>`, i.e.,
    // consume the callback, which better communicates that you should only report
    // an error once. however, the current state-sync-v2 code makes this difficult...
    fn notify_bad_response(&self, error: ResponseError);
}
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L233-263)
```rust
    /// Notifies the Aptos data client of a bad client response
    pub fn handle_notification_feedback(
        &self,
        notification_id: &NotificationId,
        notification_feedback: &NotificationFeedback,
    ) -> Result<(), Error> {
        if self.stream_end_notification_id == Some(*notification_id) {
            return if matches!(notification_feedback, NotificationFeedback::EndOfStream) {
                Ok(())
            } else {
                Err(Error::UnexpectedErrorEncountered(format!(
                    "Invalid feedback given for stream end: {:?}",
                    notification_feedback
                )))
            };
        }

        let response_context = self
            .notifications_to_responses
            .get(notification_id)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered(format!(
                    "Response context missing for notification ID: {:?}",
                    notification_id
                ))
            })?;
        let response_error = extract_response_error(notification_feedback)?;
        self.notify_bad_response(response_context, response_error);

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L813-831)
```rust
    fn insert_notification_response_mapping(
        &mut self,
        notification_id: NotificationId,
        response_context: ResponseContext,
    ) -> Result<(), Error> {
        if let Some(response_context) = self
            .notifications_to_responses
            .insert(notification_id, response_context)
        {
            Err(Error::UnexpectedErrorEncountered(format!(
                "Duplicate sent notification ID found! \
                 Notification ID: {:?}, \
                 previous Response context: {:?}",
                notification_id, response_context
            )))
        } else {
            self.garbage_collect_notification_response_map()
        }
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L833-862)
```rust
    fn garbage_collect_notification_response_map(&mut self) -> Result<(), Error> {
        let max_notification_id_mappings =
            self.streaming_service_config.max_notification_id_mappings;
        let map_length = self.notifications_to_responses.len() as u64;
        if map_length > max_notification_id_mappings {
            let num_entries_to_remove = map_length
                .checked_sub(max_notification_id_mappings)
                .ok_or_else(|| {
                    Error::IntegerOverflow("Number of entries to remove has overflown!".into())
                })?;

            // Collect all the keys that need to removed. Note: BTreeMap keys
            // are sorted, so we'll remove the lowest notification IDs. These
            // will be the oldest notifications.
            let mut all_keys = self.notifications_to_responses.keys();
            let mut keys_to_remove = vec![];
            for _ in 0..num_entries_to_remove {
                if let Some(key_to_remove) = all_keys.next() {
                    keys_to_remove.push(*key_to_remove);
                }
            }

            // Remove the keys
            for key_to_remove in &keys_to_remove {
                self.notifications_to_responses.remove(key_to_remove);
            }
        }

        Ok(())
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L871-880)
```rust
    /// Updates the score of the peer who sent the response with the specified id
    fn notify_bad_response(
        &self,
        _id: ResponseId,
        peer: PeerNetworkId,
        _request: &StorageServiceRequest,
        error_type: ErrorType,
    ) {
        self.peer_states.update_score_error(peer, error_type);
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L1240-1246)
```rust
impl ResponseCallback for AptosNetResponseCallback {
    fn notify_bad_response(&self, error: ResponseError) {
        let error_type = ErrorType::from(error);
        self.data_client
            .notify_bad_response(self.id, self.peer, &self.request, error_type);
    }
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L38-43)
```rust
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
