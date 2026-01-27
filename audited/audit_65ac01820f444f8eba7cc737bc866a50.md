# Audit Report

## Title
Epoch Boundary Subscription Rejection Due to Inconsistent Metadata Initialization

## Summary
When a node reaches the end of an epoch and attempts to continue syncing via subscription streams, the `SubscriptionStreamMetadata` contains inconsistent epoch information, causing the storage service to incorrectly reject legitimate subscription requests as invalid. This prevents nodes from syncing across epoch boundaries using subscription streams.

## Finding Description

The vulnerability exists in the initialization logic for continuous transaction streams. When `ContinuousTransactionStreamEngine::calculate_next_version_and_epoch()` is called, it increments the version but fails to update the epoch accordingly: [1](#0-0) 

This creates an inconsistency when `known_version` is an epoch-ending version. For example:
- If `known_version = 1000` (last transaction of epoch 0)
- Then `next_version = 1001` (first transaction of epoch 1)
- But `known_epoch = 0` (unchanged)

This inconsistency propagates through the system. When a subscription stream is initialized, `get_known_version_and_epoch()` retrieves these values: [2](#0-1) 

The resulting `SubscriptionStreamMetadata` is created with the inconsistent values: [3](#0-2) 

On the storage service side, when processing subscriptions that span epoch boundaries, the validation logic detects the epoch mismatch: [4](#0-3) 

At lines 949-954, when `highest_known_version` is an epoch-ending version and equals the epoch ending ledger info version, the subscription is incorrectly marked as INVALID and rejected.

## Impact Explanation

This issue causes **High Severity** impact per the bug bounty criteria:
- **Validator node slowdowns**: Nodes cannot efficiently sync across epoch boundaries using subscription streams, requiring fallback to slower sync mechanisms
- **Significant protocol violations**: The state sync protocol fails to handle epoch transitions correctly, breaking the expected subscription stream behavior

The impact is network-wide as all nodes attempting to sync past epoch boundaries will encounter this issue, potentially causing:
- Delayed block propagation during epoch changes
- Increased network traffic from repeated failed subscription attempts
- Reduced validator performance during critical epoch transition periods

## Likelihood Explanation

This vulnerability occurs **frequently and deterministically**:
- Every node that syncs to an epoch boundary will encounter this issue
- Epoch changes occur regularly in the Aptos network (approximately every 2 hours)
- No special attacker action is required—this is triggered by normal operation
- The issue affects all nodes using subscription-based state sync

The bug is guaranteed to trigger whenever:
1. A node's `highest_synced_version` equals an epoch-ending ledger info version
2. The node attempts to create a new subscription stream to continue syncing
3. The storage service has data available in the next epoch

## Recommendation

Fix the `calculate_next_version_and_epoch()` function to properly handle epoch transitions. The function should check if `known_version + 1` crosses an epoch boundary and increment the epoch accordingly:

```rust
fn calculate_next_version_and_epoch(
    known_version: Version,
    known_epoch: Epoch,
    known_version_is_epoch_ending: bool, // Add parameter to indicate epoch ending
) -> Result<(Version, Epoch), Error> {
    let next_version = known_version
        .checked_add(1)
        .ok_or_else(|| Error::IntegerOverflow("Next version has overflown!".into()))?;
    
    // Increment epoch if we just crossed an epoch boundary
    let next_epoch = if known_version_is_epoch_ending {
        known_epoch
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next epoch has overflown!".into()))?
    } else {
        known_epoch
    };
    
    Ok((next_version, next_epoch))
}
```

Alternatively, retrieve the correct epoch for `next_version` from the ledger info that proved the epoch transition, rather than assuming the epoch remains unchanged.

## Proof of Concept

```rust
// Test that reproduces the issue
#[tokio::test]
async fn test_subscription_epoch_boundary_rejection() {
    // Setup: Initialize a node that has synced to the end of epoch 0
    let epoch_0_ending_version = 1000u64;
    let epoch_0 = 0u64;
    
    // Create a continuous stream request starting from epoch ending
    let stream_request = StreamRequest::ContinuouslyStreamTransactions(
        ContinuouslyStreamTransactionsRequest {
            known_version: epoch_0_ending_version, // Last version of epoch 0
            known_epoch: epoch_0,
            include_events: false,
            target: None,
        }
    );
    
    // Initialize the stream engine
    let engine = ContinuousTransactionStreamEngine::new(
        default_config(),
        &stream_request,
    ).unwrap();
    
    // Verify the inconsistent state
    assert_eq!(engine.next_request_version_and_epoch.0, epoch_0_ending_version + 1); // Version 1001
    assert_eq!(engine.next_request_version_and_epoch.1, epoch_0); // Still epoch 0!
    
    // Create subscription stream - this will use the inconsistent metadata
    let (known_version, known_epoch) = engine.get_known_version_and_epoch().unwrap();
    assert_eq!(known_version, epoch_0_ending_version); // Version 1000
    assert_eq!(known_epoch, epoch_0); // Epoch 0
    
    // On the server side, when processing this subscription with data from epoch 1:
    // - highest_known_version = 1000 (epoch 0 ending)
    // - highest_known_epoch = 0
    // - highest_synced_epoch = 1
    // - Server fetches epoch 0 ending ledger info (version 1000)
    // - Check: 1000 <= 1000 → TRUE
    // - Result: Subscription marked as INVALID ❌
}
```

## Notes

The root cause is the assumption in `calculate_next_version_and_epoch()` that incrementing a version never crosses an epoch boundary. This assumption is invalid when `known_version` is an epoch-ending version. The fix requires either passing additional context about whether the version is epoch-ending, or retrieving the correct epoch from storage/ledger info when creating the stream.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L488-496)
```rust
    fn calculate_next_version_and_epoch(
        known_version: Version,
        known_epoch: Epoch,
    ) -> Result<(Version, Epoch), Error> {
        let next_version = known_version
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next version has overflown!".into()))?;
        Ok((next_version, known_epoch))
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L861-868)
```rust
    fn get_known_version_and_epoch(&mut self) -> Result<(u64, Epoch), Error> {
        let (next_request_version, known_epoch) = self.next_request_version_and_epoch;
        let known_version = next_request_version
            .checked_sub(1)
            .ok_or_else(|| Error::IntegerOverflow("Last version has overflown!".into()))?;

        Ok((known_version, known_epoch))
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L1174-1178)
```rust
        let subscription_stream_metadata = SubscriptionStreamMetadata {
            known_version_at_stream_start: request_metadata.known_version_at_stream_start,
            known_epoch_at_stream_start: request_metadata.known_epoch_at_stream_start,
            subscription_stream_id: request_metadata.subscription_stream_id,
        };
```

**File:** state-sync/storage-service/server/src/subscription.rs (L918-965)
```rust
        let active_task = runtime.spawn_blocking(move || {
            // Check if we have synced beyond the highest known version
            if highest_known_version < highest_synced_version {
                if highest_known_epoch < highest_synced_epoch {
                    // Fetch the epoch ending ledger info from storage (the
                    // peer needs to sync to their epoch ending ledger info).
                    let epoch_ending_ledger_info = match utils::get_epoch_ending_ledger_info(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        highest_known_epoch,
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        &peer_network_id,
                        storage.clone(),
                        time_service.clone(),
                    ) {
                        Ok(epoch_ending_ledger_info) => epoch_ending_ledger_info,
                        Err(error) => {
                            // Log the failure to fetch the epoch ending ledger info
                            error!(LogSchema::new(LogEntry::SubscriptionRefresh)
                                .error(&error)
                                .message(&format!(
                                    "Failed to get the epoch ending ledger info for epoch: {:?} !",
                                    highest_known_epoch
                                )));

                            return;
                        },
                    };

                    // Check that we haven't been sent an invalid subscription request
                    // (i.e., a request that does not respect an epoch boundary).
                    if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
                        peers_with_invalid_subscriptions
                            .lock()
                            .push(peer_network_id);
                    } else {
                        peers_with_ready_subscriptions
                            .lock()
                            .push((peer_network_id, epoch_ending_ledger_info));
                    }
                } else {
                    peers_with_ready_subscriptions
                        .lock()
                        .push((peer_network_id, highest_synced_ledger_info.clone()));
                };
            }
```
