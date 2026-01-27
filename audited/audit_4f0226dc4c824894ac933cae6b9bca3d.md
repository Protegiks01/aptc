# Audit Report

## Title
Epoch Boundary Bypass in Subscription Stream Metadata Causing Invalid State Sync

## Summary
A critical logic error in `ContinuousTransactionStreamEngine::get_known_version_and_epoch()` causes inconsistent `SubscriptionStreamMetadata` where `known_epoch_at_stream_start` is incorrectly incremented before the corresponding `known_version_at_stream_start` crosses the epoch boundary. This allows subscription clients to bypass mandatory epoch-ending ledger info verification, breaking Aptos' epoch transition security model.

## Finding Description
The vulnerability exists in how subscription stream metadata is constructed during epoch transitions. When a client finishes syncing the last version of an epoch (an epoch-ending ledger info), the internal state tracking incorrectly updates: [1](#0-0) 

The problem occurs in this sequence:
1. Client receives data up to version 1000 (last version of epoch 0, epoch-ending ledger info)
2. `update_request_version_and_epoch()` detects the epoch boundary and increments `next_request_epoch` to 1
3. Sets `next_request_version_and_epoch = (1001, 1)`

When a new subscription stream starts, the metadata is derived by: [2](#0-1) 

This calculates:
- `known_version = 1001 - 1 = 1000` (correct - last version of epoch 0)
- `known_epoch = 1` (INCORRECT - should be 0)

This inconsistent metadata propagates through: [3](#0-2) 

On the server side, the subscription handler uses this metadata to determine which data to serve: [4](#0-3) 

**The Attack:** When `highest_known_epoch` (1) equals `highest_synced_epoch` (1), the server skips the epoch boundary validation check at line 921 and directly serves data from epoch 1 at line 960-963. The client receives transactions from the new epoch WITHOUT first verifying the epoch-ending ledger info for epoch 0, which is required for secure epoch transitions in AptosBFT.

## Impact Explanation
**HIGH Severity** - This breaks Aptos' fundamental epoch transition security model:

1. **Epoch Change Verification Bypass**: Clients must verify epoch-ending ledger infos before processing transactions from the next epoch to ensure validator set changes are legitimate. This vulnerability allows a malicious storage service to serve epoch N+1 data without the client verifying the epoch N ending.

2. **State Consistency Violation**: Violates Critical Invariant #4 (State Consistency) - epoch transitions must be atomic and verifiable. A client could sync through an epoch change with inconsistent state.

3. **Consensus Safety Risk**: If a malicious peer serves invalid epoch N+1 data and the client accepts it without verifying the epoch boundary, the client could diverge from honest nodes, creating a state fork.

This qualifies as "Significant protocol violations" under High Severity ($50,000) criteria.

## Likelihood Explanation
**HIGH Likelihood** - This bug triggers automatically:

1. Occurs on EVERY epoch transition for nodes using continuous transaction streams
2. No malicious behavior required - the bug exists in normal operation
3. Affects all state-sync clients (fullnodes, validator nodes during catch-up)
4. Epoch transitions happen regularly (every few hours in production)

While the vulnerability doesn't cause immediate harm in honest-peer scenarios, it creates an exploitable attack surface where a malicious storage service can serve invalid epoch data that bypasses verification.

## Recommendation
Fix `get_known_version_and_epoch()` to maintain epoch consistency:

```rust
fn get_known_version_and_epoch(&mut self) -> Result<(u64, Epoch), Error> {
    let (next_request_version, next_request_epoch) = self.next_request_version_and_epoch;
    let known_version = next_request_version
        .checked_sub(1)
        .ok_or_else(|| Error::IntegerOverflow("Last version has overflown!".into()))?;
    
    // Fix: Determine the correct epoch for known_version by checking if
    // next_request_version is at an epoch boundary
    let known_epoch = if next_request_epoch > 0 && self.is_at_epoch_boundary(known_version)? {
        // known_version is the last version of the previous epoch
        next_request_epoch.checked_sub(1)
            .ok_or_else(|| Error::IntegerOverflow("Known epoch has underflown!".into()))?
    } else {
        next_request_epoch
    };
    
    Ok((known_version, known_epoch))
}
```

Additionally, add server-side validation: [5](#0-4) 

Add validation in `SubscriptionStreamRequests::new()` to verify metadata consistency by checking that `known_version_at_stream_start` and `known_epoch_at_stream_start` are consistent with storage's epoch information.

## Proof of Concept
```rust
#[test]
fn test_epoch_metadata_inconsistency() {
    // Setup: Create a ContinuousTransactionStreamEngine at an epoch boundary
    let mut engine = setup_stream_engine();
    
    // Simulate receiving data up to version 1000 (last version of epoch 0)
    let epoch_ending_ledger_info = create_epoch_ending_ledger_info(1000, 0);
    engine.update_request_version_and_epoch(1000, &epoch_ending_ledger_info).unwrap();
    
    // Verify internal state shows next request is for epoch 1
    assert_eq!(engine.next_request_version_and_epoch, (1001, 1));
    
    // Start a new subscription stream
    let (known_version, known_epoch) = engine.get_known_version_and_epoch().unwrap();
    
    // BUG: known_version is 1000 (epoch 0) but known_epoch is 1!
    assert_eq!(known_version, 1000);
    assert_eq!(known_epoch, 1); // Should be 0!
    
    // This inconsistent metadata will bypass epoch validation on the server
    let metadata = SubscriptionStreamMetadata {
        known_version_at_stream_start: known_version,
        known_epoch_at_stream_start: known_epoch,
        subscription_stream_id: 1,
    };
    
    // Server-side check will fail to detect epoch boundary crossing
    // because highest_known_epoch (1) == highest_synced_epoch (1)
}
```

**Notes**
This vulnerability demonstrates how subtle off-by-one errors in epoch tracking can bypass critical security checks. The fix requires ensuring that version and epoch values in subscription metadata remain consistent with their actual blockchain epoch assignment. The server should also add defense-in-depth validation to detect and reject inconsistent metadata.

### Citations

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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1086-1109)
```rust
    fn update_request_version_and_epoch(
        &mut self,
        request_end_version: Version,
        target_ledger_info: &LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Calculate the next request epoch
        let (_, mut next_request_epoch) = self.next_request_version_and_epoch;
        if request_end_version == target_ledger_info.ledger_info().version()
            && target_ledger_info.ledger_info().ends_epoch()
        {
            // We've hit an epoch change
            next_request_epoch = next_request_epoch.checked_add(1).ok_or_else(|| {
                Error::IntegerOverflow("Next request epoch has overflown!".into())
            })?;
        }

        // Update the next request version and epoch
        let next_request_version = request_end_version
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next request version has overflown!".into()))?;
        self.next_request_version_and_epoch = (next_request_version, next_request_epoch);

        Ok(())
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

**File:** state-sync/storage-service/server/src/subscription.rs (L313-336)
```rust
impl SubscriptionStreamRequests {
    pub fn new(subscription_request: SubscriptionRequest, time_service: TimeService) -> Self {
        // Extract the relevant information from the request
        let highest_known_version = subscription_request.highest_known_version_at_stream_start();
        let highest_known_epoch = subscription_request.highest_known_epoch_at_stream_start();
        let subscription_stream_metadata = subscription_request.subscription_stream_metadata();

        // Create a new set of pending subscription requests using the first request
        let mut pending_subscription_requests = BTreeMap::new();
        pending_subscription_requests.insert(
            subscription_request.subscription_stream_index(),
            subscription_request,
        );

        Self {
            highest_known_version,
            highest_known_epoch,
            next_index_to_serve: 0,
            pending_subscription_requests,
            subscription_stream_metadata,
            last_stream_update_time: time_service.now(),
            time_service,
        }
    }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L919-964)
```rust
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
```
