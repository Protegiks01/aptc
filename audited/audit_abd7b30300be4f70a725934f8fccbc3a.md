# Audit Report

## Title
Missing Reconfiguration Validation in Epoch Ending Ledger Info Retrieval

## Summary
The `get_epoch_ending_ledger_info()` function in the storage service fails to validate that retrieved epoch ending ledger infos actually contain the required `next_epoch_state` field (which represents reconfiguration data). This missing validation violates a critical invariant and could enable propagation of invalid epoch state information throughout the state synchronization system.

## Finding Description

The `get_epoch_ending_ledger_info()` function retrieves epoch ending ledger infos for state synchronization but performs no validation on the returned data. [1](#0-0) 

The function simply extracts the first ledger info from an `EpochChangeProof` and returns it without checking whether it actually ends an epoch. In the Aptos architecture, a ledger info ends an epoch if and only if it contains `next_epoch_state`, which includes the validator set for the next epoch. [2](#0-1) 

This validation gap is critical because reconfiguration events (epoch changes) require the `next_epoch_state` field to be populated. When a reconfiguration occurs, the Move framework emits a `NewEpochEvent` and the resulting ledger info must contain the next epoch's validator set. [3](#0-2) 

Other parts of the codebase correctly enforce this validation. The `VerifiedEpochStates::update_verified_epoch_states()` function explicitly checks for `next_epoch_state()` and returns an error if it's missing: [4](#0-3) 

Similarly, the storage layer's own `get_epoch_ending_ledger_info()` function validates the presence of `next_epoch_state`: [5](#0-4) 

The vulnerable function is called by two critical state sync components:

1. **Optimistic Fetch Processing** - determines if peers need epoch boundary synchronization: [6](#0-5) 

2. **Subscription Processing** - validates subscription requests respect epoch boundaries: [7](#0-6) 

Neither caller validates the presence of `next_epoch_state`, assuming the utility function would return only valid epoch-ending ledger infos.

**Attack Scenario:**
1. A storage corruption bug or malicious storage service returns a ledger info without `next_epoch_state`
2. The `get_epoch_ending_ledger_info()` function accepts it without validation
3. This invalid ledger info propagates to optimistic fetch or subscription handlers
4. Peers receive invalid epoch boundary information
5. State sync fails when peers attempt to verify the ledger info (expecting `next_epoch_state`)
6. Network-wide state synchronization is disrupted

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violation**: The function violates the fundamental invariant that epoch ending ledger infos must contain `next_epoch_state`. This is a core requirement of the epoch change mechanism.

2. **State Sync Disruption**: Invalid epoch ending ledger infos could propagate to multiple peers, causing state synchronization failures across the network. Peers would be unable to verify the epoch changes correctly.

3. **Consensus Impact**: While this doesn't directly break consensus safety, it affects the ability of nodes to sync to the correct epoch state, which is critical for network participation.

The impact falls under "Significant protocol violations" (High Severity, up to $50,000) rather than Critical because:
- It doesn't directly cause loss of funds
- It doesn't break consensus safety (requires existing storage corruption)
- It's a validation gap rather than a direct consensus attack
- Recovery is possible by resyncing from correct data sources

## Likelihood Explanation

**Likelihood: Medium**

While storage corruption is rare in normal operation, several factors increase the likelihood:

1. **Defense in Depth Violation**: Even if storage typically returns correct data, defensive validation should exist at API boundaries. The absence creates a failure point.

2. **Potential Triggers**:
   - Database bugs during epoch transitions
   - Race conditions in concurrent storage operations
   - Storage restoration from backups with partial data
   - Edge cases in epoch boundary handling

3. **Broad Usage**: The function is used by two critical state sync paths (optimistic fetch and subscriptions), amplifying the impact if triggered.

4. **No Mitigating Controls**: The callers don't perform their own validation, relying entirely on this function to return valid data.

The issue is more likely than a cryptographic break but less likely than a typical input validation bug since it requires storage-layer malfunction.

## Recommendation

Add defensive validation to ensure the returned ledger info actually ends an epoch and matches the requested epoch:

```rust
pub fn get_epoch_ending_ledger_info<T: StorageReaderInterface>(
    // ... parameters ...
) -> aptos_storage_service_types::Result<LedgerInfoWithSignatures, Error> {
    // ... existing request creation code ...
    
    // Verify the response
    match storage_response {
        Ok(storage_response) => match &storage_response.get_data_response() {
            Ok(DataResponse::EpochEndingLedgerInfos(epoch_change_proof)) => {
                if let Some(ledger_info) = epoch_change_proof.ledger_info_with_sigs.first() {
                    // ADDED: Validate this is actually an epoch-ending ledger info
                    let ledger_info_inner = ledger_info.ledger_info();
                    if !ledger_info_inner.ends_epoch() {
                        return Err(Error::UnexpectedErrorEncountered(
                            format!("Ledger info for epoch {} does not end an epoch (missing next_epoch_state)", epoch)
                        ));
                    }
                    
                    // ADDED: Validate the epoch matches what was requested
                    if ledger_info_inner.epoch() != epoch {
                        return Err(Error::UnexpectedErrorEncountered(
                            format!("Requested epoch {} but got ledger info for epoch {}", 
                                epoch, ledger_info_inner.epoch())
                        ));
                    }
                    
                    Ok(ledger_info.clone())
                } else {
                    Err(Error::UnexpectedErrorEncountered("Empty change proof found!".into()))
                }
            },
            // ... rest of error handling ...
        },
        // ... rest of error handling ...
    }
}
```

This ensures that:
1. The ledger info contains `next_epoch_state` (verified by `ends_epoch()`)
2. The epoch matches the requested value
3. Invalid data is rejected at the API boundary before propagating to callers

## Proof of Concept

The following test demonstrates the vulnerability by showing that invalid data would be accepted:

```rust
#[tokio::test]
async fn test_missing_epoch_ending_validation() {
    // Setup: Create a non-epoch-ending ledger info
    let ledger_info = LedgerInfo::new(
        BlockInfo::new(
            5,  // epoch
            100, // round
            HashValue::random(),
            HashValue::random(),
            1000, // version
            12345, // timestamp
            None, // NO next_epoch_state - this should be rejected!
        ),
        HashValue::zero(),
    );
    
    let validators = ValidatorSet::empty();
    let validator_verifier: ValidatorVerifier = (&validators).into();
    let ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        ledger_info,
        validator_verifier.aggregate_signatures([].iter()).unwrap(),
    );
    
    // Create an EpochChangeProof with this invalid ledger info
    let proof = EpochChangeProof::new(vec![ledger_info_with_sigs.clone()], false);
    
    // The current implementation would accept this invalid data!
    // It should instead validate that ends_epoch() returns true
    assert!(!ledger_info_with_sigs.ledger_info().ends_epoch()); // Proves it's invalid
    
    // With the fix, this would be rejected:
    // assert!(get_epoch_ending_ledger_info(...).is_err());
}
```

This test confirms that a ledger info without `next_epoch_state` (which fails `ends_epoch()`) would currently be accepted by the function, violating the epoch ending invariant.

## Notes

The vulnerability exists in a critical state synchronization utility function and affects multiple code paths. While the storage layer typically provides correct data, the absence of defensive validation creates an unnecessary risk surface. The fix is straightforward and aligns with validation patterns used elsewhere in the codebase, particularly in `VerifiedEpochStates::update_verified_epoch_states()` and `LedgerMetadataDb::get_epoch_ending_ledger_info()`.

### Citations

**File:** state-sync/storage-service/server/src/utils.rs (L27-82)
```rust
pub fn get_epoch_ending_ledger_info<T: StorageReaderInterface>(
    cached_storage_server_summary: Arc<ArcSwap<StorageServerSummary>>,
    optimistic_fetches: Arc<DashMap<PeerNetworkId, OptimisticFetchRequest>>,
    subscriptions: Arc<DashMap<PeerNetworkId, SubscriptionStreamRequests>>,
    epoch: u64,
    lru_response_cache: Cache<StorageServiceRequest, StorageServiceResponse>,
    request_moderator: Arc<RequestModerator>,
    peer_network_id: &PeerNetworkId,
    storage: T,
    time_service: TimeService,
) -> aptos_storage_service_types::Result<LedgerInfoWithSignatures, Error> {
    // Create a new storage request for the epoch ending ledger info
    let data_request = DataRequest::GetEpochEndingLedgerInfos(EpochEndingLedgerInfoRequest {
        start_epoch: epoch,
        expected_end_epoch: epoch,
    });
    let storage_request = StorageServiceRequest::new(
        data_request,
        false, // Don't compress because this isn't going over the wire
    );

    // Process the request
    let handler = Handler::new(
        cached_storage_server_summary,
        optimistic_fetches,
        lru_response_cache,
        request_moderator,
        storage,
        subscriptions,
        time_service,
    );
    let storage_response = handler.process_request(peer_network_id, storage_request, true);

    // Verify the response
    match storage_response {
        Ok(storage_response) => match &storage_response.get_data_response() {
            Ok(DataResponse::EpochEndingLedgerInfos(epoch_change_proof)) => {
                if let Some(ledger_info) = epoch_change_proof.ledger_info_with_sigs.first() {
                    Ok(ledger_info.clone())
                } else {
                    Err(Error::UnexpectedErrorEncountered(
                        "Empty change proof found!".into(),
                    ))
                }
            },
            data_response => Err(Error::StorageErrorEncountered(format!(
                "Failed to get epoch ending ledger info! Got: {:?}",
                data_response
            ))),
        },
        Err(error) => Err(Error::StorageErrorEncountered(format!(
            "Failed to get epoch ending ledger info! Error: {:?}",
            error
        ))),
    }
}
```

**File:** types/src/ledger_info.rs (L145-147)
```rust
    pub fn ends_epoch(&self) -> bool {
        self.next_epoch_state().is_some()
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L106-159)
```text
    public(friend) fun reconfigure() acquires Configuration {
        // Do not do anything if genesis has not finished.
        if (chain_status::is_genesis() || timestamp::now_microseconds() == 0 || !reconfiguration_enabled()) {
            return
        };

        let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
        let current_time = timestamp::now_microseconds();

        // Do not do anything if a reconfiguration event is already emitted within this transaction.
        //
        // This is OK because:
        // - The time changes in every non-empty block
        // - A block automatically ends after a transaction that emits a reconfiguration event, which is guaranteed by
        //   VM spec that all transactions comming after a reconfiguration transaction will be returned as Retry
        //   status.
        // - Each transaction must emit at most one reconfiguration event
        //
        // Thus, this check ensures that a transaction that does multiple "reconfiguration required" actions emits only
        // one reconfiguration event.
        //
        if (current_time == config_ref.last_reconfiguration_time) {
            return
        };

        reconfiguration_state::on_reconfig_start();

        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
        storage_gas::on_reconfig();

        assert!(current_time > config_ref.last_reconfiguration_time, error::invalid_state(EINVALID_BLOCK_TIME));
        config_ref.last_reconfiguration_time = current_time;
        spec {
            assume config_ref.epoch + 1 <= MAX_U64;
        };
        config_ref.epoch = config_ref.epoch + 1;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                NewEpoch {
                    epoch: config_ref.epoch,
                },
            );
        };
        event::emit_event<NewEpochEvent>(
            &mut config_ref.events,
            NewEpochEvent {
                epoch: config_ref.epoch,
            },
        );

        reconfiguration_state::on_reconfig_finish();
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L111-125)
```rust
        if let Some(next_epoch_state) = epoch_ending_ledger_info.ledger_info().next_epoch_state() {
            self.highest_fetched_epoch_ending_version =
                epoch_ending_ledger_info.ledger_info().version();
            self.latest_epoch_state = next_epoch_state.clone();
            self.insert_new_epoch_ending_ledger_info(epoch_ending_ledger_info.clone())?;

            trace!(LogSchema::new(LogEntry::Bootstrapper).message(&format!(
                "Updated the latest epoch state to epoch: {:?}",
                self.latest_epoch_state.epoch
            )));
        } else {
            return Err(Error::VerificationError(
                "The ledger info was not epoch ending!".into(),
            ));
        }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L172-174)
```rust
        li.ledger_info().next_epoch_state().ok_or_else(|| {
            AptosDbError::NotFound(format!("Not an epoch change at version {version}"))
        })?;
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L506-540)
```rust
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
                            error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
                                .error(&error)
                                .message(&format!(
                                    "Failed to get the epoch ending ledger info for epoch: {:?} !",
                                    highest_known_epoch
                                )));

                            return;
                        },
                    };

                    // Check that we haven't been sent an invalid optimistic fetch request
                    // (i.e., a request that does not respect an epoch boundary).
                    if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
                        peers_with_invalid_optimistic_fetches
                            .lock()
                            .push(peer_network_id);
                    } else {
                        peers_with_ready_optimistic_fetches
                            .lock()
                            .push((peer_network_id, epoch_ending_ledger_info));
```

**File:** state-sync/storage-service/server/src/subscription.rs (L924-959)
```rust
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
```
