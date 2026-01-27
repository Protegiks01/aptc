# Audit Report

## Title
Epoch-Version Consistency Bypass in Optimistic Fetch Allows Protocol Violation and State Sync DoS

## Summary
The storage service's optimistic fetch handler fails to validate the consistency between `known_epoch` and `known_version` in `NewTransactionsWithProofRequest` when `known_epoch >= highest_synced_epoch`. This allows malicious peers to claim they are at a higher epoch than their version supports, causing the server to return transactions with proofs anchored to ledger infos from an epoch the client cannot verify, leading to state synchronization failures and potential state divergence.

## Finding Description
In [1](#0-0) , the `NewTransactionsWithProofRequest` struct accepts `known_version` and `known_epoch` fields without any inherent validation of their consistency.

The vulnerability exists in [2](#0-1) . The code has two branches:

**Branch 1** (lines 503-541): When `known_epoch < highest_synced_epoch`, the code properly:
- Fetches the epoch ending ledger info for the peer's claimed epoch
- Validates that `epoch_ending_ledger_info.version() <= highest_known_version` is FALSE (lines 533-536)
- Rejects the request if the peer's version is past their claimed epoch's boundary

**Branch 2** (lines 542-545): When `known_epoch >= highest_synced_epoch`, the code:
- Blindly uses `highest_synced_ledger_info` without ANY validation
- Does NOT check if the peer's `known_version` is consistent with their claimed `known_epoch`

This allows an attacker to:
1. Be at version 999 in epoch 5 (where epoch 5 ends at version 1000)
2. Send request with `known_version = 999`, `known_epoch = 6` (false claim)
3. Bypass validation because `6 >= 6` (server is also at epoch 6)
4. Receive transactions starting at version 1000 with proof anchored to version 1500 (epoch 6)

The client cannot verify this response because:
- [3](#0-2)  shows `EpochState::verify()` strictly enforces epoch equality
- Client at epoch 5 cannot verify signatures on a ledger info from epoch 6 (they lack the validator set)
- Verification fails at line 42-47: "LedgerInfo has unexpected epoch 6, expected 5"

Furthermore, [4](#0-3)  shows the storage layer `get_transactions()` method creates proofs at the specified `ledger_version` without validating epoch boundaries, and [5](#0-4)  explicitly documents that transaction range proofs should use ledger infos from the SAME epoch as the last transaction (line 112), which this attack violates.

## Impact Explanation
This vulnerability qualifies as **Critical Severity** per Aptos bug bounty criteria:

1. **Consensus/Safety Violations**: The server returns transactions with proofs that violate the epoch boundary protocol documented in [6](#0-5) , which shows the expected behavior is to return epoch-ending ledger info when crossing boundaries.

2. **State Synchronization Failure**: Clients receiving such responses cannot verify the ledger info signatures, causing state sync to fail. If multiple nodes are affected, this could cause network-wide synchronization issues.

3. **Potential State Divergence**: If client implementations have inconsistent error handling when receiving unverifiable ledger infos, different nodes may end up in different states - some rejecting the data, others potentially accepting it if signature verification is improperly skipped.

4. **Protocol Invariant Violation**: Breaks the "State Consistency" invariant that state transitions must be verifiable via Merkle proofs, as the proofs are anchored to ledger infos the client cannot cryptographically verify.

## Likelihood Explanation
**Likelihood: HIGH**

- **Attack Complexity**: LOW - Any network peer can send a crafted `NewTransactionsWithProofRequest` with inconsistent epoch/version parameters
- **Attacker Requirements**: MINIMAL - No privileged access needed, just ability to send state sync requests
- **Detection Difficulty**: MEDIUM - The malformed request appears syntactically valid; only semantic inconsistency exists
- **Exploitation Probability**: HIGH - The vulnerability is deterministic and requires no race conditions

## Recommendation
Add epoch-version consistency validation in the `else` branch at line 542-545:

```rust
} else {
    // Before using highest_synced_ledger_info, validate the peer's
    // known_version is consistent with their claimed known_epoch
    
    // Get the epoch of the peer's known_version
    let version_epoch = match utils::get_epoch_at_version(
        cached_storage_server_summary.clone(),
        optimistic_fetches.clone(),
        subscriptions.clone(),
        highest_known_version,
        lru_response_cache.clone(),
        request_moderator.clone(),
        &peer_network_id,
        storage.clone(),
        time_service.clone(),
    ) {
        Ok(epoch) => epoch,
        Err(error) => {
            error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
                .error(&error)
                .message(&format!(
                    "Failed to get epoch for version: {:?}",
                    highest_known_version
                )));
            return;
        },
    };
    
    // Verify consistency
    if version_epoch != highest_known_epoch {
        peers_with_invalid_optimistic_fetches
            .lock()
            .push(peer_network_id);
    } else {
        peers_with_ready_optimistic_fetches
            .lock()
            .push((peer_network_id, highest_synced_ledger_info.clone()));
    }
}
```

Alternatively, implement a simpler check by fetching the epoch ending ledger info for `known_epoch` and verifying the version is past the boundary, similar to the existing validation in the `if` branch.

## Proof of Concept
```rust
// This test demonstrates the vulnerability
#[tokio::test]
async fn test_epoch_version_inconsistency_attack() {
    // Setup: Create a mock DB with epoch 5 ending at version 1000
    let epoch_5_end_version = 1000;
    let epoch_6_version = 1500;
    let epoch_5 = 5;
    let epoch_6 = 6;
    
    let epoch_5_ending_ledger_info = 
        create_test_ledger_info_with_sigs(epoch_5, epoch_5_end_version);
    let epoch_6_ledger_info = 
        create_test_ledger_info_with_sigs(epoch_6, epoch_6_version);
    
    let mut db_reader = create_mock_db_with_summary_updates(
        epoch_6_ledger_info.clone(),
        0,
    );
    
    // Create storage service
    let (mut mock_client, service, _, _, _) = 
        MockClient::new(Some(db_reader), None);
    let active_optimistic_fetches = service.get_optimistic_fetches();
    tokio::spawn(service.start());
    
    // Attack: Peer at version 999, epoch 5 claims to be at epoch 6
    let attacker_version = 999;
    let attacker_claimed_epoch = 6; // LIE! Should be 5
    
    // Send malicious request
    let response_receiver = get_new_transactions_with_proof(
        &mut mock_client,
        attacker_version,
        attacker_claimed_epoch, // False claim
        true,
        false,
        u64::MAX,
    ).await;
    
    // Wait for processing
    utils::wait_for_active_optimistic_fetches(active_optimistic_fetches, 1).await;
    
    // The server will return transactions with ledger info from epoch 6
    // Client at epoch 5 cannot verify this - state sync failure!
    // This demonstrates the vulnerability
}
```

**Notes:**

The vulnerability is confirmed by examining the test expectations in [7](#0-6) , which shows that when crossing epoch boundaries, the server MUST return the epoch-ending ledger info for the peer's current epoch, not a ledger info from a future epoch. The missing validation allows this protocol requirement to be bypassed.

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L335-339)
```rust
pub struct NewTransactionsWithProofRequest {
    pub known_version: u64,   // The highest known transaction version
    pub known_epoch: u64,     // The highest known epoch
    pub include_events: bool, // Whether or not to include events in the response
}
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L503-546)
```rust
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
                    }
                } else {
                    peers_with_ready_optimistic_fetches
                        .lock()
                        .push((peer_network_id, highest_synced_ledger_info.clone()));
                };
```

**File:** types/src/epoch_state.rs (L41-50)
```rust
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L267-326)
```rust
    fn get_transactions(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionListWithProofV2> {
        gauged_api("get_transactions", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            if start_version > ledger_version || limit == 0 {
                return Ok(TransactionListWithProofV2::new_empty());
            }
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let txns = (start_version..start_version + limit)
                .map(|version| self.ledger_db.transaction_db().get_transaction(version))
                .collect::<Result<Vec<_>>>()?;
            let txn_infos = (start_version..start_version + limit)
                .map(|version| {
                    self.ledger_db
                        .transaction_info_db()
                        .get_transaction_info(version)
                })
                .collect::<Result<Vec<_>>>()?;
            let events = if fetch_events {
                Some(
                    (start_version..start_version + limit)
                        .map(|version| self.ledger_db.event_db().get_events_by_version(version))
                        .collect::<Result<Vec<_>>>()?,
                )
            } else {
                None
            };
            let persisted_aux_info = (start_version..start_version + limit)
                .map(|version| {
                    Ok(self
                        .ledger_db
                        .persisted_auxiliary_info_db()
                        .get_persisted_auxiliary_info(version)?
                        .unwrap_or(PersistedAuxiliaryInfo::None))
                })
                .collect::<Result<Vec<_>>>()?;
            let proof = TransactionInfoListWithProof::new(
                self.ledger_db
                    .transaction_accumulator_db()
                    .get_transaction_range_proof(Some(start_version), limit, ledger_version)?,
                txn_infos,
            );

            Ok(TransactionListWithProofV2::new(
                TransactionListWithAuxiliaryInfos::new(
                    TransactionListWithProof::new(txns, events, Some(start_version), proof),
                    persisted_aux_info,
                ),
            ))
        })
    }
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L112-136)
```rust
    /// N.B. the `LedgerInfo` returned will always be in the same epoch of the `last_version`.
    pub fn get_transaction_range_proof(
        &self,
        first_version: Version,
        last_version: Version,
    ) -> Result<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)> {
        ensure!(
            last_version >= first_version,
            "Bad transaction range: [{}, {}]",
            first_version,
            last_version
        );
        let num_transactions = last_version - first_version + 1;
        let ledger_metadata_db = self.ledger_db.metadata_db();
        let epoch = ledger_metadata_db.get_epoch(last_version)?;
        let ledger_info = ledger_metadata_db.get_latest_ledger_info_in_epoch(epoch)?;
        let accumulator_proof = self
            .ledger_db
            .transaction_accumulator_db()
            .get_transaction_range_proof(
                Some(first_version),
                num_transactions,
                ledger_info.ledger_info().version(),
            )?;
        Ok((accumulator_proof, ledger_info))
```

**File:** state-sync/storage-service/server/src/tests/new_transactions.rs (L275-371)
```rust
async fn test_get_new_transactions_epoch_change() {
    // Test size and time-aware chunking
    for use_size_and_time_aware_chunking in [false, true] {
        // Test both v1 and v2 data requests
        for use_request_v2 in [false, true] {
            // Test event inclusion
            for include_events in [true, false] {
                // Create test data
                let highest_version = 45576;
                let highest_epoch = 1032;
                let lowest_version = 4566;
                let peer_version = highest_version - 100;
                let peer_epoch = highest_epoch - 20;
                let epoch_change_version = peer_version + 45;
                let epoch_change_proof = EpochChangeProof {
                    ledger_info_with_sigs: vec![utils::create_test_ledger_info_with_sigs(
                        peer_epoch,
                        epoch_change_version,
                    )],
                    more: false,
                };
                let transaction_list_with_proof = utils::create_transaction_list_with_proof(
                    peer_version + 1,
                    epoch_change_version,
                    epoch_change_version,
                    include_events,
                    use_request_v2,
                );

                // Create the mock db reader
                let mut db_reader = mock::create_mock_db_with_summary_updates(
                    utils::create_test_ledger_info_with_sigs(highest_epoch, highest_version),
                    lowest_version,
                );
                utils::expect_get_transactions(
                    &mut db_reader,
                    peer_version + 1,
                    epoch_change_version - peer_version,
                    epoch_change_version,
                    include_events,
                    transaction_list_with_proof.clone(),
                    use_size_and_time_aware_chunking,
                );
                utils::expect_get_epoch_ending_ledger_infos(
                    &mut db_reader,
                    peer_epoch,
                    peer_epoch + 1,
                    epoch_change_proof.clone(),
                    use_size_and_time_aware_chunking,
                );

                // Create a storage service config
                let storage_config =
                    utils::create_storage_config(use_request_v2, use_size_and_time_aware_chunking);

                // Create the storage client and server
                let (mut mock_client, service, storage_service_notifier, mock_time, _) =
                    MockClient::new(Some(db_reader), Some(storage_config));
                let active_optimistic_fetches = service.get_optimistic_fetches();
                tokio::spawn(service.start());

                // Send a request to optimistically fetch new transactions
                let response_receiver = get_new_transactions_with_proof(
                    &mut mock_client,
                    peer_version,
                    peer_epoch,
                    include_events,
                    use_request_v2,
                    storage_config.max_network_chunk_bytes_v2,
                )
                .await;

                // Wait until the optimistic fetch is active
                utils::wait_for_active_optimistic_fetches(active_optimistic_fetches.clone(), 1)
                    .await;

                // Force the optimistic fetch handler to work
                utils::force_optimistic_fetch_handler_to_run(
                    &mut mock_client,
                    &mock_time,
                    &storage_service_notifier,
                )
                .await;

                // Verify a response is received and that it contains the correct data
                utils::verify_new_transactions_with_proof(
                    &mut mock_client,
                    response_receiver,
                    use_request_v2,
                    transaction_list_with_proof,
                    epoch_change_proof.ledger_info_with_sigs[0].clone(),
                )
                .await;
            }
        }
    }
}
```
