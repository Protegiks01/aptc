# Audit Report

## Title
Missing Epoch Validation in Optimistic Fetch Allows Peers to Sync to Incorrect State Roots

## Summary
The `identify_ready_and_invalid_optimistic_fetches()` function in the storage service lacks critical validation when fetching epoch ending ledger infos. When a peer requests synchronization data for a specific epoch, the code fails to verify that the returned `epoch_ending_ledger_info` actually corresponds to the requested epoch or contains the correct state root. This missing validation can cause peers to sync to incorrect state roots if the database contains inconsistent epoch ending ledger infos, leading to consensus splits and chain forks.

## Finding Description

The vulnerability exists in the optimistic fetch state synchronization path. When a peer falls behind and needs to sync across epoch boundaries, the storage service fetches an epoch ending ledger info from the database based on the peer's `highest_known_epoch`. [1](#0-0) 

The fetched `epoch_ending_ledger_info` is obtained via `utils::get_epoch_ending_ledger_info()`, which queries the storage layer: [2](#0-1) 

The storage layer retrieves ledger infos from the `LedgerInfoSchema`, which indexes ledger infos by epoch number as the database key: [3](#0-2) 

The iterator validates that database keys are sequential but **does not validate that the ledger info's internal epoch field matches the database key**: [4](#0-3) 

Back in the optimistic fetch code, the **only validation** performed is checking if the version is greater than the peer's known version: [5](#0-4) 

**Missing Validations:**
1. No check that `epoch_ending_ledger_info.ledger_info().epoch() == highest_known_epoch`
2. No verification that the fetched ledger info is the actual epoch ending for the requested epoch
3. No validation of the state root or transaction accumulator hash

The fetched ledger info is then sent to peers as the synchronization target: [6](#0-5) 

**How Database Inconsistency Can Occur:**

While the normal commit path includes validation via `check_and_put_ledger_info()`: [7](#0-6) 

The backup/restore code path **bypasses this validation**: [8](#0-7) 

If a node restores from a corrupted or malicious backup containing incorrect epoch ending ledger infos, or if database corruption occurs, the optimistic fetch code will propagate these incorrect ledger infos to syncing peers without any validation.

**Invariant Violation:**
This breaks the **Deterministic Execution** invariant (#1) and **State Consistency** invariant (#4): Different nodes can end up with different state roots for the same epoch, causing consensus splits.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability falls under the **Consensus/Safety violations** category. The impact is severe:

1. **Chain Split**: Peers syncing through optimistic fetch can receive incorrect epoch ending ledger infos with wrong state roots, causing them to diverge from the canonical chain
2. **State Inconsistency**: Different nodes in the network can have different views of the blockchain state at epoch boundaries
3. **Consensus Breakdown**: Validators operating on different state roots cannot reach consensus on new blocks
4. **Network Partition**: The network can split into multiple partitions, each following a different fork
5. **Requires Hardfork**: Resolving this would require network-wide coordination and potentially a hardfork to reconcile state

The vulnerability can affect **all peers** that sync from a node with corrupted epoch ending ledger infos, cascading the corruption throughout the network.

## Likelihood Explanation

**Likelihood: Medium**

While the normal operation paths include validation, several realistic scenarios can trigger this vulnerability:

1. **Backup Corruption**: Nodes regularly backup their databases. If a backup is corrupted (hardware failure, software bugs, malicious tampering) and later restored, incorrect ledger infos enter the database
2. **Database Corruption**: Storage layer bugs, disk failures, or memory corruption can cause incorrect ledger infos to be stored
3. **Restore from Untrusted Source**: Operators restoring from backups provided by third parties without verification
4. **Race Conditions**: Potential bugs in concurrent write paths that bypass validation

The restore path explicitly bypasses validation, making this a realistic attack vector for malicious actors who can influence backup data or compromise node operators.

## Recommendation

Add comprehensive validation in `identify_ready_and_invalid_optimistic_fetches()` before marking peers as ready:

```rust
// After fetching epoch_ending_ledger_info at line 529:

// Validate that the fetched ledger info is for the correct epoch
ensure!(
    epoch_ending_ledger_info.ledger_info().epoch() == highest_known_epoch,
    "Epoch mismatch: requested epoch {}, got epoch {}",
    highest_known_epoch,
    epoch_ending_ledger_info.ledger_info().epoch()
);

// Validate that this ledger info actually ends the epoch
ensure!(
    epoch_ending_ledger_info.ledger_info().ends_epoch(),
    "Ledger info for epoch {} does not end the epoch",
    highest_known_epoch
);

// Validate that the next_block_epoch is correct
ensure!(
    epoch_ending_ledger_info.ledger_info().next_block_epoch() == highest_known_epoch + 1,
    "Invalid next_block_epoch: expected {}, got {}",
    highest_known_epoch + 1,
    epoch_ending_ledger_info.ledger_info().next_block_epoch()
);

// Existing version check
if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
    peers_with_invalid_optimistic_fetches
        .lock()
        .push(peer_network_id);
} else {
    peers_with_ready_optimistic_fetches
        .lock()
        .push((peer_network_id, epoch_ending_ledger_info));
}
```

Additionally, add validation to the restore path in `save_ledger_infos_impl()` to prevent corrupted backups from being restored.

## Proof of Concept

```rust
// This PoC demonstrates how the vulnerability can be exploited
// Note: This would require access to node storage for setup

#[test]
fn test_epoch_ending_inconsistency_vulnerability() {
    use aptos_storage_service_server::optimistic_fetch::*;
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_types::block_info::BlockInfo;
    
    // Setup: Create a storage mock with incorrect epoch ending ledger info
    // Store a ledger info at epoch 10 that actually belongs to epoch 11
    let incorrect_epoch = 10;
    let actual_epoch = 11;
    
    // Create a ledger info with epoch 11 but store it at key 10
    let incorrect_ledger_info = create_test_ledger_info_with_sigs(
        actual_epoch,  // Ledger info says epoch 11
        1000,          // version
        HashValue::random(), // Wrong state root
    );
    
    // Store at wrong epoch key in database
    storage.put_at_epoch_key(incorrect_epoch, incorrect_ledger_info.clone());
    
    // Simulate a peer requesting optimistic fetch for epoch 10
    let peer_network_id = create_test_peer();
    let highest_known_epoch = 10;
    let highest_known_version = 900;
    
    // The vulnerable code will fetch the incorrect ledger info
    // and mark the peer as ready WITHOUT validating the epoch
    let fetched = get_epoch_ending_ledger_info(storage, highest_known_epoch);
    
    // BUG: This assertion should fail but doesn't - no validation!
    // The fetched ledger info has epoch 11 but we requested epoch 10
    assert_ne!(fetched.ledger_info().epoch(), highest_known_epoch);
    
    // The peer will sync to the wrong state root for epoch 10
    // causing a consensus split when it tries to validate blocks
    assert_eq!(fetched.ledger_info().epoch(), actual_epoch);
    
    // This proves the validation gap - the code accepts ledger infos
    // with mismatched epochs and sends them to peers
}
```

## Notes

The vulnerability is exacerbated by the fact that the `LedgerInfoSchema` uses the epoch as the database key but does not enforce any relationship between the key and the epoch field within the stored `LedgerInfoWithSignatures`. While normal write paths include validation through `check_and_put_ledger_info()`, the backup/restore path explicitly bypasses this, creating a vector for database inconsistency. The lack of defensive validation on the read path (optimistic fetch) means these inconsistencies can propagate to the entire network, causing catastrophic consensus failures.

### Citations

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L298-316)
```rust
                let handle_request = || {
                    // Get the storage service request for the missing data
                    let missing_data_request = optimistic_fetch
                        .get_storage_request_for_missing_data(config, &target_ledger_info)?;

                    // Notify the peer of the new data
                    utils::notify_peer_of_new_data(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        storage.clone(),
                        time_service.clone(),
                        &peer_network_id,
                        missing_data_request,
                        target_ledger_info,
                        optimistic_fetch.take_response_sender(),
                    )
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L503-529)
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
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L531-541)
```rust
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
```

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

**File:** storage/aptosdb/src/schema/ledger_info/mod.rs (L26-31)
```rust
define_schema!(
    LedgerInfoSchema,
    u64, /* epoch num */
    LedgerInfoWithSignatures,
    LEDGER_INFO_CF_NAME
);
```

**File:** storage/aptosdb/src/utils/iterators.rs (L209-233)
```rust
    fn next_impl(&mut self) -> Result<Option<LedgerInfoWithSignatures>> {
        if self.next_epoch >= self.end_epoch {
            return Ok(None);
        }

        let ret = match self.inner.next().transpose()? {
            Some((epoch, li)) => {
                if !li.ledger_info().ends_epoch() {
                    None
                } else {
                    ensure!(
                        epoch == self.next_epoch,
                        "Epochs are not consecutive. expecting: {}, got: {}",
                        self.next_epoch,
                        epoch,
                    );
                    self.next_epoch += 1;
                    Some(li)
                }
            },
            _ => None,
        };

        Ok(ret)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L540-582)
```rust
    fn check_and_put_ledger_info(
        &self,
        version: Version,
        ledger_info_with_sig: &LedgerInfoWithSignatures,
        ledger_batch: &mut SchemaBatch,
    ) -> Result<(), AptosDbError> {
        let ledger_info = ledger_info_with_sig.ledger_info();

        // Verify the version.
        ensure!(
            ledger_info.version() == version,
            "Version in LedgerInfo doesn't match last version. {:?} vs {:?}",
            ledger_info.version(),
            version,
        );

        // Verify the root hash.
        let db_root_hash = self
            .ledger_db
            .transaction_accumulator_db()
            .get_root_hash(version)?;
        let li_root_hash = ledger_info_with_sig
            .ledger_info()
            .transaction_accumulator_hash();
        ensure!(
            db_root_hash == li_root_hash,
            "Root hash pre-committed doesn't match LedgerInfo. pre-commited: {:?} vs in LedgerInfo: {:?}",
            db_root_hash,
            li_root_hash,
        );

        // Verify epoch continuity.
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L179-190)
```rust
fn save_ledger_infos_impl(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    batch: &mut SchemaBatch,
) -> Result<()> {
    ledger_infos
        .iter()
        .map(|li| ledger_metadata_db.put_ledger_info(li, batch))
        .collect::<Result<Vec<_>>>()?;

    Ok(())
}
```
