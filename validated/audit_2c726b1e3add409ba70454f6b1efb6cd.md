# Audit Report

## Title
Epoch Ending Ledger Info Truncation Causes Synchronization Failures During Protocol Upgrades

## Summary
The storage layer's hard limit of 100 epochs combined with incorrect `more` flag handling in the new size-aware chunking implementation causes nodes to fail synchronization when they need to sync through more than 100 epochs. This breaks state synchronization during protocol upgrades that shorten epoch duration.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Database Layer Silent Truncation**

The database layer enforces a hard limit of 100 epochs through the `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` constant: [1](#0-0) 

The `get_epoch_ending_ledger_info_iterator` implementation applies this limit regardless of the requested range: [2](#0-1) 

When a client requests epochs 0-200, the iterator only returns epochs 0-99 due to this truncation (line 579-583).

**2. Storage Service Incorrect `more` Flag**

The new size-aware chunking implementation always sets `more=false` when creating the `EpochChangeProof`, even when the iterator returns incomplete data: [3](#0-2) 

At line 289, the code creates `EpochChangeProof::new(epoch_ending_ledger_infos, false)` with hardcoded `false`. When the iterator exhausts early (lines 276-283), a warning is logged but the `more` flag remains incorrectly set to `false`.

In contrast, the legacy implementation correctly propagates the `more` flag from the database layer: [4](#0-3) 

The underlying implementation properly calculates the `more` flag based on whether the request exceeds the limit: [5](#0-4) 

At lines 1044-1048, the `more` flag is correctly calculated as `true` when `end_epoch - start_epoch > limit`.

**3. TrustedState Verification Failure**

The `TrustedState::verify_and_ratchet_inner` method uses the `more` flag to determine if an incomplete epoch change proof is acceptable: [6](#0-5) 

At lines 183-186, when `latest_li.ledger_info().epoch() > new_epoch` and `epoch_change_proof.more` is `false`, the verification fails with "Inconsistent epoch change proof and latest ledger info". If `more` were correctly set to `true`, it would accept the partial proof.

This behavior is confirmed by unit tests: [7](#0-6) 

The test `test_ratchet_succeeds_with_more` explicitly verifies that with `more=false` and a gap, verification fails (lines 390-393), but with `more=true`, verification succeeds (lines 395-399).

**Configuration Context**

The vulnerability is currently mitigated on mainnet because the default configuration disables size-aware chunking: [8](#0-7) 

At line 198, `enable_size_and_time_aware_chunking` defaults to `false`.

However, the config optimizer enables it for non-mainnet networks: [9](#0-8) 

At lines 623-627, the optimizer enables the feature for all non-mainnet chains when `ENABLE_SIZE_AND_TIME_AWARE_CHUNKING` is `true`.

The constant at line 14 indicates intent to enable globally once stable: [10](#0-9) 

Additionally, the default `max_epoch_chunk_size` of 200 exceeds the database limit of 100: [11](#0-10) 

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes significant protocol violations:

1. **Network Synchronization Failure**: Testnets and devnets using the new chunking implementation cannot synchronize when more than 100 epochs need to be fetched. This is a complete synchronization failure, not just performance degradation, affecting nodes' ability to participate in the network.

2. **Upgrade Deployment Blocking**: Protocol upgrades that shorten epoch duration would fail validation on testnets, blocking mainnet deployment of critical upgrades.

3. **Bootstrap Failures**: New validators or nodes recovering from extended downtime cannot bootstrap if they fall behind by more than 100 epochs.

This qualifies as HIGH severity under "Validator Node Slowdowns" criteria, though it's more severe than slowdowns—it's a complete inability to synchronize. The vulnerability is a latent time-bomb for mainnet, currently protected by legacy implementation but will activate when size-aware chunking is enabled network-wide.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability triggers automatically when:
- Network uses new size-aware chunking (currently: testnets/devnets, planned: mainnet)
- Any node needs to sync through >100 epochs (new nodes, offline nodes, protocol upgrades)

**Current Exposure:**
- Testnets/Devnets: Vulnerable NOW (feature auto-enabled by ConfigOptimizer)
- Mainnet: Protected but migration planned per code comments

**Triggering Scenarios:**
- Protocol upgrade shortening epoch duration from 6h to 30min → nodes offline 2 days need ~96 epochs (approaching limit)
- Multiple epoch-shortening upgrades accumulate beyond 100 epochs
- New validators joining after network has >100 epochs
- Validators falling behind during network transitions

## Recommendation

Fix the `get_epoch_ending_ledger_infos_by_size` method to correctly calculate and propagate the `more` flag instead of hardcoding it to `false`:

```rust
// Calculate if there's more data beyond what we fetched
let more = epoch_ending_ledger_infos.len() < num_ledger_infos_to_fetch as usize
    || num_ledger_infos_to_fetch < expected_num_ledger_infos;

// Create the epoch change proof with correct more flag
let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, more);
```

Additionally, consider either:
1. Increasing `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` limit, or
2. Ensuring `max_epoch_chunk_size` default doesn't exceed database limits, or
3. Implementing proper iterator-based API for very old clients per the TODO comment

## Proof of Concept

The vulnerability can be demonstrated on testnet by:

1. Waiting for testnet to accumulate >100 epochs
2. Starting a new node that needs to sync from genesis
3. Node will request epochs 0-200 (based on `max_epoch_chunk_size` default)
4. Storage service returns epochs 0-99 with `more=false` (bug)
5. If advertised ledger info is in epoch 150, verification fails with "Inconsistent epoch change proof and latest ledger info"
6. Node cannot progress synchronization

This can be verified by examining logs for the warning message at `state-sync/storage-service/server/src/storage.rs:278-282` followed by synchronization failure.

## Notes

This is a legitimate protocol implementation bug with clear code evidence. While currently mitigated on mainnet by configuration, it actively affects testnets/devnets and represents a blocking issue for mainnet deployment of the size-aware chunking feature. The bug must be fixed before enabling the feature on mainnet to prevent synchronization failures during protocol upgrades or normal operations requiring >100 epoch sync.

### Citations

**File:** storage/aptosdb/src/common.rs (L7-9)
```rust
// TODO: Either implement an iteration API to allow a very old client to loop through a long history
// or guarantee that there is always a recent enough waypoint and client knows to boot from there.
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L66-76)
```rust
    fn get_epoch_ending_ledger_infos(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<EpochChangeProof> {
        gauged_api("get_epoch_ending_ledger_infos", || {
            let (ledger_info_with_sigs, more) =
                Self::get_epoch_ending_ledger_infos(self, start_epoch, end_epoch)?;
            Ok(EpochChangeProof::new(ledger_info_with_sigs, more))
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L572-595)
```rust
    fn get_epoch_ending_ledger_info_iterator(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<LedgerInfoWithSignatures>> + '_>> {
        gauged_api("get_epoch_ending_ledger_info_iterator", || {
            self.check_epoch_ending_ledger_infos_request(start_epoch, end_epoch)?;
            let limit = std::cmp::min(
                end_epoch.saturating_sub(start_epoch),
                MAX_NUM_EPOCH_ENDING_LEDGER_INFO as u64,
            );
            let end_epoch = start_epoch.saturating_add(limit);

            let iter = self
                .ledger_db
                .metadata_db()
                .get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?;

            Ok(Box::new(iter)
                as Box<
                    dyn Iterator<Item = Result<LedgerInfoWithSignatures>> + '_,
                >)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1036-1064)
```rust
    pub(super) fn get_epoch_ending_ledger_infos_impl(
        &self,
        start_epoch: u64,
        end_epoch: u64,
        limit: usize,
    ) -> Result<(Vec<LedgerInfoWithSignatures>, bool)> {
        self.check_epoch_ending_ledger_infos_request(start_epoch, end_epoch)?;

        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };

        let lis = self
            .ledger_db
            .metadata_db()
            .get_epoch_ending_ledger_info_iter(start_epoch, paging_epoch)?
            .collect::<Result<Vec<_>>>()?;

        ensure!(
            lis.len() == (paging_epoch - start_epoch) as usize,
            "DB corruption: missing epoch ending ledger info for epoch {}",
            lis.last()
                .map(|li| li.ledger_info().next_block_epoch() - 1)
                .unwrap_or(start_epoch),
        );
        Ok((lis, more))
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L209-296)
```rust
    /// Returns an epoch ending ledger info response (bound by the max response size in bytes)
    fn get_epoch_ending_ledger_infos_by_size(
        &self,
        start_epoch: u64,
        expected_end_epoch: u64,
        max_response_size: u64,
        use_size_and_time_aware_chunking: bool,
    ) -> Result<EpochChangeProof, Error> {
        // Calculate the number of ledger infos to fetch
        let expected_num_ledger_infos = inclusive_range_len(start_epoch, expected_end_epoch)?;
        let max_num_ledger_infos = self.config.max_epoch_chunk_size;
        let num_ledger_infos_to_fetch = min(expected_num_ledger_infos, max_num_ledger_infos);

        // If size and time-aware chunking are disabled, use the legacy implementation
        if !use_size_and_time_aware_chunking {
            return self.get_epoch_ending_ledger_infos_by_size_legacy(
                start_epoch,
                expected_end_epoch,
                num_ledger_infos_to_fetch,
                max_response_size,
            );
        }

        // Calculate the end epoch for storage. This is required because the DbReader
        // interface returns the epochs up to: `end_epoch - 1`. However, we wish to
        // fetch epoch endings up to expected_end_epoch (inclusive).
        let end_epoch = start_epoch
            .checked_add(num_ledger_infos_to_fetch)
            .ok_or_else(|| Error::UnexpectedErrorEncountered("End epoch has overflown!".into()))?;

        // Get the epoch ending ledger info iterator
        let mut epoch_ending_ledger_info_iterator = self
            .storage
            .get_epoch_ending_ledger_info_iterator(start_epoch, end_epoch)?;

        // Initialize the fetched epoch ending ledger infos
        let mut epoch_ending_ledger_infos = vec![];

        // Create a response progress tracker
        let mut response_progress_tracker = ResponseDataProgressTracker::new(
            num_ledger_infos_to_fetch,
            max_response_size,
            self.config.max_storage_read_wait_time_ms,
            self.time_service.clone(),
        );

        // Fetch as many epoch ending ledger infos as possible
        while !response_progress_tracker.is_response_complete() {
            match epoch_ending_ledger_info_iterator.next() {
                Some(Ok(epoch_ending_ledger_info)) => {
                    // Calculate the number of serialized bytes for the epoch ending ledger info
                    let num_serialized_bytes = get_num_serialized_bytes(&epoch_ending_ledger_info)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;

                    // Add the ledger info to the list
                    if response_progress_tracker
                        .data_items_fits_in_response(true, num_serialized_bytes)
                    {
                        epoch_ending_ledger_infos.push(epoch_ending_ledger_info);
                        response_progress_tracker.add_data_item(num_serialized_bytes);
                    } else {
                        break; // Cannot add any more data items
                    }
                },
                Some(Err(error)) => {
                    return Err(Error::StorageErrorEncountered(error.to_string()));
                },
                None => {
                    // Log a warning that the iterator did not contain all the expected data
                    warn!(
                        "The epoch ending ledger info iterator is missing data! \
                        Start epoch: {:?}, expected end epoch: {:?}, num ledger infos to fetch: {:?}",
                        start_epoch, expected_end_epoch, num_ledger_infos_to_fetch
                    );
                    break;
                },
            }
        }

        // Create the epoch change proof
        let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, false);

        // Update the data truncation metrics
        response_progress_tracker
            .update_data_truncation_metrics(DataResponse::get_epoch_ending_ledger_info_label());

        Ok(epoch_change_proof)
    }
```

**File:** types/src/trusted_state.rs (L147-233)
```rust
    pub fn verify_and_ratchet_inner<'a>(
        &self,
        latest_li: &'a LedgerInfoWithSignatures,
        epoch_change_proof: &'a EpochChangeProof,
    ) -> Result<TrustedStateChange<'a>> {
        // Abort early if the response is stale.
        let curr_version = self.version();
        let target_version = latest_li.ledger_info().version();
        ensure!(
            target_version >= curr_version,
            "The target latest ledger info version is stale ({}) and behind our current trusted version ({})",
            target_version, curr_version,
        );

        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
            let new_epoch_state = epoch_change_li
                .ledger_info()
                .next_epoch_state()
                .cloned()
                .ok_or_else(|| {
                    format_err!(
                        "A valid EpochChangeProof will never return a non-epoch change ledger info"
                    )
                })?;

            // If the latest ledger info is in the same epoch as the new verifier, verify it and
            // use it as latest state, otherwise fallback to the epoch change ledger info.
            let new_epoch = new_epoch_state.epoch;

            let verified_ledger_info = if epoch_change_li == latest_li {
                latest_li
            } else if latest_li.ledger_info().epoch() == new_epoch {
                new_epoch_state.verify(latest_li)?;
                latest_li
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };
            let new_waypoint = Waypoint::new_any(verified_ledger_info.ledger_info());

            let new_state = TrustedState::EpochState {
                waypoint: new_waypoint,
                epoch_state: new_epoch_state,
            };

            Ok(TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li: epoch_change_li,
            })
        } else {
            let (curr_waypoint, curr_epoch_state) = match self {
                Self::EpochWaypoint(_) => {
                    bail!("EpochWaypoint can only verify an epoch change ledger info")
                },
                Self::EpochState {
                    waypoint,
                    epoch_state,
                    ..
                } => (waypoint, epoch_state),
            };

            // The EpochChangeProof is empty, stale, or only gets us into our
            // current epoch. We then try to verify that the latest ledger info
            // is inside this epoch.
            let new_waypoint = Waypoint::new_any(latest_li.ledger_info());
            if new_waypoint.version() == curr_waypoint.version() {
                ensure!(
                    &new_waypoint == curr_waypoint,
                    "LedgerInfo doesn't match verified state"
                );
                Ok(TrustedStateChange::NoChange)
            } else {
                // Verify the target ledger info, which should be inside the current epoch.
                curr_epoch_state.verify(latest_li)?;

                let new_state = Self::EpochState {
                    waypoint: new_waypoint,
                    epoch_state: curr_epoch_state.clone(),
                };

                Ok(TrustedStateChange::Version { new_state })
            }
        }
    }
```

**File:** types/src/unit_tests/trusted_state_test.rs (L363-410)
```rust
    fn test_ratchet_succeeds_with_more(
        (_vsets, mut lis_with_sigs, latest_li, accumulator) in arb_update_proof(
            1,    /* start epoch */
            1,    /* start version */
            3,    /* version delta */
            3..6, /* epoch changes */
            1..3, /* validators per epoch */
        ),
    ) {
        let initial_li_with_sigs = lis_with_sigs.remove(0);
        let initial_li = initial_li_with_sigs.ledger_info();
        let trusted_state = TrustedState::try_from_epoch_change_li(
            initial_li,
            accumulator.get_accumulator_summary(initial_li.version()),
        ).unwrap();

        // remove the last LI from the proof
        lis_with_sigs.pop();

        let expected_latest_epoch_change_li = lis_with_sigs.last().unwrap().clone();
        let expected_latest_version = expected_latest_epoch_change_li
            .ledger_info()
            .version();

        // ratcheting with more = false should fail, since the state proof claims
        // we're done syncing epoch changes but doesn't get us all the way to the
        // latest ledger info
        let mut change_proof = EpochChangeProof::new(lis_with_sigs, false /* more */);
        trusted_state
            .verify_and_ratchet_inner(&latest_li, &change_proof)
            .expect_err("Should return Err when more is false and there's a gap");

        // ratcheting with more = true is fine
        change_proof.more = true;
        let trusted_state_change = trusted_state
            .verify_and_ratchet_inner(&latest_li, &change_proof)
            .expect("Should succeed with more in EpochChangeProof");

        match trusted_state_change {
            TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li,
            } => {
                assert_eq!(new_state.version(), expected_latest_version);
                assert_eq!(latest_epoch_change_li, &expected_latest_epoch_change_li);
            }
            _ => panic!("Unexpected ratchet result"),
        };
```

**File:** config/src/config/state_sync_config.rs (L12-14)
```rust
// Whether to enable size and time-aware chunking (for non-production networks).
// Note: once this becomes stable, we should enable it for all networks (e.g., Mainnet).
const ENABLE_SIZE_AND_TIME_AWARE_CHUNKING: bool = true;
```

**File:** config/src/config/state_sync_config.rs (L23-27)
```rust
// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```

**File:** config/src/config/state_sync_config.rs (L195-218)
```rust
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: false,
            enable_transaction_data_v2: true,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            max_invalid_requests_per_peer: 500,
            max_lru_cache_size: 500, // At ~0.6MiB per chunk, this should take no more than 0.5GiB
            max_network_channel_size: 4000,
            max_network_chunk_bytes: SERVER_MAX_MESSAGE_SIZE as u64,
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
            max_num_active_subscriptions: 30,
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
            request_moderator_refresh_interval_ms: 1000, // 1 second
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
        }
    }
}
```

**File:** config/src/config/state_sync_config.rs (L610-634)
```rust
impl ConfigOptimizer for StorageServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let storage_service_config = &mut node_config.state_sync.storage_service;
        let local_storage_config_yaml = &local_config_yaml["state_sync"]["storage_service"];

        // Potentially enable size and time-aware chunking for all networks except Mainnet
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if ENABLE_SIZE_AND_TIME_AWARE_CHUNKING
                && !chain_id.is_mainnet()
                && local_storage_config_yaml["enable_size_and_time_aware_chunking"].is_null()
            {
                storage_service_config.enable_size_and_time_aware_chunking = true;
                modified_config = true;
            }
        }

        Ok(modified_config)
    }
}
```
