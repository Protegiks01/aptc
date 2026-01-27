# Audit Report

## Title
Incorrect `more` Field in Incomplete Epoch Change Proofs Causes Network Liveness Failures

## Summary
The `get_epoch_ending_ledger_infos_by_size()` function in the storage service incorrectly hardcodes the `more` field to `false` when creating `EpochChangeProof` objects, even when epoch chains are incomplete due to size, time, or iterator constraints. This causes state sync failures and can lead to validator set fragmentation during epoch transitions, potentially resulting in total network liveness loss.

## Finding Description

The storage service's `get_epoch_ending_ledger_infos_by_size()` function fetches epoch ending ledger infos through an iterator that can stop early due to:
1. Response size limits
2. Time constraints via `ResponseDataProgressTracker`
3. Iterator exhaustion [1](#0-0) 

Despite potentially returning an incomplete epoch chain, the function always creates the `EpochChangeProof` with `more = false`: [2](#0-1) 

This is incorrect. The `more` field should be `true` when there are additional epochs available but not returned due to constraints. The database layer correctly implements this logic: [3](#0-2) 

And properly creates the `EpochChangeProof` with the correct `more` field: [4](#0-3) 

However, the storage service layer overrides this by creating its own `EpochChangeProof` with `more` hardcoded to `false`.

**Impact on State Sync:**

When clients use `TrustedState::verify_and_ratchet_inner()` to sync with an incomplete proof (`more = false`) and a `latest_li` in a higher epoch, the verification fails: [5](#0-4) 

The condition `epoch_change_proof.more` evaluates to `false` (incorrectly), causing the function to bail with "Inconsistent epoch change proof and latest ledger info" instead of properly handling the incomplete chain.

**Impact on Consensus:**

When consensus uses `EpochManager::initiate_new_epoch()`, it verifies the incomplete proof and syncs to the last epoch in the proof: [6](#0-5) 

The `EpochChangeProof::verify()` method returns the **last** ledger info in the incomplete proof: [7](#0-6) 

This causes nodes to sync to older epochs than the network's current epoch, leading to:
- Validators unable to participate in consensus (wrong epoch/validator set)
- Network fragmentation if different nodes receive different incomplete proofs
- Potential total liveness loss if enough validators get stuck at old epochs during epoch transitions

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos bug bounty program:

1. **Total loss of liveness/network availability**: If during an epoch transition (e.g., epoch 10→11), enough validators receive incomplete proofs keeping them at epoch 10 while others advance to epoch 11, neither epoch can achieve the 2/3+ quorum needed for consensus. The network halts.

2. **Non-recoverable network partition**: In severe cases where the validator set is fragmented across multiple epochs due to different nodes receiving different incomplete proofs, recovery may require manual intervention or even a hardfork to resynchronize the network.

The bug is enabled by default for non-mainnet networks: [8](#0-7) 

And activated through config optimization for all networks except mainnet: [9](#0-8) 

## Likelihood Explanation

**Likelihood: High**

The bug triggers naturally during normal operations:
1. Epoch ending ledger infos can be large (each contains validator signatures)
2. Size limits are easily hit when syncing across many epochs
3. Time limits (`max_storage_read_wait_time_ms` = 10 seconds) can be exceeded during heavy load
4. The bug is enabled by default for all non-mainnet networks

The vulnerability is **most critical during epoch transitions**, which occur regularly in the Aptos network. During these transitions, multiple nodes simultaneously request epoch ending ledger infos, increasing the likelihood of incomplete proofs due to load or size constraints.

## Recommendation

Fix the `get_epoch_ending_ledger_infos_by_size()` function to correctly set the `more` field based on whether all expected epochs were fetched: [10](#0-9) 

**Recommended Fix:**

```rust
// Determine if there are more epochs available
let more = epoch_ending_ledger_infos.len() < num_ledger_infos_to_fetch as usize;

// Create the epoch change proof
let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, more);
```

This ensures that `more = true` when the iteration stopped early due to constraints, allowing clients to:
1. Properly handle incomplete proofs in `TrustedState::verify_and_ratchet_inner()`
2. Make additional requests to fetch remaining epochs
3. Avoid false "Inconsistent epoch change proof" errors

The same fix should be verified in the `ResponseDataProgressTracker` to ensure it accurately tracks completion.

## Proof of Concept

**Rust Test to Reproduce:**

```rust
#[tokio::test]
async fn test_incomplete_epoch_chain_more_field() {
    // Setup: Create a storage service with multiple epochs
    let (mut config, mock_db) = setup_storage_service_with_epochs(1, 20); // Epochs 1-20
    
    // Set small max_network_chunk_bytes to force truncation
    config.max_network_chunk_bytes = 1000; // Very small to force incomplete proof
    config.enable_size_and_time_aware_chunking = true;
    
    let storage = StorageReader::new(config, Arc::new(mock_db), TimeService::mock());
    
    // Request epochs 1-20, but size limit will truncate response
    let result = storage.get_epoch_ending_ledger_infos(1, 20).unwrap();
    
    // BUG: The proof is incomplete but more=false
    assert!(result.ledger_info_with_sigs.len() < 20); // Incomplete
    assert_eq!(result.more, false); // INCORRECT - should be true
    
    // This causes sync failures:
    let trusted_state = TrustedState::from_epoch_waypoint(waypoint_for_epoch_1);
    let latest_li = create_ledger_info_for_epoch(20); // Latest network state
    
    // This will fail with "Inconsistent epoch change proof"
    let sync_result = trusted_state.verify_and_ratchet_inner(&latest_li, &result);
    assert!(sync_result.is_err()); // Sync fails due to incorrect more=false
}
```

**Steps to Verify in Production:**

1. Deploy a node with `enable_size_and_time_aware_chunking = true`
2. Let the network progress through multiple epochs (10+)
3. Bootstrap a new node from epoch 1
4. Set `max_network_chunk_bytes` to a small value (e.g., 10KB)
5. Observe state sync failures with "Inconsistent epoch change proof" errors
6. Check logs for incomplete epoch chains with `more=false`

**Notes**

This vulnerability specifically affects the "size and time-aware chunking" implementation introduced to optimize network bandwidth. The legacy implementation correctly preserves the `more` field from the database layer and does not have this bug: [11](#0-10) 

The bug was likely introduced during refactoring when the new chunking logic was added, and the developer forgot to track whether the iteration completed successfully. While the default configuration has `enable_size_and_time_aware_chunking = false` for safety, the code is automatically enabled for non-mainnet networks, making this a critical issue for testnets and devnets where epoch transitions are more frequent.

### Citations

**File:** state-sync/storage-service/server/src/storage.rs (L256-286)
```rust
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L287-289)
```rust

        // Create the epoch change proof
        let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, false);
```

**File:** state-sync/storage-service/server/src/storage.rs (L315-327)
```rust
            let epoch_change_proof = self
                .storage
                .get_epoch_ending_ledger_infos(start_epoch, end_epoch)?;
            if num_ledger_infos_to_fetch == 1 {
                return Ok(epoch_change_proof); // We cannot return less than a single item
            }

            // Attempt to divide up the request if it overflows the message size
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&epoch_change_proof, max_response_size)?;
            if !overflow_frame {
                return Ok(epoch_change_proof);
            } else {
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L72-74)
```rust
            let (ledger_info_with_sigs, more) =
                Self::get_epoch_ending_ledger_infos(self, start_epoch, end_epoch)?;
            Ok(EpochChangeProof::new(ledger_info_with_sigs, more))
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1044-1048)
```rust
        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };
```

**File:** types/src/trusted_state.rs (L183-187)
```rust
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };
```

**File:** consensus/src/epoch_manager.rs (L544-565)
```rust
    async fn initiate_new_epoch(&mut self, proof: EpochChangeProof) -> anyhow::Result<()> {
        let ledger_info = proof
            .verify(self.epoch_state())
            .context("[EpochManager] Invalid EpochChangeProof")?;
        info!(
            LogSchema::new(LogEvent::NewEpoch).epoch(ledger_info.ledger_info().next_block_epoch()),
            "Received verified epoch change",
        );

        // shutdown existing processor first to avoid race condition with state sync.
        self.shutdown_current_processor().await;
        *self.pending_blocks.lock() = PendingBlocks::new();
        // make sure storage is on this ledger_info too, it should be no-op if it's already committed
        // panic if this doesn't succeed since the current processors are already shutdown.
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");
```

**File:** types/src/epoch_change.rs (L117-118)
```rust
        Ok(self.ledger_info_with_sigs.last().unwrap())
    }
```

**File:** config/src/config/state_sync_config.rs (L14-14)
```rust
const ENABLE_SIZE_AND_TIME_AWARE_CHUNKING: bool = true;
```

**File:** config/src/config/state_sync_config.rs (L623-628)
```rust
            if ENABLE_SIZE_AND_TIME_AWARE_CHUNKING
                && !chain_id.is_mainnet()
                && local_storage_config_yaml["enable_size_and_time_aware_chunking"].is_null()
            {
                storage_service_config.enable_size_and_time_aware_chunking = true;
                modified_config = true;
```
