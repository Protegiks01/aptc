# Audit Report

## Title
Incorrect `more` Flag in Epoch Change Proof Causes Synchronization Failure Beyond 100 Epochs

## Summary
When size-and-time-aware chunking is enabled, the storage service incorrectly hardcodes `more = false` in epoch change proofs even when the database iterator is capped at 100 epochs. This causes clients more than 100 epochs behind to fail synchronization with "Inconsistent epoch change proof and latest ledger info" errors, creating a liveness failure for affected nodes.

## Finding Description

The Aptos storage system has a fundamental inconsistency in how it constructs epoch change proofs when using the size-and-time-aware chunking feature.

The database layer enforces a hard limit of 100 epoch ending ledger infos per request via `MAX_NUM_EPOCH_ENDING_LEDGER_INFO`. [1](#0-0) 

When the database determines that the requested epoch range exceeds this limit, it correctly computes `more = true` to indicate truncation. [2](#0-1) 

The legacy storage service implementation correctly propagates this `more` flag by calling the database method that returns an `EpochChangeProof` with the proper flag. [3](#0-2) 

However, when `enable_size_and_time_aware_chunking` is enabled, the storage service uses an iterator-based approach that applies the same 100-epoch cap but fails to track whether truncation occurred. The iterator is capped at the limit. [4](#0-3) 

When constructing the response, the storage service hardcodes `more = false`. [5](#0-4) 

This incorrect flag causes verification to fail on the client side. When a client receives an epoch change proof with `more = false` but the proof doesn't reach the latest ledger info's epoch, the verification logic correctly rejects it. [6](#0-5) 

The test suite explicitly confirms this is the expected security behavior - verification MUST fail when `more = false` with an epoch gap. [7](#0-6) 

**Execution Flow:**
1. A node is offline for >100 epochs (e.g., epoch 0 to epoch 150)
2. When it comes back online, it requests epoch ending ledger infos
3. The storage service iterator is capped at 100 epochs due to `MAX_NUM_EPOCH_ENDING_LEDGER_INFO`
4. The service returns an `EpochChangeProof` with epochs 0-99 but incorrectly sets `more = false`
5. The client receives a latest ledger info at epoch 150
6. Verification fails because `latest_li.epoch() (150) > new_epoch (99) && !more (false)`
7. The client cannot sync and remains stuck until manual intervention

## Impact Explanation

This issue represents a **Medium Severity** vulnerability per Aptos bug bounty criteria:

- **Limited Protocol Violation**: Breaks the state synchronization protocol for a subset of nodes
- **Temporary Liveness Issues**: Nodes that have been offline for >100 epochs cannot rejoin through normal sync
- **Requires Manual Intervention**: Affected nodes need a recent waypoint or must wait for a protocol fix

The vulnerability does not cause consensus safety violations, fund loss, or total network failure. However, it creates a practical liveness failure for nodes attempting to catch up after extended offline periods. The ConfigOptimizer automatically enables this feature for non-mainnet networks. [8](#0-7) 

The impact is real for any network where the feature is active. Additionally, the application-level limit (200) exceeds the database limit (100), making the bug easily triggerable when clients request large epoch ranges. [9](#0-8) [1](#0-0) 

## Likelihood Explanation

**Likelihood: High**

This issue occurs naturally without any malicious action:
- Any node offline for >100 epochs will encounter this when trying to sync
- The buggy code path is active when `enable_size_and_time_aware_chunking = true`
- While the config default is `false`, [10](#0-9)  the `ConfigOptimizer` automatically enables it for non-mainnet networks [8](#0-7) 
- No special conditions, race conditions, or attacker actions required
- The scenario is realistic for nodes experiencing extended downtime

## Recommendation

Track whether the iterator was truncated by comparing the number of fetched epochs against the requested range, and set the `more` flag accordingly:

```rust
// After the iterator loop completes
let fetched_epoch_count = epoch_ending_ledger_infos.len() as u64;
let more = fetched_epoch_count < num_ledger_infos_to_fetch 
    || num_ledger_infos_to_fetch < expected_num_ledger_infos;
let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, more);
```

Alternatively, align the application-level `MAX_EPOCH_CHUNK_SIZE` with the database-level `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` to prevent the mismatch.

## Proof of Concept

The vulnerability can be observed by:
1. Setting up a non-mainnet network with `enable_size_and_time_aware_chunking = true`
2. Running a validator node and letting it accumulate 150 epochs
3. Starting a new node from genesis
4. Observing the sync failure when the node attempts to fetch epochs 0-150 but receives only 0-99 with `more = false`

## Notes

This vulnerability represents a logic error in the epoch change proof construction when using the iterator-based chunking approach. The legacy implementation correctly handles this case by using the database method that returns the `more` flag, but the newer iterator-based approach fails to track truncation. This is a clear violation of the state synchronization protocol's invariants, as explicitly validated by the test suite.

### Citations

**File:** storage/aptosdb/src/common.rs (L9-9)
```rust
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L579-583)
```rust
            let limit = std::cmp::min(
                end_epoch.saturating_sub(start_epoch),
                MAX_NUM_EPOCH_ENDING_LEDGER_INFO as u64,
            );
            let end_epoch = start_epoch.saturating_add(limit);
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1044-1048)
```rust
        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };
```

**File:** state-sync/storage-service/server/src/storage.rs (L289-289)
```rust
        let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, false);
```

**File:** state-sync/storage-service/server/src/storage.rs (L315-317)
```rust
            let epoch_change_proof = self
                .storage
                .get_epoch_ending_ledger_infos(start_epoch, end_epoch)?;
```

**File:** types/src/trusted_state.rs (L183-186)
```rust
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
```

**File:** types/src/unit_tests/trusted_state_test.rs (L387-393)
```rust
        // ratcheting with more = false should fail, since the state proof claims
        // we're done syncing epoch changes but doesn't get us all the way to the
        // latest ledger info
        let mut change_proof = EpochChangeProof::new(lis_with_sigs, false /* more */);
        trusted_state
            .verify_and_ratchet_inner(&latest_li, &change_proof)
            .expect_err("Should return Err when more is false and there's a gap");
```

**File:** config/src/config/state_sync_config.rs (L24-24)
```rust
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
```

**File:** config/src/config/state_sync_config.rs (L198-198)
```rust
            enable_size_and_time_aware_chunking: false,
```

**File:** config/src/config/state_sync_config.rs (L623-629)
```rust
            if ENABLE_SIZE_AND_TIME_AWARE_CHUNKING
                && !chain_id.is_mainnet()
                && local_storage_config_yaml["enable_size_and_time_aware_chunking"].is_null()
            {
                storage_service_config.enable_size_and_time_aware_chunking = true;
                modified_config = true;
            }
```
