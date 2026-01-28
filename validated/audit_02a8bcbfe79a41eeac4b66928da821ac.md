# Audit Report

## Title
Epoch Ending Ledger Info Truncation Causes Synchronization Failures During Protocol Upgrades

## Summary
The storage layer's hard limit of 100 epochs combined with incorrect `more` flag handling in the new size-aware chunking implementation causes nodes to fail synchronization when they need to sync through more than 100 epochs. This breaks state synchronization during protocol upgrades that shorten epoch duration.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Database Layer Silent Truncation**

The database layer enforces a hard limit of 100 epochs through the `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` constant, which silently truncates any request exceeding this limit: [1](#0-0) 

The `get_epoch_ending_ledger_info_iterator` implementation applies this limit regardless of the requested range: [2](#0-1) 

When a client requests epochs 0-200, the iterator only returns epochs 0-99 due to this truncation.

**2. Storage Service Incorrect `more` Flag**

The new size-aware chunking implementation in the storage service always sets `more=false` when creating the `EpochChangeProof`, even when the iterator returns incomplete data: [3](#0-2) 

When the iterator exhausts early due to the 100-epoch truncation, the code logs a warning but still creates an `EpochChangeProof` with `more=false`, incorrectly signaling data completeness.

In contrast, the legacy implementation correctly propagates the `more` flag from the database layer: [4](#0-3) 

The underlying implementation properly calculates the `more` flag based on whether the request exceeds the limit: [5](#0-4) 

**3. TrustedState Verification Failure**

The `TrustedState::verify_and_ratchet_inner` method uses the `more` flag to determine if an incomplete epoch change proof is acceptable: [6](#0-5) 

When `latest_li.ledger_info().epoch() > new_epoch` and `epoch_change_proof.more` is `false`, the verification fails with "Inconsistent epoch change proof and latest ledger info". If `more` were correctly set to `true`, it would accept the partial proof.

This behavior is confirmed by unit tests: [7](#0-6) 

**Attack Scenario**

During a protocol upgrade that shortens epoch duration, a node syncing through 150 epochs:
1. Requests epochs 0-200 from storage service
2. Database truncates to epochs 0-99 
3. Storage service returns `EpochChangeProof` with `more=false`
4. Node's advertised ledger info is in epoch 150
5. Verification detects epoch 150 > 99 with `more=false`
6. Bails with "Inconsistent epoch change proof and latest ledger info"
7. Node cannot synchronize

**Configuration Context**

The vulnerability is currently mitigated on mainnet because the default configuration disables size-aware chunking: [8](#0-7) 

However, the config optimizer enables it for non-mainnet networks: [9](#0-8) 

The constant indicates intent to enable globally: [10](#0-9) 

Additionally, the default `max_epoch_chunk_size` of 200 exceeds the database limit of 100: [11](#0-10) 

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes significant protocol violations:

1. **Network Partition Risk**: Testnets and devnets using the new chunking implementation cannot synchronize when more than 100 epochs need to be fetched, potentially partitioning the network during protocol upgrades.

2. **Upgrade Deployment Failures**: Protocol upgrades that shorten epoch duration would fail validation on testnets, blocking mainnet deployment.

3. **Bootstrap Failures**: New validators or nodes recovering from extended downtime cannot bootstrap if they fall behind by more than 100 epochs.

The vulnerability is a latent time-bomb for mainnet - currently protected by legacy implementation but will activate when size-aware chunking is enabled network-wide.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability triggers automatically when:
- Network uses new size-aware chunking (currently: testnets, planned: mainnet)
- Any node needs to sync through >100 epochs (new nodes, offline nodes, protocol upgrades)

**Current Exposure:**
- Testnets/Devnets: Vulnerable now
- Mainnet: Protected but migration planned

**Triggering Scenarios:**
- Protocol upgrade shortening epoch duration from 6h to 30min → nodes offline 2 days need ~96 epochs (close to limit)
- Multiple epoch-shortening upgrades accumulate beyond 100 epochs
- Validators falling behind during network transitions

## Recommendation

**Fix 1: Propagate `more` flag correctly in new implementation**

In `state-sync/storage-service/server/src/storage.rs`, track whether the iterator completed successfully and set the `more` flag accordingly:

```rust
let mut more = false;
while !response_progress_tracker.is_response_complete() {
    match epoch_ending_ledger_info_iterator.next() {
        // ... existing logic ...
        None => {
            // Iterator exhausted before expected - signal incomplete data
            more = true;
            warn!("The epoch ending ledger info iterator is missing data! ...");
            break;
        },
    }
}
let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, more);
```

**Fix 2: Increase MAX_NUM_EPOCH_ENDING_LEDGER_INFO**

Increase the limit to at least 200 to match `max_epoch_chunk_size`:

```rust
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 200;
```

**Fix 3: Add validation**

Add assertion that `max_epoch_chunk_size` doesn't exceed database limits in config validation.

## Proof of Concept

A proof of concept would require:
1. Setting up a testnet with size-aware chunking enabled
2. Creating 150+ epochs through rapid epoch transitions
3. Starting a new validator node that needs to sync from genesis
4. Observing the "Inconsistent epoch change proof and latest ledger info" error

The vulnerability is demonstrated through the code analysis above, showing the mismatch between the 100-epoch database limit and the missing `more` flag propagation in the new implementation.

## Notes

This is a legitimate protocol bug affecting state synchronization, not a DoS attack. No malicious actor is required - the bug triggers during normal protocol operations when specific conditions are met (syncing >100 epochs). The vulnerability represents a critical gap in the migration path from legacy to size-aware chunking implementations.

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

**File:** state-sync/storage-service/server/src/storage.rs (L276-289)
```rust
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
```

**File:** types/src/trusted_state.rs (L178-187)
```rust
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
```

**File:** types/src/unit_tests/trusted_state_test.rs (L387-399)
```rust
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
```

**File:** config/src/config/state_sync_config.rs (L12-14)
```rust
// Whether to enable size and time-aware chunking (for non-production networks).
// Note: once this becomes stable, we should enable it for all networks (e.g., Mainnet).
const ENABLE_SIZE_AND_TIME_AWARE_CHUNKING: bool = true;
```

**File:** config/src/config/state_sync_config.rs (L24-24)
```rust
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
```

**File:** config/src/config/state_sync_config.rs (L195-198)
```rust
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: false,
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
