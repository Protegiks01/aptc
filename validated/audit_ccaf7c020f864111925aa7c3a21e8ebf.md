# Audit Report

## Title
Epoch Ending Ledger Info Truncation Causes Synchronization Failures During Protocol Upgrades

## Summary
The `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` constant (100) in the database layer silently truncates epoch ending ledger info responses, while the storage service incorrectly sets the `more` flag to `false` in the new size-aware chunking implementation. This causes the `TrustedState` verification logic to reject valid state proofs when nodes need to sync through more than 100 epochs, preventing network synchronization during protocol upgrades.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Database Layer Iterator Truncation**

The `get_epoch_ending_ledger_info_iterator` function silently limits responses to 100 epochs: [1](#0-0) 

The iterator truncates the end_epoch by computing `limit = min(end_epoch - start_epoch, 100)` and adjusting the end_epoch accordingly: [2](#0-1) 

**2. Storage Service Incorrect `more` Flag**

The new size-aware chunking implementation always sets `more=false` when creating the `EpochChangeProof`, even when the iterator returns incomplete data: [3](#0-2) 

When the iterator returns `None` prematurely due to the 100-epoch truncation, the storage service logs a warning but still creates an `EpochChangeProof` with `more=false`: [4](#0-3) 

**3. TrustedState Verification Failure**

The `TrustedState::verify_and_ratchet_inner` method uses the `more` flag to determine validity when the latest ledger info is in a higher epoch than the proof: [5](#0-4) 

When `latest_li.ledger_info().epoch() > new_epoch` and `epoch_change_proof.more` is false, the method bails with "Inconsistent epoch change proof and latest ledger info". However, if `more` were correctly set to true, it would accept the partial proof.

**4. Legacy Implementation Works Correctly**

The legacy implementation correctly propagates the `more` flag from the database. The database's `get_epoch_ending_ledger_infos_impl` properly sets `more = true` when the requested range exceeds the limit: [6](#0-5) 

This is correctly returned through the DbReader trait implementation: [7](#0-6) 

**Attack Scenario:**
During a protocol upgrade that shortens epoch duration, a node needing to sync through 150 epochs:
1. Requests epochs 0-200 from storage service
2. Database iterator silently truncates to epochs 0-99
3. Storage service returns `EpochChangeProof { ledger_info_with_sigs: [epochs 0-99], more: false }`
4. Node's latest advertised ledger info is in epoch 150
5. `TrustedState::verify_and_ratchet_inner` detects: epoch 150 > epoch 99 and `more=false`
6. Bails with "Inconsistent epoch change proof and latest ledger info"
7. Node fails to synchronize

## Impact Explanation

**Severity: HIGH** (aligns with "Validator Node Slowdowns" category in Aptos Bug Bounty, up to $50,000)

This vulnerability causes significant protocol violations:

1. **Network Partition Risk**: Nodes using the new chunking implementation cannot synchronize when more than 100 epochs need to be fetched. The config optimizer automatically enables this feature on non-mainnet networks: [8](#0-7) 

2. **Upgrade Deployment Failures**: Protocol upgrades that shorten epoch duration would fail on testnet, preventing validation before mainnet deployment.

3. **Bootstrap Failures**: New validator nodes or nodes recovering from extended downtime cannot bootstrap successfully if they fall behind by more than 100 epochs.

The vulnerability is currently mitigated on mainnet because the default configuration disables the new chunking: [9](#0-8) 

However, this is a latent vulnerability that would activate when the new chunking is enabled on mainnet, as indicated by the global constant: [10](#0-9) 

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability triggers automatically when:
1. Network uses new size-aware chunking (currently: testnets/devnets, future: mainnet)
2. Protocol upgrade changes epoch duration to be significantly shorter
3. Any node needs to sync through >100 epochs

Current situation:
- **Testnets/Devnets**: Currently vulnerable
- **Mainnet**: Protected by legacy implementation, but planned migration makes this a time-bomb

The storage service configuration allows up to 200 epochs per chunk: [11](#0-10) 

This creates a mismatch where clients can request up to 200 epochs, but the database silently truncates to 100, and the storage service fails to detect this truncation.

## Recommendation

**Fix the `more` flag logic in the new size-aware chunking implementation:**

1. Track whether the iterator returned fewer items than requested
2. Set `more=true` when the iterator terminates early due to the 100-epoch limit
3. Alternatively, use the database's `get_epoch_ending_ledger_infos` method which correctly handles the `more` flag

The fix should ensure that when the iterator returns `None` or provides fewer epochs than requested, the `more` flag is set to `true` to indicate incomplete data.

## Proof of Concept

The vulnerability can be reproduced by:
1. Configuring a testnet with `enable_size_and_time_aware_chunking: true`
2. Creating a scenario where a node needs to sync through >100 epochs
3. Observing the "Inconsistent epoch change proof and latest ledger info" error in logs
4. Verifying that switching to legacy implementation (`enable_size_and_time_aware_chunking: false`) resolves the issue

The code evidence demonstrates this is a genuine bug where the new implementation deviates from the correct behavior of the legacy implementation.

## Notes

- All affected files are in-scope Aptos Core components (storage system, state sync, types)
- This is a logic vulnerability that doesn't require an attacker - it's a protocol bug
- The vulnerability doesn't affect consensus directly but prevents state synchronization
- The TODO comment in the database layer acknowledges the limitation but no proper handling was implemented: [12](#0-11) 
- The issue is particularly critical because it affects the upgrade path - testnets are the testing ground for mainnet upgrades

### Citations

**File:** storage/aptosdb/src/common.rs (L7-9)
```rust
// TODO: Either implement an iteration API to allow a very old client to loop through a long history
// or guarantee that there is always a recent enough waypoint and client knows to boot from there.
pub(crate) const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L72-74)
```rust
            let (ledger_info_with_sigs, more) =
                Self::get_epoch_ending_ledger_infos(self, start_epoch, end_epoch)?;
            Ok(EpochChangeProof::new(ledger_info_with_sigs, more))
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

**File:** state-sync/storage-service/server/src/storage.rs (L276-284)
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L289-289)
```rust
        let epoch_change_proof = EpochChangeProof::new(epoch_ending_ledger_infos, false);
```

**File:** types/src/trusted_state.rs (L183-186)
```rust
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
```

**File:** config/src/config/state_sync_config.rs (L14-14)
```rust
const ENABLE_SIZE_AND_TIME_AWARE_CHUNKING: bool = true;
```

**File:** config/src/config/state_sync_config.rs (L24-24)
```rust
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
```

**File:** config/src/config/state_sync_config.rs (L197-198)
```rust
        Self {
            enable_size_and_time_aware_chunking: false,
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
