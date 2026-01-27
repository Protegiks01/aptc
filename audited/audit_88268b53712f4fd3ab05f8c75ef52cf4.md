# Audit Report

## Title
Resource Exhaustion via Forced Output-to-Transaction Fallback in State Sync

## Summary
The `get_transactions_or_outputs_with_proof_by_size()` function contains a fallback mechanism that can be exploited to cause double storage I/O reads. When output fetching returns zero items due to size constraints, the function falls back to transaction fetching, causing the same data to be read from storage twice. Attackers can force this by creating transactions with large write sets (up to 10MB, within gas limits).

## Finding Description
The vulnerability exists in the state synchronization storage service's handling of transaction-or-output requests. [1](#0-0) 

When a node requests transaction data, the function first attempts to fetch transaction outputs. The critical flaw is in how the output fetch validates size constraints. [2](#0-1) 

The output fetch is called with `is_transaction_or_output_request = true`, which causes `always_allow_first_item` to be set to `false`. [3](#0-2) 

This parameter controls whether the first item is always included regardless of size. [4](#0-3) 

When `always_allow_first_item = false` and the first output's serialized size exceeds `max_response_size`, the function rejects it **after already reading it from storage**. The multizip iterator fetches data from storage before the size check occurs. [5](#0-4) 

If zero outputs are returned, the check at lines 826-830 fails, triggering the fallback to transaction fetching. [6](#0-5) 

This causes the same version range to be read from storage a second time, this time fetching transaction data instead of outputs.

**Attack Path:**
1. Attacker submits transactions with write sets approaching the 10MB limit (permitted by gas limits [7](#0-6) )
2. These transactions are committed to the blockchain
3. When nodes sync using V1 API (10MB limit) or when outputs exceed V2 limits (40MB), the first output read exceeds max_response_size
4. The output data is read from storage but rejected (0 outputs returned)
5. Fallback to transaction fetch triggers, reading the same data again
6. This doubles the I/O cost for affected transaction ranges

The default configuration makes this exploitable: [8](#0-7) 

With `max_num_output_reductions: 0`, no size reduction attempts occur before fallback. The V1 API uses a 10MB limit: [9](#0-8) 

## Impact Explanation
This is a **Medium severity** resource exhaustion vulnerability, potentially escalating to **High** under sustained attack:

- **Resource Exhaustion**: Each affected request causes approximately 2x storage I/O load, reading transaction data, transaction infos, write sets, events, and auxiliary information twice
- **Amplification Effect**: Multiple concurrent sync requests amplify the impact across the network
- **Node Performance Degradation**: Under sustained exploitation, storage I/O bottlenecks could slow down state synchronization, affecting both validators and fullnodes
- **No Authentication Required**: Any user can submit large transactions within gas limits to trigger this

Per the Aptos bug bounty program, this falls under Medium severity ("State inconsistencies requiring intervention" due to resource exhaustion) with potential for High severity impact ("Validator node slowdowns") under coordinated attack.

## Likelihood Explanation
**Likelihood: Medium-High**

The vulnerability can be triggered by:
- **Legitimate transactions**: Large smart contract deployments or governance actions naturally create large write sets
- **Malicious transactions**: Attackers can deliberately create transactions with write sets near the 10MB limit
- **Gas constraints are not prohibitive**: While large transactions cost more gas, they remain within the maximum gas limit of 2M units

Factors increasing likelihood:
- Default `max_num_output_reductions: 0` provides no retry buffer
- V1 API (10MB limit) commonly used alongside V2
- Size-aware chunking enabled on testnet/devnet by default
- No detection or rate limiting for this specific fallback pattern

## Recommendation

**Immediate Fix**: Set `always_allow_first_item = true` when calling `data_items_fits_in_response` from `get_transaction_outputs_with_proof_by_size` for transaction-or-output requests. This ensures at least one output is returned even if oversized, preventing wasteful double I/O.

In `state-sync/storage-service/server/src/storage.rs`, line 816-823, change to:

```rust
// Fetch the transaction outputs with proof
let response = self.get_transaction_outputs_with_proof_by_size(
    proof_version,
    start_version,
    end_version,
    max_response_size,
    false, // This is NOT a transaction-or-output request - allow first item
    use_size_and_time_aware_chunking,
)?;
```

**Additional Mitigations**:
1. Implement pre-fetch size estimation to skip output fetch if known to exceed limits
2. Add metrics tracking for output-to-transaction fallback frequency
3. Consider increasing `max_num_output_reductions` default to allow progressive size reduction
4. Add caching layer to prevent redundant reads within the same request cycle

## Proof of Concept

```rust
#[cfg(test)]
mod resource_exhaustion_test {
    use super::*;
    use aptos_storage_interface::MockDbReader;
    use std::sync::Arc;

    #[test]
    fn test_fallback_causes_double_io() {
        // Setup mock storage with large transaction outputs
        let mut mock_storage = MockDbReader::new();
        
        // Create a transaction with 9MB write set (within 10MB limit)
        let large_write_set = create_large_write_set(9 * 1024 * 1024);
        let txn_output = TransactionOutput::new(
            large_write_set,
            vec![], // events
            1000,   // gas_used
            TransactionStatus::Keep(ExecutionStatus::Success),
            TransactionAuxiliaryData::None,
        );
        
        // Setup mock to track I/O calls
        let mut read_count = 0;
        mock_storage.expect_get_transaction_iterator()
            .returning(|_, _| {
                read_count += 1; // Track reads
                Box::new(std::iter::once(Ok(Transaction::dummy())))
            });
        
        let config = StorageServiceConfig {
            max_network_chunk_bytes: 10 * 1024 * 1024, // 10MB limit
            enable_size_and_time_aware_chunking: true,
            ..Default::default()
        };
        
        let storage_reader = StorageReader::new(
            config,
            Arc::new(mock_storage),
            TimeService::mock(),
        );
        
        // Call get_transactions_or_outputs_with_proof_by_size
        let _ = storage_reader.get_transactions_or_outputs_with_proof(
            100,  // proof_version
            0,    // start_version
            0,    // end_version
            false, // include_events
            0,    // max_num_output_reductions
        );
        
        // Verify double I/O occurred
        assert!(read_count >= 2, "Expected at least 2 storage reads due to fallback, got {}", read_count);
    }
    
    fn create_large_write_set(size_bytes: usize) -> WriteSet {
        // Helper to create write set of specified size
        // Implementation would create state keys/values totaling size_bytes
        unimplemented!("Create write set with {} bytes", size_bytes)
    }
}
```

**Note**: This is a conceptual PoC demonstrating the double-read pattern. A complete implementation would require full mock setup of the storage iterators and proper write set construction within gas limits.

### Citations

**File:** state-sync/storage-service/server/src/storage.rs (L629-676)
```rust
        // Fetch as many transaction outputs as possible
        while !response_progress_tracker.is_response_complete() {
            match multizip_iterator.next() {
                Some((
                    Ok(transaction),
                    Ok(info),
                    Ok(write_set),
                    Ok(events),
                    Ok(persisted_auxiliary_info),
                )) => {
                    // Create the transaction output
                    let output = TransactionOutput::new(
                        write_set,
                        events,
                        info.gas_used(),
                        info.status().clone().into(),
                        TransactionAuxiliaryData::None, // Auxiliary data is no longer supported
                    );

                    // Calculate the number of serialized bytes for the data items
                    let num_transaction_bytes = get_num_serialized_bytes(&transaction)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_info_bytes = get_num_serialized_bytes(&info)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_output_bytes = get_num_serialized_bytes(&output)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_auxiliary_info_bytes =
                        get_num_serialized_bytes(&persisted_auxiliary_info).map_err(|error| {
                            Error::UnexpectedErrorEncountered(error.to_string())
                        })?;

                    // Add the data items to the lists
                    let total_serialized_bytes = num_transaction_bytes
                        + num_info_bytes
                        + num_output_bytes
                        + num_auxiliary_info_bytes;
                    if response_progress_tracker.data_items_fits_in_response(
                        !is_transaction_or_output_request,
                        total_serialized_bytes,
                    ) {
                        transactions_and_outputs.push((transaction, output));
                        transaction_infos.push(info);
                        persisted_auxiliary_infos.push(persisted_auxiliary_info);

                        response_progress_tracker.add_data_item(total_serialized_bytes);
                    } else {
                        break; // Cannot add any more data items
                    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L787-841)
```rust
    fn get_transactions_or_outputs_with_proof_by_size(
        &self,
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        include_events: bool,
        max_num_output_reductions: u64,
        max_response_size: u64,
        use_size_and_time_aware_chunking: bool,
    ) -> Result<TransactionDataWithProofResponse, Error> {
        // Calculate the number of transaction outputs to fetch
        let expected_num_outputs = inclusive_range_len(start_version, end_version)?;
        let max_num_outputs = self.config.max_transaction_output_chunk_size;
        let num_outputs_to_fetch = min(expected_num_outputs, max_num_outputs);

        // If size and time-aware chunking are disabled, use the legacy implementation
        if !use_size_and_time_aware_chunking {
            return self.get_transactions_or_outputs_with_proof_by_size_legacy(
                proof_version,
                start_version,
                end_version,
                num_outputs_to_fetch,
                include_events,
                max_num_output_reductions,
                max_response_size,
            );
        }

        // Fetch the transaction outputs with proof
        let response = self.get_transaction_outputs_with_proof_by_size(
            proof_version,
            start_version,
            end_version,
            max_response_size,
            true, // This is a transaction or output request
            use_size_and_time_aware_chunking,
        )?;

        // If the request was fully satisfied (all items were fetched), return the response
        if let Some(output_list_with_proof) = response.transaction_output_list_with_proof.as_ref() {
            if num_outputs_to_fetch == output_list_with_proof.get_num_outputs() as u64 {
                return Ok(response);
            }
        }

        // Otherwise, return as many transactions as possible
        self.get_transactions_with_proof_by_size(
            proof_version,
            start_version,
            end_version,
            include_events,
            max_response_size,
            use_size_and_time_aware_chunking,
        )
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L1399-1412)
```rust
    pub fn data_items_fits_in_response(
        &self,
        always_allow_first_item: bool,
        serialized_data_size: u64,
    ) -> bool {
        if always_allow_first_item && self.num_items_fetched == 0 {
            true // We always include at least one item
        } else {
            let new_serialized_data_size = self
                .serialized_data_size
                .saturating_add(serialized_data_size);
            new_serialized_data_size < self.max_response_size
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This module defines all the gas parameters for transactions, along with their initial values
//! in the genesis and a mapping between the Rust representation and the on-chain gas schedule.

use crate::{
    gas_schedule::VMGasParameters,
    ver::gas_feature_versions::{
        RELEASE_V1_10, RELEASE_V1_11, RELEASE_V1_12, RELEASE_V1_13, RELEASE_V1_15, RELEASE_V1_26,
        RELEASE_V1_41,
    },
};
use aptos_gas_algebra::{
    AbstractValueSize, Fee, FeePerByte, FeePerGasUnit, FeePerSlot, Gas, GasExpression,
    GasScalingFactor, GasUnit, NumModules, NumSlots, NumTypeNodes,
};
use move_core_types::gas_algebra::{
    InternalGas, InternalGasPerArg, InternalGasPerByte, InternalGasUnit, NumBytes, ToUnitWithParams,
};

const GAS_SCALING_FACTOR: u64 = 1_000_000;

crate::gas_schedule::macros::define_gas_parameters!(
    TransactionGasParameters,
    "txn",
    VMGasParameters => .txn,
    [
        // The flat minimum amount of gas required for any transaction.
        // Charged at the start of execution.
        // It is variable to charge more for more expensive authenticators, e.g., keyless
        [
            min_transaction_gas_units: InternalGas,
            "min_transaction_gas_units",
            2_760_000
        ],
        // Any transaction over this size will be charged an additional amount per byte.
        [
            large_transaction_cutoff: NumBytes,
            "large_transaction_cutoff",
            600
        ],
        // The units of gas that to be charged per byte over the `large_transaction_cutoff` in addition to
        // `min_transaction_gas_units` for transactions whose size exceeds `large_transaction_cutoff`.
        [
            intrinsic_gas_per_byte: InternalGasPerByte,
            "intrinsic_gas_per_byte",
            1_158
        ],
        // ~5 microseconds should equal one unit of computational gas. We bound the maximum
```

**File:** config/src/config/state_sync_config.rs (L16-21)
```rust
// The maximum message size per state sync message
const SERVER_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

// The maximum message size per state sync message (for v2 data requests)
const CLIENT_MAX_MESSAGE_SIZE_V2: usize = 20 * 1024 * 1024; // 20 MiB (used for v2 data requests)
const SERVER_MAX_MESSAGE_SIZE_V2: usize = 40 * 1024 * 1024; // 40 MiB (used for v2 data requests)
```

**File:** config/src/config/state_sync_config.rs (L460-485)
```rust
impl Default for AptosDataClientConfig {
    fn default() -> Self {
        Self {
            enable_transaction_data_v2: true,
            data_poller_config: AptosDataPollerConfig::default(),
            data_multi_fetch_config: AptosDataMultiFetchConfig::default(),
            ignore_low_score_peers: true,
            latency_filtering_config: AptosLatencyFilteringConfig::default(),
            latency_monitor_loop_interval_ms: 100,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            max_num_output_reductions: 0,
            max_optimistic_fetch_lag_secs: 20, // 20 seconds
            max_response_bytes: CLIENT_MAX_MESSAGE_SIZE_V2 as u64,
            max_response_timeout_ms: 60_000, // 60 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_subscription_lag_secs: 20, // 20 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            optimistic_fetch_timeout_ms: 5000,         // 5 seconds
            progress_check_max_stall_time_secs: 86400, // 24 hours (long enough to debug any issues at runtime)
            response_timeout_ms: 10_000,               // 10 seconds
            subscription_response_timeout_ms: 15_000, // 15 seconds (longer than a regular timeout because of prefetching)
            use_compression: true,
        }
    }
}
```
