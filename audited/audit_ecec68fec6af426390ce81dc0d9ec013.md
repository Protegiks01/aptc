# Audit Report

## Title
Transaction Replay Failure Due to Missing Auxiliary Info Fallback in REST Interface

## Summary
The `get_persisted_auxiliary_infos` function in the REST interface falls back to `PersistedAuxiliaryInfo::None` when the REST API fails, instead of propagating errors. This causes replay failures for transactions that use the `monotonically_increasing_counter()` native function, as these transactions abort with `ETRANSACTION_INDEX_NOT_AVAILABLE` during replay despite having succeeded in their original execution.

## Finding Description
The vulnerability exists in the backward compatibility handling of persisted auxiliary information retrieval: [1](#0-0) 

The TODO comment explicitly acknowledges that once nodes upgrade to v1.37, this function should return an error when the REST API fails. However, the current implementation silently falls back to returning `PersistedAuxiliaryInfo::None` values.

The issue manifests when Move smart contracts call the `monotonically_increasing_counter()` function: [2](#0-1) 

This function internally calls a native implementation that requires a valid transaction index: [3](#0-2) 

When `TransactionIndexKind::NotAvailable` is encountered (which occurs when `PersistedAuxiliaryInfo::None` is used), the native function aborts with `ETRANSACTION_INDEX_NOT_AVAILABLE`.

**Attack Scenario:**
1. A transaction successfully executes on a v1.37+ node, using `monotonically_increasing_counter()` (e.g., in the experimental trading framework for order ID generation) [4](#0-3) 

2. The transaction is stored with `PersistedAuxiliaryInfo::V1 { transaction_index: N }`
3. A debugger/replay tool attempts to fetch and replay this transaction from a node where the REST API fails (pre-v1.37 node or network issues)
4. The REST interface returns `PersistedAuxiliaryInfo::None` as fallback
5. During replay execution, the transaction aborts because the native function cannot provide a monotonically increasing counter without a transaction index
6. The replay fails despite the original execution succeeding, breaking replay determinism

## Impact Explanation
This issue qualifies as **High Severity** per the Aptos bug bounty criteria for the following reasons:

**API Reliability Issues**: The REST API provides incorrect fallback data instead of properly signaling failure, causing downstream tool failures. While the API itself doesn't crash, it returns semantically incorrect data that causes replay tools to produce wrong results.

**Significant Protocol Violations**: The replay/debugging protocol relies on accurate transaction replay to validate blockchain state. This bug breaks the fundamental guarantee that replaying a successful transaction should produce the same result. This affects:
- Transaction debugging and forensics
- State validation tools  
- Testing frameworks
- Block replay mechanisms

**However**, this does NOT affect:
- Consensus operations (validators generate their own auxiliary info during block execution) [5](#0-4) 

- Validator node operations (the interface is only used by external debugging tools) [6](#0-5) 

## Likelihood Explanation
**HIGH Likelihood** - This issue will occur whenever:
1. The monotonically increasing counter feature is enabled (feature flag 98)
2. Transactions use `transaction_context::monotonically_increasing_counter()` (already used in experimental trading framework)
3. Replay is attempted from nodes running pre-v1.37 or experiencing REST API failures
4. The debugger/replay tools are used for transaction validation or testing

The conditions are common in realistic scenarios where:
- Network has mixed node versions during upgrade periods
- Debugging tools connect to older archive nodes
- Network connectivity issues cause API timeouts

## Recommendation
Implement the fix suggested in the TODO comment - return an error when the REST API fails instead of silently falling back:

```rust
async fn get_persisted_auxiliary_infos(
    &self,
    start: Version,
    limit: u64,
) -> Result<Vec<PersistedAuxiliaryInfo>> {
    // Once all nodes are upgraded to v1.37+, return error instead of fallback
    self.0
        .get_persisted_auxiliary_infos(start, limit)
        .await
        .map_err(|e| anyhow!("Failed to fetch auxiliary infos from REST API: {}. Ensure the node is running v1.37 or later.", e))
}
```

Additionally, update `get_committed_transactions` to handle this error appropriately and inform users that they need to connect to a v1.37+ node for accurate replay.

## Proof of Concept
```rust
// Reproduction steps:
// 1. Deploy a Move module that calls transaction_context::monotonically_increasing_counter()
// 2. Execute a transaction that calls this function on a v1.37+ node (succeeds)
// 3. Configure RestDebuggerInterface to connect to a pre-v1.37 node or mock API failure
// 4. Attempt to replay the transaction using AptosDebugger
// 5. Observe that replay aborts with ETRANSACTION_INDEX_NOT_AVAILABLE

#[tokio::test]
async fn test_replay_failure_with_missing_auxiliary_info() {
    // Setup: Create a REST client that will fail to fetch auxiliary info
    let client = Client::new(/* pre-v1.37 node URL */);
    let debugger = RestDebuggerInterface::new(client);
    
    // Execute: Fetch a transaction that used monotonically_increasing_counter()
    let (txns, infos, aux_infos) = debugger
        .get_committed_transactions(version, 1)
        .await
        .unwrap();
    
    // Verify: The auxiliary info is None (fallback was used)
    assert_eq!(aux_infos[0], PersistedAuxiliaryInfo::None);
    
    // Attempt replay: This will abort during execution
    let result = debugger.execute_transactions_at_version(
        version,
        txns,
        aux_infos,
        1,
        &[1]
    );
    
    // Expected: Replay fails with ETRANSACTION_INDEX_NOT_AVAILABLE abort
    // even though original execution succeeded
    assert!(result.is_err());
}
```

**Notes:**
- This vulnerability only affects external debugging and replay tools, not consensus validators
- Validators generate their own auxiliary information during block execution and do not rely on the REST API
- The issue is explicitly acknowledged in the codebase via the TODO comment as a temporary backward compatibility measure
- The security impact is limited to the integrity of replay/debugging operations rather than blockchain consensus itself

### Citations

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L371-388)
```rust
    async fn get_persisted_auxiliary_infos(
        &self,
        start: Version,
        limit: u64,
    ) -> Result<Vec<PersistedAuxiliaryInfo>> {
        // TODO: Once testnet and mainnet are upgraded to v1.37, return error when the REST API fails.
        // self.0
        //  .get_persisted_auxiliary_infos(start, limit)
        //  .await
        //  .map_err(|e| anyhow!(e))
        match self.0.get_persisted_auxiliary_infos(start, limit).await {
            Ok(auxiliary_infos) => Ok(auxiliary_infos),
            Err(_) => {
                // Fallback to empty auxiliary info when REST API fails
                Ok(vec![PersistedAuxiliaryInfo::None; limit as usize])
            },
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_context.move (L195-207)
```text
    /// Returns a monotonically increasing counter value that combines timestamp, transaction index,
    /// session counter, and local counter into a 128-bit value.
    /// Format: `<reserved_byte (8 bits)> || timestamp_us (64 bits) || transaction_index (32 bits) || session_counter (8 bits) || local_counter (16 bits)`
    /// The function aborts if the local counter overflows (after 65535 calls in a single session).
    /// When compiled for testing, this function bypasses feature checks and returns a simplified counter value.
    public fun monotonically_increasing_counter(): u128 {
        if (__COMPILE_FOR_TESTING__) {
            monotonically_increasing_counter_internal_for_test_only()
        } else {
            assert!(features::is_monotonically_increasing_counter_enabled(), error::invalid_state(EMONOTONICALLY_INCREASING_COUNTER_NOT_ENABLED));
            monotonically_increasing_counter_internal(timestamp::now_microseconds())
        }
    }
```

**File:** aptos-move/framework/src/natives/transaction_context.rs (L187-211)
```rust
        // monotonically_increasing_counter (128 bits) = `<reserved_byte (8 bits)> || timestamp_us (64 bits) || transaction_index (32 bits) || session counter (8 bits) || local_counter (16 bits)`
        // reserved_byte: 0 for block/chunk execution (V1), 1 for validation/simulation (TimestampNotYetAssignedV1)
        let timestamp_us = safely_pop_arg!(args, u64);
        let transaction_index_kind = user_transaction_context.transaction_index_kind();

        let (reserved_byte, transaction_index) = match transaction_index_kind {
            TransactionIndexKind::BlockExecution { transaction_index } => {
                (0u128, transaction_index)
            },
            TransactionIndexKind::ValidationOrSimulation { transaction_index } => {
                (1u128, transaction_index)
            },
            TransactionIndexKind::NotAvailable => {
                return Err(SafeNativeError::Abort {
                    abort_code: error::invalid_state(abort_codes::ETRANSACTION_INDEX_NOT_AVAILABLE),
                });
            },
        };

        let mut monotonically_increasing_counter: u128 = reserved_byte << 120;
        monotonically_increasing_counter |= (timestamp_us as u128) << 56;
        monotonically_increasing_counter |= (transaction_index as u128) << 24;
        monotonically_increasing_counter |= session_counter << 16;
        monotonically_increasing_counter |= local_counter;
        Ok(smallvec![Value::u128(monotonically_increasing_counter)])
```

**File:** aptos-move/framework/aptos-experimental/sources/trading/order_book/order_book_types.move (L75-78)
```text
    public fun next_order_id(): OrderIdType {
        // reverse bits to make order ids random, so indices on top of them are shuffled.
        OrderIdType { order_id: reverse_bits(transaction_context::monotonically_increasing_counter()) }
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L831-854)
```rust
        let auxiliary_info: Vec<_> = txns
            .iter()
            .enumerate()
            .map(|(txn_index, txn)| {
                let persisted_auxiliary_info = match persisted_auxiliary_info_version {
                    0 => PersistedAuxiliaryInfo::None,
                    1 => PersistedAuxiliaryInfo::V1 {
                        transaction_index: txn_index as u32,
                    },
                    _ => unimplemented!("Unsupported persisted auxiliary info version"),
                };

                let ephemeral_auxiliary_info = txn
                    .borrow_into_inner()
                    .try_as_signed_user_txn()
                    .and_then(|_| {
                        proposer_index.map(|index| EphemeralAuxiliaryInfo {
                            proposer_index: index as u64,
                        })
                    });

                AuxiliaryInfo::new(persisted_auxiliary_info, ephemeral_auxiliary_info)
            })
            .collect();
```

**File:** aptos-move/aptos-debugger/src/aptos_debugger.rs (L183-217)
```rust
    pub async fn execute_past_transactions(
        &self,
        begin: Version,
        limit: u64,
        use_same_block_boundaries: bool,
        repeat_execution_times: u64,
        concurrency_levels: &[usize],
    ) -> anyhow::Result<Vec<TransactionOutput>> {
        let (txns, txn_infos, auxiliary_infos) =
            self.get_committed_transactions(begin, limit).await?;

        if use_same_block_boundaries {
            // when going block by block, no need to worry about epoch boundaries
            // as new epoch is always a new block.
            Ok(self
                .execute_transactions_by_block(
                    begin,
                    txns.clone(),
                    auxiliary_infos.clone(),
                    repeat_execution_times,
                    concurrency_levels,
                )
                .await?)
        } else {
            self.execute_transactions_by_epoch(
                limit,
                begin,
                txns,
                auxiliary_infos,
                repeat_execution_times,
                concurrency_levels,
                txn_infos,
            )
            .await
        }
```
