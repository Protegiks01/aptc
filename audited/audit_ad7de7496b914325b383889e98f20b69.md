# Audit Report

## Title
Event Loss During Post-Execution Cleanup Due to Delayed Field Materialization Failures

## Summary
When `code_invariant_error()` occurs during post-execution cleanup (specifically during event materialization), **all events from the entire block are lost**. Additionally, if a delayed field value is missing during materialization, the validator node **panics and crashes**, causing severe liveness impact.

## Finding Description

During transaction execution, events may contain delayed field identifiers (for aggregators/snapshots). Before finalizing the transaction output, these identifiers must be replaced with actual values during the materialization phase.

The event materialization flow is:

1. Transaction executes successfully and emits events with delayed field IDs [1](#0-0) 

2. During post-execution, `map_id_to_values_events()` is called to replace delayed field IDs with values [2](#0-1) 

3. This calls `replace_identifiers_with_values()` which performs deserialization-serialization to replace IDs [3](#0-2) 

4. During serialization, `identifier_to_value()` looks up the delayed field value [4](#0-3) 

**Critical Issue #1: Node Crash on Missing Value**

The `identifier_to_value()` method uses `.expect()` calls that will **panic** if the delayed field value doesn't exist: [5](#0-4) 

**Critical Issue #2: Event Loss in Sequential Execution**

If `map_id_to_values_events()` fails with `code_invariant_error`: [6](#0-5) 

The error propagates in sequential execution: [7](#0-6) 

This causes the entire sequential execution to fail: [8](#0-7) 

With default configuration (`discard_failed_blocks=false`), the block execution fails and propagates the error: [9](#0-8) 

**Result:** All events from the entire block are lost because no transaction outputs are committed.

**Events Cannot Be Duplicated**

Events use `set_events()` which replaces the entire event vector, preventing duplication: [10](#0-9) 

## Impact Explanation

**High to Critical Severity:**

1. **Node Crash (Critical)**: If delayed field values are missing, `.expect()` panics crash the validator node, causing:
   - Total loss of liveness for that validator
   - Potential consensus disruption if multiple validators affected
   - All pending events lost until node restart

2. **Event Loss (High)**: When deserialization/serialization fails:
   - All events from the entire block are lost
   - Breaks state consistency invariant (events are part of transaction output)
   - Indexers and off-chain systems lose critical data
   - No recovery mechanism - events are permanently lost

3. **Consensus Impact**: While this doesn't directly break consensus safety (all validators would fail identically on the same bug), it severely impacts liveness and data availability.

## Likelihood Explanation

**Low to Medium Likelihood:**

This issue can occur when:
1. A bug in Move VM's delayed field implementation causes missing values
2. A race condition in parallel execution leaves values uncommitted
3. Memory corruption or data structure bugs
4. Layout mismatches between event emission and materialization

While not directly exploitable by an attacker (requires internal VM bugs), the consequences are severe when triggered. The `.expect()` calls indicate the developers assumed this "should never happen," but the use of `code_invariant_error` shows they anticipated potential failures.

## Recommendation

**Immediate Fixes:**

1. **Replace panic with graceful error handling:**

```rust
// In value_exchange.rs, replace .expect() with proper error handling
let delayed_field = match &self.latest_view.latest_view {
    ViewState::Sync(state) => state
        .versioned_map
        .delayed_fields()
        .read_latest_predicted_value(&identifier, self.txn_idx, ReadPosition::AfterCurrentTxn)
        .ok_or_else(|| {
            PartialVMError::new(StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR)
                .with_message(format!("Missing delayed field value for ID {:?}", identifier))
        })?,
    ViewState::Unsync(state) => state
        .read_delayed_field(identifier)
        .ok_or_else(|| {
            PartialVMError::new(StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR)
                .with_message(format!("Missing delayed field value for ID {:?} in sequential execution", identifier))
        })?,
};
```

2. **Add per-transaction error handling instead of block-level:**

Modify sequential execution to handle materialization failures per transaction rather than failing the entire block. Discard only the failing transaction and continue with others.

3. **Add defensive validation:**

Before materialization, validate that all delayed field IDs in events have corresponding values in the versioned/unsync map.

## Proof of Concept

This vulnerability cannot be easily demonstrated with a standalone PoC because it requires triggering an internal VM bug. However, the execution flow can be traced:

```rust
// Reproduction steps (conceptual):
// 1. Create a transaction that emits an event with a delayed field
// 2. Introduce a bug that causes the delayed field value to not be stored
// 3. Execute the transaction
// 4. During event materialization, the node will panic

// Expected outcome:
// - Node crashes at value_exchange.rs:101 or 104
// - OR code_invariant_error propagates, causing block failure and event loss

// Test scenario that could trigger this:
// - Use aggregator in Move code
// - Emit event containing the aggregator value  
// - If there's a bug in aggregator value storage, materialization will fail
```

## Notes

**Answer to Security Question:**

**YES, events CAN be lost** when `code_invariant_error()` occurs during post-execution cleanup:
- In production (default `discard_failed_blocks=false`): Entire block fails, all events lost
- With `discard_failed_blocks=true`: All transactions discarded, all events lost  
- If panic occurs: Node crashes, all pending events lost

**NO, events CANNOT be duplicated** because `set_events()` replaces the event vector entirely rather than appending.

The vulnerability breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable" - events are part of the transaction output and should not be lost if transactions executed successfully.

### Citations

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L83-83)
```rust
    events: Vec<(ContractEvent, Option<MoveTypeLayout>)>,
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L331-335)
```rust
    pub(crate) fn set_events(&mut self, materialized_events: impl Iterator<Item = ContractEvent>) {
        self.events = materialized_events
            .map(|event| (event, None))
            .collect::<Vec<_>>();
    }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L252-278)
```rust
pub(crate) fn map_id_to_values_events<T: Transaction, S: TStateView<Key = T::Key> + Sync>(
    events: Box<dyn Iterator<Item = (T::Event, Option<MoveTypeLayout>)>>,
    latest_view: &LatestView<T, S>,
) -> Result<Vec<T::Event>, PanicError> {
    events
        .map(|(event, layout)| {
            if let Some(layout) = layout {
                let event_data = event.get_event_data();
                latest_view
                    .replace_identifiers_with_values(&Bytes::from(event_data.to_vec()), &layout)
                    .map(|(bytes, _)| {
                        let mut patched_event = event;
                        patched_event.set_event_data(bytes.to_vec());
                        patched_event
                    })
                    .map_err(|_| {
                        code_invariant_error(format!(
                            "Failed to replace identifiers with values in an event {:?}",
                            layout
                        ))
                    })
            } else {
                Ok(event)
            }
        })
        .collect::<Result<Vec<_>, PanicError>>()
}
```

**File:** aptos-move/block-executor/src/view.rs (L1269-1335)
```rust
    pub(crate) fn replace_identifiers_with_values(
        &self,
        bytes: &Bytes,
        layout: &MoveTypeLayout,
    ) -> anyhow::Result<(Bytes, HashSet<DelayedFieldID>)> {
        // Cfg due to deserialize_to_delayed_field_id use.
        #[cfg(test)]
        fail_point!("delayed_field_test", |_| {
            assert_eq!(
                layout,
                &mock_layout(),
                "Layout does not match expected mock layout"
            );

            // Replicate the logic of identifier_to_value.
            let (delayed_field_id, txn_idx) = deserialize_to_delayed_field_id(bytes)
                .expect("Mock deserialization failed in delayed field test.");
            let delayed_field = match &self.latest_view {
                ViewState::Sync(state) => state
                    .versioned_map
                    .delayed_fields()
                    .read_latest_predicted_value(
                        &delayed_field_id,
                        self.txn_idx,
                        ReadPosition::AfterCurrentTxn,
                    )
                    .expect("Committed value for ID must always exist"),
                ViewState::Unsync(state) => state
                    .read_delayed_field(delayed_field_id)
                    .expect("Delayed field value for ID must always exist in sequential execution"),
            };

            // Note: Test correctness relies on the fact that current proptests use the
            // same layout for all values ever stored at any key, given that some value
            // at the key contains a delayed field.
            Ok((
                serialize_from_delayed_field_u128(
                    delayed_field.into_aggregator_value().unwrap(),
                    txn_idx,
                ),
                HashSet::from([delayed_field_id]),
            ))
        });

        // This call will replace all occurrences of aggregator / snapshot
        // identifiers with values with the same type layout.
        let function_value_extension = self.as_function_value_extension();
        let value = ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_func_args_deserialization(&function_value_extension)
            .with_delayed_fields_serde()
            .deserialize(bytes, layout)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to deserialize resource during id replacement: {:?}",
                    bytes
                )
            })?;

        let mapping = TemporaryValueToIdentifierMapping::new(self, self.txn_idx);
        let patched_bytes = ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_delayed_fields_replacement(&mapping)
            .with_func_args_deserialization(&function_value_extension)
            .serialize(&value, layout)?
            .ok_or_else(|| anyhow::anyhow!("Failed to serialize resource during id replacement"))?
            .into();
        Ok((patched_bytes, mapping.into_inner()))
    }
```

**File:** aptos-move/block-executor/src/value_exchange.rs (L86-107)
```rust
    fn identifier_to_value(
        &self,
        layout: &MoveTypeLayout,
        identifier: DelayedFieldID,
    ) -> PartialVMResult<Value> {
        self.delayed_field_ids.borrow_mut().insert(identifier);
        let delayed_field = match &self.latest_view.latest_view {
            ViewState::Sync(state) => state
                .versioned_map
                .delayed_fields()
                .read_latest_predicted_value(
                    &identifier,
                    self.txn_idx,
                    ReadPosition::AfterCurrentTxn,
                )
                .expect("Committed value for ID must always exist"),
            ViewState::Unsync(state) => state
                .read_delayed_field(identifier)
                .expect("Delayed field value for ID must always exist in sequential execution"),
        };
        delayed_field.try_into_move_value(layout, identifier.extract_width())
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L2456-2459)
```rust
                        let materialized_events = map_id_to_values_events(
                            Box::new(output_before_guard.get_events().into_iter()),
                            &latest_view,
                        )?;
```

**File:** aptos-move/block-executor/src/executor.rs (L2648-2665)
```rust
        if self.config.local.discard_failed_blocks {
            // We cannot execute block, discard everything (including block metadata and validator transactions)
            // (TODO: maybe we should add fallback here to first try BlockMetadataTransaction alone)
            let error_code = match sequential_error {
                BlockExecutionError::FatalBlockExecutorError(_) => {
                    StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
                },
                BlockExecutionError::FatalVMError(_) => {
                    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                },
            };
            let ret = (0..signature_verified_block.num_txns())
                .map(|_| E::Output::discard_output(error_code))
                .collect();
            return Ok(BlockOutput::new(ret, None));
        }

        Err(sequential_error)
```

**File:** aptos-move/block-executor/src/errors.rs (L48-53)
```rust
impl<E> From<PanicError> for SequentialBlockExecutionError<E> {
    fn from(err: PanicError) -> Self {
        SequentialBlockExecutionError::ErrorToReturn(BlockExecutionError::FatalBlockExecutorError(
            err,
        ))
    }
```
