# Audit Report

## Title
Write Operation Limit Bypass via Unmaterialized Aggregator V1 Deltas

## Summary
The `check_change_set()` validation in `change_set_configs.rs` counts write operations before aggregator V1 deltas are materialized, allowing transactions to bypass the `max_write_ops_per_transaction` limit by including numerous aggregator operations that are later converted into write operations without re-validation.

## Finding Description

The validation flow contains a critical timing issue:

**Validation Phase (BEFORE materialization):** [1](#0-0) 

The `num_write_ops()` implementation only counts materialized writes: [2](#0-1) 

Notice that `aggregator_v1_delta_set` and `delayed_field_change_set` are **NOT** included in the count.

**Materialization Phase (AFTER validation):** [3](#0-2) 

During materialization, **all** deltas from `aggregator_v1_delta_set` are converted into write operations and added to `aggregator_v1_write_set`: [4](#0-3) 

**No Re-validation After Materialization:** [5](#0-4) 

The `into_transaction_output_with_materialized_write_set()` method extends the write set but performs no write count validation.

**Attack Path:**
1. Attacker creates transaction with minimal resource writes (e.g., 10 operations)
2. Transaction includes extensive aggregator V1 operations (e.g., 5000 delta operations)
3. `check_change_set()` validates only the 10 resource writes, passes limit check
4. `try_materialize_aggregator_v1_delta_set()` converts 5000 deltas into 5000 write operations
5. Final transaction has 5010 write operations, bypassing the configured limit
6. All operations are committed to storage without re-validation

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Storage Bombing**: Transactions can write significantly more data than `max_write_ops_per_transaction` allows, enabling storage exhaustion attacks
2. **Resource Exhaustion**: Validators must process and commit far more writes than intended, causing performance degradation
3. **Deterministic Execution Violation**: Different implementations of validation boundaries could cause consensus splits
4. **DoS Vector**: Repeated exploitation could degrade network performance and increase storage costs

The `max_write_ops_per_transaction` limit exists as a critical resource bound (separate from gas limits). Bypassing it violates the **Resource Limits** invariant that "all operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**High Likelihood** - This vulnerability is:
- **Easily Triggerable**: Any transaction that performs aggregator operations (framework coin operations, fee tracking, etc.) can exploit this
- **Framework-Accessible**: Aggregator V1 operations are available through standard framework functions
- **Unmitigated**: No compensating controls exist - the validation simply doesn't account for unmaterialized deltas
- **Systematic**: Affects all transaction types using aggregator V1 features

The execution flow guarantees this occurs on every transaction with aggregator deltas, making it a deterministic vulnerability rather than a race condition.

## Recommendation

**Solution 1 (Immediate Fix)**: Include unmaterialized deltas in the write operation count:

```rust
fn num_write_ops(&self) -> usize {
    self.resource_write_set().len() 
        + self.aggregator_v1_write_set().len()
        + self.aggregator_v1_delta_set().len()  // ADD THIS
        + self.delayed_field_change_set().len()  // ADD THIS
}
```

**Solution 2 (Defense in Depth)**: Add post-materialization validation in `into_transaction_output_with_materialized_write_set()`:

```rust
pub fn into_transaction_output_with_materialized_write_set(
    mut self,
    materialized_aggregator_v1_deltas: Vec<(StateKey, WriteOp)>,
    patched_resource_write_set: Vec<(StateKey, WriteOp)>,
    patched_events: Vec<ContractEvent>,
) -> Result<TransactionOutput, PanicError> {
    // ... existing materialization code ...
    
    // ADD POST-MATERIALIZATION VALIDATION:
    let total_writes = self.change_set.num_write_ops();
    if total_writes > MAX_ALLOWED_WRITES {
        return Err(code_invariant_error(
            format!("Post-materialization write count {} exceeds limit", total_writes)
        ));
    }
    
    self.into_transaction_output()
}
```

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the validation bypass mechanism
#[test]
fn test_aggregator_delta_bypass() {
    use aptos_vm_types::change_set::VMChangeSet;
    use aptos_vm_types::storage::change_set_configs::ChangeSetConfigs;
    
    // Configure limit of 100 write ops
    let config = ChangeSetConfigs::new(5, &gas_params_with_limit(100));
    
    // Create change set with:
    // - 10 resource writes
    // - 500 aggregator deltas (NOT YET MATERIALIZED)
    let mut change_set = VMChangeSet::new(
        create_resource_writes(10),
        vec![],
        BTreeMap::new(),
        BTreeMap::new(),
        create_aggregator_deltas(500),  // 500 unmaterialized deltas
    );
    
    // Validation sees only 10 writes, PASSES
    assert!(config.check_change_set(&change_set).is_ok());
    
    // Materialize deltas -> converts 500 deltas into 500 writes
    change_set.try_materialize_aggregator_v1_delta_set(&resolver).unwrap();
    
    // Now we have 510 total writes, but NO re-validation occurs
    assert_eq!(change_set.num_write_ops(), 510);  // LIMIT BYPASSED!
    
    // Transaction commits with 510 writes despite 100 write limit
}
```

## Notes

The vulnerability stems from a fundamental architectural decision: validation occurs before materialization. While aggregator deltas are an optimization for parallel execution, their exclusion from write operation counting creates a validation gap. The `max_write_ops_per_transaction` limit is distinct from gas limits and serves to bound storage operations per transaction - bypassing it enables storage bombing attacks that respect gas limits but exceed storage write limits.

The fix should account for the fact that every delta operation will eventually become a write operation, so they must be counted during validation. Alternative implementations using different materialization strategies could exhibit consensus divergence if this validation gap is exploited.

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L86-99)
```rust
    pub fn check_change_set(&self, change_set: &impl ChangeSetInterface) -> Result<(), VMStatus> {
        let storage_write_limit_reached = |maybe_message: Option<&str>| {
            let mut err = PartialVMError::new(StatusCode::STORAGE_WRITE_LIMIT_REACHED);
            if let Some(message) = maybe_message {
                err = err.with_message(message.to_string())
            }
            Err(err.finish(Location::Undefined).into_vm_status())
        };

        if self.max_write_ops_per_transaction != 0
            && change_set.num_write_ops() as u64 > self.max_write_ops_per_transaction
        {
            return storage_write_limit_reached(Some("Too many write ops."));
        }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L365-399)
```rust
    /// Materializes this change set: all aggregator v1 deltas are converted into writes and
    /// are combined with existing aggregator writes. The aggregator v2 changeset is not touched.
    pub fn try_materialize_aggregator_v1_delta_set(
        &mut self,
        resolver: &impl AggregatorV1Resolver,
    ) -> VMResult<()> {
        let into_write =
            |(state_key, delta): (StateKey, DeltaOp)| -> VMResult<(StateKey, WriteOp)> {
                // Materialization is needed when committing a transaction, so
                // we need precise mode to compute the true value of an
                // aggregator.
                let write = resolver
                    .try_convert_aggregator_v1_delta_into_write_op(&state_key, &delta)
                    .map_err(|e| {
                        // We need to set abort location for Aggregator V1 to ensure correct VMStatus can
                        // be constructed.
                        const AGGREGATOR_V1_ADDRESS: AccountAddress = CORE_CODE_ADDRESS;
                        const AGGREGATOR_V1_MODULE_NAME: &IdentStr = ident_str!("aggregator");
                        e.finish(Location::Module(ModuleId::new(
                            AGGREGATOR_V1_ADDRESS,
                            AGGREGATOR_V1_MODULE_NAME.into(),
                        )))
                    })?;
                Ok((state_key, write))
            };

        let aggregator_v1_delta_set = std::mem::take(&mut self.aggregator_v1_delta_set);
        let materialized_aggregator_delta_set = aggregator_v1_delta_set
            .into_iter()
            .map(into_write)
            .collect::<VMResult<BTreeMap<StateKey, WriteOp>>>()?;
        self.aggregator_v1_write_set
            .extend(materialized_aggregator_delta_set);
        Ok(())
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L856-860)
```rust
    fn num_write_ops(&self) -> usize {
        // Note: we only use resources and aggregators because they use write ops directly,
        // and deltas & events are not part of these.
        self.resource_write_set().len() + self.aggregator_v1_write_set().len()
    }
```

**File:** aptos-move/aptos-vm-types/src/output.rs (L220-262)
```rust

    /// Updates the VMChangeSet based on the input aggregator v1 deltas, patched resource write set,
    /// patched events, and generates TransactionOutput
    pub fn into_transaction_output_with_materialized_write_set(
        mut self,
        materialized_aggregator_v1_deltas: Vec<(StateKey, WriteOp)>,
        patched_resource_write_set: Vec<(StateKey, WriteOp)>,
        patched_events: Vec<ContractEvent>,
    ) -> Result<TransactionOutput, PanicError> {
        // materialize aggregator V1 deltas into writes
        if materialized_aggregator_v1_deltas.len() != self.aggregator_v1_delta_set().len() {
            return Err(code_invariant_error(
                "Different number of materialized deltas and deltas in the output.",
            ));
        }
        if !materialized_aggregator_v1_deltas
            .iter()
            .all(|(k, _)| self.aggregator_v1_delta_set().contains_key(k))
        {
            return Err(code_invariant_error(
                "Materialized aggregator writes contain a key which does not exist in delta set.",
            ));
        }
        self.change_set
            .extend_aggregator_v1_write_set(materialized_aggregator_v1_deltas.into_iter());
        // TODO[agg_v2](cleanup) move all drains to happen when getting what to materialize.
        let _ = self.change_set.drain_aggregator_v1_delta_set();

        // materialize delayed fields into resource writes
        self.change_set
            .extend_resource_write_set(patched_resource_write_set.into_iter())?;
        let _ = self.change_set.drain_delayed_field_change_set();

        // materialize delayed fields into events
        if patched_events.len() != self.events().len() {
            return Err(code_invariant_error(
                "Different number of events and patched events in the output.",
            ));
        }
        self.change_set.set_events(patched_events.into_iter());

        self.into_transaction_output()
    }
```
