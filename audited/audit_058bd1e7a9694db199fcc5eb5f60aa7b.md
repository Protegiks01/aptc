# Audit Report

## Title
Change Set Validation Bypass via Unmaterialized Aggregator Deltas and Delayed Fields

## Summary
The `check_change_set()` validation in `ChangeSetConfigs` fails to count aggregator v1 deltas (`aggregator_v1_delta_set`) and delayed field changes (`delayed_field_change_set`) when validating transaction change sets. This allows transactions to bypass configured safety limits (`max_write_ops_per_transaction`, `max_bytes_all_write_ops_per_transaction`) that are designed to prevent resource exhaustion and ensure deterministic execution across validators.

## Finding Description

The vulnerability exists in the change set validation flow for both system sessions (prologue, abort hook) and user sessions: [1](#0-0) 

The `check_change_set()` method validates change sets against safety limits by calling methods on the `ChangeSetInterface` trait. However, the implementation of this trait for `VMChangeSet` is incomplete: [2](#0-1) 

The `num_write_ops()` method only counts `resource_write_set` and `aggregator_v1_write_set`, explicitly excluding `aggregator_v1_delta_set` and `delayed_field_change_set`. Similarly, `write_set_size_iter()` only iterates over materialized writes, not deltas or delayed fields.

**Attack Flow:**

1. A transaction (user, prologue, or abort hook) executes Move code that creates many aggregator delta operations or delayed field changes
2. These operations are stored in `aggregator_v1_delta_set` or `delayed_field_change_set` within the `VMChangeSet` [3](#0-2) 

3. When `SystemSessionChangeSet::new()` or `UserSessionChangeSet::new()` is called, it validates the change set: [4](#0-3) 

4. The validation passes because deltas and delayed fields are not counted toward the limits
5. Later, during materialization in the block executor, these deltas are converted to actual write operations: [5](#0-4) 

6. The materialized writes could exceed the configured safety limits, but no re-validation occurs after materialization
7. This bypasses the safety checks that exist to prevent resource exhaustion

## Impact Explanation

**Severity: Medium to High**

This vulnerability breaks the **Resource Limits** invariant (#9) which states "All operations must respect gas, storage, and computational limits." The safety limits in `ChangeSetConfigs` exist to:

- Prevent resource exhaustion on validator nodes
- Ensure deterministic transaction execution across all validators
- Protect against storage bombing attacks
- Maintain block size constraints

By bypassing these limits, an attacker could:

1. **Resource Exhaustion**: Create transactions that appear small during validation but materialize to large write sets, exhausting validator memory and disk I/O
2. **Database Bloat**: Repeatedly submit transactions with many aggregator deltas that bypass write count limits, causing database size to grow beyond intended constraints
3. **Validator Slowdown**: Force validators to process and materialize more writes than the safety limits intended, degrading network performance

The configured limits vary by gas feature version: [6](#0-5) 

For feature version 3+, limits like 1MB per write op exist. Feature version 5+ uses gas parameters. Bypassing these limits could allow writes significantly larger than intended safety bounds.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is exploitable if:

1. **Aggregator Usage**: Transactions can create aggregator deltas through Move code that uses aggregator v1 or aggregator v2 operations (add, sub, create). These are available in the Aptos Framework and can be called by user contracts
2. **Delta Accumulation**: An attacker creates many small aggregator operations that each produce a delta, accumulating numerous deltas without being counted during validation
3. **Materialization Exceeds Limits**: When materialized, the sum of all delta-derived writes exceeds `max_write_ops_per_transaction` or `max_bytes_all_write_ops_per_transaction`

The comment in the code acknowledges deltas are excluded: [7](#0-6) 

This suggests the exclusion may be intentional, but it creates a security gap because materialization happens without re-validation.

## Recommendation

**Solution 1: Validate After Materialization**

Add a validation step after materialization to ensure the final write set doesn't exceed limits:

```rust
// In VMOutput or TransactionOutput creation
pub fn try_materialize_into_transaction_output(
    mut self,
    resolver: &impl AggregatorV1Resolver,
    change_set_configs: &ChangeSetConfigs,
) -> VMResult<TransactionOutput> {
    self.try_materialize(resolver)?;
    
    // Re-validate after materialization
    change_set_configs.check_change_set(&self.change_set)?;
    
    // ... continue with conversion
}
```

**Solution 2: Count Deltas as Writes**

Modify `ChangeSetInterface` implementation to count deltas and delayed fields as potential writes:

```rust
impl ChangeSetInterface for VMChangeSet {
    fn num_write_ops(&self) -> usize {
        self.resource_write_set().len() 
            + self.aggregator_v1_write_set().len()
            + self.aggregator_v1_delta_set().len()  // Add this
            + self.delayed_field_change_set().len()  // Add this
    }
    
    fn write_set_size_iter(&self) -> impl Iterator<Item = (&StateKey, WriteOpSize)> {
        // Include estimated sizes for deltas and delayed fields
        // ...
    }
}
```

**Solution 3: Enforce Limits During Delta Creation**

Add limits specifically for deltas and delayed fields in `ChangeSetConfigs` and check them during session execution before finalization.

**Recommended: Solution 1** - It's the safest approach as it validates the actual materialized output that will be committed to storage.

## Proof of Concept

```rust
// Move test demonstrating bypass (conceptual)
module attacker::bypass_test {
    use aptos_framework::aggregator_v2;
    
    public entry fun exploit_aggregator_bypass(account: &signer) {
        // Create many aggregators (each creates a delayed field change)
        let i = 0;
        while (i < 10000) {  // Exceeds max_write_ops_per_transaction
            let agg = aggregator_v2::create_unbounded_aggregator<u64>();
            aggregator_v2::add(&mut agg, 1);  // Creates delta operation
            aggregator_v2::destroy(agg);
            i = i + 1;
        };
        
        // During validation: deltas not counted, passes check_change_set
        // During materialization: 10000 writes created, exceeds limits
        // No re-validation occurs
    }
}
```

**Validation Steps:**
1. Deploy the above Move module
2. Execute the entry function with `max_write_ops_per_transaction` set to a value < 10000
3. Observe that validation passes during `check_change_set()`
4. Observe that materialization creates more write ops than the configured limit
5. No error is raised after materialization despite exceeding safety bounds

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L68-84)
```rust
    fn for_feature_version_3() -> Self {
        const MB: u64 = 1 << 20;

        Self::new_impl(3, MB, u64::MAX, MB, 10 * MB, u64::MAX)
    }

    fn from_gas_params(gas_feature_version: u64, gas_params: &AptosGasParameters) -> Self {
        let params = &gas_params.vm.txn;
        Self::new_impl(
            gas_feature_version,
            params.max_bytes_per_write_op.into(),
            params.max_bytes_all_write_ops_per_transaction.into(),
            params.max_bytes_per_event.into(),
            params.max_bytes_all_events_per_transaction.into(),
            params.max_write_ops_per_transaction.into(),
        )
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L86-128)
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

        let mut write_set_size = 0;
        for (key, op_size) in change_set.write_set_size_iter() {
            if let Some(len) = op_size.write_len() {
                let write_op_size = len + (key.size() as u64);
                if write_op_size > self.max_bytes_per_write_op {
                    return storage_write_limit_reached(None);
                }
                write_set_size += write_op_size;
            }
            if write_set_size > self.max_bytes_all_write_ops_per_transaction {
                return storage_write_limit_reached(None);
            }
        }

        let mut total_event_size = 0;
        for event in change_set.events_iter() {
            let size = event.event_data().len() as u64;
            if size > self.max_bytes_per_event {
                return storage_write_limit_reached(None);
            }
            total_event_size += size;
            if total_event_size > self.max_bytes_all_events_per_transaction {
                return storage_write_limit_reached(None);
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L76-92)
```rust
/// A change set produced by the VM.
///
/// **WARNING**: Just like VMOutput, this type should only be used inside the
/// VM. For storage backends, use `ChangeSet`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VMChangeSet {
    resource_write_set: BTreeMap<StateKey, AbstractResourceWriteOp>,
    events: Vec<(ContractEvent, Option<MoveTypeLayout>)>,

    // Changes separated out from the writes, for better concurrency,
    // materialized back into resources when transaction output is computed.
    delayed_field_change_set: BTreeMap<DelayedFieldID, DelayedChange<DelayedFieldID>>,

    // TODO[agg_v1](cleanup) deprecate aggregator_v1 fields.
    aggregator_v1_write_set: BTreeMap<StateKey, WriteOp>,
    aggregator_v1_delta_set: BTreeMap<StateKey, DeltaOp>,
}
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L367-399)
```rust
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

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L855-908)
```rust
impl ChangeSetInterface for VMChangeSet {
    fn num_write_ops(&self) -> usize {
        // Note: we only use resources and aggregators because they use write ops directly,
        // and deltas & events are not part of these.
        self.resource_write_set().len() + self.aggregator_v1_write_set().len()
    }

    fn write_set_size_iter(&self) -> impl Iterator<Item = (&StateKey, WriteOpSize)> {
        self.resource_write_set()
            .iter()
            .map(|(k, v)| (k, v.materialized_size()))
            .chain(
                self.aggregator_v1_write_set()
                    .iter()
                    .map(|(k, v)| (k, v.write_op_size())),
            )
    }

    fn write_op_info_iter_mut<'a>(
        &'a mut self,
        executor_view: &'a dyn ExecutorView,
        _module_storage: &'a impl AptosModuleStorage,
        fix_prev_materialized_size: bool,
    ) -> impl Iterator<Item = PartialVMResult<WriteOpInfo<'a>>> {
        let resources = self.resource_write_set.iter_mut().map(move |(key, op)| {
            Ok(WriteOpInfo {
                key,
                op_size: op.materialized_size(),
                prev_size: op.prev_materialized_size(
                    key,
                    executor_view,
                    fix_prev_materialized_size,
                )?,
                metadata_mut: op.metadata_mut(),
            })
        });
        let v1_aggregators = self.aggregator_v1_write_set.iter_mut().map(|(key, op)| {
            Ok(WriteOpInfo {
                key,
                op_size: op.write_op_size(),
                prev_size: executor_view
                    .get_aggregator_v1_state_value_size(key)?
                    .unwrap_or(0),
                metadata_mut: op.metadata_mut(),
            })
        });

        resources.chain(v1_aggregators)
    }

    fn events_iter(&self) -> impl Iterator<Item = &ContractEvent> {
        self.events().iter().map(|(e, _)| e)
    }
}
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L74-82)
```rust
impl SystemSessionChangeSet {
    pub(crate) fn new(
        change_set: VMChangeSet,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<Self, VMStatus> {
        let system_session_change_set = Self { change_set };
        change_set_configs.check_change_set(&system_session_change_set)?;
        Ok(system_session_change_set)
    }
```
