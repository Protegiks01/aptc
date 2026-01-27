# Audit Report

## Title
Genesis Transaction Bypasses Move Bytecode Verification for Direct WriteSet Payloads

## Summary
Genesis transactions with `WriteSetPayload::Direct` containing Move modules are not validated for correct bytecode structure before waypoint generation and commitment to storage. Malformed or invalid Move bytecode can be written directly to the initial chain state, potentially causing consensus failures when validators attempt to load and execute these corrupt modules.

## Finding Description

The `generate_waypoint()` function in `db_bootstrapper/mod.rs` accepts genesis transactions and generates a waypoint from the resulting state without validating Move bytecode in `WriteSetPayload::Direct` payloads. [1](#0-0) 

The execution flow proceeds through `calculate_genesis()`: [2](#0-1) 

For genesis transactions, the VM calls `process_waypoint_change_set()`: [3](#0-2) 

Which calls `execute_write_set()`: [4](#0-3) 

For `WriteSetPayload::Direct`, the critical function `create_vm_change_set_with_module_write_set_when_delayed_field_optimization_disabled()` simply extracts modules from the write set WITHOUT any bytecode verification: [5](#0-4) 

The only validation performed is checking for epoch/block events: [6](#0-5) 

**In contrast**, when genesis modules are created through the official `vm-genesis` crate, they ARE properly verified through `StagingModuleStorage::create()`: [7](#0-6) [8](#0-7) 

This creates a validation asymmetry: properly created genesis transactions contain verified bytecode, but the execution path accepts ANY bytecode without verification.

**Attack Scenario:**
1. Attacker crafts malicious `genesis.blob` file with `Transaction::GenesisTransaction(WriteSetPayload::Direct(change_set))` containing:
   - Valid resource initializations and epoch change events
   - **Malformed Move bytecode** for critical framework modules (invalid opcodes, corrupted structure, etc.)

2. Genesis transaction passes through `calculate_genesis()` without bytecode validation

3. Waypoint is generated from corrupt state root

4. Genesis is committed to database with invalid bytecode

5. When validators execute first real transaction after genesis:
   - Transaction requires loading a framework module
   - Module deserialization/verification fails at load time
   - Different validators may fail at different points depending on which modules they access
   - **Consensus breaks** because validators cannot agree on execution results

## Impact Explanation

**Critical Severity** - This meets the criteria for "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)":

- **Breaks Invariant #1 (Deterministic Execution)**: Validators produce different state roots when corrupt modules fail to load at different execution points
- **Breaks Invariant #3 (Move VM Safety)**: Invalid bytecode bypasses verification, violating the guarantee that all on-chain code is safe
- **Breaks Invariant #4 (State Consistency)**: Initial chain state contains unverifiable bytecode

The impact is permanent corruption of the genesis state that cannot be recovered without a complete chain restart and hardfork.

## Likelihood Explanation

**Low-to-Medium Likelihood** - While the technical vulnerability is real, exploitation requires operational compromise:

- Attacker must be able to provide a malicious genesis.blob file to validators
- Requires either compromising the genesis creation process OR convincing validators to use an untrusted genesis file
- Not exploitable by a purely external, unprivileged attacker without social engineering or insider access

However, the vulnerability represents a critical defense-in-depth failure that violates security invariants.

## Recommendation

Add Move bytecode verification for all modules in `WriteSetPayload::Direct` before waypoint generation. Modify `execute_write_set()` to deserialize and verify module bytecode:

```rust
fn execute_write_set(
    &self,
    resolver: &impl AptosMoveResolver,
    code_storage: &impl AptosCodeStorage,
    write_set_payload: &WriteSetPayload,
    txn_sender: Option<AccountAddress>,
    session_id: SessionId,
) -> Result<(VMChangeSet, ModuleWriteSet), VMStatus> {
    match write_set_payload {
        WriteSetPayload::Direct(change_set) => {
            let (change_set, module_write_set) =
                create_vm_change_set_with_module_write_set_when_delayed_field_optimization_disabled(
                    change_set.clone(),
                );
            
            // ADD: Verify all modules in the write set
            for (state_key, module_write) in module_write_set.writes() {
                if let Some(write_op) = module_write.write_op().as_state_value() {
                    // Deserialize and verify the module bytecode
                    let module_bytes = write_op.bytes();
                    let compiled_module = CompiledModule::deserialize_with_config(
                        module_bytes,
                        &self.runtime_environment().vm_config().deserializer_config
                    ).map_err(|e| {
                        VMStatus::error(
                            StatusCode::CODE_DESERIALIZATION_ERROR,
                            Some(format!("Genesis module deserialization failed: {}", e))
                        )
                    })?;
                    
                    // Verify the module bytecode
                    move_bytecode_verifier::verify_module_with_config(
                        &compiled_module,
                        &self.runtime_environment().vm_config().verifier_config
                    ).map_err(|e| {
                        VMStatus::error(
                            StatusCode::VERIFICATION_ERROR,
                            Some(format!("Genesis module verification failed: {}", e))
                        )
                    })?;
                }
            }
            
            Ok((change_set, module_write_set))
        },
        WriteSetPayload::Script { script, execute_as } => {
            // ... existing script validation path ...
        }
    }
}
```

## Proof of Concept

```rust
// Create a malicious genesis transaction with invalid bytecode
use aptos_types::transaction::{Transaction, WriteSetPayload, ChangeSet};
use aptos_types::write_set::{WriteSet, WriteSetMut, WriteOp};
use aptos_types::state_store::state_key::StateKey;
use move_core_types::language_storage::ModuleId;

// Create invalid module bytecode (corrupted magic bytes)
let invalid_bytecode = vec![0xFF; 100]; // Invalid Move bytecode

let mut write_set_mut = WriteSetMut::new(vec![]);
let module_id = ModuleId::new(
    AccountAddress::from_hex_literal("0x1").unwrap(),
    Identifier::new("invalid_module").unwrap()
);

// Add invalid module to write set
let state_key = StateKey::module(&module_id.address(), &module_id.name());
write_set_mut.insert((state_key, WriteOp::legacy_creation(invalid_bytecode.into())));

// Add valid epoch change events to pass validation
let events = vec![/* NewEpochEvent and NewBlockEvent */];

let change_set = ChangeSet::new(
    write_set_mut.freeze().unwrap(),
    events
);

let genesis_txn = Transaction::GenesisTransaction(
    WriteSetPayload::Direct(change_set)
);

// This will pass through generate_waypoint() without bytecode verification
// and corrupt the initial chain state
```

**Note on Exploitability**: While this vulnerability represents a real validation gap that violates security invariants, it does NOT meet the strict exploitability requirement of being usable by an unprivileged attacker without operational access. The attacker must either compromise the genesis creation process or convince validators to use a malicious genesis file, which requires privileged access or social engineering.

Given the explicit validation checklist requirement that vulnerabilities must be "exploitable by unprivileged attacker (no validator insider access required)", this finding does not fully satisfy the bounty program criteria despite being a genuine security weakness.

---

## Notes

The validation gap exists and should be fixed for defense-in-depth, but practical exploitation requires operational compromise rather than a purely technical attack vector available to unprivileged actors. The official genesis creation process (`vm-genesis` crate) does verify modules correctly, so this vulnerability would only manifest if validators are provided with a maliciously crafted genesis file outside the normal chain initialization process.

### Citations

**File:** execution/executor/src/db_bootstrapper/mod.rs (L35-43)
```rust
pub fn generate_waypoint<V: VMBlockExecutor>(
    db: &DbReaderWriter,
    genesis_txn: &Transaction,
) -> Result<Waypoint> {
    let ledger_summary = db.reader.get_pre_committed_ledger_summary()?;

    let committer = calculate_genesis::<V>(db, ledger_summary, genesis_txn)?;
    Ok(committer.waypoint)
}
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L115-150)
```rust
pub fn calculate_genesis<V: VMBlockExecutor>(
    db: &DbReaderWriter,
    ledger_summary: LedgerSummary,
    genesis_txn: &Transaction,
) -> Result<GenesisCommitter> {
    // DB bootstrapper works on either an empty transaction accumulator or an existing block chain.
    // In the very extreme and sad situation of losing quorum among validators, we refer to the
    // second use case said above.
    let genesis_version = ledger_summary.version().map_or(0, |v| v + 1);
    let base_state_view = CachedStateView::new(
        StateViewId::Miscellaneous,
        Arc::clone(&db.reader),
        ledger_summary.state.latest().clone(),
    )?;

    let epoch = if genesis_version == 0 {
        GENESIS_EPOCH
    } else {
        get_state_epoch(&base_state_view)?
    };

    let execution_output = DoGetExecutionOutput::by_transaction_execution::<V>(
        &V::new(),
        vec![genesis_txn.clone().into()].into(),
        // TODO(grao): Do we need any auxiliary info for hard fork? Not now, but maybe one day we
        // will need it.
        vec![AuxiliaryInfo::new_empty()],
        &ledger_summary.state,
        base_state_view,
        BlockExecutorConfigFromOnchain::new_no_block_limit(),
        TransactionSliceMetadata::unknown(),
    )?;
    ensure!(
        execution_output.num_transactions_to_commit() != 0,
        "Genesis txn execution failed."
    );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2266-2295)
```rust
    fn execute_write_set(
        &self,
        resolver: &impl AptosMoveResolver,
        code_storage: &impl AptosCodeStorage,
        write_set_payload: &WriteSetPayload,
        txn_sender: Option<AccountAddress>,
        session_id: SessionId,
    ) -> Result<(VMChangeSet, ModuleWriteSet), VMStatus> {
        match write_set_payload {
            WriteSetPayload::Direct(change_set) => {
                // this transaction is never delayed field capable.
                // it requires restarting execution afterwards,
                // which allows it to be used as last transaction in delayed_field_enabled context.
                let (change_set, module_write_set) =
                    create_vm_change_set_with_module_write_set_when_delayed_field_optimization_disabled(
                        change_set.clone(),
                    );

                // validate_waypoint_change_set checks that this is true, so we only log here.
                if !Self::should_restart_execution(change_set.events()) {
                    // This invariant needs to hold irrespectively, so we log error always.
                    // but if we are in delayed_field_optimization_capable context, we cannot execute any transaction after this.
                    // as transaction afterwards would be executed assuming delayed fields are exchanged and
                    // resource groups are split, but WriteSetPayload::Direct has materialized writes,
                    // and so after executing this transaction versioned state is inconsistent.
                    error!(
                        "[aptos_vm] direct write set finished without requiring should_restart_execution");
                }

                Ok((change_set, module_write_set))
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2365-2382)
```rust
    fn validate_waypoint_change_set(
        events: &[(ContractEvent, Option<MoveTypeLayout>)],
        log_context: &AdapterLogSchema,
    ) -> Result<(), VMStatus> {
        let has_new_block_event = events
            .iter()
            .any(|(e, _)| e.event_key() == Some(&new_block_event_key()));
        let has_new_epoch_event = events.iter().any(|(e, _)| e.is_new_epoch_event());
        if has_new_block_event && has_new_epoch_event {
            Ok(())
        } else {
            error!(
                *log_context,
                "[aptos_vm] waypoint txn needs to emit new epoch and block"
            );
            Err(VMStatus::error(StatusCode::INVALID_WRITE_SET, None))
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2908-2916)
```rust
            Transaction::GenesisTransaction(write_set_payload) => {
                let (vm_status, output) = self.process_waypoint_change_set(
                    resolver,
                    code_storage,
                    write_set_payload.clone(),
                    log_context,
                )?;
                (vm_status, output)
            },
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L789-826)
```rust
pub fn create_vm_change_set_with_module_write_set_when_delayed_field_optimization_disabled(
    change_set: StorageChangeSet,
) -> (VMChangeSet, ModuleWriteSet) {
    let (write_set, events) = change_set.into_inner();

    // There should be no aggregator writes if we have a change set from
    // storage.
    let mut resource_write_set = BTreeMap::new();
    let mut module_write_ops = BTreeMap::new();

    for (state_key, write_op) in write_set.expect_into_write_op_iter() {
        if let StateKeyInner::AccessPath(ap) = state_key.inner() {
            if let Some(module_id) = ap.try_get_module_id() {
                module_write_ops.insert(state_key, ModuleWrite::new(module_id, write_op));
                continue;
            }
        }

        // TODO[agg_v1](fix) While everything else must be a resource, first
        // version of aggregators is implemented as a table item. Revisit when
        // we split MVHashMap into data and aggregators.

        // We can set layout to None, as we are not in the is_delayed_field_optimization_capable context
        resource_write_set.insert(state_key, AbstractResourceWriteOp::Write(write_op));
    }

    // We can set layout to None, as we are not in the is_delayed_field_optimization_capable context
    let events = events.into_iter().map(|event| (event, None)).collect();
    let change_set = VMChangeSet::new(
        resource_write_set,
        events,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );

    let module_write_set = ModuleWriteSet::new(module_write_ops);
    (change_set, module_write_set)
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1128-1150)
```rust
fn code_to_writes_for_publishing(
    genesis_runtime_environment: &RuntimeEnvironment,
    genesis_features: &Features,
    genesis_state_view: &GenesisStateView,
    addr: AccountAddress,
    code: Vec<Bytes>,
) -> VMResult<BTreeMap<StateKey, ModuleWrite<WriteOp>>> {
    let module_storage = genesis_state_view.as_aptos_code_storage(genesis_runtime_environment);
    let resolver = genesis_state_view.as_move_resolver();

    let module_storage_with_staged_modules =
        StagingModuleStorage::create(&addr, &module_storage, code)?;
    let verified_module_bundle =
        module_storage_with_staged_modules.release_verified_module_bundle();

    convert_modules_into_write_ops(
        &resolver,
        genesis_features,
        &module_storage,
        verified_module_bundle,
    )
    .map_err(|e| e.finish(Location::Undefined))
}
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L95-152)
```rust
impl<'a, M: ModuleStorage> StagingModuleStorage<'a, M> {
    /// Returns new module storage with staged modules, running full compatability checks for them.
    pub fn create(
        sender: &AccountAddress,
        existing_module_storage: &'a M,
        module_bundle: Vec<Bytes>,
    ) -> VMResult<Self> {
        Self::create_with_compat_config(
            sender,
            Compatibility::full_check(),
            existing_module_storage,
            module_bundle,
        )
    }

    /// Returns new module storage with staged modules, checking compatibility based on the
    /// provided config.
    pub fn create_with_compat_config(
        sender: &AccountAddress,
        compatibility: Compatibility,
        existing_module_storage: &'a M,
        module_bundle: Vec<Bytes>,
    ) -> VMResult<Self> {
        // Create a new runtime environment, so that it is not shared with the existing one. This
        // is extremely important for correctness of module publishing: we need to make sure that
        // no speculative information is cached! By cloning the environment, we ensure that when
        // using this new module storage with changes, global caches are not accessed. Only when
        // the published module is committed, and its structs are accessed, their information will
        // be cached in the global runtime environment.
        //
        // Note: cloning the environment is relatively cheap because it only stores global caches
        // that cannot be invalidated by module upgrades using a shared pointer, so it is not a
        // deep copy. See implementation of Clone for this struct for more details.
        let staged_runtime_environment = existing_module_storage.runtime_environment().clone();
        let is_lazy_loading_enabled = existing_module_storage
            .runtime_environment()
            .vm_config()
            .enable_lazy_loading;
        let is_enum_option_enabled = staged_runtime_environment.vm_config().enable_enum_option;
        let is_framework_for_option_enabled = staged_runtime_environment
            .vm_config()
            .enable_framework_for_option;
        let deserializer_config = &staged_runtime_environment.vm_config().deserializer_config;

        // For every module in bundle, run compatibility checks and construct a new bytes storage
        // view such that added modules shadow any existing ones.
        let mut staged_modules = BTreeMap::new();
        for module_bytes in module_bundle {
            let compiled_module =
                CompiledModule::deserialize_with_config(&module_bytes, deserializer_config)
                    .map(Arc::new)
                    .map_err(|err| {
                        err.append_message_with_separator(
                            '\n',
                            "[VM] module deserialization failed".to_string(),
                        )
                        .finish(Location::Undefined)
                    })?;
```
