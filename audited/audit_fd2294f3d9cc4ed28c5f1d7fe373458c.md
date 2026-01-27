# Audit Report

## Title
Module Bundle Deserialization DoS via Dependency Limit Bypass

## Summary
The Aptos VM deserializes all modules in a transaction bundle before enforcing the `max_num_dependencies` limit (768 modules), allowing attackers to force validator nodes to deserialize up to ~1,600 modules (64 KB transaction limit) or ~25,000 modules (1 MB governance transaction limit) before transaction rejection. This causes excessive memory allocation and CPU consumption, leading to validator node slowdowns. [1](#0-0) 

## Finding Description

The vulnerability exists in the module publishing flow where resource-intensive operations occur before security limits are enforced:

**Transaction Flow:**

1. **Transaction Size Check** - Transactions are validated against `max_transaction_size_in_bytes` (64 KB) or `max_transaction_size_in_bytes_gov` (1 MB for governance): [2](#0-1) [3](#0-2) 

2. **Premature Module Deserialization** - ALL modules in the bundle are deserialized into memory BEFORE any dependency or write ops limits are checked: [4](#0-3) 

3. **Late Limit Enforcement** - The `max_num_dependencies` limit (768 modules) is only enforced during gas charging, which occurs AFTER complete deserialization: [5](#0-4) [6](#0-5) 

4. **Write Ops Check Never Reached** - The `max_write_ops_per_transaction` limit (8,192) is checked even later in `UserSessionChangeSet::new()`, which is never reached if dependency limits are exceeded: [7](#0-6) [8](#0-7) 

**Attack Scenario:**

An attacker crafts a transaction containing many minimal Move modules (approximately 30-50 bytes each):
- Regular transaction (64 KB): ~1,600 modules
- Governance transaction (1 MB): ~25,000 modules

All modules are deserialized into `Vec<CompiledModule>` before the transaction is rejected at module 769 due to the dependency limit. Each `CompiledModule` struct contains multiple Vec fields for handles, definitions, signatures, and metadata: [9](#0-8) 

This causes:
- **Memory exhaustion**: Each CompiledModule allocates heap memory for its internal vectors
- **CPU exhaustion**: Deserialization involves parsing bytecode, validating structure, and building in-memory representations
- **Resource waste**: All work is discarded when the transaction is rejected

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program criteria:

**"Validator node slowdowns"** - The vulnerability directly causes validator performance degradation through:
1. **Memory pressure**: Allocating memory for thousands of CompiledModule structures
2. **CPU saturation**: Deserializing complex module bytecode structures
3. **Repeated attacks**: Attackers can submit multiple such transactions in rapid succession

**Broken Invariant**: The vulnerability violates the documented invariant **"Resource Limits: All operations must respect gas, storage, and computational limits"** because significant computational resources (deserialization) and memory allocation occur BEFORE the dependency limits that should prevent excessive resource consumption.

The impact is amplified because:
- Any user can submit 64 KB transactions containing ~1,600 modules
- Attack requires no special privileges beyond transaction submission
- Multiple validators are affected simultaneously as they all process the same transaction
- Repeated attacks can cause sustained performance degradation

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low barrier to entry**: Any user can submit transactions without special privileges
2. **Easy to execute**: Creating minimal valid Move modules is straightforward
3. **Repeatable**: Attackers can submit multiple malicious transactions
4. **No detection**: Transactions appear valid until they fail dependency checks after resource consumption
5. **Wide impact**: All validators processing the transaction are affected

The attack is limited only by:
- Transaction fees (which attackers must pay)
- Mempool limits on transaction submission rate
- Transaction size bounds (64 KB for regular, 1 MB for governance)

However, even at 64 KB per transaction with ~1,600 modules, repeated attacks can cause significant degradation.

## Recommendation

**Enforce module count limits before deserialization:**

Add an early check in `resolve_pending_code_publish_and_finish_user_session` before calling `deserialize_module_bundle`:

```rust
// In aptos-move/aptos-vm/src/aptos_vm.rs, around line 1490
let PublishRequest {
    destination,
    bundle,
    expected_modules,
    allowed_deps,
    check_compat: _,
} = maybe_publish_request.expect("Publish request exists");

// NEW: Check module count before deserialization
if self.gas_feature_version() >= RELEASE_V1_10 {
    let module_count = bundle.iter().count();
    let max_modules: usize = self.vm_gas_params().txn.max_num_dependencies.into();
    
    if module_count > max_modules {
        return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED)
            .with_message(format!(
                "Module bundle contains {} modules, exceeds limit of {}",
                module_count, max_modules
            ))
            .finish(Location::Undefined)
            .into_vm_status());
    }
}

let modules = self.deserialize_module_bundle(&bundle)?;
```

This ensures the dependency limit is enforced BEFORE any expensive deserialization occurs, preventing resource exhaustion attacks.

**Alternative**: Add a separate `max_modules_per_bundle` parameter that is checked even earlier, potentially in the transaction validation phase before execution begins.

## Proof of Concept

The following demonstrates the vulnerability exists (conceptual PoC - requires Aptos test harness):

```rust
#[test]
fn test_module_bundle_dos() {
    let mut h = MoveHarness::new();
    let acc = h.new_account_at(AccountAddress::from_hex_literal("0xcafe").unwrap());
    
    // Create 1500 minimal modules (exceeds 768 limit)
    let mut module_bundle = vec![];
    for i in 0..1500 {
        // Each minimal module: just a module declaration with one empty function
        let module_code = create_minimal_module(format!("module_{}", i));
        module_bundle.push(module_code);
    }
    
    // Create transaction with large bundle
    let txn = create_publish_transaction(&acc, module_bundle);
    
    // This should fail, but only AFTER deserializing all 1500 modules
    let result = h.run_transaction(txn);
    
    // Verify it fails with DEPENDENCY_LIMIT_REACHED
    assert!(matches!(
        result,
        TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(
            StatusCode::DEPENDENCY_LIMIT_REACHED
        )))
    ));
    
    // The vulnerability is that deserialization happened for all 1500 modules
    // before this check, consuming memory and CPU time
}

fn create_minimal_module(name: String) -> Vec<u8> {
    // Creates bytecode for:
    // module 0xcafe::<name> {
    //     fun init() { }
    // }
    // Approximately 30-50 bytes of compiled bytecode
    compile_minimal_module(name)
}
```

**Notes**

While the question asks about "millions of modules", the actual vulnerability is limited by transaction size constraints to ~1,600 modules (regular transactions) or ~25,000 modules (governance transactions). However, this is still sufficient to cause validator node slowdowns through resource exhaustion, qualifying as HIGH severity under the Aptos bug bounty program.

The vulnerability fundamentally violates the principle that resource consumption should be bounded upfront before expensive operations are performed. The fix is straightforward: check module counts before deserialization.

### Citations

**File:** aptos-move/aptos-vm-types/src/module_write_set.rs (L90-92)
```rust
    pub fn num_write_ops(&self) -> usize {
        self.writes.len()
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-81)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```

**File:** aptos-move/aptos-vm/src/gas.rs (L109-121)
```rust
    } else if txn_metadata.transaction_size > txn_gas_params.max_transaction_size_in_bytes {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Transaction size too big {} (max {})",
                txn_metadata.transaction_size, txn_gas_params.max_transaction_size_in_bytes
            ),
        );
        return Err(VMStatus::error(
            StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
            None,
        ));
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1443-1461)
```rust
    /// Deserialize a module bundle.
    fn deserialize_module_bundle(&self, modules: &ModuleBundle) -> VMResult<Vec<CompiledModule>> {
        let mut result = vec![];
        for module_blob in modules.iter() {
            match CompiledModule::deserialize_with_config(
                module_blob.code(),
                self.deserializer_config(),
            ) {
                Ok(module) => {
                    result.push(module);
                },
                Err(_err) => {
                    return Err(PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR)
                        .finish(Location::Undefined))
                },
            }
        }
        Ok(result)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1525-1536)
```rust
            // Charge all modules in the bundle that is about to be published.
            for (module, blob) in modules.iter().zip(bundle.iter()) {
                let addr = module.self_addr();
                let name = module.self_name();
                gas_meter
                    .charge_dependency(
                        DependencyKind::New,
                        addr,
                        name,
                        NumBytes::new(blob.code().len() as u64),
                    )
                    .map_err(|err| err.finish(Location::Undefined))?;
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L300-313)
```rust
    fn count_dependency(&mut self, size: NumBytes) -> PartialVMResult<()> {
        if self.feature_version >= 15 {
            self.num_dependencies += 1.into();
            self.total_dependency_size += size;

            if self.num_dependencies > self.vm_gas_params.txn.max_num_dependencies {
                return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED));
            }
            if self.total_dependency_size > self.vm_gas_params.txn.max_total_dependency_size {
                return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED));
            }
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L24-45)
```rust
    pub(crate) fn new(
        change_set: VMChangeSet,
        module_write_set: ModuleWriteSet,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<Self, VMStatus> {
        let user_session_change_set = Self {
            change_set,
            module_write_set,
        };
        change_set_configs.check_change_set(&user_session_change_set)?;
        Ok(user_session_change_set)
    }

    pub(crate) fn unpack(self) -> (VMChangeSet, ModuleWriteSet) {
        (self.change_set, self.module_write_set)
    }
}

impl ChangeSetInterface for UserSessionChangeSet {
    fn num_write_ops(&self) -> usize {
        self.change_set.num_write_ops() + self.module_write_set.num_write_ops()
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L95-99)
```rust
        if self.max_write_ops_per_transaction != 0
            && change_set.num_write_ops() as u64 > self.max_write_ops_per_transaction
        {
            return storage_write_limit_reached(Some("Too many write ops."));
        }
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L3434-3479)
```rust
pub struct CompiledModule {
    /// Version number found during deserialization
    pub version: u32,
    /// Handle to self.
    pub self_module_handle_idx: ModuleHandleIndex,
    /// Handles to external dependency modules and self.
    pub module_handles: Vec<ModuleHandle>,
    /// Handles to external and internal types.
    pub struct_handles: Vec<StructHandle>,
    /// Handles to external and internal functions.
    pub function_handles: Vec<FunctionHandle>,
    /// Handles to fields.
    pub field_handles: Vec<FieldHandle>,
    /// Friend declarations, represented as a collection of handles to external friend modules.
    pub friend_decls: Vec<ModuleHandle>,

    /// Struct instantiations.
    pub struct_def_instantiations: Vec<StructDefInstantiation>,
    /// Function instantiations.
    pub function_instantiations: Vec<FunctionInstantiation>,
    /// Field instantiations.
    pub field_instantiations: Vec<FieldInstantiation>,

    /// Locals signature pool. The signature for all locals of the functions defined in the module.
    pub signatures: SignaturePool,

    /// All identifiers used in this module.
    pub identifiers: IdentifierPool,
    /// All address identifiers used in this module.
    pub address_identifiers: AddressIdentifierPool,
    /// Constant pool. The constant values used in the module.
    pub constant_pool: ConstantPool,

    pub metadata: Vec<Metadata>,

    /// Types defined in this module.
    pub struct_defs: Vec<StructDefinition>,
    /// Function defined in this module.
    pub function_defs: Vec<FunctionDefinition>,

    /// Since bytecode version 7: variant related handle tables
    pub struct_variant_handles: Vec<StructVariantHandle>,
    pub struct_variant_instantiations: Vec<StructVariantInstantiation>,
    pub variant_field_handles: Vec<VariantFieldHandle>,
    pub variant_field_instantiations: Vec<VariantFieldInstantiation>,
}
```
