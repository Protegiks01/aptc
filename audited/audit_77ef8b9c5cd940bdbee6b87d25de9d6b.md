# Audit Report

## Title
View Function Gas Limit Bypass via Unmetered Dependency Loading

## Summary
View functions in `execute_view_function_in_vm()` bypass gas metering for module dependency loading, allowing attackers to cause resource exhaustion (CPU, I/O, memory) without consuming gas from the configured limit. This breaks the invariant that "all operations must respect gas, storage, and computational limits."

## Finding Description

The vulnerability exists in the view function execution path where dependency loading is explicitly unmetered, unlike regular transaction execution: [1](#0-0) 

The function uses `LegacyLoaderConfig::unmetered()` which bypasses gas charging for loading module dependencies: [2](#0-1) 

When loading dependencies with this configuration, the gas charging checks are skipped: [3](#0-2) 

The dependency loading function performs expensive operations (storage I/O, deserialization, traversing transitive dependencies) without charging gas: [4](#0-3) 

**Attack Flow:**
1. Attacker deploys a chain of Move modules M₁ → M₂ → M₃ → ... → Mₙ where each module depends on the next
2. M₁ contains a simple view function (minimal execution cost)
3. Attacker calls the view function repeatedly via the REST API endpoint
4. Each call loads all n modules from storage without charging gas
5. Only the minimal function execution consumes gas from the configured limit
6. The expensive loading operations bypass gas metering entirely

**Comparison with Regular Transactions:**
Regular transactions validate gas limits and charge for dependencies: [5](#0-4) 

View functions skip this validation and dependency charging: [6](#0-5) 

## Impact Explanation

This vulnerability enables a **Medium to High severity** DoS attack:

- **High Severity Criteria**: "Validator node slowdowns" and "API crashes"
  - Repeated calls with deep dependency chains cause excessive storage I/O
  - Module deserialization consumes significant CPU
  - Memory usage grows with cached modules
  - API endpoints become slow or unresponsive

- **Medium Severity Criteria**: "Limited resource exhaustion"
  - The attack requires deploying modules first (deployment itself is metered)
  - Effect is limited to view function endpoints, not consensus or state modification
  - Node operators can mitigate by setting very low `max_gas_view_function` config

The configured `max_gas_view_function` limit (default 2,000,000 gas) only applies to execution, not loading: [7](#0-6) 

## Likelihood Explanation

**High Likelihood:**
- Exploitation requires no special permissions—any user can deploy modules and call view functions
- Attack is simple: deploy modules with many dependencies, call view function repeatedly
- No rate limiting exists specifically for view function calls
- The bypass is structural: `LegacyLoaderConfig::unmetered()` is used unconditionally for all view functions
- The REST API publicly exposes view function execution: [8](#0-7) 

## Recommendation

**Fix Option 1: Charge for dependency loading**
Use metered loading configuration for view functions:

```rust
let func = loader.load_instantiated_function(
    &LegacyLoaderConfig {
        charge_for_dependencies: true,
        charge_for_ty_tag_dependencies: true,
    },
    gas_meter,
    traversal_context,
    &module_id,
    &func_name,
    &ty_args,
)?;
```

**Fix Option 2: Add max_gas_amount validation**
Validate the configured `max_gas_view_function` against system limits before use:

```rust
pub fn execute_view_function(
    state_view: &impl StateView,
    module_id: ModuleId,
    func_name: Identifier,
    type_args: Vec<TypeTag>,
    arguments: Vec<Vec<u8>>,
    max_gas_amount: u64,
) -> ViewFunctionOutput {
    let env = AptosEnvironment::new(state_view);
    let vm = AptosVM::new(&env);
    let log_context = AdapterLogSchema::new(state_view.id(), 0);
    
    // Add validation
    let vm_gas_params = match vm.gas_params(&log_context) {
        Ok(params) => params,
        Err(err) => return ViewFunctionOutput::new_error_message(/*...*/),
    };
    
    if max_gas_amount > vm_gas_params.vm.txn.maximum_number_of_gas_units.into() {
        return ViewFunctionOutput::new_error_message(
            "max_gas_amount exceeds maximum_number_of_gas_units",
            Some(StatusCode::MAX_GAS_UNITS_EXCEEDS_MAX_GAS_UNITS_BOUND),
            0,
        );
    }
    
    // ... rest of function
}
```

**Fix Option 3: Add dependency depth/count limits**
Enforce limits on module dependency chains during view function validation.

## Proof of Concept

```move
// Module A with minimal code
module 0xCAFE::a {
    public fun helper() {}
}

// Module B depends on A
module 0xCAFE::b {
    use 0xCAFE::a;
    public fun helper() { a::helper(); }
}

// Continue pattern: C depends on B, D depends on C, etc.
// ... (create 100+ modules in dependency chain)

// Final module with view function
module 0xCAFE::exploit {
    use 0xCAFE::z; // Depends on end of chain
    
    #[view]
    public fun expensive_view(): u64 {
        z::helper();
        1 // Minimal execution cost
    }
}
```

**Test Steps:**
1. Deploy all modules in dependency chain (100+ modules)
2. Call view function via API: `POST /view` with `0xCAFE::exploit::expensive_view`
3. Observe: Gas reported as ~100 units (only execution)
4. Measure: Actual CPU/IO consumed is 100x higher (loading all dependencies)
5. Repeat: Send 1000 concurrent requests
6. Result: API becomes slow/unresponsive despite low gas consumption

**Expected Behavior:** Dependency loading should consume gas from the limit, preventing this bypass.

**Notes**
- This is a structural issue in how view functions are designed to optimize for read-only operations
- The unmetered loading is intentional but creates an exploitable asymmetry between resource consumption and gas accounting
- Regular transactions correctly charge for dependency loading, establishing the precedent that this should be metered

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2628-2669)
```rust
    pub fn execute_view_function(
        state_view: &impl StateView,
        module_id: ModuleId,
        func_name: Identifier,
        type_args: Vec<TypeTag>,
        arguments: Vec<Vec<u8>>,
        max_gas_amount: u64,
    ) -> ViewFunctionOutput {
        let env = AptosEnvironment::new(state_view);
        let vm = AptosVM::new(&env);

        let log_context = AdapterLogSchema::new(state_view.id(), 0);

        let vm_gas_params = match vm.gas_params(&log_context) {
            Ok(gas_params) => gas_params.vm.clone(),
            Err(err) => {
                return ViewFunctionOutput::new_error_message(
                    format!("{}", err),
                    Some(err.status_code()),
                    0,
                )
            },
        };
        let storage_gas_params = match vm.storage_gas_params(&log_context) {
            Ok(gas_params) => gas_params.clone(),
            Err(err) => {
                return ViewFunctionOutput::new_error_message(
                    format!("{}", err),
                    Some(err.status_code()),
                    0,
                )
            },
        };

        let mut gas_meter = make_prod_gas_meter(
            vm.gas_feature_version(),
            vm_gas_params,
            storage_gas_params,
            /* is_approved_gov_script */ false,
            max_gas_amount.into(),
            &NoopBlockSynchronizationKillSwitch {},
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2751-2758)
```rust
            let func = loader.load_instantiated_function(
                &LegacyLoaderConfig::unmetered(),
                gas_meter,
                traversal_context,
                &module_id,
                &func_name,
                &ty_args,
            )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/traits.rs (L114-120)
```rust
    /// Returns config which does not charge for anything.
    pub fn unmetered() -> Self {
        Self {
            charge_for_dependencies: false,
            charge_for_ty_tag_dependencies: false,
        }
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L281-292)
```rust
        if config.charge_for_dependencies {
            // Charge gas for function code loading.
            let arena_id = traversal_context
                .referenced_module_ids
                .alloc(module_id.clone());
            check_dependencies_and_charge_gas(
                self.module_storage,
                gas_meter,
                traversal_context,
                [(arena_id.address(), arena_id.name())],
            )?;
        }
```

**File:** third_party/move/move-vm/runtime/src/storage/dependencies_gas_charging.rs (L80-89)
```rust
    while let Some((addr, name)) = stack.pop() {
        let size = module_storage.unmetered_get_existing_module_size(addr, name)?;
        gas_meter
            .charge_dependency(
                DependencyKind::Existing,
                addr,
                name,
                NumBytes::new(size as u64),
            )
            .map_err(|err| err.finish(Location::Module(ModuleId::new(*addr, name.to_owned()))))?;
```

**File:** aptos-move/aptos-vm/src/gas.rs (L126-138)
```rust
    if txn_metadata.max_gas_amount() > txn_gas_params.maximum_number_of_gas_units {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.maximum_number_of_gas_units,
                txn_metadata.max_gas_amount()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::MAX_GAS_UNITS_EXCEEDS_MAX_GAS_UNITS_BOUND,
            None,
        ));
```

**File:** config/src/config/api_config.rs (L102-102)
```rust
const DEFAULT_MAX_VIEW_GAS: u64 = 2_000_000; // We keep this value the same as the max number of gas allowed for one single transaction defined in aptos-gas.
```

**File:** api/src/view_function.rs (L154-161)
```rust
    let output = AptosVM::execute_view_function(
        &state_view,
        view_function.module.clone(),
        view_function.function.clone(),
        view_function.ty_args.clone(),
        view_function.args.clone(),
        context.node_config.api.max_gas_view_function,
    );
```
