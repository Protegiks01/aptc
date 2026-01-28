# Audit Report

## Title
Unmetered CPU Exhaustion via Excessive Function Handles in Dependency Verification

## Summary
The Move bytecode verifier enforces limits on `function_defs` count but not on `function_handles` count. During dependency verification, all function handles undergo expensive validation in an unmetered O(N) loop. An attacker can create modules with thousands of function handles, forcing validators to perform excessive CPU work while paying only for module size in gas, enabling validator slowdown attacks.

## Finding Description

The vulnerability stems from an asymmetry in the bytecode verifier's limit enforcement and gas charging mechanism.

**Missing Limit Check**: The `verify_definitions` function checks `function_defs` count against `max_function_definitions` [1](#0-0)  but there is no corresponding check for the total count of `function_handles`. The `verify_function_handles` function only validates properties like type parameters and parameters for each handle [2](#0-1)  but never checks the total count of function handles.

**Large Attack Surface**: The binary format permits up to 65,535 function handles as defined by TABLE_INDEX_MAX [3](#0-2) .

**Expensive Unmetered Validation**: During dependency verification, the `verify_imported_functions` function iterates through every function handle [4](#0-3)  and performs expensive operations including module lookups, function signature comparisons via `compare_cross_module_signatures`, type parameter validation, and attribute compatibility checks.

**No Gas Metering**: The `build_verified_module_with_linking_checks` function calls `dependencies::verify_module` without any gas metering [5](#0-4) . This verification happens synchronously during module publishing even with lazy loading enabled [6](#0-5) .

**Production Configuration**: In production, there is no limit on function definitions [7](#0-6) , allowing attackers to deploy dependency modules with thousands of functions.

**Gas Asymmetry**: Gas charging is based solely on module size using the formula `DEPENDENCY_PER_MODULE + DEPENDENCY_PER_BYTE * size` [8](#0-7)  and [9](#0-8) , not on verification complexity. This creates a severe asymmetry where attackers pay based on module size but validators consume CPU based on handle count.

**Attack Vector**:
1. Attacker deploys dependency modules with thousands of function definitions (no limit in production)
2. Attacker creates a module with thousands of function_handles referencing those functions
3. During publishing, all validators must iterate through all handles performing expensive validation
4. Gas cost is O(module_bytes) but CPU cost is O(N * signature_complexity) where N is function handle count

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria for "Validator node slowdowns: Significant performance degradation affecting consensus, DoS through resource exhaustion."

**Network-Wide Impact**: All validator nodes must verify published modules during block execution. An attacker can publish modules that force validators to perform excessive unmetered CPU work during dependency verification.

**Liveness Threat**: Multiple such modules published in succession could cause validators to experience significant slowdowns in block production and consensus participation, degrading network liveness.

**Resource Exhaustion**: The verification creates a gas-computation asymmetry where the cost to the attacker is O(module_size_in_bytes) but the cost to validators is O(number_of_function_handles * signature_complexity), enabling disproportionate resource exhaustion.

**Deterministic Impact**: All validators execute the same verification logic synchronously during block production, making the attack reliable and affecting the entire network simultaneously.

## Likelihood Explanation

**Likelihood: High**

**Ease of Exploitation**: Any user can publish Move modules through the standard `0x1::code::publish_package_txn` entry function. Creating the attack requires deploying dependency modules with multiple functions, then creating a module that references them - all achievable through normal transactions.

**No Special Privileges**: This is exploitable by any unprivileged transaction sender through normal module publishing APIs.

**Economic Feasibility**: While deploying dependency modules has a cost, the asymmetry makes the attack economically viable. An attacker can cause significantly more CPU work on validators than they pay in gas.

**Deterministic Impact**: All validators experience the same CPU exhaustion when processing the block containing the malicious module, making the attack reliable and repeatable.

## Recommendation

1. **Add Function Handle Count Limit**: Implement a `max_function_handles` check in the `LimitsVerifier::verify_function_handles` function, similar to the existing `max_function_definitions` check.

2. **Meter Dependency Verification**: Add gas metering to the `verify_imported_functions` loop based on the number of function handles being verified and the complexity of signature comparisons.

3. **Set Production Limits**: Configure non-None values for `max_function_definitions` and the new `max_function_handles` in production verifier config to bound the attack surface.

4. **Gas Formula Adjustment**: Consider including verification complexity factors in the dependency gas charging formula, not just module size.

## Proof of Concept

A complete PoC would involve:
1. Deploying multiple dependency modules each with 1,000+ function definitions
2. Creating a module with 10,000+ function_handles referencing those functions
3. Publishing the module and measuring validator CPU time during verification
4. Demonstrating that gas charged is disproportionately low compared to CPU work performed

The vulnerability is demonstrable through code analysis showing the unmetered iteration through all function handles in `verify_imported_functions` with no corresponding gas charges for verification complexity.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L65-94)
```rust
    fn verify_function_handles(&self, config: &VerifierConfig) -> PartialVMResult<()> {
        for (idx, function_handle) in self.resolver.function_handles().iter().enumerate() {
            if let Some(limit) = config.max_generic_instantiation_length {
                if function_handle.type_parameters.len() > limit {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_PARAMETERS)
                        .at_index(IndexKind::FunctionHandle, idx as u16));
                }
            };
            if let Some(limit) = config.max_function_parameters {
                if self
                    .resolver
                    .signature_at(function_handle.parameters)
                    .0
                    .len()
                    > limit
                {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_PARAMETERS)
                        .at_index(IndexKind::FunctionHandle, idx as u16));
                }
            }
            if let Some(limit) = config.max_function_return_values {
                if self.resolver.signature_at(function_handle.return_).0.len() > limit {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_PARAMETERS)
                        .at_index(IndexKind::FunctionHandle, idx as u16));
                }
            };
            // Note: the size of `attributes` is limited by the deserializer.
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L197-205)
```rust
    fn verify_definitions(&self, config: &VerifierConfig) -> PartialVMResult<()> {
        if let Some(defs) = self.resolver.function_defs() {
            if let Some(max_function_definitions) = config.max_function_definitions {
                if defs.len() > max_function_definitions {
                    return Err(PartialVMError::new(
                        StatusCode::MAX_FUNCTION_DEFINITIONS_REACHED,
                    ));
                }
            }
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L43-50)
```rust
pub const TABLE_INDEX_MAX: u64 = 65535;
pub const SIGNATURE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const ADDRESS_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const IDENTIFIER_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const MODULE_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const STRUCT_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const STRUCT_DEF_INDEX_MAX: u64 = TABLE_INDEX_MAX;
pub const FUNCTION_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
```

**File:** third_party/move/move-bytecode-verifier/src/dependencies.rs (L281-388)
```rust
fn verify_imported_functions(context: &Context) -> PartialVMResult<()> {
    let self_module = context.resolver.self_handle_idx();
    for (idx, function_handle) in context.resolver.function_handles().iter().enumerate() {
        if Some(function_handle.module) == self_module {
            continue;
        }
        let owner_module_id = context
            .resolver
            .module_id_for_handle(context.resolver.module_handle_at(function_handle.module));
        let function_name = context.resolver.identifier_at(function_handle.name);
        let owner_module = safe_unwrap!(context.dependency_map.get(&owner_module_id));
        match context
            .func_id_to_index_map
            .get(&(owner_module_id.clone(), function_name.to_owned()))
        {
            Some((owner_handle_idx, owner_def_idx)) => {
                let def_handle = owner_module.function_handle_at(*owner_handle_idx);
                // compatible type parameter constraints
                if !compatible_fun_type_parameters(
                    &function_handle.type_parameters,
                    &def_handle.type_parameters,
                ) {
                    return Err(verification_error(
                        StatusCode::TYPE_MISMATCH,
                        IndexKind::FunctionHandle,
                        idx as TableIndex,
                    )
                    .with_message("imported function mismatches expectation"));
                }
                // same parameters
                let handle_params = context.resolver.signature_at(function_handle.parameters);
                let def_params = match context.dependency_map.get(&owner_module_id) {
                    Some(module) => module.signature_at(def_handle.parameters),
                    None => {
                        return Err(verification_error(
                            StatusCode::LOOKUP_FAILED,
                            IndexKind::FunctionHandle,
                            idx as TableIndex,
                        ))
                    },
                };

                compare_cross_module_signatures(
                    context,
                    &handle_params.0,
                    &def_params.0,
                    owner_module,
                )
                .map_err(|e| e.at_index(IndexKind::FunctionHandle, idx as TableIndex))?;

                // same return_
                let handle_return = context.resolver.signature_at(function_handle.return_);
                let def_return = match context.dependency_map.get(&owner_module_id) {
                    Some(module) => module.signature_at(def_handle.return_),
                    None => {
                        return Err(verification_error(
                            StatusCode::LOOKUP_FAILED,
                            IndexKind::FunctionHandle,
                            idx as TableIndex,
                        ))
                    },
                };

                compare_cross_module_signatures(
                    context,
                    &handle_return.0,
                    &def_return.0,
                    owner_module,
                )
                .map_err(|e| e.at_index(IndexKind::FunctionHandle, idx as TableIndex))?;

                // Compatible attributes.
                let mut def_attrs = def_handle.attributes.as_slice();
                let handle_attrs = function_handle.attributes.as_slice();
                if !handle_attrs.is_empty() && def_attrs.is_empty() {
                    // This is a function with no attributes, which can come from that
                    // it's compiled for < Move 2.2. Synthesize the
                    // `persistent` attribute from Public visibility, which we find
                    // in the definition.
                    if owner_module.function_def_at(*owner_def_idx).visibility == Visibility::Public
                    {
                        def_attrs = &[FunctionAttribute::Persistent]
                    }
                }
                if !FunctionAttribute::is_compatible_with(handle_attrs, def_attrs) {
                    let def_view = FunctionHandleView::new(*owner_module, def_handle);
                    return Err(verification_error(
                        StatusCode::LINKER_ERROR,
                        IndexKind::FunctionHandle,
                        idx as TableIndex,
                    )
                    .with_message(format!(
                        "imported function `{}` missing expected attributes",
                        def_view.name()
                    )));
                }
            },
            None => {
                return Err(verification_error(
                    StatusCode::LOOKUP_FAILED,
                    IndexKind::FunctionHandle,
                    idx as TableIndex,
                ));
            },
        }
    }
    Ok(())
}
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L205-216)
```rust
    pub(crate) fn build_verified_module_with_linking_checks(
        &self,
        locally_verified_module: LocallyVerifiedModule,
        immediate_dependencies: &[Arc<Module>],
    ) -> VMResult<Module> {
        dependencies::verify_module(
            &self.vm_config.verifier_config,
            locally_verified_module.0.as_ref(),
            immediate_dependencies
                .iter()
                .map(|module| module.as_ref().as_ref()),
        )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L272-275)
```rust
                staged_runtime_environment.build_verified_module_with_linking_checks(
                    locally_verified_code,
                    &verified_dependencies,
                )?;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L171-171)
```rust
        max_function_definitions: None,
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L57-76)
```rust
    fn charge_dependency(
        &mut self,
        _kind: DependencyKind,
        addr: &AccountAddress,
        _name: &IdentStr,
        size: NumBytes,
    ) -> PartialVMResult<()> {
        // Modules under special addresses are considered system modules that should always
        // be loaded, and are therefore excluded from gas charging.
        //
        // TODO: 0xA550C18 is a legacy system address we used, but it is currently not covered by
        //       `.is_special()`. We should double check if this address still needs special
        //       treatment.
        if self.feature_version() >= 15 && !addr.is_special() {
            self.algebra
                .charge_execution(DEPENDENCY_PER_MODULE + DEPENDENCY_PER_BYTE * size)?;
            self.algebra.count_dependency(size)?;
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L241-248)
```rust
            dependency_per_module: InternalGas,
            { RELEASE_V1_10.. => "dependency_per_module" },
            74460,
        ],
        [
            dependency_per_byte: InternalGasPerByte,
            { RELEASE_V1_10.. => "dependency_per_byte" },
            42,
```
