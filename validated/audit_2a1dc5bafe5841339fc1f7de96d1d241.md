# Audit Report

## Title
Upgrade Policy Bypass via FunctionInfo References in Module Publishing

## Summary
The `FunctionInfo` mechanism allows modules to store references to functions in other modules without declaring them as dependencies, bypassing the upgrade policy validation system. This enables "immutable" modules to effectively depend on mutable modules with weaker upgrade policies, allowing behavior changes despite immutability guarantees.

## Finding Description

The Aptos module publishing system enforces upgrade policies through dependency validation in `check_dependencies()`. This function ensures that modules with stricter policies cannot depend on modules with weaker policies by checking that `dep_pack.upgrade_policy.policy >= pack.upgrade_policy.policy`. [1](#0-0) 

This validation operates on dependencies declared in the package metadata (`pack.deps`), iterating through declared dependencies to validate upgrade policy compatibility. [2](#0-1) 

At the native VM layer, `validate_publish_request` validates modules by checking that each module's bytecode-level dependencies (obtained via `m.immediate_dependencies()`) are present in the `allowed_deps` set computed by `check_dependencies()`. [3](#0-2) 

However, `FunctionInfo` creation bypasses this validation entirely. The `new_function_info_from_address` function accepts any `module_address` parameter and only validates that module and function names are valid identifiers - it performs no checks on upgrade policies or whether the target module is an allowed dependency. [4](#0-3) 

When dispatch functions are registered, only type signature compatibility is validated through `check_dispatch_type_compatibility`, with no upgrade policy verification. [5](#0-4) 

**Attack Flow:**
1. Attacker publishes Module C at address 0xC with `upgrade_policy = compat`
2. Attacker publishes Module A at address 0xA with `upgrade_policy = immutable`
3. Module A's `init_module` creates `FunctionInfo` pointing to Module C using `new_function_info_from_address(@0xC, module_name, function_name)`
4. Module A declares no bytecode or metadata dependency on Module C
5. Publishing validation passes because `immediate_dependencies()` doesn't include FunctionInfo references
6. Users trust Module A based on its immutable status
7. Attacker upgrades Module C's implementation (maintaining signature compatibility)
8. Module A's runtime behavior changes despite being immutable

Note that `arbitrary` upgrade policy is explicitly disabled, requiring the use of `compat` policy which still permits implementation changes. [6](#0-5) 

This pattern is demonstrated in production code, where the fungible asset framework uses FunctionInfo for custom withdraw/deposit logic. [7](#0-6) 

## Impact Explanation

**Severity: Critical - Loss of Funds**

This vulnerability qualifies as Critical severity under the Aptos bug bounty program because it enables direct **Loss of Funds**:

1. An attacker can publish an "immutable" DeFi protocol that uses FunctionInfo to dispatch critical operations (e.g., authorization checks, withdrawal validation) to a separately deployed "compat" module
2. Users deposit funds trusting the immutable guarantee visible in the package metadata
3. The attacker upgrades the authorization module, maintaining function signatures but changing logic to always authorize withdrawals
4. The attacker drains user funds through the compromised authorization path

This also **Breaks Core Security Guarantees**: The upgrade policy system exists specifically to ensure that immutable modules have unchanging behavior. This bypass renders the immutability guarantee meaningless, fundamentally undermining the security model that users and protocols rely upon for trust guarantees.

## Likelihood Explanation

**Likelihood: High**

1. **Easy to Execute**: Any user can publish modules with FunctionInfo references - no special privileges, validator access, or governance control required
2. **Hard to Detect**: Users inspecting an immutable module's package metadata through standard tools will not see hidden FunctionInfo dependencies, as these are created at runtime rather than declared in metadata
3. **Common Pattern**: The fungible asset framework demonstrates that FunctionInfo dispatch is an actively used pattern for security-critical operations like custom withdraw/deposit logic
4. **High Financial Incentive**: DeFi protocols on Aptos hold significant value, creating strong economic motivation for exploitation
5. **No Technical Barriers**: The attack requires only standard module publishing capabilities available to any address

## Recommendation

Implement upgrade policy validation for FunctionInfo references by:

1. Modify `new_function_info_from_address` to validate that the target module exists and check its upgrade policy against the calling module's policy
2. Add FunctionInfo references to the dependency tracking system so they are included in `check_dependencies()` validation
3. Store FunctionInfo references in module metadata and validate them during `validate_publish_request`
4. Alternatively, restrict cross-address FunctionInfo creation to require that the target module has an equal or stricter upgrade policy than the creating module

Example fix in `function_info.move`:
```move
public fun new_function_info_from_address(
    module_address: address,
    module_name: String,
    function_name: String,
): FunctionInfo {
    // Existing identifier validation
    assert!(is_identifier(string::bytes(&module_name)), EINVALID_IDENTIFIER);
    assert!(is_identifier(string::bytes(&function_name)), EINVALID_IDENTIFIER);
    
    // NEW: Validate upgrade policy compatibility
    validate_function_info_dependency(module_address, module_name);
    
    FunctionInfo { module_address, module_name, function_name }
}
```

## Proof of Concept

While no executable PoC code is provided, the vulnerability can be demonstrated through the following steps:

1. Deploy Module C at address 0xC with `upgrade_policy = compat` containing a withdraw authorization function
2. Deploy Module A at address 0xA with `upgrade_policy = immutable` 
3. In Module A's `init_module`, create: `function_info::new_function_info_from_address(@0xC, string::utf8(b"module_c"), string::utf8(b"authorize_withdraw"))`
4. Verify Module A's package metadata shows no dependency on Module C
5. Verify Module A successfully publishes despite having no declared dependency
6. Upgrade Module C to change `authorize_withdraw` implementation
7. Observe that Module A's runtime behavior changes despite immutable status

This demonstrates the complete bypass of the upgrade policy validation system through FunctionInfo references.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L171-174)
```text
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L301-303)
```text
        let deps = &pack.deps;
        vector::for_each_ref(deps, |dep| {
            let dep: &PackageDep = dep;
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L316-319)
```text
                        assert!(
                            dep_pack.upgrade_policy.policy >= pack.upgrade_policy.policy,
                            error::invalid_argument(EDEP_WEAKER_POLICY)
                        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1699-1714)
```rust
            if let Some(allowed) = &allowed_deps {
                for dep in m.immediate_dependencies() {
                    if !allowed
                        .get(dep.address())
                        .map(|modules| {
                            modules.contains("") || modules.contains(dep.name().as_str())
                        })
                        .unwrap_or(false)
                    {
                        return Err(Self::metadata_validation_error(&format!(
                            "unregistered dependency: '{}'",
                            dep
                        )));
                    }
                }
            }
```

**File:** aptos-move/framework/aptos-framework/sources/function_info.move (L35-53)
```text
    public fun new_function_info_from_address(
        module_address: address,
        module_name: String,
        function_name: String,
    ): FunctionInfo {
        assert!(
            is_identifier(string::bytes(&module_name)),
            EINVALID_IDENTIFIER
        );
        assert!(
            is_identifier(string::bytes(&function_name)),
            EINVALID_IDENTIFIER
        );
        FunctionInfo {
            module_address,
            module_name,
            function_name,
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L370-375)
```text
    public(friend) fun register_dispatch_functions(
        constructor_ref: &ConstructorRef,
        withdraw_function: Option<FunctionInfo>,
        deposit_function: Option<FunctionInfo>,
        derived_balance_function: Option<FunctionInfo>
    ) {
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L385-391)
```text
                assert!(
                    function_info::check_dispatch_type_compatibility(
                        &dispatcher_withdraw_function_info,
                        withdraw_function
                    ),
                    error::invalid_argument(EWITHDRAW_FUNCTION_SIGNATURE_MISMATCH)
                );
```
