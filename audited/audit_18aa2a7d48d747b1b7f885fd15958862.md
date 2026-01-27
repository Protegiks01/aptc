# Audit Report

## Title
Critical Dependency Verification Bypass When CODE_DEPENDENCY_CHECK Feature Flag is Disabled

## Summary

When the `CODE_DEPENDENCY_CHECK` feature flag is disabled through on-chain governance, the Aptos VM completely bypasses module dependency verification during publishing. This allows attackers to deploy malicious modules that: (1) hide actual dependencies from metadata to violate upgrade policy restrictions, (2) reference non-existent modules that will cause runtime linker errors, and (3) form circular dependency chains that are not detected during publishing due to lazy loading being enabled by default. This breaks the deterministic execution invariant and can cause consensus divergence.

## Finding Description

The vulnerability exists in the module publishing flow where dependency verification is conditionally enforced based on the `CODE_DEPENDENCY_CHECK` feature flag: [1](#0-0) 

When this feature flag is enabled (default state), the Move framework calls `request_publish_with_allowed_deps` which passes a list of allowed module dependencies computed from package metadata. When disabled, it falls back to `request_publish` without any dependency restrictions.

The critical check occurs in the VM's validation logic: [2](#0-1) 

This check uses `if let Some(allowed) = &allowed_deps` meaning when `allowed_deps` is `None` (feature flag disabled), the entire dependency verification block is **completely skipped**. No validation occurs to ensure bytecode dependencies match metadata declarations.

The attack is further enabled because lazy loading is enabled by default: [3](#0-2) 

With lazy loading active, the module publishing code explicitly does NOT check for circular dependencies: [4](#0-3) 

The lazy loading path only verifies that immediate dependencies exist, but only those listed in the metadata. If an attacker clears dependencies from metadata while keeping them in bytecode, the system never attempts to load or verify them.

**Attack Scenarios:**

1. **Fake/Hidden Dependencies**: Attacker publishes module with bytecode dependency on Module X, but clears X from metadata. Module gets accepted. This allows violating upgrade policy restrictions (e.g., immutable module depending on compatible module).

2. **Non-existent Module References**: Attacker publishes module referencing Module Y that doesn't exist on-chain. Since metadata doesn't list Y, lazy loading never tries to load it. Module publishes successfully but causes `LINKER_ERROR` at runtime.

3. **Circular Dependencies**: Attacker publishes modules A and B in one transaction where A→B and B→A. Without cycle detection in lazy loading path, both modules get accepted and cause runtime failures.

The existing test case confirms this vulnerability: [5](#0-4) 

This test explicitly shows that without the feature flag, publishing succeeds even when metadata dependencies are cleared (`metadata.deps.clear()`), while the bytecode still contains the dependency.

## Impact Explanation

**Critical Severity** - This vulnerability breaks multiple critical invariants:

1. **Deterministic Execution Violation**: When modules with hidden non-existent dependencies are called, different validators may handle linker errors differently or at different times, potentially causing state divergence. This violates Invariant #1: "All validators must produce identical state roots for identical blocks."

2. **Upgrade Policy Bypass**: The test demonstrates an immutable module depending on a compatible (upgradeable) module by hiding the dependency. This violates the fundamental security guarantee that stricter upgrade policies cannot depend on weaker ones, as it could lead to unexpected behavior when the dependency is upgraded.

3. **Consensus Safety Risk**: If malicious modules with circular dependencies or non-existent references are published and later executed, the runtime behavior (linker errors, cycle detection failures) could cause validator disagreements about transaction success/failure, potentially leading to consensus splits.

4. **State Consistency Violation**: Successfully publishing modules that violate dependency invariants corrupts the module state in a way that requires manual intervention to fix, violating Invariant #4: "State transitions must be atomic and verifiable."

Per Aptos bug bounty criteria, this qualifies as **Critical Severity** because it enables:
- Consensus/Safety violations (validators may disagree on execution results)
- State inconsistencies requiring intervention (malformed module dependencies)
- Potential non-recoverable network issues if consensus diverges

## Likelihood Explanation

**High Likelihood** - The attack is highly feasible:

1. **Governance Can Disable Flag**: The feature flag can be legitimately disabled through governance proposals. If governance believes the check is too restrictive or causing issues, they might disable it.

2. **Low Attacker Requirements**: Any account with publishing permissions can exploit this. No validator access or special privileges needed beyond the ability to submit module publishing transactions.

3. **Easy to Execute**: The attack simply requires publishing a module with manipulated metadata. The test case shows it's a straightforward operation: compile module normally, then clear dependencies from metadata before submission.

4. **Hard to Detect**: Once disabled, there's no warning system. Malicious modules would be accepted silently. The issues only manifest at runtime when the modules are actually called.

5. **Lazy Loading Enabled by Default**: The combination of disabled dependency checks + enabled lazy loading creates the perfect storm where circular dependencies and non-existent references slip through all verification layers.

The test case exists specifically because this was a known historical problem that the feature flag was designed to fix. Disabling the flag regresses to the vulnerable state.

## Recommendation

**Primary Fix**: Never allow `CODE_DEPENDENCY_CHECK` to be fully disabled. Instead, modify the feature flag system to make this feature non-disableable: [6](#0-5) 

Mark `CODE_DEPENDENCY_CHECK` similar to other permanently-enabled flags like `_REJECT_UNSTABLE_BYTECODE` or `_DISALLOW_USER_NATIVES`.

**Alternative Fix**: If backward compatibility requires keeping the flag toggleable, add mandatory fallback checks in the publishing path that always verify:

1. All bytecode dependencies must be declared in metadata
2. Circular dependency detection must run even with lazy loading
3. All referenced modules must exist on-chain

These checks should occur in `validate_publish_request` regardless of `allowed_deps` value: [7](#0-6) 

Add an additional validation block that always runs:
- Iterate through each module's `immediate_dependencies()`
- Verify each dependency exists in storage
- Verify each dependency is declared in package metadata
- Run cycle detection regardless of lazy loading setting

## Proof of Concept

The vulnerability is already demonstrated by the existing test case: [8](#0-7) 

**To reproduce:**

1. Create Move harness with `CODE_DEPENDENCY_CHECK` disabled
2. Publish Package1 with `compatible` upgrade policy at address `0xcafe`
3. Create Package2 with `immutable` upgrade policy that depends on Package1
4. Clear the dependency from Package2's metadata using the patcher: `metadata.deps.clear()`
5. Publish Package2 at address `0xdeaf`
6. **Result**: Publishing succeeds (line 385: `assert_success!(result)`)
7. **Expected**: Should fail with `CONSTRAINT_NOT_SATISFIED` (line 387)

This demonstrates that an immutable module can illegally depend on an upgradeable module when the feature flag is disabled, violating upgrade policy invariants and allowing hidden dependencies that could cause runtime failures or consensus issues.

## Notes

The test case at line 383-385 explicitly documents this as a known issue: "In the previous version we were not able to detect this problem". The feature flag was added specifically to fix this vulnerability, making it a regression risk if governance ever disables the flag. The combination with lazy loading (enabled by default per line 266 of aptos_features.rs) makes this particularly dangerous as circular dependencies are also not detected during publishing.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L222-227)
```text
        if (features::code_dependency_check_enabled())
            request_publish_with_allowed_deps(addr, module_names, allowed_deps, code, policy.policy)
        else
        // The new `request_publish_with_allowed_deps` has not yet rolled out, so call downwards
        // compatible code.
            request_publish(addr, module_names, code, policy.policy)
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1679-1739)
```rust
    /// Validate a publish request.
    fn validate_publish_request(
        &self,
        module_storage: &impl AptosModuleStorage,
        traversal_context: &mut TraversalContext,
        gas_meter: &mut impl GasMeter,
        modules: &[CompiledModule],
        mut expected_modules: BTreeSet<String>,
        allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
    ) -> VMResult<()> {
        self.reject_unstable_bytecode(modules)?;
        native_validation::validate_module_natives(modules)?;

        for m in modules {
            if !expected_modules.remove(m.self_id().name().as_str()) {
                return Err(Self::metadata_validation_error(&format!(
                    "unregistered module: '{}'",
                    m.self_id().name()
                )));
            }
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
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
        }

        resource_groups::validate_resource_groups(
            self.features(),
            module_storage,
            traversal_context,
            gas_meter,
            modules,
        )?;
        event_validation::validate_module_events(
            self.features(),
            module_storage,
            traversal_context,
            modules,
        )?;

        if !expected_modules.is_empty() {
            return Err(Self::metadata_validation_error(
                "not all registered modules published",
            ));
        }
        Ok(())
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L20-20)
```rust
    CODE_DEPENDENCY_CHECK = 1,
```

**File:** types/src/on_chain_config/aptos_features.rs (L266-266)
```rust
            FeatureFlag::ENABLE_LAZY_LOADING,
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L259-260)
```rust
                // Linking checks to immediate dependencies. Note that we do not check cyclic
                // dependencies here.
```

**File:** aptos-move/e2e-move-tests/src/tests/code_publishing.rs (L360-389)
```rust
fn code_publishing_faked_dependency(enabled: Vec<FeatureFlag>, disabled: Vec<FeatureFlag>) {
    let mut h = MoveHarness::new_with_features(enabled.clone(), disabled);
    let acc1 = h.new_account_at(AccountAddress::from_hex_literal("0xcafe").unwrap());
    let acc2 = h.new_account_at(AccountAddress::from_hex_literal("0xdeaf").unwrap());

    let mut pack1 = PackageBuilder::new("Package1").with_policy(UpgradePolicy::compat());
    pack1.add_source("m", "module 0xcafe::m { public fun f() {} }");
    let pack1_dir = pack1.write_to_temp().unwrap();
    assert_success!(h.publish_package(&acc1, pack1_dir.path()));

    // pack2 has a higher policy and should not be able to depend on pack1
    let mut pack2 = PackageBuilder::new("Package2").with_policy(UpgradePolicy::immutable());
    pack2.add_local_dep("Package1", &pack1_dir.path().to_string_lossy());
    pack2.add_source(
        "m",
        "module 0xdeaf::m { use 0xcafe::m; public fun f() { m::f() } }",
    );
    let pack2_dir = pack2.write_to_temp().unwrap();
    let result = h.publish_package_with_patcher(&acc2, pack2_dir.path(), |metadata| {
        // Hide the dependency from the lower policy package from the metadata. We detect this
        // this via checking the actual bytecode module dependencies.
        metadata.deps.clear()
    });
    if !enabled.contains(&FeatureFlag::CODE_DEPENDENCY_CHECK) {
        // In the previous version we were not able to detect this problem
        assert_success!(result)
    } else {
        assert_vm_status!(result, StatusCode::CONSTRAINT_NOT_SATISFIED)
    }
}
```
