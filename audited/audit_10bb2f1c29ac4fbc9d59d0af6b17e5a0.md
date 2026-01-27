# Audit Report

## Title
Feature Flag Bypass in Object Code Deployment: ManagingRefs Allow Continued Code Deployment After Feature Disablement

## Summary
The `upgrade()` and `freeze_code_object()` functions in the object code deployment module do not verify whether the `OBJECT_CODE_DEPLOYMENT` feature flag is enabled. This allows users who created `ManagingRefs` before the feature was disabled to continue deploying and managing code after governance has disabled the feature, bypassing governance decisions.

## Finding Description

The object code deployment system implements a feature-gated mechanism for deploying Move modules to objects. The feature is controlled by the `OBJECT_CODE_DEPLOYMENT` feature flag (value 52). [1](#0-0) 

The `publish()` function correctly checks this feature flag before allowing code deployment: [2](#0-1) 

When `publish()` succeeds, it creates a `ManagingRefs` resource containing an `ExtendRef` that can be used later for upgrades.

However, the `upgrade()` function does not check the feature flag: [3](#0-2) 

Similarly, `freeze_code_object()` also lacks the feature flag check: [4](#0-3) 

**Attack Scenario:**

1. When `OBJECT_CODE_DEPLOYMENT` is enabled, a user publishes code via `publish()`, creating a `ManagingRefs` resource at the code object address
2. Governance detects issues with the feature and disables `OBJECT_CODE_DEPLOYMENT` via a governance proposal
3. The user continues to call `upgrade()` to deploy new versions of their code, bypassing the feature disable
4. The user can also call `freeze_code_object()` to freeze their code objects despite the feature being disabled
5. Meanwhile, new users cannot call `publish()` (correctly blocked by the feature flag check)

This creates an inconsistent state where existing users retain full functionality while new users are blocked, violating the governance decision's intent to fully disable the feature.

## Impact Explanation

**Severity: High** - This qualifies as a "Significant protocol violation" under the Aptos Bug Bounty program.

**Governance Integrity Violation:** Feature flags are a core governance mechanism in Aptos. When governance disables a feature, all functionality related to that feature should be disabled. This vulnerability allows partial feature operation, undermining:

1. **Governance Authority:** The governance decision to disable the feature is only partially enforced
2. **Security Response:** If the feature is disabled due to a security issue, existing deployments can continue exploiting it
3. **Protocol Consistency:** Different users have different capabilities based on whether they created objects before or after the disable
4. **Trust in Governance:** Users cannot trust that governance decisions will be fully effective

The existing test suite confirms that `publish()` is properly blocked when the feature is disabled, but no tests verify that `upgrade()` and `freeze_code_object()` are also blocked: [5](#0-4) 

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability will occur whenever:
1. Users have published code objects while the feature was enabled (highly likely in production)
2. Governance decides to disable `OBJECT_CODE_DEPLOYMENT` (possible during incident response or feature deprecation)

The likelihood increases because:
- The feature is enabled by default in the current codebase
- Many users may have already deployed code objects in production
- Governance may need to disable the feature for security or stability reasons
- The attack requires no special privileges beyond having previously published code

The complexity is **low** - it simply requires calling existing public entry functions.

## Recommendation

Add feature flag checks to both `upgrade()` and `freeze_code_object()` functions to ensure consistency with the `publish()` function's behavior.

**For the `upgrade()` function:**

Add the following check after line 126 in `object_code_deployment.move`:

```move
assert!(
    features::is_object_code_deployment_enabled(),
    error::unavailable(EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED),
);
```

**For the `freeze_code_object()` function:**

Add the same check after line 146:

```move
assert!(
    features::is_object_code_deployment_enabled(),
    error::unavailable(EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED),
);
```

This ensures that when governance disables `OBJECT_CODE_DEPLOYMENT`, all three operations (`publish`, `upgrade`, and `freeze_code_object`) are consistently disabled, fully enforcing the governance decision.

## Proof of Concept

```rust
#[test]
fn object_code_deployment_upgrade_blocked_after_feature_disabled() {
    // Initialize with feature enabled
    let mut context = TestContext::new(
        Some(vec![FeatureFlag::OBJECT_CODE_DEPLOYMENT]), 
        Some(vec![])
    );
    let acc = context.account.clone();

    // Successfully publish code while feature is enabled
    let status = context.execute_object_code_action(
        &acc,
        "object_code_deployment.data/pack_initial",
        ObjectCodeAction::Deploy,
    );
    assert_success!(status);

    // Verify ManagingRefs was created
    let code_object: ManagingRefs = context
        .harness
        .read_resource_from_resource_group(
            &context.object_address,
            parse_struct_tag("0x1::object::ObjectGroup").unwrap(),
            parse_struct_tag("0x1::object_code_deployment::ManagingRefs").unwrap(),
        )
        .unwrap();
    assert_eq!(code_object, ManagingRefs::new(context.object_address));

    // Governance disables the feature
    context.harness.disable_feature(FeatureFlag::OBJECT_CODE_DEPLOYMENT);
    
    // Verify feature is disabled
    assert!(!context.harness.is_feature_enabled(FeatureFlag::OBJECT_CODE_DEPLOYMENT));

    // Attempt to upgrade - this SHOULD fail but currently succeeds (vulnerability)
    let status = context.execute_object_code_action(
        &acc,
        "object_code_deployment.data/pack_upgrade_compat",
        ObjectCodeAction::Upgrade,
    );
    
    // EXPECTED: Feature flag error
    // ACTUAL: Success (vulnerability)
    context.assert_feature_flag_error(status, EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED);
    
    // Similarly, freeze should also be blocked
    let freeze_status = context.execute_object_code_action(
        &acc, 
        "", 
        ObjectCodeAction::Freeze
    );
    context.assert_feature_flag_error(freeze_status, EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED);
}
```

This test demonstrates that after disabling the `OBJECT_CODE_DEPLOYMENT` feature flag, both `upgrade()` and `freeze_code_object()` operations should fail with `EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED` error, but currently they succeed, confirming the governance bypass vulnerability.

## Notes

This vulnerability represents a critical gap between intended governance control and actual implementation. While the feature flag mechanism is designed to allow governance to enable/disable functionality dynamically, the incomplete implementation in the object code deployment module allows partial feature operation after disablement.

The fix is straightforward and follows the existing pattern established by the `publish()` function. All three entry points (`publish`, `upgrade`, `freeze_code_object`) should consistently check the feature flag to ensure governance decisions are fully enforced across the entire feature surface.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L417-422)
```text
    /// Whether deploying to objects is enabled.
    const OBJECT_CODE_DEPLOYMENT: u64 = 52;

    public fun is_object_code_deployment_enabled(): bool acquires Features {
        is_enabled(OBJECT_CODE_DEPLOYMENT)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L84-106)
```text
    public entry fun publish(
        publisher: &signer,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>,
    ) {
        code::check_code_publishing_permission(publisher);
        assert!(
            features::is_object_code_deployment_enabled(),
            error::unavailable(EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED),
        );

        let publisher_address = signer::address_of(publisher);
        let object_seed = object_seed(publisher_address);
        let constructor_ref = &object::create_named_object(publisher, object_seed);
        let code_signer = &object::generate_signer(constructor_ref);
        code::publish_package_txn(code_signer, metadata_serialized, code);

        event::emit(Publish { object_address: signer::address_of(code_signer), });

        move_to(code_signer, ManagingRefs {
            extend_ref: object::generate_extend_ref(constructor_ref),
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L120-141)
```text
    public entry fun upgrade(
        publisher: &signer,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>,
        code_object: Object<PackageRegistry>,
    ) acquires ManagingRefs {
        code::check_code_publishing_permission(publisher);
        let publisher_address = signer::address_of(publisher);
        assert!(
            object::is_owner(code_object, publisher_address),
            error::permission_denied(ENOT_CODE_OBJECT_OWNER),
        );

        let code_object_address = object::object_address(&code_object);
        assert!(exists<ManagingRefs>(code_object_address), error::not_found(ECODE_OBJECT_DOES_NOT_EXIST));

        let extend_ref = &borrow_global<ManagingRefs>(code_object_address).extend_ref;
        let code_signer = &object::generate_signer_for_extending(extend_ref);
        code::publish_package_txn(code_signer, metadata_serialized, code);

        event::emit(Upgrade { object_address: signer::address_of(code_signer), });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L146-150)
```text
    public entry fun freeze_code_object(publisher: &signer, code_object: Object<PackageRegistry>) {
        code::freeze_code_object(publisher, code_object);

        event::emit(Freeze { object_address: object::object_address(&code_object), });
    }
```

**File:** aptos-move/e2e-move-tests/src/tests/object_code_deployment.rs (L138-194)
```rust
/// Tests the `publish` object code deployment function with feature flags enabled/disabled.
/// Deployment should only happen when feature is enabled.
#[rstest(enabled, disabled,
    case(vec![], vec![FeatureFlag::OBJECT_CODE_DEPLOYMENT]),
    case(vec![FeatureFlag::OBJECT_CODE_DEPLOYMENT], vec![]),
)]
fn object_code_deployment_publish_package(enabled: Vec<FeatureFlag>, disabled: Vec<FeatureFlag>) {
    let mut context = TestContext::new(Some(enabled.clone()), Some(disabled));
    let acc = context.account.clone();

    let status = context.execute_object_code_action(
        &acc,
        "object_code_deployment.data/pack_initial",
        ObjectCodeAction::Deploy,
    );

    if enabled.contains(&FeatureFlag::OBJECT_CODE_DEPLOYMENT) {
        assert_success!(status);

        let registry = context
            .read_resource::<PackageRegistry>(&context.object_address, PACKAGE_REGISTRY_ACCESS_PATH)
            .unwrap();
        assert_eq!(registry.packages.len(), 1);
        assert_eq!(registry.packages[0].name, "test_package");
        assert_eq!(registry.packages[0].modules.len(), 1);
        assert_eq!(registry.packages[0].modules[0].name, "test");

        let code_object: ManagingRefs = context
            .harness
            .read_resource_from_resource_group(
                &context.object_address,
                parse_struct_tag("0x1::object::ObjectGroup").unwrap(),
                parse_struct_tag("0x1::object_code_deployment::ManagingRefs").unwrap(),
            )
            .unwrap();
        // Verify the object created owns the `ManagingRefs`
        assert_eq!(code_object, ManagingRefs::new(context.object_address));

        let module_address = context.object_address.to_string();
        assert_success!(context.harness.run_entry_function(
            &context.account,
            str::parse(&format!("{}::test::hello", module_address)).unwrap(),
            vec![],
            vec![bcs::to_bytes::<u64>(&42).unwrap()]
        ));

        let state = context
            .read_resource::<State>(
                context.account.address(),
                &format!("{}::test::State", module_address),
            )
            .unwrap();
        assert_eq!(state.value, 42);
    } else {
        context.assert_feature_flag_error(status, EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED);
    }
}
```
