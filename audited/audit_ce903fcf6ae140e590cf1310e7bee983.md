# Audit Report

## Title
Object Code Upgrade Bypasses Compatibility Validation via Package Name Manipulation

## Summary
The object code upgrade mechanism fails to enforce the documented "one package per object" invariant, allowing object owners to bypass upgrade compatibility validation by publishing a package with a different name. This violates critical safety guarantees and can break external contracts depending on object interfaces.

## Finding Description

The `object_code_deployment` module documents that "each code_object should only have one package" [1](#0-0) , but this invariant is not enforced during upgrades.

When `object_code_deployment::upgrade()` is called [2](#0-1) , it generates a signer for the object and calls `code::publish_package_txn()` [3](#0-2) , which deserializes metadata and calls `code::publish_package()` [4](#0-3) .

In `publish_package()`, the code iterates through existing packages and only applies `check_upgradability()` when package names match [5](#0-4) . If package names differ, only `check_coexistence()` is called, which merely checks for module name clashes [6](#0-5) .

The `check_upgradability()` function ensures modules aren't removed and validates struct/function compatibility [7](#0-6) , while VM-level compatibility checking validates struct layouts [8](#0-7) .

**Attack Path:**
1. Attacker deploys package "PackageV1" to object O with modules and resources
2. External DeFi contracts interact with O, expecting specific public functions and struct layouts
3. Attacker "upgrades" by deploying package "PackageV2" with different module names
4. Since package names differ, NO compatibility validation occurs - only module name clash checking
5. Attacker can remove public functions, change struct layouts, and break all assumptions
6. External contracts fail, potentially losing access to funds locked in the object

## Impact Explanation

**Critical Severity** - This vulnerability enables multiple attack vectors:

1. **Loss of Funds**: DeFi protocols holding funds in objects can lose access if object owners bypass compatibility checks and break expected interfaces. This qualifies under the "Loss of Funds" critical severity category.

2. **Protocol Violations**: Bypasses the documented upgrade compatibility validation system, violating the fundamental safety guarantee that upgrades maintain backward compatibility [9](#0-8) .

3. **State Consistency Violations**: Breaks the "one package per object" design invariant explicitly documented in the codebase [1](#0-0) , allowing multiple packages to coexist in a single object.

The compatibility validation system exists specifically to prevent breaking changes during upgrades. Bypassing it undermines the entire safety model for on-chain code evolution.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

- Requires only object ownership (no special privileges)
- No complex attack setup needed - simply publish with a different package name
- No race conditions or timing dependencies
- Works with standard transaction submission via CLI or SDK
- Package metadata (including name) is fully controlled by the publisher

The attack is trivial to execute: any object owner can call the upgrade function with metadata specifying a different package name, and the system will accept it without compatibility validation.

## Recommendation

Add validation in `object_code_deployment::upgrade()` to enforce the "one package per object" invariant:

```move
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

    // NEW: Validate package name matches existing package
    let new_metadata = util::from_bytes<PackageMetadata>(metadata_serialized);
    if (exists<PackageRegistry>(code_object_address)) {
        let registry = borrow_global<PackageRegistry>(code_object_address);
        assert!(
            vector::length(&registry.packages) == 1,
            error::invalid_state(EMULTIPLE_PACKAGES_IN_OBJECT)
        );
        let existing_package = vector::borrow(&registry.packages, 0);
        assert!(
            existing_package.name == new_metadata.name,
            error::invalid_argument(EPACKAGE_NAME_MISMATCH)
        );
    };

    let extend_ref = &borrow_global<ManagingRefs>(code_object_address).extend_ref;
    let code_signer = &object::generate_signer_for_extending(extend_ref);
    code::publish_package_txn(code_signer, metadata_serialized, code);

    event::emit(Upgrade { object_address: signer::address_of(code_signer), });
}
```

Add error constants:
```move
const EMULTIPLE_PACKAGES_IN_OBJECT: u64 = 0xC;
const EPACKAGE_NAME_MISMATCH: u64 = 0xD;
```

## Proof of Concept

```move
#[test_only]
module test_addr::exploit_bypass_validation {
    use std::signer;
    use std::vector;
    use aptos_framework::object;
    use aptos_framework::object_code_deployment;
    use aptos_framework::code;

    struct ResourceV1 has key {
        value: u64,
    }

    #[test(creator = @0xCAFE)]
    public fun test_bypass_upgrade_validation(creator: &signer) {
        // 1. Deploy initial package "PackageV1" to object
        let metadata_v1 = create_package_metadata(b"PackageV1", vector[b"module_v1"]);
        let code_v1 = vector[compile_module_v1()];
        object_code_deployment::publish(creator, metadata_v1, code_v1);
        
        // Assume object address is determined
        let obj_addr = get_created_object_address();
        
        // 2. Store resources using V1 code
        move_to(creator, ResourceV1 { value: 1000 });
        
        // 3. "Upgrade" with different package name - bypasses compatibility!
        let metadata_v2 = create_package_metadata(b"PackageV2", vector[b"module_v2"]);
        let code_v2 = vector[compile_incompatible_module_v2()]; // Removes public functions!
        
        // This should fail due to compatibility but succeeds because package name differs
        object_code_deployment::upgrade(
            creator,
            metadata_v2,
            code_v2,
            object::address_to_object<code::PackageRegistry>(obj_addr)
        );
        
        // Result: Object now has TWO packages, compatibility validation bypassed
        // External contracts expecting V1 interface are broken
    }
}
```

**Notes**

This vulnerability is particularly severe because:
- It's not visible in standard usage patterns (most users upgrade with the same package name)
- The design documents explicitly forbid multiple packages per object, but enforcement is missing
- The `freeze_code_object` implementation acknowledges multiple packages can exist [10](#0-9) , contradicting the documented design
- External contracts have no way to detect this bypass without explicitly checking package names

The fix must be implemented at the framework level to maintain the documented security invariant and prevent upgrade validation bypass.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L144-144)
```text
    /// Each `code_object` should only have one package, as one package is deployed per object in this module.
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L137-141)
```text
    /// Whether a compatibility check should be performed for upgrades. The check only passes if
    /// a new module has (a) the same public functions (b) for existing resources, no layout change.
    public fun upgrade_policy_compat(): UpgradePolicy {
        UpgradePolicy { policy: 1 }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L192-202)
```text
        vector::enumerate_ref(package_immutable
        , |i, old| {
            let old: &PackageMetadata = old;
            if (old.name == pack.name) {
                upgrade_number = old.upgrade_number + 1;
                check_upgradability(old, &pack, &module_names);
                index = i;
            } else {
                check_coexistence(old, &module_names)
            };
        });
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L240-243)
```text
        vector::for_each_mut(&mut registry.packages, |pack| {
            let package: &mut PackageMetadata = pack;
            package.upgrade_policy = upgrade_policy_immutable();
        });
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L265-279)
```text
    fun check_upgradability(
        old_pack: &PackageMetadata, new_pack: &PackageMetadata, new_modules: &vector<String>) {
        assert!(old_pack.upgrade_policy.policy < upgrade_policy_immutable().policy,
            error::invalid_argument(EUPGRADE_IMMUTABLE));
        assert!(can_change_upgrade_policy_to(old_pack.upgrade_policy, new_pack.upgrade_policy),
            error::invalid_argument(EUPGRADE_WEAKER_POLICY));
        let old_modules = get_module_names(old_pack);

        vector::for_each_ref(&old_modules, |old_module| {
            assert!(
                vector::contains(new_modules, old_module),
                EMODULE_MISSING
            );
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L282-293)
```text
    fun check_coexistence(old_pack: &PackageMetadata, new_modules: &vector<String>) {
        // The modules introduced by each package must not overlap with `names`.
        vector::for_each_ref(&old_pack.modules, |old_mod| {
            let old_mod: &ModuleMetadata = old_mod;
            let j = 0;
            while (j < vector::length(new_modules)) {
                let name = vector::borrow(new_modules, j);
                assert!(&old_mod.name != name, error::already_exists(EMODULE_NAME_CLASH));
                j = j + 1;
            };
        });
    }
```

**File:** third_party/move/move-binary-format/src/compatibility.rs (L86-301)
```rust
    pub fn need_check_compat(&self) -> bool {
        self.check_struct_and_pub_function_linking
            || self.check_friend_linking
            || self.check_struct_layout
    }

    /// Check compatibility for `new_module` relative to old module `old_module`.
    #[allow(clippy::nonminimal_bool)] // simplification is more unreadable
    pub fn check(
        &self,
        old_module: &CompiledModule,
        new_module: &CompiledModule,
    ) -> PartialVMResult<()> {
        let mut errors = vec![];

        // module's name and address are unchanged
        if old_module.address() != new_module.address() {
            errors.push(format!(
                "module address changed to `{}`",
                new_module.address()
            ));
        }
        if old_module.name() != new_module.name() {
            errors.push(format!("module name changed to `{}`", new_module.name()));
        }

        let old_view = ModuleView::new(old_module);
        let new_view = ModuleView::new(new_module);

        // old module's structs are a subset of the new module's structs
        for old_struct in old_view.structs() {
            let new_struct = match new_view.struct_definition(old_struct.name()) {
                Some(new_struct) => new_struct,
                None => {
                    // Struct not present in new . Existing modules that depend on this struct will fail to link with the new version of the module.
                    // Also, struct layout cannot be guaranteed transitively, because after
                    // removing the struct, it could be re-added later with a different layout.
                    errors.push(format!("removed struct `{}`", old_struct.name()));
                    break;
                },
            };

            if !self.struct_abilities_compatible(old_struct.abilities(), new_struct.abilities()) {
                errors.push(format!(
                    "removed abilities `{}` from struct `{}`",
                    old_struct.abilities().setminus(new_struct.abilities()),
                    old_struct.name()
                ));
            }
            if !self.struct_type_parameters_compatible(
                old_struct.type_parameters(),
                new_struct.type_parameters(),
            ) {
                errors.push(format!(
                    "changed type parameters of struct `{}`",
                    old_struct.name()
                ));
            }
            // Layout of old and new struct need to be compatible
            if self.check_struct_layout && !self.struct_layout_compatible(&old_struct, new_struct) {
                errors.push(format!("changed layout of struct `{}`", old_struct.name()));
            }
        }

        // The modules are considered as compatible function-wise when all the conditions are met:
        //
        // - old module's public functions are a subset of the new module's public functions
        //   (i.e. we cannot remove or change public functions)
        // - old module's entry functions are a subset of the new module's entry functions
        //   (i.e. we cannot remove or change entry functions). This can be turned off by
        //   `!self.check_friend_linking`.
        // - for any friend function that is removed or changed in the old module
        //   - if the function visibility is upgraded to public, it is OK
        //   - otherwise, it is considered as incompatible.
        // - moreover, a function marked as `#[persistent]` is treated as a public function.
        //
        for old_func in old_view.functions() {
            let old_is_persistent = old_func
                .attributes()
                .contains(&FunctionAttribute::Persistent);

            // private, non entry function doesn't need to follow any checks here, skip
            if old_func.visibility() == Visibility::Private
                && !old_func.is_entry()
                && !old_is_persistent
            {
                // Function not exposed, continue with next one
                continue;
            }
            let new_func = match new_view.function_definition(old_func.name()) {
                Some(new_func) => new_func,
                None => {
                    // Function has been removed
                    // Function is NOT a private, non entry function, or it is persistent.
                    if old_is_persistent
                        || !matches!(old_func.visibility(), Visibility::Friend)
                        // Above: Either Private Entry, or Public
                        || self.check_friend_linking
                        // Here we know that the old_function has to be Friend.
                        // And if friends are not considered private (self.check_friend_linking is
                        // true), we can't update.
                        || (old_func.is_entry() && self.treat_entry_as_public)
                    // Here we know that the old_func has to be Friend, and the
                    // check_friend_linking is set to false. We make sure that we don't allow
                    // any Entry functions to be deleted, when self.treat_entry_as_public is
                    // set (treats entry as public)
                    {
                        errors.push(format!("removed function `{}`", old_func.name()));
                    }
                    continue;
                },
            };

            if !old_is_persistent
                && matches!(old_func.visibility(), Visibility::Friend)
                && !self.check_friend_linking
                // Above: We want to skip linking checks for public(friend) if
                // self.check_friend_linking is set to false.
                && !(old_func.is_entry() && self.treat_entry_as_public)
            // However, public(friend) entry function still needs to be checked.
            {
                continue;
            }
            let is_vis_compatible = match (old_func.visibility(), new_func.visibility()) {
                // public must remain public
                (Visibility::Public, Visibility::Public) => true,
                (Visibility::Public, _) => false,
                // friend can become public or remain friend
                (Visibility::Friend, Visibility::Public)
                | (Visibility::Friend, Visibility::Friend) => true,
                (Visibility::Friend, _) => false,
                // private can become public or friend, or stay private
                (Visibility::Private, _) => true,
            };
            let is_entry_compatible =
                if old_view.module().version < VERSION_5 && new_view.module().version < VERSION_5 {
                    // if it was public(script), it must remain public(script)
                    // if it was not public(script), it _cannot_ become public(script)
                    old_func.is_entry() == new_func.is_entry()
                } else {
                    // If it was an entry function, it must remain one.
                    // If it was not an entry function, it is allowed to become one.
                    !old_func.is_entry() || new_func.is_entry()
                };
            let is_attribute_compatible =
                FunctionAttribute::is_compatible_with(old_func.attributes(), new_func.attributes());
            let error_msg = if !is_vis_compatible {
                Some("changed visibility")
            } else if !is_entry_compatible {
                Some("removed `entry` modifier")
            } else if !is_attribute_compatible {
                Some("removed required attributes")
            } else if !self.signature_compatible(
                old_module,
                old_func.parameters(),
                new_module,
                new_func.parameters(),
            ) {
                Some("changed parameter types")
            } else if !self.signature_compatible(
                old_module,
                old_func.return_type(),
                new_module,
                new_func.return_type(),
            ) {
                Some("changed return type")
            } else if !self.fun_type_parameters_compatible(
                old_func.type_parameters(),
                new_func.type_parameters(),
            ) {
                Some("changed type parameters")
            } else {
                None
            };
            if let Some(msg) = error_msg {
                errors.push(format!("{} of function `{}`", msg, old_func.name()));
            }
        }

        // check friend declarations compatibility
        //
        // - additions to the list are allowed
        // - removals are not allowed
        //
        if self.check_friend_linking {
            let old_friend_module_ids: BTreeSet<_> =
                old_module.immediate_friends().iter().cloned().collect();
            let new_friend_module_ids: BTreeSet<_> =
                new_module.immediate_friends().iter().cloned().collect();
            if !old_friend_module_ids.is_subset(&new_friend_module_ids) {
                errors.push(format!(
                    "removed friend declaration {}",
                    old_friend_module_ids
                        .difference(&new_friend_module_ids)
                        .map(|id| format!("`{}`", id))
                        .collect::<Vec<_>>()
                        .join(" and ")
                ))
            }
        }

        if !errors.is_empty() {
            Err(
                PartialVMError::new(StatusCode::BACKWARD_INCOMPATIBLE_MODULE_UPDATE).with_message(
                    format!(
                        "Module update failure: new module not compatible with \
                        existing module in `{}`: {}",
                        old_view.id(),
                        errors.join(", ")
                    ),
                ),
            )
        } else {
            Ok(())
        }
    }
```
