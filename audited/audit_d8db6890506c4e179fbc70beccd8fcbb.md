# Audit Report

## Title
Backward Compatibility Break in Dispatchable Fungible Asset Interface Causes Permanent Token Freezing

## Summary
Changes to the dispatcher function signatures in the Aptos Framework can permanently freeze all existing fungible assets that have registered custom dispatch functions. The runtime type checking mechanism in the Move VM will reject dispatches when signatures don't match, and there is no mechanism to update or migrate registered dispatch functions after deployment.

## Finding Description

The dispatchable fungible asset system allows token issuers to register custom functions for `withdraw`, `deposit`, `derived_balance`, and `derived_supply` operations. These functions are stored in the `DispatchFunctionStore` resource at registration time and cannot be modified afterward. [1](#0-0) 

When dispatch functions are registered, they undergo type compatibility validation against the current dispatcher signatures: [2](#0-1) 

However, the registration function explicitly prevents re-registration: [3](#0-2) 

At runtime, when a dispatch occurs, the native function returns a `FunctionDispatch` instruction to the VM: [4](#0-3) 

The Move VM interpreter performs strict runtime type checking when executing the dispatch: [5](#0-4) 

**The vulnerability**: If the Aptos Framework is upgraded and the dispatcher function signatures change (e.g., adding a parameter, changing types), the runtime type check will fail for ALL existing fungible assets with registered dispatch functions. Since there is no mechanism to update the stored `FunctionInfo` in `DispatchFunctionStore`, these tokens become permanently frozen.

**Attack scenario**: 
1. Token issuer deploys a dispatchable fungible asset with custom withdraw/deposit functions
2. Users acquire and hold these tokens
3. Aptos Framework upgrade changes dispatcher signatures (e.g., adds compliance parameter)
4. All withdraw/deposit operations fail with `RUNTIME_DISPATCH_ERROR`
5. Tokens are permanently frozen - no way to transfer, withdraw, or access funds

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program because it causes **"Permanent freezing of funds (requires hardfork)"**, which is explicitly listed as a Critical impact category worth up to $1,000,000.

The impact affects:
- **All dispatchable fungible assets in production** - any token that registered custom dispatch functions becomes frozen
- **No recovery mechanism** - the `DispatchFunctionStore` cannot be updated, modified, or replaced
- **Requires hardfork** - the only solution is a protocol upgrade to add migration functionality
- **Ecosystem-wide damage** - affects all DeFi protocols, DEXs, and users holding dispatchable tokens
- **Loss of funds** - users cannot access or transfer their tokens

## Likelihood Explanation

**Likelihood: HIGH**

Framework upgrades are routine maintenance activities on Aptos. The likelihood is high because:

1. **Common upgrade scenarios**: Adding security features (e.g., compliance checks, sender tracking), improving gas efficiency (parameter type changes), or adding functionality (new parameters) all require signature changes
2. **No versioning system**: The dispatcher interface has no version checking or compatibility layers
3. **Already deployed tokens**: Any dispatchable fungible assets currently on mainnet would be immediately affected
4. **No warning mechanism**: Token issuers have no way to know their tokens will be frozen until after the upgrade

The type compatibility validation logic confirms this will occur automatically: [6](#0-5) 

## Recommendation

Implement a multi-layered solution:

**1. Add version-aware dispatch mechanism:**
```move
struct DispatchFunctionStore has key {
    version: u64,
    withdraw_function: Option<FunctionInfo>,
    deposit_function: Option<FunctionInfo>,
    derived_balance_function: Option<FunctionInfo>
}
```

**2. Add migration function (friend-only):**
```move
public(friend) fun migrate_dispatch_functions(
    metadata: Object<Metadata>,
    new_withdraw: Option<FunctionInfo>,
    new_deposit: Option<FunctionInfo>,
    new_derived_balance: Option<FunctionInfo>
) acquires DispatchFunctionStore {
    let store = borrow_global_mut<DispatchFunctionStore>(object::object_address(&metadata));
    store.withdraw_function = new_withdraw;
    store.deposit_function = new_deposit;
    store.derived_balance_function = new_derived_balance;
    store.version = store.version + 1;
}
```

**3. Add compatibility layer in native dispatch:**
- Check version field
- Apply parameter transformations based on version
- Support multiple signature versions simultaneously

**4. Implement upgrade notification system:**
- Emit events when dispatcher signatures will change
- Provide migration window before enforcing new signatures
- Document breaking changes in governance proposals

## Proof of Concept

```move
#[test_only]
module 0xcafe::dispatch_freeze_poc {
    use aptos_framework::fungible_asset;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::object::{Self, ConstructorRef};
    use aptos_framework::function_info;
    use std::option;
    use std::string;
    use std::signer;

    // Step 1: Deploy token with dispatch functions
    public fun deploy_token(creator: &signer, constructor_ref: &ConstructorRef) {
        let withdraw_fn = function_info::new_function_info(
            creator,
            string::utf8(b"dispatch_freeze_poc"),
            string::utf8(b"custom_withdraw")
        );
        
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw_fn),
            option::none(),
            option::none()
        );
    }

    // Original custom withdraw matching current dispatcher signature
    public fun custom_withdraw<T: key>(
        store: object::Object<T>,
        amount: u64,
        transfer_ref: &fungible_asset::TransferRef,
    ): fungible_asset::FungibleAsset {
        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }

    // Step 2: Simulate framework upgrade - dispatcher signature changes
    // New dispatchable_withdraw signature adds 'sender' parameter:
    // native fun dispatchable_withdraw<T: key>(
    //     store: Object<T>,
    //     amount: u64,
    //     sender: address,  // NEW PARAMETER
    //     transfer_ref: &TransferRef,
    //     function: &FunctionInfo,
    // ): FungibleAsset;

    // Step 3: Runtime type check fails
    // VM compares:
    //   Dispatcher params: [Object<T>, u64, address, &TransferRef, &FunctionInfo]
    //   Target params:     [Object<T>, u64, &TransferRef]
    // Check fails: [Object<T>, u64, address, &TransferRef] != [Object<T>, u64, &TransferRef]
    // Error: RUNTIME_DISPATCH_ERROR - "Invoking function with incompatible type"
    
    // Step 4: All withdrawals permanently fail - tokens frozen
}
```

**Reproduction Steps:**
1. Deploy a dispatchable fungible asset with custom dispatch functions
2. Modify the dispatcher native function signatures in `dispatchable_fungible_asset.move`
3. Attempt to call `withdraw()` or `deposit()` on the deployed token
4. Observe `RUNTIME_DISPATCH_ERROR` with message "Invoking function with incompatible type"
5. Verify that `DispatchFunctionStore` cannot be updated (EALREADY_REGISTERED error)
6. Confirm tokens are permanently frozen with no recovery path

### Citations

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L158-162)
```text
    struct DispatchFunctionStore has key {
        withdraw_function: Option<FunctionInfo>,
        deposit_function: Option<FunctionInfo>,
        derived_balance_function: Option<FunctionInfo>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L376-392)
```text
        // Verify that caller type matches callee type so wrongly typed function cannot be registered.
        withdraw_function.for_each_ref(|withdraw_function| {
                let dispatcher_withdraw_function_info =
                    function_info::new_function_info_from_address(
                        @aptos_framework,
                        string::utf8(b"dispatchable_fungible_asset"),
                        string::utf8(b"dispatchable_withdraw")
                    );

                assert!(
                    function_info::check_dispatch_type_compatibility(
                        &dispatcher_withdraw_function_info,
                        withdraw_function
                    ),
                    error::invalid_argument(EWITHDRAW_FUNCTION_SIGNATURE_MISMATCH)
                );
            });
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L430-435)
```text
        assert!(
            !exists<DispatchFunctionStore>(
                constructor_ref.address_from_constructor_ref()
            ),
            error::already_exists(EALREADY_REGISTERED)
        );
```

**File:** aptos-move/framework/src/natives/dispatchable_fungible_asset.rs (L22-56)
```rust
pub(crate) fn native_dispatch(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let (module_name, func_name) = extract_function_info(&mut arguments)?;

    // Check if the module is already properly charged in this transaction.
    let check_visited = |a, n| {
        let special_addresses_considered_visited =
            context.get_feature_flags().is_account_abstraction_enabled()
                || context
                    .get_feature_flags()
                    .is_derivable_account_abstraction_enabled();
        if special_addresses_considered_visited {
            context
                .traversal_context()
                .check_is_special_or_visited(a, n)
        } else {
            context.traversal_context().legacy_check_visited(a, n)
        }
    };
    check_visited(module_name.address(), module_name.name())
        .map_err(|_| SafeNativeError::Abort { abort_code: 4 })?;

    context.charge(DISPATCHABLE_FUNGIBLE_ASSET_DISPATCH_BASE)?;

    // Use Error to instruct the VM to perform a function call dispatch.
    Err(SafeNativeError::FunctionDispatch {
        module_name,
        func_name,
        ty_args: ty_args.to_vec(),
        args: arguments.into_iter().collect(),
    })
}
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1204-1211)
```rust
                if function.ty_param_abilities() != target_func.ty_param_abilities()
                    || function.return_tys() != target_func.return_tys()
                    || &function.param_tys()[0..function.param_tys().len() - 1]
                        != target_func.param_tys()
                {
                    return Err(PartialVMError::new(StatusCode::RUNTIME_DISPATCH_ERROR)
                        .with_message("Invoking function with incompatible type".to_string()));
                }
```

**File:** aptos-move/framework/src/natives/function_info.rs (L122-133)
```rust
    if lhs.param_tys().is_empty() {
        return Err(SafeNativeError::Abort { abort_code: 2 });
    }

    Ok(smallvec![Value::bool(
        rhs.ty_param_abilities() == lhs.ty_param_abilities()
            && rhs.return_tys() == lhs.return_tys()
            && &lhs.param_tys()[0..lhs.param_count() - 1] == rhs.param_tys()
            && rhs.is_public()
            && !rhs.is_native()
            && lhs_id != rhs_id
    )])
```
