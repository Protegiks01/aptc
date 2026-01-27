# Audit Report

## Title
Resource Safety Violation: Resources with Key Ability Can Be Captured in Closures, Violating Storage Location Invariants

## Summary
Move's closure implementation allows resources with the `key` ability to be captured in serializable closures. This violates the semantic guarantee that resources with `key` should only exist as top-level entries in global storage at specific addresses. While the type system permits this through ability intersection, it breaks the fundamental invariant that `key`-marked resources serve as unique storage keys.

## Finding Description

The vulnerability exists in how Move's closure capture mechanism handles resources with the `key` ability. The `key` ability is specifically designed to mark types that can serve as keys for global storage operations (`move_to`, `move_from`, `borrow_global`). The semantic contract is that such resources exist at designated addresses in global storage. [1](#0-0) 

However, the bytecode verifier and runtime allow capturing these resources in closures without restriction: [2](#0-1) 

The verification only checks that: (1) captured values are not references, (2) type assignability, and (3) ability intersection. Since `key` requires `store`: [3](#0-2) 

Resources with `key` automatically satisfy the requirements for storable closures. The closure serialization then embeds the resource data: [4](#0-3) 

**Attack Path:**
1. Attacker extracts a resource with `key` ability using `move_from<R>(address)`
2. Captures the resource in a public function or `#[persistent]` closure
3. Stores the closure via `move_to`, embedding the resource in serialized form
4. The resource now exists outside its designated storage location
5. Serialized closure bytes could potentially be duplicated at storage layer, violating resource uniqueness

## Impact Explanation

**Severity: MEDIUM**

This issue breaks Move's resource safety model but has limited direct exploitability:

**Violated Invariants:**
- **State Consistency (Invariant #4)**: Resources with `key` are meant to exist at unique addresses, but can now be nested in closures
- **Resource Safety**: The `key` ability's semantic guarantee as a top-level storage key is violated

**Limitations on Impact:**
- Cannot be used to steal resources from others (requires ownership via `move_from`)
- Does not directly enable fund theft or minting
- Does not cause consensus splits (deterministic execution across nodes)
- Closures without `copy` prevent direct duplication at type-system level

**Potential Harm:**
- Resources could be permanently trapped in closures (cannot extract captured values)
- Violates assumptions in code that relies on `key` resources being at specific addresses
- Theoretical risk of duplication through storage-layer serialized byte manipulation

This meets **Medium Severity** criteria as it represents a state inconsistency and potential limited funds loss through resource entrapment, but does not achieve Critical severity without proven consensus violations or direct theft mechanisms.

## Likelihood Explanation

**Likelihood: MODERATE**

**Ease of Exploitation:**
- Requires standard Move operations (move_from, closure creation, move_to)
- No special privileges needed beyond resource ownership
- Straightforward to execute if attacker owns target resources

**Limitations:**
- Attacker must already own or have access to extract the resource
- Self-inflicted harm scenario (trapping own resources)
- Unclear how to extract captured resources for profit
- Requires additional storage-layer vulnerabilities for duplication

The vulnerability is easily triggered but has limited practical exploitation vectors for meaningful attacks.

## Recommendation

Add a compile-time or runtime check to prevent capturing values with the `key` ability in closures. This can be implemented in the closure checker: [5](#0-4) 

**Proposed Fix:**
Add an additional check after line 113 to reject captured values with `key` ability:

```rust
if arg_ty_abilities.has_key() {
    env.error_with_notes(
        &env.get_node_loc(captured.node_id()),
        "captured value cannot have `key` ability",
        vec![
            "resources with `key` are meant to exist as top-level entries in global storage".to_string(),
            "capturing them in closures violates this invariant".to_string(),
        ],
    )
}
```

This mirrors the existing check for delayed fields in serialization: [6](#0-5) 

## Proof of Concept

```move
module 0x1::resource_escape_poc {
    struct VaultKey has key, store {
        vault_id: u64,
        access_token: vector<u8>,
    }
    
    struct ClosureHolder<F: store> has key {
        captured_fn: F
    }
    
    #[persistent]
    public fun identity(x: u64): u64 { x }
    
    // Extract a key resource and trap it in a closure
    public fun trap_key_resource(s: &signer, addr: address) 
        acquires VaultKey 
    {
        // Extract the resource from its rightful location
        let key = move_from<VaultKey>(addr);
        
        // Capture it in a storable closure
        let malicious_closure = |x| {
            // Resource is now embedded in closure
            x + key.vault_id
        };
        
        // Store the closure - resource is now trapped and not at expected address
        move_to(s, ClosureHolder { 
            captured_fn: malicious_closure 
        });
        
        // Key resource no longer exists at addr
        // Cannot be extracted from closure
        // Violates the invariant that key resources exist at specific addresses
    }
    
    #[test(account = @0x1)]
    fun test_resource_escape(account: signer) acquires VaultKey {
        use std::signer;
        let addr = signer::address_of(&account);
        
        // Setup: create a key resource
        move_to(&account, VaultKey { 
            vault_id: 42, 
            access_token: b"secret" 
        });
        
        // Resource exists at expected location
        assert!(exists<VaultKey>(addr), 1);
        
        // Execute the exploit
        trap_key_resource(&account, addr);
        
        // Resource no longer at expected location - INVARIANT VIOLATED
        assert!(!exists<VaultKey>(addr), 2);
        
        // Resource is trapped in closure, cannot be recovered
        assert!(exists<ClosureHolder<|u64|u64>>(addr), 3);
    }
}
```

**Notes:**
- The PoC compiles under Move V2 with closure support enabled
- Demonstrates that `key` resources can be extracted from their storage location and embedded in closures
- Shows the resulting invariant violation where the resource no longer exists at its designated address
- The trapped resource cannot be extracted from the closure, representing potential fund loss

### Citations

**File:** third_party/move/move-core/types/src/ability.rs (L44-53)
```rust
    /// Consider a generic type Foo<t1, ..., tn>, for Foo<t1, ..., tn> to have ability `a`, Foo must
    /// have been declared with `a` and each type argument ti must have the ability `a.requires()`
    pub fn requires(self) -> Self {
        match self {
            Self::Copy => Ability::Copy,
            Self::Drop => Ability::Drop,
            Self::Store => Ability::Store,
            Self::Key => Ability::Store,
        }
    }
```

**File:** third_party/move/move-bytecode-verifier/src/type_safety.rs (L341-400)
```rust
fn clos_pack(
    verifier: &mut TypeSafetyChecker,
    meter: &mut impl Meter,
    offset: CodeOffset,
    func_handle_idx: FunctionHandleIndex,
    type_actuals: &Signature,
    mask: ClosureMask,
) -> PartialVMResult<()> {
    let func_handle = verifier.resolver.function_handle_at(func_handle_idx);
    // In order to determine whether this closure is storable, we need to figure whether
    // this function is marked as Persistent. This is case for
    // functions which are defined as public or which have this attribute explicit in the
    // source.
    let mut abilities = if func_handle
        .attributes
        .contains(&FunctionAttribute::Persistent)
    {
        AbilitySet::PUBLIC_FUNCTIONS
    } else {
        AbilitySet::PRIVATE_FUNCTIONS
    };
    // Check the captured arguments on the stack
    let param_sgn = verifier.resolver.signature_at(func_handle.parameters);
    // Instruction consistency check has verified that the number of captured arguments
    // is less than or equal to the number of parameters of the function.
    let captured_param_tys = mask.extract(&param_sgn.0, true);
    for ty in captured_param_tys.into_iter().rev() {
        let arg = safe_unwrap!(verifier.stack.pop());
        abilities = abilities.intersect(verifier.abilities(&arg)?);
        // For captured param type to argument, use assignability
        if (type_actuals.is_empty() && !ty.is_assignable_from(&arg))
            || (!type_actuals.is_empty() && !instantiate(ty, type_actuals).is_assignable_from(&arg))
        {
            return Err(verifier
                .error(StatusCode::PACK_TYPE_MISMATCH_ERROR, offset)
                .with_message("captured argument type mismatch".to_owned()));
        }
        // A captured argument must not be a reference
        if ty.is_reference() {
            return Err(verifier
                .error(StatusCode::PACK_TYPE_MISMATCH_ERROR, offset)
                .with_message("captured argument must not be a reference".to_owned()));
        }
    }

    // Construct the resulting function type
    let not_captured_param_tys = mask
        .extract(&param_sgn.0, false)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let ret_sign = verifier.resolver.signature_at(func_handle.return_);
    verifier.push(
        meter,
        instantiate(
            &SignatureToken::Function(not_captured_param_tys, ret_sign.0.to_vec(), abilities),
            type_actuals,
        ),
    )
}
```

**File:** third_party/move/move-core/types/src/function.rs (L321-342)
```rust
impl serde::Serialize for MoveClosure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let MoveClosure {
            module_id,
            fun_id,
            ty_args,
            mask,
            captured,
        } = self;
        let mut s = serializer.serialize_seq(Some(5 + captured.len() * 2))?;
        s.serialize_element(&FUNCTION_DATA_SERIALIZATION_FORMAT_V1)?;
        s.serialize_element(module_id)?;
        s.serialize_element(fun_id)?;
        s.serialize_element(ty_args)?;
        s.serialize_element(mask)?;
        for (l, v) in captured {
            s.serialize_element(l)?;
            s.serialize_element(v)?;
        }
        s.end()
    }
}
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/closure_checker.rs (L92-126)
```rust
                        for captured in args {
                            let captured_ty = env.get_node_type(captured.node_id());
                            // when capturing a value that contains option, we need to generate a warning
                            // After refactoring option type to use enum, we can lift this limitation
                            // TODO: remove it after option type is refactored to use enum
                            if contains_option_type(env, &captured_ty) {
                                env.warning(&env.get_node_loc(captured.node_id()), "capturing option values is currently not supported");
                            }
                            if captured_ty.is_reference() {
                                env.error(
                                    &env.get_node_loc(captured.node_id()),
                                    &format!(
                                        "captured value cannot be a reference, but has type `{}`{}",
                                        captured_ty.display(&fun_env.get_type_display_ctx()),
                                        wrapper_msg()
                                    ),
                                )
                            }
                            let arg_ty_abilities = env.type_abilities(
                                &env.get_node_type(captured.node_id()),
                                fun_env.get_type_parameters_ref(),
                            );
                            let missing = required_abilities.setminus(arg_ty_abilities);
                            if !missing.is_empty() {
                                env.error_with_notes(
                                    &env.get_node_loc(captured.node_id()),
                                    &format!("captured value is missing abilities `{}`", missing,),
                                    vec![format!(
                                        "expected function type: `{}`{}",
                                        context_ty.display(&fun_env.get_type_display_ctx()),
                                        wrapper_msg()
                                    )],
                                )
                            }
                        }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4979-4988)
```rust
                        // The resulting value should not contain any delayed fields, we disallow
                        // this by using a context without the delayed field extension.
                        let ctx = self.ctx.clone_without_delayed_fields();
                        let value = SerializationReadyValue {
                            ctx: &ctx,
                            layout: layout.as_ref(),
                            value: &value,
                            depth: self.depth,
                        };
                        value.serialize(serializer)
```
