# Audit Report

## Title
Module Boundary Bypass via Persistent Closures Over Private Functions

## Summary
Private functions marked with `#[persistent]` attribute can be exposed and invoked by external modules through closures, bypassing Move's module encapsulation guarantees. The Move VM intentionally skips visibility checks for closure invocations, creating a semantic gap where developers may unintentionally expose security-sensitive private functions.

## Finding Description

The Move compiler allows private functions with the `#[persistent]` attribute to be captured in closures that have the `store` ability. [1](#0-0) 

Once a closure captures a private persistent function, it can be:
1. Stored in global storage
2. Returned from public functions  
3. Passed across module boundaries

When the closure is invoked, the Move VM explicitly skips visibility checks for `CallType::ClosureDynamicDispatch`, allowing private functions of other modules to be called. [2](#0-1) 

**Attack Path:**
1. Victim module defines private function with `#[persistent]` containing sensitive logic
2. Victim module creates closure over this function (directly or via lambda lifting)
3. Victim module exposes closure through public API or generic storage mechanism
4. Attacker module obtains closure via public interface
5. Attacker invokes closure, executing victim's private function with no visibility checks

**Example from test files:**
The pattern is demonstrated where private persistent functions are stored in closures and invoked across module boundaries. [3](#0-2) 

Generic storage modules can extract and return closures of any type, enabling cross-module invocation. [4](#0-3) 

This breaks the **Access Control invariant** where module boundaries should protect private implementation details from external access.

## Impact Explanation

**Severity: High**

This vulnerability enables:
- **Access Control Bypass**: Private functions containing security-sensitive logic (admin privilege grants, access control checks, internal state mutations) can be invoked by unauthorized external modules
- **Module Encapsulation Violation**: Breaks the fundamental Move security model where `private` visibility guarantees functions are only callable within their defining module
- **Semantic Confusion**: Creates a footgun where developers using `#[persistent]` (e.g., for module upgrades) unknowingly expose private functions globally

While this doesn't directly cause loss of funds or consensus violations in Aptos Core itself, it creates a **systemic vulnerability pattern** that affects any application-level Move code, including governance and staking modules. Any module using this pattern for security-critical operations would be vulnerable.

This meets **High Severity** criteria as it represents a "Significant protocol violation" - the violation of module encapsulation is fundamental to Move's security model.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
1. Developer marks private function with `#[persistent]` (common for upgrade compatibility)
2. Function contains security-sensitive logic
3. Closure over function is exposed via public API or storage (may happen unintentionally)
4. Attacker discovers the exposure and function signature

The likelihood is medium because:
- The `#[persistent]` attribute is legitimately used for module upgrades
- Developers expect `private` to mean "not callable externally"
- No compiler warnings alert developers to this behavior
- The pattern appears in test files, suggesting it may be used in production code

## Recommendation

1. **Add Compiler Warning**: Emit a warning when closures over private `#[persistent]` functions are returned from public functions or stored in resources with `store+key` abilities:

```rust
// In closure_checker.rs, after line 78:
if required_abilities.has_ability(Ability::Store)
    && fun_env.visibility() != Visibility::Public
    && fun_env.has_attribute(|attr| {
        env.symbol_pool().string(attr.name()).as_str()
            == well_known::PERSISTENT_ATTRIBUTE
    })
{
    env.warning(
        &env.get_node_loc(*id),
        "closure over private function with #[persistent] can be invoked by external modules; \
         consider making the function public or removing #[persistent] if external access is unintended"
    );
}
```

2. **Documentation**: Clearly document that `#[persistent]` on private functions allows them to be invoked via closures from any module, effectively making them "publicly callable through indirection"

3. **Static Analysis**: Add lint check to detect when closures over private persistent functions escape module boundaries through public APIs

4. **Alternative Design**: Consider adding `#[persistent(private)]` and `#[persistent(public)]` to make the visibility implications explicit

## Proof of Concept

```move
//# publish
module 0x42::VictimModule {
    use std::signer;
    
    struct AdminRegistry has key {
        admins: vector<address>
    }
    
    // Private function - developer expects only internal access
    #[persistent]
    fun add_admin_internal(new_admin: address) acquires AdminRegistry {
        let registry = borrow_global_mut<AdminRegistry>(@0x42);
        vector::push_back(&mut registry.admins, new_admin);
    }
    
    // Public function returns closure - unintentionally exposes private function
    public fun get_admin_adder(): |address| {
        add_admin_internal
    }
    
    public fun init(account: &signer) {
        move_to(account, AdminRegistry { admins: vector[] });
    }
    
    public fun is_admin(addr: address): bool acquires AdminRegistry {
        let registry = borrow_global<AdminRegistry>(@0x42);
        vector::contains(&registry.admins, &addr)
    }
}

//# publish  
module 0x42::AttackerModule {
    use 0x42::VictimModule;
    
    // Attacker exploits the exposed closure
    public fun exploit_add_admin(attacker_addr: address) {
        let add_admin_closure = VictimModule::get_admin_adder();
        add_admin_closure(attacker_addr);  // Calls private function!
    }
}

//# run 0x42::VictimModule::init --signers 0x42

//# run 0x42::AttackerModule::exploit_add_admin --signers 0x42 --args @0x999

//# run --check-success
script {
    use 0x42::VictimModule;
    fun check_exploit() {
        assert!(VictimModule::is_admin(@0x999), 1);  // Attacker is now admin!
    }
}
```

**Notes:**

This vulnerability is rooted in an intentional design decision where closures bypass visibility checks (as documented in the code comments), but this creates a dangerous semantic gap. While technically "working as designed," the behavior violates developers' reasonable expectations about `private` function visibility and creates a systemic security risk across the Move ecosystem. The lack of compiler warnings makes this particularly dangerous as developers using `#[persistent]` for legitimate module upgrade purposes may unknowingly expose security-critical functions.

### Citations

**File:** third_party/move/move-compiler-v2/src/env_pipeline/closure_checker.rs (L45-51)
```rust
                        if required_abilities.has_ability(Ability::Store)
                            && fun_env.visibility() != Visibility::Public
                            && !fun_env.has_attribute(|attr| {
                                env.symbol_pool().string(attr.name()).as_str()
                                    == well_known::PERSISTENT_ATTRIBUTE
                            })
                        {
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L55-59)
```rust
            CallType::ClosureDynamicDispatch => {
                // In difference to regular calls, we skip visibility check. It is possible to call
                // a private function of another module via a closure.
                Ok(())
            },
```

**File:** third_party/move/move-vm/transactional-tests/tests/function_values_safety/closure_store.masm (L16-21)
```text
#[persistent] fun action(x: u64): u32
    move_loc x
    cast_u32
    ld_u32 20
    add
    ret
```

**File:** third_party/move/move-compiler-v2/transactional-tests/tests/no-v1-comparison/closures/funs_as_storage_key.move (L11-14)
```text
    public fun remove_item<F: store+copy>(addr: address): F acquires Registry {
        let Registry{func} = move_from<Registry<F>>(addr);
        func
    }
```
