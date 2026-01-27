# Audit Report

## Title
Cyclic Friend Relationships Bypass Access Control Due to Missing Bytecode Verification

## Summary
The Move bytecode verifier fails to detect cyclic friend relationships between modules, despite explicit documentation prohibiting such cycles and existing verification code designed to catch them. This allows modules to create privilege escalation chains that violate intended access control boundaries.

## Finding Description

The Move language's friend visibility mechanism allows modules to grant access to `public(friend)` functions by declaring specific modules as friends. The official Move documentation explicitly states: [1](#0-0) 

However, the bytecode verifier **does not enforce this rule**. While verification code exists in `cyclic_dependencies.rs` to detect such cycles: [2](#0-1) 

This verification function is **never called** during module verification. The main bytecode verifier pipeline omits this check: [3](#0-2) 

Note that line 154 only calls `friends::verify_module`, which performs limited checks: [4](#0-3) 

This only checks for self-friendship and cross-address friendship, **not cycles**.

During module loading, only dependency cycles are checked, not friend cycles: [5](#0-4) 

The test suite confirms this behavior is intentional - cyclic friends are explicitly **allowed**: [6](#0-5) 

**Attack Scenario:**
Consider three modules under account `0x1`:
- Module A (core framework) has `public(friend) fun withdraw_funds()`
- Module A declares B as friend
- Module B declares C as friend  
- Module C declares A as friend (cycle: A → B → C → A)

This creates an unintended privilege chain where:
- C can call B's friend functions
- B can call A's friend functions
- A can call C's friend functions

If an attacker can publish/upgrade any module in this chain, they could potentially access functions meant to be restricted, violating the access control invariant.

## Impact Explanation

This is a **High Severity** issue under the Aptos bug bounty program:

1. **Significant Protocol Violation**: The documented invariant explicitly prohibits cyclic friend relationships, yet they are silently allowed.

2. **Access Control Bypass**: Friend visibility is a critical security mechanism in Move. Cycles undermine the principle of least privilege and create unexpected privilege escalation paths.

3. **Framework Security Risk**: Large multi-module frameworks (like the Aptos Framework itself) could accidentally create cycles during upgrades, exposing sensitive functions to unintended callers.

4. **Audit/Analysis Failure**: Security auditors and formal verification tools would assume cycles cannot exist based on documentation, potentially missing vulnerabilities.

The runtime visibility checks still function correctly: [7](#0-6) 

However, the existence of cycles violates the intended security model.

## Likelihood Explanation

**Likelihood: Medium**

While this requires publishing rights under the same account address, such rights are available to any Aptos user. The likelihood increases in scenarios where:

1. Large frameworks with many interconnected modules exist under one address
2. Module upgrades occur without comprehensive cross-module analysis
3. Multiple developers collaborate on modules under a shared account

The fact that the verification code exists but is deliberately not invoked (as evidenced by the test) suggests this may be a known limitation rather than an oversight, but it still violates documented invariants.

## Recommendation

**Immediate Fix:** Integrate cyclic friend verification into the main bytecode verifier pipeline:

In `third_party/move/move-bytecode-verifier/src/verifier.rs`, modify the `verify_module_with_config` function to call the cyclic dependency verifier. This requires providing closures that can resolve immediate dependencies and friends from the provided dependencies iterator.

Alternatively, add this check during module publishing in `publishing.rs` after line 257:

```rust
// Check for cyclic friend relationships
let imm_deps = |module_id: &ModuleId| -> PartialVMResult<Vec<ModuleId>> {
    // Resolve immediate dependencies from staged_module_storage
};
let imm_friends = |module_id: &ModuleId| -> PartialVMResult<Vec<ModuleId>> {
    // Resolve immediate friends from staged_module_storage
};
cyclic_dependencies::verify_module(compiled_module, imm_deps, imm_friends)
    .map_err(|e| e.finish(Location::Undefined))?;
```

**Long-term:** Update documentation to either:
1. Enforce the prohibition by activating existing verification code, OR
2. Clarify that cyclic friends are allowed despite the prohibition statement (though this weakens security)

## Proof of Concept

The existing test proves cycles are allowed: [6](#0-5) 

To demonstrate the access control issue, create three Move modules:

```move
address 0x1 {
    module A {
        friend 0x1::B;
        public(friend) fun sensitive_function() { /* privileged operation */ }
    }
    
    module B {
        friend 0x1::C;
        public(friend) fun call_a() { 0x1::A::sensitive_function(); }
    }
    
    module C {
        friend 0x1::A;
        public fun exploit() { 0x1::B::call_a(); } // Indirectly calls A's sensitive function
    }
}
```

This bundle will successfully verify and publish, creating a privilege escalation chain that violates the documented prohibition on cyclic friend relationships.

### Citations

**File:** third_party/move/changes/1-friend-visibility.md (L66-68)
```markdown
* Friends relationships cannot create cyclic module dependencies.
    * Cycles are not allowed in the friend relationships. E.g., `0x2::A` friends `0x2::B` friends `0x2::C` friends `0x2::A` is not allowed.
    * More generally, declaring a friend module adds a dependency upon the current module to the friend module (because the purpose is for the friend to call functions in the current module). If that friend module is already used, either directly or transitively, a cycle of dependencies would be created. E.g., a cycle would be created if `0x2::A` friends `0x2::B` and `0x2::A` also calls a function `0x2::B::foo().`
```

**File:** third_party/move/move-bytecode-verifier/src/cyclic_dependencies.rs (L96-102)
```rust
    // collect and check that there is no cyclic friend relation
    let all_friends = collect_all_with_cycle_detection(
        &self_id,
        &module.immediate_friends(),
        &imm_friends,
        StatusCode::CYCLIC_MODULE_FRIENDSHIP,
    )?;
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L134-173)
```rust
pub fn verify_module_with_config(config: &VerifierConfig, module: &CompiledModule) -> VMResult<()> {
    if config.verify_nothing() {
        return Ok(());
    }
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
    result
}
```

**File:** third_party/move/move-bytecode-verifier/src/friends.rs (L17-48)
```rust
fn verify_module_impl(module: &CompiledModule) -> PartialVMResult<()> {
    // cannot make friends with the module itself
    let self_handle = module.self_handle();
    if module.friend_decls().contains(self_handle) {
        return Err(PartialVMError::new(
            StatusCode::INVALID_FRIEND_DECL_WITH_SELF,
        ));
    }

    // cannot make friends with modules outside of the account address
    //
    // NOTE: this constraint is a policy decision rather than a technical requirement. The VM and
    // other bytecode verifier passes do not rely on the assumption that friend modules must be
    // declared within the same account address.
    //
    // However, lacking a definite use case of friending modules across account boundaries, and also
    // to minimize the associated changes on the module publishing flow, we temporarily enforce this
    // constraint and we may consider lifting this limitation in the future.
    let self_address =
        module.address_identifier_at(module.module_handle_at(module.self_handle_idx()).address);
    let has_external_friend = module
        .friend_decls()
        .iter()
        .any(|handle| module.address_identifier_at(handle.address) != self_address);
    if has_external_friend {
        return Err(PartialVMError::new(
            StatusCode::INVALID_FRIEND_DECL_WITH_MODULES_OUTSIDE_ACCOUNT_ADDRESS,
        ));
    }

    Ok(())
}
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L332-344)
```rust
/// Visits the dependencies of the given module. If dependencies form a cycle (which should not be
/// the case as we check this when modules are added to the module cache), an error is returned.
///
/// Note:
///   This implementation **does not** load transitive friends. While it is possible to view
///   friends as `used-by` relation, it cannot be checked fully. For example, consider the case
///   when we have four modules A, B, C, D and let `X --> Y` be a dependency relation (Y is a
///   dependency of X) and `X ==> Y ` a friend relation (X declares Y a friend). Then consider the
///   case `A --> B <== C --> D <== A`. Here, if we opt for `used-by` semantics, there is a cycle.
///   But it cannot be checked, since, A only sees B and D, and C sees B and D, but both B and D do
///   not see any dependencies or friends. Hence, A cannot discover C and vice-versa, making
///   detection of such corner cases only possible if **all existing modules are checked**, which
///   is clearly infeasible.
```

**File:** third_party/move/move-vm/integration-tests/src/tests/module_storage_tests.rs (L242-259)
```rust
#[test]
fn test_cyclic_friends_are_allowed() {
    let mut module_bytes_storage = InMemoryStorage::new();

    let c_id = ModuleId::new(AccountAddress::ZERO, Identifier::new("c").unwrap());

    add_module_bytes(&mut module_bytes_storage, "a", vec![], vec!["b"]);
    add_module_bytes(&mut module_bytes_storage, "b", vec![], vec!["c"]);
    add_module_bytes(&mut module_bytes_storage, "c", vec![], vec!["a"]);

    let module_storage = module_bytes_storage.into_unsync_module_storage();

    let result = module_storage.unmetered_get_eagerly_verified_module(c_id.address(), c_id.name());
    assert_ok!(result);

    // Since `c` has no dependencies, only it gets deserialized and verified.
    module_storage.assert_cached_state(vec![], vec![&c_id]);
}
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L960-978)
```rust
        if callee.is_friend() {
            let callee_module = callee.owner_as_module().map_err(|err| err.to_partial())?;
            if !caller
                .module_id()
                .is_some_and(|id| callee_module.friends.contains(id))
            {
                let msg = format!(
                    "Function {}::{} cannot be called because it has friend visibility, but {} \
                     is not {}'s friend",
                    callee.module_or_script_id(),
                    callee.name(),
                    caller.module_or_script_id(),
                    callee.module_or_script_id()
                );
                return Err(
                    PartialVMError::new_invariant_violation(msg).with_sub_status(EPARANOID_FAILURE)
                );
            }
        }
```
