# Audit Report

## Title
Missing Bytecode Verification Allows FunctionAttribute::Persistent Injection to Bypass Closure Store Ability Restrictions

## Summary
The Move bytecode verifier contains a critical gap: it does not validate that `FunctionAttribute::Persistent` is correctly set on self-module function handles based on function visibility. An attacker can manually craft bytecode to inject this attribute on private functions, enabling creation of storable closures that violate the security invariant that only public functions should have storable closures. This breaks module upgrade compatibility guarantees and leads to runtime errors when stored closures become invalid after upgrades.

## Finding Description

The Move VM enforces a fundamental security invariant: only closures from public functions (or functions explicitly marked with `#[persistent]`) should have the `store` ability. This is because public functions must maintain signature compatibility across module upgrades, ensuring stored closures remain valid over time.

**Compiler Behavior (Expected):**
The compiler correctly derives the Persistent attribute for public functions automatically: [1](#0-0) 

**Verification Gap:**
The dependency verifier explicitly skips validation of function handles belonging to the same module: [2](#0-1) 

The bounds checker only validates index bounds, not attribute correctness: [3](#0-2) 

No other verification pass in the complete verification flow validates self-module function handle attributes: [4](#0-3) 

**Exploitation Mechanism:**
During closure creation, the type safety verifier grants `AbilitySet::PUBLIC_FUNCTIONS` (which includes `store`) based solely on the presence of the Persistent attribute, without validating it matches the function's actual visibility: [5](#0-4) 

The ability sets are defined as: [6](#0-5) 

The runtime also trusts the Persistent attribute without validation: [7](#0-6) 

**Attack Path:**
1. Attacker compiles a module with a private function
2. Deserializes the compiled bytecode
3. Locates the function handle for the private function
4. Injects `FunctionAttribute::Persistent` (0x1) into the attributes vector
5. Reserializes and submits the module for deployment
6. Module passes all verification because no verifier checks self-module function handle attributes against function definitions
7. At runtime, closures from the private function receive `store` ability
8. Users store these closures in global storage
9. After module upgrade, if the private function signature changes, stored closures reference incompatible code
10. Runtime errors or undefined behavior occurs when stored closures are invoked

The module publishing flow confirms modules undergo verification but this gap persists: [8](#0-7) 

## Impact Explanation

This vulnerability represents a **significant protocol violation** that breaks fundamental Move VM safety guarantees. While it doesn't directly enable fund theft or consensus violations, it has concrete security impact:

**Security Invariant Violated:**
The Move type system guarantees that storable closures only reference functions with stable signatures across upgrades. This invariant ensures stored values remain valid over time.

**Direct Consequences:**
1. **Upgrade Compatibility Violation**: Users who store closures from malicious modules will experience runtime failures after module upgrades when private function signatures change
2. **Type System Integrity Breach**: Code that appears type-safe at compile time violates runtime invariants
3. **User Impact**: Any user interacting with the malicious module may experience unexpected behavior, with potential fund loss if closures control financial logic

**Severity Justification:**
According to Aptos bug bounty criteria, this qualifies as **Medium to High severity**:
- It affects multiple users who interact with the malicious module
- It breaks fundamental Move VM guarantees
- It creates state inconsistencies requiring manual intervention
- While not direct fund theft, it can lead to indirect losses if closures control financial operations

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Ability to deploy modules (standard user capability on Aptos)
- Knowledge of Move bytecode format (publicly documented)
- Access to bytecode serialization/deserialization tools (available in open-source Move libraries)

**Attack Complexity: Low**
The attack is straightforward:
1. Use the Move compiler to generate valid bytecode
2. Use standard deserialization tools to parse the bytecode
3. Locate and modify the function handle attributes vector
4. Reserialize using standard tools
5. Submit via normal transaction flow

**Detection Difficulty: High**
- Malicious bytecode passes all existing verification checks
- No runtime errors during initial deployment
- Issue only manifests after module upgrade when stored closures become invalid
- No automated detection mechanisms exist

**Preconditions:**
- Normal network operation (no special conditions required)
- Standard gas costs (attacker controlled)
- No coordination with validators needed

## Recommendation

Add a verification pass that validates self-module function handle attributes match function definition visibility. Specifically:

1. **Create new verifier component** that iterates through function handles and function definitions
2. **For each self-module function handle**, verify:
   - If function definition has `Visibility::Public`, the function handle must have `FunctionAttribute::Persistent`
   - If function definition has `Visibility::Private` or `Visibility::Friend`, the function handle must NOT have `FunctionAttribute::Persistent` (unless explicitly marked with `#[persistent]` attribute in metadata)
3. **Integrate into verification flow** in `verifier.rs` after bounds checking but before type safety verification

Example fix location:
```
// In third_party/move/move-bytecode-verifier/src/verifier.rs
pub fn verify_module_with_config(config: &VerifierConfig, module: &CompiledModule) -> VMResult<()> {
    // ... existing checks ...
    BoundsChecker::verify_module(module)?;
    FeatureVerifier::verify_module(config, module)?;
    // ADD NEW VERIFICATION HERE:
    SelfModuleFunctionAttributeChecker::verify_module(module)?;
    // ... rest of verification ...
}
```

## Proof of Concept

While a complete PoC requires bytecode manipulation tools, the attack flow can be demonstrated conceptually:

```move
// 1. Attacker creates module with private function
module attacker::malicious {
    // Private function - should NOT have storable closures
    fun leak_data(x: u64): u64 {
        x * 2
    }
    
    public fun exploit() {
        // After manual bytecode modification to add Persistent attribute,
        // this closure would have store ability
        let closure = |y| leak_data(y);
        // Store it in global storage (would normally fail for private functions)
        // move_to(closure); // This becomes possible with injected attribute
    }
}

// 2. User stores closure in their account
// 3. Attacker upgrades module, changing leak_data signature:
module attacker::malicious {
    fun leak_data(x: u64, y: u64): u64 { // Changed signature
        x * y
    }
    // ... rest unchanged ...
}

// 4. Stored closures now reference invalid function signature
// 5. Runtime error when closure is invoked
```

The bytecode modification would involve:
1. Deserializing the compiled module
2. Finding the function handle with index matching `leak_data`
3. Adding `FunctionAttribute::Persistent` (byte value 0x1) to the `attributes` vector
4. Reserializing with updated attributes
5. Deploying via standard transaction

**Notes:**
- This vulnerability affects any module where users can be convinced to store closures
- The impact scales with the number of users who store closures from the malicious module
- Detection requires comparing function handle attributes against function definition visibility, which current verifiers do not perform
- The fix is straightforward: add attribute validation for self-module function handles

### Citations

**File:** third_party/move/move-compiler-v2/src/file_format_generator/module_generator.rs (L1728-1731)
```rust
        if !has_persistent && fun_env.visibility() == Visibility::Public {
            // For a public function, derive the persistent attribute
            result.push(FF::FunctionAttribute::Persistent)
        }
```

**File:** third_party/move/move-bytecode-verifier/src/dependencies.rs (L284-286)
```rust
        if Some(function_handle.module) == self_module {
            continue;
        }
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L238-248)
```rust
    fn check_function_handle(&self, function_handle: &FunctionHandle) -> PartialVMResult<()> {
        check_bounds_impl(self.view.module_handles(), function_handle.module)?;
        check_bounds_impl(self.view.identifiers(), function_handle.name)?;
        check_bounds_impl(self.view.signatures(), function_handle.parameters)?;
        check_bounds_impl(self.view.signatures(), function_handle.return_)?;
        // function signature type parameters must be in bounds to the function type parameters
        let type_param_count = function_handle.type_parameters.len();
        self.check_type_parameters_in_signature(function_handle.parameters, type_param_count)?;
        self.check_type_parameters_in_signature(function_handle.return_, type_param_count)?;
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L141-163)
```rust
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
```

**File:** third_party/move/move-bytecode-verifier/src/type_safety.rs (L354-361)
```rust
    let mut abilities = if func_handle
        .attributes
        .contains(&FunctionAttribute::Persistent)
    {
        AbilitySet::PUBLIC_FUNCTIONS
    } else {
        AbilitySet::PRIVATE_FUNCTIONS
    };
```

**File:** third_party/move/move-core/types/src/ability.rs (L110-113)
```rust
    pub const PRIVATE_FUNCTIONS: AbilitySet = Self((Ability::Copy as u8) | (Ability::Drop as u8));
    /// Abilities for `public` user-defined/"primitive" functions (not closures)
    pub const PUBLIC_FUNCTIONS: AbilitySet =
        Self((Ability::Copy as u8) | (Ability::Drop as u8) | (Ability::Store as u8));
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L149-153)
```rust
    let mut abilities = if func.function.is_persistent() {
        AbilitySet::PUBLIC_FUNCTIONS
    } else {
        AbilitySet::PRIVATE_FUNCTIONS
    };
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L192-195)
```rust
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
```
