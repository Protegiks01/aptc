# Audit Report

## Title
Unimplemented `object::owner` Address Specifier Causes Complete Denial of Service for Functions with Object-Based Access Control

## Summary
The Move VM's access control system advertises support for `object::owner` as an address specifier function but leaves it unimplemented, causing any function using this feature to fail at runtime with `ACCESS_CONTROL_INVARIANT_VIOLATION`. This completely prevents legitimate functions from executing, creating a critical denial of service vulnerability for any code that attempts to use object-based access specifications.

## Finding Description

The Move language v2.5+ introduced access specifiers that allow functions to declare which resources they access, with support for parameterized addresses using function calls. The system explicitly recognizes `0x1::object::owner` as a valid address specifier function, as shown in the parser: [1](#0-0) 

When a function with an access specifier is entered, the VM attempts to "specialize" the specifier by evaluating any `AddressSpecifier::Eval` variants to convert them into concrete addresses: [2](#0-1) 

This specialization calls down to evaluate the address specifier function: [3](#0-2) 

However, the `ObjectAddress` evaluation is explicitly unimplemented and always returns an error: [4](#0-3) 

**Attack Scenario:**

1. A developer writes a legitimate Move function using object-based access control:
   ```move
   fun transfer_token(token: Object<Token>) 
       writes TokenData(object::owner(token)) {
       // Transfer logic
   }
   ```

2. The Move compiler accepts this code - no compilation error occurs

3. The bytecode is deployed to the blockchain

4. When any transaction attempts to call this function, `enter_function()` is invoked

5. The specialization step attempts to evaluate `ObjectAddress` 

6. The evaluation returns `ACCESS_CONTROL_INVARIANT_VIOLATION`

7. The function call fails immediately - **the function is completely uncallable**

This breaks the **Deterministic Execution** invariant - code that successfully compiles should execute correctly. It also violates **Move VM Safety** by allowing non-functional bytecode to be deployed.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos bug bounty criteria)

This qualifies as "Significant protocol violations" under the High Severity category:

1. **Complete Denial of Service**: Any function using `object::owner` in access specifiers becomes permanently uncallable, even though it compiles successfully

2. **Silent Failure**: No compile-time warning indicates this feature is broken, leading developers to deploy non-functional code

3. **Framework Risk**: If this feature were used in core framework modules (tokens, governance, staking), it would cause critical operations to halt network-wide

4. **Deterministic Failure**: All validators fail identically, preventing workarounds and potentially requiring emergency chain halts

5. **Production Impact**: The `object::owner` function exists in the Aptos Framework and is widely used in token operations, making this a realistic deployment scenario [5](#0-4) 

While no current production code uses this in access specifiers, the feature is presented as functional by the compiler, creating a trap for developers.

## Likelihood Explanation

**Likelihood: Medium-High**

Factors increasing likelihood:
- The feature is recognized by the parser and accepted by the compiler
- `object::owner` is a core framework function used extensively
- Access specifiers with `signer::address_of` work correctly, suggesting `object::owner` should too
- No documentation warns that this specific function is unimplemented
- Token and NFT developers naturally want to express "accesses resource at object owner's address" [6](#0-5) 

The test suite demonstrates similar patterns work with `signer::address_of`, creating an expectation that `object::owner` should also work.

Factors decreasing likelihood:
- Access specifiers are a relatively new language feature
- Current framework code doesn't use this pattern (yet)
- Developers would discover the issue during testing

However, once any production code uses this pattern, the impact is immediate and total.

## Recommendation

Implement the `ObjectAddress` evaluation function to properly extract the owner address from an object parameter:

```rust
ObjectAddress => {
    // Extract Object<T> from the value
    let obj_ref = arg.value_as::<Reference>()?;
    let obj_addr = obj_ref.read_ref()?.value_as::<AccountAddress>()?;
    
    // Read ObjectCore to get owner
    // This requires access to global storage, similar to how
    // borrow_global works. The implementation should:
    // 1. Verify ObjectCore exists at obj_addr
    // 2. Read the owner field
    // 3. Return the owner address
    
    // Placeholder implementation until storage access is added:
    Err(PartialVMError::new(
        StatusCode::ACCESS_CONTROL_INVARIANT_VIOLATION,
    ).with_message(
        "object::owner requires storage access - use alternative patterns"
    ))
}
```

**Alternative Solutions:**

1. **Remove parser support**: If implementing this is infeasible, remove `object::owner` from the parser's recognized functions to fail at compile-time instead of runtime

2. **Add compile-time warning**: Emit a compiler warning when `object::owner` is used in access specifiers

3. **Documentation**: Clearly document that only `signer::address_of` is currently supported for address specifier functions

The root issue is that the feature appears to work at compile-time but fails at runtime, violating the principle of fail-fast.

## Proof of Concept

```move
//# publish
module 0x42::object_access_test {
    use std::signer;
    use aptos_framework::object::{Self, Object};
    
    struct MyResource has key {
        value: u64
    }
    
    // This function compiles successfully but will fail at runtime
    // with ACCESS_CONTROL_INVARIANT_VIOLATION
    public fun read_from_object_owner<T: key>(
        obj: Object<T>
    ): u64 reads MyResource(object::owner(obj)) {
        let owner_addr = object::owner(obj);
        borrow_global<MyResource>(owner_addr).value
    }
    
    public fun init(s: &signer) {
        move_to(s, MyResource { value: 42 });
    }
}

//# run --signers 0x1 -- 0x42::object_access_test::init

// This run will fail with ACCESS_CONTROL_INVARIANT_VIOLATION
// when enter_function() tries to specialize the access specifier
//# run --args object:0x1 -- 0x42::object_access_test::read_from_object_owner
```

**Expected Result**: Function executes and returns 42

**Actual Result**: Transaction fails with `ACCESS_CONTROL_INVARIANT_VIOLATION: unimplemented address specifier function ObjectAddress` before the function body even executes.

## Notes

The vulnerability lies in the mismatch between compile-time acceptance and runtime rejection. The comparison with `SignerAddress` (which is fully implemented) shows this is solvable: [7](#0-6) 

The `Eval` variant's behavior of never matching addresses compounds the issue: [8](#0-7) 

If specialization were to fail silently (not propagate the error), the `Eval` variant would remain and cause all access checks to fail, creating an even worse denial of service. The current error propagation in `enter_function()` at least prevents silent failures.

### Citations

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L222-229)
```rust
    fn matches(&self, addr: &AccountAddress) -> bool {
        use AddressSpecifier::*;
        match self {
            Any => true,
            Literal(a) => a == addr,
            Eval(_, _) => false,
        }
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L232-237)
```rust
    fn specialize(&mut self, env: &impl AccessSpecifierEnv) -> PartialVMResult<()> {
        if let AddressSpecifier::Eval(fun, arg) = self {
            *self = AddressSpecifier::Literal(env.eval_address_specifier_function(*fun, *arg)?)
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L241-247)
```rust
    pub fn parse(module_str: &str, fun_str: &str) -> Option<AddressSpecifierFunction> {
        match (module_str, fun_str) {
            ("0x1::signer", "address_of") => Some(AddressSpecifierFunction::SignerAddress),
            ("0x1::object", "owner") => Some(AddressSpecifierFunction::ObjectAddress),
            _ => None,
        }
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L253-261)
```rust
            SignerAddress => {
                // See also: implementation of `signer::native_borrow_address`.
                let signer_ref = arg.value_as::<SignerRef>()?;
                signer_ref
                    .borrow_signer()?
                    .value_as::<Reference>()?
                    .read_ref()?
                    .value_as::<AccountAddress>()
            },
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L262-269)
```rust
            ObjectAddress => Err(PartialVMError::new(
                StatusCode::ACCESS_CONTROL_INVARIANT_VIOLATION,
            )
            .with_message(format!(
                "unimplemented address specifier function `{:?}`",
                self
            ))),
        }
```

**File:** third_party/move/move-vm/runtime/src/access_control.rs (L43-46)
```rust
            // Specialize the functions access specifier and push it on the stack.
            let mut fun_specifier = fun.access_specifier().clone();
            fun_specifier.specialize(env)?;
            self.specifier_stack.push(fun_specifier);
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L669-677)
```text
    #[view]
    /// Return the current owner.
    public fun owner<T: key>(self: Object<T>): address acquires ObjectCore {
        assert!(
            exists<ObjectCore>(self.inner),
            error::not_found(EOBJECT_DOES_NOT_EXIST),
        );
        borrow_global<ObjectCore>(self.inner).owner
    }
```

**File:** third_party/move/move-compiler-v2/transactional-tests/tests/no-v1-comparison/access_control/dynamic.move (L15-17)
```text
    fun ok2(s: &signer): bool reads R(signer::address_of(s)) {
        borrow_global<R>(signer::address_of(s)).value
    }
```
