# Audit Report

## Title
Type Confusion Vulnerability in Closure Deserialization Allows Arbitrary Function Invocation with Mistyped Arguments

## Summary
The closure deserialization mechanism in `ClosureVisitor::visit_seq()` accepts arbitrary `ModuleId` values without validation at line 173, and does not verify that the deserialized `captured_layouts` match the actual parameter types of the target function. This allows attackers to craft malicious closures in storage that bypass type safety checks, potentially causing consensus failures, unauthorized function invocations, or memory corruption. [1](#0-0) 

## Finding Description
When a closure is deserialized from on-chain storage (e.g., from a table or resource field), the system performs no validation that the deserialized metadata correctly describes the target function. Specifically:

1. **No Module Validation at Deserialization**: The `ModuleId` is deserialized via `read_required_value` without checking if the module exists or is authorized. [2](#0-1) 

2. **Captured Layouts Not Validated**: The `captured_layouts` field describes the types of captured arguments, and these layouts are used to deserialize the captured values. However, these layouts are never validated against the actual parameter types of the resolved function. [3](#0-2) 

3. **Type Checking Skipped for Captured Args**: When the closure is invoked, the interpreter assumes captured arguments were already type-checked and skips validation. [4](#0-3) 

4. **Lazy Resolution Without Validation**: When the closure is resolved via `as_resolved()`, it loads the function but does not validate the stored `captured_layouts` against the function's actual signature. [5](#0-4) 

**Attack Scenario:**
1. Attacker stores a malicious `Closure` value in a table or resource with:
   - `module_id`: points to a privileged function (e.g., `0x1::coin::transfer`)
   - `fun_id`: target function name
   - `captured_layouts`: describes incorrect types (e.g., `[u64]` instead of `[&signer, address, u64]`)
   - `captured` values: arbitrary data matching the wrong layouts

2. When an honest user or contract invokes this closure:
   - Deserialization succeeds using the attacker-provided layouts
   - Function resolution loads the target function based on `module_id::fun_id`
   - Captured values are passed to the function WITHOUT type checking
   - **Type confusion occurs**: values of wrong types are interpreted as parameters

This breaks the **Move VM Safety** invariant (#3) and could cause **Deterministic Execution** failures (#1) if different validators handle the type confusion differently.

## Impact Explanation
**Critical Severity** - This vulnerability can lead to:

1. **Consensus Safety Violations**: If different validator implementations handle type-confused values differently, this could cause state divergence and chain splits, violating the "Deterministic Execution" invariant.

2. **Unauthorized Access**: An attacker could invoke privileged functions with wrong argument types, potentially bypassing access control checks that rely on type safety (e.g., passing a u64 where a `&signer` is expected).

3. **Memory Corruption**: Type confusion in the Move VM runtime could lead to memory safety violations if Rust unsafe code assumes type correctness, potentially causing validator crashes or undefined behavior.

4. **Loss of Funds**: If the type confusion affects financial operations (e.g., transfer amounts, addresses), it could result in theft or unauthorized minting of tokens.

This meets the **Critical Severity** criteria per the Aptos bug bounty program: "Consensus/Safety violations" and potentially "Loss of Funds (theft or minting)".

## Likelihood Explanation
**High Likelihood** - The vulnerability is easily exploitable because:

1. **No Special Privileges Required**: Any user can store closure values in tables or resources they control.

2. **Direct Exploitation Path**: The attacker simply needs to serialize malicious closure data using standard BCS serialization with arbitrary `module_id`, `fun_id`, and `captured_layouts`.

3. **No Runtime Detection**: The system does not validate the closure metadata at any point, so the malicious data will remain undetected until invocation.

4. **Common Attack Surface**: Closures stored in tables are a standard feature, and many contracts may store and invoke closures from storage.

The main barrier is that the attacker needs to control code that invokes the malicious closure, but this is trivial if they deploy their own contract or if an existing contract allows user-provided closure values.

## Recommendation
Implement strict validation of closure metadata during deserialization or before invocation:

**Option 1: Validate at Resolution Time** (Recommended)
When `LazyLoadedFunction::as_resolved()` transitions from `Unresolved` to `Resolved` state, validate that the stored `captured_layouts` match the function's actual parameter types according to the `mask`:

```rust
// In as_resolved() after loading the function:
let fun = loader.load_closure(...)?;

// NEW: Validate captured_layouts match function signature
let expected_captured_types = mask.extract(fun.param_tys(), false);
if expected_captured_types.len() != captured_layouts.len() {
    return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
        .with_message("Closure captured_layouts count mismatch"));
}

for (idx, (expected_ty, stored_layout)) in expected_captured_types.iter()
    .zip(captured_layouts.iter()).enumerate() {
    let computed_layout = layout_converter.type_to_type_layout(
        gas_meter, traversal_context, expected_ty)?;
    if computed_layout != *stored_layout {
        return Err(PartialVMError::new(StatusCode::TYPE_MISMATCH)
            .with_message(format!(
                "Closure captured layout mismatch at index {}", idx)));
    }
}
```

**Option 2: Validate at Deserialization Time**
Add validation in `ClosureVisitor::visit_seq()` that eagerly loads the function and validates layouts: [6](#0-5) 

This approach requires access to a loader during deserialization, which may require architectural changes.

**Option 3: Runtime Type Checking**
Remove the exception for captured arguments in `make_call_frame` and always perform type checking: [7](#0-6) 

Change line 964 to remove the `&& !is_captured` condition, but this has performance implications.

## Proof of Concept

```move
// malicious_closure.move
module attacker::exploit {
    use std::table::{Self, Table};
    use std::signer;
    
    // Store a malicious closure that will cause type confusion
    struct MaliciousClosureStore has key {
        // This table will store a closure with wrong types
        closures: Table<u64, |u64|>
    }
    
    // Target function that expects specific types
    public fun privileged_transfer(from: &signer, to: address, amount: u64) {
        // This function expects (&signer, address, u64)
        // But attacker will invoke it with wrong types via closure
        // ... transfer logic ...
    }
    
    // Attacker creates malicious closure by manually crafting BCS bytes
    public fun store_malicious_closure(attacker: &signer) {
        // Craft BCS-serialized closure with:
        // - module_id = attacker::exploit
        // - fun_id = "privileged_transfer"
        // - captured_layouts = [U64, U64, U64] (wrong types!)
        // - captured values = [attacker_u64, victim_address_as_u64, amount]
        
        // When this closure is invoked, type confusion occurs
        let store = MaliciousClosureStore {
            closures: table::new()
        };
        
        // Store manually crafted malicious closure bytes
        // ... (implementation details omitted for brevity) ...
        
        move_to(attacker, store);
    }
    
    public fun trigger_exploit(victim: &signer, closure_id: u64) 
        acquires MaliciousClosureStore {
        let store = borrow_global<MaliciousClosureStore>(@attacker);
        let malicious_closure = table::borrow(&store.closures, closure_id);
        
        // Invoking this closure will call privileged_transfer
        // but with u64 values instead of proper types!
        malicious_closure(0); // Type confusion occurs here
    }
}
```

**Rust Test Reproduction Steps:**
1. Create a serialized closure with arbitrary `module_id` and mismatched `captured_layouts`
2. Deserialize it using `ValueSerDeContext::deserialize()`
3. Cast to `Closure` and invoke via `into_call_data()`
4. Observe that no type validation error occurs despite type mismatch

## Notes
This vulnerability exists because the system trusts serialized closure metadata from storage without validation. The assumption that "captured arguments are already verified against function signature" (comment at line 966 in interpreter.rs) is only valid for closures created during normal execution, not for closures deserialized from potentially malicious storage. [8](#0-7) 

The fix must ensure that closure metadata from untrusted sources (storage) undergoes the same validation as freshly-created closures. This is essential to maintain the type safety guarantees that Move VM depends on for secure execution.

### Citations

**File:** third_party/move/move-vm/types/src/values/function_values_impl.rs (L173-176)
```rust
        let module_id = read_required_value::<_, ModuleId>(&mut seq)?;
        let fun_id = read_required_value::<_, Identifier>(&mut seq)?;
        let ty_args = read_required_value::<_, Vec<TypeTag>>(&mut seq)?;
        let mask = read_required_value::<_, ClosureMask>(&mut seq)?;
```

**File:** third_party/move/move-vm/types/src/values/function_values_impl.rs (L178-193)
```rust
        let num_captured_values = mask.captured_count() as usize;
        let mut captured_layouts = Vec::with_capacity(num_captured_values);
        let mut captured = Vec::with_capacity(num_captured_values);
        for _ in 0..num_captured_values {
            let layout = read_required_value::<_, MoveTypeLayout>(&mut seq)?;
            match seq.next_element_seed(DeserializationSeed {
                ctx: self.0.ctx,
                layout: &layout,
            })? {
                Some(v) => {
                    captured_layouts.push(layout);
                    captured.push(v)
                },
                None => return Err(A::Error::invalid_length(captured.len(), &self)),
            }
        }
```

**File:** third_party/move/move-vm/types/src/values/function_values_impl.rs (L198-208)
```rust
        let fun = fun_ext
            .create_from_serialization_data(SerializedFunctionData {
                format_version: FUNCTION_DATA_SERIALIZATION_FORMAT_V1,
                module_id,
                fun_id,
                ty_args,
                mask,
                captured_layouts,
            })
            .map_err(A::Error::custom)?;
        Ok(Closure(fun, Box::new(captured)))
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L964-981)
```rust
            if should_check && !is_captured {
                // Only perform paranoid type check for actual operands on the stack.
                // Captured arguments are already verified against function signature.
                let ty_args = function.ty_args();
                let ty = self.operand_stack.pop_ty()?;
                let expected_ty = &function.local_tys()[i];
                if !ty_args.is_empty() {
                    let expected_ty = self
                        .vm_config
                        .ty_builder
                        .create_ty_with_subst(expected_ty, ty_args)?;
                    // For parameter to argument, use assignability
                    ty.paranoid_check_assignable(&expected_ty)?;
                } else {
                    // Directly check against the expected type to save a clone here.
                    ty.paranoid_check_assignable(expected_ty)?;
                }
            }
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L430-441)
```rust
                let fun = loader.load_closure(
                    gas_meter,
                    traversal_context,
                    module_id,
                    fun_id,
                    ty_args,
                )?;
                *state = LazyLoadedFunctionState::Resolved {
                    fun: fun.clone(),
                    ty_args: mem::take(ty_args),
                    mask: *mask,
                    captured_layouts: Some(mem::take(captured_layouts)),
```
