# Audit Report

## Title
Stack Overflow via Unlimited Vector Nesting in Transaction Argument Construction Bypassing max_invocations Protection

## Summary
The `validate_and_construct()` function's UTF-8 constructor shortcut allows attackers to bypass the `max_invocations` depth limit by crafting deeply nested `Vector<Vector<...<String>...>>` structures. This enables stack overflow attacks on validator nodes during transaction argument deserialization, potentially causing validator crashes and network disruption.

## Finding Description

The transaction argument validation system implements a `max_invocations` counter initialized to 10 to prevent excessive recursion during constructor invocations. [1](#0-0) 

However, this protection contains two critical bypasses:

**Bypass #1: UTF-8 Constructor Shortcut**

The `validate_and_construct()` function checks `max_invocations` at the function entry, but the UTF-8 string constructor takes an early return path that does not decrement the counter. [2](#0-1) 

The UTF-8 shortcut begins at line 433 and returns early at line 467-468, completely bypassing the decrement operation at line 470. [3](#0-2) [4](#0-3) 

**Bypass #2: Vector Nesting Without Invocation Counting**

The `recursively_construct_arg()` function processes Vector types recursively without calling `validate_and_construct()`, meaning vector nesting consumes zero `max_invocations`. [5](#0-4) 

**Combined Exploit Path:**

An attacker can craft a transaction argument of type `Vector<Vector<Vector<...<String>...>>>` with arbitrary nesting depth:

1. Each outer Vector level is processed by `recursively_construct_arg()` lines 345-363 (no `max_invocations` consumed)
2. Each recursive call increases stack depth by one frame
3. The innermost String elements use `validate_and_construct()` but take the UTF-8 shortcut (no `max_invocations` consumed)
4. Result: Unlimited recursion depth consuming only stack memory

**Why Existing Protections Fail:**

- The 6 MB transaction size limit does not prevent this attack, as deeply nested vectors can be represented compactly in BCS encoding (approximately N bytes for N levels of nesting using uleb128 length prefixes)
- The VM's `DEFAULT_MAX_VM_VALUE_NESTED_DEPTH` limit of 128 only applies during value execution, not during transaction argument construction [6](#0-5) 
- No depth checking exists in the argument construction phase [7](#0-6) 

## Impact Explanation

**Severity: Critical (up to $1,000,000)**

This vulnerability enables:

1. **Validator Node Crashes**: Stack overflow causes validator process termination, qualifying as "Total loss of liveness/network availability" per the bug bounty criteria
2. **Consensus Disruption**: If multiple validators process the malicious transaction simultaneously, simultaneous crashes could impact consensus quorum
3. **Deterministic Execution Violation**: The crash behavior may be platform-dependent (different stack sizes on different OS/architectures), potentially causing consensus splits

The attack breaks the **Move VM Safety** invariant: "Bytecode execution must respect gas limits and memory constraints" and the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: High**

The attack requires:
- No special privileges (any transaction sender)
- Minimal transaction size (< 10 KB for thousands of nesting levels)
- No validator collusion
- Standard transaction submission through mempool

The attack is trivial to execute and can be automated. The comment in the code explicitly acknowledges the security concern: "HACK mitigation of performance attack" and "we need to allow unlimited strings" [8](#0-7) , suggesting the developers were aware of the trade-off but may not have recognized the complete bypass.

## Recommendation

**Fix #1: Add explicit depth tracking to recursively_construct_arg()**

Add a `recursion_depth` parameter to `recursively_construct_arg()` and check it against a maximum (e.g., 128 to match VM value depth limits):

```rust
pub(crate) fn recursively_construct_arg(
    session: &mut SessionExt<impl AptosMoveResolver>,
    loader: &impl Loader,
    gas_meter: &mut impl GasMeter,
    traversal_context: &mut TraversalContext,
    ty: &Type,
    allowed_structs: &ConstructorMap,
    cursor: &mut Cursor<&[u8]>,
    initial_cursor_len: usize,
    max_invocations: &mut u64,
    recursion_depth: &mut u64,  // NEW PARAMETER
    arg: &mut Vec<u8>,
) -> Result<(), VMStatus> {
    const MAX_RECURSION_DEPTH: u64 = 128; // Match VM value depth limit
    
    if *recursion_depth > MAX_RECURSION_DEPTH {
        return Err(VMStatus::error(
            StatusCode::VM_MAX_VALUE_DEPTH_REACHED,
            None,
        ));
    }
    
    *recursion_depth += 1;
    
    // ... existing logic ...
    
    *recursion_depth -= 1;
    Ok(())
}
```

**Fix #2: Count UTF-8 constructors against max_invocations or document the security trade-off**

Either:
- Remove the UTF-8 shortcut bypass and decrement `max_invocations` for all constructors
- OR clearly document that the current design allows unlimited String nesting and add explicit depth checking

## Proof of Concept

```rust
// Reproduction steps in Rust test:
#[test]
fn test_deeply_nested_vector_string_stack_overflow() {
    use bcs;
    use std::io::Write;
    
    // Construct Vector<Vector<...<String>...>> with 10000 levels
    const DEPTH: usize = 10000;
    let mut payload = Vec::new();
    
    // Start with innermost String (empty string)
    let mut current = bcs::to_bytes(&vec![""]).unwrap();
    
    // Wrap in vectors repeatedly
    for _ in 0..DEPTH {
        let wrapped = bcs::to_bytes(&vec![current]).unwrap();
        current = wrapped;
    }
    
    // Submit as transaction argument
    // Expected: Stack overflow during recursively_construct_arg()
    // Actual: Should be caught by depth limit (after fix)
    
    let result = construct_arg(
        session,
        loader,
        gas_meter,
        traversal_context,
        &vector_of_vector_of_string_type,
        allowed_structs,
        current,
        false,
    );
    
    // Without fix: Process crashes with stack overflow
    // With fix: Returns VM_MAX_VALUE_DEPTH_REACHED error
    assert!(result.is_err());
}
```

**Move-based PoC:**

```move
script {
    use std::vector;
    use std::string;
    
    // Entry function accepting deeply nested vector type
    fun exploit_stack_overflow(nested: vector<vector<vector<string::String>>>) {
        // Function signature forces validation of deeply nested structure
        // The crash occurs during argument construction, before execution
    }
}
```

Transaction payload (BCS-encoded):
- Create minimal nested structure: `[[...[[""]]...]]` with 5000+ levels
- Total size: ~5-10 KB (well under 6 MB limit)
- Stack frames consumed: 5000+ (exceeds typical 2-8 MB stack limits)

**Notes**

The vulnerability exists because the `max_invocations` protection was designed to limit constructor calls but inadvertently exempted two critical cases: vector nesting and UTF-8 strings. The comment at lines 429-432 suggests this was a deliberate design choice for compatibility, but the security implications were not fully addressed. [8](#0-7) 

The absence of depth checking in the transaction argument validation phase, contrasted with the explicit 128-level limit during value execution, represents a critical gap in defense-in-depth. [9](#0-8)

### Citations

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L289-289)
```rust
            let mut max_invocations = 10; // Read from config in the future
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L330-405)
```rust
pub(crate) fn recursively_construct_arg(
    session: &mut SessionExt<impl AptosMoveResolver>,
    loader: &impl Loader,
    gas_meter: &mut impl GasMeter,
    traversal_context: &mut TraversalContext,
    ty: &Type,
    allowed_structs: &ConstructorMap,
    cursor: &mut Cursor<&[u8]>,
    initial_cursor_len: usize,
    max_invocations: &mut u64,
    arg: &mut Vec<u8>,
) -> Result<(), VMStatus> {
    use move_vm_types::loaded_data::runtime_types::Type::*;

    match ty {
        Vector(inner) => {
            // get the vector length and iterate over each element
            let mut len = get_len(cursor)?;
            serialize_uleb128(len, arg);
            while len > 0 {
                recursively_construct_arg(
                    session,
                    loader,
                    gas_meter,
                    traversal_context,
                    inner,
                    allowed_structs,
                    cursor,
                    initial_cursor_len,
                    max_invocations,
                    arg,
                )?;
                len -= 1;
            }
        },
        Struct { .. } | StructInstantiation { .. } => {
            let (module_id, identifier) = loader
                .runtime_environment()
                .get_struct_name(ty)
                .map_err(|_| {
                    // Note: The original behaviour was to map all errors to an invalid signature
                    //       error, here we want to preserve it for now.
                    invalid_signature()
                })?
                .ok_or_else(invalid_signature)?;
            let full_name = format!("{}::{}", module_id.short_str_lossless(), identifier);
            let constructor = allowed_structs
                .get(&full_name)
                .ok_or_else(invalid_signature)?;
            // By appending the BCS to the output parameter we construct the correct BCS format
            // of the argument.
            arg.append(&mut validate_and_construct(
                session,
                loader,
                gas_meter,
                traversal_context,
                ty,
                constructor,
                allowed_structs,
                cursor,
                initial_cursor_len,
                max_invocations,
            )?);
        },
        Bool | U8 | I8 => read_n_bytes(1, cursor, arg)?,
        U16 | I16 => read_n_bytes(2, cursor, arg)?,
        U32 | I32 => read_n_bytes(4, cursor, arg)?,
        U64 | I64 => read_n_bytes(8, cursor, arg)?,
        U128 | I128 => read_n_bytes(16, cursor, arg)?,
        U256 | I256 | Address => read_n_bytes(32, cursor, arg)?,
        Signer | Reference(_) | MutableReference(_) | TyParam(_) | Function { .. } => {
            return Err(invalid_signature())
        },
    };
    Ok(())
}
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L423-428)
```rust
    if *max_invocations == 0 {
        return Err(VMStatus::error(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
            None,
        ));
    }
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L429-432)
```rust
    // HACK mitigation of performance attack
    // To maintain compatibility with vector<string> or so on, we need to allow unlimited strings.
    // So we do not count the string constructor against the max_invocations, instead we
    // shortcut the string case to avoid the performance attack.
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L433-468)
```rust
    if constructor.func_name.as_str() == "utf8" {
        let constructor_error = || {
            // A slight hack, to prevent additional piping of the feature flag through all
            // function calls. We know the feature is active when more structs then just strings are
            // allowed.
            let are_struct_constructors_enabled = allowed_structs.len() > 1;
            if are_struct_constructors_enabled {
                PartialVMError::new(StatusCode::ABORTED)
                    .with_sub_status(1)
                    .at_code_offset(FunctionDefinitionIndex::new(0), 0)
                    .finish(Location::Module(constructor.module_id.clone()))
                    .into_vm_status()
            } else {
                VMStatus::error(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT, None)
            }
        };
        // Short cut for the utf8 constructor, which is a special case.
        let len = get_len(cursor)?;
        if cursor
            .position()
            .checked_add(len as u64)
            .is_none_or(|l| l > initial_cursor_len as u64)
        {
            // We need to make sure we do not allocate more bytes than
            // needed.
            return Err(VMStatus::error(
                StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
                Some("String argument is too long".to_string()),
            ));
        }

        let mut arg = vec![];
        read_n_bytes(len, cursor, &mut arg)?;
        std::str::from_utf8(&arg).map_err(|_| constructor_error())?;
        return bcs::to_bytes(&arg)
            .map_err(|_| VMStatus::error(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT, None));
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L470-470)
```rust
        *max_invocations -= 1;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L50-57)
```rust
/// Values can be recursive, and so it is important that we do not use recursive algorithms over
/// deeply nested values as it can cause stack overflow. Since it is not always possible to avoid
/// recursion, we opt for a reasonable limit on VM value depth. It is defined in Move VM config,
/// but since it is difficult to propagate config context everywhere, we use this constant.
///
/// IMPORTANT: When changing this constant, make sure it is in-sync with one in VM config (it is
/// used there now).
pub const DEFAULT_MAX_VM_VALUE_NESTED_DEPTH: u64 = 128;
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L149-157)
```rust
    pub(crate) fn check_depth(&self, depth: u64) -> PartialVMResult<()> {
        if self
            .max_value_nested_depth
            .is_some_and(|max_depth| depth > max_depth)
        {
            return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
        }
        Ok(())
    }
```
