# Audit Report

## Title
Stack Overflow via Unbounded Recursive Type Validation in Module Compilation

## Summary
The `check_transaction_input_type()` function in `extended_checks.rs` performs unbounded recursive validation of vector types during module compilation, allowing an attacker to cause stack overflow by publishing a Move module with deeply nested vector types (e.g., `vector<vector<vector<...>>>` with thousands of nesting levels).

## Finding Description

The vulnerability exists in the compile-time validation logic for entry function parameters. When a Move module is published, the extended checks validate that entry function parameters use allowed transaction input types. [1](#0-0) 

At lines 253-255, when a `Vector` type is encountered, the function recursively calls itself with the inner element type without any depth limit or stack overflow protection. This creates a direct recursion chain where `vector<vector<vector<...u8>>>` with N levels of nesting results in N recursive calls.

**Attack Flow:**
1. Attacker creates a Move module with an entry function like:
   ```move
   entry fun malicious(param: vector<vector<vector<...(10000 levels)...vector<u8>>>) {}
   ```

2. When the module is published, `run_extended_checks()` is invoked after bytecode verification [2](#0-1) 

3. The check reaches the malicious entry function and calls `check_transaction_input_type()` for each parameter [3](#0-2) 

4. The recursive descent through 10,000+ nested vector types exhausts the stack, crashing the validator node or compilation service

**Why Runtime is Protected but Compile-Time is Not:**

At runtime, transaction argument validation uses `TypeBuilder` which enforces `max_ty_depth = 20`: [4](#0-3) [5](#0-4) 

However, `check_transaction_input_type()` operates on `move_model::ty::Type` during compilation, NOT on runtime types, so TypeBuilder's limits don't apply. The bytecode verifier's `max_type_depth` limit defaults to `None`: [6](#0-5) 

While production config sets it to 20, this only validates bytecode signatures, not the Move model types used in extended checks.

## Impact Explanation

**Severity: HIGH**

This vulnerability allows Denial of Service attacks against validator nodes:

- **Validator Node Crashes**: Any validator attempting to validate/compile the malicious module will crash, causing temporary unavailability
- **Consensus Disruption**: If multiple validators crash simultaneously, the network could experience liveness failures or reduced block production capacity
- **Compilation Service DoS**: Affects any service that compiles Move modules (developer tools, explorers, indexers)

This meets **High Severity** criteria per Aptos bug bounty: "Validator node slowdowns" and "Significant protocol violations" (violates invariant #9: "Resource Limits - All operations must respect computational limits").

It does not reach Critical because:
- Nodes can be restarted
- Does not cause permanent state corruption
- Does not allow fund theft or consensus safety violations

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- No special permissions required (anyone can publish modules to most Aptos networks)
- Extremely simple to craft (just nest vector types deeply in source code)
- No computational cost to the attacker (the victim node does the work)
- Deterministic outcome (will always crash with sufficient nesting)

The only barrier is that some deployment environments may have restrictions on who can publish modules, but this is not the case for permissionless deployment.

## Recommendation

Add explicit depth tracking and limits to `check_transaction_input_type()`:

```rust
fn check_transaction_input_type(&self, loc: &Loc, ty: &Type) {
    self.check_transaction_input_type_with_depth(loc, ty, 0)
}

fn check_transaction_input_type_with_depth(&self, loc: &Loc, ty: &Type, depth: usize) {
    const MAX_TYPE_DEPTH: usize = 20; // Match runtime limit
    
    if depth > MAX_TYPE_DEPTH {
        self.env.error(
            loc,
            &format!(
                "type nesting depth {} exceeds maximum allowed depth of {}",
                depth, MAX_TYPE_DEPTH
            ),
        );
        return;
    }
    
    use Type::*;
    match ty {
        Primitive(_) | TypeParameter(_) => {},
        Reference(ReferenceKind::Immutable, bt)
            if matches!(bt.as_ref(), Primitive(PrimitiveType::Signer)) => {},
        Vector(ety) => {
            self.check_transaction_input_type_with_depth(loc, ety, depth + 1)
        },
        Struct(mid, sid, _) if self.is_allowed_input_struct(mid.qualified(*sid)) => {},
        _ => {
            self.env.error(
                loc,
                &format!(
                    "type `{}` is not supported as a transaction parameter type",
                    ty.display(&self.env.get_type_display_ctx())
                ),
            );
        },
    }
}
```

This ensures consistency with the runtime `max_ty_depth` limit of 20 enforced by TypeBuilder.

## Proof of Concept

Create a Move module with deeply nested vectors:

```rust
// file: malicious_module.move
module 0xCAFE::attack {
    // Generate this programmatically with ~1000+ nesting levels
    entry fun overflow(
        param: vector<vector<vector<vector<vector<
               vector<vector<vector<vector<vector<
               vector<vector<vector<vector<vector<
               // ... repeat nesting 1000+ times ...
               vector<u8>
               >>>>>>>>>>>>>>
        ) {}
}
```

Compile with:
```bash
aptos move compile --package-dir . --named-addresses 0xCAFE=0xCAFE
```

Expected result: Stack overflow crash during extended checks. Actual depth required depends on system stack size (typically 2MB = ~8000 frames on 64-bit systems).

**Notes:**
- This vulnerability only affects compile-time validation in `extended_checks.rs`
- Runtime transaction argument validation is protected by TypeBuilder's depth limits
- The fix should align compile-time limits with runtime limits (20 levels)
- Similar unbounded recursion may exist in other type validation paths and should be audited

### Citations

**File:** aptos-move/framework/src/extended_checks.rs (L87-91)
```rust
pub fn run_extended_checks(env: &GlobalEnv) -> BTreeMap<ModuleId, RuntimeModuleMetadataV1> {
    let mut checker = ExtendedChecker::new(env);
    checker.run();
    checker.output
}
```

**File:** aptos-move/framework/src/extended_checks.rs (L214-218)
```rust
    fn check_transaction_args(&self, arg_tys: &[Parameter]) {
        for Parameter(_sym, ty, param_loc) in arg_tys {
            self.check_transaction_input_type(param_loc, ty)
        }
    }
```

**File:** aptos-move/framework/src/extended_checks.rs (L242-271)
```rust
    fn check_transaction_input_type(&self, loc: &Loc, ty: &Type) {
        use Type::*;
        match ty {
            Primitive(_) | TypeParameter(_) => {
                // Any primitive type allowed, any parameter expected to instantiate with primitive
            },
            Reference(ReferenceKind::Immutable, bt)
                if matches!(bt.as_ref(), Primitive(PrimitiveType::Signer)) =>
            {
                // Immutable reference to signer allowed
            },
            Vector(ety) => {
                // Vectors are allowed if element type is allowed
                self.check_transaction_input_type(loc, ety)
            },
            Struct(mid, sid, _) if self.is_allowed_input_struct(mid.qualified(*sid)) => {
                // Specific struct types are allowed
            },
            _ => {
                // Everything else is disallowed.
                self.env.error(
                    loc,
                    &format!(
                        "type `{}` is not supported as a transaction parameter type",
                        ty.display(&self.env.get_type_display_ctx())
                    ),
                );
            },
        }
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L188-192)
```rust
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1195-1203)
```rust
    fn check(&self, count: &mut u64, depth: u64) -> PartialVMResult<()> {
        if *count >= self.max_ty_size {
            return self.too_many_nodes_error();
        }
        if depth > self.max_ty_depth {
            return self.too_large_depth_error();
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L270-270)
```rust
            max_type_depth: None,
```
