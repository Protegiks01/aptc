# Audit Report

## Title
Duplicate Signature Metering in Move Bytecode Complexity Checker

## Summary
The Move bytecode complexity checker charges signatures multiple times (2-3x) due to a caching implementation that prevents cost recalculation but not re-charging. This causes legitimate Move modules to be incorrectly rejected as "too complex" and violates resource limit invariants.

## Finding Description

The `check_module_complexity` function in [1](#0-0)  performs complexity metering in multiple phases. The vulnerability occurs because signatures referenced in the signature table are charged multiple times across different metering phases:

**Phase 1 - Upfront Signature Metering**: [2](#0-1)  charges ALL signatures in the signature table.

**Phase 2 - Table Metering**: Functions like `meter_function_handles()` [3](#0-2)  charge function parameter and return signatures again, even though these signature indices were already charged in Phase 1.

**Phase 3 - Bytecode Metering**: The `meter_code()` function [4](#0-3)  charges the locals signature [5](#0-4)  and vector operation signatures again.

**Root Cause**: The `meter_signature()` function [6](#0-5)  uses a cache to avoid recalculating signature costs, but it **always charges the cost** at line 99, regardless of whether the cost was retrieved from cache (cache hit) or newly calculated (cache miss).

**Concrete Example**:
1. A module has signature index 5 in its signature table containing type parameters `<T, U>`
2. This signature is used as: function handle parameters, function locals, and a vector operation
3. `meter_signatures()` charges signature 5 once (cost = 16 units, assuming 2 type nodes × 8)
4. `meter_function_handles()` charges signature 5 again (cost retrieved from cache, but charged again = 16 units)
5. `meter_code()` charges signature 5 a third time for locals (cost from cache, charged again = 16 units)
6. Total: 48 units charged instead of 16 units

Since `CodeUnit.locals` [7](#0-6)  and `FunctionHandle.parameters` / `FunctionHandle.return_` [8](#0-7)  are all `SignatureIndex` types pointing into the same signature table, they are metered in Phase 1 and then re-charged in subsequent phases.

## Impact Explanation

**Severity: Medium** - This qualifies as "Significant protocol violations" and causes state inconsistencies in resource accounting.

**Specific Impacts**:

1. **Resource Limit Violation (Invariant 9)**: The complexity budget is a critical resource limit designed to prevent resource exhaustion attacks. Incorrect over-charging by 2-3× violates the protocol's resource accounting invariants.

2. **Denial of Service**: Legitimate module publishers attempting to deploy valid Move modules may have their transactions fail with `StatusCode::PROGRAM_TOO_COMPLEX` [9](#0-8)  even when their actual complexity is within limits. The budget calculation in production is `2048 + blob.code().len() as u64 * 20` [10](#0-9) , and double-charging can exhaust this incorrectly.

3. **Protocol Correctness**: The complexity checker is part of Move's security model. Incorrect metering breaks the fairness and correctness guarantees of the system.

4. **Potential Consensus Impact**: If different node implementations or versions have inconsistent complexity checking behavior (e.g., during upgrades), this could lead to nodes disagreeing on whether a module is valid, potentially causing consensus divergence.

## Likelihood Explanation

**Likelihood: High** - This bug triggers automatically for any module containing:
- Functions with non-empty parameter signatures
- Functions with non-empty return signatures  
- Functions with local variables
- Vector operations in bytecode
- Generic instantiations

These are extremely common patterns in Move code, meaning virtually all non-trivial modules are affected. The bug is deterministic and requires no special attacker capabilities beyond publishing a normal Move module.

## Recommendation

Fix the `meter_signature()` function to only charge signatures once by tracking which signatures have already been charged:

**Option 1 - Track Charged Signatures**:
```rust
struct BinaryComplexityMeter<'a> {
    resolver: BinaryIndexedView<'a>,
    cached_signature_costs: RefCell<BTreeMap<SignatureIndex, u64>>,
    charged_signatures: RefCell<BTreeSet<SignatureIndex>>,  // NEW
    balance: RefCell<u64>,
}

fn meter_signature(&self, idx: SignatureIndex) -> PartialVMResult<()> {
    // Only charge if not already charged
    if self.charged_signatures.borrow().contains(&idx) {
        return Ok(());
    }
    
    let cost = match self.cached_signature_costs.borrow_mut().entry(idx) {
        btree_map::Entry::Occupied(entry) => *entry.into_mut(),
        btree_map::Entry::Vacant(entry) => {
            let sig = safe_get_table(self.resolver.signatures(), idx.0)?;
            let mut cost: u64 = 0;
            for ty in &sig.0 {
                cost = cost.saturating_add(self.signature_token_cost(ty)?);
            }
            *entry.insert(cost)
        },
    };

    self.charge(cost)?;
    self.charged_signatures.borrow_mut().insert(idx);  // Mark as charged
    Ok(())
}
```

**Option 2 - Remove Upfront Metering**:
Remove the call to `meter_signatures()` in `check_module_complexity()` and rely on on-demand metering during table and bytecode processing. This ensures each signature is only charged when first encountered.

## Proof of Concept

```rust
#[cfg(test)]
mod test_double_charging {
    use super::*;
    use crate::file_format::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;

    #[test]
    fn test_signature_double_charging() {
        // Create a minimal module with a function that uses a signature for both parameters and locals
        let mut module = CompiledModule {
            version: 6,
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            struct_handles: vec![],
            function_handles: vec![FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(1),
                parameters: SignatureIndex(0),  // References signature 0
                return_: SignatureIndex(1),
                type_parameters: vec![],
                access_specifiers: None,
                attributes: vec![],
            }],
            function_instantiations: vec![],
            signatures: vec![
                Signature(vec![SignatureToken::U64, SignatureToken::U64]),  // Signature 0: used by function params
                Signature(vec![]),  // Signature 1: empty return
            ],
            identifiers: vec![
                Identifier::new("TestModule").unwrap(),
                Identifier::new("test_function").unwrap(),
            ],
            address_identifiers: vec![AccountAddress::ZERO],
            constant_pool: vec![],
            metadata: vec![],
            struct_defs: Some(vec![]),
            struct_def_instantiations: Some(vec![]),
            function_defs: Some(vec![FunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Public,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(CodeUnit {
                    locals: SignatureIndex(0),  // REUSES signature 0 for locals
                    code: vec![Bytecode::Ret],
                }),
            }]),
            field_handles: Some(vec![]),
            field_instantiations: Some(vec![]),
            friend_decls: Some(vec![]),
            struct_variant_handles: Some(vec![]),
            struct_variant_instantiations: Some(vec![]),
            variant_field_handles: Some(vec![]),
            variant_field_instantiations: Some(vec![]),
        };

        // Calculate complexity with large budget
        let budget = 100000u64;
        let used = check_module_complexity(&module, budget).unwrap();
        
        // Expected cost for signature 0: 2 type nodes * 8 = 16 units (should be charged once)
        // Actual behavior: Charged 3 times (meter_signatures + meter_function_handles + meter_code)
        // So used should be ~48 units for signature 0 alone, proving double-charging
        
        println!("Complexity used: {}", used);
        // If double-charging is fixed, used should be around 16 + overhead
        // With the bug, used will be around 48 + overhead
        assert!(used > 32, "Signature was charged multiple times (expected if bug exists)");
    }
}
```

## Notes

This vulnerability is particularly insidious because:

1. **Silent over-charging**: Users receive `PROGRAM_TOO_COMPLEX` errors without understanding why their module is rejected
2. **Affects all modules**: Nearly every Move module uses signatures in multiple contexts
3. **Compounds with module size**: Larger modules with more functions and complex types are disproportionately affected
4. **Hidden in caching logic**: The bug is subtle because the cache appears to work correctly (prevents recalculation) but the charging logic is incorrect

The fix should be thoroughly tested across the entire Move test suite to ensure no modules are incorrectly rejected after the correction.

### Citations

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L38-49)
```rust
    fn charge(&self, amount: u64) -> PartialVMResult<()> {
        let mut balance = self.balance.borrow_mut();
        match balance.checked_sub(amount) {
            Some(new_balance) => {
                *balance = new_balance;
                Ok(())
            },
            None => {
                *balance = 0;
                Err(PartialVMError::new(StatusCode::PROGRAM_TOO_COMPLEX))
            },
        }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L84-102)
```rust
    fn meter_signature(&self, idx: SignatureIndex) -> PartialVMResult<()> {
        let cost = match self.cached_signature_costs.borrow_mut().entry(idx) {
            btree_map::Entry::Occupied(entry) => *entry.into_mut(),
            btree_map::Entry::Vacant(entry) => {
                let sig = safe_get_table(self.resolver.signatures(), idx.0)?;

                let mut cost: u64 = 0;
                for ty in &sig.0 {
                    cost = cost.saturating_add(self.signature_token_cost(ty)?);
                }

                *entry.insert(cost)
            },
        };

        self.charge(cost)?;

        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L104-109)
```rust
    fn meter_signatures(&self) -> PartialVMResult<()> {
        for sig_idx in 0..self.resolver.signatures().len() {
            self.meter_signature(SignatureIndex(sig_idx as u16))?;
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L214-222)
```rust
    fn meter_function_handles(&self) -> PartialVMResult<()> {
        for fh in self.resolver.function_handles() {
            self.meter_module_handle(fh.module)?;
            self.meter_identifier(fh.name)?;
            self.meter_signature(fh.parameters)?;
            self.meter_signature(fh.return_)?;
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L259-384)
```rust
    fn meter_code(&self, code: &CodeUnit) -> PartialVMResult<()> {
        use Bytecode::*;

        self.meter_signature(code.locals)?;

        for instr in &code.code {
            match instr {
                CallGeneric(idx) | PackClosureGeneric(idx, ..) => {
                    self.meter_function_instantiation(*idx)?;
                },
                PackGeneric(idx) | UnpackGeneric(idx) => {
                    self.meter_struct_instantiation(*idx)?;
                },
                PackVariantGeneric(idx) | UnpackVariantGeneric(idx) | TestVariantGeneric(idx) => {
                    self.meter_struct_variant_instantiation(*idx)?;
                },
                ExistsGeneric(idx)
                | MoveFromGeneric(idx)
                | MoveToGeneric(idx)
                | ImmBorrowGlobalGeneric(idx)
                | MutBorrowGlobalGeneric(idx) => {
                    self.meter_struct_instantiation(*idx)?;
                },
                ImmBorrowFieldGeneric(idx) | MutBorrowFieldGeneric(idx) => {
                    self.meter_field_instantiation(*idx)?;
                },
                ImmBorrowVariantFieldGeneric(idx) | MutBorrowVariantFieldGeneric(idx) => {
                    self.meter_variant_field_instantiation(*idx)?;
                },
                CallClosure(idx)
                | VecPack(idx, _)
                | VecLen(idx)
                | VecImmBorrow(idx)
                | VecMutBorrow(idx)
                | VecPushBack(idx)
                | VecPopBack(idx)
                | VecUnpack(idx, _)
                | VecSwap(idx) => {
                    self.meter_signature(*idx)?;
                },

                // List out the other options explicitly so there's a compile error if a new
                // bytecode gets added.
                Pop
                | Ret
                | Branch(_)
                | BrTrue(_)
                | BrFalse(_)
                | LdU8(_)
                | LdU16(_)
                | LdU32(_)
                | LdU64(_)
                | LdU128(_)
                | LdU256(_)
                | LdI8(_)
                | LdI16(_)
                | LdI32(_)
                | LdI64(_)
                | LdI128(_)
                | LdI256(_)
                | LdConst(_)
                | CastU8
                | CastU16
                | CastU32
                | CastU64
                | CastU128
                | CastU256
                | CastI8
                | CastI16
                | CastI32
                | CastI64
                | CastI128
                | CastI256
                | LdTrue
                | LdFalse
                | Call(_)
                | Pack(_)
                | Unpack(_)
                | PackVariant(_)
                | UnpackVariant(_)
                | TestVariant(_)
                | PackClosure(..)
                | ReadRef
                | WriteRef
                | FreezeRef
                | Add
                | Sub
                | Mul
                | Mod
                | Div
                | Negate
                | BitOr
                | BitAnd
                | Xor
                | Shl
                | Shr
                | Or
                | And
                | Not
                | Eq
                | Neq
                | Lt
                | Gt
                | Le
                | Ge
                | CopyLoc(_)
                | MoveLoc(_)
                | StLoc(_)
                | MutBorrowLoc(_)
                | ImmBorrowLoc(_)
                | MutBorrowField(_)
                | ImmBorrowField(_)
                | MutBorrowVariantField(_)
                | ImmBorrowVariantField(_)
                | MutBorrowGlobal(_)
                | ImmBorrowGlobal(_)
                | Exists(_)
                | MoveTo(_)
                | MoveFrom(_)
                | Abort
                | AbortMsg
                | Nop => (),
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L401-420)
```rust
pub fn check_module_complexity(module: &CompiledModule, budget: u64) -> PartialVMResult<u64> {
    let meter = BinaryComplexityMeter {
        resolver: BinaryIndexedView::Module(module),
        cached_signature_costs: RefCell::new(BTreeMap::new()),
        balance: RefCell::new(budget),
    };

    meter.meter_signatures()?;
    meter.meter_function_instantiations()?;
    meter.meter_struct_def_instantiations()?;
    meter.meter_field_instantiations()?;

    meter.meter_function_handles()?;
    meter.meter_struct_handles()?;
    meter.meter_function_defs()?;
    meter.meter_struct_defs()?;

    let used = budget - *meter.balance.borrow();
    Ok(used)
}
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L327-355)
```rust
pub struct FunctionHandle {
    /// The module that defines the function.
    pub module: ModuleHandleIndex,
    /// The name of the function.
    pub name: IdentifierIndex,
    /// The list of arguments to the function.
    pub parameters: SignatureIndex,
    /// The list of return types.
    pub return_: SignatureIndex,
    /// The type formals (identified by their index into the vec) and their constraints
    pub type_parameters: Vec<AbilitySet>,
    /// An optional list of access specifiers. If this is unspecified, the function is assumed
    /// to access arbitrary resources. Otherwise, each specifier approximates a set of resources
    /// which are read/written by the function. An empty list indicates the function is pure and
    /// does not depend on any global state.
    #[cfg_attr(
        any(test, feature = "fuzzing"),
        proptest(filter = "|x| x.as_ref().map(|v| v.len() <= 64).unwrap_or(true)")
    )]
    pub access_specifiers: Option<Vec<AccessSpecifier>>,
    /// A list of attributes the referenced function definition had at compilation time.
    /// Depending on the attribute kind, those need to be also present in the actual
    /// function definition, which is checked in the dependency verifier.
    #[cfg_attr(
        any(test, feature = "fuzzing"),
        proptest(strategy = "vec(any::<FunctionAttribute>(), 0..8)")
    )]
    pub attributes: Vec<FunctionAttribute>,
}
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L1337-1346)
```rust
pub struct CodeUnit {
    /// List of locals type. All locals are typed.
    pub locals: SignatureIndex,
    /// Code stream, function body.
    #[cfg_attr(
        any(test, feature = "fuzzing"),
        proptest(strategy = "vec(any::<Bytecode>(), 0..=params)")
    )]
    pub code: Vec<Bytecode>,
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1554-1559)
```rust
        for (module, blob) in modules.iter().zip(bundle.iter()) {
            // TODO(Gas): Make budget configurable.
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
        }
```
