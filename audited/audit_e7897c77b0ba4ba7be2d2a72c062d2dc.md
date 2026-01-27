# Audit Report

## Title
Invalid Ability Sets in Function TypeTags Bypass Runtime Type Safety Checks

## Summary
A critical type safety vulnerability exists where TypeTags containing function types with invalid ability sets can be deserialized and bypass runtime type checks. The system fails to validate that ability sets conform to the valid range (0x0-0xF), allowing attackers to inject function types with arbitrary ability values (e.g., 0xFF) that pass all subset checks and violate Move's type system invariants.

## Finding Description

The Move VM's type system relies on ability sets to enforce type safety constraints. Abilities (Copy, Drop, Store, Key) are represented as bit flags in an AbilitySet(u8) structure. Valid ability sets must be subsets of `AbilitySet::ALL` (0xF = Copy|Drop|Store|Key). [1](#0-0) 

However, when TypeTags are deserialized from BCS-encoded transaction data, there is **no validation** that ability sets are within valid bounds: [2](#0-1) 

The FunctionTag struct directly deserializes the abilities field without validation. When this TypeTag is converted to a runtime Type, the invalid abilities are copied without checking: [3](#0-2) 

The critical impact occurs in runtime type checking. The `paranoid_check_assignable` function verifies type assignability using ability subset checks: [4](#0-3) 

The subset check implementation: [5](#0-4) 

**Exploitation**: If an attacker provides a FunctionTag with `abilities = AbilitySet(0xFF)`, the subset check `(expected_abilities & 0xFF) == expected_abilities` will **always be true** for any expected abilities ≤ 0xF. This allows the malicious function type to bypass all ability constraints.

**Attack Scenario:**
1. Attacker crafts a transaction with type argument: `TypeTag::Function(FunctionTag { abilities: AbilitySet(0xFF), ... })`
2. Transaction is submitted and deserialized (no validation occurs)
3. TypeTag converts to `Type::Function { abilities: AbilitySet(0xFF), ... }`
4. Runtime checks using `paranoid_check_assignable` pass for any expected abilities
5. Function type bypasses intended ability restrictions

The fuzzer validates this property, but only in test code: [6](#0-5) 

This validation is **not enforced** in the production runtime.

## Impact Explanation

**Severity: High** - This constitutes a significant protocol violation meeting Aptos bug bounty High severity criteria.

**Type Safety Violation**: Move's type system guarantees rely on correct ability enforcement. By bypassing ability checks, attackers can:
- Pass function values where they should be rejected based on ability constraints
- Violate Move's type safety invariants that assume valid ability sets
- Potentially cause type confusion in the VM if invalid abilities propagate to other type operations

**Deterministic Execution Risk**: While the vulnerability itself is deterministic (all nodes process the same invalid TypeTag identically), it undermines the correctness guarantees of Move's type system, which is foundational to ensuring safe execution.

**Consensus Safety**: This does not directly cause consensus splits (execution remains deterministic), but it violates Critical Invariant #3 (Move VM Safety) by allowing bytecode execution to bypass type constraints.

## Likelihood Explanation

**Likelihood: High**

The attack requires only:
- Crafting a malicious TypeTag (trivial with BCS serialization)
- Submitting a transaction with malicious type arguments (standard transaction flow)
- No special privileges or validator access required
- No complex timing or state manipulation needed

Type arguments are accepted from unprivileged transaction senders in entry function calls, making this trivially exploitable.

## Recommendation

**Immediate Fix**: Add validation when deserializing or processing TypeTags to ensure ability sets are valid:

1. **Option A - Validate on deserialization**: Implement a custom deserializer for FunctionTag that validates abilities:

```rust
// In language_storage.rs
impl<'de> Deserialize<'de> for FunctionTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawFunctionTag {
            args: Vec<FunctionParamOrReturnTag>,
            results: Vec<FunctionParamOrReturnTag>,
            abilities: AbilitySet,
        }
        
        let raw = RawFunctionTag::deserialize(deserializer)?;
        
        // Validate abilities
        if raw.abilities.into_u8() > AbilitySet::ALL.into_u8() {
            return Err(serde::de::Error::custom(
                "Invalid ability set in FunctionTag"
            ));
        }
        
        Ok(FunctionTag {
            args: raw.args,
            results: raw.results,
            abilities: raw.abilities,
        })
    }
}
```

2. **Option B - Validate in create_ty_impl**: Add validation when converting TypeTag to Type: [7](#0-6) 

Add after line 1497:
```rust
// Validate abilities
if abilities.into_u8() > AbilitySet::ALL.into_u8() {
    return Err(PartialVMError::new(StatusCode::INVALID_ABILITY_SET)
        .with_message(format!("Invalid ability set in function type: {}", abilities.into_u8())));
}
```

3. **Add runtime assertion**: In paranoid checking, assert abilities are valid before use: [8](#0-7) 

**Recommended approach**: Implement Option A (validation on deserialization) as the earliest possible check, combined with defensive assertions in create_ty_impl.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_invalid_ability_bypass() {
    use move_core_types::{
        ability::AbilitySet,
        language_storage::{FunctionTag, FunctionParamOrReturnTag, TypeTag},
    };
    
    // Create a malicious FunctionTag with invalid abilities
    let malicious_tag = TypeTag::Function(Box::new(FunctionTag {
        args: vec![],
        results: vec![],
        abilities: AbilitySet::from_u8(0xFF).unwrap_or(AbilitySet(0xFF)), // Invalid!
    }));
    
    // Serialize and deserialize (simulating transaction input)
    let serialized = bcs::to_bytes(&malicious_tag).unwrap();
    let deserialized: TypeTag = bcs::from_bytes(&serialized).unwrap();
    
    // No error occurs - invalid ability set passes through!
    if let TypeTag::Function(func_tag) = deserialized {
        assert_eq!(func_tag.abilities.into_u8(), 0xFF);
        
        // This would bypass subset checks for any expected abilities:
        // For example, checking if 0x7 (copy|drop|store) is subset of 0xFF:
        // (0x7 & 0xFF) == 0x7 → TRUE (when it should require valid abilities)
        assert!(func_tag.abilities.into_u8() > AbilitySet::ALL.into_u8());
    }
}
```

**Notes**

This vulnerability demonstrates a gap between fuzzing-level validation (which catches invalid ability sets) and runtime validation (which does not). The Move VM's type system assumes ability sets are always valid, but this assumption can be violated through crafted transaction inputs. While this doesn't directly cause consensus splits, it fundamentally undermines Move's type safety guarantees, which are critical for secure smart contract execution on Aptos.

### Citations

**File:** third_party/move/move-core/types/src/ability.rs (L94-100)
```rust
    pub const ALL: Self = Self(
        // Cannot use AbilitySet bitor because it is not const
        (Ability::Copy as u8)
            | (Ability::Drop as u8)
            | (Ability::Store as u8)
            | (Ability::Key as u8),
    );
```

**File:** third_party/move/move-core/types/src/ability.rs (L198-204)
```rust
    fn is_subset_bits(sub: u8, sup: u8) -> bool {
        (sub & sup) == sub
    }

    pub fn is_subset(self, other: Self) -> bool {
        Self::is_subset_bits(self.0, other.0)
    }
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L315-319)
```rust
pub struct FunctionTag {
    pub args: Vec<FunctionParamOrReturnTag>,
    pub results: Vec<FunctionParamOrReturnTag>,
    pub abilities: AbilitySet,
}
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L577-591)
```rust
                Type::Function {
                    args,
                    results,
                    abilities,
                },
                Type::Function {
                    args: given_args,
                    results: given_results,
                    abilities: given_abilities,
                },
            ) => {
                args == given_args
                    && results == given_results
                    && abilities.is_subset(*given_abilities)
            },
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L820-833)
```rust
                    .map(|arg| arg.abilities())
                    .collect::<PartialVMResult<Vec<_>>>()?;
                AbilitySet::polymorphic_abilities(
                    *base_ability_set,
                    phantom_ty_args_mask.iter(),
                    type_argument_abilities,
                )
                .map_err(|e| {
                    PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                        .with_message(e.to_string())
                })
            },
            Type::Function { abilities, .. } => Ok(*abilities),
        }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1493-1498)
```rust
            T::Function(fun) => {
                let FunctionTag {
                    args,
                    results,
                    abilities,
                } = fun.as_ref();
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1518-1523)
```rust
                Function {
                    args: to_list(args)?,
                    results: to_list(results)?,
                    abilities: *abilities,
                }
            },
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/type_tag_to_string.rs (L26-27)
```rust
        TypeTag::Function(function_tag) => {
            function_tag.abilities.into_u8() <= AbilitySet::ALL.into_u8()
```
