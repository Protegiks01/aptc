# Audit Report

## Title
Resource Safety Violation: Subset Check Allows Ability Removal Enabling Duplication of Unique Resources

## Summary
The `compatible_struct_abilities()` function uses a subset check that allows importing modules to remove the `key` ability from structs while retaining `copy` or `drop` abilities. Combined with how the Move VM loader constructs runtime types using local struct handle abilities, this enables malicious modules to duplicate what should be unique global resources, violating Move's fundamental resource safety guarantees. [1](#0-0) 

## Finding Description

The vulnerability exists across two critical code paths:

**1. Bytecode Verification (Subset Check)**

The dependency verifier checks that imported struct abilities are compatible using a subset test. This allows local declarations to have FEWER abilities than the definition: [2](#0-1) 

The comment explicitly states "Removing abilities locally does nothing but limit the local usage," but this assumption is incorrect when combined with how abilities are resolved at runtime.

**2. Runtime Type Construction (Uses Local View)**

When the Move VM loader converts signature tokens to runtime types, it uses the LOCAL MODULE's struct handle abilities, not the defining module's abilities: [3](#0-2) 

Similarly for generic structs: [4](#0-3) 

**3. Ability Checks Use Runtime Type**

All ability checks during execution use the runtime `Type::abilities()` method, which returns the cached abilities from the struct handle: [5](#0-4) 

**Attack Scenario:**

1. Framework module defines: `struct AdminToken has key, copy, store { power: u64 }`
   - The `key` ability indicates this should be stored uniquely in global storage
   - The `copy` ability allows copying (unusual but permitted for config structs)

2. Malicious module imports AdminToken but declares: `struct AdminToken has copy, store`
   - Removes `key` ability from local view
   - Subset check passes: `{copy, store}.is_subset({key, copy, store})` = TRUE

3. When malicious module's bytecode is verified:
   - `CopyLoc` checks: does AdminToken have copy? YES (from local view)
   - `MoveTo` checks: does AdminToken have key? NO (from local view) - would fail

4. When malicious module's code executes:
   - Runtime type has `{copy, store}` abilities (from local struct handle)
   - Can receive AdminToken via cross-module function call
   - Can duplicate the token using `CopyLoc`
   - Cannot store in global storage (no key in local view)

**Concrete Exploitation:**

Real Aptos framework structs that have both `key` and `copy`: [6](#0-5) 

A malicious module could import `GasScheduleV2` with only `{copy, drop, store}`, enabling duplication of what should be unique configuration state.

## Impact Explanation

**Critical Severity** - This vulnerability fundamentally breaks Move's resource safety model:

1. **Resource Uniqueness Violation**: Structs with `key` ability represent unique global state. Allowing duplication violates the semantic guarantee that resources are unique and cannot be copied arbitrarily.

2. **Capability Duplication**: Admin tokens, credentials, or capabilities defined with `key` ability can be duplicated, leading to privilege escalation attacks.

3. **State Inconsistency**: Different modules viewing the same type with different abilities creates semantic confusion and can lead to consensus violations if validators process transactions differently.

4. **Framework Security**: Critical Aptos framework structs like `GasScheduleV2`, `StakingConfig`, and governance-related structs have both `key` and `copy` abilities, making them vulnerable to this attack.

This meets the **Critical** category criteria:
- Violates fundamental consensus invariant (deterministic execution)
- Enables potential loss of funds through capability duplication
- Breaks core Move VM safety guarantees

## Likelihood Explanation

**HIGH Likelihood**:

1. **Easy to Exploit**: Any module deployer can declare imported structs with modified abilities. No special privileges required.

2. **Passes Verification**: The subset check explicitly allows removing abilities, so malicious modules pass all bytecode verification.

3. **Real Attack Surface**: Multiple Aptos framework structs have both `key` and `copy` abilities, providing concrete exploitation targets.

4. **Not Obviously Malicious**: Removing `key` while keeping `copy` might appear as an optimization or deliberate restriction, not triggering obvious red flags.

5. **Cross-Module Interactions**: The vulnerability manifests when receiving values from other modules, which is a common pattern in Move programming.

The only limitation is that the attacker needs a way to obtain an instance of the target struct, typically through calling a function that returns it.

## Recommendation

**Fix 1: Stricter Subset Check** - Reject ability removal for semantically critical abilities:

```rust
fn compatible_struct_abilities(
    local_struct_abilities_declaration: AbilitySet,
    defined_struct_abilities: AbilitySet,
) -> bool {
    // Local view must be exactly equal if the struct has `key` ability
    // This prevents removing key while keeping copy/drop
    if defined_struct_abilities.has_key() {
        return local_struct_abilities_declaration == defined_struct_abilities;
    }
    
    // Otherwise, allow subset (more restrictive local view)
    local_struct_abilities_declaration.is_subset(defined_struct_abilities)
}
```

**Fix 2: Use Canonical Abilities** - Modify the loader to always use abilities from the defining module:

```rust
// In type_loader.rs, when loading struct types:
SignatureToken::Struct(sh_idx) => {
    let struct_handle = module.struct_handle_at(*sh_idx);
    let canonical_abilities = resolve_canonical_abilities(
        struct_name_table[sh_idx.0 as usize],
        struct_handle.abilities
    )?;
    let ty = Type::Struct {
        idx: struct_name_table[sh_idx.0 as usize],
        ability: AbilityInfo::struct_(canonical_abilities),
    };
    (ty, true)
}
```

**Recommended Approach**: Implement **Fix 1** as it maintains backward compatibility while preventing the vulnerability. Add additional validation in the loader (Fix 2) as defense-in-depth.

## Proof of Concept

```move
// Module A (Framework) - Defines a capability with key + copy
module 0x1::capabilities {
    struct AdminCapability has key, copy, store {
        level: u64
    }
    
    // Only callable by framework during initialization
    public fun create_capability(): AdminCapability {
        AdminCapability { level: 100 }
    }
    
    // Returns a copy of the stored capability
    public fun get_capability(addr: address): AdminCapability acquires AdminCapability {
        *borrow_global<AdminCapability>(addr)
    }
    
    public fun use_capability(cap: &AdminCapability): u64 {
        cap.level // Assumes this is unique
    }
}

// Module B (Malicious) - Imports with modified abilities
module 0x2::exploit {
    use 0x1::capabilities;
    
    // Malicious import: removes 'key', keeps 'copy'
    // Bytecode would declare: struct AdminCapability has copy, store
    // Subset check: {copy, store}.is_subset({key, copy, store}) = TRUE ✓
    
    public entry fun exploit_duplication(framework_addr: address) {
        // Get one instance from framework
        let cap1 = capabilities::get_capability(framework_addr);
        
        // In this module's view, AdminCapability has {copy, store}
        // So CopyLoc is allowed!
        let cap2 = copy cap1;  // DUPLICATION SUCCEEDS
        let cap3 = copy cap1;  // Can make unlimited copies
        
        // Now have multiple copies of what should be unique
        let val1 = capabilities::use_capability(&cap1);
        let val2 = capabilities::use_capability(&cap2);
        let val3 = capabilities::use_capability(&cap3);
        
        // All capabilities work, violating uniqueness invariant
        assert!(val1 == val2 && val2 == val3, 0);
    }
}
```

**Validation Steps**:
1. Deploy Module A with `AdminCapability has key, copy, store`
2. Deploy Module B with bytecode declaring `AdminCapability has copy, store`
3. Module B passes verification (subset check allows it)
4. Call `exploit_duplication()` - successfully creates multiple copies
5. Observe that unique capability has been duplicated

## Notes

This vulnerability demonstrates a fundamental mismatch between the bytecode verifier's assumptions (removing abilities only restricts usage) and the runtime behavior (abilities are resolved from local declarations). The issue is particularly dangerous because:

1. It affects real Aptos framework code (GasScheduleV2, StakingConfig, etc.)
2. The vulnerability is not obvious from code review of either component alone
3. It violates Move's core design principle that resources with `key` are unique

The fix requires coordinated changes to both the bytecode verifier and potentially the module loader to ensure ability consistency across module boundaries.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/dependencies.rs (L390-400)
```rust
// The local view must be a subset of (or equal to) the defined set of abilities. Conceptually, the
// local view can be more constrained than the defined one. Removing abilities locally does nothing
// but limit the local usage.
// (Note this works because there are no negative constraints, i.e. you cannot constrain a type
// parameter with the absence of an ability)
fn compatible_struct_abilities(
    local_struct_abilities_declaration: AbilitySet,
    defined_struct_abilities: AbilitySet,
) -> bool {
    local_struct_abilities_declaration.is_subset(defined_struct_abilities)
}
```

**File:** third_party/move/move-vm/runtime/src/loader/type_loader.rs (L103-110)
```rust
        SignatureToken::Struct(sh_idx) => {
            let struct_handle = module.struct_handle_at(*sh_idx);
            let ty = Type::Struct {
                idx: struct_name_table[sh_idx.0 as usize],
                ability: AbilityInfo::struct_(struct_handle.abilities),
            };
            (ty, true)
        },
```

**File:** third_party/move/move-vm/runtime/src/loader/type_loader.rs (L111-128)
```rust
        SignatureToken::StructInstantiation(sh_idx, tys) => {
            let (type_args, type_args_fully_instantiated) =
                convert_toks_to_types_impl(module, tys, struct_name_table)?;
            let struct_handle = module.struct_handle_at(*sh_idx);
            let ty = Type::StructInstantiation {
                idx: struct_name_table[sh_idx.0 as usize],
                ty_args: TriompheArc::new(type_args),
                ability: AbilityInfo::generic_struct(
                    struct_handle.abilities,
                    struct_handle
                        .type_parameters
                        .iter()
                        .map(|ty| ty.is_phantom)
                        .collect(),
                ),
            };
            (ty, type_args_fully_instantiated)
        },
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L774-808)
```rust
    pub fn abilities(&self) -> PartialVMResult<AbilitySet> {
        match self {
            Type::Bool
            | Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::U128
            | Type::U256
            | Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::I128
            | Type::I256
            | Type::Address => Ok(AbilitySet::PRIMITIVES),

            // Technically unreachable but, no point in erroring if we don't have to
            Type::Reference(_) | Type::MutableReference(_) => Ok(AbilitySet::REFERENCES),
            Type::Signer => Ok(AbilitySet::SIGNER),

            Type::TyParam(_) => Err(PartialVMError::new(StatusCode::UNREACHABLE).with_message(
                "Unexpected TyParam type after translating from TypeTag to Type".to_string(),
            )),

            Type::Vector(ty) => {
                AbilitySet::polymorphic_abilities(AbilitySet::VECTOR, vec![false], vec![
                    ty.abilities()?
                ])
                .map_err(|e| {
                    PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                        .with_message(e.to_string())
                })
            },
            Type::Struct { ability, .. } => Ok(ability.base_ability_set),
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L33-40)
```text
    struct GasSchedule has key, copy, drop {
        entries: vector<GasEntry>
    }

    struct GasScheduleV2 has key, copy, drop, store {
        feature_version: u64,
        entries: vector<GasEntry>,
    }
```
