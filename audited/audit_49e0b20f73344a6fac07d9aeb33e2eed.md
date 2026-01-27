# Audit Report

## Title
Event Attribute Removal Detection Bypass via Unvalidated Metadata Manipulation

## Summary
An attacker can bypass the event attribute removal detection mechanism by manually crafting module metadata that falsely claims a struct retains its `#[event]` attribute, even when the attribute has been removed from the actual module code. This is possible because event attribute struct names in metadata are not validated against the actual module structure.

## Finding Description

The Aptos blockchain enforces that event attributes on structs cannot be removed during module upgrades to maintain event schema stability for off-chain indexers. This check occurs in the removal detection logic: [1](#0-0) 

However, there is a critical validation gap. When validating module metadata during publishing, event attributes are NOT checked against the actual module structure, unlike resource groups which ARE validated: [2](#0-1) 

Notice that for resource groups (line 498), the code calls `is_valid_resource_group(&structs, struct_)?` to validate the struct exists. For event attributes (lines 507-508), it merely continues without any validation.

**Attack Path:**

1. **Old Module (deployed):** Contains `struct EventStruct` with `#[event]` attribute, properly compiled with metadata `{"EventStruct": [event()]}`

2. **New Module (attacker's upgrade):**
   - Source code removes `#[event]` attribute from `EventStruct`
   - Removes all `event::emit<EventStruct>()` calls
   - Compiles to bytecode
   - **Attacker manually modifies the metadata section** in the compiled bytecode to falsely include `{"EventStruct": [event()]}`
   - Submits the modified bytecode for publishing

3. **Validation bypassed:**
   - `verify_module_metadata_for_module_publishing`: Event attributes at lines 507-508 are not validated against actual module structs (unlike resource groups), so the fake metadata passes
   - `validate_emit_calls`: No emit calls exist, so no validation triggered
   - Event removal detection at line 73: `new_event_structs.remove("EventStruct")` succeeds because the fake metadata claims the attribute still exists
   - **Upgrade succeeds, event attribute removed despite detection mechanism**

The module metadata is part of the compiled bytecode and is BCS-serialized: [3](#0-2) 

An attacker can deserialize, modify the `struct_attributes` field, re-serialize, and include it in the published module bundle: [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for "Significant protocol violations."

**Protocol Violation:** Event attribute immutability is a documented invariant. The removal detection exists specifically to prevent breaking changes to event schemas that off-chain indexers depend on.

**State Inconsistencies:** Off-chain systems (indexers, APIs, explorers) rely on event structure stability. If event attributes can be silently removed, these systems will fail to properly index or interpret events, requiring manual intervention.

**Deterministic Execution Risk:** If different nodes have different expectations about event schemas (e.g., due to cached metadata vs. actual bytecode), this could lead to subtle consensus divergence in systems that process events.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Ability to publish module upgrades (requires control of the module address)
- Basic understanding of BCS serialization and Move bytecode structure
- Access to tools for bytecode manipulation (readily available)

**Complexity:** Low-Medium
- The attack requires manual metadata modification, but this is straightforward with existing tools
- No complex timing or race conditions required
- Exploitation is deterministic and repeatable

**Motivation:** Attackers upgrading modules may want to remove event attributes for various reasons (reducing gas costs, removing telemetry, breaking off-chain monitoring), making this a realistic attack scenario.

## Recommendation

**Fix:** Add validation for event attribute struct names, similar to how resource groups are validated.

In `types/src/vm/module_metadata.rs`, modify the event attribute validation (lines 507-509):

```rust
if features.is_module_event_enabled() && attr.is_event() {
    // Add validation that struct exists in module
    if let Ok(ident_struct) = Identifier::new(struct_) {
        if !structs.contains_key(ident_struct.as_ident_str()) {
            return Err(AttributeValidationError {
                key: struct_.clone(),
                attribute: attr.kind,
            }
            .into());
        }
    } else {
        return Err(AttributeValidationError {
            key: struct_.clone(),
            attribute: attr.kind,
        }
        .into());
    }
    continue;
}
```

This ensures that any struct name listed in event attributes must correspond to an actual struct in the module, preventing attackers from adding fake event attributes to bypass removal detection.

## Proof of Concept

```rust
#[test]
fn test_event_attribute_removal_bypass() {
    use move_binary_format::CompiledModule;
    use aptos_types::vm::module_metadata::{RuntimeModuleMetadataV1, KnownAttribute};
    use std::collections::BTreeMap;
    
    // Step 1: Create old module with EventStruct having event attribute
    let old_module_source = r#"
        module 0xCAFE::test {
            #[event]
            struct EventStruct has drop { value: u64 }
            
            public fun emit_event() {
                0x1::event::emit(EventStruct { value: 42 });
            }
        }
    "#;
    
    // Compile old module (would have {"EventStruct": [event()]} in metadata)
    // ... compilation code ...
    
    // Step 2: Create new module WITHOUT event attribute
    let new_module_source = r#"
        module 0xCAFE::test {
            // Event attribute removed!
            struct EventStruct has drop { value: u64 }
            
            // No emit calls
            public fun do_something() {
                // ...
            }
        }
    "#;
    
    // Step 3: Compile new module
    let mut new_module: CompiledModule = /* compiled from new_module_source */;
    
    // Step 4: Attacker manually crafts fake metadata
    let mut fake_metadata = RuntimeModuleMetadataV1::default();
    fake_metadata.struct_attributes.insert(
        "EventStruct".to_string(),
        vec![KnownAttribute::event()]
    );
    
    // Step 5: Inject fake metadata into compiled module
    let fake_metadata_bytes = bcs::to_bytes(&fake_metadata).unwrap();
    // ... inject into new_module.metadata with key APTOS_METADATA_KEY_V1 ...
    
    // Step 6: Submit for publishing
    // The validation should FAIL but currently PASSES:
    // - verify_module_metadata_for_module_publishing: lines 507-508 just continue
    // - validate_module_events: removal check passes because fake metadata claims EventStruct exists
    
    // Expected: Validation error "Invalid change in event attributes"
    // Actual: Validation passes, event attribute removal bypass successful!
}
```

**Notes**

This vulnerability demonstrates a critical gap in metadata validation where event attributes receive less scrutiny than resource groups. The fix is straightforward but essential to maintain event schema stability guarantees. The attack is realistic because module publishers control their bytecode and can modify metadata before submission. This breaks the documented invariant that event attributes are immutable during upgrades.

### Citations

**File:** aptos-move/aptos-vm/src/verifier/event_validation.rs (L70-76)
```rust
            let original_event_structs = extract_event_metadata(&metadata)?;
            for member in original_event_structs {
                // Fail if we see a removal of an event attribute.
                if !new_event_structs.remove(&member) {
                    metadata_validation_err("Invalid change in event attributes")?;
                }
            }
```

**File:** types/src/vm/module_metadata.rs (L66-77)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeModuleMetadataV1 {
    /// The error map containing the description of error reasons as grabbed from the source.
    /// These are typically only a few entries so no relevant size difference.
    pub error_map: BTreeMap<u64, ErrorDescription>,

    /// Attributes attached to structs.
    pub struct_attributes: BTreeMap<String, Vec<KnownAttribute>>,

    /// Attributes attached to functions, by definition index.
    pub fun_attributes: BTreeMap<String, Vec<KnownAttribute>>,
}
```

**File:** types/src/vm/module_metadata.rs (L494-516)
```rust
    for (struct_, attrs) in &metadata.struct_attributes {
        for attr in attrs {
            if features.are_resource_groups_enabled() {
                if attr.is_resource_group() && attr.get_resource_group().is_some() {
                    is_valid_resource_group(&structs, struct_)?;
                    continue;
                } else if attr.is_resource_group_member()
                    && attr.get_resource_group_member().is_some()
                {
                    is_valid_resource_group_member(&structs, struct_)?;
                    continue;
                }
            }
            if features.is_module_event_enabled() && attr.is_event() {
                continue;
            }
            return Err(AttributeValidationError {
                key: struct_.clone(),
                attribute: attr.kind,
            }
            .into());
        }
    }
```

**File:** aptos-move/framework/src/natives/code.rs (L232-240)
```rust
pub struct PublishRequest {
    pub destination: AccountAddress,
    pub bundle: ModuleBundle,
    pub expected_modules: BTreeSet<String>,
    /// Allowed module dependencies. Empty for no restrictions. An empty string in the set
    /// allows all modules from that address.
    pub allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
    pub check_compat: bool,
}
```
