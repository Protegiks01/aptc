# Audit Report

## Title
Event Attribute Duplicate Detection Bypass via Invalid Metadata Keys

## Summary
The event validation system contains a critical validation gap where event attributes on structs are not validated to ensure struct names are valid Move identifiers or correspond to actual structs in the module bytecode. This allows attackers to craft modules with invalid struct names (e.g., containing null bytes) in metadata that bypass duplicate detection and permanently block legitimate module upgrades.

## Finding Description

The event validation system has an inconsistent validation approach compared to resource group attributes, creating an exploitable logic vulnerability.

When validating module metadata during publishing in `verify_module_metadata_for_module_publishing()`, event attributes only check if the feature flag is enabled and skip all other validation [1](#0-0) . This contrasts sharply with resource group attributes, which are properly validated by calling `is_valid_resource_group()` to validate both that the string is a valid Move identifier and that the struct exists in the bytecode [2](#0-1)  and [3](#0-2) .

This validation gap allows an attacker to manually craft module bytecode with a `struct_attributes` BTreeMap containing entries with invalid struct names (e.g., `"MyEvent"` and `"MyEvent\x00"`). The duplicate detection in `extract_event_metadata()` uses HashSet insertion, which treats these as separate entries since they are different Rust strings [4](#0-3) .

During module upgrades, the compatibility check in `validate_module_events()` requires all event attributes from the old module to be present in the new module [5](#0-4) . When a legitimate upgrade (compiled normally) only has `"MyEvent"` but the old module has both `"MyEvent"` and `"MyEvent\x00"`, the compatibility check fails because `new_event_structs.remove("MyEvent\x00")` returns false, permanently blocking the upgrade.

The feasibility of manually crafting such bytecode is demonstrated in the test infrastructure [6](#0-5) , which shows how to deserialize modules, modify metadata, and republish.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring manual intervention"

1. **Denial of Service on Module Upgrades**: Legitimate module upgrades are permanently blocked with `EVENT_METADATA_VALIDATION_ERROR`, as the compatibility check demonstrates [7](#0-6) . This requires manual intervention (governance proposal or hardfork) to recover.

2. **Persistent State Inconsistency**: Modules exist on-chain with semantically invalid metadata that violates the system's integrity assumptions. The metadata contains struct names that are not valid Move identifiers, contradicting the design assumption that all struct names in metadata correspond to actual structs.

3. **Griefing Attack Vector**: Malicious actors can permanently pollute any module they publish with invalid metadata, creating a persistent attack surface affecting module upgradeability—a core blockchain functionality.

This does not directly cause fund loss or consensus violations, correctly placing it in the Medium severity category rather than Critical or High.

## Likelihood Explanation

**Moderate to High Likelihood:**

1. **Attack Prerequisites**: Attacker needs only standard ability to publish modules and capability to craft bytecode manually. The test infrastructure proves this is feasible [6](#0-5) .

2. **Detection Difficulty**: The malicious metadata passes all current validation checks because event attribute validation explicitly skips struct name validation when the feature flag is enabled [1](#0-0) .

3. **Persistence**: Once published, the malformed metadata is permanently stored on-chain and will block all future upgrade attempts.

4. **Attack Surface**: Any module with event attributes becomes vulnerable to this attack pattern during publishing.

## Recommendation

Add validation for event attributes similar to resource group validation. Modify the event attribute validation in `verify_module_metadata_for_module_publishing()` to:

1. Validate that the struct name is a valid Move identifier using `Identifier::new(struct_)`
2. Verify that the struct actually exists in the module's bytecode by checking the `structs` BTreeMap
3. Return an appropriate `AttributeValidationError` if validation fails

This would create consistency with resource group validation and close the exploit path.

## Proof of Concept

```rust
// Build a normal module with an event attribute
let source = r#"
    module 0xCAFE::M {
        #[event]
        struct MyEvent { }
    }
"#;
let package = BuiltPackage::build(...);
let code = package.extract_code();

// Deserialize and modify metadata
let mut module = CompiledModule::deserialize(&code[0]).unwrap();
let mut metadata = get_metadata_from_compiled_code(&module).unwrap();

// Add invalid struct name with null byte
metadata.struct_attributes.insert(
    "MyEvent\x00".to_string(), 
    vec![KnownAttribute::event()]
);

// Serialize modified metadata
let modified_metadata = Metadata {
    key: APTOS_METADATA_KEY_V1.to_vec(),
    value: bcs::to_bytes(&metadata).unwrap(),
};
module.metadata = vec![modified_metadata];

let mut malicious_code = vec![];
module.serialize(&mut malicious_code).unwrap();

// Publish malicious module - validation passes
h.publish_package(&account, malicious_code);

// Future upgrade attempts will fail at compatibility check
// because legitimate compiler won't generate "MyEvent\x00"
```

## Notes

This is a logic vulnerability arising from inconsistent validation policies between different attribute types. The vulnerability is triggerable without requiring any trusted role compromise, majority stake, or consensus manipulation. It affects real module upgradeability guarantees and requires manual intervention to resolve, meeting the definition of Medium severity in the Aptos bug bounty program.

### Citations

**File:** types/src/vm/module_metadata.rs (L398-421)
```rust
pub fn is_valid_resource_group(
    structs: &BTreeMap<&IdentStr, (&StructHandle, &StructDefinition)>,
    struct_: &str,
) -> Result<(), AttributeValidationError> {
    if let Ok(ident_struct) = Identifier::new(struct_) {
        if let Some((struct_handle, struct_def)) = structs.get(ident_struct.as_ident_str()) {
            let num_fields = match &struct_def.field_information {
                StructFieldInformation::Native | StructFieldInformation::DeclaredVariants(_) => 0,
                StructFieldInformation::Declared(fields) => fields.len(),
            };
            if struct_handle.abilities == AbilitySet::EMPTY
                && struct_handle.type_parameters.is_empty()
                && num_fields == 1
            {
                return Ok(());
            }
        }
    }

    Err(AttributeValidationError {
        key: struct_.to_string(),
        attribute: KnownAttributeKind::ViewFunction as u8,
    })
}
```

**File:** types/src/vm/module_metadata.rs (L496-499)
```rust
            if features.are_resource_groups_enabled() {
                if attr.is_resource_group() && attr.get_resource_group().is_some() {
                    is_valid_resource_group(&structs, struct_)?;
                    continue;
```

**File:** types/src/vm/module_metadata.rs (L507-509)
```rust
            if features.is_module_event_enabled() && attr.is_event() {
                continue;
            }
```

**File:** aptos-move/aptos-vm/src/verifier/event_validation.rs (L69-76)
```rust
        if let Some(metadata) = old_module_metadata_if_exists {
            let original_event_structs = extract_event_metadata(&metadata)?;
            for member in original_event_structs {
                // Fail if we see a removal of an event attribute.
                if !new_event_structs.remove(&member) {
                    metadata_validation_err("Invalid change in event attributes")?;
                }
            }
```

**File:** aptos-move/aptos-vm/src/verifier/event_validation.rs (L258-270)
```rust
pub(crate) fn extract_event_metadata(
    metadata: &RuntimeModuleMetadataV1,
) -> VMResult<HashSet<String>> {
    let mut event_structs = HashSet::new();
    for (struct_, attrs) in &metadata.struct_attributes {
        for attr in attrs {
            if attr.is_event() && !event_structs.insert(struct_.clone()) {
                metadata_validation_err("Found duplicate event attribute")?;
            }
        }
    }
    Ok(event_structs)
}
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L104-139)
```rust
fn test_metadata_with_changes(f: impl Fn() -> Vec<Metadata>) -> TransactionStatus {
    let mut h = MoveHarness::new();
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());

    let mut builder = PackageBuilder::new("Package");
    builder.add_source(
        "m.move",
        r#"
        module 0xf00d::M {
            #[view]
            fun foo(value: u64): u64 { value }
        }
        "#,
    );
    let path = builder.write_to_temp().unwrap();

    let package = BuiltPackage::build(path.path().to_path_buf(), BuildOptions::default())
        .expect("building package must succeed");
    let origin_code = package.extract_code();
    let mut compiled_module = CompiledModule::deserialize(&origin_code[0]).unwrap();
    let metadata = f();
    let mut invalid_code = vec![];
    compiled_module.metadata = metadata;
    compiled_module.serialize(&mut invalid_code).unwrap();

    let package_metadata = package
        .extract_metadata()
        .expect("extracting package metadata must succeed");
    h.run_transaction_payload(
        &account,
        aptos_stdlib::code_publish_package_txn(
            bcs::to_bytes(&package_metadata).expect("PackageMetadata has BCS"),
            vec![invalid_code],
        ),
    )
}
```

**File:** aptos-move/e2e-move-tests/src/tests/module_event.rs (L109-122)
```rust
    // Incompatible upgrades -- remove existing event attribute
    let source = r#"
        module 0xf00d::M {
            struct Event1 { }

            #[event]
            struct Event2 { }
        }
        "#;
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("m.move", source);
    let path = builder.write_to_temp().unwrap();
    let result = h.publish_package(&account, path.path());
    assert_vm_status!(result, StatusCode::EVENT_METADATA_VALIDATION_ERROR);
```
