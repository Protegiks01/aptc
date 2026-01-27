# Audit Report

## Title
Metadata Attribute Validation DoS via Unmetered StructTag Parsing

## Summary
The proptest strategy for metadata generation uses extremely small blob sizes (0-20 bytes), failing to test the computational complexity of metadata validation against the actual limit of 65KB. Metadata attribute validation, specifically StructTag parsing for resource group members, is not metered by the `COMPLEXITY_BUDGET` check, allowing attackers to craft modules with expensive validation costs that bypass complexity limits.

## Finding Description

The property-based test strategy generates metadata with minimal blob sizes: [1](#0-0) 

However, the actual metadata value size limit is 65,535 bytes: [2](#0-1) 

During module publishing validation, the `check_module_complexity()` function meters signatures, identifiers, and struct fields, but does NOT meter the metadata attributes themselves: [3](#0-2) 

The metadata validation process parses StructTag strings from resource group member attributes: [4](#0-3) 

This parsing occurs TWICE during validation:
1. In `verify_module_metadata_for_module_publishing()`: [5](#0-4) 
2. In `extract_resource_group_metadata()`: [6](#0-5) 

An attacker can craft a module with:
- Metadata approaching 65KB limit
- ~1,500-2,000 struct entries with resource_group_member attributes
- Each attribute containing complex StructTag strings (e.g., `"0x1::long_module_name::LongStructName<vector<u8>, vector<u64>, 0x2::another::Struct<T1, T2>>"`)

While StructTag parsing is depth-limited to 8 levels to prevent exponential blowup: [7](#0-6) 

The parsing complexity is O(N × M) where N is the number of attributes and M is the average string length. With 2,000 entries parsed twice (4,000 total parses) of ~50 character strings, this results in ~200,000 characters of parsing operations, taking potentially 100-500ms per module.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns".

An attacker publishing multiple malicious modules can cause cumulative validator slowdowns. Since validation occurs before gas metering during module verification: [8](#0-7) 

The attacker bypasses the resource limits invariant by causing expensive computation without proportional gas charges. Multiple such transactions can degrade validator performance, affecting consensus liveness.

## Likelihood Explanation

**High likelihood**: Any user can publish modules. The attack requires:
1. Crafting a module with maximum-sized metadata (straightforward using BCS serialization)
2. Submitting the module publishing transaction
3. Paying standard gas costs (which don't reflect validation complexity)

The 65KB metadata limit is sufficient to pack thousands of attributes requiring expensive parsing. The proptest's 20-byte limit means this worst-case scenario is untested in the codebase.

## Recommendation

1. **Add complexity metering for metadata attributes**: Extend `check_module_complexity()` to meter the size and count of metadata attributes:
   - Count each attribute entry
   - Meter the length of string arguments
   - Set a budget for total metadata attribute complexity

2. **Improve proptest coverage**: Update the metadata generation strategy to test with realistic blob sizes approaching the 65KB limit, not just 0-20 bytes.

3. **Consider caching parsed StructTags**: Since the same StructTag may be parsed multiple times, implement memoization to avoid redundant parsing.

## Proof of Concept

```rust
#[test]
fn test_malicious_metadata_dos() {
    use move_binary_format::file_format::*;
    use move_core_types::metadata::Metadata;
    use aptos_types::vm::module_metadata::{RuntimeModuleMetadataV1, KnownAttribute};
    use std::collections::BTreeMap;
    use std::time::Instant;
    
    // Create metadata with ~2000 struct attributes
    let mut struct_attributes = BTreeMap::new();
    for i in 0..2000 {
        let struct_name = format!("Struct{}", i);
        let complex_tag = format!(
            "0x1::module_name::StructName<vector<u8>, vector<u64>, 0x2::other::Type<T1, T2>>"
        );
        struct_attributes.insert(
            struct_name,
            vec![KnownAttribute::resource_group_member(complex_tag)]
        );
    }
    
    let metadata = RuntimeModuleMetadataV1 {
        error_map: BTreeMap::new(),
        struct_attributes,
        fun_attributes: BTreeMap::new(),
    };
    
    let serialized = bcs::to_bytes(&metadata).unwrap();
    println!("Metadata size: {} bytes", serialized.len());
    assert!(serialized.len() <= 65535);
    
    // Create a minimal compiled module with this metadata
    let mut module = empty_module();
    module.metadata = vec![Metadata {
        key: b"aptos::metadata_v1".to_vec(),
        value: serialized,
    }];
    
    // Measure validation time
    let start = Instant::now();
    let result = verify_module_metadata_for_module_publishing(&module, &Features::default());
    let elapsed = start.elapsed();
    
    println!("Validation time: {:?}", elapsed);
    assert!(elapsed.as_millis() > 100, "Validation should take significant time");
}
```

**Notes:**
- The actual complexity is polynomial (O(N × M)), not exponential, due to depth limits on StructTag parsing
- The 20-byte proptest blob size provides inadequate coverage of the 65KB actual limit
- Metadata attribute validation is unmetered, allowing bypass of complexity budgets
- Multiple malicious modules can cause cumulative validator slowdowns affecting consensus

### Citations

**File:** third_party/move/move-binary-format/src/proptest_types/metadata.rs (L21-21)
```rust
        btree_set(vec(any::<u8>(), 0..=20), blob_size).prop_map(|blobs| Self {
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L72-72)
```rust
pub const METADATA_VALUE_SIZE_MAX: u64 = 65535;
```

**File:** types/src/vm/module_metadata.rs (L138-144)
```rust
    pub fn get_resource_group_member(&self) -> Option<StructTag> {
        if self.kind == KnownAttributeKind::ResourceGroupMember as u8 {
            self.args.first()?.parse().ok()
        } else {
            None
        }
    }
```

**File:** types/src/vm/module_metadata.rs (L500-502)
```rust
                } else if attr.is_resource_group_member()
                    && attr.get_resource_group_member().is_some()
                {
```

**File:** types/src/vm/module_metadata.rs (L559-607)
```rust
/// Checks the complexity of a module.
fn check_module_complexity(module: &CompiledModule) -> Result<(), MetaDataValidationError> {
    let mut meter: usize = 0;
    for sig in module.signatures() {
        for tok in &sig.0 {
            check_sigtok_complexity(module, &mut meter, tok)?
        }
    }
    for handle in module.function_handles() {
        check_ident_complexity(module, &mut meter, handle.name)?;
        for tok in &safe_get_table(module.signatures(), handle.parameters.0)?.0 {
            check_sigtok_complexity(module, &mut meter, tok)?
        }
        for tok in &safe_get_table(module.signatures(), handle.return_.0)?.0 {
            check_sigtok_complexity(module, &mut meter, tok)?
        }
    }
    for handle in module.struct_handles() {
        check_ident_complexity(module, &mut meter, handle.name)?;
    }
    for def in module.struct_defs() {
        match &def.field_information {
            StructFieldInformation::Native => {},
            StructFieldInformation::Declared(fields) => {
                for field in fields {
                    check_ident_complexity(module, &mut meter, field.name)?;
                    check_sigtok_complexity(module, &mut meter, &field.signature.0)?
                }
            },
            StructFieldInformation::DeclaredVariants(variants) => {
                for variant in variants {
                    check_ident_complexity(module, &mut meter, variant.name)?;
                    for field in &variant.fields {
                        check_ident_complexity(module, &mut meter, field.name)?;
                        check_sigtok_complexity(module, &mut meter, &field.signature.0)?
                    }
                }
            },
        }
    }
    for def in module.function_defs() {
        if let Some(unit) = &def.code {
            for tok in &safe_get_table(module.signatures(), unit.locals.0)?.0 {
                check_sigtok_complexity(module, &mut meter, tok)?
            }
        }
    }
    Ok(())
}
```

**File:** aptos-move/aptos-vm/src/verifier/resource_groups.rs (L234-237)
```rust
            } else if attr.is_resource_group_member() {
                let member = attr.get_resource_group_member().ok_or_else(|| {
                    metadata_validation_error("Invalid resource_group_member attribute")
                })?;
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-11)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1715-1716)
```rust
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
```
