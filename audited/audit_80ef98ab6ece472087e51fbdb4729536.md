# Audit Report

## Title
Insufficient Validation of error_map Metadata Allows Injection of Malicious Strings in Module Publishing

## Summary
The `inject_runtime_metadata()` function does not validate the `error_map` field in `RuntimeModuleMetadataV1`, and the publish-time validation in `verify_module_metadata_for_module_publishing()` also fails to validate `error_map` content. This allows an attacker to manually modify compiled `.mv` files to inject malicious or oversized error descriptions that are returned in transaction error responses, potentially exploiting downstream systems. [1](#0-0) 

## Finding Description

The `inject_runtime_metadata()` function accepts a `BTreeMap<ModuleId, RuntimeModuleMetadataV1>` parameter and directly serializes it into module bytecode without any content validation: [2](#0-1) 

While the metadata normally comes from the trusted `run_extended_checks()` function, an attacker can exploit this validation gap through the following attack path: [3](#0-2) 

**Attack Steps:**
1. Build a legitimate Move module using standard compilation
2. Manually edit the resulting `.mv` file to modify the BCS-serialized metadata, specifically the `error_map` field in `RuntimeModuleMetadataV1`
3. Inject malicious content into `ErrorDescription` strings (`code_name` and `code_description`)
4. Publish the modified module

At publish time, `verify_module_metadata_for_module_publishing()` performs validation but **completely skips validation of the error_map content**: [4](#0-3) 

The validation only checks:
- Module complexity (structural properties)
- Metadata format (BCS deserialization succeeds)
- Function attributes match actual function definitions
- Struct attributes match actual struct definitions

The `error_map` field (a `BTreeMap<u64, ErrorDescription>`) containing arbitrary strings is never validated. At runtime, when Move aborts occur, these strings are extracted and included in error responses: [5](#0-4) [6](#0-5) 

The `ErrorDescription` struct contains unbounded strings: [7](#0-6) 

## Impact Explanation

**Severity: Medium**

This vulnerability does not meet **Critical** severity criteria (requires consensus violation, fund theft, RCE, or network partition). While it affects error reporting infrastructure, it has limited impact:

1. **Injection Attacks on Downstream Systems**: Malicious strings could exploit log injection, XSS in blockchain explorers, or other vulnerabilities in systems that display error messages without proper sanitization.

2. **Resource Consumption**: Although transaction size limits cap the attack (64KB for regular transactions, 1MB for governance), an attacker could still inject substantial error_map data that consumes memory when modules are loaded. [8](#0-7) 

3. **Misleading Error Information**: Attackers could inject false error descriptions to confuse users or hide actual error causes.

4. **No Consensus Impact**: The error_map is read after transaction execution and only affects the `ExecutionStatus` in transaction output, not state changes or consensus.

This qualifies as **Medium severity** per Aptos bug bounty criteria due to potential impact on external systems and limited node resource consumption.

## Likelihood Explanation

**Likelihood: Low to Medium**

The attack requires:
- Building a valid Move module
- Understanding BCS serialization format to manually edit `.mv` files
- Publishing the module (costs transaction fees)
- Waiting for module aborts to occur for strings to be returned

The technical barrier (BCS manipulation) reduces likelihood, but the attack is feasible for sophisticated attackers with knowledge of the module format.

## Recommendation

Add validation of `error_map` content in `verify_module_metadata_for_module_publishing()`:

```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    // ... existing validation ...
    
    // Add error_map validation
    const MAX_ERROR_NAME_LEN: usize = 256;
    const MAX_ERROR_DESC_LEN: usize = 1024;
    const MAX_ERROR_MAP_ENTRIES: usize = 1000;
    
    if metadata.error_map.len() > MAX_ERROR_MAP_ENTRIES {
        return Err(MetaDataValidationError::Malformed(
            MalformedError::ModuleTooComplex
        ));
    }
    
    for (_, error_desc) in &metadata.error_map {
        if error_desc.code_name.len() > MAX_ERROR_NAME_LEN 
            || error_desc.code_description.len() > MAX_ERROR_DESC_LEN {
            return Err(MetaDataValidationError::Malformed(
                MalformedError::ModuleTooComplex
            ));
        }
        
        // Validate strings don't contain control characters or other malicious content
        validate_error_string(&error_desc.code_name)?;
        validate_error_string(&error_desc.code_description)?;
    }
    
    Ok(())
}

fn validate_error_string(s: &str) -> Result<(), MetaDataValidationError> {
    // Reject strings with control characters, null bytes, etc.
    if s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(MetaDataValidationError::Malformed(
            MalformedError::UnknownKey(vec![])
        ));
    }
    Ok(())
}
```

## Proof of Concept

```rust
// This demonstrates the validation gap - error_map is not checked
use move_core_types::errmap::ErrorDescription;
use std::collections::BTreeMap;

#[test]
fn test_malicious_error_map_bypasses_validation() {
    // Build a module with legitimate code
    let mut module = build_test_module();
    
    // Create malicious error_map with oversized strings
    let mut malicious_error_map = BTreeMap::new();
    malicious_error_map.insert(
        1,
        ErrorDescription {
            code_name: "E".repeat(10000), // 10KB string
            code_description: "<script>alert('XSS')</script>".repeat(1000), // Injection payload
        }
    );
    
    // Create metadata with malicious error_map
    let metadata = RuntimeModuleMetadataV1 {
        error_map: malicious_error_map,
        struct_attributes: BTreeMap::new(),
        fun_attributes: BTreeMap::new(),
    };
    
    // Serialize and inject into module (simulating manual .mv file edit)
    let serialized = bcs::to_bytes(&metadata).unwrap();
    module.metadata.push(Metadata {
        key: APTOS_METADATA_KEY_V1.to_vec(),
        value: serialized,
    });
    
    // Publish-time validation - PASSES despite malicious content
    let result = verify_module_metadata_for_module_publishing(&module, &features);
    assert!(result.is_ok()); // Validation INCORRECTLY passes!
    
    // At runtime, malicious strings are returned in errors
    let runtime_metadata = get_metadata_from_compiled_code(&module).unwrap();
    let abort_info = runtime_metadata.extract_abort_info(1).unwrap();
    assert!(abort_info.reason_name.len() == 10000); // Oversized string
    assert!(abort_info.description.contains("<script>")); // Injection payload
}
```

## Notes

This vulnerability exists because the security model assumes that metadata injected during build time is trusted (coming from `run_extended_checks()`), but fails to enforce this assumption at publish time. The validation gap in `verify_module_metadata_for_module_publishing()` allows manually-modified modules to bypass security checks. While transaction size limits prevent catastrophic DoS, the vulnerability still enables injection attacks against downstream systems and resource consumption within allowable limits.

### Citations

**File:** aptos-move/framework/src/built_package.rs (L310-310)
```rust
            let runtime_metadata = extended_checks::run_extended_checks(model);
```

**File:** aptos-move/framework/src/built_package.rs (L612-658)
```rust
fn inject_runtime_metadata(
    package_path: PathBuf,
    pack: &mut CompiledPackage,
    metadata: BTreeMap<ModuleId, RuntimeModuleMetadataV1>,
    bytecode_version: Option<u32>,
) -> anyhow::Result<()> {
    for unit_with_source in pack.root_compiled_units.iter_mut() {
        match &mut unit_with_source.unit {
            CompiledUnit::Module(named_module) => {
                if let Some(module_metadata) = metadata.get(&named_module.module.self_id()) {
                    if !module_metadata.is_empty() {
                        if bytecode_version.unwrap_or(METADATA_V1_MIN_FILE_FORMAT_VERSION)
                            >= METADATA_V1_MIN_FILE_FORMAT_VERSION
                        {
                            let serialized_metadata = bcs::to_bytes(&module_metadata)
                                .expect("BCS for RuntimeModuleMetadata");
                            named_module.module.metadata.push(Metadata {
                                key: APTOS_METADATA_KEY_V1.to_vec(),
                                value: serialized_metadata,
                            });
                        } else {
                            let serialized_metadata =
                                bcs::to_bytes(&module_metadata.clone().downgrade())
                                    .expect("BCS for RuntimeModuleMetadata");
                            named_module.module.metadata.push(Metadata {
                                key: APTOS_METADATA_KEY.to_vec(),
                                value: serialized_metadata,
                            });
                        }

                        // Also need to update the .mv file on disk.
                        let path = package_path
                            .join(CompiledPackageLayout::CompiledModules.path())
                            .join(named_module.name.as_str())
                            .with_extension(MOVE_COMPILED_EXTENSION);
                        if path.is_file() {
                            let bytes = unit_with_source.unit.serialize(bytecode_version);
                            std::fs::write(path, bytes)?;
                        }
                    }
                }
            },
            CompiledUnit::Script(_) => {},
        }
    }
    Ok(())
}
```

**File:** types/src/vm/module_metadata.rs (L441-518)
```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    if features.is_enabled(FeatureFlag::SAFER_METADATA) {
        check_module_complexity(module)?;
    }

    if features.are_resource_groups_enabled() {
        check_metadata_format(module)?;
    }
    let metadata = if let Some(metadata) = get_metadata_from_compiled_code(module) {
        metadata
    } else {
        return Ok(());
    };

    let functions = module
        .function_defs
        .iter()
        .map(|func_def| {
            let func_handle = module.function_handle_at(func_def.function);
            let name = module.identifier_at(func_handle.name);
            (name, (func_handle, func_def))
        })
        .collect::<BTreeMap<_, _>>();

    for (fun, attrs) in &metadata.fun_attributes {
        for attr in attrs {
            if attr.is_view_function() {
                is_valid_view_function(module, &functions, fun)?;
            } else if attr.is_randomness() {
                is_valid_unbiasable_function(&functions, fun)?;
            } else {
                return Err(AttributeValidationError {
                    key: fun.clone(),
                    attribute: attr.kind,
                }
                .into());
            }
        }
    }

    let structs = module
        .struct_defs
        .iter()
        .map(|struct_def| {
            let struct_handle = module.struct_handle_at(struct_def.struct_handle);
            let name = module.identifier_at(struct_handle.name);
            (name, (struct_handle, struct_def))
        })
        .collect::<BTreeMap<_, _>>();

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
    Ok(())
}
```

**File:** types/src/vm/module_metadata.rs (L548-557)
```rust
    pub fn extract_abort_info(&self, code: u64) -> Option<AbortInfo> {
        self.error_map
            .get(&(code & 0xFFF))
            .or_else(|| self.error_map.get(&code))
            .map(|descr| AbortInfo {
                reason_name: descr.code_name.clone(),
                description: descr.code_description.clone(),
            })
    }
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L634-680)
```rust
    fn inject_abort_info_if_available(
        &self,
        module_storage: &impl AptosModuleStorage,
        traversal_context: &TraversalContext,
        log_context: &AdapterLogSchema,
        status: ExecutionStatus,
    ) -> ExecutionStatus {
        if let ExecutionStatus::MoveAbort {
            location: AbortLocation::Module(module_id),
            code,
            info: current_info,
        } = status
        {
            // Note: in general, this module should have been charged for (because the location is
            // set). This cannot be enforced though, so the best option is to perform unmetered
            // access in any case to get a consistent error message. In case it was not metered,
            // log an error.
            if self.features().is_lazy_loading_enabled()
                && traversal_context
                    .check_is_special_or_visited(module_id.address(), module_id.name())
                    .is_err()
            {
                alert!(
                    *log_context,
                    "Unmetered metadata access for {}::{} when injecting abort info",
                    module_id.address(),
                    module_id.name()
                );
            }

            let mut info = module_storage
                .unmetered_get_deserialized_module(module_id.address(), module_id.name())
                .ok()
                .flatten()
                .and_then(|module| get_metadata(&module.metadata))
                .and_then(|m| m.extract_abort_info(code));

            // If the abort had a message, override the description with the message.
            if let Some(mut current_info) = current_info {
                if let Some(info) = info {
                    current_info.reason_name = info.reason_name;
                }
                info = Some(current_info);
            }

            ExecutionStatus::MoveAbort {
                location: AbortLocation::Module(module_id),
```

**File:** third_party/move/move-core/types/src/errmap.rs (L14-20)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDescription {
    /// The constant name of error e.g., ECANT_PAY_DEPOSIT
    pub code_name: String,
    /// The code description. This is generated from the doc comments on the constant.
    pub code_description: String,
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-81)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```
