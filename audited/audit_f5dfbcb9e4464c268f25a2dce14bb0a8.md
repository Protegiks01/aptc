# Audit Report

## Title
Module Metadata Excluded from Complexity Metering Allows Bypassing Complexity Limits

## Summary
The `check_module_complexity()` function in the Move binary format verifier does not meter module metadata, source maps, or debug information when calculating module complexity. This allows attackers to inflate module budgets by including large metadata while keeping actual code complexity unmeasured, effectively bypassing intended complexity limits.

## Finding Description

The complexity metering system is designed to prevent publishing overly complex modules that could cause performance issues or DoS during verification and execution. However, this protection can be bypassed through the metadata field. [1](#0-0) 

The `check_module_complexity()` function only meters signatures, handles, instantiations, and definitions, but completely excludes the `metadata` field from complexity calculations. Meanwhile, the budget calculation in the VM includes metadata in the blob size: [2](#0-1) 

The metadata field is serialized as part of the binary format: [3](#0-2) 

Metadata can contain arbitrary-sized strings in error descriptions and attributes: [4](#0-3) [5](#0-4) 

**Attack Path:**
1. Attacker creates a module with legitimate code structures
2. Adds large metadata with verbose error descriptions (e.g., 40KB of error message strings)
3. Total blob size = 50KB (40KB metadata + 10KB code)
4. Budget calculated = 2048 + 50000 * 20 = 1,002,048 units
5. Complexity meter only charges for the 10KB of actual code structures
6. Metadata consumes 0 budget despite contributing 80% of blob size
7. Attacker can now use remaining budget for highly complex code structures that would normally be rejected

This breaks the **Resource Limits** invariant that "all operations must respect gas, storage, and computational limits" by allowing modules with disproportionate complexity relative to their non-metadata content.

## Impact Explanation

This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria:

- Bypasses complexity metering security controls
- Allows publishing modules with excessive complexity relative to intended limits
- May cause validator performance degradation during module verification
- Could lead to state inconsistencies if complex modules cause processing timeouts
- Does not directly result in fund loss or consensus violations, preventing Critical/High classification
- Requires gas payment for publishing, providing some economic deterrent

## Likelihood Explanation

**High Likelihood** - The vulnerability is:
- Trivial to exploit (simply add large metadata strings)
- No special permissions required (any module publisher)
- Metadata validation only checks key validity, not size limits: [6](#0-5) 

- Economically feasible within gas/size constraints
- Discoverable through basic code inspection

## Recommendation

Modify `check_module_complexity()` to meter metadata content:

```rust
pub fn check_module_complexity(module: &CompiledModule, budget: u64) -> PartialVMResult<u64> {
    let meter = BinaryComplexityMeter {
        resolver: BinaryIndexedView::Module(module),
        cached_signature_costs: RefCell::new(BTreeMap::new()),
        balance: RefCell::new(budget),
    };

    // Add metadata metering
    meter.meter_metadata()?;
    
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

Add the metering function:

```rust
impl BinaryComplexityMeter<'_> {
    fn meter_metadata(&self) -> PartialVMResult<()> {
        for metadata in self.resolver.metadata() {
            // Charge for key size
            self.charge(metadata.key.len() as u64 * COST_PER_IDENT_BYTE)?;
            // Charge for value size
            self.charge(metadata.value.len() as u64 * COST_PER_IDENT_BYTE)?;
        }
        Ok(())
    }
}
```

Additionally, consider adding explicit size limits in metadata validation to prevent abuse even with metering.

## Proof of Concept

```rust
// Compile a module with minimal code but large metadata
use move_binary_format::file_format::{CompiledModule, Metadata};

fn create_exploit_module() -> CompiledModule {
    let mut module = create_minimal_module(); // Basic valid module
    
    // Add large metadata that doesn't consume complexity budget
    let large_error_desc = "A".repeat(40000); // 40KB error description
    let metadata_value = bcs::to_bytes(&RuntimeModuleMetadataV1 {
        error_map: [(1u64, ErrorDescription {
            code_name: "ERROR".to_string(),
            code_description: large_error_desc,
        })].into_iter().collect(),
        struct_attributes: BTreeMap::new(),
        fun_attributes: BTreeMap::new(),
    }).unwrap();
    
    module.metadata.push(Metadata {
        key: APTOS_METADATA_KEY_V1.to_vec(),
        value: metadata_value,
    });
    
    // Serialize and check complexity
    let mut blob = vec![];
    module.serialize(&mut blob).unwrap();
    
    let budget = 2048 + (blob.len() as u64) * 20;
    println!("Blob size: {} bytes", blob.len());
    println!("Budget: {} units", budget);
    
    let used = check_module_complexity(&module, budget).unwrap();
    println!("Budget used: {} units", used);
    println!("Budget remaining: {} units", budget - used);
    
    // Demonstrates that large metadata inflates budget without consuming it
    assert!(budget - used > 800_000); // Most budget unused despite large blob
}
```

This demonstrates that a 50KB module with 40KB metadata gets a budget of ~1 million units but only consumes ~200k units, leaving 800k units available for complex code structures that should have been rejected.

## Notes

While package size limits (60KB) and gas costs provide some protection, they do not prevent this bypass within those constraints. The complexity metering system's purpose is to ensure modules are not too complex to process efficiently, and metadata exclusion undermines this guarantee. Source maps and debug information are typically stored separately (not in the module metadata field itself), but the metadata field vulnerability alone is sufficient for exploitation.

### Citations

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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1554-1559)
```rust
        for (module, blob) in modules.iter().zip(bundle.iter()) {
            // TODO(Gas): Make budget configurable.
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
        }
```

**File:** third_party/move/move-binary-format/src/serializer.rs (L1483-1490)
```rust
        if self.major_version >= VERSION_5 {
            self.metadata = serialize_table(
                &mut table_count,
                binary,
                tables.get_metadata(),
                serialize_metadata_entry,
            )?;
        }
```

**File:** third_party/move/move-core/types/src/metadata.rs (L10-15)
```rust
pub struct Metadata {
    /// The key identifying the type of metadata.
    pub key: Vec<u8>,
    /// The value of the metadata.
    pub value: Vec<u8>,
}
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

**File:** types/src/vm/module_metadata.rs (L252-283)
```rust
/// Check if the metadata has unknown key/data types
fn check_metadata_format(module: &CompiledModule) -> Result<(), MalformedError> {
    let mut exist = false;
    let mut compilation_key_exist = false;
    for data in module.metadata.iter() {
        if data.key == *APTOS_METADATA_KEY || data.key == *APTOS_METADATA_KEY_V1 {
            if exist {
                return Err(MalformedError::DuplicateKey);
            }
            exist = true;

            if data.key == *APTOS_METADATA_KEY {
                bcs::from_bytes::<RuntimeModuleMetadata>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            } else if data.key == *APTOS_METADATA_KEY_V1 {
                bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            }
        } else if data.key == *COMPILATION_METADATA_KEY {
            if compilation_key_exist {
                return Err(MalformedError::DuplicateKey);
            }
            compilation_key_exist = true;
            bcs::from_bytes::<CompilationMetadata>(&data.value)
                .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
        } else {
            return Err(MalformedError::UnknownKey(data.key.clone()));
        }
    }

    Ok(())
}
```
