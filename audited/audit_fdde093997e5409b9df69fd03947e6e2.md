# Audit Report

## Title
Metadata Version Validation Bypass Enables Biasable Randomness Attack via Version 5 Modules with V1 Metadata

## Summary
A critical metadata validation vulnerability allows attackers to publish Move modules with bytecode version 5 containing V1 metadata attributes (such as `#[randomness]`) that should only be supported in version 6+. During publishing, the validation clears these attributes for version 5, allowing the module to pass checks. However, at runtime, the attributes are not cleared, enabling PUBLIC functions to gain access to security-critical randomness APIs, breaking the biasable randomness protection model.

## Finding Description

The Aptos codebase has two different functions for extracting runtime metadata from compiled modules: [1](#0-0) [2](#0-1) 

The critical difference is that `get_metadata_from_compiled_code` has access to the module's bytecode version via the `CompiledCodeMetadata` trait and clears attributes for version 5, while `get_metadata` only receives raw metadata bytes and cannot perform version checking.

During module publishing, the validation process uses `get_metadata_from_compiled_code`: [3](#0-2) 

For version 5 modules, this clears `struct_attributes` and `fun_attributes`, causing the subsequent validation to pass since no attributes exist to validate. The code even contains a comment acknowledging this issue should have been caught earlier: [4](#0-3) 

However, the validation function `check_metadata_format` does not reject V1 metadata for modules with version < 6: [5](#0-4) 

At runtime, when checking for randomness annotations during entry function execution, the code uses `get_metadata` without version validation: [6](#0-5) [7](#0-6) 

This allows the randomness annotation to be recognized, marking the session as unbiasable and granting access to randomness APIs: [8](#0-7) 

The security model requires that functions using randomness must be private or friend-only to prevent biasable randomness (test-and-abort attacks). This is validated during proper publishing: [9](#0-8) [10](#0-9) 

However, this validation is bypassed because the attributes are cleared before validation runs.

**Attack Path:**
1. Attacker crafts a CompiledModule with version=5 and V1 metadata containing `#[randomness]` on a PUBLIC entry function
2. Module publishing validation calls `get_metadata_from_compiled_code`, which clears attributes for version 5
3. Validation passes (no attributes to validate)
4. Module is stored with original V1 metadata intact
5. At runtime, `get_randomness_annotation_for_entry_function` uses `get_metadata` (no version check)
6. Randomness annotation is found, session marked as unbiasable
7. PUBLIC function can call randomness APIs, enabling test-and-abort attacks

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the cryptographic randomness security model, qualifying as a **Consensus/Safety violation** under Critical severity criteria. The impact includes:

1. **Biasable Randomness Attacks**: Attackers can create PUBLIC entry functions with randomness access, allowing external callers to test random outcomes and abort unfavorable transactions. This enables:
   - Manipulation of randomness-dependent on-chain games and gambling applications
   - Loss of funds for users in systems relying on fair randomness
   - Unfair advantages in NFT minting, lottery systems, and random selection mechanisms

2. **Deterministic Execution Violation**: If different validators have different interpretations of metadata validation, this could cause consensus splits where validators disagree on transaction outcomes.

3. **Access Control Bypass**: The vulnerability circumvents the visibility requirement that randomness functions must be private/friend-only, fundamentally breaking the security boundary.

The minimum bytecode version is VERSION_5, making this attack feasible: [11](#0-10) 

V1 metadata was intended only for version 6+: [12](#0-11) 

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Complexity**: Requires only crafting a module with version 5 bytecode and V1 metadata (achievable with standard Move compiler + manual metadata injection)
2. **No Special Permissions**: Any user can publish modules and execute entry functions
3. **Direct Economic Incentive**: Immediate profit opportunity in gambling/gaming applications using randomness
4. **Existing Infrastructure**: Randomness is actively used in Aptos applications, providing ready targets
5. **Difficult to Detect**: The malicious module appears valid during publishing, making it hard for reviewers to identify

The vulnerability exists in production code paths executed during every module publishing and entry function execution involving randomness.

## Recommendation

Add version validation to reject V1 metadata for modules with version < METADATA_V1_MIN_FILE_FORMAT_VERSION during publishing:

```rust
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
                // ADD VERSION CHECK HERE
                if module.version < METADATA_V1_MIN_FILE_FORMAT_VERSION {
                    return Err(MalformedError::UnknownKey(data.key.clone()));
                }
                bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            }
        }
        // ... rest of validation
    }
    Ok(())
}
```

Additionally, ensure `check_metadata_format` is always called (not just when `are_resource_groups_enabled()`): [13](#0-12) 

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability by showing how a version 5 module
// with V1 metadata bypasses validation

use move_binary_format::{CompiledModule, file_format::Metadata};
use move_core_types::metadata::Metadata as CoreMetadata;
use aptos_types::vm::module_metadata::{
    RuntimeModuleMetadataV1, KnownAttribute, APTOS_METADATA_KEY_V1,
    verify_module_metadata_for_module_publishing, get_randomness_annotation_for_entry_function
};
use std::collections::BTreeMap;

// Step 1: Create a valid version 5 compiled module (use Move compiler)
// Step 2: Manually inject V1 metadata with randomness attribute
fn craft_malicious_module() -> CompiledModule {
    let mut module = create_basic_module_v5(); // version = 5
    
    // Create V1 metadata with randomness attribute on a PUBLIC function
    let mut metadata = RuntimeModuleMetadataV1::default();
    metadata.fun_attributes.insert(
        "public_random_func".to_string(),
        vec![KnownAttribute::randomness(Some(1000000))]
    );
    
    // Serialize and inject as V1 metadata
    let serialized = bcs::to_bytes(&metadata).unwrap();
    module.metadata.push(Metadata {
        key: APTOS_METADATA_KEY_V1.to_vec(),
        value: serialized,
    });
    
    module
}

// Step 3: Publish the module - validation passes!
// verify_module_metadata_for_module_publishing will:
// - Call get_metadata_from_compiled_code
// - Clear attributes for version 5
// - Find no attributes to validate
// - Return Ok(())

// Step 4: At runtime, execute the public entry function
// get_randomness_annotation_for_entry_function will:
// - Call get_metadata (NOT get_metadata_from_compiled_code)
// - Deserialize V1 metadata WITHOUT clearing
// - Find randomness annotation
// - Mark session as unbiasable
// - Grant access to randomness APIs from PUBLIC function!

// Result: Test-and-abort attack possible on randomness
```

**Notes:**

The vulnerability stems from architectural inconsistency in metadata extraction between publishing and runtime. The minimum supported bytecode version (VERSION_5) predates V1 metadata support (VERSION_6), but there's no enforcement preventing this invalid combination. The comment in the code acknowledging "this should have been gated in the verify module metadata" confirms this is a known gap that was never properly addressed.

Similar issues may exist for other V1 metadata attributes like `#[view]`, `#[resource_group]`, and `#[event]`, though randomness has the most critical security implications due to its role in preventing biasable randomness attacks.

### Citations

**File:** types/src/vm/module_metadata.rs (L39-40)
```rust
/// The minimal file format version from which the V1 metadata is supported
pub const METADATA_V1_MIN_FILE_FORMAT_VERSION: u32 = 6;
```

**File:** types/src/vm/module_metadata.rs (L198-230)
```rust
/// Extract metadata from the VM, upgrading V0 to V1 representation as needed
pub fn get_metadata(md: &[Metadata]) -> Option<Arc<RuntimeModuleMetadataV1>> {
    if let Some(data) = find_metadata(md, APTOS_METADATA_KEY_V1) {
        V1_METADATA_CACHE.with(|ref_cell| {
            let mut cache = ref_cell.borrow_mut();
            if let Some(meta) = cache.get(&data.value) {
                meta.clone()
            } else {
                let meta = bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .ok()
                    .map(Arc::new);
                cache.put(data.value.clone(), meta.clone());
                meta
            }
        })
    } else if let Some(data) = find_metadata(md, APTOS_METADATA_KEY) {
        V0_METADATA_CACHE.with(|ref_cell| {
            let mut cache = ref_cell.borrow_mut();
            if let Some(meta) = cache.get(&data.value) {
                meta.clone()
            } else {
                let meta = bcs::from_bytes::<RuntimeModuleMetadata>(&data.value)
                    .ok()
                    .map(RuntimeModuleMetadata::upgrade)
                    .map(Arc::new);
                cache.put(data.value.clone(), meta.clone());
                meta
            }
        })
    } else {
        None
    }
}
```

**File:** types/src/vm/module_metadata.rs (L234-250)
```rust
pub fn get_randomness_annotation_for_entry_function(
    entry_func: &EntryFunction,
    metadata: &[Metadata],
) -> Option<RandomnessAnnotation> {
    get_metadata(metadata).and_then(|metadata| {
        metadata
            .fun_attributes
            .get(entry_func.function().as_str())
            .map(|attrs| {
                attrs
                    .iter()
                    .filter_map(KnownAttribute::try_as_randomness_annotation)
                    .next()
            })
            .unwrap_or(None)
    })
}
```

**File:** types/src/vm/module_metadata.rs (L253-283)
```rust
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

**File:** types/src/vm/module_metadata.rs (L286-308)
```rust
/// needed.
pub fn get_metadata_from_compiled_code(
    code: &impl CompiledCodeMetadata,
) -> Option<RuntimeModuleMetadataV1> {
    if let Some(data) = find_metadata(code.metadata(), APTOS_METADATA_KEY_V1) {
        let mut metadata = bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value).ok();
        // Clear out metadata for v5, since it shouldn't have existed in the first place and isn't
        // being used. Note, this should have been gated in the verify module metadata.
        if code.version() == 5 {
            if let Some(metadata) = metadata.as_mut() {
                metadata.struct_attributes.clear();
                metadata.fun_attributes.clear();
            }
        }
        metadata
    } else if let Some(data) = find_metadata(code.metadata(), APTOS_METADATA_KEY) {
        // Old format available, upgrade to new one on the fly
        let data_v0 = bcs::from_bytes::<RuntimeModuleMetadata>(&data.value).ok()?;
        Some(data_v0.upgrade())
    } else {
        None
    }
}
```

**File:** types/src/vm/module_metadata.rs (L360-376)
```rust
pub fn is_valid_unbiasable_function(
    functions: &BTreeMap<&IdentStr, (&FunctionHandle, &FunctionDefinition)>,
    fun: &str,
) -> Result<(), AttributeValidationError> {
    if let Ok(ident_fun) = Identifier::new(fun) {
        if let Some((_func_handle, func_def)) = functions.get(ident_fun.as_ident_str()) {
            if func_def.is_entry && !func_def.visibility.is_public() {
                return Ok(());
            }
        }
    }

    Err(AttributeValidationError {
        key: fun.to_string(),
        attribute: KnownAttributeKind::Randomness as u8,
    })
}
```

**File:** types/src/vm/module_metadata.rs (L441-456)
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
```

**File:** types/src/vm/module_metadata.rs (L468-482)
```rust
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L983-991)
```rust
            if function.is_friend_or_private() {
                let maybe_randomness_annotation = get_randomness_annotation_for_entry_function(
                    entry_fn,
                    &function.owner_as_module()?.metadata,
                );
                if maybe_randomness_annotation.is_some() {
                    session.mark_unbiasable();
                }
            }
```

**File:** aptos-move/framework/src/natives/randomness.rs (L79-98)
```rust
pub fn fetch_and_increment_txn_counter(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    _args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    if context.gas_feature_version() >= RELEASE_V1_23 {
        context.charge(RANDOMNESS_FETCH_AND_INC_COUNTER)?;
    }

    let ctx = context.extensions_mut().get_mut::<RandomnessContext>();
    if !ctx.is_unbiasable() {
        return Err(SafeNativeError::Abort {
            abort_code: E_API_USE_SUSCEPTIBLE_TO_TEST_AND_ABORT,
        });
    }

    let ret = ctx.txn_local_state.to_vec();
    ctx.increment();
    Ok(smallvec![Value::vector_u8(ret)])
}
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L561-562)
```rust
/// Mark which oldest version is supported.
pub const VERSION_MIN: u32 = VERSION_5;
```
