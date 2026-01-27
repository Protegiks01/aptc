# Audit Report

## Title
Source Map File Hash Validation Bypass Enables Bait-and-Switch Attacks in Module Publishing

## Summary
The Aptos blockchain does not validate that source maps match the actual source code or compiled bytecode during module publishing. This allows attackers to publish modules where the on-chain "source code" differs from the executed bytecode, enabling bait-and-switch attacks that can hide malicious behavior from auditors and users.

## Finding Description

During module publishing in Aptos, packages include `ModuleMetadata` which contains three key fields: the compiled bytecode, source code (gzipped), and source_map (BCS-encoded). The source_map includes a file hash that should match the source code it references. [1](#0-0) 

The source_map provides a `check()` method that verifies the file hash matches given file contents: [2](#0-1) 

However, this validation is **never enforced** during module publishing. The `check()` method is only used in development tools (bytecode viewer and coverage tools), not in the core blockchain validation path: [3](#0-2) 

During module publishing, the validation flow calls `verify_module_metadata_for_module_publishing()`: [4](#0-3) 

This function only validates metadata format, attributes, and module complexity - but **does not verify source map correctness or file hash matches**: [5](#0-4) 

**Attack Flow:**

1. Attacker writes malicious Move code (e.g., fund-stealing logic)
2. Compiles it to bytecode
3. Creates DIFFERENT benign source code (e.g., innocent-looking token contract)
4. Generates or modifies source_map to have file_hash of the benign source
5. Publishes package with: malicious bytecode + benign source + crafted source_map
6. Validators execute malicious bytecode
7. Block explorers, auditors, and users see benign source code

The bytecode deserialization only validates the compiled module structure, not the source map: [6](#0-5) 

## Impact Explanation

This is **High Severity** per Aptos Bug Bounty criteria for the following reasons:

1. **Breaks Code Transparency**: The fundamental promise of blockchain transparency - that anyone can verify what code executes - is violated. Users cannot trust that the "source code" they inspect matches what actually runs.

2. **Enables Hidden Malicious Behavior**: Attackers can hide fund-stealing logic, backdoors, or other malicious functionality while presenting clean-looking source code to auditors and users.

3. **Undermines Trust Model**: The blockchain ecosystem relies on code being verifiable. This vulnerability breaks that trust, potentially leading to:
   - Loss of funds if users trust fake source code
   - Failed audits (auditors review wrong source)
   - Ecosystem-wide reputation damage

4. **No Special Privileges Required**: Any user with code publishing permissions can exploit this - no validator access needed.

While this doesn't directly violate consensus safety, it represents a **significant protocol violation** that can lead to loss of funds, qualifying as High Severity under the bug bounty program.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Easy to Execute**: The attack requires no special skills beyond normal Move development - just compile malicious code and provide different source files during publishing.

2. **Low Barrier to Entry**: Any user who can publish modules (which is enabled by default in many deployments) can exploit this.

3. **Hard to Detect**: Without automated verification tools checking source-to-bytecode correspondence, malicious packages may pass manual audits.

4. **High Attacker Motivation**: The ability to hide malicious behavior while appearing legitimate is extremely valuable for attackers targeting DeFi protocols, token contracts, and other high-value applications.

5. **No Runtime Detection**: Once published, there's no mechanism to detect the mismatch - the malicious code executes normally while the fake source remains visible.

## Recommendation

Implement mandatory source map validation during module publishing. The fix should:

**1. Add validation in `verify_module_metadata_for_module_publishing()`:**

Add a new validation step that:
- Extracts the source code from `ModuleMetadata.source`
- Extracts and deserializes the source_map from `ModuleMetadata.source_map`
- Calls `source_map.check(source_contents)` to verify file hash matches
- Rejects the module if validation fails

**2. Optionally verify bytecode-to-source correspondence:**

For stronger guarantees, consider:
- Recompiling the source code and comparing the resulting bytecode hash
- This ensures not just that source_map matches source, but that source actually produced the bytecode

**3. Code Fix Location:**

In `types/src/vm/module_metadata.rs`, modify `verify_module_metadata_for_module_publishing()` to add source map validation after line 456.

**4. Backward Compatibility:**

For existing modules published before the fix:
- Mark them with a flag indicating "unverified source"
- Display warnings in block explorers
- Consider a grace period for re-verification

## Proof of Concept

**Step 1: Create malicious Move module (steal_funds.move):**

```move
module attacker::steal_funds {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    public entry fun innocent_transfer(from: &signer, to: address, amount: u64) {
        // Actually steals funds to attacker's address
        coin::transfer<AptosCoin>(from, @attacker, amount);
    }
}
```

**Step 2: Compile to bytecode**

**Step 3: Create benign source file (innocent.move):**

```move
module attacker::steal_funds {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    public entry fun innocent_transfer(from: &signer, to: address, amount: u64) {
        // Legitimately transfers funds
        coin::transfer<AptosCoin>(from, to, amount);
    }
}
```

**Step 4: Generate source_map with file_hash of innocent.move**

**Step 5: Publish package:**

```rust
// In a transaction:
code::publish_package_txn(
    publisher_signer,
    bcs::to_bytes(&PackageMetadata {
        name: "innocent_package",
        upgrade_policy: upgrade_policy_compat(),
        modules: vec![ModuleMetadata {
            name: "steal_funds",
            source: gzip(read("innocent.move")),  // Benign source
            source_map: serialize(crafted_source_map),  // Points to benign source
            extension: None,
        }],
        ...
    }),
    vec![read_bytecode("steal_funds.mv")]  // Malicious bytecode
)
```

**Result:**
- Module publishes successfully (no validation errors)
- Block explorer shows innocent source code
- Actual execution steals funds to attacker address
- Users trusting the displayed source lose funds

**Verification:**
To verify this vulnerability exists, audit the publishing path and confirm that `SourceMap::check()` is never called during `validate_publish_request()` or `verify_module_metadata_for_module_publishing()`.

## Notes

This vulnerability fundamentally breaks the code transparency guarantee that is central to blockchain trust models. While the source map feature exists for debugging purposes, its integration into the on-chain metadata without validation creates a significant security gap. The fix is straightforward but requires careful consideration of backward compatibility with already-published modules.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L58-67)
```text
    struct ModuleMetadata has copy, drop, store {
        /// Name of the module.
        name: String,
        /// Source text, gzipped String. Empty if not provided.
        source: vector<u8>,
        /// Source map, in compressed BCS. Empty if not provided.
        source_map: vector<u8>,
        /// For future extensions.
        extension: Option<Any>,
    }
```

**File:** third_party/move/move-ir-compiler/move-bytecode-source-map/src/source_map.rs (L337-340)
```rust
    pub fn check(&self, file_contents: &str) -> bool {
        let file_hash = FileHash::new(file_contents);
        self.definition_location.file_hash() == file_hash
    }
```

**File:** third_party/move/tools/move-bytecode-viewer/src/source_viewer.rs (L31-34)
```rust
        assert!(
            source_map.check(&file_contents),
            "File contents are out of sync with source map"
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1444-1461)
```rust
    fn deserialize_module_bundle(&self, modules: &ModuleBundle) -> VMResult<Vec<CompiledModule>> {
        let mut result = vec![];
        for module_blob in modules.iter() {
            match CompiledModule::deserialize_with_config(
                module_blob.code(),
                self.deserializer_config(),
            ) {
                Ok(module) => {
                    result.push(module);
                },
                Err(_err) => {
                    return Err(PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR)
                        .finish(Location::Undefined))
                },
            }
        }
        Ok(result)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1715-1716)
```rust
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
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
