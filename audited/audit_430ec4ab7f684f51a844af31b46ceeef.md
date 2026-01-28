# Audit Report

## Title
Missing UTF-8 Validation in Move BCS Deserialization Enables Storage of Malformed Package Metadata

## Summary
The Move `util::from_bytes` function used to deserialize `PackageMetadata` during package publication does not validate UTF-8 encoding in string fields (`name`, `source_digest`, `package_name`). This allows attackers to store package metadata with invalid UTF-8 strings on-chain, causing API/indexer deserialization failures and potential undefined behavior if string operations are performed on the malformed data.

## Finding Description
When a package is published via `publish_package_txn`, the `PackageMetadata` is deserialized from BCS bytes using `util::from_bytes<PackageMetadata>`. [1](#0-0) 

This deserialization uses the native function which delegates to `ValueSerDeContext::deserialize`. [2](#0-1) 

For Move `String` types (which are structs containing `bytes: vector<u8>`), this deserialization simply reconstructs the struct without validating that the byte sequence is valid UTF-8. [3](#0-2)  The BCS deserialization process for structs iterates through fields and deserializes them according to their layout. [4](#0-3)  For the String struct defined in Move, the bytes field is deserialized as a raw `vector<u8>` without UTF-8 validation. [5](#0-4) 

While module names are validated when passed to native functions like `request_publish`, the validation occurs through `get_move_string` which calls `String::from_utf8` to validate UTF-8. [6](#0-5) [7](#0-6) 

However, the `PackageMetadata.name`, `PackageMetadata.source_digest`, and `PackageDep.package_name` fields are only used for equality comparisons and are never passed through UTF-8 validation before being stored on-chain. [8](#0-7) [9](#0-8) 

Once stored, this corrupted metadata causes two issues:

1. **Rust Deserialization Failures**: When off-chain tools attempt to read the `PackageRegistry` resource using `bcs::from_bytes::<PackageMetadata>`, Rust's serde String deserialization will fail because Rust's `String` type requires valid UTF-8. The Rust `PackageMetadata` struct defines the name field as a standard Rust `String`. [10](#0-9)  Off-chain infrastructure commonly deserializes this data. [11](#0-10) [12](#0-11) 

2. **Potential Undefined Behavior**: Move's string native functions use `std::str::from_utf8_unchecked` which assumes valid UTF-8. [13](#0-12) [14](#0-13) [15](#0-14)  If future code performs string operations on these malformed strings, it triggers undefined behavior in Rust.

## Impact Explanation
This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because:

1. **API/Indexer Disruption**: Off-chain infrastructure (APIs, indexers, block explorers) that read package metadata will fail when attempting to deserialize corrupted `PackageRegistry` resources, requiring intervention to filter or repair the data

2. **Data Integrity Violation**: The blockchain stores data that violates its own type invariants (String must be valid UTF-8), creating technical debt and compatibility issues

3. **Potential for Undefined Behavior**: While no current framework code triggers it, the presence of malformed strings in storage creates a latent vulnerability for any future Move code that performs string operations on package metadata

The issue does not rise to High or Critical severity because:
- No funds are at risk
- Consensus is not affected (all validators store identical malformed data)
- Core blockchain functionality continues operating
- The impact is primarily on off-chain tooling

## Likelihood Explanation
**High Likelihood**. Any user can exploit this because regular signers (non-permissioned signers) are treated as "master signers" with all permissions by default. [16](#0-15) 

The attack can be executed by:
1. Crafting a valid Move package
2. Extracting and modifying the `PackageMetadata` to include invalid UTF-8 in `name` or `source_digest`
3. Ensuring module names remain valid UTF-8 (to pass native validation)
4. Publishing via `publish_package_txn` with the malformed metadata

The attack requires no special privileges beyond a normal account and can be executed with standard tools.

## Recommendation
Add UTF-8 validation for all String fields in `PackageMetadata` and `PackageDep` structures before storing them on-chain. This can be implemented by:

1. Validating `PackageMetadata.name`, `PackageMetadata.source_digest`, and `PackageDep.package_name` in the `publish_package` function before storage
2. Using the existing `string::utf8()` function which performs UTF-8 validation, or calling a validation function similar to `get_move_string` used for module names
3. Aborting the transaction with an appropriate error code if invalid UTF-8 is detected

Example fix location: Add validation after line 168 in code.move to validate all String fields in the PackageMetadata struct.

## Proof of Concept
A proof of concept would involve:
1. Creating a valid Move package
2. Serializing `PackageMetadata` with BCS
3. Manually modifying the serialized bytes to inject invalid UTF-8 sequences (e.g., `[0xFF, 0xFE]`) into the `name` field
4. Calling `publish_package_txn` with the malformed metadata
5. Verifying storage succeeded on-chain
6. Attempting to deserialize the `PackageRegistry` resource from off-chain tools and observing the failure

The core vulnerability is that the Move VM's BCS deserialization path does not enforce UTF-8 validity for String types, allowing malformed data to be stored that breaks the String type invariant.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L193-202)
```text
        , |i, old| {
            let old: &PackageMetadata = old;
            if (old.name == pack.name) {
                upgrade_number = old.upgrade_number + 1;
                check_upgradability(old, &pack, &module_names);
                index = i;
            } else {
                check_coexistence(old, &module_names)
            };
        });
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L312-318)
```text
                let found = vector::any(&registry.packages, |dep_pack| {
                    let dep_pack: &PackageMetadata = dep_pack;
                    if (dep_pack.name == dep.package_name) {
                        // Check policy
                        assert!(
                            dep_pack.upgrade_policy.policy >= pack.upgrade_policy.policy,
                            error::invalid_argument(EDEP_WEAKER_POLICY)
```

**File:** aptos-move/framework/src/natives/util.rs (L48-51)
```rust
    let val = match ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .deserialize(&bytes, &layout)
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L238-241)
```rust
    pub fn deserialize(self, bytes: &[u8], layout: &MoveTypeLayout) -> Option<Value> {
        let seed = DeserializationSeed { ctx: &self, layout };
        bcs::from_bytes_seed(seed, bytes).ok()
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5132-5138)
```rust
            L::Struct(struct_layout) => {
                let seed = DeserializationSeed {
                    ctx: self.ctx,
                    layout: struct_layout,
                };
                Ok(Value::struct_(seed.deserialize(deserializer)?))
            },
```

**File:** aptos-move/framework/move-stdlib/sources/string.move (L11-14)
```text
    /// A `String` holds a sequence of bytes which is guaranteed to be in utf8 format.
    struct String has copy, drop, store {
        bytes: vector<u8>,
    }
```

**File:** aptos-move/framework/src/natives/code.rs (L60-71)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PackageMetadata {
    pub name: String,
    pub upgrade_policy: UpgradePolicy,
    pub upgrade_number: u64,
    pub source_digest: String,
    #[serde(with = "serde_bytes")]
    pub manifest: Vec<u8>,
    pub modules: Vec<ModuleMetadata>,
    pub deps: Vec<PackageDep>,
    pub extension: Option<Any>,
}
```

**File:** aptos-move/framework/src/natives/code.rs (L243-251)
```rust
fn get_move_string(v: Value) -> PartialVMResult<String> {
    let bytes = v
        .value_as::<Struct>()?
        .unpack()?
        .next()
        .ok_or_else(|| PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR))?
        .value_as::<Vec<u8>>()?;
    String::from_utf8(bytes).map_err(|_| PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR))
}
```

**File:** aptos-move/framework/src/natives/code.rs (L326-333)
```rust
    let mut expected_modules = BTreeSet::new();
    for name in safely_pop_arg!(args, Vec<Value>) {
        let str = get_move_string(name)?;

        // TODO(Gas): fine tune the gas formula
        context.charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(str.len() as u64))?;
        expected_modules.insert(str);
    }
```

**File:** aptos-move/replay-benchmark/src/overrides.rs (L172-173)
```rust
                    let mut package_registry = bcs::from_bytes::<PackageRegistry>(&bytes)
                        .expect("Package registry should deserialize");
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L50-53)
```rust
        let inner = client
            .get_account_resource_bcs::<PackageRegistry>(addr, "0x1::code::PackageRegistry")
            .await?
            .into_inner();
```

**File:** aptos-move/framework/move-stdlib/src/natives/string.rs (L75-78)
```rust
    let ok = unsafe {
        // This is safe because we guarantee the bytes to be utf8.
        std::str::from_utf8_unchecked(s_ref.as_slice()).is_char_boundary(i as usize)
    };
```

**File:** aptos-move/framework/move-stdlib/src/natives/string.rs (L110-113)
```rust
    let s_str = unsafe {
        // This is safe because we guarantee the bytes to be utf8.
        std::str::from_utf8_unchecked(s_ref.as_slice())
    };
```

**File:** aptos-move/framework/move-stdlib/src/natives/string.rs (L136-142)
```rust
    let r_str = unsafe { std::str::from_utf8_unchecked(r_ref.as_slice()) };

    context.charge(STRING_INDEX_OF_PER_BYTE_PATTERN * NumBytes::new(r_str.len() as u64))?;

    let s_arg = safely_pop_arg!(args, VectorRef);
    let s_ref = s_arg.as_bytes_ref();
    let s_str = unsafe { std::str::from_utf8_unchecked(s_ref.as_slice()) };
```

**File:** aptos-move/framework/aptos-framework/sources/permissioned_signer.move (L561-564)
```text
        if (!is_permissioned_signer(s)) {
            // master signer has all permissions
            return true
        };
```
