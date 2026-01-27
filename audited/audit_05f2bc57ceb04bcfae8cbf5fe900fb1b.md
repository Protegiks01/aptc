# Audit Report

## Title
Panic in CLI Tools Due to Unchecked Decompression Failures in Display Trait Implementation

## Summary
The `Display` trait implementations for `PackageMetadata` and `ModuleMetadata` use `.unwrap()` on decompression results, causing client-side panics when displaying packages with malformed compressed metadata stored on-chain.

## Finding Description

The Display implementation for `CachedPackageMetadata` delegates to `PackageMetadata::Display`, which unconditionally unwraps decompression results: [1](#0-0) 

Similarly, `ModuleMetadata::Display` unwraps decompression of source code and source maps: [2](#0-1) 

The `unzip_metadata_str` function returns a `Result` that can fail if the data is not valid gzip or contains invalid UTF-8: [3](#0-2) 

**Attack Path:**

1. An attacker crafts a `PackageMetadata` with invalid/corrupted gzip data in the `manifest`, `source`, or `source_map` fields
2. The attacker publishes this package via `publish_package_txn`: [4](#0-3) 

3. The package is stored on-chain without validation of compressed data validity. The `validate_publish_request` function only validates bytecode structure, not metadata compression: [5](#0-4) 

4. When a user runs `aptos move download --print-metadata`, the Display trait is invoked: [6](#0-5) 

5. The `.unwrap()` call panics, crashing the CLI tool

## Impact Explanation

This vulnerability is categorized as **Low Severity** per the Aptos bug bounty program because:

- **No consensus impact**: Does not affect validator nodes, blockchain state, or consensus protocol
- **Client-side only**: Only affects CLI tools (`aptos` and `aptos-release-builder`), not the blockchain itself
- **No funds at risk**: Cannot cause loss, theft, or freezing of funds
- **Workaround available**: Users can avoid the panic by not using the `--print-metadata` flag
- **Graceful error handling exists elsewhere**: The `save_package_to_disk` function properly handles decompression errors using the `?` operator: [7](#0-6) 

## Likelihood Explanation

**High likelihood** of occurrence:
- Any user can publish packages without special permissions
- No validation prevents malformed compressed data from being stored on-chain
- The attack is trivial to execute: simply provide invalid gzip bytes when constructing `PackageMetadata`
- Users frequently use `--print-metadata` to inspect on-chain packages

## Recommendation

Replace `.unwrap()` calls with proper error handling in Display implementations:

**For `PackageMetadata::Display` (code.rs:79):**
```rust
let manifest_str = unzip_metadata_str(&self.manifest)
    .unwrap_or_else(|_| "<invalid compressed data>".to_string());
```

**For `ModuleMetadata::Display` (code.rs:116, 121):**
```rust
let source = unzip_metadata_str(&self.source)
    .unwrap_or_else(|_| "<decompression failed>".to_string());
let source_map = unzip_metadata_str(&self.source_map)
    .unwrap_or_else(|_| "<decompression failed>".to_string());
```

Alternatively, add validation during package publishing to reject packages with invalid compressed metadata.

## Proof of Concept

**Rust reproduction steps:**

1. Create a test that constructs a `PackageMetadata` with invalid gzip data:
```rust
let malicious_metadata = PackageMetadata {
    name: "malicious".to_string(),
    upgrade_policy: UpgradePolicy::arbitrary(),
    upgrade_number: 0,
    source_digest: "test".to_string(),
    manifest: vec![0xFF, 0xFF, 0xFF], // Invalid gzip data
    modules: vec![],
    deps: vec![],
    extension: None,
};
```

2. Attempt to display it:
```rust
println!("{}", malicious_metadata); // Panics with unwrap error
```

The panic occurs because the invalid gzip data cannot be decompressed by `GzDecoder`.

## Notes

This is a **Low severity** implementation bug that causes client-side denial of service but does not affect blockchain security, consensus, or state integrity. The issue should be fixed to improve user experience, but it poses no risk to the blockchain protocol itself.

### Citations

**File:** aptos-move/framework/src/natives/code.rs (L73-92)
```rust
impl fmt::Display for PackageMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Package name:{}", self.name)?;
        writeln!(f, "Upgrade policy:{}", self.upgrade_policy)?;
        writeln!(f, "Upgrade number:{}", self.upgrade_number)?;
        writeln!(f, "Source digest:{}", self.source_digest)?;
        let manifest_str = unzip_metadata_str(&self.manifest).unwrap();
        writeln!(f, "Manifest:")?;
        writeln!(f, "{}", manifest_str)?;
        writeln!(f, "Package Dependency:")?;
        for dep in &self.deps {
            writeln!(f, "{:?}", dep)?;
        }
        writeln!(f, "extension:{:?}", self.extension)?;
        writeln!(f, "Modules:")?;
        for module in &self.modules {
            writeln!(f, "{}", module)?;
        }
        Ok(())
    }
```

**File:** aptos-move/framework/src/natives/code.rs (L111-126)
```rust
impl fmt::Display for ModuleMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Module name:{}", self.name)?;
        if !self.source.is_empty() {
            writeln!(f, "Source code:")?;
            let source = unzip_metadata_str(&self.source).unwrap();
            writeln!(f, "{}", source)?;
        }
        if !self.source_map.is_empty() {
            writeln!(f, "Source map:")?;
            let source_map = unzip_metadata_str(&self.source_map).unwrap();
            writeln!(f, "{}", source_map)?;
        }
        writeln!(f, "Module extension:{:?}", self.extension)?;
        Ok(())
    }
```

**File:** aptos-move/framework/src/lib.rs (L58-62)
```rust
pub fn unzip_metadata_str(data: &[u8]) -> anyhow::Result<String> {
    let r = unzip_metadata(data)?;
    let s = String::from_utf8(r)?;
    Ok(s)
}
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1680-1739)
```rust
    fn validate_publish_request(
        &self,
        module_storage: &impl AptosModuleStorage,
        traversal_context: &mut TraversalContext,
        gas_meter: &mut impl GasMeter,
        modules: &[CompiledModule],
        mut expected_modules: BTreeSet<String>,
        allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
    ) -> VMResult<()> {
        self.reject_unstable_bytecode(modules)?;
        native_validation::validate_module_natives(modules)?;

        for m in modules {
            if !expected_modules.remove(m.self_id().name().as_str()) {
                return Err(Self::metadata_validation_error(&format!(
                    "unregistered module: '{}'",
                    m.self_id().name()
                )));
            }
            if let Some(allowed) = &allowed_deps {
                for dep in m.immediate_dependencies() {
                    if !allowed
                        .get(dep.address())
                        .map(|modules| {
                            modules.contains("") || modules.contains(dep.name().as_str())
                        })
                        .unwrap_or(false)
                    {
                        return Err(Self::metadata_validation_error(&format!(
                            "unregistered dependency: '{}'",
                            dep
                        )));
                    }
                }
            }
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
        }

        resource_groups::validate_resource_groups(
            self.features(),
            module_storage,
            traversal_context,
            gas_meter,
            modules,
        )?;
        event_validation::validate_module_events(
            self.features(),
            module_storage,
            traversal_context,
            modules,
        )?;

        if !expected_modules.is_empty() {
            return Err(Self::metadata_validation_error(
                "not all registered modules published",
            ));
        }
        Ok(())
    }
```

**File:** crates/aptos/src/move_tool/mod.rs (L1998-2000)
```rust
        if self.print_metadata {
            println!("{}", package);
        }
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L161-181)
```rust
    pub fn save_package_to_disk(&self, path: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(path)?;
        fs::write(
            path.join("Move.toml"),
            unzip_metadata_str(&self.metadata.manifest)?,
        )?;
        let sources_dir = path.join(CompiledPackageLayout::Sources.path());
        fs::create_dir_all(&sources_dir)?;
        for module in &self.metadata.modules {
            match module.source.is_empty() {
                true => {
                    println!("module without code: {}", module.name);
                },
                false => {
                    let source = unzip_metadata_str(&module.source)?;
                    fs::write(sources_dir.join(format!("{}.move", module.name)), source)?;
                },
            };
        }
        Ok(())
    }
```
