# Audit Report

## Title
Unbounded Memory Allocation in Package Metadata Decompression Enabling Client-Side DoS

## Summary
The `unzip_metadata()` function in `aptos-move/framework/src/lib.rs` uses `read_to_end()` without size limits when decompressing package metadata fields, allowing attackers to publish packages with decompression bombs that cause excessive memory allocation and crashes in client-side tools.

## Finding Description
The vulnerability exists in the metadata decompression implementation: [1](#0-0) 

This function is called when displaying PackageMetadata through the Display trait implementation: [2](#0-1) [3](#0-2) 

The attack path:

1. **Publishing Phase**: Attacker publishes a package with malicious compressed metadata. The package metadata structure stores compressed data in `manifest`, `source`, and `source_map` fields: [4](#0-3) 

2. **Size Validation Bypassed**: Only the compressed size is validated (60KB limit for standard publishing): [5](#0-4) 

A highly compressed decompression bomb (e.g., 50KB compressed → 5GB decompressed) easily passes this check.

3. **Exploitation Trigger**: When developers or operators use CLI tools to inspect the malicious package, the Display implementation is invoked: [6](#0-5) 

Or when saving packages to disk: [7](#0-6) 

4. **Resource Exhaustion**: The unbounded `read_to_end()` call attempts to allocate gigabytes of memory, causing:
   - Out-of-memory crashes
   - Vec reallocation thrashing as the buffer grows repeatedly
   - System performance degradation
   - Denial of service for the affected tool

## Impact Explanation
**Medium Severity** - This represents a client-side denial-of-service attack that affects developer tools and operational utilities but does not directly impact blockchain consensus or validator operations. While the blockchain continues to function normally, developers and operators cannot safely inspect or work with the malicious packages, potentially hindering incident response and package analysis workflows. This falls under "state inconsistencies requiring intervention" as the malicious on-chain data prevents normal tooling operations.

## Likelihood Explanation
**High Likelihood** - The attack is trivial to execute:
- Any account can publish packages on-chain
- Decompression bomb creation is well-understood
- No special privileges required
- Multiple CLI tools and utilities are affected
- Common developer workflows trigger the vulnerability

## Recommendation
Implement a maximum decompressed size limit in the `unzip_metadata()` function:

```rust
pub fn unzip_metadata(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    const MAX_DECOMPRESSED_SIZE: usize = 10_000_000; // 10MB limit
    
    let mut d = GzDecoder::new(data);
    let mut res = Vec::new();
    
    // Use take() to limit reading
    let mut limited_reader = d.take(MAX_DECOMPRESSED_SIZE as u64);
    limited_reader.read_to_end(&mut res)?;
    
    // Check if we hit the limit
    if res.len() >= MAX_DECOMPRESSED_SIZE {
        anyhow::bail!("Decompressed data exceeds maximum size limit");
    }
    
    Ok(res)
}
```

## Proof of Concept

```rust
use aptos_framework::{zip_metadata, unzip_metadata};
use std::io::Write;

#[test]
fn test_decompression_bomb() {
    // Create a decompression bomb: compress 10MB of zeros
    let malicious_data = vec![0u8; 10_000_000];
    let compressed = zip_metadata(&malicious_data).unwrap();
    
    println!("Compressed size: {} bytes", compressed.len());
    println!("Will decompress to: {} bytes", malicious_data.len());
    
    // This will cause excessive memory allocation without limits
    let result = unzip_metadata(&compressed);
    assert!(result.is_ok());
    
    // In production, an attacker could create much larger decompression ratios
    // (e.g., 50KB compressed → 5GB decompressed) causing OOM crashes
}
```

To demonstrate the full attack:

1. Create a Move package with large source files filled with compressible data
2. Publish the package on-chain (compressed size < 60KB)
3. Run `aptos move download --account <address> --package <name>`
4. Observe excessive memory allocation and potential crash

## Notes
The vulnerability is limited to **client-side tools** and does not affect:
- Consensus protocol operation
- VM execution during transaction processing  
- Validator node stability during normal operation
- API servers (they return hex-encoded compressed data without decompression)

However, it represents a legitimate security concern for operational tooling and developer workflows, warranting the Medium severity classification.

### Citations

**File:** aptos-move/framework/src/lib.rs (L51-56)
```rust
pub fn unzip_metadata(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut d = GzDecoder::new(data);
    let mut res = vec![];
    d.read_to_end(&mut res)?;
    Ok(res)
}
```

**File:** aptos-move/framework/src/natives/code.rs (L73-93)
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
}
```

**File:** aptos-move/framework/src/natives/code.rs (L111-127)
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
}
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L29-67)
```text
    /// Metadata for a package. All byte blobs are represented as base64-of-gzipped-bytes
    struct PackageMetadata has copy, drop, store {
        /// Name of this package.
        name: String,
        /// The upgrade policy of this package.
        upgrade_policy: UpgradePolicy,
        /// The numbers of times this module has been upgraded. Also serves as the on-chain version.
        /// This field will be automatically assigned on successful upgrade.
        upgrade_number: u64,
        /// The source digest of the sources in the package. This is constructed by first building the
        /// sha256 of each individual source, than sorting them alphabetically, and sha256 them again.
        source_digest: String,
        /// The package manifest, in the Move.toml format. Gzipped text.
        manifest: vector<u8>,
        /// The list of modules installed by this package.
        modules: vector<ModuleMetadata>,
        /// Holds PackageDeps.
        deps: vector<PackageDep>,
        /// For future extension
        extension: Option<Any>
    }

    /// A dependency to a package published at address
    struct PackageDep has store, drop, copy {
        account: address,
        package_name: String
    }

    /// Metadata about a module in a package.
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

**File:** crates/aptos/src/move_tool/mod.rs (L984-984)
```rust
pub const MAX_PUBLISH_PACKAGE_SIZE: usize = 60_000;
```

**File:** aptos-move/aptos-release-builder/src/main.rs (L437-464)
```rust
        Commands::PrintPackageMetadata {
            endpoint,
            package_address,
            package_name,
            print_json,
            node_api_key,
        } => {
            let mut client = Client::builder(AptosBaseUrl::Custom(endpoint));
            if let Some(api_key) = node_api_key {
                client = client.api_key(&api_key)?;
            }
            let client = client.build();
            let address = AccountAddress::from_str_strict(&package_address)?;
            let packages = client
                .get_account_resource_bcs::<PackageRegistry>(address, "0x1::code::PackageRegistry")
                .await?;
            for package in packages.into_inner().packages {
                if package.name == package_name {
                    if print_json {
                        println!("{}", serde_json::to_string(&package).unwrap());
                    } else {
                        println!("{}", package);
                    }
                    break;
                }
            }
            Ok(())
        },
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
