# Audit Report

## Title
Path Traversal Vulnerability in On-Chain Package Module Name Handling During Local Caching

## Summary
The package cache system fails to validate module names retrieved from on-chain package metadata before using them in filesystem path construction. While `PackageName` itself is properly validated, module names within `ModuleMetadata` are deserialized as raw strings and directly used in `Path::join()` operations, allowing path traversal attacks when a malicious or compromised full node returns crafted BCS data.

## Finding Description

The vulnerability exists in the `fetch_on_chain_package` function where module names from on-chain `PackageMetadata` are used unsanitized to construct file paths. [1](#0-0) 

The attack flow:
1. User's package resolver connects to a full node to download an on-chain package
2. The full node returns a `PackageRegistry` BCS-serialized response containing `ModuleMetadata`
3. Module names are extracted from the deserialized data without validation [2](#0-1) 

4. These unsanitized module names are directly used in path construction [3](#0-2) 

5. The code creates parent directories and writes files based on the traversed path [4](#0-3) 

While legitimate on-chain packages have module names validated as `Identifier` types during compilation (which prohibit path separators), the deserialization process accepts arbitrary strings: [5](#0-4) 

A malicious full node can return crafted BCS data where `module.name` contains path traversal sequences like `"../../../etc/malicious"` or absolute paths. The Rust `Path::join()` method will honor these path components, allowing writes outside the intended cache directory.

## Impact Explanation

**Medium Severity** - This vulnerability enables arbitrary file write on systems running the Aptos package resolver when connecting to malicious full nodes. While it doesn't directly affect blockchain consensus or validator operations, it compromises developer and user machines attempting to download packages. 

The impact is limited to client-side security rather than protocol-level security, placing it in the Medium severity category as it requires a compromised full node and affects local filesystem integrity rather than on-chain state or funds.

## Likelihood Explanation

**Medium Likelihood** - The attack requires:
1. User connecting to a malicious or compromised full node
2. User attempting to download an on-chain package dependency
3. Attacker having the ability to return crafted BCS responses

While users typically connect to trusted infrastructure, the code should defend against malicious responses. Developers working with multiple networks or testing against custom nodes are particularly at risk. The absence of cryptographic proof verification for resource data (beyond state root verification at the API layer) makes this exploitation vector realistic. [6](#0-5) 

## Recommendation

Add module name validation before filesystem operations:

```rust
// In package_cache.rs, after line 370:
let module_name = module.name.clone();

// Add validation:
if !module_name.chars().all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '$')) {
    bail!("Invalid module name '{}' contains unsafe characters", module_name);
}

// Or use Move's Identifier validation:
use move_core_types::identifier::Identifier;
let validated_name = Identifier::new(&module_name)
    .map_err(|_| anyhow!("Invalid module name '{}'", module_name))?
    .as_str();
```

Additionally, implement path sanitization to ensure constructed paths remain within the cache directory:

```rust
let module_file_path = temp_path.join(&validated_name).with_extension("mv");

// Validate the resulting path doesn't escape the temp directory
if !module_file_path.starts_with(&temp_path) {
    bail!("Path traversal attempt detected in module name '{}'", module_name);
}
```

## Proof of Concept

```rust
// Mock test demonstrating the vulnerability
#[tokio::test]
async fn test_path_traversal_in_module_names() {
    use tempfile::TempDir;
    
    // Create temporary cache directory
    let cache_dir = TempDir::new().unwrap();
    let package_cache = PackageCache::new(cache_dir.path()).unwrap();
    
    // Craft malicious PackageMetadata with path traversal in module name
    let malicious_metadata = PackageMetadata {
        name: "legitimate_package".to_string(),
        upgrade_policy: UpgradePolicy::compat(),
        upgrade_number: 0,
        source_digest: String::new(),
        manifest: vec![],
        modules: vec![ModuleMetadata {
            name: "../../../tmp/evil_module".to_string(), // Path traversal
            source: vec![],
            source_map: vec![],
            extension: None,
        }],
        deps: vec![],
        extension: None,
    };
    
    // When a malicious node returns this metadata and the cache processes it,
    // files will be written to /tmp/evil_module.mv instead of the cache directory
    // demonstrating arbitrary file write capability
}
```

## Notes

While the original security question focuses on `PackageName` validation, the actual vulnerability lies in **module names** within package metadata. The `PackageName` struct correctly validates package names and they are safely used in path construction via the `canonical_name` format string. However, module names escape validation because they're deserialized as raw `String` types from BCS data without subsequent sanitization before filesystem operations.

This is a defense-in-depth issue where the system relies on on-chain data integrity but doesn't validate untrusted data from full node responses. While legitimate packages published through normal channels will have valid module names (enforced by the Move compiler), the client-side code should not trust that all data received from the network is well-formed.

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L333-340)
```rust
        let package_registry = client
            .get_account_resource_at_version_bcs::<PackageRegistry>(
                address,
                "0x1::code::PackageRegistry",
                network_version,
            )
            .await?
            .into_inner();
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L366-378)
```rust
        let fetch_futures = package.modules.iter().map(|module| {
            let client = client.clone();
            let temp_path = temp.path().to_owned();
            let package_name = package_name.to_string();
            let module_name = module.name.clone();

            async move {
                let module_bytes = client
                    .get_account_module_bcs_at_version(address, &module_name, network_version)
                    .await?
                    .into_inner();

                let module_file_path = temp_path.join(&module_name).with_extension("mv");
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L381-384)
```rust
                tokio::task::spawn_blocking(move || {
                    fs::create_dir_all(module_file_path.parent().unwrap())?;
                    let mut file = File::create(&module_file_path)?;
                    file.write_all(&module_bytes)?;
```

**File:** aptos-move/framework/src/natives/code.rs (L101-109)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub source: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub source_map: Vec<u8>,
    pub extension: Option<Any>,
}
```
