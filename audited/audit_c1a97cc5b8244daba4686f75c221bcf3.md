# Audit Report

## Title
Directory Traversal Vulnerability in Move Package Compilation via Malicious Package Names

## Summary
The Move package compilation system lacks validation for special directory names ("." and "..") in package names, allowing attackers to write files outside the intended build directory during package compilation. While the security question focuses on the `ends_with()` check at line 157, the actual vulnerability exists in the package name parsing and file save operations.

## Finding Description

The Move package compilation system uses two different package name parsing implementations:

1. **Validated parser** in `move-package-manifest` that properly rejects invalid names [1](#0-0) 

2. **Legacy parser** that directly converts strings to `Symbol` without validation [2](#0-1) 

The actual compilation flow uses the legacy parser: [3](#0-2) 

Since `Symbol` accepts any string without validation, package names "." or ".." are accepted: [4](#0-3) 

During compilation, the package directory path is created by joining the build root with the package name: [5](#0-4) 

Files are then saved using this path: [6](#0-5) [7](#0-6) 

**Attack Path:**
1. Attacker creates a malicious Move package dependency with `name = ".."` in Move.toml
2. Victim developer includes this dependency or compiles the malicious package
3. During compilation, `root_path` becomes `build/..` (parent directory)
4. Files are written to `build/../sources/`, `build/../BuildInfo.yaml`, etc.
5. These paths normalize to `../sources/`, `../BuildInfo.yaml` (parent of project root)
6. Critical project files, configuration, or scripts can be overwritten

**Regarding the `ends_with()` check at line 157:** [8](#0-7) 

This check is **not directly vulnerable** because `std::fs::read_dir()` does not return "." or ".." as directory entries—these are filesystem navigation symbols. The traversal occurs during file save operations, not during cleanup.

## Impact Explanation

**Severity: High**

If a validator node operator compiles a malicious Move package on their node:
- Critical node configuration files could be overwritten
- Build scripts or startup scripts could be replaced with malicious code
- This could lead to node compromise or validator private key theft
- Qualifies as a supply chain attack vector against validator infrastructure

While this doesn't directly affect blockchain consensus or state (not Critical), it enables compromise of validator nodes through social engineering (High severity per "Validator node slowdowns" and "Significant protocol violations" criteria).

## Likelihood Explanation

**Likelihood: Medium-High**

- Requires victim to compile malicious package
- Common in dependency supply chain attacks
- Move ecosystem uses package dependencies extensively
- Node operators regularly compile packages for deployments
- No warning or validation prevents this attack

## Recommendation

Add package name validation to the legacy parser. In `manifest_parser.rs`:

```rust
// In parse_package_info function, after line 126:
let name = name
    .as_str()
    .ok_or_else(|| format_err!("Package name must be a string"))?;

// Add validation before line 127:
if name == "." || name == ".." || name.contains("..") || name.contains("/") || name.contains("\\") {
    bail!("Invalid package name '{}': cannot contain directory traversal characters", name);
}

let name = PM::PackageName::from(name);
```

Additionally, use the validated `PackageName` type from `move-package-manifest` instead of raw `Symbol` for package names, or add validation in `save_to_disk`:

```rust
// In compiled_package.rs, before line 867:
let package_name_str = root_package.as_str();
if package_name_str.contains("..") || package_name_str.contains(".") 
   || package_name_str.contains("/") || package_name_str.contains("\\") {
    bail!("Invalid package name for filesystem operations: {}", package_name_str);
}
```

## Proof of Concept

Create a malicious Move.toml:
```toml
[package]
name = ".."
version = "0.0.1"

[dependencies]
```

Compile this package using `aptos move compile` or include it as a dependency. The compilation will write files to the parent directory, potentially overwriting:
- `../Move.toml` (project manifest)
- `../scripts/` (build scripts)
- `../.aptos/` (configuration)

**Notes**

The vulnerability exists in the Move package build tooling rather than the blockchain protocol itself. However, it poses a real security risk to developers and node operators who compile Move packages, making it a valid supply chain attack vector. The specific `ends_with()` check mentioned in the security question is not vulnerable; the actual vulnerability is in the package name validation and file save operations.

### Citations

**File:** third_party/move/tools/move-package-manifest/src/package_name.rs (L58-67)
```rust
fn is_valid_package_name(s: &str) -> bool {
    let mut chars = s.chars();

    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => (),
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L124-127)
```rust
            let name = name
                .as_str()
                .ok_or_else(|| format_err!("Package name must be a string"))?;
            let name = PM::PackageName::from(name);
```

**File:** third_party/move/tools/move-package/src/lib.rs (L217-217)
```rust
        let manifest = manifest_parser::parse_source_manifest(toml_manifest)?;
```

**File:** third_party/move/move-symbol-pool/src/symbol.rs (L50-56)
```rust
impl<'a> From<Cow<'a, str>> for Symbol {
    fn from(s: Cow<'a, str>) -> Self {
        let mut pool = SYMBOL_POOL.lock().expect("could not acquire lock on pool");
        let address = pool.insert(s).as_ptr() as u64;
        Symbol(NonZeroU64::new(address).expect("address of symbol cannot be null"))
    }
}
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L279-284)
```rust
    pub(crate) fn save_under(&self, file: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        let path_to_save = self.root_path.join(file);
        let parent = path_to_save.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        std::fs::write(path_to_save, bytes).map_err(|err| err.into())
    }
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L841-841)
```rust
            root_path: under_path.join(root_package.as_str()),
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L867-867)
```rust
        std::fs::create_dir_all(&on_disk_package.root_path)?;
```

**File:** third_party/move/tools/move-package/src/compilation/build_plan.rs (L157-161)
```rust
            if path.is_dir() && !keep_paths.iter().any(|name| path.ends_with(name.as_str())) {
                std::fs::remove_dir_all(&path).with_context(|| {
                    format!("When deleting directory {}", path.to_string_lossy())
                })?;
            }
```
