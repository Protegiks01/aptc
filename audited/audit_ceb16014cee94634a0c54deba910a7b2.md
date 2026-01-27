# Audit Report

## Title
Legacy Manifest Parser Allows Whitespace in Package Names Leading to Dependency Resolution Failures

## Summary
The older `move-package` manifest parser accepts package names containing leading, trailing, or internal whitespace without validation, while the newer `move-package-manifest` system correctly rejects such names. This inconsistency can cause on-chain dependency resolution failures when packages with whitespace-containing names are published and referenced by other packages.

## Finding Description

The Aptos codebase contains two parallel package manifest parsing systems with different validation rules:

**System 1 (Validated)**: The newer `move-package-manifest` crate properly validates package names using `is_valid_package_name()` which only allows ASCII alphanumeric characters, hyphens, and underscores. Whitespace is explicitly rejected. [1](#0-0) 

**System 2 (Unvalidated)**: The older `move-package` crate uses `Symbol` as the package name type, which accepts any string without validation. The manifest parser directly converts TOML string values to `Symbol` instances. [2](#0-1) [3](#0-2) 

The `Symbol` implementation accepts any string: [4](#0-3) 

**Exploitation Path:**

1. Attacker creates a `Move.toml` manifest with whitespace in the package name (e.g., `name = " MyPackage "`).
2. The older manifest parser accepts this without validation and converts it to a `Symbol`.
3. Package is built using the `BuiltPackage` infrastructure, which extracts metadata from the parsed manifest. [5](#0-4) 

4. Package is published on-chain with a name containing whitespace.
5. When another package attempts to declare a dependency on this package using the name without whitespace, the on-chain dependency check fails because Move performs exact string equality comparison. [6](#0-5) 

The older manifest parser is actively used in the Aptos framework for package building and metadata extraction: [7](#0-6) [8](#0-7) 

## Impact Explanation

This issue has **Low to Medium** severity operational impact:

- **Dependency Resolution Failures**: Packages with whitespace-containing names cannot be properly referenced as dependencies, causing transaction failures with `EPACKAGE_DEP_MISSING` error code.
- **User Confusion**: Package names with whitespace are visually confusing and could facilitate typosquatting attacks.
- **Filesystem Issues**: Package names are used in directory paths, and whitespace can cause filesystem operations to behave unexpectedly.

However, this does NOT constitute a Critical or High severity security vulnerability because:
- No consensus violation occurs (all nodes consistently apply the same string comparison)
- No loss of funds is possible
- No state corruption occurs
- The issue is recoverable by republishing packages with corrected names

## Likelihood Explanation

The likelihood of accidental occurrence is **Low** because:
- Most developers follow standard naming conventions
- IDEs and linters typically flag unusual characters in identifiers
- The newer validated system is preferred for new code

The likelihood of malicious exploitation is **Low to Medium** because:
- Attacker would need to intentionally craft malformed manifests
- The impact is limited to operational disruption rather than security compromise
- The attack surface is constrained to package publishing operations

## Recommendation

**Immediate Fix**: Add validation to the older manifest parser to reject package names with whitespace:

```rust
// In manifest_parser.rs, after line 126
let name = name
    .as_str()
    .ok_or_else(|| format_err!("Package name must be a string"))?;

// Add validation before converting to Symbol
if name.chars().any(|c| c.is_whitespace()) {
    bail!("Package name '{}' contains whitespace characters", name);
}

let name = PM::PackageName::from(name);
```

**Long-term Solution**: Migrate all package operations to use the validated `move-package-manifest` system and deprecate the older unvalidated parser.

## Proof of Concept

Create a `Move.toml` file with whitespace in the package name:

```toml
[package]
name = " TestPackage "
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/aptos-framework", rev = "main" }
```

Attempt to build and publish this package. The build will succeed (using the unvalidated parser), but any dependent package attempting to reference `TestPackage` (without spaces) will fail dependency resolution with `EPACKAGE_DEP_MISSING`.

## Notes

While this finding represents a validation gap and code quality issue, it does **not** meet the threshold for a security vulnerability requiring immediate patching under the Aptos bug bounty program criteria. The impact is limited to operational inconvenience rather than security compromise. The recommendation is to address this through normal development processes as a hardening measure.

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

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L10-10)
```rust
pub type PackageName = Symbol;
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L124-127)
```rust
            let name = name
                .as_str()
                .ok_or_else(|| format_err!("Package name must be a string"))?;
            let name = PM::PackageName::from(name);
```

**File:** third_party/move/move-symbol-pool/src/symbol.rs (L58-62)
```rust
impl From<&str> for Symbol {
    fn from(s: &str) -> Self {
        Self::from(Cow::Borrowed(s))
    }
}
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L759-764)
```rust
            compiled_package_info: CompiledPackageInfo {
                package_name: resolved_package.source_package.package.name,
                address_alias_instantiation: resolved_package.resolution_table,
                source_digest: Some(resolved_package.source_digest),
                build_flags: resolution_graph.build_options.clone(),
            },
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L314-314)
```text
                    if (dep_pack.name == dep.package_name) {
```

**File:** aptos-move/framework/src/built_package.rs (L411-413)
```rust
    pub fn name(&self) -> &str {
        self.package.compiled_package_info.package_name.as_str()
    }
```

**File:** aptos-move/framework/src/built_package.rs (L582-582)
```rust
            name: self.name().to_string(),
```
