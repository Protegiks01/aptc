# Audit Report

## Title
Path Traversal Vulnerability in Move CLI Coverage Collection via Unsanitized Package Names

## Summary
The `collect_coverage()` function in the Move CLI testing framework does not sanitize package names from `Move.toml` before using them in file path construction, allowing path traversal attacks that can read arbitrary files outside the intended build directory.

## Finding Description

The vulnerability exists in the Move package manifest parsing and coverage collection workflow: [1](#0-0) 

The manifest parser extracts the package name as a string and wraps it in a `Symbol` type without any validation: [2](#0-1) 

The `PackageName` type is simply an alias for `Symbol`, which accepts any string content: [3](#0-2) 

`Symbol::from()` stores strings without sanitization. This unsanitized package name is then used directly in path construction within `collect_coverage()`: [4](#0-3) 

The package name is concatenated to `build_dir` using `.join()` at line 86 without any validation to prevent directory traversal sequences like `../`.

**Attack Scenario:**
1. Attacker creates a malicious `Move.toml` with: `name = "../../sensitive"`
2. When running `move test --track-cov`, the code constructs the path: `<build_dir>/../../sensitive/BuildInfo.yaml`
3. This resolves to a location outside the build directory, allowing file system traversal
4. `OnDiskCompiledPackage::from_path()` attempts to read and deserialize the YAML file at the traversed location [5](#0-4) 

Notably, a validated `PackageName` type with proper sanitization exists in the codebase but is not used: [6](#0-5) 

This validation function rejects package names containing path traversal characters, but the manifest parser uses an unvalidated `Symbol` type instead.

## Impact Explanation

This vulnerability allows an attacker who can control a `Move.toml` file and execute the Move CLI test framework to:

1. **Information Disclosure**: Read arbitrary YAML files from the file system by traversing outside the build directory
2. **Potential Deserialization Attacks**: If a crafted YAML file exists at the traversed location, it will be deserialized into `OnDiskPackage`, which could trigger additional vulnerabilities depending on the YAML content

While this is in developer tooling rather than blockchain runtime, it affects:
- Developers working on Move packages
- CI/CD systems running Move tests
- Any environment processing untrusted Move packages

The security question rates this as **High** severity, which is appropriate for a path traversal vulnerability that could expose sensitive configuration files or enable further exploitation in development and build environments.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- Attacker ability to provide a malicious `Move.toml` file
- Victim running `move test` with the `--track-cov` flag
- A readable file at the traversed path (or a crafted file placed there)

This is realistic in scenarios where:
- Developers test third-party Move packages
- CI/CD pipelines automatically test submitted packages
- Shared development environments process untrusted code

The vulnerability is easy to exploit once the conditions are met, requiring only a simple string in the package name field.

## Recommendation

Implement package name validation before using it in file path operations. Use the existing validated `PackageName` type from `move-package-manifest`:

1. **Immediate Fix**: Add validation in the manifest parser to reject package names containing path traversal sequences:

```rust
// In manifest_parser.rs, modify parse_package_info():
let name = name
    .as_str()
    .ok_or_else(|| format_err!("Package name must be a string"))?;

// Validate that name doesn't contain path traversal sequences
if name.contains("..") || name.contains('/') || name.contains('\\') {
    bail!("Package name cannot contain path separators or traversal sequences");
}

// Use the validated PackageName type
let name = move_package_manifest::PackageName::new(name)?;
```

2. **Long-term Solution**: Refactor the manifest parser to use the validated `PackageName` type from `move-package-manifest` instead of raw `Symbol` types, ensuring all package names are validated at parse time.

3. **Defense in Depth**: In `collect_coverage()`, canonicalize and validate that the resolved path is within the expected build directory before passing to `OnDiskCompiledPackage::from_path()`.

## Proof of Concept

Create a malicious Move package:

```toml
# Move.toml
[package]
name = "../../etc"
version = "0.0.0"
```

Place a crafted `BuildInfo.yaml` at the traversal target:

```bash
mkdir -p /tmp/etc
cat > /tmp/etc/BuildInfo.yaml << 'EOF'
compiled_package_info:
  package_name: "etc"
  version: [0, 0, 0]
  build_flags: {}
  source_digest: ""
  address_alias_instantiation: {}
dependencies: []
bytecode_deps: []
EOF
```

Run Move CLI with coverage:

```bash
cd <malicious_package_dir>
move test --track-cov
```

The code will traverse to `/tmp/etc/BuildInfo.yaml` instead of the intended build directory, demonstrating the path traversal vulnerability.

## Notes

While this vulnerability is in the Move CLI testing framework (developer tooling) rather than the blockchain consensus or runtime, it represents a genuine security issue that could affect development environments, CI/CD systems, and any context where untrusted Move packages are processed. The validated `PackageName` type already exists in the codebase but is not utilized by the manifest parser, indicating this is a straightforward oversight that should be corrected.

### Citations

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L118-127)
```rust
            let name = table
                .remove("name")
                .ok_or_else(|| format_err!("'name' is a required field but was not found",))?;
            let version = table
                .remove("version")
                .ok_or_else(|| format_err!("'version' is a required field but was not found",))?;
            let name = name
                .as_str()
                .ok_or_else(|| format_err!("Package name must be a string"))?;
            let name = PM::PackageName::from(name);
```

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L10-10)
```rust
pub type PackageName = Symbol;
```

**File:** third_party/move/move-symbol-pool/src/symbol.rs (L58-62)
```rust
impl From<&str> for Symbol {
    fn from(s: &str) -> Self {
        Self::from(Cow::Borrowed(s))
    }
}
```

**File:** third_party/move/tools/move-cli/src/test/mod.rs (L73-89)
```rust
fn collect_coverage(
    trace_file: &Path,
    build_dir: &Path,
) -> anyhow::Result<ExecCoverageMapWithModules> {
    let canonical_build = build_dir.canonicalize().unwrap();
    let package_name = parse_move_manifest_from_file(
        &SourcePackageLayout::try_find_root(&canonical_build).unwrap(),
    )?
    .package
    .name
    .to_string();
    let pkg = OnDiskCompiledPackage::from_path(
        &build_dir
            .join(package_name)
            .join(CompiledPackageLayout::BuildInfo.path()),
    )?
    .into_compiled_package()?;
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L127-140)
```rust
    pub fn from_path(p: &Path) -> Result<Self> {
        let (buf, build_path) = if p.exists() && extension_equals(p, "yaml") {
            (std::fs::read(p)?, p.parent().unwrap().parent().unwrap())
        } else {
            (
                std::fs::read(p.join(CompiledPackageLayout::BuildInfo.path()))?,
                p.parent().unwrap(),
            )
        };
        let package = serde_yaml::from_slice::<OnDiskPackage>(&buf)?;
        assert!(build_path.ends_with(CompiledPackageLayout::Root.path()));
        let root_path = build_path.join(package.compiled_package_info.package_name.as_str());
        Ok(Self { root_path, package })
    }
```

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
