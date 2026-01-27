# Audit Report

## Title
Panic-Inducing Dependency Resolution Vulnerability in Move Package Model Builder

## Summary
The `build_model()` function in `model_builder.rs` uses unsafe `.unwrap()` calls when retrieving source files and bytecode from dependencies, causing panics when encountering malformed package metadata. An attacker can craft a malicious Move package with valid metadata but missing required directories, triggering a denial-of-service against any developer tooling that attempts to analyze packages depending on it. [1](#0-0) 

## Finding Description

The vulnerability exists in two `.unwrap()` calls that handle dependency source and bytecode retrieval without proper error handling:

1. **Line 49**: `pkg.get_sources(&self.resolution_graph.build_options).unwrap()`
2. **Line 53**: `pkg.get_bytecodes().unwrap()`

These methods can fail when:

**Primary Attack Vector (get_sources failure):**
The `get_sources()` method calls `get_source_paths_for_config()` which unconditionally adds the `sources/` directory path because it is marked as non-optional in the package layout specification. [2](#0-1) 

When `get_source_paths_for_config()` adds paths, it only skips optional directories that don't exist. The `Sources` directory is non-optional, so it gets added regardless: [3](#0-2) 

Subsequently, `find_move_filenames()` calls `find_filenames()`, which explicitly bails when a path doesn't exist: [4](#0-3) 

**Secondary Attack Vector (get_bytecodes failure):**
Similarly, `get_bytecodes()` can fail if the build directory contains paths with non-Unicode characters: [5](#0-4) 

**Exploitation Path:**
1. Attacker creates a malicious Move package with a valid `Move.toml` manifest but missing the `sources/` directory
2. Package is distributed as a dependency (via git, local path, or package registry)
3. Victim's package depends on this malicious package
4. Victim runs any tool that invokes `build_model()`:
   - Move Prover (`move prove`)
   - Documentation generator (`move docgen`)
   - Error map generator (`move errmap`)
   - Framework builds using `BuiltPackage::build()`
5. The `build_model()` function attempts to process dependencies
6. When processing the malformed dependency, `get_sources()` returns an error
7. The `.unwrap()` panics, crashing the entire process

This affects critical Aptos infrastructure including framework compilation: [6](#0-5) 

## Impact Explanation

**High Severity** - This vulnerability causes API crashes and halts the compilation pipeline, meeting the High severity criteria in the Aptos bug bounty program:

- **Developer Tooling Denial of Service**: Any developer using Move Prover, documentation generation, or error map generation on packages with malformed dependencies will experience immediate crashes
- **Framework Build Disruption**: Aptos framework builds that use model building can be disrupted
- **Supply Chain Attack Vector**: Malicious actors can distribute trojan dependencies that appear valid but break dependent projects
- **No Recovery Without Manual Intervention**: Developers must manually identify and remove the malformed dependency to restore functionality

While this doesn't directly impact consensus or validator operations, it disrupts the development ecosystem and can be weaponized to prevent legitimate development work.

## Likelihood Explanation

**High Likelihood**:
- **Trivial to Exploit**: Creating a malformed package requires only removing the `sources/` directory while keeping `Move.toml`
- **Widespread Exposure**: Any package that depends on the malformed package is vulnerable
- **No Authentication Required**: The attack works through public package distribution channels
- **Difficult to Detect**: The malformed package appears valid during dependency resolution; the panic only occurs during model building
- **Common Operations Affected**: Developers routinely run prover, documentation, and build tools

The attack complexity is minimal, requiring no special privileges or insider access.

## Recommendation

Replace `.unwrap()` calls with proper error handling that propagates errors gracefully:

```rust
// In build_model() around lines 47-55
let mut dep_source_paths = pkg
    .get_sources(&self.resolution_graph.build_options)?;  // Remove .unwrap()
let mut source_available = true;
// If source is empty, search bytecode
if dep_source_paths.is_empty() {
    dep_source_paths = pkg.get_bytecodes()?;  // Remove .unwrap()
    source_available = false;
}
```

Additionally, consider defensive validation in `get_source_paths_for_config()` to check directory existence for non-optional paths before adding them, providing clearer error messages:

```rust
fn get_source_paths_for_config(
    package_path: &Path,
    config: &BuildConfig,
) -> Result<Vec<PathBuf>> {
    let mut places_to_look = Vec::new();
    let mut add_path = |layout_path: SourcePackageLayout| {
        let path = package_path.join(layout_path.path());
        if layout_path.is_optional() && !path.exists() {
            return Ok(());
        }
        // Add validation for non-optional paths
        if !layout_path.is_optional() && !path.exists() {
            bail!(
                "Required directory '{}' does not exist in package at '{}'",
                layout_path.location_str(),
                package_path.display()
            );
        }
        places_to_look.push(path);
        Ok(())
    };
    
    add_path(SourcePackageLayout::Sources)?;
    add_path(SourcePackageLayout::Scripts)?;
    
    if config.dev_mode {
        add_path(SourcePackageLayout::Examples)?;
        add_path(SourcePackageLayout::Tests)?;
    }
    Ok(places_to_look)
}
```

## Proof of Concept

**Setup:**
```bash
# Create malformed dependency package
mkdir malicious_dep
cd malicious_dep
cat > Move.toml << EOF
[package]
name = "MaliciousDep"
version = "0.0.1"

[addresses]
malicious = "0x42"
EOF
# Note: intentionally NOT creating sources/ directory

cd ..

# Create victim package that depends on it
mkdir victim_package
cd victim_package
cat > Move.toml << EOF
[package]
name = "VictimPackage"
version = "0.0.1"

[dependencies]
MaliciousDep = { local = "../malicious_dep" }

[addresses]
victim = "0x1"
EOF

mkdir sources
cat > sources/main.move << EOF
module victim::main {
    public fun hello() {}
}
EOF
```

**Trigger the vulnerability:**
```bash
# Any of these commands will panic:
move prove
move docgen
move build --generate-docs
```

**Expected behavior (without fix):**
```
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: 
No such file or directory '../malicious_dep/sources'
```

**Expected behavior (with fix):**
```
Error: Failed to build model: Required directory 'sources' does not exist 
in package at '../malicious_dep'
```

## Notes

This vulnerability specifically affects the Move package toolchain's model building phase, which is separate from runtime Move VM execution. However, it represents a significant supply chain security risk in the Move ecosystem, as malformed packages can be distributed to disrupt legitimate development workflows. The fix is straightforward and should be applied to all similar patterns where dependency paths are accessed without proper error handling.

### Citations

**File:** third_party/move/tools/move-package/src/compilation/model_builder.rs (L47-55)
```rust
                let mut dep_source_paths = pkg
                    .get_sources(&self.resolution_graph.build_options)
                    .unwrap();
                let mut source_available = true;
                // If source is empty, search bytecode
                if dep_source_paths.is_empty() {
                    dep_source_paths = pkg.get_bytecodes().unwrap();
                    source_available = false;
                }
```

**File:** third_party/move/tools/move-package/src/source_package/layout.rs (L66-76)
```rust
    pub fn is_optional(&self) -> bool {
        match self {
            Self::Sources | Self::Manifest => false,
            Self::Tests
            | Self::Scripts
            | Self::Examples
            | Self::Specifications
            | Self::DocTemplates
            | Self::Build => true,
        }
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L652-673)
```rust
    fn get_source_paths_for_config(
        package_path: &Path,
        config: &BuildConfig,
    ) -> Result<Vec<PathBuf>> {
        let mut places_to_look = Vec::new();
        let mut add_path = |layout_path: SourcePackageLayout| {
            let path = package_path.join(layout_path.path());
            if layout_path.is_optional() && !path.exists() {
                return;
            }
            places_to_look.push(path)
        };

        add_path(SourcePackageLayout::Sources);
        add_path(SourcePackageLayout::Scripts);

        if config.dev_mode {
            add_path(SourcePackageLayout::Examples);
            add_path(SourcePackageLayout::Tests);
        }
        Ok(places_to_look)
    }
```

**File:** third_party/move/move-command-line-common/src/files.rs (L70-72)
```rust
        if !path.exists() {
            bail!("No such file or directory '{}'", path.to_string_lossy())
        }
```

**File:** third_party/move/move-command-line-common/src/files.rs (L120-125)
```rust
pub fn path_to_string(path: &Path) -> anyhow::Result<String> {
    match path.to_str() {
        Some(p) => Ok(p.to_string()),
        None => Err(anyhow!("non-Unicode file name")),
    }
}
```

**File:** aptos-move/framework/src/built_package.rs (L220-231)
```rust
        },
    };
    let compiler_version = compiler_version.unwrap_or_default();
    let language_version = language_version.unwrap_or_default();
    compiler_version.check_language_support(language_version)?;
    build_config.move_model_for_package(package_path, ModelConfig {
        target_filter,
        all_files_as_targets: false,
        compiler_version,
        language_version,
    })
}
```
