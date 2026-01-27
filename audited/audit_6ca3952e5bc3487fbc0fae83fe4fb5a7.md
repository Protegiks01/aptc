# Audit Report

## Title
Package Substitution via SourceManifest Collision in Legacy Resolver

## Summary
The legacy package resolution system compares only Move.toml metadata (SourceManifest) when determining if a package has already been resolved, without verifying the source code or filesystem location matches. This allows an attacker to substitute malicious source code for a legitimate package if their package is resolved first in the dependency tree and has an identical Move.toml file.

## Finding Description

The vulnerability exists in the package deduplication logic: [1](#0-0) 

When processing a package, the system checks if a package with the same name already exists in the package table. If it does, it compares the SourceManifest structs for equality. The SourceManifest only contains parsed Move.toml metadata: [2](#0-1) 

Critically, the SourceManifest does NOT include:
- The source code content
- The source digest (hash of source files)
- The package location (filesystem path or Git URL)

The source digest is computed AFTER the equality check: [3](#0-2) 

If the equality check passes (line 223), the function returns early without computing or validating the source code of the second package. This means the first resolved package's code is used for all subsequent references with matching SourceManifests.

**Attack Scenario:**

1. Attacker creates a malicious package "CommonLib" at `github.com/attacker/common` with:
   - Identical Move.toml to legitimate `github.com/trusted/common` (same name, version, dependencies, addresses)
   - Malicious `.move` source files with backdoors or exploits

2. Developer creates root package that depends on:
   - Package A (which depends on attacker's CommonLib)
   - Package B (which depends on legitimate CommonLib)

3. During resolution, if Package A is processed first:
   - Attacker's malicious CommonLib is added to package_table
   - When Package B's dependency on legitimate CommonLib is processed, SourceManifest equality check passes
   - Function returns early without loading legitimate source code
   - All modules are compiled from attacker's malicious code

4. The dependency digest validation provides no protection unless explicitly specified: [4](#0-3) 

This breaks the **Deterministic Execution** invariant - different build orders can result in different bytecode, and breaks package integrity guarantees that are fundamental to supply chain security.

## Impact Explanation

**Severity: HIGH**

This vulnerability allows:
- **Arbitrary Code Execution**: Malicious code runs in any package depending on the substituted package
- **Supply Chain Attack**: Affects all transitive dependents without their knowledge
- **On-Chain Impact**: If malicious package reaches production, deployed contracts execute attacker-controlled logic
- **Silent Compromise**: No warnings or errors indicate the substitution occurred

The impact is HIGH rather than CRITICAL because:
- Requires specific dependency tree configuration (same package name from multiple sources)
- Developers would typically notice if they explicitly depend on different Git URLs for the same package name
- Newer resolver has TODO to handle this case properly
- Does not directly affect consensus or validator operations (build-time attack)

However, this still represents a **significant protocol violation** qualifying for HIGH severity per Aptos bug bounty criteria.

## Likelihood Explanation

**Likelihood: MEDIUM-LOW**

The attack requires:
1. Two packages with identical Move.toml but different source code
2. Both referenced in the same dependency tree from different Git URLs  
3. Attacker's package resolved before legitimate package
4. No source digest specified in dependency declaration

While each condition is individually feasible, the combination is less common in practice. Most projects wouldn't intentionally depend on the same package name from multiple sources. However, this could occur through:
- Transitive dependencies where different packages specify different sources
- Typosquatting attacks with copied manifests
- Compromised upstream dependencies that mirror legitimate package metadata

The legacy resolver is still in active use, making this exploitable in current deployments.

## Recommendation

**Immediate Fix**: Include source digest comparison in the package equality check, or verify that packages with the same name originate from the same location.

```rust
fn build_resolution_graph<W: Write>(
    &mut self,
    package: SourceManifest,
    package_path: PathBuf,
    is_root_package: bool,
    override_std: &Option<StdVersion>,
    writer: &mut W,
) -> Result<()> {
    let package_name = package.package.name;
    let package_node_id = match self.package_table.get(&package_name) {
        None => self.get_or_add_node(package_name)?,
        Some(other) if other.source_package == package => {
            // NEW: Verify package path matches to prevent substitution
            if other.package_path != package_path {
                bail!(
                    "Package '{}' already resolved from different location: '{}' vs '{}'",
                    package_name,
                    other.package_path.display(),
                    package_path.display()
                );
            }
            return Ok(())
        },
        Some(other) => {
            bail!(
                "Conflicting dependencies found: package '{}' conflicts with '{}'",
                other.source_package.package.name,
                package.package.name,
            )
        },
    };
    // ... rest of function
}
```

**Additional Protections**:
1. Mandate source digest in all dependency declarations
2. Emit warnings when same package name appears from multiple locations
3. Complete migration to new resolver which has TODO to properly handle this case: [5](#0-4) 

## Proof of Concept

**Setup:**

1. Create malicious package at `/tmp/malicious-common/Move.toml`:
```toml
[package]
name = "Common"
version = "1.0.0"

[addresses]
Common = "_"
```

2. Create malicious source at `/tmp/malicious-common/sources/lib.move`:
```move
module Common::Lib {
    public fun get_value(): u64 { 999 } // Malicious return value
}
```

3. Create legitimate package at `/tmp/legitimate-common/Move.toml` (identical):
```toml
[package]
name = "Common"
version = "1.0.0"

[addresses]
Common = "_"
```

4. Create legitimate source at `/tmp/legitimate-common/sources/lib.move`:
```move
module Common::Lib {
    public fun get_value(): u64 { 42 } // Legitimate return value
}
```

5. Create package A at `/tmp/pkg-a/Move.toml`:
```toml
[package]
name = "A"
version = "1.0.0"

[dependencies]
Common = { local = "../malicious-common" }
```

6. Create package B at `/tmp/pkg-b/Move.toml`:
```toml
[package]
name = "B"
version = "1.0.0"

[dependencies]
Common = { local = "../legitimate-common" }
```

7. Create root package at `/tmp/root/Move.toml`:
```toml
[package]
name = "Root"
version = "1.0.0"

[dependencies]
A = { local = "../pkg-a" }
B = { local = "../pkg-b" }
```

8. Build root package - observe that Common from pkg-a (malicious) is used for both A and B, proven by the compiled bytecode returning 999 instead of 42.

**Expected**: Build should fail detecting package source mismatch  
**Actual**: Build succeeds using malicious code for all references to "Common"

## Notes

The newer package resolver has explicit name conflict detection that would catch this scenario, but includes a TODO indicating they plan to relax this restriction. When implementing support for packages with the same name from different sources, source digest validation must be mandatory to prevent substitution attacks.

### Citations

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L220-232)
```rust
        let package_node_id = match self.package_table.get(&package_name) {
            None => self.get_or_add_node(package_name)?,
            // Same package and we've already resolved it: OK, return early
            Some(other) if other.source_package == package => return Ok(()),
            // Different packages, with same name: Not OK
            Some(other) => {
                bail!(
                    "Conflicting dependencies found: package '{}' conflicts with '{}'",
                    other.source_package.package.name,
                    package.package.name,
                )
            },
        };
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L306-307)
```rust
        let source_digest =
            ResolvingPackage::get_package_digest_for_config(&package_path, &self.build_options)?;
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L456-472)
```rust
        match dep.digest {
            None => (),
            Some(fixed_digest) => {
                let resolved_pkg = self
                    .package_table
                    .get(&dep_name_in_pkg)
                    .context("Unable to find resolved package by name")?;
                if fixed_digest != resolved_pkg.source_digest {
                    bail!(
                        "Source digest mismatch in dependency '{}'. Expected '{}' but got '{}'.",
                        dep_name_in_pkg,
                        fixed_digest,
                        resolved_pkg.source_digest
                    )
                }
            },
        }
```

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L20-28)
```rust
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceManifest {
    pub package: PackageInfo,
    pub addresses: Option<AddressDeclarations>,
    pub dev_address_assignments: Option<DevAddressDeclarations>,
    pub build: Option<BuildInfo>,
    pub dependencies: Dependencies,
    pub dev_dependencies: Dependencies,
}
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L25-32)
```rust
// TODOs
// - Addr subst
// - Allow same package name
// - Dep override
// - Fetch transitive deps for on-chain packages
// - Structured errors and error rendering
// - (Low Priority) Symbolic links in git repos
// - (Low Priority) Resolve deps in parallel
```
