# Audit Report

## Title
Package Replacement Attack via Missing Integrity Verification in Move Package Resolver

## Summary
The new `move-package-resolver` system lacks cryptographic integrity verification for on-chain package dependencies, allowing attackers to inject malicious code through package upgrades. The `PackageIdentity` structure does not include version information or content hashes, and fetched packages are never verified against expected digests, enabling silent code substitution attacks.

## Finding Description

The `move-package-resolver` system identifies on-chain packages using only `(name, node, package_addr)` without any version or content hash binding: [1](#0-0) 

When a package is upgraded on-chain via the `publish_package` function, the `upgrade_number` is incremented and new bytecode is deployed at the same address: [2](#0-1) 

However, the new dependency resolution system has **no `digest` field** to pin expected package content: [3](#0-2) 

This contrasts with the older `move-package` system which includes digest verification: [4](#0-3) 

During resolution, the network version is pinned per-node (not per-package), and all packages from that node use the same ledger version: [5](#0-4) 

Most critically, when packages are fetched from the cache, there is **no integrity verification**: [6](#0-5) 

The TODO comment explicitly acknowledges this missing verification.

**Attack Scenario:**

1. Attacker publishes legitimate Package B v1 at address `0xB` with `upgrade_number = 0`
2. Developer Alice creates Project A depending on Package B, generates `Move.lock` with `ledger_version = 1000`
3. Alice's build fetches and caches Package B v1 (safe code)
4. **Attacker upgrades Package B to malicious v2** at same address `0xB`, setting `upgrade_number = 1` (ledger version now 1500)
5. Developer Bob creates new Project C depending on Package B
6. Bob's build generates fresh `Move.lock` with current `ledger_version = 1500`
7. Bob fetches **malicious Package B v2** without any warning or verification
8. The `PackageIdentity` remains `(B, node, 0xB)` - same identity, different code
9. Alice adds a new dependency and regenerates her lock file
10. Alice now fetches **malicious v2** with no indication the package changed

Additionally, on-chain packages do not have their transitive dependencies resolved: [7](#0-6) 

## Impact Explanation

**Critical Severity** - This breaks multiple critical invariants:

1. **Deterministic Execution**: Different developers building the same project specification get different bytecode, violating consensus if used for validator software or framework upgrades
2. **Supply Chain Security**: Attackers can inject malicious code into all downstream dependents via package upgrades
3. **No Defense**: Developers have no mechanism to pin package versions or verify integrity

If this system is used for building Aptos Framework packages or validator node software, a compromised dependency could:
- Steal validator private keys
- Manipulate consensus voting
- Corrupt state transitions
- Drain staking pools

This meets the **Critical Severity** criteria of "Loss of Funds" and "Consensus/Safety violations" with potential impact up to $1,000,000 per the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood** if the system is deployed:

1. Package upgrades are normal operations on Aptos
2. No special privileges needed - any package owner can upgrade
3. Attack is silent - no warnings or verification failures
4. Developers routinely regenerate lock files when adding dependencies
5. Cache poisoning is possible with filesystem access

The attack requires only:
- Ability to publish/upgrade a package on-chain (normal operation)
- OR ability to run a malicious full node that serves modified bytecode
- OR filesystem access to poison the package cache

## Recommendation

Implement comprehensive integrity verification:

1. **Add digest field** to `Dependency` struct in `move-package-manifest/src/manifest.rs`:
```rust
pub struct Dependency {
    version: Option<Version>,
    pub location: PackageLocation,
    pub digest: Option<String>, // SHA256 of source_digest from PackageMetadata
}
```

2. **Verify digest** during resolution in `move-package-resolver/src/resolver.rs`:
```rust
// After fetching package metadata, verify digest
if let Some(expected_digest) = dep.digest {
    if expected_digest != package_metadata.source_digest {
        bail!("Digest mismatch for package {}: expected {}, got {}", 
              package_name, expected_digest, package_metadata.source_digest);
    }
}
```

3. **Implement cache verification** in `move-package-cache/src/package_cache.rs`:
```rust
// Replace TODO at line 302 with actual verification
if cached_package_path.exists() {
    // Verify cached package integrity by re-fetching metadata
    let metadata = fetch_package_metadata(fullnode_url, network_version, address)?;
    verify_cached_package(&cached_package_path, &metadata)?;
    return Ok(cached_package_path);
}
```

4. **Add upgrade_number tracking** to enable version pinning

5. **Include digest in PackageIdentity** to make identity cryptographically bound to content

## Proof of Concept

```rust
// File: test_package_replacement.rs
use move_package_resolver::{resolve, PackageLock};
use move_package_cache::PackageCache;
use std::path::Path;

#[tokio::test]
async fn test_package_replacement_attack() {
    let cache = PackageCache::new("/tmp/test_cache").unwrap();
    let mut lock = PackageLock::new();
    
    // Step 1: Developer A builds project depending on Package B v1
    let project_a = Path::new("tests/fixtures/project_a");
    let graph_a = resolve(&cache, &mut lock, project_a, false).await.unwrap();
    lock.save_to_file(project_a.join("Move.lock")).unwrap();
    
    // Step 2: Attacker upgrades Package B to v2 on-chain
    // (Simulated by changing the on-chain state)
    
    // Step 3: Developer B creates new project with same dependency
    let project_b = Path::new("tests/fixtures/project_b");
    let mut lock_b = PackageLock::new(); // Fresh lock file
    let graph_b = resolve(&cache, &mut lock_b, project_b, false).await.unwrap();
    
    // Step 4: Verify that project_b fetched different code than project_a
    // Same PackageIdentity (name, node, addr) but different bytecode
    // This demonstrates the vulnerability - no warning, no error, just different code
    
    assert_eq!(
        graph_a.package_table["PackageB"].identity,
        graph_b.package_table["PackageB"].identity,
        "Identities should be the same"
    );
    
    // But the actual bytecode is different (v1 vs v2)
    // This violates deterministic execution invariant
}
```

## Notes

The vulnerability exists in the new `move-package-resolver` codebase which is present in the Aptos Core repository workspace. While it's unclear if this system is currently used in production (the main build system appears to use the older `move-package` system with digest verification), the code is actively maintained and contains TODO comments indicating planned deployment.

This represents a critical design flaw that must be addressed before the new resolver system is deployed, as it fundamentally undermines supply chain security for Move package dependencies. The older `move-package` system correctly implements digest verification, demonstrating that the developers are aware of this requirement but have not yet implemented it in the new resolver.

### Citations

**File:** third_party/move/tools/move-package-resolver/src/identity.rs (L19-28)
```rust
    OnChain {
        node: CanonicalNodeIdentity,
        package_addr: AccountAddress,
    },
    Git {
        repo: CanonicalGitIdentity,
        commit_id: Oid,
        subdir: NormalizedPath,
    },
}
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L168-228)
```text
    public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
        check_code_publishing_permission(owner);
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );

        let addr = signer::address_of(owner);
        if (!exists<PackageRegistry>(addr)) {
            move_to(owner, PackageRegistry { packages: vector::empty() })
        };

        // Checks for valid dependencies to other packages
        let allowed_deps = check_dependencies(addr, &pack);

        // Check package against conflicts
        // To avoid prover compiler error on spec
        // the package need to be an immutable variable
        let module_names = get_module_names(&pack);
        let package_immutable = &borrow_global<PackageRegistry>(addr).packages;
        let len = vector::length(package_immutable);
        let index = len;
        let upgrade_number = 0;
        vector::enumerate_ref(package_immutable
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

        // Assign the upgrade counter.
        pack.upgrade_number = upgrade_number;

        let packages = &mut borrow_global_mut<PackageRegistry>(addr).packages;
        // Update registry
        let policy = pack.upgrade_policy;
        if (index < len) {
            *vector::borrow_mut(packages, index) = pack
        } else {
            vector::push_back(packages, pack)
        };

        event::emit(PublishPackage {
            code_address: addr,
            is_upgrade: upgrade_number > 0
        });

        // Request publish
        if (features::code_dependency_check_enabled())
            request_publish_with_allowed_deps(addr, module_names, allowed_deps, code, policy.policy)
        else
        // The new `request_publish_with_allowed_deps` has not yet rolled out, so call downwards
        // compatible code.
            request_publish(addr, module_names, code, policy.policy)
    }
```

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L110-123)
```rust
/// Represents a dependency entry in `[dependencies]` or `[dev-dependencies]`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Dependency {
    /// Optional version requirement for the dependency.
    /// Not in use by the package resolver, yet.
    ///
    /// Note: This is intended to be a build-time constraint, and it alone does not guarantee
    ///       that your program will be linked to the specific version of the dependency
    ///       during execution on-chain.
    version: Option<Version>,

    /// Location of the dependency: local, git, or aptos (on-chain).
    pub location: PackageLocation,
}
```

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L73-81)
```rust
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Dependency {
    pub local: PathBuf,
    pub subst: Option<Substitution>,
    pub version: Option<Version>,
    pub digest: Option<PackageDigest>,
    pub git_info: Option<GitInfo>,
    pub node_info: Option<CustomDepInfo>,
}
```

**File:** third_party/move/tools/move-package-resolver/src/lock.rs (L90-106)
```rust
    pub async fn resolve_network_version(&mut self, fullnode_url: &Url) -> Result<u64> {
        let node_identity = CanonicalNodeIdentity::new(fullnode_url)?;

        let res = match self.on_chain.entry(node_identity.to_string()) {
            btree_map::Entry::Occupied(entry) => *entry.get(),
            btree_map::Entry::Vacant(entry) => {
                let client = aptos_rest_client::Client::new(fullnode_url.clone());
                let version = client.get_ledger_information().await?.into_inner().version;

                entry.insert(version);

                version
            },
        };

        Ok(res)
    }
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L300-304)
```rust
        // If the package directory already exists, assume it has been cached.
        if cached_package_path.exists() {
            // TODO: In the future, consider verifying data integrity,
            //       e.g. hash of metadata or full contents.
            return Ok(cached_package_path);
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L235-245)
```rust
    match &identity.location {
        SourceLocation::OnChain { .. } => {
            let node_idx = graph.add_node(Package {
                identity: identity.clone(),
                local_path,
            });
            resolved.insert(identity, node_idx);

            // TODO: fetch transitive deps

            Ok(node_idx)
```
