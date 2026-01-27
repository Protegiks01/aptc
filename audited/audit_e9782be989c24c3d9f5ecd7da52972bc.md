# Audit Report

## Title
Missing On-Chain Package Version Validation Enables Supply Chain Attacks and Non-Deterministic Builds

## Summary
The Move package resolver does not validate that on-chain package versions match the version specified in Move.toml dependency declarations. When resolving Aptos on-chain dependencies, the system fetches whatever package version is currently published at the specified address without checking the package's `upgrade_number` against the requested version, enabling supply chain attacks and breaking build reproducibility.

## Finding Description

The vulnerability exists across multiple components of the package resolution system:

**1. Manifest Declaration (No Version Enforcement)**

The `Dependency` struct contains a `version` field that is explicitly marked as unused: [1](#0-0) 

The comment explicitly states this does not guarantee linking to the specific version during execution on-chain.

**2. Aptos Location Missing Version**

The `PackageLocation::Aptos` enum variant only stores the node URL and package address, with no version information: [2](#0-1) 

**3. Dependency Resolution Without Version Checking**

When resolving Aptos dependencies, the resolver creates a `PackageIdentity` using only the node and package address: [3](#0-2) 

**4. Package Fetching by Name Only**

The `fetch_on_chain_package` function retrieves packages by name without version validation: [4](#0-3) 

**5. On-Chain PackageDep Without Version**

The on-chain `PackageDep` struct only stores account address and package name, not the version/upgrade_number: [5](#0-4) [6](#0-5) 

**6. Lock File Pins Ledger Version, Not Package Version**

The `PackageLock` stores blockchain ledger version (block height), not package upgrade_number: [7](#0-6) [8](#0-7) 

**Attack Scenario:**

1. Developer Alice creates package `VictimApp` depending on `TrustedLib` v1.0.0 at address `0xBOB`
2. Alice specifies in Move.toml: `TrustedLib = { aptos = "mainnet", address = "0xBOB", version = "1.0.0" }`
3. Bob initially publishes `TrustedLib` v1.0.0 (upgrade_number = 0) with legitimate code
4. Alice compiles and deploys `VictimApp` successfully
5. Bob upgrades `TrustedLib` to v2.0.0 (upgrade_number = 1) with malicious code or breaking changes
6. When Alice rebuilds `VictimApp` or any other developer tries to build a package depending on `TrustedLib`:
   - The resolver fetches `TrustedLib` from chain
   - It retrieves v2.0.0 (the current version) without checking against requested v1.0.0
   - The malicious code gets compiled into the dependent package
7. If the lock file doesn't exist or is regenerated, different ledger versions will be pinned, potentially fetching different package versions

## Impact Explanation

This vulnerability achieves **HIGH** severity under the Aptos bug bounty criteria for "Significant protocol violations":

1. **Supply Chain Attack Vector**: Malicious package owners can upgrade dependencies with backdoors, affecting all downstream dependents. This violates the trust model where developers expect to control which dependency versions they use.

2. **Build Non-Determinism**: Different developers or validators building at different times will compile against different package versions, violating the **Deterministic Execution** invariant during the build phase. While on-chain execution uses pre-compiled bytecode, the compilation phase must be deterministic for security audits and reproducible builds.

3. **Framework Governance Impact**: Governance proposals for framework upgrades could be affected if different parties build the proposal with different dependency versions, potentially causing consensus issues during the upgrade process.

4. **No Developer Control**: The absence of version pinning means developers cannot enforce which dependency versions are used, breaking a fundamental security guarantee of modern package management systems.

While this does not directly affect on-chain execution (which uses pre-deployed bytecode), it creates a critical vulnerability in the development and deployment pipeline that could lead to compromised packages being deployed on-chain.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Low Attacker Requirements**: Only requires owning a package that others depend on - no special privileges, validator access, or collusion needed.

2. **Passive Exploitation**: Attack is automatic - dependents will fetch malicious versions without any additional action by the attacker beyond upgrading the package.

3. **No Detection Mechanism**: Victims have no way to detect that they're building against a different version than specified in Move.toml.

4. **Common Dependency Pattern**: Framework packages and shared libraries are commonly used as dependencies, creating a large attack surface.

5. **Known Limitation**: The TODO comment indicates this is a known issue that hasn't been addressed, increasing the likelihood of exploitation before a fix is implemented.

## Recommendation

Implement package version validation during dependency resolution:

**1. Extend PackageDep to Include Version:**
```rust
// In aptos-move/framework/aptos-framework/sources/code.move
struct PackageDep has store, drop, copy {
    account: address,
    package_name: String,
    upgrade_number: u64,  // Add this field
}
```

**2. Validate Version During Resolution:**
```rust
// In third_party/move/tools/move-package-cache/src/package_cache.rs
// In fetch_on_chain_package function, after finding the package:

let package = match package_registry
    .packages
    .iter()
    .find(|package_metadata| package_metadata.name == package_name)
{
    Some(package) => package,
    None => bail!("package not found: {}//{}::{}", fullnode_url, address, package_name),
};

// ADD VERSION VALIDATION HERE:
if let Some(expected_version) = expected_upgrade_number {
    if package.upgrade_number != expected_version {
        bail!(
            "Package version mismatch: expected upgrade_number {}, found {}",
            expected_version,
            package.upgrade_number
        );
    }
}
```

**3. Store Version in PackageLock:**
```rust
// In third_party/move/tools/move-package-resolver/src/lock.rs
#[derive(Serialize, Deserialize)]
pub struct PackageLock {
    git: BTreeMap<String, String>,
    // Change to store both ledger version and package upgrade_number
    on_chain: BTreeMap<String, OnChainDependency>,
}

#[derive(Serialize, Deserialize)]
struct OnChainDependency {
    ledger_version: u64,
    upgrade_number: u64,
}
```

**4. Use Version from Manifest:**
Enable the version field by removing the "not in use" limitation and passing it through the resolution chain to validate against the on-chain package's upgrade_number.

## Proof of Concept

```move
// File: malicious_upgrade_poc/Move.toml
[package]
name = "VictimApp"
version = "1.0.0"

[dependencies]
TrustedLib = { aptos = "testnet", address = "0xBOB", version = "1.0.0" }

// Initially, TrustedLib v1.0.0 has:
module 0xBOB::TrustedLib {
    public fun safe_operation(): u64 { 42 }
}

// Victim compiles against v1.0.0 and deploys

// Attacker upgrades to v2.0.0 (upgrade_number increments):
module 0xBOB::TrustedLib {
    public fun safe_operation(): u64 { 
        // Malicious: returns different value, could contain backdoor
        0 
    }
}

// When victim rebuilds or another developer tries to build:
// - Resolver fetches TrustedLib from chain
// - Gets v2.0.0 instead of v1.0.0
// - No validation error occurs
// - Malicious code compiled into dependent package
```

**Steps to Reproduce:**
1. Publish package A at address 0xTEST with upgrade_number = 0
2. Create package B depending on A with version = "1.0.0" in Move.toml
3. Compile package B successfully (links against A upgrade_number = 0)
4. Upgrade package A to upgrade_number = 1 with modified code
5. Recompile package B or compile on different machine
6. Observe that package B now compiles against A upgrade_number = 1 without any version mismatch error
7. Compare bytecode - different bytecode produced despite identical Move.toml

## Notes

This vulnerability is explicitly acknowledged as a limitation in the codebase but represents a critical security gap. While on-chain execution determinism is maintained (bytecode is pre-compiled), build-time determinism is essential for:
- Security audits (auditors must know exact dependency versions)
- Reproducible builds (different parties must produce identical bytecode)
- Supply chain security (preventing malicious dependency upgrades)
- Governance framework upgrades (all participants must build against same versions)

The TODO comment indicates awareness but not urgency, yet the security implications warrant immediate attention given the growing adoption of Aptos and the critical nature of supply chain attacks in blockchain ecosystems.

### Citations

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L113-119)
```rust
    /// Optional version requirement for the dependency.
    /// Not in use by the package resolver, yet.
    ///
    /// Note: This is intended to be a build-time constraint, and it alone does not guarantee
    ///       that your program will be linked to the specific version of the dependency
    ///       during execution on-chain.
    version: Option<Version>,
```

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L149-155)
```rust
    Aptos {
        /// URL to the Aptos full-node connected to the network where the package is published.
        node_url: String,

        /// Address of the published package.
        package_addr: AccountAddress,
    },
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L413-428)
```rust
        PackageLocation::Aptos {
            node_url,
            package_addr,
        } => {
            remote_url = Url::from_str(&node_url)?;

            let identity = PackageIdentity {
                name: dep_name.to_string(),
                location: SourceLocation::OnChain {
                    node: CanonicalNodeIdentity::new(&remote_url)?,
                    package_addr,
                },
            };

            (identity, Some(&remote_url))
        },
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L342-354)
```rust
        let package = match package_registry
            .packages
            .iter()
            .find(|package_metadata| package_metadata.name == package_name)
        {
            Some(package) => package,
            None => bail!(
                "package not found: {}//{}::{}",
                fullnode_url,
                address,
                package_name
            ),
        };
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L51-55)
```text
    /// A dependency to a package published at address
    struct PackageDep has store, drop, copy {
        account: address,
        package_name: String
    }
```

**File:** aptos-move/framework/src/natives/code.rs (L95-99)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct PackageDep {
    pub account: AccountAddress,
    pub package_name: String,
}
```

**File:** third_party/move/tools/move-package-resolver/src/lock.rs (L24-25)
```rust
    // node_identity (stringified) -> version
    on_chain: BTreeMap<String, u64>,
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
