# Audit Report

## Title
Bytecode Poisoning via TOCTOU Race Condition and Missing Integrity Verification in Package Download

## Summary
The `DownloadPackage::execute()` function downloads Move package metadata and bytecode without ledger version pinning or cryptographic verification. This allows an attacker to exploit a Time-of-Check-Time-of-Use (TOCTOU) race condition to inject malicious bytecode that differs from the on-chain source code, enabling supply chain attacks against developers.

## Finding Description

The vulnerability exists in how the Aptos CLI downloads Move packages with the `--bytecode` flag. The download process consists of two separate, non-atomic operations:

1. **Fetching PackageRegistry metadata** (containing source digest and module names) [1](#0-0) 

2. **Fetching individual module bytecode** for each module [2](#0-1) 

**Critical Flaws:**

1. **No Ledger Version Pinning**: Both API calls use the default behavior without specifying a `ledger_version` parameter, meaning they query the latest state independently: [3](#0-2) [4](#0-3) 

2. **No Bytecode Hash in Metadata**: The `PackageMetadata` structure only stores `source_digest` (hash of source code), not bytecode hash: [5](#0-4) [6](#0-5) 

3. **No Verification Before Saving**: Downloaded bytecode is saved directly to disk without any integrity check: [7](#0-6) [8](#0-7) 

**Attack Scenario:**

1. Attacker publishes `PackageV1` at ledger version L1 with legitimate source code S1 and bytecode B1
2. Developer executes: `aptos move download --account <attacker> --package MyPackage --bytecode`
3. Client fetches `PackageRegistry` at ledger version L1 → receives metadata with `source_digest(S1)`
4. **Attacker immediately upgrades to `PackageV2`** at ledger version L2 with malicious bytecode B2
5. Client fetches module bytecode at ledger version L2 → receives malicious bytecode B2
6. Developer now has:
   - Source code S1 (from metadata, appears legitimate)
   - Source digest for S1 (appears legitimate)
   - **Malicious bytecode B2** (saved to disk)
   - No error or warning issued

The developer integrates what appears to be legitimate code but contains poisoned bytecode, enabling arbitrary malicious behavior in their application.

## Impact Explanation

**Critical Severity** - This vulnerability enables a sophisticated supply chain attack:

- **Supply Chain Compromise**: Developers downloading packages with `--bytecode` receive malicious bytecode that differs from the source code they can review
- **Silent Failure**: No verification errors occur; the poisoned package appears legitimate
- **Wide Attack Surface**: Any published package can be exploited; developers commonly download popular packages
- **Arbitrary Code Execution**: Malicious bytecode can steal funds, manipulate state, or compromise dependent applications
- **Persistent Threat**: Once integrated, the malicious bytecode persists in the developer's project

This meets the **Critical** severity criteria per Aptos Bug Bounty:
- Potential for **Loss of Funds** through compromised applications
- **State Consistency** violations (downloaded code doesn't match on-chain source)
- Breaks the fundamental trust model of package downloads

## Likelihood Explanation

**High Likelihood:**

- **Easy to Execute**: Attacker only needs to control a publishing account and time an upgrade during a download window (typically seconds)
- **No Special Permissions**: Any account can publish packages; no validator access required
- **Common Operation**: Developers frequently download packages, especially popular libraries
- **Difficult to Detect**: The attack leaves no obvious traces; source code appears legitimate
- **Timing Window**: Even a narrow race window (milliseconds to seconds) is sufficient given network latency
- **Automation Possible**: Attacker can automate monitoring for download requests and triggering upgrades

The TOCTOU window exists because:
1. `PackageRegistry` fetch and module bytecode fetches are separate HTTP requests
2. Network latency creates a measurable gap between requests
3. No transaction-level atomicity guarantees across these operations

## Recommendation

Implement atomic, versioned package downloads with cryptographic verification:

**Fix 1: Pin Ledger Version Across All Fetches**

Modify `CachedPackageRegistry::create()` to:
1. First fetch the latest ledger version
2. Use that specific version for all subsequent queries

```rust
pub async fn create(url: Url, addr: AccountAddress, with_bytecode: bool) -> anyhow::Result<Self> {
    let client = Client::new(url);
    
    // Get PackageRegistry with version
    let registry_response = client
        .get_account_resource_bcs::<PackageRegistry>(addr, "0x1::code::PackageRegistry")
        .await?;
    let ledger_version = registry_response.state().version;
    let inner = registry_response.into_inner();
    
    let mut bytecode = BTreeMap::new();
    if with_bytecode {
        for pack in &inner.packages {
            for module in &pack.modules {
                // Use pinned ledger version
                let bytes = client
                    .get_account_module_bcs_at_version(addr, &module.name, ledger_version)
                    .await?
                    .into_inner()
                    .to_vec();
                bytecode.insert(module.name.clone(), bytes);
            }
        }
    }
    Ok(Self { inner, bytecode })
}
```

**Fix 2: Add Bytecode Hash to PackageMetadata**

Extend `PackageMetadata` and `ModuleMetadata` to include bytecode hashes:

```move
struct ModuleMetadata has copy, drop, store {
    name: String,
    source: vector<u8>,
    source_map: vector<u8>,
    bytecode_hash: String,  // ADD THIS: SHA3-256 hash of compiled bytecode
    extension: Option<Any>,
}
```

**Fix 3: Verify Downloaded Bytecode**

Add verification in `DownloadPackage::execute()`:

```rust
if self.bytecode {
    for module in package.module_names() {
        if let Some(bytecode) = registry.get_bytecode(module).await? {
            // Verify bytecode hash matches metadata
            let computed_hash = HashValue::sha3_256_of(bytecode);
            let expected_hash = package.module(module)?.bytecode_hash();
            if computed_hash.to_hex() != expected_hash {
                return Err(CliError::UnexpectedError(
                    format!("Bytecode hash mismatch for module {}", module)
                ));
            }
            package.save_bytecode_to_disk(package_path.as_path(), module, bytecode)?;
        }
    }
}
```

**Fix 4: Add Warning for Bytecode Downloads Without Verification**

Until cryptographic verification is implemented, warn users:

```rust
if self.bytecode {
    eprintln!("WARNING: Bytecode download cannot be cryptographically verified.");
    eprintln!("Downloaded bytecode may differ from on-chain source code.");
    eprintln!("Use 'aptos move verify-package' after download to verify integrity.");
}
```

## Proof of Concept

**Scenario Setup:**

1. **Attacker publishes initial package:**
```bash
# Attacker publishes legitimate PackageV1
aptos move publish --package-dir legitimate_package --named-addresses attacker=0xA11CE
```

2. **Developer starts download (in parallel with step 3):**
```bash
# Developer downloads package with bytecode
aptos move download --account 0xA11CE --package MyPackage --bytecode --output-dir ./downloaded
```

3. **Attacker triggers upgrade (during download):**
```bash
# Attacker immediately publishes malicious PackageV2
aptos move publish --package-dir malicious_package --named-addresses attacker=0xA11CE
```

**Exploitation Script:**

```rust
// Demonstrates the race condition
use aptos_rest_client::Client;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let client = Client::new("https://fullnode.mainnet.aptoslabs.com".parse().unwrap());
    let attacker_addr = "0xA11CE".parse().unwrap();
    
    // Simulate download timing
    let start = Instant::now();
    
    // Step 1: Fetch PackageRegistry
    let registry = client
        .get_account_resource_bcs::<PackageRegistry>(attacker_addr, "0x1::code::PackageRegistry")
        .await
        .unwrap();
    println!("PackageRegistry fetched at {:?}", start.elapsed());
    
    // Attacker upgrades here (in real attack)
    println!(">>> ATTACKER UPGRADES PACKAGE HERE <<<");
    
    // Step 2: Fetch module bytecode (now at different version)
    let module_bytecode = client
        .get_account_module(attacker_addr, "MyModule")
        .await
        .unwrap();
    println!("Module bytecode fetched at {:?}", start.elapsed());
    
    // Result: metadata from V1, bytecode from V2
    println!("TOCTOU window: {:?}", start.elapsed());
}
```

**Expected Result:** Developer receives metadata for PackageV1 but bytecode for PackageV2, with no error or warning.

## Notes

This vulnerability is exacerbated by the lack of any bytecode hash in the on-chain `PackageMetadata`. The `source_digest` field only verifies source code, creating a fundamental gap in the integrity verification chain. Even without the TOCTOU race condition, there's no way to verify that downloaded bytecode matches the declared source code.

The `VerifyPackage` command exists but requires local compilation and only verifies source code matches, not that the bytecode is correct. A complete fix requires both atomic fetching at a pinned ledger version AND cryptographic bytecode verification.

### Citations

**File:** crates/aptos/src/move_tool/stored_package.rs (L50-53)
```rust
        let inner = client
            .get_account_resource_bcs::<PackageRegistry>(addr, "0x1::code::PackageRegistry")
            .await?
            .into_inner();
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L58-64)
```rust
                    let bytes = client
                        .get_account_module(addr, &module.name)
                        .await?
                        .into_inner()
                        .bytecode
                        .0;
                    bytecode.insert(module.name.clone(), bytes);
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L183-193)
```rust
    pub fn save_bytecode_to_disk(
        &self,
        path: &Path,
        module_name: &str,
        bytecode: &[u8],
    ) -> anyhow::Result<()> {
        let bytecode_dir = path.join(CompiledPackageLayout::CompiledModules.path());
        fs::create_dir_all(&bytecode_dir)?;
        fs::write(bytecode_dir.join(format!("{}.mv", module_name)), bytecode)?;
        Ok(())
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1209-1220)
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
```

**File:** crates/aptos-rest-client/src/lib.rs (L1313-1323)
```rust
    pub async fn get_account_module(
        &self,
        address: AccountAddress,
        module_name: &str,
    ) -> AptosResult<Response<MoveModuleBytecode>> {
        let url = self.build_path(&format!(
            "accounts/{}/module/{}",
            address.to_hex(),
            module_name
        ))?;
        self.get(url).await
```

**File:** aptos-move/framework/src/natives/code.rs (L60-71)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PackageMetadata {
    pub name: String,
    pub upgrade_policy: UpgradePolicy,
    pub upgrade_number: u64,
    pub source_digest: String,
    #[serde(with = "serde_bytes")]
    pub manifest: Vec<u8>,
    pub modules: Vec<ModuleMetadata>,
    pub deps: Vec<PackageDep>,
    pub extension: Option<Any>,
}
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

**File:** crates/aptos/src/move_tool/mod.rs (L2005-2011)
```rust
        if self.bytecode {
            for module in package.module_names() {
                if let Some(bytecode) = registry.get_bytecode(module).await? {
                    package.save_bytecode_to_disk(package_path.as_path(), module, bytecode)?
                }
            }
        };
```
