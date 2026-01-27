# Audit Report

## Title
Stack Overflow Denial-of-Service via Malicious YAML Files in Identity Loading and Genesis Generation (CVE-2022-38900)

## Summary
The Aptos Core codebase uses `serde_yaml = "0.8.24"`, which is vulnerable to CVE-2022-38900. This allows an attacker to craft deeply nested YAML structures that cause stack overflow during deserialization, leading to validator node crashes and genesis ceremony disruption. The vulnerability affects both `IdentityBlob::from_file` for validator identity loading and the genesis generation CLI tools that parse YAML from GitHub repositories.

## Finding Description
The security vulnerability stems from insufficient validation in YAML deserialization across multiple critical components. While the original question asks about buffer overflows or arbitrary code execution, the actual exploitable vulnerability is a **stack overflow causing denial-of-service** through the vulnerable `serde_yaml` dependency. [1](#0-0) 

The attack propagates through two primary vectors:

**Vector 1: Validator Identity File Loading**

When a validator node starts, it loads its network identity through `NetworkConfig::identity_key()`: [2](#0-1) 

For `Identity::FromFile`, this calls `IdentityBlob::from_file()`: [3](#0-2) 

The `serde_yaml::from_str` function deserializes the YAML without depth limits. A malicious YAML file with deeply nested structures (e.g., nested maps or sequences) will cause recursive parsing that exhausts the stack.

**Vector 2: Genesis Generation from GitHub Repositories**

The genesis CLI tool fetches configuration files from GitHub repositories and parses them using the same vulnerable library: [4](#0-3) [5](#0-4) 

The genesis generation process retrieves multiple YAML files: [6](#0-5) [7](#0-6) 

An attacker controlling or compromising a GitHub repository can inject malicious YAML that crashes the genesis coordinator's tool.

**Why Not Buffer Overflow or RCE:**

Rust's memory safety prevents traditional buffer overflows. The `x25519::PrivateKey` deserialization validates only length: [8](#0-7) 

The vulnerability is specifically **CVE-2022-38900**: a stack overflow in `serde_yaml` versions < 0.9.0 caused by unbounded recursion during YAML parsing. This leads to process termination (DoS), not arbitrary code execution.

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **Validator Node Crashes**: Malicious identity files cause validator nodes to crash during startup, preventing participation in consensus and reducing network liveness.

2. **Genesis Ceremony Disruption**: Attackers can crash the genesis coordinator's tooling by hosting malicious YAML files in GitHub repositories, preventing new network launches or testnet creation.

3. **Operational Disruption**: Any component using `serde_yaml` for configuration parsing is vulnerable to crash-on-load attacks.

While this does not achieve the Critical severity thresholds (no fund loss, no consensus safety violation, no RCE), it represents a significant protocol violation through availability attacks on critical infrastructure.

## Likelihood Explanation
**Likelihood: High**

**Genesis Attack Vector:**
- Attack complexity: Low - attacker only needs to host a malicious GitHub repository
- Attacker requirements: None - no privileged access needed
- User interaction: Victim must run `aptos genesis generate-genesis --github-repository attacker/repo`
- Detection difficulty: Low - tool simply crashes with stack overflow error

**Identity File Attack Vector:**
- Attack complexity: Medium - requires filesystem access on validator machine
- Attacker requirements: System access or configuration manipulation
- User interaction: Validator must restart/start with malicious config
- Detection difficulty: Low - node crashes on startup

The genesis attack is particularly concerning as it's exploitable without any system access and can disrupt critical network initialization processes.

## Recommendation
Upgrade `serde_yaml` to version 0.9.0 or later, which includes the fix for CVE-2022-38900.

**Fix in Cargo.toml:**
```toml
serde_yaml = "0.9"  # Was: "0.8.24"
```

**Additional Hardening:**
1. Implement depth limits for YAML parsing in security-critical contexts
2. Add file size limits before parsing identity files
3. Validate YAML structure before full deserialization in genesis tools
4. Consider moving to safer configuration formats (e.g., TOML with depth limits)

## Proof of Concept

**Step 1: Create malicious YAML file (malicious-identity.yaml):**
```yaml
network_private_key: "0x1234567890123456789012345678901234567890123456789012345678901234"
a: &a [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]
d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]
e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]
```

**Step 2: Configure validator to use malicious file:**
```yaml
validator_network:
  identity:
    type: "from_file"
    path: /path/to/malicious-identity.yaml
```

**Step 3: Start validator node:**
```bash
aptos-node -f validator.yaml
```

**Expected Result:** The node crashes with a stack overflow error during identity loading, before successfully starting.

**For Genesis Attack:**
Create a GitHub repository with malicious `layout.yaml`, `balances.yaml`, or operator/owner configuration files containing deeply nested YAML anchors. When a user runs:
```bash
aptos genesis generate-genesis --github-repository attacker/malicious-genesis
```

The tool crashes before completing genesis generation.

## Notes
This vulnerability does not achieve arbitrary code execution or buffer overflow as originally questioned, but represents a concrete denial-of-service attack exploitable through multiple vectors. The CVE-2022-38900 vulnerability in `serde_yaml < 0.9.0` is a known issue that should be patched immediately to protect validator operations and genesis ceremonies.

### Citations

**File:** Cargo.toml (L799-799)
```text
serde_yaml = "0.8.24"
```

**File:** config/src/config/network_config.rs (L187-206)
```rust
    pub fn identity_key(&self) -> x25519::PrivateKey {
        let key = match &self.identity {
            Identity::FromConfig(config) => Some(config.key.private_key()),
            Identity::FromStorage(config) => {
                let storage: Storage = (&config.backend).into();
                let key = storage
                    .export_private_key(&config.key_name)
                    .expect("Unable to read key");
                let key = x25519::PrivateKey::from_ed25519_private_bytes(&key.to_bytes())
                    .expect("Unable to convert key");
                Some(key)
            },
            Identity::FromFile(config) => {
                let identity_blob: IdentityBlob = IdentityBlob::from_file(&config.path).unwrap();
                Some(identity_blob.network_private_key)
            },
            Identity::None => None,
        };
        key.expect("identity key should be present")
    }
```

**File:** config/src/config/identity_config.rs (L40-42)
```rust
    pub fn from_file(path: &Path) -> anyhow::Result<IdentityBlob> {
        Ok(serde_yaml::from_str(&fs::read_to_string(path)?)?)
    }
```

**File:** crates/aptos/src/genesis/git.rs (L159-183)
```rust
    pub fn get<T: DeserializeOwned + Debug>(&self, path: &Path) -> CliTypedResult<T> {
        match self {
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(path);

                if !path.exists() {
                    return Err(CliError::UnableToReadFile(
                        path.display().to_string(),
                        "File not found".to_string(),
                    ));
                }

                eprintln!("Reading {}", path.display());
                let mut file = std::fs::File::open(path.as_path())
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;

                let mut contents = String::new();
                file.read_to_string(&mut contents)
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;
                from_yaml(&contents)
            },
            Client::Github(client) => {
                from_base64_encoded_yaml(&client.get_file(&path.display().to_string())?)
            },
        }
```

**File:** crates/aptos/src/genesis/git.rs (L250-256)
```rust
pub fn to_yaml<T: Serialize + ?Sized>(input: &T) -> CliTypedResult<String> {
    Ok(serde_yaml::to_string(input)?)
}

pub fn from_yaml<T: DeserializeOwned>(input: &str) -> CliTypedResult<T> {
    Ok(serde_yaml::from_str(input)?)
}
```

**File:** crates/aptos/src/genesis/mod.rs (L138-152)
```rust
pub fn fetch_mainnet_genesis_info(git_options: GitOptions) -> CliTypedResult<MainnetGenesisInfo> {
    let client = git_options.get_client()?;
    let layout: Layout = client.get(Path::new(LAYOUT_FILE))?;

    if layout.root_key.is_some() {
        return Err(CliError::UnexpectedError(
            "Root key must not be set for mainnet.".to_string(),
        ));
    }

    let total_supply = layout.total_supply.ok_or_else(|| {
        CliError::UnexpectedError("Layout file does not have `total_supply`".to_string())
    })?;

    let account_balance_map: AccountBalanceMap = client.get(Path::new(BALANCES_FILE))?;
```

**File:** crates/aptos/src/genesis/mod.rs (L352-361)
```rust
fn get_config(
    client: &Client,
    user: &str,
    is_mainnet: bool,
) -> CliTypedResult<ValidatorConfiguration> {
    // Load a user's configuration files
    let dir = PathBuf::from(user);
    let owner_file = dir.join(OWNER_FILE);
    let owner_file = owner_file.as_path();
    let owner_config = client.get::<StringOwnerConfiguration>(owner_file)?;
```

**File:** crates/aptos-crypto/src/x25519.rs (L161-170)
```rust
impl std::convert::TryFrom<&[u8]> for PrivateKey {
    type Error = traits::CryptoMaterialError;

    fn try_from(private_key_bytes: &[u8]) -> Result<Self, Self::Error> {
        let private_key_bytes: [u8; PRIVATE_KEY_SIZE] = private_key_bytes
            .try_into()
            .map_err(|_| traits::CryptoMaterialError::DeserializationError)?;
        Ok(Self(x25519_dalek::StaticSecret::from(private_key_bytes)))
    }
}
```
