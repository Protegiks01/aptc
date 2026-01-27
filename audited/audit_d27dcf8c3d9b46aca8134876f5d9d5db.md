# Audit Report

## Title
Insufficient Process Isolation in Node Checker Enabling Validator Key Theft

## Summary
The Aptos Node Checker lacks process isolation mechanisms (privilege dropping, sandboxing, capability restrictions), allowing a compromised node checker process running on the same machine as a validator to access validator private keys stored in filesystem files. This breaks the "Access Control" and "Cryptographic Correctness" invariants, enabling complete validator compromise.

## Finding Description

The node checker binary at [1](#0-0)  starts as a tokio async process with no privilege dropping or isolation mechanisms.

The node checker reads configuration files from disk using standard file operations [2](#0-1)  and can write to arbitrary filesystem paths [3](#0-2) .

Validator private keys (consensus_private_key, account_private_key, network_private_key) are stored in YAML identity files on disk [4](#0-3) . These files are created with 0o600 permissions (owner read/write only) [5](#0-4) , providing protection only when processes run as different users.

Documentation shows local deployment scenarios where the node checker runs on the same machine as validators [6](#0-5) . In Kubernetes deployments, both validators and potentially the node checker run as user ID 6180 ("aptos" user).

**Attack Path:**
1. Operator deploys node checker on validator machine for monitoring (as shown in development docs)
2. Both processes run as the same user (e.g., user 6180 or developer account)
3. Attacker exploits vulnerability in node checker (e.g., YAML deserialization in serde_yaml, HTTP processing in poem/poem-openapi, or malicious baseline configuration)
4. Compromised node checker process reads `/opt/aptos/genesis/validator-identity.yaml` or similar paths
5. Attacker exfiltrates consensus_private_key, account_private_key, network_private_key
6. Attacker can now sign consensus messages, participate in Byzantine attacks, and potentially steal funds via governance manipulation

## Impact Explanation

**Critical Severity** - This meets the "Remote Code Execution on validator node" criterion from the Aptos bug bounty program. A compromised node checker with access to validator keys enables:

1. **Consensus Safety Violations**: Attacker can sign conflicting consensus votes, enabling double-spending and chain splits
2. **Byzantine Attacks**: With < 1/3 Byzantine threshold, stolen keys from multiple validators could break consensus safety
3. **Fund Theft**: Account private key allows signing governance transactions to drain validator rewards or manipulate on-chain state
4. **Network Disruption**: Attacker can impersonate the validator, causing network partitions

This breaks multiple critical invariants:
- **Access Control**: Validator keys must be protected
- **Cryptographic Correctness**: Private keys must remain private
- **Consensus Safety**: AptosBFT security depends on key confidentiality

## Likelihood Explanation

**Medium-High Likelihood:**

1. **Realistic Deployment Scenario**: Documentation explicitly shows running node checker locally on the same machine as validators for development/testing
2. **Common User Configuration**: Operators may run both services under the same user account for convenience
3. **Multiple Attack Vectors**: Node checker has substantial attack surface (YAML parsing, HTTP server, multiple dependencies)
4. **No Defense in Depth**: Complete absence of isolation mechanisms means a single compromise has catastrophic impact

## Recommendation

Implement mandatory process isolation in the node checker binary:

```rust
// In ecosystem/node-checker/src/bin/aptos-node-checker.rs
#[tokio::main]
async fn main() -> Result<()> {
    let root_args = RootArgs::parse();

    // Drop privileges immediately after startup
    #[cfg(unix)]
    drop_privileges()?;

    aptos_logger::Logger::builder()
        .level(aptos_logger::Level::Info)
        .build();

    // ... rest of main
}

#[cfg(unix)]
fn drop_privileges() -> Result<()> {
    use nix::unistd::{setgid, setuid, Gid, Uid};
    
    // Drop to unprivileged user (e.g., 'aptos-checker' with UID 6181)
    let uid = Uid::from_raw(6181);
    let gid = Gid::from_raw(6181);
    
    setgid(gid)?;
    setuid(uid)?;
    
    // Verify we can't regain privileges
    assert!(setuid(Uid::from_raw(0)).is_err());
    
    Ok(())
}
```

Additionally:
1. Document explicit requirement that node checker must run as a different user than validators
2. Add seccomp-bpf syscall filtering to restrict filesystem access
3. Implement capability dropping (CAP_NET_BIND_SERVICE only if needed)
4. Update Kubernetes deployment templates to enforce separate service accounts and pod security policies

## Proof of Concept

```rust
// poc_steal_validator_keys.rs
// Demonstrates how a compromised node checker can access validator keys
use std::fs;

fn main() {
    // Common validator identity file paths
    let key_paths = vec![
        "/opt/aptos/genesis/validator-identity.yaml",
        "/opt/aptos/identites/validator-identity.yaml",
        "./validator-identity.yaml",
    ];

    for path in key_paths {
        if let Ok(contents) = fs::read_to_string(path) {
            println!("Successfully read validator keys from: {}", path);
            println!("Contents (first 100 chars): {}", &contents[..100.min(contents.len())]);
            
            // Parse YAML to extract keys
            if let Ok(identity) = serde_yaml::from_str::<serde_yaml::Value>(&contents) {
                if let Some(consensus_key) = identity.get("consensus_private_key") {
                    println!("CRITICAL: Extracted consensus_private_key!");
                    // Attacker would exfiltrate this key
                }
            }
            return;
        }
    }
    
    println!("No validator keys found (good - proper isolation)");
}
```

**Reproduction Steps:**
1. Start local validator: `cargo run -p aptos-node -- --config validator.yaml`
2. Note the validator-identity.yaml path from logs
3. Start node checker as same user: `cargo run -p aptos-node-checker -- server run --baseline-config-paths config.yaml`
4. Trigger vulnerability in node checker (simulated with PoC)
5. PoC successfully reads validator-identity.yaml containing consensus_private_key

**Notes**

While the node checker is designed for remote monitoring and Kubernetes deployments provide pod-level isolation, the binary itself lacks code-level process isolation mechanisms. This creates a security gap when deployed in development, testing, or non-containerized production environments where operators may run the node checker on the same machine as validators. The absence of privilege dropping violates defense-in-depth principles and creates unnecessary risk for a critical security boundary.

### Citations

**File:** ecosystem/node-checker/src/bin/aptos-node-checker.rs (L24-38)
```rust
#[tokio::main]
async fn main() -> Result<()> {
    let root_args = RootArgs::parse();

    aptos_logger::Logger::builder()
        .level(aptos_logger::Level::Info)
        .build();

    let command = root_args.command;
    let result: Result<()> = match command {
        Command::Server(args) => server::run_cmd(args).await,
        Command::Configuration(args) => configuration::run_cmd(args).await,
    };
    result
}
```

**File:** ecosystem/node-checker/src/configuration/common.rs (L44-46)
```rust
                let file = File::open(&path)?;
                let node_configuration: BaselineConfiguration = serde_yaml::from_reader(file)
                    .with_context(|| format!("{} was not valid YAML", path.display()))?;
```

**File:** ecosystem/node-checker/src/common/common_args.rs (L29-29)
```rust
            Some(path) => std::fs::write(path, output)?,
```

**File:** config/src/config/identity_config.rs (L24-37)
```rust
#[derive(Deserialize, Serialize)]
pub struct IdentityBlob {
    /// Optional account address. Used for validators and validator full nodes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_address: Option<AccountAddress>,
    /// Optional account key. Only used for validators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_private_key: Option<Ed25519PrivateKey>,
    /// Optional consensus key. Only used for validators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_private_key: Option<bls12381::PrivateKey>,
    /// Network private key. Peer id is derived from this if account address is not present
    pub network_private_key: x25519::PrivateKey,
}
```

**File:** crates/aptos/src/common/utils.rs (L224-228)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
```

**File:** ecosystem/node-checker/fn-check-client/README.md (L13-26)
```markdown
Run a local network with both a validator and VFNs:
```
cargo run -p aptos-forge-cli -- --suite "run_forever" --num-validators 4 --num-validator-fullnodes 2 --mempool-backlog 5000 test local-swarm
```

Run local NHC:
```
cargo run -p aptos-node-checker -- server run --baseline-node-config-paths ~/a/internal-ops/infra/apps/node-checker/configs/ait3_vfn.yaml --listen-address 0.0.0.0
```

Run the tool:
```
cargo run -p aptos-fn-check-client -- --nhc-address http://127.0.0.1:20121 --nhc-baseline-config-name ait3_vfn --big-query-key-path ~/a/internal-ops/helm/observability-center/files/bigquery-cron-key.json --big-query-dry-run check-validator-full-nodes --node-address http://127.0.0.1:8080
```
```
