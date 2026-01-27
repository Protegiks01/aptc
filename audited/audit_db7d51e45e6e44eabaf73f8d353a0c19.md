# Audit Report

## Title
Config Sanitizer Bypass Allows Validators to Start Without Required Network Configuration

## Summary
The configuration sanitizer in Aptos Core can be bypassed by setting `skip_config_sanitizer: true` within the configuration file itself, allowing validators to start with missing critical fields like `validator_network`, resulting in non-functional validators that cannot participate in consensus.

## Finding Description

The Aptos node configuration system includes a sanitizer that validates critical security settings before node startup. However, this sanitizer has a fundamental design flaw: it can be disabled from within the configuration file it's supposed to validate. [1](#0-0) 

This allows an attacker with config file access to set both `skip_config_sanitizer: true` and remove critical required fields. For validator nodes, the sanitizer normally enforces that `validator_network` must be present: [2](#0-1) 

When the sanitizer is bypassed, a validator node can load with `validator_network: null`. The network setup code safely handles this by not creating consensus network interfaces: [3](#0-2) 

Without validator network configuration, the consensus runtime fails to start: [4](#0-3) 

The validator node starts successfully but cannot participate in consensus, block production, or network validation.

While the original question asks about null injection in `diff_override_config_yaml()` at lines 41-42, that function is only used for computing YAML diffs during config serialization, not loading. The actual vulnerability is the self-disabling sanitizer. [5](#0-4) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables denial-of-service attacks against validator nodes:

1. **Validator Non-functionality**: Affected validators cannot participate in consensus, reducing network security
2. **Bypasses All Security Checks**: The sanitizer enforces mainnet-specific requirements (paranoid verification, authentication, secure backends). Bypassing it circumvents all these protections
3. **Network Degradation**: If multiple validators are compromised, the network loses liveness or safety guarantees

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to "significant protocol violations" - validators failing to function properly violates protocol invariants.

## Likelihood Explanation

**Likelihood: MEDIUM to LOW**

**Attack Prerequisites:**
- Write access to validator configuration files, OR
- Compromised configuration management/deployment pipeline, OR  
- Social engineering to convince operator to use malicious config template

**Realistic Attack Scenarios:**
1. **Supply Chain Attack**: Malicious default config templates distributed to operators
2. **Compromised CI/CD**: Automated deployment systems inject malicious configs
3. **Operator Error**: Accidental use of test configs with sanitizer disabled in production

**Limitation:** Requires validator operator-level access or compromised infrastructure, not achievable by unprivileged network attackers. This significantly reduces exploitability compared to pure protocol-level bugs.

## Recommendation

**Fix 1: Remove the bypass flag from production code**

The `skip_config_sanitizer` flag should only exist in test builds:

```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeStartupConfig {
    pub skip_config_optimizer: bool,
    #[cfg(test)]
    pub skip_config_sanitizer: bool,
}

impl Default for NodeStartupConfig {
    fn default() -> Self {
        Self {
            skip_config_optimizer: false,
            #[cfg(test)]
            skip_config_sanitizer: false,
        }
    }
}
```

**Fix 2: Add external enforcement**

Even if the flag exists, enforce sanitization at a higher level:

```rust
pub fn load_and_sanitize_config(&self) -> Result<NodeConfig, Error> {
    let mut node_config = NodeConfig::load_config(&self.node_config_path)?;
    
    // Always enforce sanitization in production builds
    #[cfg(not(test))]
    if node_config.node_startup.skip_config_sanitizer {
        return Err(Error::ConfigSanitizerFailed(
            "ConfigLoader".to_string(),
            "skip_config_sanitizer cannot be enabled in production builds".into(),
        ));
    }
    
    // ... rest of function
}
```

## Proof of Concept

**Malicious Configuration File** (`malicious_validator.yaml`):

```yaml
# Bypass sanitizer
node_startup:
  skip_config_sanitizer: true

# Base config with validator role
base:
  role: "validator"
  data_dir: "/opt/aptos/data"

# Critical field is null/absent
validator_network: null

# Other required fields use defaults
consensus: {}
execution: {}
storage: {}
```

**Exploitation Steps:**

1. Deploy the malicious config to a validator node
2. Start the aptos-node with: `aptos-node -f malicious_validator.yaml`
3. Node starts successfully (no panic or immediate error)
4. Check logs - consensus never initializes
5. Validator is non-functional but appears to be running

**Expected Behavior vs Actual:**
- **Expected**: Config loading fails with "Validator network config cannot be empty for validators!"
- **Actual**: Node starts, sanitizer is bypassed, validator is non-functional

**Detection:**
Monitor for validators with `skip_config_sanitizer: true` in production configs or validators that start but never participate in consensus.

---

**Notes:**

This vulnerability represents a security anti-pattern where the security control (sanitizer) can be disabled by the artifact being controlled (config file). While exploitation requires elevated access, the design flaw enables attack scenarios involving compromised deployment infrastructure or social engineering. The issue affects validator availability rather than directly causing consensus violations or fund loss, placing it at HIGH severity under the bug bounty program.

### Citations

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/config_sanitizer.rs (L166-170)
```rust
    if validator_network.is_none() && node_type.is_validator() {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Validator network config cannot be empty for validators!".into(),
        ));
```

**File:** aptos-node/src/network.rs (L218-227)
```rust
fn extract_network_configs(node_config: &NodeConfig) -> Vec<NetworkConfig> {
    let mut network_configs: Vec<NetworkConfig> = node_config.full_node_networks.to_vec();
    if let Some(network_config) = node_config.validator_network.as_ref() {
        // Ensure that mutual authentication is enabled by default!
        if !network_config.mutual_authentication {
            panic!("Validator networks must always have mutual_authentication enabled!");
        }
        network_configs.push(network_config.clone());
    }
    network_configs
```

**File:** aptos-node/src/consensus.rs (L50-54)
```rust
    consensus_network_interfaces.map(|consensus_network_interfaces| {
        let (consensus_runtime, consensus_db, quorum_store_db) = services::start_consensus_runtime(
            node_config,
            db_rw.clone(),
            consensus_reconfig_subscription,
```

**File:** config/src/config/override_node_config.rs (L41-41)
```rust
        (serde_yaml::Value::Null, serde_yaml::Value::Null) => Ok(None),
```
