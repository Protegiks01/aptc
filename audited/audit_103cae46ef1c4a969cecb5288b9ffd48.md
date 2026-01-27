# Audit Report

## Title
Validator PeerId Regeneration on Restart Due to Missing Identity Persistence

## Summary
When a validator's network configuration lacks a properly configured identity (using `Identity::None` or omitting the identity field), a new random PeerId is generated on every node restart, breaking peer connections and preventing validator participation in consensus.

## Finding Description

The vulnerability exists in the node identity initialization flow. When a validator node starts, the configuration loading process calls `aptos_node_identity::init()` with a PeerId obtained from the network configuration. [1](#0-0) 

The PeerId is retrieved via `config.get_peer_id()`, which delegates to the network configuration's `peer_id()` method. [2](#0-1) 

The critical issue occurs in `NetworkConfig::peer_id()` and `prepare_identity()`. The default NetworkConfig sets `identity: Identity::None`: [3](#0-2) 

During config optimization (which runs on every node startup), `prepare_identity()` is invoked: [4](#0-3) 

For `Identity::None`, this generates a **new random PeerId** using OS entropy (OsRng). This auto-generated identity is stored only in memory and is **never persisted to disk**. [5](#0-4) 

The configuration is loaded from disk, optimized, and used—but the auto-generated identity is not saved back. On the next restart, the process repeats with a **different random PeerId**.

The validator network requires mutual authentication, where each validator maintains a trusted peer set mapping PeerIds to expected public keys. When a validator restarts with a new PeerId, it cannot authenticate with other validators because:
1. Other validators still expect the original PeerId
2. The new PeerId is not in their trusted peer sets
3. Mutual authentication fails
4. The validator cannot participate in consensus

Crucially, the config sanitizer **does not validate** that identity is properly configured for validators: [6](#0-5) 

The sanitizer only checks that mutual authentication is enabled, but does not prevent `Identity::None` for validator networks.

## Impact Explanation

**Severity: High**

This vulnerability breaks the critical invariant that validators must maintain consistent network identities across restarts to participate in consensus. A validator with this misconfiguration will experience:

1. **Loss of Consensus Participation**: After any restart (crash, upgrade, maintenance), the validator cannot reconnect to the validator network due to PeerId mismatch
2. **Stake Reward Loss**: The validator loses rewards while unable to participate
3. **Network Liveness Risk**: If multiple validators have this misconfiguration, overall network liveness could be affected
4. **Validator Reputation Damage**: Repeated failures to participate harm the validator's reliability metrics

This qualifies as **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations" - a validator completely unable to participate after restart represents a critical availability failure.

## Likelihood Explanation

**Likelihood: Medium-High**

While this requires a configuration error by the validator operator, it is realistically exploitable because:

1. **No Validation**: The config sanitizer has no check to prevent `Identity::None` for validators, making this misconfiguration silently accepted
2. **Silent Failure**: The node starts successfully with auto-generated identity, giving no warning that persistence is missing
3. **Common Mistake**: Operators following incomplete documentation or examples might omit the identity configuration
4. **Production Impact**: This could occur in production validators, not just test environments

The lack of any warning or validation means this could easily happen through honest operator error during initial deployment or configuration updates.

## Recommendation

**Fix 1: Add Config Validation (Recommended)**

Add validation in `sanitize_validator_network_config()` to reject `Identity::None` for validator networks:

```rust
// In config/src/config/config_sanitizer.rs, within sanitize_validator_network_config()
if let Some(validator_network_config) = validator_network {
    // ... existing checks ...
    
    // NEW: Validate identity is properly configured
    if matches!(validator_network_config.identity, Identity::None) {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Validator network identity must be explicitly configured (from_storage, from_file, or from_config). Identity::None is not allowed for validators.".into(),
        ));
    }
}
```

**Fix 2: Auto-Persist Generated Identity**

Alternatively, automatically persist auto-generated identities to disk in a secure location and reload them on subsequent starts. However, this is less secure than requiring explicit configuration.

**Fix 3: Add Warning Logs**

At minimum, log a prominent WARNING when auto-generating identity for a validator network to alert operators of the misconfiguration.

## Proof of Concept

**Reproduction Steps:**

1. Create a validator configuration file without specifying identity:

```yaml
base:
    role: "validator"
    data_dir: "/opt/aptos/data"
    
validator_network:
    listen_address: "/ip4/0.0.0.0/tcp/6180"
    mutual_authentication: true
    # NOTE: identity field is missing - will use Identity::None default
```

2. Start the validator node - it will auto-generate a random PeerId (e.g., `0xabc123...`)

3. The validator attempts to join the network with PeerId `0xabc123...`

4. Restart the validator node

5. A NEW random PeerId is generated (e.g., `0xdef456...`)

6. Other validators reject connections because they don't have `0xdef456...` in their trusted peer sets (they still expect `0xabc123...`)

7. The validator cannot participate in consensus

**Expected vs Actual Behavior:**
- **Expected**: Validator maintains the same PeerId across restarts and can rejoin the network
- **Actual**: Validator generates a new PeerId on each restart and cannot authenticate with the network

## Notes

This vulnerability specifically answers the security question: "After a node crashes and restarts, does `init()` guarantee the same PeerId is used?" The answer is **NO** - if the network identity configuration is `Identity::None` (the default when not explicitly specified), a new random PeerId is generated on each restart. The system does not guarantee PeerId persistence in this configuration, and there is no validation to prevent this dangerous misconfiguration for validator nodes.

Production validators should always use `Identity::FromStorage` (with Vault or secure storage) or `Identity::FromFile` (with a persistent identity file) to ensure PeerId consistency across restarts.

### Citations

**File:** aptos-node/src/lib.rs (L240-240)
```rust
    aptos_node_identity::init(config.get_peer_id())?;
```

**File:** config/src/config/node_config.rs (L146-149)
```rust
    pub fn get_peer_id(&self) -> Option<PeerId> {
        self.get_primary_network_config()
            .map(NetworkConfig::peer_id)
    }
```

**File:** config/src/config/network_config.rs (L140-140)
```rust
            identity: Identity::None,
```

**File:** config/src/config/network_config.rs (L272-288)
```rust
    fn prepare_identity(&mut self) {
        match &mut self.identity {
            Identity::FromStorage(_) => (),
            Identity::None => {
                let mut rng = StdRng::from_seed(OsRng.r#gen());
                let key = x25519::PrivateKey::generate(&mut rng);
                let peer_id = from_identity_public_key(key.public_key());
                self.identity = Identity::from_config_auto_generated(key, peer_id);
            },
            Identity::FromConfig(config) => {
                if config.peer_id == PeerId::ZERO {
                    config.peer_id = from_identity_public_key(config.key.public_key());
                }
            },
            Identity::FromFile(_) => (),
        };
    }
```

**File:** config/src/config/node_config_loader.rs (L85-89)
```rust
        // Optimize and sanitize the node config
        let local_config_yaml = get_local_config_yaml(&self.node_config_path)?;
        optimize_and_sanitize_node_config(&mut node_config, local_config_yaml)?;

        Ok(node_config)
```

**File:** config/src/config/config_sanitizer.rs (L157-201)
```rust
fn sanitize_validator_network_config(
    node_config: &NodeConfig,
    node_type: NodeType,
    _chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let sanitizer_name = VALIDATOR_NETWORK_SANITIZER_NAME.to_string();
    let validator_network = &node_config.validator_network;

    // Verify that the validator network config is not empty for validators
    if validator_network.is_none() && node_type.is_validator() {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Validator network config cannot be empty for validators!".into(),
        ));
    }

    // Check the validator network config
    if let Some(validator_network_config) = validator_network {
        let network_id = validator_network_config.network_id;
        if !network_id.is_validator_network() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The validator network config must have a validator network ID!".into(),
            ));
        }

        // Verify that the node is a validator
        if !node_type.is_validator() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The validator network config cannot be set for non-validators!".into(),
            ));
        }

        // Ensure that mutual authentication is enabled
        if !validator_network_config.mutual_authentication {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Mutual authentication must be enabled for the validator network!".into(),
            ));
        }
    }

    Ok(())
}
```
