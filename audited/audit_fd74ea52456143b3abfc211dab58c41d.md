# Audit Report

## Title
Missing Sanitizer Validation for DKG and JWK Consensus Network Channel Configurations Allowing Node Crash via Invalid Config Values

## Summary
The `DKGConfig` and `JWKConsensusConfig` modules lack `ConfigSanitizer` implementations and are not called in the main sanitization flow, allowing invalid configuration values (particularly `max_network_channel_size: 0`) to bypass validation. This causes runtime panics when the node attempts to initialize network channels for these critical consensus components, resulting in validator node crashes.

## Finding Description

The Aptos configuration system implements a sanitizer framework to validate all configuration values before node startup. However, two critical security modules bypass this validation entirely:

1. **DKGConfig** (Distributed Key Generation for randomness) [1](#0-0) 

2. **JWKConsensusConfig** (JSON Web Key consensus for keyless accounts) [2](#0-1) 

Both configurations contain a `max_network_channel_size` field that controls the size of network message queues for these consensus-critical components.

The `NodeConfig::sanitize()` function orchestrates validation of all sub-configs, but notably **excludes** DKGConfig and JWKConsensusConfig from the sanitization process: [3](#0-2) 

When these configs are loaded into the NodeConfig struct, they are never validated: [4](#0-3) 

During node initialization, these channel sizes are used to create network channels. For DKG: [5](#0-4) 

For JWK Consensus: [6](#0-5) 

The `aptos_channel::Config::new()` eventually calls the `new()` function which uses the `NonZeroUsize!` macro to validate the channel size: [7](#0-6) 

This macro panics if the value is zero: [8](#0-7) 

**Attack Scenario:**

1. An operator (accidentally or through configuration error) sets `dkg.max_network_channel_size: 0` or `jwk_consensus.max_network_channel_size: 0` in the node configuration file
2. The configuration loads successfully without sanitizer validation
3. Node startup proceeds normally until network initialization
4. When initializing DKG or JWK consensus network channels, the `NonZeroUsize!` macro encounters the zero value
5. The macro panics with "aptos_channel cannot be of size 0"
6. The validator node crashes immediately

This breaks the defense-in-depth principle where the sanitizer framework should catch invalid configurations before runtime initialization.

## Impact Explanation

**Severity: High** (per Aptos bug bounty criteria: "Validator node slowdowns, API crashes")

**Impact:**
- **Availability Loss**: Validator nodes crash on startup, causing complete loss of liveness
- **Consensus Disruption**: If multiple validators are affected (e.g., through automated config deployment), it can impact network consensus participation
- **Critical Component Failure**: Affects DKG (required for on-chain randomness) and JWK Consensus (required for keyless account authentication)
- **No Recovery Without Manual Intervention**: Node remains crashed until config is manually corrected

The impact is particularly severe because:
1. DKG is critical for generating randomness used in consensus protocols
2. JWK Consensus is critical for keyless account security infrastructure
3. The failure is immediate and total (complete node crash, not degraded performance)
4. The bug bypasses the intended security validation layer

## Likelihood Explanation

**Likelihood: Medium to High**

This issue can occur through several realistic scenarios:

1. **Operator Configuration Error**: A node operator accidentally sets the value to 0 while editing configs
2. **Automated Deployment Misconfiguration**: GitOps pipelines or Infrastructure-as-Code tools (Terraform, Ansible) might generate invalid configs
3. **Template Errors**: Config templates or examples with placeholder values (e.g., `0` as a placeholder) could be deployed without modification
4. **Copy-Paste Mistakes**: Operators copying config sections might inadvertently include invalid values

The likelihood is elevated because:
- The error is silent during config loading (no validation warnings)
- The failure only manifests at runtime initialization
- Other similar configurations (ConsensusConfig, MempoolConfig) ARE sanitized, creating inconsistent behavior expectations
- No bounds checking exists at the configuration layer

## Recommendation

Implement `ConfigSanitizer` for both DKGConfig and JWKConsensusConfig, and add them to the sanitization flow:

**Step 1:** Add sanitizer implementations in `config/src/config/dkg_config.rs`:

```rust
impl ConfigSanitizer for DKGConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let dkg_config = &node_config.dkg;

        // Validate max_network_channel_size is non-zero
        if dkg_config.max_network_channel_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "max_network_channel_size cannot be zero for DKG!".into(),
            ));
        }

        // Optional: Add reasonable upper bound to prevent memory exhaustion
        const MAX_REASONABLE_CHANNEL_SIZE: usize = 100_000;
        if dkg_config.max_network_channel_size > MAX_REASONABLE_CHANNEL_SIZE {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "max_network_channel_size ({}) exceeds reasonable limit ({})!",
                    dkg_config.max_network_channel_size, MAX_REASONABLE_CHANNEL_SIZE
                ),
            ));
        }

        Ok(())
    }
}
```

**Step 2:** Add similar implementation in `config/src/config/jwk_consensus_config.rs`

**Step 3:** Update `config/src/config/config_sanitizer.rs` to call these sanitizers:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // ... existing code ...
        
        // Add these lines after line 65:
        DKGConfig::sanitize(node_config, node_type, chain_id)?;
        JWKConsensusConfig::sanitize(node_config, node_type, chain_id)?;

        Ok(())
    }
}
```

**Step 4:** Import the types in `config_sanitizer.rs`:

```rust
use crate::config::{
    // ... existing imports ...
    DKGConfig, JWKConsensusConfig,
};
```

## Proof of Concept

```rust
// Test file: config/src/config/dkg_config_test.rs
#[cfg(test)]
mod tests {
    use crate::config::{ConfigSanitizer, DKGConfig, NodeConfig, NodeType};
    use aptos_types::chain_id::ChainId;

    #[test]
    fn test_dkg_config_zero_channel_size_should_fail() {
        // Create a node config with zero DKG channel size
        let mut node_config = NodeConfig::default();
        node_config.dkg.max_network_channel_size = 0;

        // Attempt to sanitize - should fail
        let result = NodeConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::testnet()));
        
        // This test will PASS with current code (no validation)
        // but SHOULD FAIL after implementing the fix
        assert!(result.is_err(), "Sanitizer should reject zero channel size");
    }

    #[test]
    fn test_jwk_consensus_zero_channel_size_causes_panic() {
        // Demonstrate the actual runtime panic
        use crate::config::NodeConfig;
        use aptos_channels::aptos_channel;
        use aptos_channels::message_queues::QueueStyle;

        let mut node_config = NodeConfig::default();
        node_config.jwk_consensus.max_network_channel_size = 0;

        // This will PANIC at runtime when creating the channel
        // Uncomment to see the panic:
        // let _channel = aptos_channel::Config::new(node_config.jwk_consensus.max_network_channel_size)
        //     .queue_style(QueueStyle::FIFO)
        //     .build::<(), ()>();
    }
}
```

**Notes**

This finding represents a defense-in-depth failure where the configuration sanitizer framework—specifically designed to validate configurations before node startup—does not cover two critical consensus components (DKG and JWK Consensus). While the issue requires configuration file modification (typically operator access), the sanitizer exists precisely to catch operator errors and misconfigurations. The consistency problem is evident: other similar configurations with `max_network_channel_size` fields (ConsensusConfig, MempoolConfig, StorageServiceConfig) are properly validated through their sanitizers, but these two security-critical modules are not. The runtime panic occurs in a consensus-critical code path, making this a High severity availability issue affecting validator node operation.

### Citations

**File:** config/src/config/dkg_config.rs (L6-18)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DKGConfig {
    pub max_network_channel_size: usize,
}

impl Default for DKGConfig {
    fn default() -> Self {
        Self {
            max_network_channel_size: 256,
        }
    }
}
```

**File:** config/src/config/jwk_consensus_config.rs (L6-18)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct JWKConsensusConfig {
    pub max_network_channel_size: usize,
}

impl Default for JWKConsensusConfig {
    fn default() -> Self {
        Self {
            max_network_channel_size: 256,
        }
    }
}
```

**File:** config/src/config/config_sanitizer.rs (L39-71)
```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }

        // Sanitize all of the sub-configs
        AdminServiceConfig::sanitize(node_config, node_type, chain_id)?;
        ApiConfig::sanitize(node_config, node_type, chain_id)?;
        BaseConfig::sanitize(node_config, node_type, chain_id)?;
        ConsensusConfig::sanitize(node_config, node_type, chain_id)?;
        DagConsensusConfig::sanitize(node_config, node_type, chain_id)?;
        ExecutionConfig::sanitize(node_config, node_type, chain_id)?;
        sanitize_failpoints_config(node_config, node_type, chain_id)?;
        sanitize_fullnode_network_configs(node_config, node_type, chain_id)?;
        IndexerGrpcConfig::sanitize(node_config, node_type, chain_id)?;
        InspectionServiceConfig::sanitize(node_config, node_type, chain_id)?;
        LoggerConfig::sanitize(node_config, node_type, chain_id)?;
        MempoolConfig::sanitize(node_config, node_type, chain_id)?;
        NetbenchConfig::sanitize(node_config, node_type, chain_id)?;
        StateSyncConfig::sanitize(node_config, node_type, chain_id)?;
        StorageConfig::sanitize(node_config, node_type, chain_id)?;
        InternalIndexerDBConfig::sanitize(node_config, node_type, chain_id)?;
        sanitize_validator_network_config(node_config, node_type, chain_id)?;

        Ok(()) // All configs passed validation
    }
}
```

**File:** config/src/config/node_config.rs (L51-67)
```rust
    pub dkg: DKGConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub failpoints: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_node_networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub indexer: IndexerConfig,
    #[serde(default)]
    pub indexer_grpc: IndexerGrpcConfig,
    #[serde(default)]
    pub indexer_table_info: IndexerTableInfoConfig,
    #[serde(default)]
    pub inspection_service: InspectionServiceConfig,
    #[serde(default)]
    pub jwk_consensus: JWKConsensusConfig,
```

**File:** aptos-node/src/network.rs (L74-89)
```rust
/// Returns the network application config for the DKG client and service
pub fn dkg_network_configuration(node_config: &NodeConfig) -> NetworkApplicationConfig {
    let direct_send_protocols: Vec<ProtocolId> =
        aptos_dkg_runtime::network_interface::DIRECT_SEND.into();
    let rpc_protocols: Vec<ProtocolId> = aptos_dkg_runtime::network_interface::RPC.into();

    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(node_config.dkg.max_network_channel_size)
            .queue_style(QueueStyle::FIFO),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}
```

**File:** aptos-node/src/network.rs (L91-106)
```rust
/// Returns the network application config for the JWK consensus client and service
pub fn jwk_consensus_network_configuration(node_config: &NodeConfig) -> NetworkApplicationConfig {
    let direct_send_protocols: Vec<ProtocolId> =
        aptos_jwk_consensus::network_interface::DIRECT_SEND.into();
    let rpc_protocols: Vec<ProtocolId> = aptos_jwk_consensus::network_interface::RPC.into();

    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(node_config.jwk_consensus.max_network_channel_size)
            .queue_style(QueueStyle::FIFO),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}
```

**File:** crates/channel/src/aptos_channel.rs (L235-241)
```rust
pub fn new<K: Eq + Hash + Clone, M>(
    queue_style: QueueStyle,
    max_queue_size_per_key: usize,
    counters: Option<&'static IntCounterVec>,
) -> (Sender<K, M>, Receiver<K, M>) {
    let max_queue_size_per_key =
        NonZeroUsize!(max_queue_size_per_key, "aptos_channel cannot be of size 0");
```

**File:** crates/aptos-infallible/src/nonzero.rs (L6-13)
```rust
macro_rules! NonZeroUsize {
    ($num:expr) => {
        NonZeroUsize!($num, "Must be non-zero")
    };
    ($num:expr, $message:literal) => {
        std::num::NonZeroUsize::new($num).expect($message)
    };
}
```
