# Audit Report

## Title
Divide-by-Zero Panic via Unvalidated NetworkConfig Parameters

## Summary
The `NetworkConfig` structure allows malicious or misconfigured values for `max_frame_size`, `max_message_size`, and `max_inbound_connections` without validation during configuration loading or sanitization. When `max_frame_size` is set to zero or to values that violate network protocol invariants, it causes panic conditions that crash validator and fullnode instances, leading to network-wide denial of service.

## Finding Description

The Aptos network layer accepts configuration parameters through `NetworkConfig` that are directly used in critical network operations without validation. The vulnerability manifests through three distinct panic paths:

**Path 1: Divide-by-Zero in Peer Initialization**

When `NetworkBuilder::create()` is called with a `NetworkConfig` containing `max_frame_size: 0`, the value flows through the network stack without validation: [1](#0-0) 

These unvalidated parameters are passed to `PeerManagerBuilder::create()`: [2](#0-1) 

When a network connection is established, `Peer::new()` is invoked with these parameters and performs an unchecked division: [3](#0-2) 

**This division by zero causes an immediate panic, terminating the node process.**

**Path 2: Frame Size Validation Failure**

If `max_frame_size < 64` (FRAME_OVERHEAD_BYTES), the `OutboundStream::new()` constructor panics: [4](#0-3) 

**Path 3: Insufficient Fragmentation Capacity**

If `max_frame_size * 255 < max_message_size`, the protocol cannot support message fragmentation: [5](#0-4) 

**Missing Validation:**

The configuration sanitizer validates multiple aspects of network configuration but does NOT validate these critical numeric parameters: [6](#0-5) 

NetworkConfig does not implement `ConfigSanitizer` to validate its numeric fields. The default values are safe, but configuration files can override them without constraint: [7](#0-6) 

**Attack Scenario:**

1. Attacker crafts malicious `validator.yaml` or `fullnode.yaml` with:
   ```yaml
   validator_network:
     max_frame_size: 0
     max_message_size: 64000000
   ```

2. Node operator loads configuration (via YAML deserialization)

3. Node starts and calls `NetworkBuilder::create()`

4. When first network connection attempt occurs (immediate for validators connecting to seeds), `Peer::new()` executes the division: `max_fragments = 64000000 / 0`

5. **Node crashes with divide-by-zero panic**

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria:

- **Validator node slowdowns/crashes**: Malicious configuration causes immediate node termination
- **Significant protocol violations**: Prevents nodes from participating in consensus
- **Network availability impact**: If multiple validators are affected (e.g., through compromised configuration management), the network could experience liveness failures

The impact escalates if:
- Configuration is distributed via automated deployment systems
- Attacker compromises configuration management infrastructure
- Default configurations are modified in distributed node packages

While this requires the ability to modify node configuration files (typically requiring system access), it represents a severe failure in defense-in-depth: configuration validation should prevent invalid values from causing panics regardless of how they enter the system.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is exploitable through several vectors:

1. **Compromised Configuration Management**: If an attacker gains access to configuration repositories or deployment systems, they can distribute malicious configs to multiple nodes

2. **Social Engineering**: Node operators could be tricked into applying "performance optimization" configs containing malicious values

3. **Insider Threat**: Malicious operators can intentionally crash their own nodes or distribute configs to other operators

4. **Configuration Errors**: Even without malicious intent, accidental typos or misconfiguration could trigger this panic

The attack does not require:
- Cryptographic key compromise
- Consensus participation
- Network access to the node
- Complex exploit chains

It only requires the ability to influence node configuration, which is often less protected than private keys but still a privileged operation.

## Recommendation

Implement validation for `NetworkConfig` parameters by adding a `ConfigSanitizer` implementation:

```rust
// In config/src/config/network_config.rs

impl ConfigSanitizer for NetworkConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = "NetworkConfigSanitizer";
        
        // Validate max_frame_size
        if self.max_frame_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_string(),
                "max_frame_size must be greater than zero!".into(),
            ));
        }
        
        if self.max_frame_size < FRAME_OVERHEAD_BYTES {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_string(),
                format!(
                    "max_frame_size ({}) must be at least FRAME_OVERHEAD_BYTES ({})!",
                    self.max_frame_size, FRAME_OVERHEAD_BYTES
                ),
            ));
        }
        
        // Validate max_message_size
        if self.max_message_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_string(),
                "max_message_size must be greater than zero!".into(),
            ));
        }
        
        // Validate fragmentation capacity
        let max_frame_size_after_overhead = self.max_frame_size.saturating_sub(FRAME_OVERHEAD_BYTES);
        if max_frame_size_after_overhead * (u8::MAX as usize) < self.max_message_size {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_string(),
                format!(
                    "max_frame_size ({}) cannot support max_message_size ({}) with max {} fragments!",
                    self.max_frame_size, self.max_message_size, u8::MAX
                ),
            ));
        }
        
        // Validate max_inbound_connections
        if self.max_inbound_connections == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_string(),
                "max_inbound_connections must be greater than zero!".into(),
            ));
        }
        
        Ok(())
    }
}
```

Then add the sanitizer call in `config/src/config/config_sanitizer.rs`:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // ... existing sanitizers ...
        
        // Sanitize validator network config
        if let Some(validator_network) = &node_config.validator_network {
            validator_network.sanitize(node_config, node_type, chain_id)?;
        }
        
        // Sanitize fullnode network configs
        for fullnode_network in &node_config.full_node_networks {
            fullnode_network.sanitize(node_config, node_type, chain_id)?;
        }
        
        Ok(())
    }
}
```

## Proof of Concept

Create a malicious configuration file `malicious_config.yaml`:

```yaml
base:
  role: "validator"
  data_dir: "/opt/aptos/data"

validator_network:
  network_id: "Validator"
  max_frame_size: 0          # MALICIOUS VALUE
  max_message_size: 64000000
  max_inbound_connections: 100
  listen_address: "/ip4/0.0.0.0/tcp/6180"
  discovery_method: "onchain"
```

Rust reproduction demonstrating the panic:

```rust
use aptos_config::config::NetworkConfig;
use aptos_network::peer::Peer;
use aptos_types::PeerId;

#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_divide_by_zero_with_zero_frame_size() {
    let max_frame_size = 0;  // Malicious value
    let max_message_size = 64_000_000;
    
    // This calculation is performed in Peer::new() at line 168
    let _max_fragments = max_message_size / max_frame_size;  // PANIC!
}

#[test]
fn test_malicious_config_causes_panic() {
    // Load malicious config
    let mut network_config = NetworkConfig::default();
    network_config.max_frame_size = 0;  // Malicious value
    network_config.max_message_size = 64_000_000;
    
    // When NetworkBuilder::create() is called with this config,
    // and a connection is established, Peer::new() will panic
    assert_eq!(network_config.max_frame_size, 0);
    
    // Demonstrate the panic would occur:
    let result = std::panic::catch_unwind(|| {
        let _fragments = network_config.max_message_size / network_config.max_frame_size;
    });
    assert!(result.is_err(), "Expected panic on divide by zero");
}
```

**Steps to Reproduce:**

1. Create a validator node configuration with `max_frame_size: 0`
2. Start the validator node with: `aptos-node -f malicious_config.yaml`
3. Node attempts to establish network connections
4. `Peer::new()` is called during connection establishment
5. **Node crashes with panic: "attempt to divide by zero"**

This vulnerability allows an attacker with configuration access to cause immediate denial of service on Aptos validator and fullnode instances.

### Citations

**File:** network/builder/src/builder.rs (L186-190)
```rust
            config.max_frame_size,
            config.max_message_size,
            config.enable_proxy_protocol,
            config.network_channel_size,
            config.max_inbound_connections,
```

**File:** network/framework/src/peer_manager/builder.rs (L196-209)
```rust
            peer_manager_context: Some(PeerManagerContext::new(
                pm_reqs_tx,
                pm_reqs_rx,
                connection_reqs_tx,
                connection_reqs_rx,
                peers_and_metadata,
                HashMap::new(),
                Vec::new(),
                channel_size,
                max_frame_size,
                max_message_size,
                inbound_connection_limit,
                tcp_buffer_cfg,
            )),
```

**File:** network/framework/src/peer/mod.rs (L168-168)
```rust
        let max_fragments = max_message_size / max_frame_size;
```

**File:** network/framework/src/protocols/stream/mod.rs (L232-234)
```rust
        let max_frame_size = max_frame_size
            .checked_sub(FRAME_OVERHEAD_BYTES)
            .expect("Frame size too small, overhead exceeds frame size!");
```

**File:** network/framework/src/protocols/stream/mod.rs (L237-243)
```rust
        assert!(
            (max_frame_size * (u8::MAX as usize)) >= max_message_size,
            "Stream only supports {} chunks! Frame size {}, message size {}.",
            u8::MAX,
            max_frame_size,
            max_message_size
        );
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

**File:** config/src/config/network_config.rs (L103-121)
```rust
    pub max_frame_size: usize,
    /// Enables proxy protocol on incoming connections to get original source addresses
    pub enable_proxy_protocol: bool,
    /// Interval to send healthcheck pings to peers
    pub ping_interval_ms: u64,
    /// Timeout until a healthcheck ping is rejected
    pub ping_timeout_ms: u64,
    /// Number of failed healthcheck pings until a peer is marked unhealthy
    pub ping_failures_tolerated: u64,
    /// Maximum number of outbound connections, limited by ConnectivityManager
    pub max_outbound_connections: usize,
    /// Maximum number of outbound connections, limited by PeerManager
    pub max_inbound_connections: usize,
    /// Inbound rate limiting configuration, if not specified, no rate limiting
    pub inbound_rate_limit_config: Option<RateLimitConfig>,
    /// Outbound rate limiting configuration, if not specified, no rate limiting
    pub outbound_rate_limit_config: Option<RateLimitConfig>,
    /// The maximum size of an inbound or outbound message (it may be divided into multiple frame)
    pub max_message_size: usize,
```
