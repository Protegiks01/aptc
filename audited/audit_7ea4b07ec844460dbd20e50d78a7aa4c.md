# Audit Report

## Title
Config Sanitizer Bypass Allows Netbench Service on Mainnet Validators Exposing Network Performance Reconnaissance

## Summary
The `skip_config_sanitizer` flag in `NodeStartupConfig` bypasses all configuration validation, including the critical check that prevents the network benchmarking service (netbench) from running on mainnet. This allows mainnet validators to enable netbench, exposing network performance measurement endpoints to any connected peer, enabling reconnaissance attacks and resource consumption.

## Finding Description

The Aptos node configuration system includes a sanitizer mechanism that validates configurations before node startup. The `NetbenchConfig` sanitizer explicitly prevents netbench from being enabled on testnet or mainnet networks. [1](#0-0) 

However, the `NodeConfig::sanitize()` function checks the `skip_config_sanitizer` flag at the beginning and returns early without performing any validation if this flag is set to `true`: [2](#0-1) 

This bypass is called during node startup in the config loading process: [3](#0-2) 

When netbench is enabled, the service is registered on all network interfaces during network setup, including public-facing fullnode networks: [4](#0-3) 

The netbench service then starts and automatically responds to benchmark messages from any connected peer: [5](#0-4) 

**Attack Path:**
1. A mainnet validator sets `skip_config_sanitizer: true` and `netbench.enabled: true` in their node configuration
2. The sanitizer bypass allows the configuration to pass validation despite being on mainnet
3. The netbench service starts on all networks, including public/VFN networks that accept connections from untrusted peers
4. An attacker connects as a peer to the validator's public network endpoint
5. The attacker sends `NetbenchMessage::DataSend` messages to measure network latency with microsecond precision
6. The validator automatically responds with `NetbenchMessage::DataReply` containing timing information
7. The attacker can continuously probe to build a performance profile of the validator's network infrastructure

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Information Disclosure**: Exposes precise network performance characteristics (latency, throughput, response times) that should not be available on production networks. The netbench config explicitly documents this restriction. [6](#0-5) 

2. **Attack Reconnaissance**: Network timing information can be used to:
   - Identify validators with poor network performance for targeted attacks
   - Correlate network behavior with on-chain activity
   - Map validator infrastructure and network topology
   - Prepare timing-based attacks against consensus

3. **Resource Consumption**: While the netbench service has rate limits, an attacker can consume validator network bandwidth and processing resources through continuous benchmark traffic

4. **Security Policy Violation**: This directly violates the documented security requirement that netbench must never run on mainnet, representing a critical configuration validation failure

The impact does not reach High or Critical severity because it does not directly cause consensus violations, loss of funds, or total liveness failures. However, it enables reconnaissance that could facilitate more severe attacks and violates an explicit security boundary.

## Likelihood Explanation

The likelihood of exploitation is **Medium to High**:

**Prerequisites:**
- A mainnet validator must explicitly set `skip_config_sanitizer: true` in their configuration
- The validator must also set `netbench.enabled: true`
- Both settings must be present in the configuration file

**Attacker Requirements:**
- Ability to connect to the validator's public or VFN network (standard P2P connection)
- Knowledge of the netbench protocol (documented in codebase)
- No special privileges or authentication beyond basic peer connection

**Execution Complexity:**
- Low - Once a validator has the misconfiguration, exploitation is trivial
- The netbench service automatically responds to any peer's benchmark messages
- No authentication checks beyond the standard P2P handshake [7](#0-6) 

While `skip_config_sanitizer` is intended as a testing/debugging feature and defaults to `false`, the existence of this bypass creates a vulnerability if misused. [8](#0-7) 

## Recommendation

**Primary Fix**: Remove the global sanitizer bypass or restrict netbench sanitization to be unskippable:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // Always sanitize critical security configs even if skip_config_sanitizer is set
        // Netbench must NEVER be enabled on mainnet/testnet
        NetbenchConfig::sanitize(node_config, node_type, chain_id)?;
        
        // If config sanitization is disabled, skip other checks
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }

        // Sanitize all other sub-configs...
        AdminServiceConfig::sanitize(node_config, node_type, chain_id)?;
        // ... rest of sanitizers
        
        Ok(())
    }
}
```

**Alternative Fix**: Add a dedicated flag for netbench that cannot be bypassed:

```rust
impl ConfigSanitizer for NetbenchConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // This check should NEVER be skippable - netbench is a security-critical restriction
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.netbench.is_none() {
            return Ok(());
        }

        let netbench_config = node_config.netbench.unwrap();
        if !netbench_config.enabled {
            return Ok(());
        }

        // CRITICAL: Always enforce mainnet/testnet restriction regardless of skip_config_sanitizer
        if let Some(chain_id) = chain_id {
            if chain_id.is_testnet() || chain_id.is_mainnet() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "SECURITY VIOLATION: The netbench application must never be enabled in testnet or mainnet! This restriction cannot be bypassed."
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}
```

**Additional Hardening**: Add runtime validation in the netbench service startup:

```rust
pub fn start_netbench_service(
    node_config: &NodeConfig,
    network_interfaces: ApplicationNetworkInterfaces<NetbenchMessage>,
    runtime: &Handle,
) {
    // Runtime check: verify we're not on mainnet/testnet
    // This provides defense-in-depth even if config validation is bypassed
    if let Some(chain_id) = /* obtain chain_id */ {
        if chain_id.is_mainnet() || chain_id.is_testnet() {
            panic!("SECURITY VIOLATION: Attempted to start netbench service on mainnet/testnet!");
        }
    }
    
    let network_client = network_interfaces.network_client;
    runtime.spawn(run_netbench_service(
        node_config.clone(),
        network_client,
        network_interfaces.network_service_events,
        TimeService::real(),
    ));
}
```

## Proof of Concept

```rust
#[test]
fn test_netbench_mainnet_bypass_via_skip_sanitizer() {
    use aptos_config::config::{
        config_sanitizer::ConfigSanitizer, 
        node_config_loader::NodeType,
        node_startup_config::NodeStartupConfig,
        netbench_config::NetbenchConfig,
        NodeConfig
    };
    use aptos_types::chain_id::ChainId;

    // Create a node config with netbench enabled on mainnet
    let mut node_config = NodeConfig {
        node_startup: NodeStartupConfig {
            skip_config_sanitizer: false,  // Normal sanitization
            ..Default::default()
        },
        netbench: Some(NetbenchConfig {
            enabled: true,  // Trying to enable on mainnet
            ..Default::default()
        }),
        ..Default::default()
    };

    // This should fail - netbench not allowed on mainnet
    let result = NodeConfig::sanitize(
        &node_config, 
        NodeType::Validator, 
        Some(ChainId::mainnet())
    );
    assert!(result.is_err(), "Netbench should be blocked on mainnet");

    // Now bypass the sanitizer
    node_config.node_startup.skip_config_sanitizer = true;

    // This should pass - sanitizer is bypassed!
    let result = NodeConfig::sanitize(
        &node_config, 
        NodeType::Validator, 
        Some(ChainId::mainnet())
    );
    assert!(result.is_ok(), "Sanitizer bypass allows netbench on mainnet");

    // Verify netbench config is still enabled
    assert!(node_config.netbench.unwrap().enabled);
    
    // At this point, netbench service would start on mainnet
    // exposing network benchmarking endpoints to any connected peer
}
```

## Notes

This vulnerability demonstrates a critical design flaw in the configuration validation bypass mechanism. While `skip_config_sanitizer` may be useful for testing, it should never bypass security-critical checks like the netbench mainnet restriction. The netbench service is explicitly documented as a testing/development tool that must not run on production networks, and this bypass undermines that security boundary.

The vulnerability affects validators who might use `skip_config_sanitizer` for operational convenience without understanding the security implications. The fix should ensure that certain critical security checks remain unskippable, maintaining defense-in-depth even when other validation is relaxed for operational reasons.

### Citations

**File:** config/src/config/netbench_config.rs (L65-74)
```rust
        // Otherwise, verify that netbench is not enabled in testnet or mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_testnet() || chain_id.is_mainnet() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The netbench application should not be enabled in testnet or mainnet!"
                        .to_string(),
                ));
            }
        }
```

**File:** config/src/config/config_sanitizer.rs (L46-48)
```rust
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/node_config_loader.rs (L143-144)
```rust
    // Sanitize the node config
    NodeConfig::sanitize(node_config, node_type, chain_id)
```

**File:** aptos-node/src/network.rs (L391-400)
```rust
        if let Some(app_config) = netbench_network_configuration(node_config) {
            let netbench_handle = register_client_and_service_with_network(
                &mut network_builder,
                network_id,
                &network_config,
                app_config,
                true,
            );
            netbench_handles.push(netbench_handle);
        }
```

**File:** network/benchmark/src/lib.rs (L92-117)
```rust
async fn handle_direct(
    network_client: &NetworkClient<NetbenchMessage>,
    network_id: NetworkId,
    peer_id: AccountAddress,
    msg_wrapper: NetbenchMessage,
    time_service: TimeService,
    shared: Arc<RwLock<NetbenchSharedState>>,
) {
    match msg_wrapper {
        NetbenchMessage::DataSend(send) => {
            let reply = NetbenchDataReply {
                request_counter: send.request_counter,
                send_micros: time_service.now_unix_time().as_micros() as u64,
                request_send_micros: send.send_micros,
            };
            let result = network_client.send_to_peer(
                NetbenchMessage::DataReply(reply),
                PeerNetworkId::new(network_id, peer_id),
            );
            if let Err(err) = result {
                direct_messages("reply_err");
                info!(
                    "netbench ds [{}] could not reply: {}",
                    send.request_counter, err
                );
            }
```

**File:** network/benchmark/src/lib.rs (L183-222)
```rust
async fn handler_task(
    network_client: NetworkClient<NetbenchMessage>,
    work_rx: async_channel::Receiver<(NetworkId, Event<NetbenchMessage>)>,
    time_service: TimeService,
    shared: Arc<RwLock<NetbenchSharedState>>,
) {
    loop {
        let (network_id, event) = match work_rx.recv().await {
            Ok(v) => v,
            Err(_) => {
                // RecvError means source was closed, we're done here.
                return;
            },
        };
        match event {
            Event::Message(peer_id, wat) => {
                let msg_wrapper: NetbenchMessage = wat;
                handle_direct(
                    &network_client,
                    network_id,
                    peer_id,
                    msg_wrapper,
                    time_service.clone(),
                    shared.clone(),
                )
                .await;
            },
            Event::RpcRequest(peer_id, msg_wrapper, protocol_id, sender) => {
                handle_rpc(
                    peer_id,
                    msg_wrapper,
                    protocol_id,
                    time_service.clone(),
                    sender,
                )
                .await;
            },
        }
    }
}
```

**File:** config/src/config/node_startup_config.rs (L10-10)
```rust
    pub skip_config_sanitizer: bool, // Whether or not to skip the config sanitizer at startup
```
