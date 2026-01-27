# Audit Report

## Title
Missing Input Validation in AptosDataPollerConfig Allows Node Crash via Division by Zero

## Summary
The `AptosDataPollerConfig` struct lacks validation on construction, allowing configuration values such as `peer_bucket_size = 0` or `poll_loop_interval_ms = 0` that cause division by zero panics or complete failure of state synchronization when used by the data poller.

## Finding Description
The `AptosDataPollerConfig` struct is defined with no input validation mechanism. [1](#0-0)  The configuration only implements a `Default` trait with reasonable default values, but provides no safeguards against malicious or accidental misconfiguration.

The `StateSyncConfig::sanitize()` method delegates validation to `StateSyncDriverConfig` [2](#0-1)  but does not validate any fields within `AptosDataPollerConfig`.

This configuration is consumed by the `calculate_num_peers_to_poll()` function, which performs two critical division operations:

1. **Integer division by `peer_bucket_size`** at line 361, which will panic if the value is 0 [3](#0-2) 

2. **Floating-point division by `poll_loop_interval_ms`** at line 371, which produces infinity if the value is 0, causing polling to cease entirely [4](#0-3) 

**Attack Scenario:**
A node operator (or compromised deployment system) sets `peer_bucket_size: 0` in the configuration file. When the poller calls `calculate_num_peers_to_poll()` during normal state sync operations, the integer division by zero at line 361 causes an immediate panic, crashing the node.

Alternatively, setting `poll_loop_interval_ms: 0` causes `loops_per_second` to become `f64::INFINITY`, which in turn makes `num_peers_to_poll` evaluate to 0 at line 375, preventing any peer polling and halting state synchronization indefinitely.

## Impact Explanation
This qualifies as **High Severity** per the Aptos bug bounty criteria because it enables "Validator node slowdowns" and "API crashes." A node with these malicious configuration values will either:
- **Crash immediately** (peer_bucket_size = 0), causing complete loss of availability
- **Fail to synchronize state** (poll_loop_interval_ms = 0), rendering the node unable to participate in the network

However, this does **not** meet Critical severity because:
- It does not violate consensus safety
- It does not cause loss or freezing of funds
- It does not enable remote code execution
- It requires configuration file access (node operator privileges)

## Likelihood Explanation
**Likelihood: Medium-to-Low**

This vulnerability requires configuration file modification, which means:
1. A node operator must intentionally or accidentally set invalid values, OR
2. An attacker must compromise the node operator's system or deployment pipeline

While node operators are generally trusted actors, defense-in-depth principles require validating all inputs. Configuration errors are common in production systems, and the lack of validation makes the system fragile. The impact is severe (node crash), but the attack surface is limited to those with configuration access.

## Recommendation
Implement validation in the `ConfigSanitizer` trait for `AptosDataPollerConfig`. Add explicit checks to ensure all configuration values meet minimum requirements:

```rust
impl ConfigSanitizer for AptosDataPollerConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.state_sync.data_client.data_poller_config;

        // Validate poll_loop_interval_ms
        if config.poll_loop_interval_ms == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "poll_loop_interval_ms must be greater than 0".into(),
            ));
        }

        // Validate peer_bucket_size
        if config.peer_bucket_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "peer_bucket_size must be greater than 0".into(),
            ));
        }

        // Validate polling rate consistency
        if config.min_polls_per_second > config.max_polls_per_second {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "min_polls_per_second cannot exceed max_polls_per_second".into(),
            ));
        }

        Ok(())
    }
}
```

Update `StateSyncConfig::sanitize()` to include this validation.

## Proof of Concept
```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_peer_bucket_size_zero_causes_panic() {
    use aptos_config::config::AptosDataPollerConfig;
    use maplit::hashset;
    use aptos_network::network_id::NetworkId;
    use aptos_types::PeerId;
    use aptos_config::network_id::PeerNetworkId;

    // Create a malicious config with peer_bucket_size = 0
    let malicious_config = AptosDataPollerConfig {
        additional_polls_per_peer_bucket: 1,
        min_polls_per_second: 5,
        max_num_in_flight_priority_polls: 30,
        max_num_in_flight_regular_polls: 30,
        max_polls_per_second: 20,
        peer_bucket_size: 0, // MALICIOUS VALUE
        poll_loop_interval_ms: 100,
    };

    // Create some potential peers
    let peer1 = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let peer2 = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let potential_peers = hashset! { peer1, peer2 };

    // This will panic due to division by zero
    let _ = crate::poller::calculate_num_peers_to_poll(
        &potential_peers,
        10,
        malicious_config,
    );
}

#[test]
fn test_poll_loop_interval_zero_breaks_polling() {
    use aptos_config::config::AptosDataPollerConfig;
    use maplit::hashset;
    use aptos_network::network_id::NetworkId;
    use aptos_types::PeerId;
    use aptos_config::network_id::PeerNetworkId;

    // Create a malicious config with poll_loop_interval_ms = 0
    let malicious_config = AptosDataPollerConfig {
        additional_polls_per_peer_bucket: 1,
        min_polls_per_second: 5,
        max_num_in_flight_priority_polls: 30,
        max_num_in_flight_regular_polls: 30,
        max_polls_per_second: 20,
        peer_bucket_size: 10,
        poll_loop_interval_ms: 0, // MALICIOUS VALUE
    };

    // Create some potential peers
    let peer1 = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let peer2 = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let potential_peers = hashset! { peer1, peer2 };

    // This will return 0, causing no peers to be polled
    let num_peers = crate::poller::calculate_num_peers_to_poll(
        &potential_peers,
        10,
        malicious_config,
    );
    
    assert_eq!(num_peers, 0, "With poll_loop_interval_ms=0, no peers should be polled");
}
```

## Notes
While this vulnerability requires configuration file access (node operator privileges), it represents a critical defense-in-depth failure. The Aptos codebase implements `ConfigSanitizer` for many other configuration structures to prevent exactly these types of operational failures, but `AptosDataPollerConfig` lacks this protection. The severity is classified as High rather than Critical because exploitation requires privileged access rather than being exploitable by an unprivileged network participant.

### Citations

**File:** config/src/config/state_sync_config.rs (L327-358)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AptosDataPollerConfig {
    /// The additional number of polls to send per peer bucket (per second)
    pub additional_polls_per_peer_bucket: u64,
    /// The minimum number of polls that should be sent per second
    pub min_polls_per_second: u64,
    /// The maximum number of in-flight polls for priority peers
    pub max_num_in_flight_priority_polls: u64,
    /// The maximum number of in-flight polls for regular peers
    pub max_num_in_flight_regular_polls: u64,
    /// The maximum number of polls that should be sent per second
    pub max_polls_per_second: u64,
    /// The number of peers per bucket
    pub peer_bucket_size: u64,
    /// Interval (in ms) between summary poll loop executions
    pub poll_loop_interval_ms: u64,
}

impl Default for AptosDataPollerConfig {
    fn default() -> Self {
        Self {
            additional_polls_per_peer_bucket: 1,
            min_polls_per_second: 5,
            max_num_in_flight_priority_polls: 30,
            max_num_in_flight_regular_polls: 30,
            max_polls_per_second: 20,
            peer_bucket_size: 10,
            poll_loop_interval_ms: 100,
        }
    }
}
```

**File:** config/src/config/state_sync_config.rs (L487-495)
```rust
impl ConfigSanitizer for StateSyncConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // Sanitize the state sync driver config
        StateSyncDriverConfig::sanitize(node_config, node_type, chain_id)
    }
```

**File:** state-sync/aptos-data-client/src/poller.rs (L360-361)
```rust
    let total_polls_per_second = min_polls_per_second
        + (additional_polls_per_bucket * (potential_peers.len() as u64 / peer_bucket_sizes));
```

**File:** state-sync/aptos-data-client/src/poller.rs (L370-371)
```rust
    let mut loops_per_second =
        NUM_MILLISECONDS_IN_SECONDS / (data_poller_config.poll_loop_interval_ms as f64);
```
