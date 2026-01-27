# Audit Report

## Title
Missing Port Validation Allows Validators to Register Invalid Port 0 Causing Connection Failures

## Summary
The Aptos validator network address registration system lacks validation to prevent port 0 (or other invalid ports) from being registered. When a validator operator calls `update_network_and_fullnode_addresses`, no validation occurs on the port numbers embedded in the serialized `NetworkAddress`. This allows validators to register port 0, which is a reserved wildcard port that cannot be used for TCP connections, causing systematic connection failures for both the node health checker and inter-validator consensus communication.

## Finding Description

The vulnerability exists across multiple layers of the validator network configuration system:

**1. Missing Validation in On-Chain Registration**

When validator operators update their network addresses via the `update_network_and_fullnode_addresses` function, the Move code accepts raw BCS-serialized bytes without any validation: [1](#0-0) 

The function directly stores `new_network_addresses` and `new_fullnode_addresses` as opaque byte vectors without deserializing or validating the port numbers.

**2. No Validation in Port Extraction**

The `extract_network_address()` function extracts the port from the network address without validating that it's within the valid range (1-65535, excluding 0): [2](#0-1) 

The function extracts `addr.port()` which returns a `u16`, allowing port 0 to pass through without any checks.

**3. No Validation in NetworkAddress Parsing**

The `Protocol::Tcp(u16)` enum variant stores the port as a `u16`, which naturally allows values 0-65535: [3](#0-2) 

Port 0 can be parsed and stored without any validation.

**4. No Validation in Genesis Configuration**

Even during genesis validator validation, the `HostAndPort::from_str` function parses ports without validating they are non-zero: [4](#0-3) 

The parser accepts `u16::from_str()` which allows port 0.

**5. Connection Failures at TCP Layer**

When validators or the node checker attempt to connect to port 0, the TCP connection will fail because port 0 is a reserved wildcard port: [5](#0-4) 

Port 0 cannot be used as a listening port for remote connections - it's only valid for local binding where the OS assigns an ephemeral port.

## Impact Explanation

This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria for the following reasons:

1. **Validator Unavailability**: A validator registering port 0 becomes completely unreachable for consensus communication, effectively removing them from the network.

2. **Node Checker Failures**: The handshake checker will consistently fail when attempting to validate the validator: [6](#0-5) 

3. **Network Liveness Impact**: While primarily self-inflicted, if multiple validators accidentally or maliciously register port 0, it could affect network liveness if enough validators become unreachable.

4. **No On-Chain Recovery Path**: Once registered on-chain, the invalid port remains until the operator submits a corrective transaction, during which time the validator cannot participate in consensus.

This doesn't meet Critical severity because:
- It's primarily a self-DOS (validator hurts themselves)
- No funds are at risk
- Consensus safety is not violated (just liveness affected for that validator)
- The network can continue with remaining validators

It qualifies as Medium because it causes "state inconsistencies requiring intervention" - the validator's registered state is inconsistent with their actual network capability.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Common Configuration Error**: Port 0 could easily be entered accidentally during validator setup or configuration updates, especially in automated deployment scripts.

2. **No User Feedback**: The transaction to update network addresses will succeed on-chain even with port 0, providing no immediate indication of the error.

3. **Delayed Detection**: The problem only manifests when:
   - Other validators attempt to connect during epoch transitions
   - The node health checker runs periodic checks
   - New peers try to establish connections

4. **No Protection Layer**: Every validation layer that could catch this issue is missing the check:
   - Move smart contract validation ❌
   - Network address parsing ❌
   - Genesis configuration validation ❌
   - Port extraction validation ❌

## Recommendation

Add port validation at multiple defensive layers:

**1. Add On-Chain Validation in Move**

Modify `update_network_and_fullnode_addresses` to deserialize and validate network addresses before accepting them. However, this is gas-intensive for Move, so prefer Rust-side validation.

**2. Add Validation in HostAndPort Parsing**

```rust
impl FromStr for HostAndPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::Error::msg(
                "Invalid host and port, must be of the form 'host:port` e.g. '127.0.0.1:6180'",
            ));
        }
        let host_str = *parts.first().unwrap();
        if host_str.trim().is_empty() {
            return Err(anyhow::Error::msg("Invalid host, host is empty"));
        }
        let host = DnsName::from_str(host_str)?;
        let port = u16::from_str(parts.get(1).unwrap())?;
        
        // ADD THIS VALIDATION
        if port == 0 {
            return Err(anyhow::Error::msg(
                "Invalid port: port 0 is reserved and cannot be used for network connections"
            ));
        }
        
        Ok(HostAndPort { host, port })
    }
}
```

**3. Add Validation in extract_network_address**

```rust
pub fn extract_network_address(network_address: &NetworkAddress) -> Result<(Url, u16)> {
    let mut socket_addrs = network_address
        .to_socket_addrs()
        .with_context(|| format!("Failed to parse network address as SocketAddr..."))?;
    let socket_addr = socket_addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("No socket address found"))?;
    match socket_addr {
        SocketAddr::V4(addr) => {
            let port = addr.port();
            // ADD THIS VALIDATION
            if port == 0 {
                return Err(anyhow::anyhow!(
                    "Invalid port 0: port must be in range 1-65535"
                ));
            }
            Ok((
                Url::parse(&format!("http://{}", addr.ip()))
                    .context("Failed to parse address as URL")?,
                port,
            ))
        },
        SocketAddr::V6(addr) => Err(anyhow::anyhow!(
            "We do not support IPv6 addresses: {}",
            addr
        )),
    }
}
```

**4. Add Validation in Genesis Validator Checks**

Extend `validate_validators` to validate that ports in validator hosts are non-zero.

## Proof of Concept

**Step 1: Validator Setup with Port 0**

```rust
// In validator operator code
use aptos_sdk::types::network_address::{NetworkAddress, Protocol};
use std::str::FromStr;

#[test]
fn test_port_zero_registration() {
    // Create a network address with port 0
    let addr_str = "/ip4/127.0.0.1/tcp/0/noise-ik/080e287879c918794170e258bfaddd75acac5b3e350419044655e4983a487120/handshake/0";
    let network_addr = NetworkAddress::from_str(addr_str).unwrap();
    
    // This succeeds - no validation!
    assert!(network_addr.find_port() == Some(0));
    
    // Serialize for on-chain registration
    let serialized = bcs::to_bytes(&network_addr).unwrap();
    
    // Call update_network_and_fullnode_addresses with this - it will succeed
    // The validator is now registered with port 0 on-chain
}
```

**Step 2: Connection Attempt Fails**

```rust
use tokio::net::TcpStream;

#[tokio::test]
async fn test_connection_to_port_zero_fails() {
    // Attempt to connect to port 0
    let result = TcpStream::connect("127.0.0.1:0").await;
    
    // This will fail with connection refused or invalid argument
    assert!(result.is_err());
    // Error: "Connection refused" or "Invalid argument"
}
```

**Step 3: Node Checker Fails**

When the node health checker runs against this validator:
- `extract_network_address()` extracts port 0
- `resolve_and_connect()` attempts to connect to port 0
- Connection fails with `io::Error`
- Validator is marked as unreachable

**Step 4: Consensus Communication Fails**

Other validators attempting to establish connections for consensus:
- Parse the on-chain `NetworkAddress` 
- Extract port 0
- Attempt TCP connection to port 0
- Fail to establish connection
- Validator is effectively excluded from consensus

The validator remains in this broken state until the operator realizes the issue and submits a corrective transaction with a valid port number.

---

**Notes**

This vulnerability demonstrates a classic "defense in depth" failure where multiple validation layers that should catch invalid input all fail to do so. The issue is particularly insidious because the invalid configuration is accepted and stored on-chain, creating a persistent problem that only manifests during actual network operations. While port 0 is the most obvious invalid port, the same lack of validation could theoretically allow other problematic ports (e.g., reserved system ports) to be registered, though those would fail for different reasons.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L955-995)
```text
    public entry fun update_network_and_fullnode_addresses(
        operator: &signer,
        pool_address: address,
        new_network_addresses: vector<u8>,
        new_fullnode_addresses: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_network_addresses = validator_info.network_addresses;
        validator_info.network_addresses = new_network_addresses;
        let old_fullnode_addresses = validator_info.fullnode_addresses;
        validator_info.fullnode_addresses = new_fullnode_addresses;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateNetworkAndFullnodeAddresses {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.update_network_and_fullnode_addresses_events,
                UpdateNetworkAndFullnodeAddressesEvent {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        };
    }
```

**File:** ecosystem/node-checker/fn-check-client/src/helpers.rs (L12-30)
```rust
pub fn extract_network_address(network_address: &NetworkAddress) -> Result<(Url, u16)> {
    let mut socket_addrs = network_address
        .to_socket_addrs()
        .with_context(|| format!("Failed to parse network address as SocketAddr, this might imply that the domain name doesn't resolve to an IP: {}", network_address))?;
    let socket_addr = socket_addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("No socket address found"))?;
    match socket_addr {
        SocketAddr::V4(addr) => Ok((
            Url::parse(&format!("http://{}", addr.ip()))
                .context("Failed to parse address as URL")?,
            addr.port(),
        )),
        SocketAddr::V6(addr) => Err(anyhow::anyhow!(
            "We do not not support IPv6 addresses: {}",
            addr
        )),
    }
}
```

**File:** types/src/network_address/mod.rs (L111-127)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum Protocol {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Dns(DnsName),
    Dns4(DnsName),
    Dns6(DnsName),
    Tcp(u16),
    Memory(u16),
    // human-readable x25519::PublicKey is lower-case hex encoded
    NoiseIK(x25519::PublicKey),
    // TODO(philiphayes): use actual handshake::MessagingProtocolVersion. we
    // probably need to move network wire into its own crate to avoid circular
    // dependency b/w network and types.
    Handshake(u8),
}
```

**File:** crates/aptos-genesis/src/config.rs (L326-346)
```rust
impl FromStr for HostAndPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(':').collect();
        if parts.len() != 2 {
            Err(anyhow::Error::msg(
                "Invalid host and port, must be of the form 'host:port` e.g. '127.0.0.1:6180'",
            ))
        } else {
            let host_str = *parts.first().unwrap();
            if host_str.trim().is_empty() {
                Err(anyhow::Error::msg("Invalid host, host is empty"))
            } else {
                let host = DnsName::from_str(host_str)?;
                let port = u16::from_str(parts.get(1).unwrap())?;
                Ok(HostAndPort { host, port })
            }
        }
    }
}
```

**File:** network/netcore/src/transport/tcp.rs (L199-219)
```rust
pub async fn connect_with_config(
    port: u16,
    ipaddr: std::net::IpAddr,
    tcp_buff_cfg: TCPBufferCfg,
) -> io::Result<TcpStream> {
    let addr = SocketAddr::new(ipaddr, port);

    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    if let Some(rx_buf) = tcp_buff_cfg.outbound_rx_buffer_bytes {
        socket.set_recv_buffer_size(rx_buf)?;
    }
    if let Some(tx_buf) = tcp_buff_cfg.outbound_tx_buffer_bytes {
        socket.set_send_buffer_size(tx_buf)?;
    }
    socket.connect(addr).await
}
```

**File:** ecosystem/node-checker/src/checker/handshake.rs (L38-78)
```rust
impl Checker for HandshakeChecker {
    /// Assert that we can establish a noise connection with the target node
    /// with the given public key. If we cannot, it implies that either the
    /// node is not listening on that port, or the node is not running with
    /// the private key matching the public key provided as part of the request
    /// to NHC.
    async fn check(
        &self,
        providers: &ProviderCollection,
    ) -> Result<Vec<CheckResult>, CheckerError> {
        let target_noise_provider = get_provider!(
            providers.target_noise_provider,
            self.config.common.required,
            NoiseProvider
        );

        Ok(vec![
            match target_noise_provider.establish_connection().await {
                Ok(message) => Self::build_result(
                    "Noise connection established successfully".to_string(),
                    100,
                    format!(
                        "{}. This indicates your noise port ({}) is open and the node is \
                    running with the private key matching the provided public key.",
                        message,
                        target_noise_provider.network_address.find_port().unwrap()
                    ),
                ),
                Err(err) => Self::build_result(
                    "Failed to establish noise connection".to_string(),
                    0,
                    format!(
                        "{:#}. Either the noise port ({}) is closed or the node is not \
                    running with the private key matching the provided public key.",
                        err,
                        target_noise_provider.network_address.find_port().unwrap()
                    ),
                ),
            },
        ])
    }
```
