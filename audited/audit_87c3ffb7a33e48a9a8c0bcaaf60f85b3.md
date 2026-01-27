# Audit Report

## Title
Proxy Protocol Source IP Spoofing via Unauthenticated Header Injection

## Summary
The `enable_proxy_protocol` feature in the network layer accepts proxy protocol v2 headers from ANY incoming connection without validating the source. When enabled, an attacker with direct network access to the node can inject arbitrary source IP addresses, bypassing IP-based rate limiting and access controls implemented at the HAProxy layer.

## Finding Description

When `enable_proxy_protocol` is configured to `true`, the Aptos node's network layer reads proxy protocol v2 headers from incoming TCP connections to extract the "real" client IP address. This is intended for deployment behind load balancers like HAProxy. [1](#0-0) 

The proxy protocol header parsing occurs in the `upgrade_inbound()` function BEFORE any cryptographic authentication: [2](#0-1) 

The proxy protocol implementation blindly trusts headers from any connection: [3](#0-2) 

**The Critical Flaw**: There is NO validation that the connection originates from a trusted proxy. Any attacker can connect directly to the node and send crafted proxy protocol headers claiming to be from any IP address.

**Exploitation Path**:
1. Operator enables `enable_proxy_protocol: true` in node configuration
2. Node port is exposed directly to the internet (misconfiguration), OR attacker bypasses HAProxy
3. Attacker connects directly and sends valid proxy protocol v2 header with spoofed source IP
4. Node accepts the spoofed IP, which becomes part of `ConnectionMetadata.addr`
5. Security controls that rely on source IP (logging, metrics, potential rate limiting) are evaded

**Evidence of IP-Based Security Controls**:

The HAProxy configuration implements IP-based blocking and rate limiting: [4](#0-3) 

The network configuration supports IP-based rate limiting: [5](#0-4) 

HAProxy conditionally sends proxy protocol headers to backends: [6](#0-5) 

The fullnode configuration inherits the proxy protocol setting from HAProxy configuration: [7](#0-6) 

## Impact Explanation

**Severity: Medium** ($10,000 category)

This vulnerability allows attackers to:
1. **Bypass IP-based blocking**: Spoof whitelisted IP addresses to evade blocked.ips filters
2. **Evade rate limiting**: Rotate spoofed IPs to bypass per-IP bandwidth limits (50 MB/s in HAProxy config)
3. **Obscure attack attribution**: Security monitoring logs spoofed IPs instead of real attacker addresses
4. **Cause state inconsistencies**: Different nodes may receive connections with different spoofed IPs, leading to inconsistent logging and metrics

While this doesn't directly compromise consensus or cause funds loss, it can facilitate:
- DoS attacks by evading rate limits
- Unauthorized access if IP-based ACLs are used
- Operational confusion during incident response

The impact is limited to "Medium" because:
- It requires misconfiguration (exposed port + enabled proxy protocol)
- It doesn't directly affect consensus, execution, or storage layers
- HAProxy should normally prevent direct access to the node

## Likelihood Explanation

**Likelihood: Low to Medium**

The attack requires:
1. Node operator explicitly enables `enable_proxy_protocol: true` (disabled by default)
2. Node's listening port is exposed directly to the internet, OR attacker can bypass HAProxy
3. Attacker has network access to the node

**Mitigating Factors**:
- Proxy protocol is disabled by default
- Production deployments typically run nodes behind HAProxy with proper network isolation
- Kubernetes/cloud deployments use network policies to restrict access

**Aggravating Factors**:
- Once enabled, there's no way to restrict which sources can send proxy protocol headers
- Misconfigured deployments or testing environments may expose ports directly
- The vulnerability is silent - operators won't detect IP spoofing without deep packet inspection

## Recommendation

Implement trusted proxy source validation:

```rust
// In TransportContext
pub struct TransportContext {
    chain_id: ChainId,
    supported_protocols: ProtocolIdSet,
    authentication_mode: AuthenticationMode,
    peers_and_metadata: Arc<PeersAndMetadata>,
    enable_proxy_protocol: bool,
    trusted_proxy_sources: Option<HashSet<IpAddr>>, // NEW FIELD
}
```

Modify `upgrade_inbound()` to validate the connection source:

```rust
async fn upgrade_inbound<T: TSocket>(
    ctxt: Arc<UpgradeContext>,
    fut_socket: impl Future<Output = io::Result<T>>,
    addr: NetworkAddress,
    proxy_protocol_enabled: bool,
    trusted_proxies: Option<HashSet<IpAddr>>, // NEW PARAMETER
) -> io::Result<Connection<NoiseStream<T>>> {
    let origin = ConnectionOrigin::Inbound;
    let mut socket = fut_socket.await?;

    let addr = if proxy_protocol_enabled {
        // Validate source IP if trusted proxies are configured
        if let Some(trusted) = &trusted_proxies {
            if let Some(source_ip) = addr.find_ip_addr() {
                if !trusted.contains(&source_ip) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("Proxy protocol headers not allowed from {}", source_ip)
                    ));
                }
            }
        }
        
        proxy_protocol::read_header(&addr, &mut socket).await?
    } else {
        addr
    };
    // ... rest of function
}
```

Add configuration option:

```yaml
full_node_networks:
- network_id: "public"
  enable_proxy_protocol: true
  trusted_proxy_sources: ["10.0.0.1", "10.0.0.2"]  # NEW FIELD
```

## Proof of Concept

```rust
use aptos_netcore::transport::proxy_protocol;
use aptos_types::network_address::NetworkAddress;
use tokio::io::AsyncWriteExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::test]
async fn test_proxy_protocol_spoofing() {
    // Create a fake TCP connection
    let (mut client, mut server) = tokio::io::duplex(1024);
    
    // Attacker crafts proxy protocol v2 header claiming to be from 1.2.3.4
    let spoofed_ip = Ipv4Addr::new(1, 2, 3, 4);
    let spoofed_port = 12345u16;
    
    // Build proxy protocol v2 header
    let mut header = Vec::new();
    header.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]); // Signature
    header.push(0x21); // Version 2, PROXY command
    header.push(0x11); // IPv4 TCP
    header.extend_from_slice(&[0x00, 0x0C]); // Length = 12 bytes
    header.extend_from_slice(&spoofed_ip.octets()); // Source address
    header.extend_from_slice(&[0, 0, 0, 0]); // Dest address (ignored)
    header.extend_from_slice(&spoofed_port.to_be_bytes()); // Source port
    header.extend_from_slice(&80u16.to_be_bytes()); // Dest port
    
    // Send the spoofed header
    client.write_all(&header).await.unwrap();
    
    // Node reads and trusts the spoofed IP
    let original_addr = NetworkAddress::from(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        6180
    ));
    
    let extracted_addr = proxy_protocol::read_header(&original_addr, &mut server).await.unwrap();
    
    // Verify the spoofed IP was accepted
    assert_eq!(
        extracted_addr.find_ip_addr().unwrap(),
        IpAddr::V4(spoofed_ip)
    );
    
    // The node now believes the connection is from 1.2.3.4 instead of 192.168.1.100
    // This bypasses any IP-based rate limiting or blocking
}
```

## Notes

This vulnerability is a **deployment security issue** that exists when:
1. Proxy protocol is explicitly enabled AND
2. The node port is directly accessible without HAProxy protection

The fix should make proxy protocol source validation mandatory when the feature is enabled, requiring operators to explicitly whitelist trusted proxy IP addresses. This follows security best practices for proxy protocol implementations (similar to NGINX's `set_real_ip_from` directive).

### Citations

**File:** network/builder/src/builder.rs (L83-103)
```rust
        enable_proxy_protocol: bool,
        network_channel_size: usize,
        inbound_connection_limit: usize,
        tcp_buffer_cfg: TCPBufferCfg,
    ) -> Self {
        // A network cannot exist without a PeerManager
        // TODO:  construct this in create and pass it to new() as a parameter. The complication is manual construction of NetworkBuilder in various tests.
        let peer_manager_builder = PeerManagerBuilder::create(
            chain_id,
            network_context,
            time_service.clone(),
            listen_address,
            peers_and_metadata.clone(),
            authentication_mode,
            network_channel_size,
            max_frame_size,
            max_message_size,
            enable_proxy_protocol,
            inbound_connection_limit,
            tcp_buffer_cfg,
        );
```

**File:** network/framework/src/transport/mod.rs (L249-274)
```rust
async fn upgrade_inbound<T: TSocket>(
    ctxt: Arc<UpgradeContext>,
    fut_socket: impl Future<Output = io::Result<T>>,
    addr: NetworkAddress,
    proxy_protocol_enabled: bool,
) -> io::Result<Connection<NoiseStream<T>>> {
    let origin = ConnectionOrigin::Inbound;
    let mut socket = fut_socket.await?;

    // If we have proxy protocol enabled, process the event, otherwise skip it
    // TODO: This would make more sense to build this in at instantiation so we don't need to put the if statement here
    let addr = if proxy_protocol_enabled {
        proxy_protocol::read_header(&addr, &mut socket)
            .await
            .map_err(|err| {
                debug!(
                    network_address = addr,
                    error = %err,
                    "ProxyProtocol: Failed to read header: {}",
                    err
                );
                err
            })?
    } else {
        addr
    };
```

**File:** network/netcore/src/transport/proxy_protocol.rs (L51-132)
```rust
pub async fn read_header<T: AsyncRead + std::marker::Unpin>(
    original_addr: &NetworkAddress,
    stream: &mut T,
) -> io::Result<NetworkAddress> {
    // This is small enough that it should not be fragmented by TCP
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;

    // If it's not proxy protocol, let's stop
    if header[0..12] != PPV2_SIGNATURE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ProxyProtocol: Invalid signature",
        ));
    }

    // High 4 bits is version, low 4 bits is command
    let version_and_command = header[12];
    match version_and_command {
        PPV2_LOCAL | PPV2_PROXY => (),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProxyProtocol: Unsupported command or protocol version",
            ));
        },
    };

    // High 4 bits is family, low 4 bits is protocol
    let family_and_protocol = header[13];
    let address_size: [u8; 2] = header[14..16].try_into().unwrap();
    let address_size = u16::from_be_bytes(address_size);

    let mut address_bytes: Vec<u8> = vec![0; address_size as usize];
    stream.read_exact(&mut address_bytes).await?;

    let source_address = match family_and_protocol {
        // TODO: Support UDP in the future
        LOCAL_PROTOCOL | UDP_IPV4 | UDP_IPV6 | TCP_UNIX | UDP_UNIX => {
            // UNSPEC, UDP, and UNIX Steam/datagram
            // Accept connection but ignore address info as per spec
            original_addr.clone()
        },
        TCP_IPV4 => {
            // This is not mentioned in the spec, but if it doesn't match we might not read correctly
            if address_size < IPV4_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ProxyProtocol: Header size doesn't match expected address type",
                ));
            }

            let src_addr = u32::from_be_bytes(address_bytes[0..4].try_into().unwrap());
            let src_port = u16::from_be_bytes(address_bytes[8..10].try_into().unwrap());
            let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_addr)), src_port);
            NetworkAddress::from(socket_addr)
        },
        TCP_IPV6 => {
            // This is not mentioned in the spec, but if it doesn't match we might not read correctly
            if address_size < IPV6_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ProxyProtocol: Header size doesn't match expected address type",
                ));
            }

            let src_addr = u128::from_be_bytes(address_bytes[0..16].try_into().unwrap());
            let src_port = u16::from_be_bytes(address_bytes[32..34].try_into().unwrap());

            let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src_addr)), src_port);
            NetworkAddress::from(socket_addr)
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProxyProtocol: Unsupported Address Family or Protocol",
            ));
        },
    };

    Ok(source_address)
}
```

**File:** docker/compose/aptos-node/haproxy.cfg (L43-56)
```text
    # Deny requests from blocked IPs
    tcp-request connection silent-drop if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    # Create TCP request bandwidth limits of 25 MB/s (per TCP stream)
    filter bwlim-in incoming-limit default-limit 25m default-period 1s
    filter bwlim-out outgoing-limit default-limit 25m default-period 1s
    tcp-request content set-bandwidth-limit incoming-limit
    tcp-request content set-bandwidth-limit outgoing-limit

    # Create TCP request bandwidth limits of 50 MB/s (per source IP)
    filter bwlim-in incoming-src-limit key src table limit-by-src limit 50m
    filter bwlim-out outgoing-src-limit key src table limit-by-src limit 50m
    tcp-request content set-bandwidth-limit incoming-src-limit
    tcp-request content set-bandwidth-limit outgoing-src-limit
```

**File:** config/src/config/network_config.rs (L366-388)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Maximum number of bytes/s for an IP
    pub ip_byte_bucket_rate: usize,
    /// Maximum burst of bytes for an IP
    pub ip_byte_bucket_size: usize,
    /// Initial amount of tokens initially in the bucket
    pub initial_bucket_fill_percentage: u8,
    /// Allow for disabling the throttles
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_byte_bucket_rate: IP_BYTE_BUCKET_RATE,
            ip_byte_bucket_size: IP_BYTE_BUCKET_SIZE,
            initial_bucket_fill_percentage: 25,
            enabled: true,
        }
    }
}
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L159-162)
```text
## Specify the PFN network backend
backend {{ $config.name }}-aptosnet
    default-server maxconn {{ $.Values.fullnode.config.max_inbound_connections }} {{ if $.Values.haproxy.config.send_proxy_protocol }}send-proxy-v2{{ end }}
    server {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-{{ $config.name }} {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-{{ $config.name }}:6182
```

**File:** terraform/helm/aptos-node/files/configs/fullnode-base.yaml (L20-26)
```yaml
- network_id: "public"
  discovery_method: "onchain"
  listen_address: "/ip4/0.0.0.0/tcp/6182"
  identity:
    type: "from_file"
    path: "/opt/aptos/genesis/validator-full-node-identity.yaml"
  enable_proxy_protocol: {{ $.Values.haproxy.config.send_proxy_protocol }}
```
