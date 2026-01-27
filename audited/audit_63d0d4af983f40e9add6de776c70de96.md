# Audit Report

## Title
Proxy Protocol Header Injection Allows IP Spoofing and Bypass of Network-Level Access Controls

## Summary
The `proxy_protocol::read_header()` function unconditionally trusts HAProxy Proxy Protocol V2 headers without validating the connection source, allowing attackers with direct network access to validator/fullnode ports to spoof their source IP address and bypass IP-based rate limiting, blocklists, and access controls.

## Finding Description

The Aptos network layer implements HAProxy Proxy Protocol V2 to preserve client source IP addresses when operating behind a load balancer. When `enable_proxy_protocol` is enabled in the network configuration, the inbound connection upgrade process calls `proxy_protocol::read_header()` to extract the client's source IP from the PPv2 header. [1](#0-0) 

The proxy protocol implementation reads and validates the PPv2 header structure but does not verify that the connection originates from a trusted proxy: [2](#0-1) 

The security model assumes that only HAProxy can connect to backend ports, which should be enforced by network isolation. However, the Kubernetes NetworkPolicy that would enforce this restriction is deprecated, broken with Cilium/GKE DataplaneV2, and **disabled by default**: [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. Attacker gains network access to validator/fullnode port (6180/6182) through:
   - Misconfigured firewall rules
   - Disabled/broken NetworkPolicy (default state)
   - Internal network position (compromised pod, insider threat)
   - Cloud security group misconfiguration

2. Attacker connects directly to the validator/fullnode, bypassing HAProxy

3. Attacker sends a crafted PPv2 header claiming to be from any IP address:
   ```
   [PPv2_SIGNATURE] [PPv2_PROXY] [TCP_IPV4] [12 bytes]
   [Spoofed Source IP] [Dest IP] [Source Port] [Dest Port]
   ```

4. The validator/fullnode accepts this header and uses the spoofed IP in `ConnectionMetadata.addr`

5. All IP-based security controls use the spoofed address:
   - HAProxy's IP blocklists are bypassed
   - HAProxy's per-IP bandwidth limits are bypassed  
   - Application-level rate limiting is bypassed
   - Logging shows incorrect source IPs [5](#0-4) [6](#0-5) 

The extracted address is stored in connection metadata without any validation: [7](#0-6) 

## Impact Explanation

**High Severity** - This vulnerability allows:

1. **Rate Limiting Bypass**: Attackers can claim different source IPs on each connection to evade per-IP rate limits configured in both HAProxy and application layers, enabling resource exhaustion attacks against validator/fullnode infrastructure

2. **Access Control Bypass**: Attackers can spoof IPs to bypass HAProxy's IP blocklists, potentially gaining access from blacklisted addresses or evading geographic restrictions

3. **DDoS Protection Evasion**: Attackers can distribute attack traffic across spoofed IP addresses, making it harder to identify and block malicious sources

4. **Forensics Poisoning**: Logs record spoofed IPs rather than true attack sources, severely hampering incident response and attribution

While this doesn't directly compromise consensus safety or cause fund loss, it qualifies as **High Severity** per Aptos bug bounty criteria for "Validator node slowdowns" and "Significant protocol violations" as it undermines critical network security controls protecting validator infrastructure.

## Likelihood Explanation

**Medium-High Likelihood** - The vulnerability is exploitable when:

1. `enable_proxy_protocol` is enabled (required for production deployments with HAProxy)
2. Network isolation fails (NetworkPolicy disabled by default, firewall misconfiguration common)
3. Attacker achieves direct network access (internal position, cloud misconfig, or pod escape)

Given that:
- NetworkPolicy is deprecated and disabled by default
- Production deployments use HAProxy with `send-proxy-v2` enabled
- Kubernetes environments are complex with frequent misconfigurations
- No code-level validation exists as a defense-in-depth measure

The likelihood of exploitable conditions is moderate to high, especially in multi-tenant or cloud environments.

## Recommendation

Implement trusted proxy source validation:

```rust
// In network_config.rs
pub struct NetworkConfig {
    // ... existing fields ...
    pub enable_proxy_protocol: bool,
    pub trusted_proxy_addresses: Option<HashSet<IpAddr>>, // NEW
}

// In proxy_protocol.rs
pub async fn read_header_from_trusted<T: AsyncRead + std::marker::Unpin>(
    original_addr: &NetworkAddress,
    stream: &mut T,
    peer_addr: Option<IpAddr>, // Actual TCP peer address
    trusted_proxies: Option<&HashSet<IpAddr>>,
) -> io::Result<NetworkAddress> {
    // If trusted proxies are configured, validate peer address
    if let (Some(peer), Some(trusted)) = (peer_addr, trusted_proxies) {
        if !trusted.contains(&peer) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("ProxyProtocol: Untrusted proxy address: {}", peer),
            ));
        }
    }
    
    // Proceed with existing header parsing...
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;
    // ... rest of existing implementation
}
```

**Additional recommendations:**

1. Make `trusted_proxy_addresses` mandatory when `enable_proxy_protocol` is true
2. Add monitoring/alerting for proxy protocol validation failures
3. Document the security requirement in configuration templates
4. Consider re-implementing NetworkPolicy or document firewall requirements clearly

## Proof of Concept

```rust
use aptos_netcore::transport::proxy_protocol;
use aptos_types::network_address::NetworkAddress;
use futures::io::AsyncWriteExt;
use tokio::io::AsyncWrite;

#[tokio::test]
async fn test_proxy_protocol_ip_spoofing() {
    // Simulated scenario: Attacker connects directly to validator port
    let (mut client, mut server) = tokio::io::duplex(1024);
    
    // Original address (HAProxy's address, not used securely)
    let original_addr = NetworkAddress::from_str("/ip4/10.0.0.1/tcp/6180").unwrap();
    
    // Attacker crafts PPv2 header claiming to be from a different IP
    let spoofed_ip = vec![192, 168, 1, 100]; // Attacker claims to be 192.168.1.100
    let dest_ip = vec![10, 0, 0, 2];
    let port = vec![0x00, 0x50]; // Port 80
    
    tokio::spawn(async move {
        // Send PPv2 signature
        client.write_all(&[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
        ]).await.unwrap();
        
        // Version 2, PROXY command
        client.write_all(&[0x21]).await.unwrap();
        
        // TCP IPv4
        client.write_all(&[0x11]).await.unwrap();
        
        // Address size (12 bytes)
        client.write_all(&[0x00, 0x0C]).await.unwrap();
        
        // Spoofed source IP
        client.write_all(&spoofed_ip).await.unwrap();
        
        // Destination IP  
        client.write_all(&dest_ip).await.unwrap();
        
        // Source and dest ports
        client.write_all(&port).await.unwrap();
        client.write_all(&port).await.unwrap();
    });
    
    // Validator accepts the spoofed IP without validation
    let extracted_addr = proxy_protocol::read_header(&original_addr, &mut server)
        .await
        .expect("Should parse valid PPv2 header");
    
    // Verify the spoofed IP was extracted
    assert!(extracted_addr.to_string().contains("192.168.1.100"));
    
    // In production, this spoofed IP would be used for:
    // - Rate limiting decisions (bypassed)
    // - Access control checks (bypassed)  
    // - Logging (poisoned)
    println!("VULNERABILITY: Accepted spoofed IP: {}", extracted_addr);
}
```

**Notes:**

This vulnerability exploits the trust boundary violation between HAProxy and backend services. The proxy protocol specification explicitly warns that it should only be enabled for connections from trusted sources, but Aptos Core lacks code-level enforcement of this requirement. Combined with deprecated network isolation controls, this creates an exploitable attack surface for IP spoofing attacks against validator infrastructure.

### Citations

**File:** network/framework/src/transport/mod.rs (L260-274)
```rust
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

**File:** network/framework/src/transport/mod.rs (L320-331)
```rust
    Ok(Connection {
        socket,
        metadata: ConnectionMetadata::new(
            remote_peer_id,
            CONNECTION_ID_GENERATOR.next(),
            addr,
            origin,
            messaging_protocol,
            application_protocols,
            peer_role,
        ),
    })
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

**File:** terraform/helm/aptos-node/values.yaml (L90-93)
```yaml
  # -- DEPRECATED: it's broken with Cillium a.k.a. GKE DataplaneV2.
  # -- templates/networkpolicy.yaml kept around for reference in case we want to resurrect it.
  # -- Lock down network ingress and egress with Kubernetes NetworkPolicy
  enableNetworkPolicy: false
```

**File:** terraform/helm/aptos-node/templates/networkpolicy.yaml (L20-36)
```yaml
  # HAproxy
  - from:
    - podSelector:
        matchLabels:
          {{- include "aptos-validator.selectorLabels" $ | nindent 10 }}
          app.kubernetes.io/name: haproxy
          app.kubernetes.io/instance: haproxy-{{$i}}
    ports:
      # AptosNet from HAproxy
    - protocol: TCP
      port: 6180
    - protocol: TCP
      port: 9101
  {{- if $.Values.service.validator.enableRestApi }}
      # REST API from HAproxy
    - protocol: TCP
      port: 8080
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

**File:** config/src/config/network_config.rs (L368-377)
```rust
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
```
