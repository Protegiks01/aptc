> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** network/netcore/src/transport/tcp.rs (L139-185)
```rust
    fn dial(&self, _peer_id: PeerId, addr: NetworkAddress) -> Result<Self::Outbound, Self::Error> {
        let protos = addr.as_slice();

        // ensure addr is well formed to save some work before potentially
        // spawning a dial task that will fail anyway.
        parse_ip_tcp(protos)
            .map(|_| ())
            .or_else(|| parse_dns_tcp(protos).map(|_| ()))
            .ok_or_else(|| invalid_addr_error(&addr))?;

        let proxy = Proxy::new();

        let proxy_addr = {
            use aptos_types::network_address::Protocol::*;

            let addr = match protos.first() {
                Some(Ip4(ip)) => proxy.https(&ip.to_string()),
                Some(Ip6(ip)) => proxy.https(&ip.to_string()),
                Some(Dns(name)) | Some(Dns4(name)) | Some(Dns6(name)) => proxy.https(name.as_ref()),
                _ => None,
            };

            addr.and_then(|https_proxy| Url::parse(https_proxy).ok())
                .and_then(|url| {
                    if url.has_host() && url.scheme() == "http" {
                        Some(format!(
                            "{}:{}",
                            url.host().unwrap(),
                            url.port_or_known_default().unwrap()
                        ))
                    } else {
                        None
                    }
                })
        };

        let f: Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>> =
            Box::pin(match proxy_addr {
                Some(proxy_addr) => Either::Left(connect_via_proxy(proxy_addr, addr)),
                None => Either::Right(resolve_and_connect(addr, self.tcp_buff_cfg)),
            });

        Ok(TcpOutbound {
            inner: f,
            config: self.clone(),
        })
    }
```

**File:** network/netcore/src/transport/tcp.rs (L189-197)
```rust
async fn resolve_with_filter(
    ip_filter: IpFilter,
    dns_name: &str,
    port: u16,
) -> io::Result<impl Iterator<Item = SocketAddr> + '_> {
    Ok(lookup_host((dns_name, port))
        .await?
        .filter(move |socketaddr| ip_filter.matches(socketaddr.ip())))
}
```

**File:** network/netcore/src/transport/tcp.rs (L221-259)
```rust
/// Note: we need to take ownership of this `NetworkAddress` (instead of just
/// borrowing the `&[Protocol]` slice) so this future can be `Send + 'static`.
pub async fn resolve_and_connect(
    addr: NetworkAddress,
    tcp_buff_cfg: TCPBufferCfg,
) -> io::Result<TcpStream> {
    let protos = addr.as_slice();

    if let Some(((ipaddr, port), _addr_suffix)) = parse_ip_tcp(protos) {
        // this is an /ip4 or /ip6 address, so we can just connect without any
        // extra resolving or filtering.
        connect_with_config(port, ipaddr, tcp_buff_cfg).await
    } else if let Some(((ip_filter, dns_name, port), _addr_suffix)) = parse_dns_tcp(protos) {
        // resolve dns name and filter
        let socketaddr_iter = resolve_with_filter(ip_filter, dns_name.as_ref(), port).await?;
        let mut last_err = None;

        // try to connect until the first succeeds
        for socketaddr in socketaddr_iter {
            match connect_with_config(socketaddr.port(), socketaddr.ip(), tcp_buff_cfg).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "could not resolve dns name to any address: name: {}, ip filter: {:?}",
                    dns_name.as_ref(),
                    ip_filter,
                ),
            )
        }))
    } else {
        Err(invalid_addr_error(&addr))
    }
}
```

**File:** types/src/network_address/mod.rs (L788-802)
```rust
pub enum IpFilter {
    Any,
    OnlyIp4,
    OnlyIp6,
}

impl IpFilter {
    pub fn matches(&self, ipaddr: IpAddr) -> bool {
        match self {
            IpFilter::Any => true,
            IpFilter::OnlyIp4 => ipaddr.is_ipv4(),
            IpFilter::OnlyIp6 => ipaddr.is_ipv6(),
        }
    }
}
```

**File:** types/src/network_address/mod.rs (L807-821)
```rust
pub fn parse_dns_tcp(protos: &[Protocol]) -> Option<((IpFilter, &DnsName, u16), &[Protocol])> {
    use Protocol::*;

    if protos.len() < 2 {
        return None;
    }

    let (prefix, suffix) = protos.split_at(2);
    match prefix {
        [Dns(name), Tcp(port)] => Some(((IpFilter::Any, name, *port), suffix)),
        [Dns4(name), Tcp(port)] => Some(((IpFilter::OnlyIp4, name, *port), suffix)),
        [Dns6(name), Tcp(port)] => Some(((IpFilter::OnlyIp6, name, *port), suffix)),
        _ => None,
    }
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L22-24)
```rust
//! When dialing a peer with a given list of addresses, we attempt each address
//! in order with a capped exponential backoff delay until we eventually connect
//! to the peer. The backoff is capped since, for validators specifically, it is
```

**File:** network/framework/src/connectivity_manager/builder.rs (L54-56)
```rust
                Duration::from_millis(connectivity_check_interval_ms),
                ExponentialBackoff::from_millis(backoff_base).factor(1000),
                Duration::from_millis(max_connection_delay_ms),
```
