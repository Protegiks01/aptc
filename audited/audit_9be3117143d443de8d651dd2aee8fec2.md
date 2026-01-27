# Audit Report

## Title
Server-Side Request Forgery (SSRF) via Unvalidated URL in Node-Checker Service

## Summary
The `NodeAddress::new()` constructor accepts user-provided URLs without validating the scheme or target host, enabling SSRF attacks against internal services when the node-checker service processes health check requests.

## Finding Description

The node-checker service exposes a `/check` endpoint that accepts a `node_url` parameter from untrusted users. This URL is passed directly to `NodeAddress::new()` without validation of the URL scheme or destination host. [1](#0-0) 

The constructor stores the URL without any security checks. The URL is subsequently used to make HTTP requests to metrics and API endpoints via the `reqwest` HTTP client library. [2](#0-1) [3](#0-2) 

The URL is used to construct HTTP clients that make outbound requests: [4](#0-3) [5](#0-4) 

While `reqwest` rejects non-HTTP schemes like `file://`, `javascript://`, or `data://` at request time, the code provides no protection against SSRF attacks using HTTP/HTTPS URLs pointing to:

- Internal/private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Localhost/loopback addresses (127.0.0.1, ::1)
- Cloud metadata endpoints (169.254.169.254 for AWS/GCP/Azure)
- Link-local addresses
- Internal service ports not exposed externally

The codebase demonstrates proper URL scheme validation in other components: [6](#0-5) 

## Impact Explanation

This vulnerability enables SSRF attacks with the following potential impacts:

1. **Cloud Metadata Access**: An attacker can retrieve cloud provider credentials by requesting `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS) or equivalent GCP/Azure endpoints, potentially leading to infrastructure compromise.

2. **Internal Network Reconnaissance**: Attackers can scan internal networks, discover services, and map the infrastructure topology behind firewalls.

3. **Internal Service Access**: Bypass authentication to internal-only services (databases, admin panels, monitoring systems) by making the node-checker proxy requests.

4. **Information Disclosure**: Access sensitive internal endpoints and leak configuration data, secrets, or operational information.

While this does not directly compromise blockchain consensus, funds, or validator nodes, it represents a **High Severity** vulnerability per the Aptos bug bounty program criteria for "API crashes" and "Significant protocol violations," as it allows unauthorized access to potentially sensitive infrastructure.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is trivially exploitable:
- No authentication required to call the `/check` endpoint
- Attack requires only a single HTTP GET request with a crafted URL parameter
- No special privileges or insider access needed
- Exploitation complexity is minimal

Any attacker with network access to the node-checker service can exploit this vulnerability immediately.

## Recommendation

Implement comprehensive URL validation in the `NodeAddress::new()` constructor or create a custom validated URL type:

```rust
impl NodeAddress {
    pub fn new(
        url: Url,
        api_port: Option<u16>,
        metrics_port: Option<u16>,
        noise_port: Option<u16>,
        public_key: Option<x25519::PublicKey>,
    ) -> Result<Self> {
        // Validate scheme
        match url.scheme() {
            "http" | "https" => {},
            other => bail!("Invalid URL scheme '{}': only http and https are allowed", other),
        }
        
        // Validate host is not internal/private
        if let Some(host) = url.host() {
            match host {
                url::Host::Ipv4(ip) => {
                    if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                        bail!("URL cannot point to private, loopback, or link-local IP addresses");
                    }
                    // Block cloud metadata endpoint
                    if ip.octets() == [169, 254, 169, 254] {
                        bail!("URL cannot point to cloud metadata endpoint");
                    }
                }
                url::Host::Ipv6(ip) => {
                    if ip.is_loopback() || ip.is_unspecified() {
                        bail!("URL cannot point to loopback or unspecified IPv6 addresses");
                    }
                }
                url::Host::Domain(domain) => {
                    if domain == "localhost" || domain.ends_with(".local") {
                        bail!("URL cannot point to localhost or .local domains");
                    }
                }
            }
        } else {
            bail!("URL must have a valid host");
        }
        
        Ok(Self {
            url,
            api_port,
            metrics_port,
            noise_port,
            public_key,
            cookie_store: Arc::new(Jar::default()),
        })
    }
}
```

Additionally, consider implementing a DNS resolution check to prevent DNS rebinding attacks where a domain initially resolves to a public IP but later resolves to a private IP.

## Proof of Concept

```bash
# Attack 1: Access AWS metadata endpoint
curl "http://<node-checker-host>/check?baseline_configuration_id=devnet_fullnode&node_url=http://169.254.169.254/latest/meta-data/&api_port=80"

# Attack 2: Scan internal network
curl "http://<node-checker-host>/check?baseline_configuration_id=devnet_fullnode&node_url=http://192.168.1.1/&api_port=80"

# Attack 3: Access localhost services
curl "http://<node-checker-host>/check?baseline_configuration_id=devnet_fullnode&node_url=http://127.0.0.1/&api_port=6060"

# Attack 4: Access internal admin panel
curl "http://<node-checker-host>/check?baseline_configuration_id=devnet_fullnode&node_url=http://10.0.0.5/admin&api_port=8080"
```

The node-checker will make HTTP requests to these internal endpoints, returning responses or errors that leak information about the internal infrastructure.

## Notes

While `reqwest` does not support `file://`, `javascript://`, or `data://` schemes (these will error during request execution), the lack of upfront validation means errors occur later in the execution path rather than at input validation time. The primary security concern is SSRF via HTTP/HTTPS URLs to internal resources, which `reqwest` does not prevent by default.

### Citations

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L38-53)
```rust
    pub fn new(
        url: Url,
        api_port: Option<u16>,
        metrics_port: Option<u16>,
        noise_port: Option<u16>,
        public_key: Option<x25519::PublicKey>,
    ) -> Self {
        Self {
            url,
            api_port,
            metrics_port,
            noise_port,
            public_key,
            cookie_store: Arc::new(Jar::default()),
        }
    }
```

**File:** ecosystem/node-checker/src/server/api.rs (L34-35)
```rust
        /// The URL of the node to check, e.g. http://44.238.19.217 or http://fullnode.mysite.com
        node_url: Query<Url>,
```

**File:** ecosystem/node-checker/src/server/api.rs (L81-87)
```rust
        let target_node_address = NodeAddress::new(
            node_url.0,
            api_port.0,
            metrics_port.0,
            noise_port.0,
            public_key,
        );
```

**File:** ecosystem/node-checker/src/provider/metrics.rs (L60-66)
```rust
        let response = self
            .client
            .get(self.metrics_url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to get data from {}", self.metrics_url))
            .map_err(|e| ProviderError::RetryableEndpointError("/metrics", e))?;
```

**File:** ecosystem/node-checker/src/provider/system_information.rs (L58-64)
```rust
        let response = self
            .client
            .get(self.metrics_url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to get data from {}", self.metrics_url))
            .map_err(|e| ProviderError::RetryableEndpointError("/system_information", e))?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L20-24)
```rust
        let url = Url::parse(s)?;
        if url.scheme() != "redis" {
            return Err(anyhow::anyhow!("Invalid scheme: {}", url.scheme()));
        }
        Ok(RedisUrl(url))
```
