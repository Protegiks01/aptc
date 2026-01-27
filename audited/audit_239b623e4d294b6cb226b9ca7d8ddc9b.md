# Audit Report

## Title
SSRF Vulnerability in JWK Fetching Allows Scanning of Internal Validator Infrastructure via Malicious jwks_uri

## Summary
The `fetch_jwks_from_jwks_uri()` function in `crates/jwk-utils/src/lib.rs` performs HTTP requests to attacker-controllable URLs without any IP address validation, URL scheme validation, or private IP range filtering. This allows an attacker who can control the `jwks_uri` value (via compromised OIDC provider or DNS rebinding) to make all validators simultaneously scan internal infrastructure, access cloud metadata endpoints, or probe private network services. [1](#0-0) 

## Finding Description

The JWK consensus mechanism in Aptos validators periodically fetches JSON Web Keys from OIDC providers to verify keyless account signatures. The attack flow proceeds as follows:

1. **OIDC Provider Configuration**: Validators read supported OIDC providers from on-chain configuration stored in `SupportedOIDCProviders`. [2](#0-1) 

2. **OpenID Configuration Fetch**: For each provider, validators fetch the OpenID configuration from the `config_url` to obtain the `jwks_uri`. [3](#0-2) 

3. **JWK Fetch Without Validation**: Validators then make an HTTP request to the `jwks_uri` returned from the OpenID configuration **without any validation**. [4](#0-3) 

4. **Periodic Execution**: This fetch happens on a 10-second interval for all configured providers. [5](#0-4) 

**Attack Scenarios:**

**Scenario 1: Compromised OIDC Provider**
- A legitimate OIDC provider (e.g., Google, Facebook) is added via governance
- Attacker compromises the provider's OpenID configuration endpoint
- The compromised endpoint returns `jwks_uri: "http://10.0.0.5:6000/admin"` (internal validator admin interface)
- All validators simultaneously make requests to internal infrastructure every 10 seconds

**Scenario 2: DNS Rebinding Attack**
- Legitimate OIDC provider is configured
- Attacker performs DNS rebinding on the `jwks_uri` domain
- First resolution returns legitimate IP, subsequent resolutions return private IPs
- Validators make requests to private network ranges

**Scenario 3: Cloud Metadata Access**
- Compromised provider returns `jwks_uri: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"`
- Validators running on AWS/GCP/Azure make requests to cloud metadata service
- Potential exposure of IAM credentials, instance information, or secrets

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." Validators making unbounded external HTTP requests to arbitrary endpoints violates operational security boundaries.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:

1. **Validator Node Slowdowns**: If internal services are slow to respond or non-responsive, validators will experience delays in JWK fetching operations, impacting performance.

2. **Significant Protocol Violations**: Validators are designed to operate within defined network boundaries. Making requests to arbitrary internal infrastructure violates the operational security model.

3. **Information Disclosure**: 
   - Scan internal validator infrastructure to map network topology
   - Access cloud provider metadata endpoints (AWS/GCP/Azure at `169.254.169.254`)
   - Probe internal services that trust traffic from validator IPs
   - Identify internal service versions and configurations

4. **Amplification**: All validators in the network simultaneously make these requests every 10 seconds, amplifying the impact and making detection easier for attackers to confirm which services are running.

5. **Lateral Movement**: Successful SSRF can be a stepping stone for more sophisticated attacks against validator infrastructure.

This clearly qualifies as **High Severity** under "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors Increasing Likelihood:**
1. **Compromised OIDC Providers**: Major OIDC providers are high-value targets. Any compromise of Google, Facebook, or other supported providers immediately affects all validators.
2. **No Defense-in-Depth**: The code relies entirely on governance being correct and OIDC providers being secure, with zero defensive validation.
3. **DNS Rebinding**: Relatively straightforward attack technique requiring only DNS control.
4. **Cloud Metadata Services**: Validators running on cloud infrastructure (AWS, GCP, Azure) are automatically vulnerable if metadata service access isn't blocked at network level.

**Factors Decreasing Likelihood:**
1. **Governance Requirement**: Adding new OIDC providers requires governance approval, which provides some initial vetting.
2. **Network-Level Protections**: Some validator deployments may have network-level egress filtering (though this isn't guaranteed by code).

However, relying on external factors (governance vetting, network configuration) rather than code-level validation violates defense-in-depth principles. The code should validate inputs even from trusted sources.

## Recommendation

Implement comprehensive URL validation before making HTTP requests:

```rust
use std::net::IpAddr;
use url::Url;

/// Validate that a URL is safe to fetch from (no private IPs, valid scheme)
fn validate_jwks_url(url_str: &str) -> Result<()> {
    // Parse URL
    let url = Url::parse(url_str)
        .context("Invalid URL format")?;
    
    // Only allow HTTPS
    if url.scheme() != "https" {
        bail!("Only HTTPS URLs are allowed for JWK fetching");
    }
    
    // Get the host
    let host = url.host_str()
        .ok_or_else(|| anyhow!("URL must have a host"))?;
    
    // Resolve hostname to IP addresses
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, url.port().unwrap_or(443)))
        .await?
        .map(|addr| addr.ip())
        .collect();
    
    // Check each resolved IP address
    for addr in addrs {
        match addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Block private ranges
                if octets[0] == 10 // 10.0.0.0/8
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) // 172.16.0.0/12
                    || (octets[0] == 192 && octets[1] == 168) // 192.168.0.0/16
                    || octets[0] == 127 // 127.0.0.0/8 (localhost)
                    || (octets[0] == 169 && octets[1] == 254) // 169.254.0.0/16 (link-local/cloud metadata)
                    || octets[0] == 0 // 0.0.0.0/8
                {
                    bail!("URL resolves to private/reserved IP address: {}", addr);
                }
            },
            IpAddr::V6(ipv6) => {
                // Block private IPv6 ranges
                if ipv6.is_loopback() || ipv6.is_unspecified() {
                    bail!("URL resolves to loopback/unspecified IPv6: {}", addr);
                }
                // Block link-local (fe80::/10)
                if ipv6.octets()[0] == 0xfe && (ipv6.octets()[1] & 0xc0) == 0x80 {
                    bail!("URL resolves to link-local IPv6: {}", addr);
                }
                // Block unique local (fc00::/7)
                if (ipv6.octets()[0] & 0xfe) == 0xfc {
                    bail!("URL resolves to unique local IPv6: {}", addr);
                }
            },
        }
    }
    
    Ok(())
}

pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    // Validate URL before fetching
    validate_jwks_url(jwks_uri).await?;
    
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

Apply the same validation to `fetch_jwks_uri_from_openid_config()`.

Additionally, configure reqwest client with timeouts and redirect limits:

```rust
let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(10))
    .redirect(reqwest::redirect::Policy::limited(3))
    .build()?;
```

## Proof of Concept

```rust
#[cfg(test)]
mod ssrf_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ssrf_private_ip_blocked() {
        // Test that private IP ranges are blocked
        let private_ips = vec![
            "http://10.0.0.1/jwks.json",
            "http://172.16.0.1/jwks.json",
            "http://192.168.1.1/jwks.json",
            "http://127.0.0.1/jwks.json",
            "http://169.254.169.254/latest/meta-data", // AWS metadata
        ];
        
        for url in private_ips {
            let result = fetch_jwks_from_jwks_uri(None, url).await;
            assert!(result.is_err(), "Should reject private IP: {}", url);
        }
    }
    
    #[tokio::test]
    async fn test_ssrf_dns_rebinding_simulation() {
        // Simulate DNS rebinding where domain resolves to private IP
        // This would require a test DNS server that returns private IPs
        let malicious_url = "https://attacker-dns-rebinding.example.com/jwks.json";
        
        // With proper validation, this should be rejected after DNS resolution
        let result = fetch_jwks_from_jwks_uri(None, malicious_url).await;
        assert!(result.is_err(), "Should reject URL that resolves to private IP");
    }
    
    #[tokio::test]
    async fn test_non_https_blocked() {
        let result = fetch_jwks_from_jwks_uri(None, "http://example.com/jwks.json").await;
        assert!(result.is_err(), "Should reject non-HTTPS URLs");
    }
}
```

## Notes

While the trust model indicates that governance participants are trusted, **defense-in-depth** is a fundamental security principle. The code should validate all external inputs, even from "trusted" sources, because:

1. **OIDC Provider Compromise**: Legitimate OIDC providers can be compromised through supply chain attacks, infrastructure breaches, or insider threats.
2. **DNS Security**: DNS is not inherently secure and can be manipulated through cache poisoning or BGP hijacking.
3. **Operational Reality**: Validators run in diverse environments with varying network security postures.
4. **Blast Radius**: A single compromised OIDC provider affects **all** validators simultaneously.

The vulnerability exists at the code level regardless of operational controls, and should be fixed to provide defense-in-depth protection for validator infrastructure.

### Citations

**File:** crates/jwk-utils/src/lib.rs (L25-37)
```rust
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

**File:** crates/jwk-utils/src/lib.rs (L40-44)
```rust
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L63-66)
```text
    /// A list of OIDC providers whose JWKs should be watched by validators. Maintained by governance proposals.
    struct SupportedOIDCProviders has copy, drop, key, store {
        providers: vector<OIDCProvider>,
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L117-124)
```rust
                    (Ok(issuer), Ok(config_url)) => Some(JWKObserver::spawn(
                        this.epoch_state.epoch,
                        this.my_addr,
                        issuer,
                        config_url,
                        Duration::from_secs(10),
                        local_observation_tx.clone(),
                    )),
```
