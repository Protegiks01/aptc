# Audit Report

## Title
Source IP Spoofing via HTTP Header Manipulation in Aptos Faucet Service

## Summary
The Aptos faucet service uses Poem's `RealIp` extractor to determine client source IP addresses for security checks. This extractor blindly trusts client-provided HTTP headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`) without validating their authenticity. Since the faucet is designed to run without a reverse proxy, attackers can trivially spoof their source IP address by including these headers in their requests, bypassing all IP-based security controls.

## Finding Description

The faucet service extracts source IP addresses using `poem::web::RealIp` in the `fund` and `is_eligible` endpoints: [1](#0-0) 

The middleware logging also extracts and logs this information: [2](#0-1) 

This extracted IP is then used throughout the security checking pipeline. In `preprocess_request`, the source IP is extracted and used to build `CheckerData`: [3](#0-2) 

This `CheckerData` containing the spoofable IP is passed to various security checkers, including the `IpBlocklistChecker` which makes access control decisions based on the source IP: [4](#0-3) 

The vulnerability exists because Poem's `RealIp` extractor trusts HTTP headers in the following priority order:
1. `X-Forwarded-For` (first IP in list)
2. `X-Real-IP`
3. `Forwarded` 
4. Actual socket peer address

Since the faucet is explicitly designed to run without a reverse proxy (as stated in the README), an attacker connecting directly can provide their own headers: [5](#0-4) 

**Attack Scenario:**
1. Attacker's real IP is `203.0.113.50` (blocked or rate-limited)
2. Attacker sends request with header: `X-Forwarded-For: 192.0.2.100`
3. `RealIp::from_request()` returns `192.0.2.100` instead of `203.0.113.50`
4. All security checkers (IP blocklist, rate limiting, etc.) use the spoofed IP
5. Attacker bypasses all IP-based restrictions

This breaks the security guarantee that IP-based access controls can effectively restrict or rate-limit malicious actors.

## Impact Explanation

This vulnerability allows attackers to:

1. **Bypass IP Blocklists**: If an attacker's IP is blocked, they can spoof any allowed IP
2. **Evade Rate Limiting**: Redis-based or memory-based rate limiting keyed by IP can be circumvented by rotating spoofed IPs
3. **Bypass Geographic Restrictions**: If the faucet implements location-based restrictions (VPN/cloud/datacenter IP detection), these can be bypassed
4. **Circumvent Allowlists**: If only specific IPs are permitted, attackers can impersonate them

However, under the Aptos Bug Bounty severity criteria, this vulnerability **does not meet the threshold** for the following reasons:

- **Not Critical**: The faucet distributes test tokens (no real monetary value), does not affect consensus, and causes no network partition
- **Not High**: Does not impact validator nodes, does not crash core APIs, and the faucet is not part of the core protocol
- **Not Medium**: No real funds are at risk as the faucet only distributes test tokens for development purposes

The faucet is an auxiliary testnet service, not a core blockchain component affecting consensus, execution, storage, governance, or staking.

## Likelihood Explanation

**Likelihood: Very High** - The exploit requires only:
- Basic HTTP client (curl, browser, any programming language)
- Adding a single HTTP header to requests
- No authentication bypass or complex attack chains needed

However, the **business impact is minimal** because:
- The faucet distributes free test tokens with no real-world value
- Excessive use only accelerates test token distribution
- No impact on mainnet or real user funds
- This is a known limitation of public testnet faucets

## Recommendation

To fix this vulnerability, the faucet should be configured to only trust the actual socket peer address when not behind a reverse proxy, or implement proper trusted proxy configuration.

**Option 1: Use Socket Peer Address Directly**
Replace `RealIp` with direct socket peer address extraction. Poem provides access to the remote address through the `Request` object.

**Option 2: Implement Trusted Proxy Configuration**
If the faucet will be deployed behind a reverse proxy in production, implement a configuration option to specify trusted proxy IP ranges. Only when requests originate from trusted proxies should forwarded headers be respected.

**Option 3: Defense in Depth**
Implement additional rate limiting mechanisms that don't rely solely on IP addresses:
- Captcha challenges after N requests
- Account-based rate limiting (for authenticated users)
- Proof-of-work challenges
- Request fingerprinting combining multiple signals

## Proof of Concept

```bash
# Normal request - IP is correctly identified
curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -d '{"address":"0x1234567890abcdef","amount":1000000000}'

# Spoofed request - IP can be faked
curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.0.2.100" \
  -d '{"address":"0x1234567890abcdef","amount":1000000000}'

# The second request will appear to come from 192.0.2.100 in logs
# and will be processed with that IP for all security checks,
# even though it came from a completely different source
```

**Note**: While this is a valid technical vulnerability in the faucet service, it does not meet the severity criteria for the Aptos Bug Bounty Program as outlined, since the faucet is a testnet utility service distributing test tokens and does not affect the core blockchain protocol, consensus, or real user funds.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L102-111)
```rust
    async fn fund(
        &self,
        fund_request: Json<FundRequest>,
        asset: poem_openapi::param::Query<Option<String>>,
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
        // Same thing, this uses FromRequest.
        header_map: &HeaderMap,
    ) -> poem::Result<Json<FundResponse>, AptosTapErrorResponse> {
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

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L25-46)
```rust
    let source_ip = RealIp::from_request(&request, &mut RequestBody::default())
        .await
        .map(|ip| ip.0)
        .unwrap_or(None);

    let request_log = HttpRequestLog {
        source_ip,
        method: request.method().to_string(),
        path: request.uri().path().to_string(),
        referer: request
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        forwarded: request
            .headers()
            .get(header::FORWARDED)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
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

**File:** crates/aptos-faucet/README.md (L23-23)
```markdown
- Built in rate limiting, e.g. with a [Redis](https://redis.io/) backend, eliminating the need for something like haproxy in front of the faucet. These are also just checkers.
```
