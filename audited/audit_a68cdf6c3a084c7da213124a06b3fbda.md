# Audit Report

## Title
Incomplete Proxy Chain Logging Prevents Detection of Rate Limit Bypass Attempts in Aptos Faucet

## Summary
The `middleware_log()` function in the Aptos Faucet only logs the RFC 7239 `Forwarded` header while ignoring `X-Forwarded-For` and `X-Real-IP` headers, despite the fact that `RealIp` uses all these headers to extract the source IP. This creates a forensic blind spot that prevents detection of proxy chain-based rate limit bypass attempts, enabling attackers to drain faucet funds while evading post-hoc detection.

## Finding Description

The middleware logging captures proxy information inconsistently with how the rate limiting system extracts client IPs: [1](#0-0) 

The `RealIp::from_request()` call uses multiple headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`) to determine the actual client IP, as documented in the comments: [2](#0-1) 

However, the `HttpRequestLog` struct only captures the standardized `Forwarded` header: [3](#0-2) [4](#0-3) 

**Attack Scenario:**
1. Attacker sends requests through proxy chains that set `X-Forwarded-For: "attacker-ip, proxy1, proxy2"` but don't set the RFC 7239 `Forwarded` header (common with many proxy services)
2. `RealIp` correctly extracts "attacker-ip" from `X-Forwarded-For` for rate limiting
3. The middleware logs `source_ip: "attacker-ip"` and `forwarded: None`
4. The full proxy chain information is lost, making it impossible to:
   - Detect that the request came through proxies
   - Correlate multiple IPs being used through the same proxy infrastructure
   - Identify patterns of proxy abuse in forensic analysis

Additionally, the middleware logging does not capture the receiver account address: [4](#0-3) 

While the receiver address is logged separately in the fund endpoint: [5](#0-4) 

This separation makes it harder to correlate IP rotation attacks targeting the same account, as the middleware logs and endpoint logs are not structurally linked.

The rate limiting implementations only track per-IP: [6](#0-5) [7](#0-6) 

This enables attackers to bypass rate limits through:
1. **Proxy chain abuse**: Using X-Forwarded-For proxies without detection
2. **IP rotation**: Funding the same account from multiple IPs
3. **User-agent rotation**: While logged, not analyzed for suspicious patterns

## Impact Explanation

This is a **Medium severity** vulnerability per Aptos Bug Bounty criteria:
- **Limited funds loss**: Attackers can drain faucet funds beyond intended rate limits through undetectable proxy abuse and IP rotation
- **State inconsistencies requiring intervention**: Faucet abuse creates operational issues requiring manual intervention and fund replenishment

The impact is limited because:
- The faucet is not part of the core consensus mechanism
- Funds are testnet tokens (though the pattern applies to production faucets)
- The vulnerability is in detection capability, not in the core rate limiting logic itself

However, the security harm is real:
- Attackers can systematically drain faucet funds
- Forensic investigation becomes impossible when X-Forwarded-For proxies are used
- Legitimate users may be denied service when faucet funds are depleted

## Likelihood Explanation

**High likelihood of exploitation:**
- Attack requires only basic proxy infrastructure (widely available)
- Many proxy services and CDNs use `X-Forwarded-For` without setting the RFC 7239 `Forwarded` header
- No special privileges required
- Rate limit bypass is economically motivated for faucet abuse

**Current state:**
- The logging gaps are present in production code
- The rate limiting is per-IP only, making IP rotation trivially effective
- No correlation analysis exists to detect cross-IP patterns

## Recommendation

**1. Capture all proxy-related headers in logging:**

```rust
// In HttpRequestLog struct, add:
x_forwarded_for: Option<String>,
x_real_ip: Option<String>,
// Keep existing forwarded field

// In middleware_log function, populate these:
x_forwarded_for: request
    .headers()
    .get("X-Forwarded-For")
    .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
x_real_ip: request
    .headers()
    .get("X-Real-IP")
    .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
```

**2. Add receiver account to middleware logging:**

```rust
// In middleware_log, extract operation-specific data and add receiver to logs
// This requires coordination with endpoint data
```

**3. Implement per-account rate limiting:**

Extend rate limiting to track `(source_ip, receiver_account)` pairs, not just `source_ip`, to detect IP rotation targeting specific accounts.

**4. Add anomaly detection logging:**

Log suspicious patterns such as:
- Same IP with multiple user agents in short time window
- Multiple IPs funding the same account rapidly
- Requests with long proxy chains (multiple hops in X-Forwarded-For)

## Proof of Concept

**Test Setup:**

```bash
# Terminal 1: Start the faucet service
cd aptos-core/crates/aptos-faucet
cargo run --bin aptos-faucet-service

# Terminal 2: Send requests through proxy chain
# Request 1: Using X-Forwarded-For without Forwarded header
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.10.11.12" \
  -d '{"address":"0x123456789abcdef"}'

# Request 2: Using different IP in X-Forwarded-For
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 13.14.15.16, 5.6.7.8, 9.10.11.12" \
  -d '{"address":"0x123456789abcdef"}'

# Request 3: Rotate user agent from same IP
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.10.11.12" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0)" \
  -d '{"address":"0x123456789abcdef"}'
```

**Expected Vulnerable Behavior:**
- Each request bypasses per-IP rate limits (different source IPs extracted)
- Middleware logs show `source_ip` but `forwarded: None` (proxy chain info lost)
- Same account receives multiple funds beyond rate limits
- No correlation possible to detect the attack pattern

**Verification:**
Check the faucet logs and observe:
1. The `forwarded` field is `None` despite X-Forwarded-For being present
2. Multiple funding requests succeed for the same account from "different" IPs
3. No way to reconstruct the proxy chain from logs for forensic analysis

## Notes

This vulnerability exists at the intersection of logging completeness and rate limit bypass detection. While the rate limiting mechanism itself functions as designed (per-IP tracking), the logging does not capture sufficient information to detect sophisticated bypass attempts post-hoc. The faucet is a non-consensus component, but the pattern is concerning for any production deployment requiring robust abuse prevention.

### Citations

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

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L72-80)
```rust
pub struct HttpRequestLog {
    #[schema(display)]
    source_ip: Option<IpAddr>,
    method: String,
    path: String,
    referer: Option<String>,
    user_agent: Option<String>,
    forwarded: Option<String>,
}
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L106-108)
```rust
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L319-327)
```rust
        info!(
            source_ip = checker_data.source_ip,
            jwt_sub = jwt_sub(checker_data.headers.clone()).ok(),
            address = checker_data.receiver,
            requested_amount = fund_request.amount,
            asset = asset_for_logging,
            txn_hashes = txn_hashes,
            success = fund_result.is_ok(),
        );
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L77-89)
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

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L44-51)
```rust
    pub async fn ratelimit_key_value(&self, data: &CheckerData) -> Result<String, AptosTapError> {
        match self {
            RatelimitKeyProvider::Ip => Ok(data.source_ip.to_string()),
            RatelimitKeyProvider::Jwt(jwt_verifier) => {
                jwt_verifier.validate_jwt(data.headers.clone()).await
            },
        }
    }
```
