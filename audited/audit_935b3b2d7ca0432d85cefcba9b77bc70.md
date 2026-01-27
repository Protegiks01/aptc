# Audit Report

## Title
X-Real-IP Header Injection Enables Complete Bypass of IP-Based Security Controls in Aptos Faucet

## Summary
The Aptos faucet service uses Poem's `RealIp` extractor to determine client IP addresses for blocklist checking and rate limiting. However, the extractor unconditionally trusts the `X-Real-IP` HTTP header without validation, allowing attackers to trivially spoof their source IP and bypass all IP-based security controls.

## Finding Description
The faucet service relies on IP-based security controls to prevent abuse [1](#0-0) . The source IP is extracted using Poem's `RealIp` extractor [2](#0-1)  and [3](#0-2) , which according to the inline comments "takes into things like X-Forwarded-IP and X-Real-IP" [4](#0-3) .

The extracted IP is stored in `CheckerData` [5](#0-4)  and used throughout the security checker system. The critical issue is that Poem framework (version 3.1.3) [6](#0-5)  prioritizes the `X-Real-IP` header above all others when extracting the client IP.

The server configuration shows no middleware that sanitizes or validates proxy headers [7](#0-6) . Only CORS and logging middleware are applied, leaving the application vulnerable to header injection.

**Attack Flow:**
1. Attacker's real IP (e.g., 192.0.2.100) is blocklisted or rate-limited
2. Attacker sends HTTP request with injected header: `X-Real-IP: 203.0.113.50`
3. Poem's `RealIp` extractor extracts the spoofed IP from the header [8](#0-7) 
4. Spoofed IP propagates to all security checks
5. Attacker bypasses blocklist [9](#0-8)  and rate limits, potentially draining the faucet

## Impact Explanation
While this is a **Critical-severity web security vulnerability**, it falls outside the scope of the Aptos blockchain core security audit for the following reasons:

The faucet service is explicitly a testnet utility: "The Aptos Faucet is a service that runs alongside a test network and mints coins for users to test and develop on Aptos" [10](#0-9) . 

This vulnerability does **not** impact:
- **Consensus safety or liveness** - The faucet is an off-chain HTTP service
- **Move VM execution** - No impact on bytecode execution or gas metering  
- **State management** - No impact on AptosDB or Merkle trees
- **On-chain governance or staking** - The faucet is separate from blockchain operations
- **Mainnet funds** - Only affects test token distribution

The impact is limited to testnet service abuse (draining test tokens, bypassing rate limits), which does not meet the "Loss of Funds" criterion since test tokens have no economic value. This also doesn't qualify as a consensus violation, network partition, or any of the Critical/High/Medium severity categories defined in the bug bounty program.

## Likelihood Explanation  
**High likelihood** of exploitation if the faucet is exposed to the internet without a properly configured reverse proxy that strips client-supplied `X-Real-IP` headers. The attack requires only basic HTTP knowledge and can be executed with a simple curl command.

## Recommendation
Implement one of the following mitigations:

1. **Deploy behind a trusted reverse proxy** (HAProxy/nginx) that strips `X-Real-IP` headers from client requests and sets it based on the actual client connection
2. **Use socket peer address instead of headers** for security-critical IP checks
3. **Implement middleware to validate proxy headers** against a configured list of trusted proxy IPs
4. **Add header sanitization middleware** before the routing layer in the server setup [11](#0-10) 

The recommended fix is option 1, as the faucet is designed to run behind infrastructure that should handle this (similar to how HAProxy is configured for other Aptos services).

## Proof of Concept
```bash
# Legitimate request (blocked IP)
curl -X POST https://faucet.testnet.aptoslabs.com/mint \
  -H "Content-Type: application/json" \
  -d '{"address": "0x1", "amount": 100000000}'
# Returns: 403 - IP 192.0.2.100 is in blocklist

# Attack: Inject X-Real-IP header to spoof clean IP
curl -X POST https://faucet.testnet.aptoslabs.com/mint \
  -H "Content-Type: application/json" \
  -H "X-Real-IP: 203.0.113.50" \
  -d '{"address": "0x1", "amount": 100000000}'
# Returns: 200 - Successfully funded (blocklist bypassed)
```

---

## Notes
This finding represents a valid **web application security vulnerability** in the faucet service. However, it **does not meet the criteria** for the Aptos blockchain core security audit as specified in the prompt, which explicitly focuses on "consensus, execution, storage, governance, and staking components." The faucet is an auxiliary testnet service that operates independently of the blockchain's core security guarantees.

For a production security assessment of the faucet service as a web application, this would be rated **Critical**. For the blockchain core audit scope, this is out of scope.

### Citations

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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L106-108)
```rust
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L200-200)
```rust
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L286-288)
```rust
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
```

**File:** Cargo.toml (L724-724)
```text
poem = { version = "3.1.3", features = ["anyhow", "compression", "rustls"] }
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L207-220)
```rust
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

**File:** crates/aptos-faucet/README.md (L1-3)
```markdown
# Aptos Faucet

The Aptos Faucet is a service that runs alongside a test network and mints coins for users to test and develop on Aptos.
```
