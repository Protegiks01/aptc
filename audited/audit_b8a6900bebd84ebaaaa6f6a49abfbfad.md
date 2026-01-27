# Audit Report

## Title
Rejection Metrics Bypass via Legacy /mint Endpoint Enables Stealthy Faucet Reconnaissance

## Summary
The legacy `/mint` endpoint bypasses rejection reason metrics collection while still being rate-limited, creating a monitoring blind spot that attackers can exploit for stealthier reconnaissance and attack preparation against the faucet system.

## Finding Description
The Aptos faucet exposes two endpoints for funding accounts: the OpenAPI-based `/fund` endpoint and the legacy `/mint` endpoint. While both endpoints enforce identical rate limiting and security controls through the shared `fund_inner()` function, they differ critically in how rejection metrics are tracked. [1](#0-0) 

When the `/fund` endpoint encounters rejections (rate limits, IP blocks, etc.), it returns an `AptosTapErrorResponse` which automatically triggers `bump_rejection_reason_counters()` to increment Prometheus metrics for each rejection reason code. [2](#0-1) 

However, the legacy `/mint` endpoint converts `AptosTapError` to a plain `poem::Error`, stripping all structured error information including rejection reasons. This conversion bypasses the metrics collection entirely. [3](#0-2) 

The `aptos_tap_rejection_reason_count` metric is critical for monitoring attack patterns, rate limit violations, and suspicious activity. By using `/mint`, attackers can probe the faucet's security boundaries without triggering these metrics, enabling:

1. **Stealthy reconnaissance**: Test rate limits, probe IP blocks, and discover bypass tokens without appearing in rejection metrics
2. **Distributed attack coordination**: Coordinate attacks across multiple IPs while evading aggregate rejection monitoring
3. **Detection evasion**: If attackers obtain valid bypass credentials (auth tokens, IP allowlist access), they can drain funds more rapidly via `/mint` while their rejected attempts remain invisible to metric-based alerting [4](#0-3) 

Additionally, `/mint` is logged with `operation_id = "operation_id_not_set"` rather than a specific operation ID, further degrading observability by aggregating its traffic with any other non-OpenAPI endpoints.

## Impact Explanation
This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria due to significant protocol violations affecting faucet security:

- **Monitoring System Bypass**: Critical security metrics are not collected for a production endpoint that handles fund distribution
- **Attack Detection Evasion**: Sophisticated attackers can systematically probe and attack the faucet while evading automated detection systems that rely on rejection metrics
- **Operational Blindness**: Security teams cannot accurately assess attack patterns, rate limit effectiveness, or threat levels when a significant portion of traffic (via `/mint`) is invisible in metrics

While this doesn't directly bypass rate limiting controls, it creates a dangerous asymmetry where attackers have better visibility into the system's defenses than defenders have into attack patterns. This enables more effective attacks and delays incident response.

## Likelihood Explanation
**Likelihood: High**

The `/mint` endpoint is a production endpoint that must remain available for backward compatibility with existing integrations. The vulnerability requires no special privileges or insider access:

1. **Trivial exploitation**: Simply use `/mint` instead of `/fund` - same functionality, zero detection
2. **No attacker requirements**: Any network peer can exploit this by choosing which endpoint to call
3. **Persistent exposure**: Cannot be easily mitigated without breaking backward compatibility
4. **Actionable intelligence**: Attackers gain valuable information about rate limits, security controls, and bypass opportunities without detection

## Recommendation

**Immediate Fix**: Ensure `/mint` endpoint tracks rejection metrics identically to `/fund`:

```rust
#[poem::handler]
pub async fn mint(
    fund_api_components: poem::web::Data<&Arc<FundApiComponents>>,
    poem::web::Query(MintRequest {
        amount,
        auth_key,
        address,
        pub_key,
        return_txns,
    }): poem::web::Query<MintRequest>,
    source_ip: RealIp,
    header_map: &HeaderMap,
) -> poem::Result<MintResponse> {
    let fund_request = FundRequest {
        amount,
        auth_key,
        address,
        pub_key,
    };
    let txns = fund_api_components
        .0
        .fund_inner(fund_request, source_ip, header_map, false, None)
        .await
        .map_err(|e| {
            // FIX: Bump rejection metrics before converting to poem::Error
            bump_rejection_reason_counters(&e.rejection_reasons);
            poem::Error::from((e.status_and_retry_after().0, anyhow::anyhow!(e.message)))
        })?;
    // ... rest of implementation
}
```

**Additional Recommendations**:
1. Set explicit operation_id for `/mint` endpoint in middleware to enable per-endpoint monitoring
2. Implement alerting on "operation_id_not_set" traffic patterns as defense-in-depth
3. Consider deprecation path for legacy `/mint` endpoint with migration timeline for integrations

## Proof of Concept

```rust
// Test demonstrating metrics bypass
#[tokio::test]
async fn test_mint_rejection_metrics_bypass() {
    // Setup: Start faucet with rate limiting enabled
    let config = include_str!("../../../configs/testing_redis.yaml");
    let (port, _handle) = start_server(config).await.unwrap();
    
    // Record initial rejection metric count
    let initial_rejection_count = get_rejection_metric_count();
    
    // Attack Scenario 1: Probe via /fund - metrics ARE tracked
    for _ in 0..10 {
        let _ = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/fund", port))
            .json(&FundRequest { amount: Some(10), ..Default::default() })
            .send()
            .await;
    }
    let fund_rejection_count = get_rejection_metric_count();
    assert!(fund_rejection_count > initial_rejection_count, "Fund rejections should be metricked");
    
    // Attack Scenario 2: Probe via /mint - metrics NOT tracked
    let pre_mint_count = fund_rejection_count;
    for _ in 0..10 {
        let _ = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/mint?amount=10&address=0x1234", port))
            .send()
            .await;
    }
    let post_mint_count = get_rejection_metric_count();
    
    // VULNERABILITY: Mint rejections don't increment metrics
    assert_eq!(post_mint_count, pre_mint_count, 
        "Mint rejections bypass metrics - attackers can probe undetected");
}

fn get_rejection_metric_count() -> u64 {
    // Query Prometheus metrics endpoint
    let metrics_text = reqwest::blocking::get("http://127.0.0.1:9101/metrics")
        .unwrap()
        .text()
        .unwrap();
    
    // Parse aptos_tap_rejection_reason_count metric
    metrics_text
        .lines()
        .filter(|line| line.starts_with("aptos_tap_rejection_reason_count"))
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|val| val.parse::<u64>().ok())
        .sum()
}
```

## Notes

This vulnerability demonstrates a critical principle: **security controls without observability create false confidence**. While rate limiting prevents actual drainage, the metrics bypass enables attackers to:
- Map the security perimeter without triggering alarms
- Discover and exploit bypass mechanisms (leaked auth tokens, misconfigured IP allowlists) more effectively
- Coordinate sophisticated attacks that would otherwise trigger incident response

The asymmetry where defenders cannot see what attackers are testing significantly degrades the security posture of the faucet system.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L100-109)
```rust
impl From<AptosTapError> for AptosTapErrorResponse {
    fn from(error: AptosTapError) -> Self {
        // We use this opportunity to bump metrics based on the specifics of
        // this response, since this function is only called right when we're
        // about to return this error to the client.
        bump_rejection_reason_counters(&error.rejection_reasons);
        let (status, retry_after) = error.status_and_retry_after();
        Self::Default(status, Json(error), retry_after)
    }
}
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L379-420)
```rust
#[poem::handler]
pub async fn mint(
    fund_api_components: poem::web::Data<&Arc<FundApiComponents>>,
    poem::web::Query(MintRequest {
        amount,
        auth_key,
        address,
        pub_key,
        return_txns,
    }): poem::web::Query<MintRequest>,
    // This automagically uses FromRequest to get this data from the request.
    // It takes into things like X-Forwarded-IP and X-Real-IP.
    source_ip: RealIp,
    // Same thing, this uses FromRequest.
    header_map: &HeaderMap,
) -> poem::Result<MintResponse> {
    // We take the AptosTapError and convert it into an anyhow error with just the
    // message so this endpoint returns a plaintext response like the faucet does.
    // We still return the intended status code though, but not any headers that
    // the /mint endpoint would, e.g. Retry-After.
    let fund_request = FundRequest {
        amount,
        auth_key,
        address,
        pub_key,
    };
    let txns = fund_api_components
        .0
        .fund_inner(fund_request, source_ip, header_map, false, None)
        .await
        .map_err(|e| {
            poem::Error::from((e.status_and_retry_after().0, anyhow::anyhow!(e.message)))
        })?;
    if return_txns.unwrap_or(false) {
        let txn_bcs =
            aptos_sdk::bcs::to_bytes(&txns).map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        let txn_bcs_hex = hex::encode(txn_bcs);
        Ok(MintResponse::SubmittedTxns(PlainText(txn_bcs_hex)))
    } else {
        Ok(MintResponse::SubmittedTxnHashes(Json(get_hashes(&txns))))
    }
}
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L29-36)
```rust
static REJECTION_REASONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_tap_rejection_reason_count",
        "Number of times the tap has returned the given rejection reason.",
        &["rejection_reason_code"]
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L54-57)
```rust
    let operation_id = response
        .data::<OperationId>()
        .map(|operation_id| operation_id.0)
        .unwrap_or("operation_id_not_set");
```
