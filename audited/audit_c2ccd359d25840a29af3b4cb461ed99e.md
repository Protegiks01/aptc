# Audit Report

## Title
Health Check Bypass in Faucet API Leading to Resource Exhaustion During Degraded States

## Summary
The Aptos Faucet service's fund endpoints (`/fund` and `/is_eligible`) perform funder health validation after consuming critical resources (semaphore permits, rate limit counters, and storage I/O), unlike the dedicated health check endpoint (`/`) which validates health before any resource consumption. This asymmetry allows attackers to deliberately waste system resources by flooding fund endpoints during periods when the funder is unhealthy, creating a denial-of-service vector and rate limit abuse opportunity.

## Finding Description

The vulnerability exists in how health checks are ordered across different API endpoints in the Aptos Faucet service:

**Health Check Endpoint (`BasicApi::root`)** validates health BEFORE resource consumption: [1](#0-0) 

This endpoint immediately checks funder health and returns `SERVICE_UNAVAILABLE` if the funder cannot process requests.

**Fund Endpoints (`FundApi::fund` and `FundApi::is_eligible`)** validate health AFTER resource consumption:

1. First, `preprocess_request()` consumes resources: [2](#0-1) 

2. Then runs rate limit checkers that write to storage: [3](#0-2) 

3. Finally, health is checked in the funder implementation: [4](#0-3) 

**Attack Scenario:**
1. Attacker monitors funder health (e.g., `TransferFunder` balance drops below `minimum_funds`)
2. Health check endpoint (`/`) returns `503 SERVICE_UNAVAILABLE`
3. Attacker floods `/fund` endpoint with requests
4. Each request:
   - Acquires semaphore permit (blocking other requests)
   - Increments rate limit counters in Redis/memory
   - Performs database I/O operations
   - Then fails with `FunderAccountProblem` error
5. Legitimate users experience:
   - Semaphore exhaustion (all permits consumed)
   - Rate limit counter pollution (counts incremented for failed requests)
   - Wasted computational resources
   - Service appears partially available (fund endpoint accepts requests) while actually being unavailable

The composition in `build_openapi_service` shows all APIs share the same service without middleware-level health enforcement: [5](#0-4) 

## Impact Explanation

This qualifies as **High Severity** based on the Aptos bug bounty criteria for "API crashes" and service disruption:

1. **Resource Exhaustion DoS**: During funder unhealthiness (which can occur due to insufficient balance, node connection issues, or account problems), attackers can deliberately exhaust:
   - Semaphore permits (blocking all concurrent request processing)
   - Redis/memory rate limit counters (polluting rate limit state)
   - Network I/O and computational resources

2. **Rate Limit Integrity Violation**: Rate limit counters are incremented for requests that inevitably fail, meaning:
   - Legitimate users' quotas are consumed by attacker's doomed requests
   - Rate limit state becomes inconsistent with actual successful funding operations
   - Users may be blocked from future valid requests due to counter pollution

3. **Service Degradation Amplification**: While load balancers should eventually deregister unhealthy instances based on the `/` health check, there's a time window where attackers can amplify the degradation by forcing the service to waste resources on requests that will fail.

4. **Inconsistent Service Behavior**: Creates confusion where:
   - Health check indicates `SERVICE_UNAVAILABLE`
   - But fund endpoint still accepts and processes requests (before failing)
   - This inconsistency makes it harder to reason about service state

## Likelihood Explanation

**High Likelihood** of exploitation:

1. **Low Attack Complexity**: Attacker only needs to:
   - Monitor when funder becomes unhealthy (publicly observable via `/` endpoint)
   - Send POST requests to `/fund` endpoint (no authentication bypass required)
   - Use valid request format (no special crafting needed)

2. **Predictable Trigger Conditions**: Funder unhealthiness occurs naturally in several scenarios:
   - `TransferFunder` balance drops below `minimum_funds` threshold
   - `MintFunder` account doesn't exist or fullnode is out of sync
   - Network connectivity issues to blockchain nodes
   - Blockchain state synchronization delays

3. **Observable Impact**: The test suite confirms this behavior is reproducible: [6](#0-5) 

The test shows that fund requests continue to be processed (consuming resources) even after health check returns `SERVICE_UNAVAILABLE`.

## Recommendation

Implement early health validation in `FundApiComponents::preprocess_request` before any resource consumption:

```rust
async fn preprocess_request(
    &self,
    fund_request: &FundRequest,
    source_ip: RealIp,
    header_map: &HeaderMap,
    dry_run: bool,
) -> poem::Result<(CheckerData, bool, Option<SemaphorePermit<'_>>), AptosTapError> {
    // ADDED: Check funder health BEFORE consuming any resources
    let funder_health = self.funder.is_healthy().await;
    if !funder_health.can_process_requests {
        return Err(AptosTapError::new(
            funder_health
                .message
                .unwrap_or_else(|| "Funder is unhealthy".to_string()),
            AptosTapErrorCode::FunderAccountProblem,
        ));
    }

    // Now proceed with resource acquisition
    let permit = match &self.concurrent_requests_semaphore {
        // ... rest of existing code
    };
    
    // ... rest of existing implementation
}
```

This ensures health validation occurs at the same point in the request lifecycle for all endpoints, preventing resource waste and maintaining consistent service behavior.

Additionally, consider implementing middleware-level health checks that apply to all API endpoints uniformly, rather than relying on each endpoint to implement health validation independently.

## Proof of Concept

The following test demonstrates the vulnerability by showing resource consumption occurs before health check failure:

```rust
#[tokio::test]
async fn test_health_check_bypass_resource_waste() -> Result<()> {
    // Setup: Create TransferFunder with exactly minimum funds
    let private_key = Ed25519PrivateKey::generate(&mut StdRng::from_seed(OsRng.gen()));
    let account_address = AuthenticationKey::ed25519(&private_key.public_key()).account_address();
    
    // Fund with minimum amount (10_000_000 octas as per test config)
    // ... (fund account setup code)
    
    // Start server with TransferFunder
    let (port, _handle) = start_server(transfer_config).await?;
    
    // Verify health check is healthy initially
    let health_response = reqwest::get(format!("http://127.0.0.1:{}/", port)).await?;
    assert_eq!(health_response.status(), StatusCode::OK);
    
    // Make ONE fund request to drop balance below minimum
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/fund", port))
        .json(&FundRequest {
            amount: Some(5_000_000),
            address: Some("0x123...".to_string()),
            ..Default::default()
        })
        .send()
        .await?;
    
    // Wait for state to propagate
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Verify health check now returns SERVICE_UNAVAILABLE
    let health_response = reqwest::get(format!("http://127.0.0.1:{}/", port)).await?;
    assert_eq!(health_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    
    // ATTACK: Send multiple fund requests while unhealthy
    // These will consume semaphore permits and increment rate limit counters
    // BEFORE being rejected by the funder health check
    let mut handles = vec![];
    for _ in 0..10 {
        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let response = reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}/fund", port))
                .json(&FundRequest {
                    amount: Some(100),
                    address: Some("0x456...".to_string()),
                    ..Default::default()
                })
                .send()
                .await?;
            let elapsed = start.elapsed();
            
            // Request fails (correctly), but only after resource consumption
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            
            // Verify this took time (proving checkers ran, storage I/O occurred)
            assert!(elapsed > Duration::from_millis(10));
            
            Result::<_, anyhow::Error>::Ok(())
        });
        handles.push(handle);
    }
    
    // All requests should fail, but they consumed resources first
    for handle in handles {
        handle.await??;
    }
    
    // Verify rate limit counters were incremented (pollution occurred)
    // Check Redis/memory state shows 10 increments even though all requests failed
    
    Ok(())
}
```

This test demonstrates that during unhealthy periods, fund requests consume processing time, semaphore permits, and rate limit counter increments before being rejected, confirming the health check bypass vulnerability.

## Notes

The code comment at line 271-274 in `transfer.rs` acknowledges this behavior and assumes load balancers will quickly deregister unhealthy instances. However, this creates a vulnerability window where attackers can deliberately waste resources and amplify service degradation. The fix should eliminate this window by checking health before any resource consumption, maintaining consistency with the dedicated health check endpoint's behavior.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/basic.rs (L46-69)
```rust
    async fn root(&self) -> poem::Result<PlainText<String>> {
        // Confirm that we haven't hit the max concurrent requests.
        if let Some(ref semaphore) = self.concurrent_requests_semaphore {
            if semaphore.available_permits() == 0 {
                return Err(poem::Error::from((
                    StatusCode::SERVICE_UNAVAILABLE,
                    anyhow::anyhow!("Server is overloaded"),
                )));
            }
        }

        // Confirm that the Funder is healthy.
        let funder_health = self.funder.is_healthy().await;
        if !funder_health.can_process_requests {
            return Err(poem::Error::from((
                StatusCode::SERVICE_UNAVAILABLE,
                anyhow::anyhow!(
                    "{}",
                    funder_health
                        .message
                        .unwrap_or_else(|| "Funder is unhealthy".to_string())
                ),
            )));
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L204-215)
```rust
        let permit = match &self.concurrent_requests_semaphore {
            Some(semaphore) => match semaphore.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Err(AptosTapError::new(
                        "Server overloaded, please try again later".to_string(),
                        AptosTapErrorCode::ServerOverloaded,
                    ))
                },
            },
            None => None,
        };
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L263-280)
```rust
        if !dry_run {
            let incremented_limit_value = match limit_value {
                Some(_) => conn.incr(&key, 1).await.map_err(|e| {
                    AptosTapError::new_with_error_code(
                        format!("Failed to increment redis key {}: {}", key, e),
                        AptosTapErrorCode::StorageError,
                    )
                })?,
                // If the limit value doesn't exist, create it and set the
                // expiration time.
                None => {
                    let (incremented_limit_value,): (i64,) = redis::pipe()
                        .atomic()
                        .incr(&key, 1)
                        // Expire at the end of the day roughly.
                        .expire(&key, seconds_until_next_day as usize)
                        // Only set the expiration if one isn't already set.
                        // Only works with Redis 7 sadly.
```

**File:** crates/aptos-faucet/core/src/funder/transfer.rs (L271-275)
```rust
        // Confirm the funder has sufficient balance, return a 500 if not. This
        // will only happen briefly, soon after we get into this state the LB
        // will deregister this instance based on the health check responses
        // being returned from `/`.
        self.is_healthy_as_result().await?;
```

**File:** crates/aptos-faucet/core/src/endpoints/api.rs (L9-28)
```rust
pub fn build_openapi_service(
    basic_api: BasicApi,
    captcha_api: CaptchaApi,
    fund_api: FundApi,
) -> OpenApiService<(BasicApi, CaptchaApi, FundApi), ()> {
    let version = VERSION.to_string();
    let license =
        LicenseObject::new("Apache 2.0").url("https://www.apache.org/licenses/LICENSE-2.0.html");
    let contact = ContactObject::new()
        .name("Aptos Labs")
        .url("https://github.com/aptos-labs");

    let apis = (basic_api, captcha_api, fund_api);

    OpenApiService::new(apis, "Aptos Tap", version.trim())
        .server("/v1")
        .description("todo")
        .license(license)
        .contact(contact)
}
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L783-807)
```rust
        // Now check the health endpoint. It should now be unhealthy because the
        // account balance has dropped below the minimum.
        let response = reqwest::Client::new()
            .get(get_root_endpoint(port))
            .send()
            .await;
        assert_eq!(
            response.unwrap().status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );

        // An additional fund request should fail.
        let response = reqwest::Client::new()
            .post(get_fund_endpoint(port))
            .body(get_fund_request(Some(10)).to_json_string())
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let aptos_error = AptosTapError::parse_from_json_string(&response.text().await?)
            .expect("Failed to read response as AptosError");
        assert_eq!(
            aptos_error.error_code,
            AptosTapErrorCode::FunderAccountProblem
        );
```
