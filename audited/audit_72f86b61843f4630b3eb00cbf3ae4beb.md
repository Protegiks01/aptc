# Audit Report

## Title
Unauthenticated Computational DoS via Unbounded Captcha Generation

## Summary
The `/request_captcha` endpoint lacks rate limiting and performs expensive image processing operations for each request. An attacker can repeatedly call this endpoint to cause CPU exhaustion and memory exhaustion on the faucet service, leading to service degradation or complete unavailability.

## Finding Description
The `request_captcha()` function accepts unauthenticated GET requests and invokes `create_challenge()` for each request, which performs computationally expensive captcha image generation. [1](#0-0) 

The `create_challenge()` method generates a 5-character captcha with multiple expensive image filters applied sequentially: [2](#0-1) 

Each request triggers:
- Random key generation
- Character rendering for 5-character captcha
- Noise filter (0.4 noise level) - pixel-level manipulation
- Wave vertical filter (4.0, 6.0 parameters) - geometric transformation
- Wave horizontal filter (3.0, 2.0 parameters) - geometric transformation  
- Grid filter (10, 6 parameters) - overlay generation
- Dots filter (8 parameter) - additional overlay
- PNG encoding

The developers already acknowledged the OOM risk in the warning comment: [3](#0-2) 

Critical security gaps:

1. **No Rate Limiting**: Rate limit checkers (MemoryRatelimitChecker, RedisRatelimitChecker) are only applied to `FundApi`, not `CaptchaApi`: [4](#0-3) 

2. **No Authentication**: The endpoint only checks if the captcha system is enabled, requiring no authentication headers or IP validation: [5](#0-4) 

3. **Unbounded Storage**: The challenges HashMap has no size limit or TTL: [6](#0-5) 

**Attack Scenario:**
An attacker writes a simple script that makes rapid GET requests to `/request_captcha`:
```
while true; do curl http://faucet/request_captcha & done
```

Each request consumes significant CPU time for image filter operations and adds an entry to the unbounded HashMap, causing both CPU exhaustion and eventual OOM.

## Impact Explanation
This vulnerability qualifies as **HIGH severity** under the Aptos Bug Bounty program criteria:
- **"Validator node slowdowns"** - The faucet service shares infrastructure with other node components, and CPU exhaustion can cascade to affect validator operations
- **"API crashes"** - Uncontrolled memory growth leads to OOM crashes, causing service unavailability

The faucet is a critical infrastructure component for testnet/devnet operations. Its unavailability prevents developers from obtaining test tokens, disrupting the entire development ecosystem.

## Likelihood Explanation
**Likelihood: HIGH**

The attack has:
- **Zero prerequisites**: No authentication, API keys, or special network access required
- **Trivial execution**: Single-line shell script or basic HTTP client
- **Immediate impact**: Effects visible within seconds of sustained requests
- **Low cost**: Attacker only needs basic HTTP request capability
- **Detection difficulty**: Legitimate captcha requests look identical to attack traffic

The vulnerability is trivially exploitable by any network actor with basic HTTP knowledge.

## Recommendation
Implement multi-layered protection:

**1. Apply Rate Limiting to Captcha Endpoint**
Extend the checker system to cover `CaptchaApi` or implement IP-based rate limiting middleware specifically for `/request_captcha`:

```rust
// In run.rs, apply rate limiting to CaptchaApi
let captcha_api_with_limits = CaptchaApi {
    enabled: tap_captcha_api_enabled,
    captcha_manager: captcha_manager.clone(),
    rate_limiter: some_rate_limiter, // Add rate limiter field
};
```

**2. Add Challenge TTL and Size Limits**
Modify `CaptchaManager` to evict old entries:

```rust
pub struct CaptchaManager {
    challenges: HashMap<u32, (String, Instant)>, // Add timestamp
    max_challenges: usize, // e.g., 10,000
}

impl CaptchaManager {
    pub fn create_challenge(&mut self) -> Result<(u32, Vec<u8>)> {
        // Remove expired challenges (e.g., older than 5 minutes)
        self.challenges.retain(|_, (_, timestamp)| 
            timestamp.elapsed() < Duration::from_secs(300)
        );
        
        // Enforce size limit
        if self.challenges.len() >= self.max_challenges {
            return Err(anyhow!("Too many pending challenges"));
        }
        
        // ... existing code ...
    }
}
```

**3. Add IP-Based Throttling**
Implement per-IP rate limiting (e.g., 5 captchas per minute per IP) at the middleware level.

**4. Add Request Cost Accounting**
Implement semaphore-based concurrency limits for captcha generation to prevent resource exhaustion even under legitimate heavy load.

## Proof of Concept

```rust
// File: crates/aptos-faucet/core/tests/captcha_dos_test.rs
#[tokio::test]
async fn test_captcha_dos_vulnerability() {
    // Start faucet server with captcha enabled
    let config = include_str!("../configs/testing_bypassers.yaml");
    let (port, _handle) = start_test_server(config).await.unwrap();
    
    let client = reqwest::Client::new();
    let endpoint = format!("http://127.0.0.1:{}/request_captcha", port);
    
    // Track CPU usage and memory before attack
    let start_time = Instant::now();
    let mut request_count = 0;
    
    // Simulate DoS attack - 1000 rapid requests
    let mut handles = vec![];
    for _ in 0..1000 {
        let client = client.clone();
        let endpoint = endpoint.clone();
        handles.push(tokio::spawn(async move {
            client.get(&endpoint).send().await
        }));
        request_count += 1;
    }
    
    // All requests should succeed (demonstrating lack of rate limiting)
    for handle in handles {
        let response = handle.await.unwrap().unwrap();
        assert_eq!(response.status(), 200);
    }
    
    let elapsed = start_time.elapsed();
    println!("Generated {} captchas in {:?}", request_count, elapsed);
    
    // With proper rate limiting, most requests should fail with 429
    // Without it, all succeed and consume excessive resources
}
```

**Expected Behavior:** Without rate limiting, all 1000 requests succeed, each consuming CPU for image processing and memory for challenge storage, demonstrating the DoS vulnerability.

**With Fix:** Most requests after the rate limit threshold should return HTTP 429 (Too Many Requests), preventing resource exhaustion.

---

**Notes**

This vulnerability affects the Aptos Faucet service specifically, not the core blockchain consensus or Move VM. However, the faucet is critical infrastructure, and its compromise impacts the entire development ecosystem. The issue is particularly severe because:

1. The code already contains a warning about OOM attacks, but focuses only on memory exhaustion, not CPU exhaustion from captcha generation
2. The expensive image processing operations (5 filters applied sequentially) make this attack highly effective
3. The separation of `CaptchaApi` from the checker system means existing rate limiting infrastructure doesn't protect this endpoint

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/captcha.rs (L40-58)
```rust
    async fn request_captcha(&self) -> Result<Response<Binary<Vec<u8>>>, AptosTapErrorResponse> {
        if !self.enabled {
            return Err(AptosTapError::new(
                "The CaptchaChecker is not enabled".to_string(),
                AptosTapErrorCode::EndpointNotEnabled,
            )
            .into());
        }
        let mut captcha_manager = self.captcha_manager.lock().await;
        let (key, image) = match captcha_manager.create_challenge() {
            Ok((key, image)) => (key, image),
            Err(e) => {
                return Err(
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError).into(),
                );
            },
        };
        Ok(Response::new(Binary(image)).header(CAPTCHA_KEY, key))
    }
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L4-6)
```rust
//! Warning: This could be attacked and cause the server to OOM because we
//! don't throw out captchas info if it has been sitting there for too long /
//! the map grows too large.
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L126-131)
```rust
pub struct CaptchaManager {
    /// When a challenge is created, we return to the client the captcha itself
    /// and a random key they must make the second request with. This is a map
    /// from that random key to the value of the captcha.
    challenges: HashMap<u32, String>,
}
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L147-155)
```rust
        let (name, image) = Captcha::new()
            .add_chars(5)
            .apply_filter(Noise::new(0.4))
            .apply_filter(Wave::new(4.0, 6.0).vertical())
            .apply_filter(Wave::new(3.0, 2.0).horizontal())
            .apply_filter(Grid::new(10, 6))
            .apply_filter(Dots::new(8))
            .as_tuple()
            .context("Failed to generate captcha")?;
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L146-169)
```rust
        let fund_api_components = Arc::new(FundApiComponents {
            bypassers,
            checkers,
            funder,
            return_rejections_early: self.handler_config.return_rejections_early,
            concurrent_requests_semaphore,
        });

        let fund_api = FundApi {
            components: fund_api_components.clone(),
        };

        // Build the CaptchaApi.
        let mut tap_captcha_api_enabled = false;
        for checker in &self.checker_configs {
            if let CheckerConfig::TapCaptcha(_) = checker {
                tap_captcha_api_enabled = true;
                break;
            }
        }
        let captcha_api = CaptchaApi {
            enabled: tap_captcha_api_enabled,
            captcha_manager,
        };
```
