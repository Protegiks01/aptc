# Audit Report

## Title
Unprotected Captcha Generation Endpoint Enables CPU and Memory Exhaustion DoS Attack

## Summary
The `/request_captcha` endpoint in the Aptos faucet service is vulnerable to a resource exhaustion attack. Attackers can flood this endpoint to trigger computationally expensive captcha image generation without any rate limiting, authentication, or IP-based restrictions, leading to CPU exhaustion and memory exhaustion (OOM) of the faucet service.

## Finding Description

The vulnerability exists in the captcha generation flow where the `/request_captcha` endpoint calls `CaptchaManager::create_challenge()` without any protective measures.

**Vulnerable Endpoint:** [1](#0-0) 

The endpoint directly calls `captcha_manager.create_challenge()` after only checking if the captcha feature is enabled. No rate limiting, IP blocking, or authentication is performed.

**Computationally Expensive Operation:** [2](#0-1) 

The `create_challenge()` function applies five CPU-intensive image filters (Noise, Wave vertical, Wave horizontal, Grid, and Dots) to generate each captcha, then stores the result in an unbounded HashMap.

**Known Vulnerability Acknowledgment:** [3](#0-2) 

The developers explicitly documented this attack vector with a warning comment acknowledging the OOM risk.

**Rate Limiting Architecture Bypassed:** The faucet service implements rate limiting through "Checkers" [4](#0-3) 

However, these checkers (including MemoryRatelimitChecker and RedisRatelimitChecker) are only applied to the `/fund` endpoint through the FundApi, not to the CaptchaApi. [5](#0-4) 

**Attack Execution:**
1. Attacker sends rapid HTTP GET requests to `/request_captcha`
2. Each request acquires the mutex lock and generates a captcha with 5 expensive filters
3. Generated captcha key-value pairs accumulate in the unbounded HashMap
4. CPU is exhausted from continuous image generation
5. Memory is exhausted as the HashMap grows without bounds
6. Faucet service becomes unresponsive or crashes with OOM

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: HIGH**

According to the Aptos Bug Bounty program, this qualifies as HIGH severity due to:
- **Validator node slowdowns**: If the faucet service runs on or shares resources with validator infrastructure, this can degrade validator performance
- **API crashes**: The faucet API will crash from OOM or become unresponsive from CPU exhaustion

The faucet service is critical infrastructure for network onboarding, testnet operations, and developer experience. Prolonged unavailability disrupts the ecosystem and can prevent new users from accessing the network.

## Likelihood Explanation

**Likelihood: VERY HIGH**

This attack is:
- **Trivial to execute**: Requires only HTTP client (curl, browser, script)
- **No prerequisites**: No authentication, tokens, or captcha solving required
- **Cheap to perform**: Minimal bandwidth and resources needed by attacker
- **Difficult to detect**: Appears as legitimate traffic until resource exhaustion occurs
- **Publicly exposed**: The `/request_captcha` endpoint is openly accessible

The existence of the developer warning comment indicates this was a known architectural weakness that was left unaddressed.

## Recommendation

Implement multi-layered protection:

1. **Add rate limiting to the captcha endpoint** - Apply the existing rate limiting checkers (IP-based or Redis-based) to `/request_captcha`:
   - Limit requests per IP address (e.g., 10 captchas per hour)
   - Implement exponential backoff for repeated requests

2. **Implement captcha expiration** - Add TTL to captcha entries in the HashMap:
   - Remove captchas older than 5 minutes
   - Implement periodic cleanup task to prevent unbounded growth

3. **Add maximum capacity limits** - Reject new captcha requests when HashMap exceeds threshold:
   - Set maximum captcha storage (e.g., 10,000 active challenges)
   - Return HTTP 503 when limit reached

4. **Consider caching/throttling** - Implement request queuing with bounded concurrency:
   - Limit concurrent captcha generation operations
   - Use semaphore to control parallel processing

**Example Fix Pattern:**
Apply the same CheckerData validation pattern used by FundApi to CaptchaApi, or implement a simpler IP-based rate limiter directly in the captcha endpoint using the existing rate limiting infrastructure.

## Proof of Concept

```bash
#!/bin/bash
# DoS Attack Simulation - Flood the captcha endpoint

FAUCET_URL="http://localhost:10212"  # Adjust to target faucet URL

echo "Starting captcha DoS attack..."
echo "Monitor server CPU and memory usage"

# Send 1000 concurrent requests
for i in {1..1000}; do
  curl -s -o /dev/null "$FAUCET_URL/request_captcha" &
done

wait
echo "Attack complete. Server should show signs of resource exhaustion."
```

**Expected Results:**
- Server CPU usage spikes to 100%
- Memory consumption grows unbounded
- Response times degrade significantly
- Service becomes unresponsive or crashes with OOM
- Legitimate users cannot access faucet services

**To verify the vulnerability:**
1. Start a local faucet with captcha enabled
2. Run the PoC script
3. Monitor server resources (`top`, `htop`, memory usage)
4. Observe CPU exhaustion and memory growth
5. Attempt legitimate faucet requests - they will fail or timeout

---

**Notes:**
This vulnerability is particularly severe because it bypasses all existing security mechanisms (rate limiting, IP blocking, authentication) that protect the `/fund` endpoint. The mutex lock provides serialization but no throttling, meaning requests are still processed sequentially at maximum CPU utilization until the service crashes.

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

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L142-162)
```rust
    pub fn create_challenge(&mut self) -> Result<(u32, Vec<u8>)> {
        // Generate a random key.
        let key = rand::thread_rng().gen_range(0, u32::MAX - 1);

        // Generate a captcha.
        let (name, image) = Captcha::new()
            .add_chars(5)
            .apply_filter(Noise::new(0.4))
            .apply_filter(Wave::new(4.0, 6.0).vertical())
            .apply_filter(Wave::new(3.0, 2.0).horizontal())
            .apply_filter(Grid::new(10, 6))
            .apply_filter(Dots::new(8))
            .as_tuple()
            .context("Failed to generate captcha")?;

        // Store the captcha information.
        self.challenges.insert(key, name);

        // Return (key, <captcha as base64>).
        Ok((key, image))
    }
```

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L38-53)
```rust
/// Implementers of this trait are responsible for checking something about the
/// request, and if it doesn't look valid, returning a list of rejection reasons
/// explaining why. It may also do something extra after the funding happened
/// if there is something to clean up afterwards.
#[async_trait]
#[enum_dispatch]
pub trait CheckerTrait: Sync + Send + 'static {
    /// Returns a list of rejection reasons for the request, if any. If dry_run
    /// is set, if this Checker would store anything based on the request, it
    /// instead will not. This is useful for the is_eligible endpoint.
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError>;

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
