# Audit Report

## Title
Faucet Captcha Service Denial of Service via Unbounded Memory Growth

## Summary
The `TapCaptchaCheckerConfig` struct is empty and provides no configuration options for timeout, maximum attempts, or expiration. This allows an attacker to exhaust faucet server memory by repeatedly requesting captchas or by making unlimited failed verification attempts, leading to service unavailability.

## Finding Description

The `TapCaptchaCheckerConfig` struct is defined as an empty configuration: [1](#0-0) 

The developers have acknowledged this issue in a warning comment at the beginning of the file: [2](#0-1) 

The `CaptchaManager` stores all captcha challenges in an unbounded in-memory `HashMap` with no cleanup mechanism: [3](#0-2) 

**Attack Vector 1: Memory Exhaustion via Captcha Generation**

An attacker can repeatedly call the public `/request_captcha` endpoint: [4](#0-3) 

Each request generates a new captcha and stores it permanently: [5](#0-4) 

Captchas are never removed unless successfully verified: [6](#0-5) 

**Attack Vector 2: Unlimited Failed Attempts**

An attacker can obtain a valid captcha key and make unlimited incorrect guesses. Failed attempts return `false` but do not remove the entry or implement any rate limiting.

**Missing Security Controls:**
1. **Expiration timeout**: No mechanism to expire captchas after a time period
2. **Max attempts**: No limit on failed verification attempts per key
3. **Max stored captchas**: No upper bound on HashMap size
4. **Cleanup interval**: No periodic removal of stale entries

## Impact Explanation

This vulnerability causes **Denial of Service** on the Aptos faucet service through memory exhaustion. While the faucet is not part of the core blockchain consensus or execution layer, it is critical infrastructure for testnet operations and development environments.

Per Aptos bug bounty criteria, this falls under **High Severity** as it causes "API crashes" through resource exhaustion, potentially qualifying for up to $50,000. However, since this affects only the faucet service (not core blockchain functionality) and the developers are already aware of the issue (per the warning comment), the practical severity may be lower.

## Likelihood Explanation

**Likelihood: High**

The attack requires:
- No authentication or special privileges
- Simple HTTP GET requests to a public endpoint
- Minimal technical sophistication
- No rate limiting or protective measures in place

An attacker can easily script thousands of requests to exhaust available memory within minutes to hours, depending on server resources.

## Recommendation

Add configuration options to `TapCaptchaCheckerConfig` to implement security controls:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TapCaptchaCheckerConfig {
    /// Maximum number of captchas to store concurrently
    pub max_stored_captchas: usize,
    
    /// Time in seconds before a captcha expires
    pub captcha_expiration_secs: u64,
    
    /// Maximum failed verification attempts per captcha key
    pub max_verification_attempts: u32,
    
    /// Interval in seconds for cleanup task
    pub cleanup_interval_secs: u64,
}
```

Implement captcha expiration tracking in `CaptchaManager`:

```rust
pub struct CaptchaManager {
    challenges: HashMap<u32, CaptchaEntry>,
    config: TapCaptchaCheckerConfig,
}

struct CaptchaEntry {
    value: String,
    created_at: u64,
    attempt_count: u32,
}
```

Add periodic cleanup task and bounds checking in `create_challenge()` and `check_challenge()` methods.

## Proof of Concept

```python
import requests
import time

# Target faucet server
FAUCET_URL = "http://localhost:8081/request_captcha"

def memory_exhaustion_attack():
    """
    Repeatedly request captchas to exhaust server memory
    """
    captcha_count = 0
    
    while True:
        try:
            response = requests.get(FAUCET_URL)
            if response.status_code == 200:
                captcha_count += 1
                if captcha_count % 1000 == 0:
                    print(f"Generated {captcha_count} captchas (accumulating in memory)")
        except Exception as e:
            print(f"Server crashed or became unresponsive: {e}")
            break
        
        # No delay needed - flood the endpoint
        
if __name__ == "__main__":
    print("Starting memory exhaustion attack on faucet captcha service...")
    memory_exhaustion_attack()
```

**Expected Result:** After generating sufficient captchas (depends on available memory), the faucet server will experience memory exhaustion, leading to OOM conditions, performance degradation, or service crash.

## Notes

This vulnerability affects the Aptos faucet service infrastructure rather than core blockchain components (consensus, execution, state management, governance, or staking). While it represents a legitimate DoS attack vector, it does not compromise blockchain security, consensus safety, or fund security. The developers have acknowledged this issue in code comments but have not yet implemented mitigations.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L4-6)
```rust
//! Warning: This could be attacked and cause the server to OOM because we
//! don't throw out captchas info if it has been sitting there for too long /
//! the map grows too large.
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L24-25)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TapCaptchaCheckerConfig {}
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L125-131)
```rust
#[derive(Debug, Default)]
pub struct CaptchaManager {
    /// When a challenge is created, we return to the client the captcha itself
    /// and a random key they must make the second request with. This is a map
    /// from that random key to the value of the captcha.
    challenges: HashMap<u32, String>,
}
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

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L164-177)
```rust
    /// Check a captcha challenge. Returns true if the captcha is correct.
    pub fn check_challenge(&mut self, key: u32, value: &str) -> Result<bool> {
        match self.challenges.get(&key) {
            Some(captcha) => {
                if captcha == value {
                    self.challenges.remove(&key);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            None => bail!("Captcha key unknown: {}", key),
        }
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
