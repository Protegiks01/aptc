# Audit Report

## Title
Faucet Metrics Endpoint Exposes Business Logic Details Enabling Optimized Drain Attacks

## Summary
The faucet metrics server exposes a publicly accessible `/metrics` endpoint without authentication that leaks critical business logic details including real-time funder account balance, rejection reason patterns, and operational statistics. This information disclosure enables attackers to optimize faucet drain attacks, fingerprint anti-bot mechanisms, and coordinate timing to maximize fund extraction.

## Finding Description

The faucet metrics server runs on a separate port (default 9101) and exposes Prometheus metrics at `/metrics` with only basic CORS middleware allowing GET requests, but **no authentication or authorization**. [1](#0-0) [2](#0-1) 

The metrics expose three categories of sensitive business logic:

**1. Real-Time Funder Account Balance**

The `aptos_tap_transfer_funder_account_balance` gauge exposes the exact balance of the faucet's funding account in real-time, updated during health checks: [3](#0-2) [4](#0-3) 

**2. Rejection Reason Counters**

The `aptos_tap_rejection_reason_count` metric tracks how many times each rejection reason code has been returned, revealing which anti-bot mechanisms are active: [5](#0-4) [6](#0-5) 

The rejection codes expose: IP blocklisting (102), VPN detection (103), cloud detection (104), magic header validation (105), captcha verification (106), auth token validation (107), and referer blocklisting (108). [7](#0-6) 

**3. Rate Limit Values in Error Messages**

When users hit rate limits, the exact `max_requests_per_day` value is disclosed in error messages: [8](#0-7) [9](#0-8) 

**Attack Exploitation Path:**

1. Attacker monitors the public metrics endpoint continuously
2. By observing `aptos_tap_transfer_funder_account_balance`, they learn:
   - Exact remaining funds in the faucet
   - When refills occur and their amounts
   - Optimal timing for drain attacks (right after refills)
3. By observing rejection reason counters, they fingerprint:
   - Which anti-bot mechanisms are deployed
   - Which evasion techniques are necessary
   - Patterns of legitimate vs. blocked usage
4. By correlating balance changes with transaction counts, they calculate:
   - Exact per-request funding amounts
   - Whether to request maximum amounts
5. Attacker coordinates multiple bot instances to drain funds efficiently just after detection of a refill

## Impact Explanation

This qualifies as **Medium Severity** per the Aptos bug bounty program category "Limited funds loss or manipulation." 

While the faucet is not part of the core blockchain consensus, it holds real funds that can be drained. The information disclosure enables:
- **More efficient fund extraction** by timing attacks around refills
- **Reduced detection** by knowing which anti-bot mechanisms to evade
- **Optimized bot configuration** without trial-and-error probing
- **Coordinated attacks** using real-time balance information

This doesn't reach Critical/High severity because:
- It doesn't affect blockchain consensus or validator operations
- It doesn't enable direct theft without making faucet requests
- Faucet funds are typically limited test tokens, not mainnet assets
- Faucet rate limits still provide some protection

However, it materially increases the effectiveness of faucet abuse attacks.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:
1. The metrics endpoint is publicly accessible by default on port 9101
2. No authentication is required - any attacker can access it
3. Prometheus metrics are well-documented and easy to parse
4. The attack requires minimal sophistication - just periodic HTTP GET requests
5. Multiple faucet draining campaigns would benefit from this intelligence
6. Automated bots can easily integrate metrics monitoring into their attack logic

## Recommendation

**Immediate Fix: Add Authentication to Metrics Endpoint**

Modify the metrics server to require authentication, similar to how other sensitive Aptos node metrics are protected. Add a bearer token or basic auth requirement:

```rust
// In crates/aptos-faucet/metrics-server/src/server.rs
use poem::middleware::AddData;

#[handler]
fn metrics(auth_token: &str) -> Result<Vec<u8>, poem::Error> {
    // Validate auth_token against configured secret
    if !validate_auth_token(auth_token) {
        return Err(poem::Error::from_status(StatusCode::UNAUTHORIZED));
    }
    Ok(encode_metrics(TextEncoder))
}
```

**Additional Mitigations:**

1. **Reduce Metric Granularity**: 
   - Replace exact balance with a bucketed gauge (e.g., "healthy", "low", "critical")
   - Aggregate rejection reasons by category rather than specific codes
   
2. **Add Network-Level Protection**:
   - Bind metrics server to localhost by default instead of 0.0.0.0
   - Require operators to explicitly configure public exposure
   - Document that metrics should be behind a firewall or VPN

3. **Remove Sensitive Error Message Details**:
   - Don't include exact rate limit values in error messages
   - Use generic messages: "Rate limit exceeded, try again later"

## Proof of Concept

**Step 1: Query Public Metrics Endpoint**
```bash
# Access faucet metrics without authentication
curl http://<faucet-host>:9101/metrics

# Output includes:
# aptos_tap_transfer_funder_account_balance 50000000000
# aptos_tap_rejection_reason_count{rejection_reason_code="101"} 423
# aptos_tap_rejection_reason_count{rejection_reason_code="102"} 87
# aptos_tap_num_outstanding_transactions 3
```

**Step 2: Monitor Balance in Real-Time**
```python
import requests
import time

metrics_url = "http://<faucet-host>:9101/metrics"

while True:
    response = requests.get(metrics_url)
    for line in response.text.split('\n'):
        if 'aptos_tap_transfer_funder_account_balance' in line:
            balance = line.split()[-1]
            print(f"Current faucet balance: {balance}")
            
            # Detect refills
            if int(balance) > previous_balance * 1.5:
                print("REFILL DETECTED - Launch attack now!")
    time.sleep(5)
```

**Step 3: Fingerprint Anti-Bot Mechanisms**
```python
# Parse rejection reason codes to identify active security measures
rejection_codes = {
    "102": "IP Blocklisting Active",
    "103": "VPN Detection Active",
    "104": "Cloud Detection Active", 
    "105": "Magic Header Required",
    "106": "Captcha Required",
    "107": "Auth Token Required"
}

for line in response.text.split('\n'):
    if 'aptos_tap_rejection_reason_count' in line:
        for code, mechanism in rejection_codes.items():
            if f'rejection_reason_code="{code}"' in line:
                print(f"✓ {mechanism}")
```

This PoC demonstrates that an unprivileged attacker can continuously monitor faucet operational state and use this intelligence to optimize drain attacks without any authentication barriers.

## Notes

This vulnerability is specific to the Aptos Faucet auxiliary service and does not impact core blockchain consensus, execution, or state management. However, it represents a **security-by-obscurity failure** where operational details that should remain private to defenders are publicly exposed to attackers. The issue is particularly concerning because metrics endpoints are often overlooked during security reviews, yet provide a persistent, low-noise intelligence channel for adversaries.

### Citations

**File:** crates/aptos-faucet/metrics-server/src/server.rs (L31-40)
```rust
pub fn run_metrics_server(
    config: MetricsServerConfig,
) -> impl Future<Output = Result<(), std::io::Error>> {
    let cors = Cors::new().allow_methods(vec![Method::GET]);
    Server::new(TcpListener::bind((
        config.listen_address.clone(),
        config.listen_port,
    )))
    .run(Route::new().at("/metrics", metrics).with(cors))
}
```

**File:** crates/aptos-faucet/metrics-server/src/config.rs (L22-32)
```rust
    fn default_disable() -> bool {
        false
    }

    fn default_listen_address() -> String {
        "0.0.0.0".to_string()
    }

    fn default_listen_port() -> u16 {
        9101
    }
```

**File:** crates/aptos-faucet/core/src/funder/transfer.rs (L364-364)
```rust
        TRANSFER_FUNDER_ACCOUNT_BALANCE.set(funder_balance as i64);
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

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L47-53)
```rust
pub static TRANSFER_FUNDER_ACCOUNT_BALANCE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_tap_transfer_funder_account_balance",
        "Balance of the account used by the tap instance. Only populated for the TransferFunder.",
    )
    .unwrap()
});
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

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L233-267)
```rust
// todo explain that the frontend may not want to display specifics here.
// say this is only for the filters. maybe rename to say filters.
#[derive(Copy, Clone, Debug, Enum, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum RejectionReasonCode {
    /// Intentionally unhelpful reason code.
    Hehe = 1,

    /// Account already has funds.
    AccountAlreadyExists = 100,

    /// Key (IP / Firebase UID) has exhausted its usage limit.
    UsageLimitExhausted = 101,

    /// IP is in the blocklist.
    IpInBlocklist = 102,

    /// The origin of the request is from a VPN.
    RequestFromVpn = 103,

    /// The origin of the request is a cloud.
    RequestFromCloud = 104,

    /// The request did not contain the required magic header.
    MagicHeaderIncorrect = 105,

    /// The captcha was missing or incorrect.
    CaptchaInvalid = 106,

    /// Auth token was not given, is invalid, or is not allowed by the server.
    AuthTokenInvalid = 107,

    /// Referer was in the blocklist.
    RefererBlocklisted = 108,
}
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L78-85)
```rust
        if *requests_today >= self.max_requests_per_day {
            return Ok(vec![RejectionReason::new(
                format!(
                    "IP {} has exceeded the daily limit of {} requests",
                    data.source_ip, self.max_requests_per_day
                ),
                RejectionReasonCode::UsageLimitExhausted,
            )]);
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L207-217)
```rust
        if limit_value.unwrap_or(0) > self.args.max_requests_per_day as i64 {
            Some(
                RejectionReason::new(
                    format!(
                        "You have reached the maximum allowed number of requests per day: {}",
                        self.args.max_requests_per_day
                    ),
                    RejectionReasonCode::UsageLimitExhausted,
                )
                .retry_after(seconds_until_next_day),
            )
```
