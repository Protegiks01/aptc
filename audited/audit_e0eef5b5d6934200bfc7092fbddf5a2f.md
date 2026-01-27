# Audit Report

## Title
Timeout Bypass in REST Client Retry Logic Allows Malicious Servers to Extend Wait Times Indefinitely

## Summary
The `try_until_ok()` function in the Aptos REST client fails to properly enforce the `total_wait` timeout parameter. A malicious or misbehaving server can cause the client to wait significantly longer than the specified timeout by delaying responses and returning retriable error codes, leading to denial of service and resource exhaustion in services using the REST client.

## Finding Description

The `try_until_ok()` function checks the timeout at the **beginning** of each loop iteration but does not account for the time consumed by the actual function call or the subsequent sleep period. [1](#0-0) 

The vulnerability occurs in this sequence:

1. The function checks `start.elapsed() < total_wait` at the loop condition
2. It then calls `function().await` which can take arbitrarily long (e.g., 50 seconds)
3. After receiving a retriable error, it sleeps for `backoff` duration (exponentially increasing)
4. The loop continues if `start.elapsed() < total_wait` at the **next** iteration

**Attack Scenario:**
- Client sets `total_wait = 60 seconds`
- **t=0s**: Check `0 < 60` ✓, call function
- **t=0-50s**: Malicious server delays response for 50 seconds
- **t=50s**: Server returns 503 SERVICE_UNAVAILABLE (retriable per `retriable()` function)
- **t=50-51s**: Client sleeps 1 second (initial backoff)
- **t=51s**: Check `51 < 60` ✓, call function again
- **t=51-101s**: Server delays another 50 seconds
- **t=101s**: Server returns 503 again
- **t=101-103s**: Client sleeps 2 seconds (doubled backoff)
- **t=103s**: Check `103 < 60` ✗, exit

**Result:** Client blocked for 103 seconds despite 60-second timeout (72% overage).

The retriable error codes are defined here: [2](#0-1) 

Additionally, network timeouts, JSON parsing errors, and BCS errors are always considered retriable: [3](#0-2) 

## Impact Explanation

This vulnerability falls under **Medium severity** based on the Aptos bug bounty criteria for operational and availability issues:

- **Denial of Service**: Services using the REST client (indexers, explorers, SDKs, monitoring tools) experience unexpectedly long blocking times
- **Resource Exhaustion**: Multiple concurrent requests blocked beyond their timeout tie up threads, connections, and memory
- **Cascading Failures**: Dependent services with their own timeouts may fail while waiting for REST client responses
- **Operational Disruption**: Automated systems relying on predictable timeout behavior may malfunction

While this does not directly impact consensus safety or fund security (core validator operations use dedicated networking protocols, not REST API), it can significantly degrade the availability and reliability of the broader Aptos ecosystem infrastructure.

## Likelihood Explanation

**Likelihood: High**

The attack requires only:
1. Control over a REST API endpoint (compromised node, malicious third-party service, or any external REST endpoint)
2. Ability to delay responses (trivial - simple `sleep()` on server side)
3. Return standard HTTP error codes (503, 500, 502, 504)

No special privileges, validator access, or complex exploit chains are required. The vulnerability is triggered automatically whenever the REST client connects to a slow or malicious server, making it highly exploitable in real-world scenarios.

## Recommendation

Add checks to ensure the total elapsed time (including function execution and sleep time) does not exceed `total_wait` before making another attempt:

```rust
pub async fn try_until_ok<F, Fut, RetryFun, T>(
    total_wait: Option<Duration>,
    initial_interval: Option<Duration>,
    should_retry: RetryFun,
    function: F,
) -> AptosResult<T>
where
    F: Fn() -> Fut,
    RetryFun: Fn(StatusCode, Option<AptosError>) -> bool,
    Fut: Future<Output = AptosResult<T>>,
{
    let total_wait = total_wait.unwrap_or(DEFAULT_MAX_WAIT_DURATION);
    let mut backoff = initial_interval.unwrap_or(DEFAULT_INTERVAL_DURATION);
    let mut result = Err(RestError::Unknown(anyhow!("Failed to run function")));
    let start = Instant::now();

    while start.elapsed() < total_wait {
        result = function().await;

        // Check if we've exceeded timeout after function call
        if start.elapsed() >= total_wait {
            break;
        }

        let retry = match &result {
            Ok(_) => break,
            Err(err) => match err {
                RestError::Api(inner) => {
                    should_retry(inner.status_code, Some(inner.error.clone()))
                },
                RestError::Http(status_code, _e) => should_retry(*status_code, None),
                RestError::Bcs(_)
                | RestError::Json(_)
                | RestError::Timeout(_)
                | RestError::Unknown(_) => true,
                RestError::UrlParse(_) => false,
            },
        };

        if !retry {
            break;
        }

        // Calculate remaining time and limit sleep duration
        let elapsed = start.elapsed();
        let remaining = total_wait.saturating_sub(elapsed);
        if remaining.is_zero() {
            break;
        }

        let sleep_duration = backoff.min(remaining);
        
        info!(
            "Failed to call API, retrying in {}ms: {:?}",
            sleep_duration.as_millis(),
            result.as_ref().err().unwrap()
        );

        tokio::time::sleep(sleep_duration).await;
        backoff = backoff.saturating_mul(2);
    }

    result
}
```

Key changes:
1. Check timeout immediately after `function().await` returns
2. Calculate remaining time before sleeping
3. Limit sleep duration to not exceed remaining time
4. Break if no time remains before sleeping

## Proof of Concept

```rust
#[tokio::test]
async fn test_timeout_bypass_vulnerability() {
    use std::time::{Duration, Instant};
    use tokio::time::sleep;
    use aptos_rest_client::Client;
    use reqwest::StatusCode;

    let total_wait = Duration::from_secs(5);
    let start = Instant::now();
    
    // Simulate malicious server that delays responses
    let result = Client::try_until_ok(
        Some(total_wait),
        Some(Duration::from_millis(100)),
        |status, _| status == StatusCode::SERVICE_UNAVAILABLE,
        || async {
            // Simulate server delay of 4 seconds
            sleep(Duration::from_secs(4)).await;
            // Return retriable error
            Err(aptos_rest_client::error::RestError::Http(
                StatusCode::SERVICE_UNAVAILABLE,
                anyhow::anyhow!("Service unavailable")
            ))
        }
    ).await;
    
    let actual_duration = start.elapsed();
    
    // Vulnerability: actual duration exceeds total_wait significantly
    // First attempt: 4s + 503 error
    // Sleep: 100ms
    // Check: 4.1s < 5s ✓
    // Second attempt: 4s + 503 error
    // Total: ~8.1s > 5s timeout
    
    assert!(result.is_err(), "Should fail after retries");
    assert!(
        actual_duration > total_wait + Duration::from_secs(3),
        "Actual duration {:?} should exceed timeout {:?} by >3s due to vulnerability",
        actual_duration,
        total_wait
    );
}
```

This test demonstrates that with a 5-second timeout, the client can be blocked for over 8 seconds when the server delays each response by 4 seconds and returns retriable errors.

## Notes

While this vulnerability does not directly impact blockchain consensus or fund security, it represents a significant operational risk for the Aptos ecosystem. The REST client is a public API used by various tools, services, and SDKs. Proper timeout enforcement is critical for building reliable applications on top of Aptos infrastructure.

### Citations

**File:** crates/aptos-rest-client/src/lib.rs (L1781-1831)
```rust
    pub async fn try_until_ok<F, Fut, RetryFun, T>(
        total_wait: Option<Duration>,
        initial_interval: Option<Duration>,
        should_retry: RetryFun,
        function: F,
    ) -> AptosResult<T>
    where
        F: Fn() -> Fut,
        RetryFun: Fn(StatusCode, Option<AptosError>) -> bool,
        Fut: Future<Output = AptosResult<T>>,
    {
        let total_wait = total_wait.unwrap_or(DEFAULT_MAX_WAIT_DURATION);
        let mut backoff = initial_interval.unwrap_or(DEFAULT_INTERVAL_DURATION);
        let mut result = Err(RestError::Unknown(anyhow!("Failed to run function")));
        let start = Instant::now();

        // TODO: Add jitter
        while start.elapsed() < total_wait {
            result = function().await;

            let retry = match &result {
                Ok(_) => break,
                Err(err) => match err {
                    RestError::Api(inner) => {
                        should_retry(inner.status_code, Some(inner.error.clone()))
                    },
                    RestError::Http(status_code, _e) => should_retry(*status_code, None),
                    RestError::Bcs(_)
                    | RestError::Json(_)
                    | RestError::Timeout(_)
                    | RestError::Unknown(_) => true,
                    RestError::UrlParse(_) => false,
                },
            };

            if !retry {
                break;
            }

            info!(
                "Failed to call API, retrying in {}ms: {:?}",
                backoff.as_millis(),
                result.as_ref().err().unwrap()
            );

            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }

        result
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1944-1954)
```rust
pub fn retriable(status_code: StatusCode, _aptos_error: Option<AptosError>) -> bool {
    matches!(
        status_code,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::GATEWAY_TIMEOUT
            | StatusCode::BAD_GATEWAY
            | StatusCode::INSUFFICIENT_STORAGE
    )
}
```
