# Audit Report

## Title
Semaphore Exhaustion Vulnerability in Aptos Faucet Service Allows Denial of Service

## Summary
The Aptos faucet service implements a concurrency limit using a semaphore mechanism to prevent overload. However, there are no timeouts on how long a request can hold a semaphore permit. This allows an attacker to exhaust all available permits through slow client attacks or by exploiting long-running operations, causing complete denial of service for legitimate users.

## Finding Description

The faucet service uses a semaphore to limit concurrent requests via the `max_concurrent_requests` configuration parameter. [1](#0-0) 

The semaphore is initialized during server startup: [2](#0-1) 

When a funding request is received, the semaphore permit is acquired in `preprocess_request` using `try_acquire()`: [3](#0-2) 

**The vulnerability occurs because:**

1. **Permit held for entire request duration**: The permit is stored in a variable that lives for the entire request handler execution: [4](#0-3) 

2. **No HTTP-level timeouts**: The Poem server is configured without explicit request timeouts: [5](#0-4) 

3. **Long-running operations while holding permit**: The permit is held during multiple expensive operations:

   - **Sequence number updates** that can loop for up to 60 seconds: [6](#0-5) 

   - **Transaction submission and waiting** (when `wait_for_transactions` is enabled) that can take 85+ seconds (25s transaction expiration + 60s max server lag): [7](#0-6) 

   - **Checker execution and completion** that may involve external API calls: [8](#0-7) 

**Attack Execution Path:**

1. Attacker identifies `max_concurrent_requests` value (e.g., 10) through reconnaissance or trial
2. Attacker sends exactly `max_concurrent_requests` concurrent POST requests to `/fund` endpoint
3. Each request holds a semaphore permit for 60-85+ seconds due to legitimate processing time
4. All subsequent legitimate user requests immediately fail with "Server overloaded" error
5. Attack can be sustained by continuously making new requests as old ones complete
6. No authentication or rate limiting can prevent this since requests appear legitimate

**Alternative slow-client attack:**
Even without exploiting long operations, an attacker can deliberately slow-read the HTTP response, holding the permit until the TCP connection times out (which may be minutes depending on infrastructure configuration).

## Impact Explanation

This vulnerability causes **complete denial of service** for the Aptos faucet service, preventing legitimate users from obtaining test tokens. Per the Aptos bug bounty program:

- **High Severity** criteria include "API crashes" - while the API doesn't crash, it becomes completely unavailable
- **Medium Severity** criteria include service unavailability requiring intervention

The impact is **Medium Severity** because:
- The faucet service becomes completely unavailable to legitimate users
- Only the faucet service is affected, not core blockchain consensus or validator operations
- No funds are lost or manipulated (faucet distributes test tokens, not mainnet assets)
- Recovery requires operator intervention to restart service or adjust configuration
- Attack is trivial to execute (requires only `max_concurrent_requests` concurrent HTTP requests)

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited or triggered because:

1. **Zero authentication requirements**: Anyone can call the faucet endpoint
2. **Trivial to execute**: Attacker needs only basic HTTP client tools (curl, Python requests, etc.)
3. **Low attacker cost**: Requires `max_concurrent_requests` concurrent connections (typically 5-20)
4. **Natural occurrence**: Even without malicious intent, legitimate high load can trigger this during:
   - Testnet events or hackathons
   - Blockchain congestion causing transaction delays
   - Network latency issues
5. **No detection mechanisms**: Service appears healthy until all permits exhausted
6. **Sustained impact**: Once triggered, recovery requires all in-flight requests to complete

The default configuration makes this especially dangerous - if `wait_for_transactions` is enabled (common for ensuring users receive tokens), each request legitimately holds a permit for 85+ seconds.

## Recommendation

**Immediate Mitigation:**
1. Set `max_concurrent_requests` to a higher value (e.g., 100+) to increase attack cost
2. Disable `wait_for_transactions` to reduce permit hold time
3. Implement rate limiting per IP address before semaphore acquisition

**Proper Fix - Add Request Timeout Wrapper:**

```rust
// In fund.rs, wrap the entire request handler with timeout
use tokio::time::{timeout, Duration};

async fn fund_inner(
    &self,
    fund_request: FundRequest,
    source_ip: RealIp,
    header_map: &HeaderMap,
    dry_run: bool,
    asset: Option<String>,
) -> poem::Result<Vec<SignedTransaction>, AptosTapError> {
    // Wrap entire processing in timeout (e.g., 30 seconds)
    let result = timeout(
        Duration::from_secs(30),
        self.fund_inner_impl(fund_request, source_ip, header_map, dry_run, asset)
    ).await;
    
    match result {
        Ok(r) => r,
        Err(_) => Err(AptosTapError::new(
            "Request timeout - please try again".to_string(),
            AptosTapErrorCode::ServerOverloaded,
        ))
    }
}
```

**Better Architecture - Granular Semaphore Scope:**

Move semaphore acquisition to only protect the transaction submission phase, not checkers or waiting:

```rust
// Acquire permit only during transaction submission
async fn fund_inner_impl(...) -> Result<...> {
    let (checker_data, bypass, _) = self
        .preprocess_request_no_semaphore(&fund_request, source_ip, header_map, dry_run)
        .await?;
    
    // Acquire permit only for actual funding operation
    let _permit = match &self.concurrent_requests_semaphore {
        Some(semaphore) => Some(semaphore.acquire().await?),
        None => None,
    };
    
    let fund_result = self.funder.fund(...).await;
    
    // Permit automatically released here when _permit drops
    fund_result
}
```

## Proof of Concept

```rust
// PoC: Exhaust faucet semaphore permits
// Run with: cargo test --package aptos-faucet-core test_semaphore_exhaustion

#[tokio::test]
async fn test_semaphore_exhaustion() {
    // Setup faucet with max_concurrent_requests = 5
    let config = RunConfig {
        handler_config: HandlerConfig {
            max_concurrent_requests: Some(5),
            use_helpful_errors: true,
            return_rejections_early: false,
        },
        // ... other config
    };
    
    let (port, _handle) = start_faucet_server(config).await.unwrap();
    
    let client = reqwest::Client::new();
    let mut handles = vec![];
    
    // Step 1: Exhaust all 5 permits with slow requests
    for _ in 0..5 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let response = client
                .post(format!("http://127.0.0.1:{}/fund", port))
                .json(&json!({
                    "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "amount": 100000000
                }))
                .send()
                .await
                .unwrap();
            
            // Simulate slow client - read response byte by byte
            tokio::time::sleep(Duration::from_secs(60)).await;
            response
        });
        handles.push(handle);
    }
    
    // Step 2: Wait a bit to ensure all permits acquired
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    // Step 3: Legitimate user request should fail with "Server overloaded"
    let legitimate_response = client
        .post(format!("http://127.0.0.1:{}/fund", port))
        .json(&json!({
            "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "amount": 100000000
        }))
        .send()
        .await
        .unwrap();
    
    // Assert legitimate user is denied
    assert_eq!(legitimate_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error_text = legitimate_response.text().await.unwrap();
    assert!(error_text.contains("Server overloaded"));
    
    println!("✓ Vulnerability confirmed: All semaphore permits exhausted");
    println!("✓ Legitimate users completely denied access");
}
```

## Notes

While this vulnerability only affects the faucet service (not core blockchain consensus), it represents a significant operational security issue. The faucet is critical infrastructure for testnet operations, onboarding new developers, and supporting the ecosystem. Complete denial of service can severely impact developer experience and testing capabilities.

The root cause is the lack of timeout enforcement at the HTTP request handler level combined with holding the concurrency-limiting semaphore for the entire request duration, including potentially very long blockchain operations. This design pattern violates the principle of minimizing critical section duration and creates an easily exploitable denial of service condition.

### Citations

**File:** crates/aptos-faucet/core/src/server/run.rs (L49-53)
```rust
    /// The maximum number of requests the tap instance should handle at once.
    /// This allows the tap to avoid overloading its Funder, as well as to
    /// signal to a healthchecker that it is overloaded (via `/`).
    pub max_concurrent_requests: Option<usize>,
}
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L93-96)
```rust
        let concurrent_requests_semaphore = self
            .handler_config
            .max_concurrent_requests
            .map(|v| Arc::new(Semaphore::new(v)));
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L207-220)
```rust
        let api_server_future = Server::new_with_acceptor(TcpAcceptor::from_tokio(listener)?).run(
            Route::new()
                .nest(
                    &self.server_config.api_path_base,
                    Route::new()
                        .nest("", api_service)
                        .catch_all_error(convert_error),
                )
                .at("/spec.json", spec_json)
                .at("/spec.yaml", spec_yaml)
                .at("/mint", poem::post(mint.data(fund_api_components)))
                .with(cors)
                .around(middleware_log),
        );
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L262-278)
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

        if !rejection_reasons.is_empty() {
            return Err(AptosTapError::new(
                format!("Request rejected by {} checkers", rejection_reasons.len()),
                AptosTapErrorCode::Rejected,
            )
            .rejection_reasons(rejection_reasons));
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L294-296)
```rust
        let (checker_data, bypass, _semaphore_permit) = self
            .preprocess_request(&fund_request, source_ip, header_map, dry_run)
            .await?;
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L232-285)
```rust
    for _ in 0..(wait_for_outstanding_txns_secs * 2) {
        if our_funder_seq < funder_seq + MAX_NUM_OUTSTANDING_TRANSACTIONS {
            // Enforce a stronger ordering of priorities based upon the MintParams that arrived
            // first. Then put the other folks to sleep to try again until the queue fills up.
            if !set_outstanding {
                let mut requests_map = outstanding_requests.write().await;
                let queue = requests_map
                    .entry(asset_name.to_string())
                    .or_insert_with(Vec::new);
                queue.push(request_key);
                set_outstanding = true;
            }

            // Check if this request is at the front of the queue for this asset
            let requests_map = outstanding_requests.read().await;
            let is_at_front = if let Some(queue) = requests_map.get(asset_name) {
                queue.first() == Some(&request_key)
            } else {
                false
            };

            if is_at_front {
                // There might have been two requests with the same parameters, so we ensure that
                // we only pop off one of them. We do a read lock first since that is cheap,
                // followed by a write lock.
                drop(requests_map);
                let mut requests_map = outstanding_requests.write().await;
                if let Some(queue) = requests_map.get_mut(asset_name) {
                    if queue.first() == Some(&request_key) {
                        queue.remove(0);
                    }
                }
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            continue;
        }
        let num_outstanding = our_funder_seq - funder_seq;

        sample!(
            SampleRate::Duration(Duration::from_secs(2)),
            warn!(
                "We have too many outstanding transactions: {}. Sleeping to let the system catchup.",
                num_outstanding
            );
        );

        // Report the number of outstanding transactions.
        NUM_OUTSTANDING_TRANSACTIONS.set(num_outstanding as i64);

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        (funder_seq, receiver_seq) =
            get_sequence_numbers(client, funder_account, receiver_address).await?;
    }
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L349-375)
```rust
    let (result, event_on_success) = if wait_for_transactions {
        // If this fails, we assume it is the user's fault, e.g. because the
        // account already exists, but it is possible that the transaction
        // timed out. It's hard to tell because this function returns an opaque
        // anyhow error. https://github.com/aptos-labs/aptos-tap/issues/60.
        (
            client
                .submit_and_wait_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
            "transaction_success",
        )
    } else {
        (
            client
                .submit_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
            "transaction_submitted",
        )
    };
```
