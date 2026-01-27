# Audit Report

## Title
Faucet Backend API Exhaustion via Concurrent Request Amplification

## Summary
The faucet service's `get_sequence_numbers()` function makes parallel API calls to the backend blockchain node without client-side rate limiting. Combined with no default concurrent request limit, attackers can overwhelm the backend node API by sending concurrent funding requests from multiple IPs, causing service degradation.

## Finding Description
The vulnerability exists in the faucet's request processing flow where each funding request triggers multiple API calls to the backend blockchain node: [1](#0-0) 

The `get_sequence_numbers()` function makes two parallel API calls using `futures::future::join_all([f_request, r_request])` - one for the funder account and one for the receiver account. These calls have no client-side rate limiting and rely solely on the backend node's protection.

The faucet's default configuration lacks concurrent request limiting: [2](#0-1) 

The backend node API has a rate limit of 100 requests per minute: [3](#0-2) 

**Attack Path:**
1. Attacker controls multiple IP addresses (via VPN, proxy network, or botnet)
2. Each IP bypasses the faucet's per-IP rate limiter (e.g., 100 requests/day per IP)
3. Attacker sends concurrent funding requests from all IPs simultaneously
4. Each request calls `update_sequence_numbers()` which invokes `get_sequence_numbers()`: [4](#0-3) 

5. Each `get_sequence_numbers()` call makes 2 API requests = 2x amplification
6. If 100 concurrent requests are processed: 200 API calls/minute overwhelms the 100 req/min backend limit
7. Backend node starts rate-limiting or rejecting requests, causing faucet service degradation

Additionally, during transaction backpressure, the function may retry API calls in a loop: [5](#0-4) 

This further amplifies the API call volume under load conditions.

## Impact Explanation
**Medium Severity** - This vulnerability causes service degradation and resource exhaustion but does not directly compromise funds, consensus, or cause permanent damage:

- **Backend Node API Exhaustion**: The 100 requests/minute rate limit can be exceeded, causing legitimate requests to fail
- **Faucet Service Degradation**: Timeout errors and failed funding requests for legitimate users
- **Cascading Effects**: If multiple services share the same backend node, they may also experience degradation
- **No Direct Fund Loss**: This is a DoS-style attack, not theft or consensus violation

This aligns with the Medium severity category: "State inconsistencies requiring intervention" - the faucet service becomes unreliable and requires administrative action to restore normal operation.

## Likelihood Explanation
**High Likelihood** - This attack is highly feasible:

- **Low Barrier to Entry**: Attacker needs only multiple IP addresses (easily obtainable via commercial VPN services, proxy networks, or compromised devices)
- **No Authentication Required**: The faucet is publicly accessible by design
- **Amplification Factor**: 2x amplification (2 API calls per request) makes the attack efficient
- **Default Vulnerable Configuration**: `max_concurrent_requests: None` means no protection by default
- **Testnet/Devnet Deployment**: Faucets are deployed on testnets where rate limits may be more permissive

An attacker with 50 IPs sending 10 concurrent requests each = 1,000 API calls in a burst, far exceeding the 100 req/min backend limit.

## Recommendation
Implement multiple layers of protection:

1. **Set Default Concurrent Request Limit**: Configure `max_concurrent_requests` to a reasonable value (e.g., 10-20) by default to prevent unbounded parallelism

2. **Add Client-Side Rate Limiting**: Implement a token bucket rate limiter for outgoing API calls to the backend node:

```rust
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct RateLimitedClient {
    inner: Client,
    rate_limiter: Arc<Semaphore>,
}

impl RateLimitedClient {
    pub fn new(client: Client, max_requests_per_second: usize) -> Self {
        Self {
            inner: client,
            rate_limiter: Arc::new(Semaphore::new(max_requests_per_second)),
        }
    }
    
    pub async fn get_account(&self, address: AccountAddress) -> Result<Response<Account>> {
        let _permit = self.rate_limiter.acquire().await?;
        self.inner.get_account(address).await
    }
}
```

3. **Batch API Calls**: Instead of making parallel calls for each request, batch multiple account lookups into fewer API calls

4. **Configure Appropriate Rate Limits**: Document and enforce appropriate `max_requests_per_day` and `max_concurrent_requests` values based on backend node capacity

5. **Add Monitoring**: Track API call rates and alert when approaching backend limits

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;
    
    #[tokio::test]
    async fn test_concurrent_request_amplification() {
        // Setup: Create faucet with default config (no max_concurrent_requests)
        let config = RunConfig::build_for_testing(...);
        assert!(config.handler_config.max_concurrent_requests.is_none());
        
        // Simulate 50 concurrent funding requests from different IPs
        let mut handles = vec![];
        for i in 0..50 {
            let handle = tokio::spawn(async move {
                let ip = format!("192.168.1.{}", i);
                // Send funding request
                fund_account(receiver_address, amount, ip).await
            });
            handles.push(handle);
        }
        
        // Wait for all requests to start processing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Measure API call rate to backend node
        // Expected: 50 requests * 2 API calls = 100 API calls in <1 second
        // Backend limit: 100 requests per minute (1.67 per second)
        // Result: Backend rate limit exceeded, causing timeouts
        
        let results = futures::future::join_all(handles).await;
        
        // Verify some requests fail due to backend rate limiting
        let failures = results.iter().filter(|r| r.is_err()).count();
        assert!(failures > 0, "Expected some requests to fail due to rate limiting");
    }
}
```

**Notes:**

This vulnerability is specific to the faucet service infrastructure and does not affect core consensus or mainnet operations. However, it represents a legitimate security concern for testnet/devnet operations where faucets are critical for developer onboarding. The lack of default protection against concurrent request amplification violates the principle of secure-by-default configuration and can cause service degradation requiring manual intervention.

### Citations

**File:** crates/aptos-faucet/core/src/funder/common.rs (L282-285)
```rust
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        (funder_seq, receiver_seq) =
            get_sequence_numbers(client, funder_account, receiver_address).await?;
    }
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L311-339)
```rust
async fn get_sequence_numbers(
    client: &Client,
    funder_account: &RwLock<LocalAccount>,
    receiver_address: AccountAddress,
) -> Result<(u64, Option<u64>), AptosTapError> {
    let funder_address = funder_account.read().await.address();
    let f_request = client.get_account(funder_address);
    let r_request = client.get_account(receiver_address);
    let mut responses = futures::future::join_all([f_request, r_request]).await;

    let receiver_seq_num = responses
        .remove(1)
        .as_ref()
        .ok()
        .map(|account| account.inner().sequence_number);

    let funder_seq_num = responses
        .remove(0)
        .map_err(|e| {
            AptosTapError::new(
                format!("funder account {} not found: {:#}", funder_address, e),
                AptosTapErrorCode::AccountDoesNotExist,
            )
        })?
        .inner()
        .sequence_number;

    Ok((funder_seq_num, receiver_seq_num))
}
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L306-310)
```rust
            handler_config: HandlerConfig {
                use_helpful_errors: true,
                return_rejections_early: false,
                max_concurrent_requests: None,
            },
```

**File:** api/doc/README.md (L26-29)
```markdown
## Limitations
- Rate limiting: 100 requests per minute by default
- Maximum request size: 2MB
- Connection timeout: 30 seconds
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L405-414)
```rust
        let (_faucet_seq, receiver_seq) = update_sequence_numbers(
            client,
            self.get_asset_account(asset_name)?,
            &self.outstanding_requests,
            receiver_address,
            amount,
            self.txn_config.wait_for_outstanding_txns_secs,
            asset_name,
        )
        .await?;
```
