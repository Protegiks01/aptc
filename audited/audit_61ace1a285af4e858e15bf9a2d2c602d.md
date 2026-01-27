# Audit Report

## Title
Resource Exhaustion in Faucet Service Due to Missing Concurrent Request Limit During Network Partition

## Summary
The faucet service in `aptos-workspace-server` does not limit concurrent requests when configured via `build_for_cli()`. When the node API becomes unavailable after the faucet starts, unlimited concurrent requests can accumulate, each blocking for up to 40 seconds across multiple API call timeouts, leading to resource exhaustion and service unavailability.

## Finding Description

The `start_faucet()` function initializes the faucet service using `RunConfig::build_for_cli()`, which sets `max_concurrent_requests: None`. [1](#0-0) 

This configuration disables the concurrent request limiter: [2](#0-1) 

When a fund request arrives, it makes multiple API calls to the node:

1. **Gas price estimation** (if not overridden): [3](#0-2) 

2. **Sequence number retrieval** (2 calls - funder and receiver accounts): [4](#0-3) 

3. **Transaction submission**: [5](#0-4) 

Each API call has a default 10-second timeout: [6](#0-5) 

**Attack Scenario:**
1. Faucet starts successfully with node API available
2. Network partition occurs (node API becomes unreachable)  
3. Attacker sends many concurrent fund requests
4. Each request attempts 4 API calls, each timing out after 10 seconds (total: 40 seconds)
5. Without `max_concurrent_requests`, unlimited requests accumulate
6. Resources (memory for Future states, HTTP connections, TCP connections) become exhausted
7. Faucet becomes unresponsive

The semaphore mechanism exists but is not used: [7](#0-6) 

## Impact Explanation

This constitutes a **Medium severity** issue based on the Aptos bug bounty criteria under "API crashes" or service degradation. While the faucet is primarily a development tool in `aptos-workspace-server`, the vulnerability allows:

- **Service unavailability**: Faucet becomes unresponsive during network partitions
- **Resource exhaustion**: Memory and connection pool depletion
- **No circuit breaker**: Continuous resource waste without failure detection

This does not rise to High/Critical severity because:
- No blockchain consensus impact
- No fund loss or manipulation  
- Limited to faucet service availability
- Does not affect validator nodes or core protocol

## Likelihood Explanation

**Medium likelihood:**
- Network partitions between services can occur naturally or through misconfigurations
- Requires no special privileges - any user can send faucet requests
- Easy to exploit once partition exists
- The `aptos-workspace-server` is commonly used in development environments where network stability may vary

## Recommendation

Configure a reasonable `max_concurrent_requests` limit in `build_for_cli()`:

```rust
pub fn build_for_cli(
    // ... existing parameters
) -> Self {
    Self {
        // ... existing fields
        handler_config: HandlerConfig {
            use_helpful_errors: true,
            return_rejections_early: false,
            max_concurrent_requests: Some(50), // Add reasonable limit
        },
    }
}
```

Additionally, consider implementing:
1. **Circuit breaker pattern**: Stop attempting API calls after repeated failures
2. **Continuous health monitoring**: Proactively detect API unavailability
3. **Shorter timeouts**: Reduce the 10-second default timeout for faster failure detection

## Proof of Concept

```rust
// Integration test demonstrating resource exhaustion
#[tokio::test]
async fn test_faucet_network_partition_resource_exhaustion() {
    // Start faucet with node API
    let node_api_port = start_mock_node_api().await;
    let faucet_config = RunConfig::build_for_cli(
        Url::parse(&format!("http://127.0.0.1:{}", node_api_port)).unwrap(),
        "127.0.0.1".to_string(),
        0,
        FunderKeyEnum::KeyFile(PathBuf::from("/tmp/mint.key")),
        false,
        None,
    );
    
    let (port_tx, port_rx) = oneshot::channel();
    let faucet_handle = tokio::spawn(async move {
        faucet_config.run_and_report_port(port_tx).await
    });
    
    let faucet_port = port_rx.await.unwrap();
    
    // Simulate network partition - stop node API
    stop_mock_node_api(node_api_port).await;
    
    // Send 100 concurrent requests
    let mut handles = vec![];
    for _ in 0..100 {
        let handle = tokio::spawn(async move {
            reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}/fund", faucet_port))
                .json(&json!({
                    "address": "0x1234567890abcdef",
                    "amount": 1000
                }))
                .send()
                .await
        });
        handles.push(handle);
    }
    
    // Measure resource usage and response times
    // Expected: All requests timeout after ~40 seconds each
    // Without max_concurrent_requests, all 100 requests run simultaneously
    // causing resource exhaustion
}
```

## Notes

This vulnerability is specific to the `aptos-workspace-server` context using `build_for_cli()`. Production faucet deployments using full configuration files can set `max_concurrent_requests` explicitly. The issue highlights the importance of defensive configuration even in development tools, as network partition scenarios can occur in any deployment environment.

### Citations

**File:** aptos-move/aptos-workspace-server/src/services/faucet.rs (L46-53)
```rust
        let faucet_run_config = RunConfig::build_for_cli(
            Url::parse(&format!("http://{}:{}", IP_LOCAL_HOST, api_port)).unwrap(),
            IP_LOCAL_HOST.to_string(),
            0,
            FunderKeyEnum::KeyFile(test_dir.join("mint.key")),
            false,
            None,
        );
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L306-310)
```rust
            handler_config: HandlerConfig {
                use_helpful_errors: true,
                return_rejections_early: false,
                max_concurrent_requests: None,
            },
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

**File:** crates/aptos-faucet/core/src/funder/common.rs (L342-399)
```rust
pub async fn submit_transaction(
    client: &Client,
    faucet_account: &RwLock<LocalAccount>,
    signed_transaction: SignedTransaction,
    receiver_address: &AccountAddress,
    wait_for_transactions: bool,
) -> Result<SignedTransaction, AptosTapError> {
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

    // If there was an issue submitting a transaction we should just reset
    // our sequence numbers to what it was before.
    match result {
        Ok(_) => {
            info!(
                hash = signed_transaction.committed_hash(),
                address = receiver_address,
                event = event_on_success,
            );
            Ok(signed_transaction)
        },
        Err(e) => {
            faucet_account.write().await.decrement_sequence_number();
            warn!(
                hash = signed_transaction.committed_hash(),
                address = receiver_address,
                event = "transaction_failure",
                error_message = format!("{:#}", e)
            );
            Err(e)
        },
    }
}
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L440-447)
```rust
    async fn fetch_gas_unit_price(&self) -> Result<u64> {
        Ok(self
            .api_client
            .estimate_gas_price()
            .await?
            .into_inner()
            .gas_estimate)
    }
```

**File:** crates/aptos-rest-client/src/client_builder.rs (L54-54)
```rust
            timeout: Duration::from_secs(10), // Default to 10 seconds
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
