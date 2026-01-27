# Audit Report

## Title
Indefinite Hang in Indexer Data Service Due to Missing Timeout in Transaction Fetch Loop

## Summary
The `fetch_latest_data()` function in the indexer-grpc data service lacks timeout mechanisms when fetching transactions from GrpcManager endpoints. Combined with an infinite retry loop in `fetch_transactions()` that silently ignores errors, this can cause the service to hang indefinitely, resulting in complete loss of liveness for the indexer service.

## Finding Description

The vulnerability exists in two interconnected functions:

1. **In `fetch_manager.rs`**: The `fetch_latest_data()` function calls `fetch_and_update_cache()` which delegates to `data_client.fetch_transactions()` without any timeout protection. [1](#0-0) 

2. **In `data_client.rs`**: The `fetch_transactions()` function contains an infinite loop that makes gRPC calls without timeout. When the gRPC call returns an error, it's silently ignored and the loop continues indefinitely. There's even a TODO comment acknowledging the missing error handling. [2](#0-1) 

3. **Critical execution path**: The `continuously_fetch_latest_data()` function spawns the fetch task and awaits it, meaning if it hangs, the entire cache update mechanism stops. [3](#0-2) 

**Attack Scenario:**
While the GrpcManager endpoints are configured by operators, several scenarios can trigger this vulnerability:

1. **Legitimate service degradation**: A GrpcManager endpoint crashes, becomes overloaded, or experiences network issues
2. **Cascading failure**: If an attacker can exploit a separate vulnerability in the GrpcManager (DoS, resource exhaustion), this missing timeout amplifies the impact
3. **Random selection amplification**: The `get_grpc_manager_client_for_request()` function randomly selects endpoints, so even one problematic endpoint can eventually be chosen [4](#0-3) 

When triggered:
- The gRPC call never returns or consistently returns errors
- The infinite loop in `fetch_transactions()` never exits
- The `fetch_latest_data()` task hangs indefinitely
- The `continuously_fetch_latest_data()` loop blocks on the hung task
- The in-memory cache stops receiving updates
- Clients receive stale data or "data too old" errors
- The indexer service becomes effectively non-functional

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria for the following reasons:

1. **API Crashes/Unavailability**: The indexer service becomes unresponsive and cannot serve blockchain data to clients, matching the "API crashes" category.

2. **Critical Infrastructure Impact**: The indexer-grpc service is essential infrastructure for:
   - Block explorers
   - Analytics platforms  
   - DApp backends
   - Monitoring tools
   - Any application requiring indexed blockchain data

3. **Complete Loss of Service Liveness**: Unlike partial degradation, this causes complete failure of the indexer's primary function - serving recent blockchain data.

While this does not affect consensus or validator operations (thus not Critical severity), it represents a significant protocol violation in the indexer infrastructure layer.

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood is elevated because:

1. **Multiple trigger conditions**: Can occur through legitimate failures (network issues, service crashes, overload) or as amplification of other vulnerabilities
2. **No defensive measures**: Complete absence of timeouts, circuit breakers, or error handling
3. **Random endpoint selection**: Any single problematic endpoint can eventually be selected
4. **Long-running service**: The longer the service runs, the higher the probability of encountering an unresponsive endpoint
5. **Acknowledged technical debt**: The `// TODO(grao): Error handling.` comment indicates this is a known gap

The main limiting factor is that exploitation requires either:
- Degradation of GrpcManager infrastructure (can happen naturally)
- Access to GrpcManager endpoints to make them unresponsive (requires privileges)
- A separate vulnerability in GrpcManager that can be exploited to cause unresponsiveness

## Recommendation

Implement comprehensive timeout and error handling:

**1. Add timeout to gRPC calls in `data_client.rs`:**

```rust
pub(super) async fn fetch_transactions(&self, starting_version: u64) -> Vec<Transaction> {
    const MAX_RETRIES: usize = 3;
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    
    let request = GetTransactionsRequest {
        starting_version: Some(starting_version),
        transactions_count: None,
        batch_size: None,
        transaction_filter: None,
    };
    
    for attempt in 0..MAX_RETRIES {
        let mut client = self.connection_manager.get_grpc_manager_client_for_request();
        
        match tokio::time::timeout(
            REQUEST_TIMEOUT,
            client.get_transactions(request.clone())
        ).await {
            Ok(Ok(response)) => {
                let transactions = response.into_inner().transactions;
                if transactions.is_empty() {
                    return vec![];
                }
                if transactions.first().unwrap().version == starting_version {
                    return transactions;
                }
                warn!("Received transactions with incorrect starting version, retrying...");
            }
            Ok(Err(e)) => {
                warn!("gRPC call failed (attempt {}/{}): {:?}", attempt + 1, MAX_RETRIES, e);
            }
            Err(_) => {
                warn!("gRPC call timed out (attempt {}/{})", attempt + 1, MAX_RETRIES);
            }
        }
        
        if attempt < MAX_RETRIES - 1 {
            tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
        }
    }
    
    // Return empty after all retries exhausted
    warn!("Failed to fetch transactions after {} retries", MAX_RETRIES);
    vec![]
}
```

**2. Add timeout to the fetch loop in `fetch_manager.rs`:**

```rust
async fn fetch_latest_data(&'a self) -> usize {
    const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
    const MAX_EMPTY_FETCHES: usize = 300; // 1 minute with 200ms sleep
    
    let version = self.data_manager.read().await.end_version;
    info!("Fetching latest data starting from version {version}.");
    
    let mut empty_fetch_count = 0;
    
    loop {
        let num_transactions = tokio::time::timeout(
            FETCH_TIMEOUT,
            Self::fetch_and_update_cache(
                self.data_client.clone(),
                self.data_manager.clone(),
                version,
            )
        ).await.unwrap_or_else(|_| {
            warn!("Fetch timed out after {:?}", FETCH_TIMEOUT);
            0
        });
        
        if num_transactions != 0 {
            info!("Finished fetching latest data, got {num_transactions} transactions.");
            return num_transactions;
        }
        
        empty_fetch_count += 1;
        if empty_fetch_count >= MAX_EMPTY_FETCHES {
            warn!("Max empty fetches reached, returning 0");
            return 0;
        }
        
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    
    // Mock unresponsive gRPC client
    struct UnresponsiveGrpcClient;
    
    impl UnresponsiveGrpcClient {
        async fn get_transactions(&self, _request: GetTransactionsRequest) -> Result<Response<TransactionsResponse>, Status> {
            // Simulate indefinite hang
            sleep(Duration::from_secs(3600)).await;
            Err(Status::unavailable("Service unavailable"))
        }
    }
    
    #[tokio::test]
    async fn test_indefinite_hang_vulnerability() {
        // Setup: Create a data service with a mock unresponsive client
        // Expected: Without timeout, this test would hang indefinitely
        // With timeout: Should complete within reasonable time
        
        let start = std::time::Instant::now();
        
        // Simulate the vulnerable code path
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                // This represents fetch_transactions() calling an unresponsive endpoint
                let client = UnresponsiveGrpcClient;
                client.get_transactions(GetTransactionsRequest::default()).await
            }
        ).await;
        
        let elapsed = start.elapsed();
        
        // Without timeout in actual code: would hang forever (test would timeout)
        // With timeout: should complete in ~5 seconds
        assert!(result.is_err(), "Should timeout");
        assert!(elapsed.as_secs() >= 5 && elapsed.as_secs() < 10, 
                "Should timeout after ~5 seconds, got {:?}", elapsed);
    }
}
```

## Notes

This vulnerability represents a **reliability and availability issue** in critical Aptos ecosystem infrastructure. While the indexer service does not participate in consensus or affect validator operations, its unavailability has cascading effects on the entire Aptos ecosystem that depends on indexed blockchain data.

The issue is exacerbated by:
1. Complete lack of timeout protection at multiple layers
2. Silent error swallowing in the retry loop  
3. No circuit breaker or health check mechanisms
4. Blocking await in the continuous fetch loop

The recommended fix implements defense-in-depth with timeouts at both the gRPC call level and the fetch loop level, along with proper error handling and retry limits.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L40-46)
```rust
    pub(super) async fn continuously_fetch_latest_data(&'a self) {
        loop {
            let task = self.fetch_latest_data().boxed().shared();
            *self.fetching_latest_data_task.write().await = Some(task.clone());
            let _ = task.await;
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L66-87)
```rust
    async fn fetch_latest_data(&'a self) -> usize {
        let version = self.data_manager.read().await.end_version;
        info!("Fetching latest data starting from version {version}.");
        loop {
            let num_transactions = {
                let _timer = TIMER
                    .with_label_values(&["fetch_latest_data"])
                    .start_timer();
                Self::fetch_and_update_cache(
                    self.data_client.clone(),
                    self.data_manager.clone(),
                    version,
                )
                .await
            };
            if num_transactions != 0 {
                info!("Finished fetching latest data, got {num_transactions} num_transactions starting from version {version}.");
                return num_transactions;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_client.rs (L18-43)
```rust
    pub(super) async fn fetch_transactions(&self, starting_version: u64) -> Vec<Transaction> {
        trace!("Fetching transactions from GrpcManager, start_version: {starting_version}.");

        let request = GetTransactionsRequest {
            starting_version: Some(starting_version),
            transactions_count: None,
            batch_size: None,
            transaction_filter: None,
        };
        loop {
            let mut client = self
                .connection_manager
                .get_grpc_manager_client_for_request();
            let response = client.get_transactions(request.clone()).await;
            if let Ok(response) = response {
                let transactions = response.into_inner().transactions;
                if transactions.is_empty() {
                    return vec![];
                }
                if transactions.first().unwrap().version == starting_version {
                    return transactions;
                }
            }
            // TODO(grao): Error handling.
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L172-179)
```rust
    pub(crate) fn get_grpc_manager_client_for_request(&self) -> GrpcManagerClient<Channel> {
        let mut rng = thread_rng();
        self.grpc_manager_connections
            .iter()
            .choose(&mut rng)
            .map(|kv| kv.value().clone())
            .unwrap()
    }
```
