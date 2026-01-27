# Audit Report

## Title
Missing Chain ID Validation in Indexer Data Service Allows Cross-Chain Transaction Indexing

## Summary
The `fetch_transactions()` function in the indexer gRPC data service v2 does not validate the `chain_id` field in responses from the gRPC manager. This allows transactions from a different blockchain (e.g., testnet vs mainnet) or a compromised gRPC manager to be indexed without detection, violating data integrity guarantees.

## Finding Description

The `fetch_transactions()` function receives a `TransactionsResponse` from the gRPC manager that includes both transactions and a `chain_id` field. However, the implementation only validates the transaction version number and completely ignores the chain_id. [1](#0-0) 

The code extracts only the transactions from the response and validates only that the first transaction's version matches the requested version. The `chain_id` field present in the `TransactionsResponse` protobuf message is never checked. [2](#0-1) 

The `TransactionsResponse` structure includes a required `chain_id` field, which is properly populated by the gRPC manager: [3](#0-2) 

The ConnectionManager stores the expected chain_id: [4](#0-3) 

However, this chain_id is never used to validate responses in `fetch_transactions()`.

**Evidence this validation is required:** Other components in the indexer system implement strict chain_id validation:

1. The cache worker panics on chain_id mismatch: [5](#0-4) 

2. The indexer tailer validates chain_id before proceeding: [6](#0-5) 

**Attack Scenarios:**

1. **Malicious gRPC Manager**: An attacker who controls or compromises a gRPC manager instance can configure it with a different chain_id (e.g., testnet) while the data service expects mainnet. The data service will index testnet transactions as mainnet without any error.

2. **Configuration Error**: A misconfigured gRPC manager pointing to the wrong chain will have its transactions silently indexed into the wrong indexer database.

3. **During Reorg/Fork Events**: If a gRPC manager temporarily serves from a non-canonical chain source, those transactions would be indexed without validation.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria:
- **"State inconsistencies requiring intervention"** - The indexer database becomes corrupted with transactions from the wrong chain, requiring manual cleanup and reindexing.

The impact includes:
- **Data Integrity Violation**: The indexer's fundamental guarantee is broken - it should only contain transactions from its configured chain.
- **Downstream Corruption**: All applications, analytics tools, and services consuming data from this indexer receive incorrect transaction data.
- **Silent Failure**: No error is raised, making the corruption difficult to detect until downstream consumers notice inconsistencies.
- **Persistent Corruption**: Once wrong transactions are indexed, they persist in the database and continue to be served to clients.

While this doesn't directly affect on-chain consensus or validator operations, it undermines the reliability of the entire indexer infrastructure that many dApps and tools depend on.

## Likelihood Explanation

**Medium to High Likelihood:**

1. **Configuration Errors**: Operators managing multiple networks (mainnet, testnet, devnet) could accidentally misconfigure a gRPC manager connection.

2. **Compromised Infrastructure**: If an attacker gains access to a gRPC manager instance, they can serve arbitrary transactions.

3. **No Defense in Depth**: The missing validation means there's no safety net when gRPC managers misbehave or are misconfigured.

4. **Existing Code Patterns**: The fact that other indexer components (cache worker, tailer) implement this validation proves it's a recognized requirement, making the omission in data_client.rs a clear oversight.

## Recommendation

Add chain_id validation in the `fetch_transactions()` function before accepting transactions. The fix should:

1. Access the ConnectionManager's stored chain_id
2. Validate that the response's chain_id matches the expected value
3. Return an error or retry with a different gRPC manager if there's a mismatch

**Recommended Fix:**

```rust
pub(super) async fn fetch_transactions(&self, starting_version: u64) -> Vec<Transaction> {
    let expected_chain_id = self.connection_manager.chain_id();
    
    loop {
        let mut client = self
            .connection_manager
            .get_grpc_manager_client_for_request();
        let response = client.get_transactions(request.clone()).await;
        if let Ok(response) = response {
            let response_inner = response.into_inner();
            
            // Validate chain_id matches expected value
            if let Some(response_chain_id) = response_inner.chain_id {
                if response_chain_id != expected_chain_id {
                    // Log error and retry with different manager
                    warn!(
                        "Chain ID mismatch: expected {}, got {}",
                        expected_chain_id, response_chain_id
                    );
                    continue;
                }
            } else {
                // Log warning if chain_id is missing
                warn!("Response missing chain_id field");
                continue;
            }
            
            let transactions = response_inner.transactions;
            if transactions.is_empty() {
                return vec![];
            }
            if transactions.first().unwrap().version == starting_version {
                return transactions;
            }
        }
    }
}
```

Additionally, make the ConnectionManager's `chain_id()` method public if it isn't already: [7](#0-6) 

## Proof of Concept

**Rust Unit Test Demonstrating the Vulnerability:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::transaction::v1::Transaction;
    
    #[tokio::test]
    async fn test_missing_chain_id_validation() {
        // Setup: Create a mock gRPC manager that returns transactions with wrong chain_id
        // Expected chain_id: 1 (mainnet)
        let expected_chain_id = 1u64;
        
        // Create a data client connected to connection manager expecting chain_id = 1
        // ... setup code ...
        
        // Attacker's gRPC manager returns transactions with chain_id = 2 (testnet)
        let malicious_response = TransactionsResponse {
            transactions: vec![/* testnet transaction */],
            chain_id: Some(2), // Wrong chain!
            processed_range: None,
        };
        
        // Call fetch_transactions
        let result = data_client.fetch_transactions(0).await;
        
        // VULNERABILITY: The function accepts transactions from wrong chain
        // Expected behavior: Should reject or error
        // Actual behavior: Returns the wrong transactions without validation
        assert!(!result.is_empty()); // Wrong transactions are accepted!
    }
}
```

**Steps to Reproduce in Real System:**

1. Deploy an indexer data service v2 configured for mainnet (chain_id = 1)
2. Setup a malicious gRPC manager configured with testnet data (chain_id = 2)
3. Configure the data service to connect to the malicious gRPC manager
4. Observe that the data service indexes testnet transactions without any error
5. Query the indexed data - it will contain testnet transactions labeled as mainnet

**Notes**

This vulnerability represents a missing defensive check that other components in the same indexer system correctly implement. The severity is Medium because while it doesn't directly impact consensus or on-chain operations, it can cause significant data integrity issues requiring manual intervention to resolve. The fix is straightforward and follows the established pattern used elsewhere in the codebase.

### Citations

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

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L40-49)
```text
// TransactionsResponse is a batch of transactions.
message TransactionsResponse {
  // Required; transactions data.
  repeated aptos.transaction.v1.Transaction transactions = 1;

  // Required; chain id.
  optional uint64 chain_id = 2 [jstype = JS_STRING];

  optional ProcessedRange processed_range = 3;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L129-146)
```rust
    async fn get_transactions(
        &self,
        request: Request<GetTransactionsRequest>,
    ) -> Result<Response<TransactionsResponse>, Status> {
        let request = request.into_inner();
        let transactions = self
            .data_manager
            .get_transactions(request.starting_version(), MAX_SIZE_BYTES_FROM_CACHE)
            .await
            .map_err(|e| Status::internal(format!("{e}")))?;

        Ok(Response::new(TransactionsResponse {
            transactions,
            chain_id: Some(self.chain_id),
            // Not used.
            processed_range: None,
        }))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L101-108)
```rust
pub(crate) struct ConnectionManager {
    chain_id: u64,
    grpc_manager_connections: DashMap<String, GrpcManagerClient<Channel>>,
    self_advertised_address: String,
    known_latest_version: AtomicU64,
    active_streams: DashMap<String, (ActiveStream, StreamProgressSamples)>,
    is_live_data_service: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L168-170)
```rust
    pub(crate) fn chain_id(&self) -> u64 {
        self.chain_id
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L382-384)
```rust
        if received.chain_id as u64 != fullnode_chain_id as u64 {
            panic!("[Indexer Cache] Chain id mismatch happens during data streaming.");
        }
```

**File:** crates/indexer/src/indexer/tailer.rs (L82-90)
```rust
        match maybe_existing_chain_id {
            Some(chain_id) => {
                ensure!(chain_id == new_chain_id, "Wrong chain detected! Trying to index chain {} now but existing data is for chain {}", new_chain_id, chain_id);
                info!(
                    processor_name = self.processor.name(),
                    chain_id = chain_id,
                    "Chain id matches! Continue to index...",
                );
                Ok(chain_id as u64)
```
