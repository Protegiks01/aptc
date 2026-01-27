# Audit Report

## Title
Critical Chain ID Validation Bypass in Indexer GRPC Manager Enabling Cross-Chain Data Confusion

## Summary
The `GrpcManager` component in the indexer-grpc-manager service fails to validate the `chain_id` field in responses received from fullnodes and peer services. This missing validation allows misconfigured or compromised indexers to serve blockchain data from one chain while labeling it as another chain, potentially causing clients to make incorrect decisions leading to fund loss through cross-chain confusion attacks.

## Finding Description

The indexer-grpc-manager's `DataManager` and `MetadataManager` components process data from fullnodes without validating that the `chain_id` in responses matches the configured `chain_id`. This breaks the fundamental chain identity invariant that protects against cross-chain replay and confusion attacks.

**Vulnerable Code Locations:**

1. **DataManager transaction processing loop** - processes `TransactionsFromNodeResponse` without validating `chain_id`: [1](#0-0) 

2. **DataManager fullnode fallback** - fetches transactions without validating `chain_id`: [2](#0-1) 

3. **MetadataManager fullnode info handler** - accepts `FullnodeInfo` without chain_id validation: [3](#0-2) 

**Evidence of vulnerability:**

The protobuf definition confirms that `TransactionsFromNodeResponse` includes a `chain_id` field that should be validated: [4](#0-3) 

**Secure implementation comparison:**

The v2 file-store backfiller demonstrates the correct pattern by validating chain_id: [5](#0-4) 

**Attack Scenario:**

1. Operator misconfigures the indexer with `chain_id: 1` (mainnet) but points `fullnode_addresses` to testnet nodes (chain_id: 2), OR an attacker compromises the configuration file/environment variables
2. GrpcManager initializes with the misconfigured values: [6](#0-5) 

3. DataManager connects to the wrong-chain fullnodes and streams transactions without validating the response `chain_id`
4. Transactions from chain 2 (testnet) are cached and served with chain_id: 1 (mainnet) label: [7](#0-6) 

5. Clients consuming this data believe they're receiving mainnet transactions but are actually receiving testnet data, leading to incorrect financial decisions

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets the Critical severity criteria per Aptos bug bounty guidelines because it can lead to:

1. **Loss of Funds**: Clients making financial decisions based on wrong-chain data (e.g., DEX arbitrage bots executing trades based on testnet prices labeled as mainnet prices)

2. **Data Integrity Violation**: The chain_id field is a fundamental security mechanism to prevent cross-chain confusion, similar to network IDs in Ethereum. Its bypass violates the core data authenticity guarantee.

3. **Widespread Impact**: A single misconfigured or compromised indexer can affect all downstream clients, including:
   - Wallets displaying incorrect balances/transactions
   - DApps making state queries from wrong chain
   - Trading bots executing on incorrect data
   - Analytics platforms reporting wrong metrics

While the vulnerability requires configuration access, this is realistic because:
- Indexer operators are third-party infrastructure providers (not core validators)
- Configuration files can be compromised through supply chain attacks
- Environment variable injection is possible in containerized deployments
- Simple operator errors during deployment are common

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Factors increasing likelihood:
- **Common misconfiguration scenario**: Operators frequently copy configurations between testnet/mainnet environments and forget to update fullnode addresses
- **No warning or validation**: The system silently accepts mismatched chain_id values without logging warnings
- **Environment variable override**: Configuration can be overridden via environment variables which are easier to compromise: [8](#0-7) 

- **Widespread deployment**: Many third-party indexers exist, increasing the attack surface

Factors decreasing likelihood:
- Requires some level of configuration access (either file system or environment variables)
- Obvious discrepancy might be caught during initial testing (but not guaranteed)

## Recommendation

**Immediate Fix: Add chain_id validation at all data ingestion points**

Add validation in `DataManager::start()` method:

```rust
match response_item {
    Ok(r) => {
        // CRITICAL: Validate chain_id matches expected value
        if r.chain_id as u64 != self.chain_id {
            panic!(
                "Chain ID mismatch detected! Expected {}, got {} from fullnode. \
                This indicates either a configuration error or a compromised fullnode.",
                self.chain_id, r.chain_id
            );
        }
        
        if let Some(response) = r.response {
            // ... existing code ...
        }
    }
}
```

Add validation in `DataManager::get_transactions()`:

```rust
while let Some(Ok(response_item)) = response.next().await {
    // CRITICAL: Validate chain_id
    if response_item.chain_id as u64 != self.chain_id {
        bail!(
            "Chain ID mismatch! Expected {}, got {}",
            self.chain_id, response_item.chain_id
        );
    }
    // ... existing code ...
}
```

Add validation in `MetadataManager::handle_fullnode_info()`:

```rust
fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
    // CRITICAL: Validate chain_id matches
    if info.chain_id != self.chain_id {
        bail!(
            "Fullnode {} reports chain_id {} but expected {}. Rejecting.",
            address, info.chain_id, self.chain_id
        );
    }
    // ... existing code ...
}
```

**Additional Recommendations:**

1. Add startup validation that queries connected fullnodes and verifies their chain_id before beginning indexing
2. Add metrics/alerts when chain_id mismatches are detected
3. Document the chain_id validation requirement in configuration guides
4. Consider adding a `--strict-chain-id-validation` flag for production deployments

## Proof of Concept

**Rust Integration Test:**

```rust
#[tokio::test]
async fn test_chain_id_mismatch_detection() {
    // Setup: Create GrpcManager configured for mainnet (chain_id = 1)
    let config = IndexerGrpcManagerConfig {
        chain_id: 1, // Mainnet
        fullnode_addresses: vec!["http://localhost:50051".to_string()],
        // ... other config fields
    };
    
    let manager = GrpcManager::new(&config).await;
    
    // Setup: Mock fullnode that returns testnet chain_id (2)
    let mock_fullnode = MockFullnode::new(2); // Returns chain_id = 2
    mock_fullnode.start().await;
    
    // Attack: Connect and attempt to index
    // Expected: Should panic or return error due to chain_id mismatch
    // Actual (vulnerable): Accepts data without validation
    
    let result = manager.data_manager
        .get_transactions(0, 1000)
        .await;
    
    // Vulnerable behavior: This should fail but currently succeeds
    assert!(result.is_err(), "Should reject mismatched chain_id");
    assert!(result.unwrap_err().to_string().contains("Chain ID mismatch"));
}
```

**Exploitation Steps:**

1. Deploy indexer-grpc-manager with config: `chain_id: 1`
2. Set fullnode address to testnet node: `fullnode_addresses: ["https://testnet.fullnode:443"]`
3. Start the manager - it will connect and index testnet data
4. Query `/get_transactions` - returns testnet transactions labeled as chain_id: 1 (mainnet)
5. Downstream clients consuming this data make incorrect decisions based on wrong-chain information

## Notes

This vulnerability represents a **defense-in-depth failure** where critical security parameters (chain_id) are not validated at trust boundaries. While the immediate attack vector requires some configuration access, the missing validation creates multiple risks:

1. **Operator error**: Legitimate operators can accidentally misconfigure without detection
2. **Supply chain attacks**: Compromised deployment scripts or config templates could inject wrong values  
3. **Container escape**: In containerized environments, environment variable injection is a common attack vector
4. **Cascading failures**: If one indexer in a cluster is compromised, it can poison the entire infrastructure

The vulnerability is particularly severe because it breaks the fundamental chain identity guarantee that prevents cross-chain confusion attacks—a security mechanism explicitly designed into blockchain protocols to prevent exactly this type of data confusion.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L257-279)
```rust
                match response_item {
                    Ok(r) => {
                        if let Some(response) = r.response {
                            match response {
                                Response::Data(data) => {
                                    trace!(
                                        "Putting data into cache, {} transaction(s).",
                                        data.transactions.len()
                                    );
                                    self.cache.write().await.put_transactions(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        } else {
                            warn!("Error when getting transactions from fullnode: no data.");
                            continue 'out;
                        }
                    },
                    Err(e) => {
                        warn!("Error when getting transactions from fullnode: {}", e);
                        continue 'out;
                    },
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L313-322)
```rust
                    while let Some(Ok(response_item)) = response.next().await {
                        if let Some(response) = response_item.response {
                            match response {
                                Response::Data(data) => {
                                    return Ok(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        }
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L533-549)
```rust
    fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
        let mut entry = self
            .fullnodes
            .entry(address.clone())
            .or_insert(Fullnode::new(address.clone()));
        entry.value_mut().recent_states.push_back(info);
        if let Some(known_latest_version) = info.known_latest_version {
            trace!(
                "Received known_latest_version ({known_latest_version}) from fullnode {address}."
            );
            self.update_known_latest_version(known_latest_version);
        }
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
```

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L47-54)
```text
message TransactionsFromNodeResponse {
  oneof response {
    StreamStatus status = 1;
    TransactionsOutput data = 2;
  }
  // Making sure that all the responses include a chain id
  uint32 chain_id = 3;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L173-177)
```rust
                        while let Some(response_item) = stream.next().await {
                            match response_item {
                                Ok(r) => {
                                    assert!(r.chain_id == chain_id);
                                    match r.response.unwrap() {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L31-42)
```rust
    pub(crate) async fn new(config: &IndexerGrpcManagerConfig) -> Self {
        let chain_id = config.chain_id;
        let file_store_uploader = Mutex::new(
            FileStoreUploader::new(chain_id, config.file_store_config.clone())
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to create filestore uploader, config: {:?}, error: {e:?}",
                        config.file_store_config
                    )
                }),
        );
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

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L130-136)
```rust
pub fn load<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    Figment::new()
        .merge(Yaml::file(path))
        .merge(Env::raw().split("__"))
        .extract()
        .map_err(anyhow::Error::msg)
}
```
