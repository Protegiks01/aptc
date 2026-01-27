# Audit Report

## Title
Missing Chain ID Validation in Indexer GRPC Manager Allows Cross-Chain Data Poisoning via Fallback Path

## Summary
The `IndexerGrpcManagerConfig.allow_fn_fallback` flag enables direct fullnode queries when the cache is lagging, but the `DataManager` does not validate the `chain_id` field in `TransactionsFromNodeResponse` messages. This allows malicious or misconfigured fullnodes to inject transactions from different chains into the indexer cache and serve them directly to clients, corrupting the indexed data.

## Finding Description

The indexer-grpc-manager accepts a configuration flag `allow_fn_fallback` that enables fallback to fullnode queries when the local cache is lagging behind the network. [1](#0-0) 

The fullnode protocol defines `TransactionsFromNodeResponse` with a mandatory `chain_id` field to identify the source chain. [2](#0-1) 

Similarly, `FullnodeInfo` includes a `chain_id` field in ping responses. [3](#0-2) 

However, when the `DataManager` receives transactions from fullnodes in its background loop, it never validates the `chain_id` field: [4](#0-3) 

More critically, when `allow_fn_fallback` is enabled and the cache is lagging, the `get_transactions` method directly queries fullnodes and returns their transactions to clients without chain_id validation: [5](#0-4) 

The fullnode selection logic also never validates the `chain_id` from `FullnodeInfo` when handling ping responses: [6](#0-5) 

This stands in contrast to other indexer components. The cache-worker validates chain_id and panics on mismatches: [7](#0-6) 

The v2-file-store-backfiller also asserts chain_id correctness: [8](#0-7) 

**Attack Scenario:**
1. Attacker deploys a malicious fullnode on testnet (chain_id = 2) that serves valid testnet transactions
2. Attacker social engineers or exploits configuration management to add their fullnode address to `fullnode_addresses` in a mainnet (chain_id = 1) indexer-grpc-manager
3. When the cache lags (naturally or via DoS), `allow_fn_fallback` triggers direct fullnode queries
4. The malicious fullnode returns testnet transactions with `chain_id = 2`
5. DataManager accepts these transactions without validation and either:
   - Stores them in cache (background loop), poisoning all future reads
   - Returns them directly to clients (fallback path), serving wrong-chain data
6. Downstream indexers and applications receive corrupted cross-chain data

## Impact Explanation

**High Severity** - This vulnerability causes significant protocol violations:

- **Data Integrity Violation**: The indexer's fundamental invariant is broken - it must only serve data from its configured chain. Cross-chain data injection corrupts this guarantee.
  
- **Widespread Impact**: All downstream consumers (indexers, explorers, wallets, dApps) receive incorrect transaction data, potentially leading to incorrect state reconstruction and application logic errors.

- **Cache Poisoning**: Wrong-chain transactions persist in the cache and file store, requiring manual intervention to clean up.

- **Service Degradation**: When `allow_fn_fallback` is enabled (a performance optimization), the attack surface expands as lagging (a normal operational state) becomes exploitable.

This meets the **High Severity** criteria of "Significant protocol violations" per the Aptos bug bounty program. While it doesn't directly cause consensus violations or fund loss at the blockchain level, it corrupts the critical indexing infrastructure that applications rely on for chain data.

## Likelihood Explanation

**Medium-High Likelihood:**

- **Configuration Vulnerability**: Fullnode addresses are externally configured, creating opportunities for misconfiguration or social engineering attacks.

- **Natural Trigger Condition**: Cache lagging happens during normal high-load operations or network issues - no special attacker action needed to trigger the fallback path.

- **No Authentication**: Fullnodes are not authenticated beyond TCP/gRPC connection - any reachable endpoint can be configured.

- **Missing Defense-in-Depth**: While other indexer components validate chain_id, the manager (a critical aggregation point) does not, violating defense-in-depth principles.

The attack requires some level of configuration access, but this could occur through:
- Operator error (copying wrong configuration)
- Compromised deployment pipelines
- Social engineering of operators
- Supply chain attacks on configuration management

## Recommendation

Add chain_id validation at all points where the DataManager receives data from fullnodes:

**1. Validate FullnodeInfo during ping:**
```rust
fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
    // Add validation
    ensure!(
        info.chain_id == self.chain_id,
        "Chain ID mismatch: fullnode {} reports chain_id {}, expected {}",
        address, info.chain_id, self.chain_id
    );
    
    let mut entry = self.fullnodes.entry(address.clone())
        .or_insert(Fullnode::new(address.clone()));
    // ... rest of function
}
```

**2. Validate TransactionsFromNodeResponse in background loop:**
```rust
match response_item {
    Ok(r) => {
        // Add validation before processing
        ensure!(
            r.chain_id as u64 == self.chain_id,
            "Chain ID mismatch in transaction response: got {}, expected {}",
            r.chain_id, self.chain_id
        );
        
        if let Some(response) = r.response {
            // ... rest of match
        }
    },
    // ... rest of match
}
```

**3. Validate in get_transactions fallback path:**
```rust
while let Some(Ok(response_item)) = response.next().await {
    // Add validation
    ensure!(
        response_item.chain_id as u64 == self.chain_id,
        "Chain ID mismatch in fallback response: got {}, expected {}",
        response_item.chain_id, self.chain_id
    );
    
    if let Some(response) = response_item.response {
        // ... rest of match
    }
}
```

These changes align the manager with validation practices already present in the cache-worker and backfiller components.

## Proof of Concept

**Setup Requirements:**
1. Deploy two fullnode instances: one on mainnet (chain_id=1), one on testnet (chain_id=2)
2. Configure indexer-grpc-manager with `chain_id: 1`, `allow_fn_fallback: true`
3. Add the testnet fullnode address to `fullnode_addresses`

**Exploitation Steps:**

```rust
// Pseudo-code demonstration of the attack
#[tokio::test]
async fn test_cross_chain_data_injection() {
    // 1. Setup manager with mainnet chain_id
    let config = IndexerGrpcManagerConfig {
        chain_id: 1, // Mainnet
        allow_fn_fallback: true,
        fullnode_addresses: vec![
            "http://mainnet-fn:50051".to_string(),
            "http://testnet-fn:50051".to_string(), // Malicious/misconfigured
        ],
        // ... other config
    };
    
    let manager = GrpcManager::new(&config).await;
    
    // 2. Induce cache lagging to trigger fallback
    // (In practice, happens naturally under load)
    
    // 3. Query transactions
    let response = manager
        .get_data_manager()
        .get_transactions(start_version, max_size)
        .await
        .unwrap();
    
    // 4. Verify that testnet transactions (chain_id=2) were returned
    // without any validation error
    // Expected: Should have failed validation
    // Actual: Transactions accepted and served
    
    assert!(response.len() > 0);
    // These transactions are from chain_id=2 but served as chain_id=1 data
}
```

**Evidence of Vulnerability:**
The transactions will be served to clients despite originating from the wrong chain. This can be verified by:
1. Monitoring the fullnode selected via metrics
2. Checking transaction hashes against both chains
3. Observing version number inconsistencies between chains

The vulnerability is confirmed by the absence of any `chain_id` validation checks in the cited code paths.

## Notes

This vulnerability is particularly concerning because:

1. **Inconsistent Security Posture**: Other indexer components (cache-worker, backfiller) correctly validate chain_id, but the manager - which aggregates and serves data - does not.

2. **Attack Amplification**: A single misconfigured fullnode can poison data for all clients querying this manager instance.

3. **Feature Flag Risk**: The `allow_fn_fallback` flag, intended as a performance optimization, inadvertently expands the attack surface by creating direct client-to-fullnode data paths without validation.

4. **Defense-in-Depth Failure**: Chain ID validation should be present at every trust boundary. The manager receives data from external fullnodes (untrusted) but treats it as validated.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L41-41)
```rust
    pub(crate) allow_fn_fallback: bool,
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

**File:** protos/proto/aptos/indexer/v1/grpc.proto (L51-55)
```text
message FullnodeInfo {
  uint64 chain_id = 1;
  optional aptos.util.timestamp.Timestamp timestamp = 2;
  optional uint64 known_latest_version = 3;
}
```

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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L302-323)
```rust
                if self.lagging(cache_next_version) && self.allow_fn_fallback {
                    debug!("GrpcManager is lagging, getting data from FN, requested_version: {start_version}, cache_next_version: {cache_next_version}.");
                    let request = GetTransactionsFromNodeRequest {
                        starting_version: Some(start_version),
                        transactions_count: Some(5000),
                    };

                    let (_, mut fullnode_client) =
                        self.metadata_manager.get_fullnode_for_request(&request);
                    let response = fullnode_client.get_transactions_from_node(request).await?;
                    let mut response = response.into_inner();
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
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L533-550)
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
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L382-384)
```rust
        if received.chain_id as u64 != fullnode_chain_id as u64 {
            panic!("[Indexer Cache] Chain id mismatch happens during data streaming.");
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L176-176)
```rust
                                    assert!(r.chain_id == chain_id);
```
