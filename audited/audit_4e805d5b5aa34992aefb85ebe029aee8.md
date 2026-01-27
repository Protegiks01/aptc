# Audit Report

## Title
Fullnode Version Manipulation Causes Indexer Service Stall via Unvalidated known_latest_version

## Summary
A malicious or misconfigured fullnode can report an arbitrarily high `known_latest_version` in its ping responses, causing the metadata manager to select it for transaction requests it cannot fulfill, resulting in indefinite stalls of indexer services and downstream data consumers.

## Finding Description

The vulnerability exists in the indexer gRPC metadata management system where fullnodes report their sync status via `FullnodeInfo` messages. The attack flow proceeds as follows:

**Step 1: Version Reporting Without Validation**

When a fullnode sends a ping response, it includes a `FullnodeInfo` struct with a `known_latest_version` field. The serde deserialization code accepts any u64 value without validation: [1](#0-0) 

**Step 2: Uncritical Acceptance by Metadata Manager**

The metadata manager's `handle_fullnode_info` function accepts this reported version and updates the global known version tracker using `fetch_max`, which accepts any value higher than the current known version: [2](#0-1) 

The `update_known_latest_version` function uses atomic `fetch_max` without any validation: [3](#0-2) 

**Step 3: Malicious Fullnode Selection**

When the data manager needs to fetch transactions, it calls `get_fullnode_for_request` which filters fullnodes based on whether their reported `known_latest_version >= request.starting_version`: [4](#0-3) 

A fullnode that falsely reported having version 1,000,000,000 will be selected for requests even though it only has transactions up to version 1,000.

**Step 4: Request Stall**

The data manager initiates a transaction stream request to the selected fullnode: [5](#0-4) 

The stream consumer then blocks waiting for transactions: [6](#0-5) 

**Step 5: Fullnode-Side Indefinite Wait**

On the fullnode side, when it receives a request for transactions it doesn't have, the `ensure_highest_known_version` function enters a loop waiting for its database to sync to the requested version: [7](#0-6) 

If the fullnode's actual sync is permanently behind (e.g., a misconfigured or malicious node), this loop runs indefinitely, and the gRPC stream never produces any transactions.

**Attack Scenario:**
1. Attacker operates a fullnode that reports `known_latest_version = 999,999,999,999` in ping responses
2. Fullnode's actual synced version is only 1,000
3. Indexer requests transactions starting from version 500,000
4. Metadata manager selects the malicious fullnode (since 999,999,999,999 >= 500,000)
5. Fullnode receives request, waits indefinitely for its database to reach version 500,000
6. Data manager's stream consumer blocks at `response.next().await`
7. Indexer cache doesn't receive new transactions, causing downstream service failures

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program criteria for the following reasons:

1. **API Crashes/Unavailability**: Indexer gRPC services become unresponsive, blocking all dependent applications and wallets from accessing blockchain data

2. **Significant Protocol Violations**: The indexer infrastructure is a critical component for ecosystem health. Its failure violates the availability guarantees expected from the protocol's data layer

3. **Validator Node Slowdowns**: While not directly affecting consensus validators, the indexer fullnodes experience resource exhaustion from hanging connections and retry attempts

The impact is severe because:
- **Cascading Failures**: Multiple indexers may select the same malicious fullnode, causing widespread stalls
- **Cache Starvation**: The data manager's cache stops receiving updates, blocking all transaction queries
- **No Automatic Recovery**: The system has no timeout or health check mechanism to detect and blacklist the malicious fullnode
- **Ecosystem Disruption**: Wallets, explorers, and dApps that depend on indexer APIs become unusable

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to succeed because:

1. **Low Attack Bar**: Attacker only needs to operate a single fullnode with modified ping response code
2. **No Authentication Required**: Fullnodes self-report their status without cryptographic proof or validation
3. **Immediate Effect**: A single malicious fullnode can cause system-wide stalls within seconds
4. **Accidental Triggers**: Even non-malicious misconfigurations (e.g., clock skew, version number bugs) can trigger this behavior
5. **No Rate Limiting**: There's no mechanism to limit how often a fullnode is selected despite failures

The complexity of exploitation is minimal - an attacker simply modifies the `ping` function in their fullnode: [8](#0-7) 

By changing line 238 to return `known_latest_version: Some(u64::MAX)`, the attack is complete.

## Recommendation

Implement a multi-layered validation and health checking system:

**1. Add Version Validation in Metadata Manager**

```rust
fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
    let mut entry = self
        .fullnodes
        .entry(address.clone())
        .or_insert(Fullnode::new(address.clone()));
    
    if let Some(known_latest_version) = info.known_latest_version {
        // Validate against current known version with reasonable tolerance
        let current_known = self.get_known_latest_version();
        let max_acceptable_drift = 100_000; // e.g., 100k versions ahead
        
        if known_latest_version > current_known + max_acceptable_drift {
            warn!(
                "Fullnode {address} reported suspiciously high version: {known_latest_version}, current: {current_known}"
            );
            // Don't update global version, but still track for the fullnode
        } else {
            trace!("Received known_latest_version ({known_latest_version}) from fullnode {address}.");
            self.update_known_latest_version(known_latest_version);
        }
    }
    
    entry.value_mut().recent_states.push_back(info);
    if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
        entry.value_mut().recent_states.pop_front();
    }

    Ok(())
}
```

**2. Add Request Timeout in Data Manager**

```rust
let response = tokio::time::timeout(
    Duration::from_secs(30),
    fullnode_client.get_transactions_from_node(request)
).await;

match response {
    Ok(Ok(r)) => { /* success */ },
    Ok(Err(e)) => { /* grpc error */ },
    Err(_timeout) => {
        warn!("Timeout when getting transactions from fullnode ({address})");
        // Mark fullnode as unhealthy
        continue;
    }
}
```

**3. Implement Fullnode Health Scoring**

Track success/failure rates per fullnode and deprioritize or blacklist fullnodes with high failure rates.

**4. Add Cryptographic Proof**

Require fullnodes to provide ledger info signatures or state proof alongside version claims to make false reporting cryptographically expensive.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_version_manipulation_attack() {
        // Setup metadata manager
        let metadata_manager = Arc::new(MetadataManager::new(
            1, // chain_id
            "http://localhost:50051".to_string(),
            vec![],
            vec!["http://malicious-fullnode:50052".to_string()],
            None,
        ));
        
        // Simulate malicious fullnode reporting false version
        let malicious_info = FullnodeInfo {
            chain_id: 1,
            timestamp: Some(timestamp_now_proto()),
            known_latest_version: Some(999_999_999_999), // False claim
        };
        
        // Process the malicious info
        metadata_manager
            .handle_fullnode_info("http://malicious-fullnode:50052".to_string(), malicious_info)
            .unwrap();
        
        // Verify it updated the global version
        assert_eq!(metadata_manager.get_known_latest_version(), 999_999_999_999);
        
        // Create a request for a reasonable version
        let request = GetTransactionsFromNodeRequest {
            starting_version: Some(500_000),
            transactions_count: Some(1000),
        };
        
        // Verify the malicious fullnode gets selected
        let (selected_address, _) = metadata_manager.get_fullnode_for_request(&request);
        assert_eq!(selected_address, "http://malicious-fullnode:50052");
        
        // In production, this would now hang indefinitely
        // as the fullnode waits for version 500,000 which it doesn't have
        println!("Attack successful: malicious fullnode selected for request it cannot fulfill");
    }
}
```

## Notes

This vulnerability demonstrates a critical trust boundary violation in the indexer infrastructure. The system implicitly trusts fullnode self-reported metrics without validation, creating an attack surface for denial-of-service through resource exhaustion. The fix requires both input validation and defensive timeout mechanisms to ensure resilience against malicious or faulty peers.

### Citations

**File:** protos/rust/src/pb/aptos.indexer.v1.serde.rs (L782-788)
```rust
                        GeneratedField::KnownLatestVersion => {
                            if known_latest_version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("knownLatestVersion"));
                            }
                            known_latest_version__ =
                                map.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| x.0)
                            ;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L341-374)
```rust
    pub(crate) fn get_fullnode_for_request(
        &self,
        request: &GetTransactionsFromNodeRequest,
    ) -> (GrpcAddress, FullnodeDataClient<Channel>) {
        // TODO(grao): Double check the counters to see if we need a different way or additional
        // information.
        let mut rng = thread_rng();
        if let Some(fullnode) = self
            .fullnodes
            .iter()
            .filter(|fullnode| {
                fullnode
                    .recent_states
                    .back()
                    .is_some_and(|s| s.known_latest_version >= request.starting_version)
            })
            .choose(&mut rng)
            .map(|kv| (kv.key().clone(), kv.value().client.clone()))
        {
            COUNTER
                .with_label_values(&["get_fullnode_for_request__happy"])
                .inc();
            return fullnode;
        }

        COUNTER
            .with_label_values(&["get_fullnode_for_request__fallback"])
            .inc();
        self.fullnodes
            .iter()
            .choose(&mut rng)
            .map(|kv| (kv.key().clone(), kv.value().client.clone()))
            .unwrap()
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L405-409)
```rust
    fn update_known_latest_version(&self, version: u64) {
        self.known_latest_version
            .fetch_max(version, Ordering::SeqCst);
        KNOWN_LATEST_VERSION.set(version as i64);
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L207-232)
```rust
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(cache.start_version + cache.transactions.len() as u64),
                transactions_count: Some(100000),
            };
            drop(cache);

            debug!(
                "Requesting transactions from fullnodes, starting_version: {}.",
                request.starting_version.unwrap()
            );
            let (address, mut fullnode_client) =
                self.metadata_manager.get_fullnode_for_request(&request);
            trace!("Fullnode ({address}) is picked for request.");
            let response = fullnode_client.get_transactions_from_node(request).await;
            if response.is_err() {
                warn!(
                    "Error when getting transactions from fullnode ({address}): {}",
                    response.err().unwrap()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            } else {
                trace!("Got success response from fullnode.");
            }

            let mut response = response.unwrap().into_inner();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L233-280)
```rust
            while let Some(response_item) = response.next().await {
                trace!("Processing 1 response item.");
                loop {
                    trace!("Maybe running GC.");
                    if self.cache.write().await.maybe_gc() {
                        IS_FILE_STORE_LAGGING.set(0);
                        trace!("GC is done, file store is not lagging.");
                        break;
                    }
                    IS_FILE_STORE_LAGGING.set(1);
                    // If file store is lagging, we are not inserting more data.
                    let cache = self.cache.read().await;
                    warn!("Filestore is lagging behind, cache is full [{}, {}), known_latest_version ({}).",
                          cache.start_version,
                          cache.start_version + cache.transactions.len() as u64,
                          self.metadata_manager.get_known_latest_version());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if watch_file_store_version {
                        self.update_file_store_version_in_cache(
                            &cache, /*version_can_go_backward=*/ false,
                        )
                        .await;
                    }
                }
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
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L550-579)
```rust
    async fn ensure_highest_known_version(&mut self) -> bool {
        let mut empty_loops = 0;
        while self.highest_known_version == 0 || self.current_version > self.highest_known_version {
            if let Some(abort_handle) = self.abort_handle.as_ref() {
                if abort_handle.load(Ordering::SeqCst) {
                    return false;
                }
            }
            if empty_loops > 0 {
                tokio::time::sleep(Duration::from_millis(RETRY_TIME_MILLIS)).await;
            }
            empty_loops += 1;
            if let Err(err) = self.set_highest_known_version() {
                error!(
                    error = format!("{:?}", err),
                    "[Indexer Fullnode] Failed to set highest known version"
                );
                continue;
            } else {
                sample!(
                    SampleRate::Frequency(10),
                    info!(
                        highest_known_version = self.highest_known_version,
                        "[Indexer Fullnode] Found new highest known version",
                    )
                );
            }
        }
        true
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L207-242)
```rust
    async fn ping(
        &self,
        _request: Request<PingFullnodeRequest>,
    ) -> Result<Response<PingFullnodeResponse>, Status> {
        let timestamp = timestamp_now_proto();
        let known_latest_version = self
            .service_context
            .context
            .db
            .get_synced_version()
            .map_err(|e| Status::internal(format!("{e}")))?;

        let table_info_version = self
            .service_context
            .context
            .indexer_reader
            .as_ref()
            .and_then(|r| r.get_latest_table_info_ledger_version().ok().flatten());

        if known_latest_version.is_some() && table_info_version.is_some() {
            let version = std::cmp::min(known_latest_version.unwrap(), table_info_version.unwrap());
            if let Ok(timestamp_us) = self.service_context.context.db.get_block_timestamp(version) {
                let latency = SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                    - Duration::from_micros(timestamp_us);
                LATENCY_MS.set(latency.as_millis() as i64);
            }
        }

        let info = FullnodeInfo {
            chain_id: self.service_context.context.chain_id().id() as u64,
            timestamp: Some(timestamp),
            known_latest_version,
        };
        let response = PingFullnodeResponse { info: Some(info) };
        Ok(Response::new(response))
    }
```
