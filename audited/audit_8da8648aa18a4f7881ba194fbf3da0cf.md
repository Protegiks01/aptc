# Audit Report

## Title
Indexer Data Service Lacks Fork Choice Logic Leading to Mixed-Fork Transaction Indexing

## Summary
The `fetch_transactions()` function in the indexer-grpc data service randomly selects data sources without validating consensus state, allowing transactions from minority forks to be indexed alongside canonical chain transactions during network partitions or temporary forks.

## Finding Description

The indexer-grpc-data-service-v2 fetches blockchain transactions to serve to external applications. When configured with multiple GrpcManagers (which in turn connect to multiple fullnodes), the system randomly selects sources without any fork choice validation. [1](#0-0) 

The `fetch_transactions()` function only validates that the first transaction's version matches the requested version, with no validation of epoch, block_height, or chain continuity. [2](#0-1) 

The ConnectionManager randomly selects a GrpcManager using `thread_rng()` without considering which fork it's serving data from. [3](#0-2) 

The MetadataManager similarly randomly selects fullnodes based only on whether they claim to have the requested version. [4](#0-3) 

Each Transaction contains `epoch` and `block_height` fields that could be used for fork detection, but these are never validated for consistency across batches from different sources.

**Attack Scenario:**
1. Indexer configured with 2 fullnodes: Fullnode A (canonical chain) and Fullnode B (temporarily on minority fork due to network partition)
2. Indexer fetches transactions 1000-1999 from Fullnode A
3. Indexer randomly fetches transactions 2000-2999 from Fullnode B (minority fork)
4. No validation detects the epoch/block_height discontinuity
5. Applications querying the indexer receive mixed transactions from both forks
6. State inconsistencies persist until cache eviction

## Impact Explanation

This is a **High Severity** issue per Aptos bug bounty criteria as it constitutes a "significant protocol violation." While it doesn't directly affect consensus safety of the blockchain itself, it breaks the fundamental guarantee that indexers serve canonical chain data.

**Impacts:**
- **Data Integrity Violation**: Applications relying on indexed data receive inconsistent blockchain state
- **Protocol Violation**: The indexer serves transactions that may never be finalized on the canonical chain
- **Persistent Inconsistency**: Wrong data remains cached and served to clients until eviction
- **Silent Failure**: No alerts or errors indicate the fork mixing

This does NOT meet Critical severity because it doesn't steal funds, break main chain consensus, or cause network partition.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability can occur without any malicious actors during normal network conditions:

1. **Network Partitions**: During temporary network splits, different fullnodes may briefly be on different forks
2. **State Sync Delays**: Fullnodes catching up may temporarily serve different chain tips
3. **Multiple Data Centers**: Geographically distributed fullnodes may have propagation delays
4. **Common Configuration**: Production indexers typically connect to multiple fullnodes for redundancy

The vulnerability triggers whenever:
- Multiple data sources are configured (common)
- Sources temporarily diverge (happens during normal operation)
- Random selection picks different sources for consecutive batches (statistically frequent)

## Recommendation

Implement fork choice validation by tracking and validating consensus metadata across transaction batches:

**Fix Implementation:**
1. **Add Consensus State Tracking**: Maintain expected epoch and block_height
2. **Validate Epoch Continuity**: Ensure epochs only increase monotonically
3. **Validate Block Height**: Verify block heights follow expected sequence
4. **Prefer Highest Epoch Source**: When multiple sources available, select the one on the highest epoch
5. **Add Chain Continuity Checks**: Validate timestamp ordering and transaction version continuity

**Code Changes Required:**

In `data_client.rs`, add validation:
```rust
// After receiving transactions, validate consensus state
if !self.validate_consensus_continuity(&transactions, previous_epoch, previous_block_height) {
    continue; // Retry with different source
}
```

In `connection_manager.rs`, replace random selection with consensus-aware selection:
```rust
// Select GrpcManager with highest known_latest_version on highest epoch
pub(crate) fn get_grpc_manager_client_for_consensus(&self) -> GrpcManagerClient<Channel>
```

Add epoch/block_height validation in `data_manager.rs` when storing transactions:
```rust
// Verify epoch and block_height consistency before updating cache
if !self.verify_fork_consistency(&transactions) {
    return; // Reject potentially forked data
}
```

## Proof of Concept

**Reproduction Steps:**

1. Set up indexer-grpc-data-service-v2 with configuration pointing to two GrpcManagers:
   ```
   grpc_manager_addresses = ["http://fullnode-a:50051", "http://fullnode-b:50051"]
   ```

2. Simulate network partition where fullnode-b temporarily forks:
   - Use network rules to delay consensus messages to fullnode-b
   - Wait for fullnode-b to diverge by creating its own block at same height
   - fullnode-a continues on canonical chain
   - fullnode-b is on minority fork (will eventually revert)

3. Query indexer during partition:
   ```rust
   let request = GetTransactionsRequest {
       starting_version: Some(1000),
       transactions_count: Some(5000),
       ...
   };
   ```

4. Observe that returned transactions have:
   - Versions 1000-2500 with epoch=10, block_height=100-150 (from fullnode-a)
   - Versions 2501-3000 with epoch=10, block_height=120-135 (from fullnode-b, forked)

5. Verify inconsistency:
   - Block height goes backward (150 → 120)
   - Transaction outcomes differ between forks
   - Applications receive invalid state

**Expected Result:** Indexer should detect the fork and reject fullnode-b's data or wait for convergence.

**Actual Result:** Indexer blindly mixes data from both forks without validation.

---

**Notes:**

This vulnerability specifically affects the indexer infrastructure's data integrity, not the core blockchain consensus. The issue arises from architectural design choices prioritizing random load balancing over consensus validation. While fullnodes should theoretically always be on the canonical chain, temporary divergence during network partitions is a realistic scenario that the indexer should handle gracefully rather than serving mixed-fork data to applications.

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

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L40-46)
```text
message Transaction {
  aptos.util.timestamp.Timestamp timestamp = 1;
  uint64 version = 2 [jstype = JS_STRING];
  TransactionInfo info = 3;
  uint64 epoch = 4 [jstype = JS_STRING];
  uint64 block_height = 5 [jstype = JS_STRING];

```
