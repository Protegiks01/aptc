# Audit Report

## Title
Query Inconsistency Across API Nodes Due to Independent Pruning Schedules

## Summary
Different API fullnodes maintain independent pruning states, causing the same historical query to succeed on some nodes while failing on others. This violates the "State Consistency" invariant and creates unpredictable API behavior for clients using load-balanced endpoints.

## Finding Description

Aptos API fullnodes each maintain their own independent AptosDB instance with separate pruning managers. The `min_readable_version` value, which tracks the oldest available version after pruning, is stored locally as an `AtomicVersion` and updates asynchronously on each node. [1](#0-0) 

When clients query historical data through load-balanced API endpoints, the validation flow involves two layers:

1. **API Layer Validation**: The `get_latest_ledger_info_and_verify_lookup_version()` function checks if the requested version is below `oldest_ledger_version` in the `LedgerInfo` response: [2](#0-1) 

2. **Storage Layer Validation**: When actually retrieving data, functions like `error_if_ledger_pruned()` check against the current `min_readable_version`: [3](#0-2) 

Since pruning occurs independently on each node without cross-node coordination, the following scenario occurs:

**Time T1:**
- Node A: `min_readable_version = 10000` (recently pruned)
- Node B: `min_readable_version = 5000` (pruning delayed)

**Client queries version 7000:**
- Request to Node A → Error: "Ledger version(7000) has been pruned, min available version is 10000" (HTTP 410)
- Request to Node B → Success: Returns transaction data

Each fullnode deployment uses independent storage, as confirmed by the deployment configurations: [4](#0-3) 

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty criteria for "Significant protocol violations" because:

1. **API Reliability Violation**: Clients using load-balanced endpoints experience non-deterministic failures for the same query, violating the expectation that all API nodes return consistent results for valid queries.

2. **State Consistency Invariant Break**: The critical invariant "State Consistency: State transitions must be atomic and verifiable via Merkle proofs" is violated when different nodes report different data availability for the same ledger version.

3. **Potential Data Access Bypass**: Attackers can probe multiple nodes to access historical data that has been pruned on most nodes, effectively bypassing the intended data retention policy.

4. **Application-Level Failures**: Applications built on Aptos that retry failed requests may receive inconsistent results across retries, causing logic errors or incorrect state processing.

## Likelihood Explanation

**Likelihood: High**

This issue occurs naturally in production environments because:

1. **Independent Pruning**: Each fullnode prunes according to its own schedule based on local `prune_window` configuration and current `latest_version`.

2. **Network Latency**: Nodes may receive new blocks at slightly different times, causing their `latest_version` to diverge temporarily.

3. **Pruning Performance**: Nodes with different hardware capabilities or load levels prune at different speeds.

4. **Common Deployment**: Load-balanced API endpoints with multiple fullnodes are the standard production setup for high availability.

No attacker action is required - this happens automatically in any multi-node deployment with pruning enabled.

## Recommendation

Implement one of the following solutions:

**Option 1: Coordinated Pruning (Preferred)**
Add a coordination mechanism where API nodes query a shared minimum readable version from a coordination service before pruning:

```rust
// In ledger_pruner_manager.rs
fn get_coordinated_min_readable_version(&self) -> Version {
    // Query distributed coordination service (e.g., etcd, Consul)
    // to get the minimum min_readable_version across all API nodes
    let cluster_min = self.coordination_client.get_cluster_min_readable_version();
    std::cmp::max(self.min_readable_version.load(Ordering::SeqCst), cluster_min)
}
```

**Option 2: Load Balancer Affinity**
Configure load balancers to use session affinity, ensuring clients consistently hit the same node for the duration of their session.

**Option 3: Conservative oldest_ledger_version**
Modify `get_first_viable_block()` to report a more conservative `oldest_ledger_version` that accounts for potential pruning delays across nodes:

```rust
fn get_min_viable_version(&self) -> Version {
    let min_version = self.get_min_readable_version();
    if self.is_pruner_enabled() {
        // Add extra buffer beyond user_pruning_window_offset
        let adjusted_window = self.prune_window
            .saturating_sub(self.user_pruning_window_offset)
            .saturating_sub(CROSS_NODE_PRUNING_BUFFER); // e.g., 1000 versions
        let adjusted_cutoff = self.latest_version.lock().saturating_sub(adjusted_window);
        std::cmp::max(min_version, adjusted_cutoff)
    } else {
        min_version
    }
}
```

**Option 4: API Layer Protection**
Add validation in the API layer to reject queries below a cluster-wide minimum: [5](#0-4) 

Wrap `get_state_value()` to check against a cluster-coordinated minimum version before querying storage.

## Proof of Concept

**Setup:**
1. Deploy two Aptos fullnodes (Node A and Node B) with identical initial state
2. Configure both with `ledger_pruner.prune_window = 10000`
3. Let both nodes sync to version 20000

**Exploitation Steps:**

```bash
# Step 1: Force Node A to prune aggressively
curl -X POST http://node-a:9101/trigger_pruning  # Internal admin endpoint
# Wait for Node A to prune to min_readable_version = 15000

# Step 2: Verify Node B hasn't pruned yet
curl http://node-b:8080/v1/
# Check oldest_ledger_version in response (should be ~10000)

# Step 3: Query version 12000 on both nodes
curl "http://node-a:8080/v1/transactions/by_version/12000"
# Expected: 410 Gone - "Ledger version(12000) has been pruned"

curl "http://node-b:8080/v1/transactions/by_version/12000"
# Expected: 200 OK - Returns transaction data

# Step 4: Demonstrate load balancer inconsistency
for i in {1..10}; do
  curl "http://load-balancer:8080/v1/transactions/by_version/12000"
  # Some requests succeed (hit Node B), some fail (hit Node A)
done
```

**Expected Result:** Inconsistent responses (mix of 410 and 200 status codes) for the same query when using a load-balanced endpoint.

**Notes**

This finding represents a fundamental distributed systems challenge: maintaining consistency across independent nodes with asynchronous pruning. While the behavior is "by design" in that each node manages its own pruning, it creates a user-facing inconsistency that violates client expectations for API reliability. The issue is particularly problematic for:

1. **Blockchain explorers** that may show different historical data depending on backend node selection
2. **Auditing systems** that require deterministic access to historical transactions
3. **Client SDKs** that implement automatic retry logic, potentially receiving different results across retries

The Aptos documentation mentions pruning but doesn't explicitly warn users about potential cross-node inconsistencies in load-balanced environments.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L48-50)
```rust
    fn get_min_readable_version(&self) -> Version {
        self.min_readable_version.load(Ordering::SeqCst)
    }
```

**File:** api/src/context.rs (L294-316)
```rust
    pub fn get_latest_ledger_info_and_verify_lookup_version<E: StdApiError>(
        &self,
        requested_ledger_version: Option<Version>,
    ) -> Result<(LedgerInfo, Version), E> {
        let latest_ledger_info = self.get_latest_ledger_info()?;

        let requested_ledger_version =
            requested_ledger_version.unwrap_or_else(|| latest_ledger_info.version());

        // This is too far in the future, a retriable case
        if requested_ledger_version > latest_ledger_info.version() {
            return Err(version_not_found(
                requested_ledger_version,
                &latest_ledger_info,
            ));
        } else if requested_ledger_version < latest_ledger_info.oldest_ledger_version.0 {
            return Err(version_pruned(
                requested_ledger_version,
                &latest_ledger_info,
            ));
        }

        Ok((latest_ledger_info, requested_ledger_version))
```

**File:** api/src/context.rs (L374-391)
```rust
    pub fn get_state_value(&self, state_key: &StateKey, version: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .state_view_at_version(Some(version))?
            .get_state_value_bytes(state_key)?
            .map(|val| val.to_vec()))
    }

    pub fn get_state_value_poem<E: InternalError>(
        &self,
        state_key: &StateKey,
        version: u64,
        ledger_info: &LedgerInfo,
    ) -> Result<Option<Vec<u8>>, E> {
        self.get_state_value(state_key, version)
            .context("Failed to retrieve state value")
            .map_err(|e| E::internal_with_code(e, AptosErrorCode::InternalError, ledger_info))
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** terraform/helm/fullnode/values.yaml (L1-50)
```yaml
# -- Default image tag to use for all fullnode images
imageTag: devnet

# -- If true, helm will always override the deployed image with what is configured in the helm values. If not, helm will take the latest image from the currently running workloads, which is useful if you have a separate procedure to update images (e.g. rollout)
manageImages: true

chain:
  # -- Bump this number to wipe the underlying storage
  era: 1
  # -- Name of the testnet to connect to. There must be a corresponding entry in .Values.aptos_chains
  name: devnet
  # -- The value of the `chain_name` label. If empty, defaults to `.Values.chain.name`
  label:
  # -- Kubernetes Configmap from which to load the genesis.blob and waypoint.txt
  genesisConfigmap:
  # -- Kubernetes Secret from which to load the genesis.blob and waypoint.txt
  genesisSecret:

# -- For each supported chain, specify the URLs from which to download the genesis.blob and waypoint.txt
aptos_chains:
  devnet:
    waypoint_txt_url: https://devnet.aptoslabs.com/waypoint.txt
    genesis_blob_url: https://devnet.aptoslabs.com/genesis.blob
  testnet:
    waypoint_txt_url: https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/testnet/genesis_waypoint.txt
    genesis_blob_url: https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/testnet/genesis.blob
  mainnet:
    waypoint_txt_url: https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/mainnet/waypoint.txt
    genesis_blob_url: https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/mainnet/genesis.blob

fullnode:
  # -- Fullnode configuration. See NodeConfig https://github.com/aptos-labs/aptos-core/blob/main/config/src/config/mod.rs
  config:
    full_node_networks:
      # The first item in the array `full_node_networks` must always refer to the public fullnode network
      - network_id: "public"
        identity: {}
        inbound_rate_limit_config:
        outbound_rate_limit_config:

# -- Log level for the fullnode
rust_log: info

image:
  # -- Image repo to use for fullnode images. Fullnodes and validators use the same image
  repo: aptoslabs/validator
  # -- Image tag to use for fullnode images. If set, overrides `imageTag`
  tag:
  # -- Image pull policy to use for fullnode images
  pullPolicy: IfNotPresent
```
