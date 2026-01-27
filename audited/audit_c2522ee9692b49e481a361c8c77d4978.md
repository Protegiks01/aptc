# Audit Report

## Title
Unvalidated FullnodeInfo.known_latest_version Enables Indexer Service Selection Manipulation

## Summary
The indexer gRPC manager accepts `known_latest_version` values from fullnodes without validation, allowing malicious or misconfigured fullnodes to advertise inflated version numbers and win service selection unfairly. This results in routing failures and service disruption for indexer clients.

## Finding Description

The `FullnodeInfo` struct contains a `known_latest_version` field that fullnodes advertise to indicate their data synchronization status. The indexer gRPC manager uses this self-reported value for service selection without any cryptographic verification or consensus-based validation. [1](#0-0) 

When fullnodes respond to ping requests, they populate this field from their local database state: [2](#0-1) 

The GrpcManager's `MetadataManager` accepts these values without verification and directly uses them for routing decisions: [3](#0-2) 

The service selection logic filters fullnodes based solely on this unverified value: [4](#0-3) 

**Attack Scenario:**
1. A malicious actor runs an indexer fullnode and modifies the `ping()` RPC to advertise `known_latest_version = 999999999` (artificially inflated)
2. The GrpcManager accepts this value and routes transaction requests to the malicious fullnode
3. When the fullnode attempts to fetch transactions it doesn't have, it either:
   - Crashes after retry exhaustion (if unmodified code), causing self-DoS
   - Serves incorrect/empty data (if maliciously modified), breaking data integrity
   - Causes indefinite client timeouts (if deliberately delayed)
4. The GrpcManager's own `known_latest_version` tracking is also corrupted by the inflated value [5](#0-4) 

## Impact Explanation

This vulnerability causes **Medium severity** indexer infrastructure disruption:

- **Service Availability**: Clients are routed to fullnodes that cannot serve the requested data, causing request failures and service degradation
- **Data Integrity Risk**: Maliciously modified fullnodes could serve incorrect transaction data to applications relying on the indexer
- **Cascading Failures**: The inflated version corrupts the GrpcManager's global version tracking, potentially affecting routing decisions for other services

This does NOT affect:
- Core consensus operations
- Validator operations or on-chain state
- Blockchain safety or liveness guarantees

Per Aptos bug bounty categories, this qualifies as **Medium Severity** under "State inconsistencies requiring intervention" (indexer service state) and could escalate to **High Severity** if it causes persistent "API crashes" of the indexer gRPC service.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Requirements:**
- Attacker must operate an indexer fullnode (accessible to any unprivileged actor)
- Must modify the fullnode service code to advertise false versions
- No validator access or privileged credentials required

**Detection Difficulty:**
- `known_latest_version` values vary legitimately across fullnodes
- No alerting mechanism exists for version inflation
- Malicious behavior is indistinguishable from misconfiguration

**Real-World Scenarios:**
1. **Accidental**: Misconfigured fullnodes with database inconsistencies could inadvertently report incorrect versions
2. **Malicious**: Competitors or adversaries could deliberately disrupt indexer services
3. **Cascading**: A single malicious fullnode affects the entire routing infrastructure

## Recommendation

Implement cryptographic verification of `known_latest_version` claims:

**Option 1: Ledger Info Verification**
Require fullnodes to provide a signed `LedgerInfo` structure from consensus that proves the claimed version exists and has been committed. The GrpcManager should verify the BLS multi-signature before accepting the version.

**Option 2: Challenge-Response Protocol**
When a fullnode advertises a version, the GrpcManager randomly challenges it to provide specific transaction data from that version range. Only fullnodes that successfully respond are eligible for selection.

**Option 3: Reputation System**
Track historical accuracy of fullnode version claims. Penalize fullnodes that advertise versions they cannot serve by temporarily removing them from the selection pool.

**Minimal Fix (Defense in Depth):**
Add bounds checking in `handle_fullnode_info`:

```rust
fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
    let mut entry = self
        .fullnodes
        .entry(address.clone())
        .or_insert(Fullnode::new(address.clone()));
    
    // Validate version is not impossibly high
    if let Some(known_latest_version) = info.known_latest_version {
        let current_max = self.get_known_latest_version();
        // Allow reasonable lead time (e.g., 1000 versions ahead)
        const MAX_VERSION_LEAD: u64 = 1000;
        if known_latest_version > current_max + MAX_VERSION_LEAD {
            warn!("Fullnode {address} advertised suspicious version {known_latest_version}, rejecting");
            return Ok(());
        }
    }
    
    entry.value_mut().recent_states.push_back(info);
    if let Some(known_latest_version) = info.known_latest_version {
        self.update_known_latest_version(known_latest_version);
    }
    if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
        entry.value_mut().recent_states.pop_front();
    }
    Ok(())
}
```

## Proof of Concept

```rust
// PoC: Malicious Fullnode Advertising Inflated Version
// File: malicious_fullnode_poc.rs

use aptos_protos::indexer::v1::FullnodeInfo;
use aptos_protos::internal::fullnode::v1::{PingFullnodeRequest, PingFullnodeResponse};
use tonic::{Request, Response, Status};

// Malicious implementation that inflates known_latest_version
async fn malicious_ping(
    &self,
    _request: Request<PingFullnodeRequest>,
) -> Result<Response<PingFullnodeResponse>, Status> {
    // Normal fullnodes would call: self.context.db.get_synced_version()
    // Malicious fullnode advertises impossibly high version
    let malicious_version = u64::MAX - 1; // or any inflated value
    
    let info = FullnodeInfo {
        chain_id: 1, // mainnet
        timestamp: Some(timestamp_now_proto()),
        known_latest_version: Some(malicious_version), // INFLATED VALUE
    };
    
    let response = PingFullnodeResponse { info: Some(info) };
    Ok(Response::new(response))
}

// Demonstration:
// 1. Run modified fullnode with malicious_ping implementation
// 2. Fullnode sends heartbeat to GrpcManager
// 3. GrpcManager accepts inflated version without validation
// 4. Clients requesting transactions at version X < malicious_version
//    get routed to malicious fullnode
// 5. Malicious fullnode either crashes (honest code) or serves bad data
// 6. Result: Service disruption and potential data integrity issues
```

**Steps to Reproduce:**
1. Deploy an indexer fullnode with modified `ping()` RPC returning inflated `known_latest_version`
2. Configure GrpcManager to connect to this fullnode
3. Send heartbeat from malicious fullnode to GrpcManager
4. Observe that GrpcManager accepts the value (check logs/metrics)
5. Make a transaction request that falls within the inflated range
6. Observe routing to malicious fullnode and subsequent failure

**Notes**

This vulnerability exists in the **indexer infrastructure** layer, which is separate from core consensus operations. While it does not affect blockchain safety or on-chain state, it impacts the availability and reliability of data services that applications depend on. The lack of validation violates the principle of "never trust, always verify" for distributed system components. The fix requires implementing proper verification mechanisms before accepting service advertisement claims.

### Citations

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L223-230)
```rust
pub struct FullnodeInfo {
    #[prost(uint64, tag="1")]
    pub chain_id: u64,
    #[prost(message, optional, tag="2")]
    pub timestamp: ::core::option::Option<super::super::util::timestamp::Timestamp>,
    #[prost(uint64, optional, tag="3")]
    pub known_latest_version: ::core::option::Option<u64>,
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

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L320-360)
```rust
    pub async fn fetch_raw_txns_with_retries(
        context: Arc<Context>,
        ledger_version: u64,
        batch: TransactionBatchInfo,
    ) -> Vec<TransactionOnChainData> {
        let mut retries = 0;
        loop {
            match context.get_transactions(
                batch.start_version,
                batch.num_transactions_to_fetch,
                ledger_version,
            ) {
                Ok(raw_txns) => return raw_txns,
                Err(err) => {
                    UNABLE_TO_FETCH_TRANSACTION.inc();
                    retries += 1;

                    if retries >= DEFAULT_NUM_RETRIES {
                        error!(
                            starting_version = batch.start_version,
                            num_transactions = batch.num_transactions_to_fetch,
                            error = format!("{:?}", err),
                            "Could not fetch transactions: retries exhausted",
                        );
                        panic!(
                            "Could not fetch {} transactions after {} retries, starting at {}: {:?}",
                            batch.num_transactions_to_fetch, retries, batch.start_version, err
                        );
                    } else {
                        error!(
                            starting_version = batch.start_version,
                            num_transactions = batch.num_transactions_to_fetch,
                            error = format!("{:?}", err),
                            "Could not fetch transactions: will retry",
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                },
            }
        }
    }
```
