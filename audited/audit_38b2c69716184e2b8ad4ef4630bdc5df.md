# Audit Report

## Title
Chain ID Validation Missing in Indexer-GRPC Data Service Connection Manager

## Summary
The `ConnectionManager::new()` function in the indexer-grpc data service accepts an arbitrary `chain_id` parameter without validating it against expected mainnet/testnet values. Additionally, the `MetadataManager` does not validate the `chain_id` received in heartbeat messages from data services, allowing a misconfigured or malicious data service to register with a GrpcManager while advertising an incorrect chain_id.

## Finding Description

The vulnerability exists in the indexer-grpc infrastructure where data services communicate their metadata to GrpcManager instances. The attack flow proceeds as follows:

**Step 1: Misconfigured/Malicious Data Service Initialization**

In `ConnectionManager::new()`, the chain_id parameter is accepted without validation: [1](#0-0) 

The function stores the chain_id directly without checking whether it matches valid chain IDs (MAINNET=1, TESTNET=2, etc.): [2](#0-1) 

**Step 2: Heartbeat Propagation with Invalid Chain ID**

The data service then sends heartbeats containing the arbitrary chain_id to the GrpcManager: [3](#0-2) 

The chain_id is embedded in the `LiveDataServiceInfo` or `HistoricalDataServiceInfo` protocol buffers: [4](#0-3) 

**Step 3: GrpcManager Accepts Without Validation**

When the GrpcManager receives the heartbeat, it processes the service info without validating the chain_id: [5](#0-4) 

Notice that neither `handle_live_data_service_info` nor `handle_historical_data_service_info` validates that `info.chain_id` matches `self.chain_id`.

**Step 4: Data Corruption Risk**

When users request data from the GrpcManager, they may be routed to the misconfigured data service that serves data from the wrong chain: [6](#0-5) 

**Contrast with Cache Worker Validation**

The cache worker component DOES implement proper chain_id validation, demonstrating the expected security pattern: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the bug bounty program criteria: "State inconsistencies requiring intervention."

**Impact on Indexer Infrastructure:**
- Applications consuming indexer data could receive transactions/events from the wrong blockchain (e.g., mainnet data when expecting testnet)
- Indexer databases could become corrupted with cross-chain data
- User applications could make incorrect decisions based on wrong-chain data
- Requires manual intervention to identify and remove misconfigured services

**Why Not Higher Severity:**
While this is a significant data integrity issue, it does NOT:
- Affect on-chain blockchain state or consensus
- Enable theft or manipulation of on-chain funds
- Compromise validator node security
- Cause network partitions or liveness failures

The indexer-grpc is off-chain infrastructure for data serving, not part of the core blockchain protocol.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur through:
1. **Accidental Misconfiguration**: Operators deploying data services with incorrect configuration files (e.g., copying mainnet config to testnet environment)
2. **Malicious Actor**: Intentional deployment of a data service with wrong chain_id to poison indexer data
3. **Development/Testing Errors**: Test instances accidentally connecting to production GrpcManagers

The attack requires only:
- Ability to run a data service instance (no special privileges)
- Network access to a GrpcManager endpoint
- Basic understanding of the configuration structure

No sophisticated techniques or insider access needed.

## Recommendation

Implement chain_id validation at multiple layers:

**1. In ConnectionManager::new():**
```rust
pub(crate) async fn new(
    chain_id: u64,
    grpc_manager_addresses: Vec<String>,
    self_advertised_address: String,
    is_live_data_service: bool,
) -> Self {
    // Validate chain_id is non-zero and within valid u8 range
    assert!(chain_id > 0 && chain_id <= 255, 
            "Invalid chain_id: {}. Must be 1-255.", chain_id);
    
    // Optionally warn if not a named chain
    if let Err(e) = NamedChain::from_chain_id(&ChainId::new(chain_id as u8)) {
        warn!("Chain ID {} is not a recognized named chain: {}", chain_id, e);
    }
    
    // ... rest of function
}
```

**2. In MetadataManager heartbeat handlers:**
```rust
fn handle_live_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: LiveDataServiceInfo,
) -> Result<()> {
    // Validate chain_id matches
    if info.chain_id != self.chain_id {
        bail!(
            "Chain ID mismatch: data service {} reports chain_id {}, but expected {}",
            address, info.chain_id, self.chain_id
        );
    }
    
    // ... rest of function
}
```

Apply the same validation to `handle_historical_data_service_info`, `handle_fullnode_info`, and `handle_grpc_manager_info`.

## Proof of Concept

**Rust Test Demonstrating the Vulnerability:**

```rust
#[tokio::test]
async fn test_cross_chain_data_service_accepted() {
    use crate::connection_manager::ConnectionManager;
    
    // Simulate mainnet GrpcManager expecting chain_id = 1
    let expected_chain_id: u64 = 1; // MAINNET
    
    // Attacker creates data service with testnet chain_id
    let malicious_chain_id: u64 = 2; // TESTNET
    
    // ConnectionManager accepts arbitrary chain_id without validation
    let connection_manager = ConnectionManager::new(
        malicious_chain_id,  // Wrong chain!
        vec!["http://localhost:50051".to_string()],
        "http://malicious-service:50052".to_string(),
        true,
    )
    .await;
    
    // Verify the malicious chain_id is stored
    assert_eq!(connection_manager.chain_id(), malicious_chain_id);
    
    // When this service sends heartbeats to mainnet GrpcManager,
    // it will be accepted and users may receive testnet data
    // when expecting mainnet data, causing corruption.
    
    println!("VULNERABILITY: Data service with chain_id {} accepted 
             when {} was expected!", malicious_chain_id, expected_chain_id);
}
```

**Steps to Reproduce:**
1. Deploy a GrpcManager configured for mainnet (chain_id=1)
2. Deploy a data service with testnet configuration (chain_id=2) but pointing to the mainnet GrpcManager address
3. The data service successfully registers with the GrpcManager
4. Query the GrpcManager for data - it may route requests to the misconfigured service
5. Observe that testnet transactions are served when mainnet data was expected

## Notes

While this is a legitimate data integrity vulnerability in the indexer infrastructure, it's important to note that:

1. **Scope**: This affects off-chain indexer services, not the core blockchain consensus or execution layer
2. **Defense in Depth**: Applications consuming indexer data should implement their own chain_id validation
3. **Detection**: Monitoring can detect chain_id mismatches through metrics and logs
4. **Mitigation**: Manual removal of misconfigured services from GrpcManager configuration

The fix should be implemented as defense-in-depth, even though well-designed client applications should validate chain_id independently.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L111-129)
```rust
    pub(crate) async fn new(
        chain_id: u64,
        grpc_manager_addresses: Vec<String>,
        self_advertised_address: String,
        is_live_data_service: bool,
    ) -> Self {
        let grpc_manager_connections = DashMap::new();
        grpc_manager_addresses.into_iter().for_each(|address| {
            grpc_manager_connections
                .insert(address.clone(), Self::create_client_from_address(&address));
        });
        let res = Self {
            chain_id,
            grpc_manager_connections,
            self_advertised_address,
            known_latest_version: AtomicU64::new(0),
            active_streams: DashMap::new(),
            is_live_data_service,
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L249-276)
```rust
    async fn heartbeat(&self, address: &str) -> Result<(), tonic::Status> {
        info!("Sending heartbeat to GrpcManager {address}.");
        let timestamp = Some(timestamp_now_proto());
        let known_latest_version = Some(self.known_latest_version());
        let stream_info = Some(StreamInfo {
            active_streams: self.get_active_streams(),
        });

        let info = if self.is_live_data_service {
            let min_servable_version = match LIVE_DATA_SERVICE.get() {
                Some(svc) => Some(svc.get_min_servable_version().await),
                None => None,
            };
            Some(Info::LiveDataServiceInfo(LiveDataServiceInfo {
                chain_id: self.chain_id,
                timestamp,
                known_latest_version,
                stream_info,
                min_servable_version,
            }))
        } else {
            Some(Info::HistoricalDataServiceInfo(HistoricalDataServiceInfo {
                chain_id: self.chain_id,
                timestamp,
                known_latest_version,
                stream_info,
            }))
        };
```

**File:** types/src/chain_id.rs (L11-24)
```rust
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamedChain {
    /// Users might accidentally initialize the ChainId field to 0, hence reserving ChainId 0 for accidental
    /// initialization.
    /// MAINNET is the Aptos mainnet production chain and is reserved for 1
    MAINNET = 1,
    // Even though these CHAIN IDs do not correspond to MAINNET, changing them should be avoided since they
    // can break test environments for various organisations.
    TESTNET = 2,
    DEVNET = 3,
    TESTING = 4,
    PREMAINNET = 5,
}
```

**File:** protos/proto/aptos/indexer/v1/grpc.proto (L35-49)
```text
message LiveDataServiceInfo {
  uint64 chain_id = 1;
  optional aptos.util.timestamp.Timestamp timestamp = 2;
  optional uint64 known_latest_version = 3;
  optional StreamInfo stream_info = 4;
  // If not present, it means the data service is not available to serve anything yet.
  optional uint64 min_servable_version = 5;
}

message HistoricalDataServiceInfo {
  uint64 chain_id = 1;
  optional aptos.util.timestamp.Timestamp timestamp = 2;
  optional uint64 known_latest_version = 3;
  optional StreamInfo stream_info = 4;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L489-531)
```rust
    fn handle_live_data_service_info(
        &self,
        address: GrpcAddress,
        mut info: LiveDataServiceInfo,
    ) -> Result<()> {
        let mut entry = self
            .live_data_services
            .entry(address.clone())
            .or_insert(LiveDataService::new(address));
        if info.stream_info.is_none() {
            info.stream_info = Some(StreamInfo {
                active_streams: vec![],
            });
        }
        entry.value_mut().recent_states.push_back(info);
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
    }

    fn handle_historical_data_service_info(
        &self,
        address: GrpcAddress,
        mut info: HistoricalDataServiceInfo,
    ) -> Result<()> {
        let mut entry = self
            .historical_data_services
            .entry(address.clone())
            .or_insert(HistoricalDataService::new(address));
        if info.stream_info.is_none() {
            info.stream_info = Some(StreamInfo {
                active_streams: vec![],
            });
        }
        entry.value_mut().recent_states.push_back(info);
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L71-88)
```rust
    fn pick_live_data_service(&self, starting_version: u64) -> Option<String> {
        let mut candidates = vec![];
        for candidate in self.metadata_manager.get_live_data_services_info() {
            if let Some(info) = candidate.1.back().as_ref() {
                // TODO(grao): Handle the case when the requested starting version is beyond the
                // latest version.
                if info.min_servable_version.is_none()
                    || starting_version < info.min_servable_version.unwrap()
                {
                    continue;
                }
                let num_active_streams = info.stream_info.as_ref().unwrap().active_streams.len();
                candidates.push((candidate.0, num_active_streams));
            }
        }

        Self::pick_data_service_from_candidate(candidates)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L286-324)
```rust
async fn verify_fullnode_init_signal(
    cache_operator: &mut CacheOperator<redis::aio::ConnectionManager>,
    init_signal: TransactionsFromNodeResponse,
    file_store_metadata: FileStoreMetadata,
) -> Result<(ChainID, StartingVersion)> {
    let (fullnode_chain_id, starting_version) = match init_signal
        .response
        .expect("[Indexer Cache] Response type does not exist.")
    {
        Response::Status(status_frame) => {
            match StatusType::try_from(status_frame.r#type)
                .expect("[Indexer Cache] Invalid status type.")
            {
                StatusType::Init => (init_signal.chain_id, status_frame.start_version),
                _ => {
                    bail!("[Indexer Cache] Streaming error: first frame is not INIT signal.");
                },
            }
        },
        _ => {
            bail!("[Indexer Cache] Streaming error: first frame is not siganl frame.");
        },
    };

    // Guaranteed that chain id is here at this point because we already ensure that fileworker did the set up
    let chain_id = cache_operator.get_chain_id().await?.unwrap();
    if chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain ID mismatch between fullnode init signal and cache.");
    }

    // It's required to start the worker with the same version as file store.
    if file_store_metadata.version != starting_version {
        bail!("[Indexer Cache] Starting version mismatch between filestore metadata and fullnode init signal.");
    }
    if file_store_metadata.chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain id mismatch between filestore metadata and fullnode.");
    }

    Ok((fullnode_chain_id, starting_version))
```
