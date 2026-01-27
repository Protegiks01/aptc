# Audit Report

## Title
Self-Advertised Address Spoofing in Indexer gRPC Data Service Enables Client Redirection Attacks

## Summary
The indexer-grpc data service allows operators to configure an arbitrary `self_advertised_address` without validation. This address is sent to the GrpcManager via heartbeat messages and subsequently returned to clients requesting data service endpoints. A malicious data service operator can advertise a false address, causing clients to connect to attacker-controlled servers, enabling man-in-the-middle attacks and data manipulation.

## Finding Description

The indexer-grpc infrastructure uses a service discovery pattern where data services advertise their availability to a central GrpcManager. The `self_advertised_address` field is loaded from a YAML configuration file without any validation: [1](#0-0) 

This address is sent to the GrpcManager in heartbeat messages: [2](#0-1) 

The GrpcManager stores these addresses in DashMaps keyed by the advertised address, without verifying that the address is reachable or belongs to the service: [3](#0-2) 

When clients request a data service, the GrpcManager returns one of these stored addresses: [4](#0-3) 

The gateway then blindly trusts this address and proxies client requests to it: [5](#0-4) 

**Attack Scenario:**
1. Attacker deploys a malicious data service with `self_advertised_address: "http://attacker.com:50051"` in the config
2. The service connects to the GrpcManager and sends heartbeats with the malicious address
3. GrpcManager stores this address without validation
4. When a client queries the GrpcManager for a data service, it may receive the attacker's address
5. Client connects to attacker's server, which can return modified blockchain data or capture sensitive information

## Impact Explanation

This vulnerability constitutes a **High Severity** issue per the Aptos bug bounty program criteria for "Significant protocol violations." While it does not affect the core blockchain consensus or on-chain funds, it severely compromises the integrity of the indexer infrastructure, which is critical for:

- DApp developers querying historical transaction data
- Analytics platforms processing blockchain events
- Wallets fetching account balances and transaction history

A successful attack allows manipulation of off-chain data perception, potentially leading to:
- Users viewing incorrect account balances
- DApps making decisions based on false transaction history
- Analytics platforms reporting manipulated metrics
- Loss of trust in the Aptos indexer infrastructure

## Likelihood Explanation

The likelihood is **Medium** because:

**Enabling Factors:**
- No authentication mechanism prevents rogue data services from registering
- No validation of advertised addresses
- The attack requires only configuration file modification and network connectivity

**Mitigating Factors:**
- Attacker must operate infrastructure capable of running a data service
- Production GrpcManagers may be in private networks (deployment-dependent)
- The indexer ecosystem may have operational agreements limiting who can run services

However, the code-level vulnerability exists regardless of deployment practices. If the GrpcManager is accessible, the attack is straightforward.

## Recommendation

Implement multiple layers of defense:

**1. Address Validation:**
Add validation to verify the advertised address format and reachability:

```rust
fn validate_address(address: &str) -> Result<()> {
    // Validate URL format
    let url = Url::parse(address)
        .context("Invalid address format")?;
    
    // Verify scheme is http or https
    match url.scheme() {
        "http" | "https" => {},
        _ => bail!("Address must use http or https scheme"),
    }
    
    Ok(())
}
```

**2. Address Binding Verification:**
Verify that the advertised address matches the actual connection source:

```rust
// In heartbeat handler, extract the peer address
let peer_addr = request.remote_addr().context("No peer address")?;

// Verify it matches or is compatible with advertised address
if !verify_address_match(&service_info.address, peer_addr) {
    return Err(Status::invalid_argument(
        "Advertised address does not match connection source"
    ));
}
```

**3. Mutual TLS Authentication:**
Require data services to present valid certificates that bind to their advertised addresses.

**4. Address Allowlist:**
Maintain an explicit allowlist of authorized data service addresses in GrpcManager configuration.

**5. Health Checks:**
Periodically verify that advertised addresses are actually reachable and serving valid data: [6](#0-5) 

Enhance these ping methods to validate response authenticity.

## Proof of Concept

```rust
// PoC: Malicious data service configuration
// File: malicious_config.yaml

health_check_port: 8081
server_config:
  chain_id: 1
  service_config:
    listen_address: "0.0.0.0:50051"  # Actual service
    tls_config: null
  live_data_service_config:
    enabled: true
    num_slots: 100000
    size_limit_bytes: 1000000000
  historical_data_service_config:
    enabled: false
    file_store_config:
      file_store_type: LocalFileStore
      local_file_store_path: /tmp/fake
  grpc_manager_addresses:
    - "http://grpc-manager.aptos.com:50052"
  # MALICIOUS: Advertise attacker's address instead of actual service
  self_advertised_address: "http://attacker-controlled.com:50051"
  max_transaction_filter_size_bytes: 10485760
  data_service_response_channel_size: 5

# Steps to reproduce:
# 1. Deploy this config to a data service instance
# 2. The service connects to legitimate GrpcManager
# 3. Sends heartbeats with attacker's address
# 4. GrpcManager stores and returns this address to clients
# 5. Clients connect to attacker-controlled.com instead
# 6. Attacker returns manipulated blockchain data
```

**Verification Steps:**
1. Deploy malicious data service with fake `self_advertised_address`
2. Monitor GrpcManager logs to confirm heartbeat acceptance
3. Query GrpcManager's `get_data_service_for_request` RPC
4. Observe that the malicious address is returned
5. Trace client connection to confirm redirection to attacker's server

**Notes**

This vulnerability exists in the **indexer-grpc auxiliary infrastructure**, not the core blockchain consensus layer. While it does not directly compromise on-chain security, funds, or validator operations, it represents a significant trust violation in the data indexing pipeline that many ecosystem participants rely upon. The lack of address validation and authentication in the service discovery mechanism creates an exploitable attack vector for data manipulation and man-in-the-middle attacks against indexer clients.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L85-96)
```rust
pub struct IndexerGrpcDataServiceConfig {
    pub(crate) chain_id: u64,
    pub(crate) service_config: ServiceConfig,
    pub(crate) live_data_service_config: LiveDataServiceConfig,
    pub(crate) historical_data_service_config: HistoricalDataServiceConfig,
    pub(crate) grpc_manager_addresses: Vec<String>,
    pub(crate) self_advertised_address: String,
    #[serde(default = "IndexerGrpcDataServiceConfig::default_max_transaction_filter_size_bytes")]
    pub(crate) max_transaction_filter_size_bytes: usize,
    #[serde(default = "IndexerGrpcDataServiceConfig::default_data_service_response_channel_size")]
    pub data_service_response_channel_size: usize,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L249-301)
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
        let service_info = ServiceInfo {
            address: Some(self.self_advertised_address.clone()),
            info,
        };
        let request = HeartbeatRequest {
            service_info: Some(service_info),
        };
        let response = self
            .grpc_manager_connections
            .get(address)
            // TODO(grao): Consider to not use unwrap here.
            .unwrap()
            .clone()
            .heartbeat(request)
            .await?
            .into_inner();
        if let Some(known_latest_version) = response.known_latest_version {
            info!("Received known_latest_version ({known_latest_version}) from GrpcManager {address}.");
            self.update_known_latest_version(known_latest_version);
        } else {
            warn!("HeartbeatResponse doesn't contain known_latest_version, GrpcManager address: {address}");
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L445-465)
```rust
    async fn ping_live_data_service(
        &self,
        address: GrpcAddress,
        mut client: DataServiceClient<Channel>,
    ) -> Result<()> {
        let request = PingDataServiceRequest {
            known_latest_version: Some(self.get_known_latest_version()),
            ping_live_data_service: true,
        };
        let response = client.ping(request).await?;
        if let Some(info) = response.into_inner().info {
            match info {
                aptos_protos::indexer::v1::ping_data_service_response::Info::LiveDataServiceInfo(info) => {
                    self.handle_live_data_service_info(address, info)
                },
                _ => bail!("Bad response."),
            }
        } else {
            bail!("Bad response.")
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

**File:** ecosystem/indexer-grpc/indexer-grpc-gateway/src/gateway.rs (L92-153)
```rust
async fn get_data_service_url(
    State(config): State<Arc<IndexerGrpcGatewayConfig>>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let request_compression_encoding: Option<CompressionEncoding> = req
        .headers()
        .get(ENCODING_HEADER)
        .and_then(|encoding_header| {
            encoding_header
                .to_str()
                .ok()
                .map(|encoding_str| match encoding_str {
                    "gzip" => Some(CompressionEncoding::Gzip),
                    "zstd" => Some(CompressionEncoding::Zstd),
                    _ => None,
                })
        })
        .flatten();

    let (head, mut body) = req.into_parts();

    let mut user_request = None;
    if head.uri.path() == "/aptos.indexer.v1.RawData/GetTransactions" {
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .to_bytes();
        body = body_bytes.clone().into();
        let stream = Streaming::<GetTransactionsRequest>::new_request(
            <ProstCodec<GetTransactionsRequest, GetTransactionsRequest> as Codec>::decoder(
                &mut tonic::codec::ProstCodec::<GetTransactionsRequest, GetTransactionsRequest>::default(),
            ),
            Full::new(body_bytes),
            request_compression_encoding,
            None,
        );

        tokio::pin!(stream);

        if let Ok(Some(request)) = stream.try_next().await {
            user_request = Some(request);
        }
    }

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
}
```
