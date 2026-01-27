# Audit Report

## Title
Unauthenticated Network Topology Enumeration via PingFullnodeRequest gRPC Endpoint

## Summary
The `FullnodeDataService` exposes an unauthenticated `Ping` gRPC endpoint that allows any network peer to enumerate fullnodes and gather their synchronization status, enabling network reconnaissance for targeted attacks.

## Finding Description
The indexer gRPC service exposes a `Ping` RPC method defined in the `FullnodeData` service that processes `PingFullnodeRequest` messages without any authentication or authorization checks. [1](#0-0) 

The server implementation in the fullnode data service processes these requests and returns sensitive node information: [2](#0-1) 

The response includes `FullnodeInfo` containing:
- `chain_id`: The blockchain network identifier
- `timestamp`: Current timestamp  
- `known_latest_version`: The latest transaction version known to the fullnode (reveals sync status) [3](#0-2) 

The gRPC server is configured without any authentication interceptor: [4](#0-3) 

While the Tonic framework supports authentication via interceptors, the `FullnodeDataServer` is instantiated directly without calling `with_interceptor()`: [5](#0-4) 

An attacker can enumerate all fullnodes on the network by sending ping requests to discover:
1. Which nodes are available and responsive
2. Each node's synchronization status (`known_latest_version`)
3. Nodes that are behind in syncing (lower version numbers)
4. Network topology and node distribution

This information enables targeted attacks such as:
- Focusing attacks on nodes that are behind in sync (more vulnerable)
- Mapping the network architecture for eclipse attacks
- Timing attacks based on sync lag

## Impact Explanation
This vulnerability falls into the **Low Severity** category per the Aptos bug bounty criteria: "Minor information leaks". While it enables network reconnaissance, it does not directly cause:
- Loss of funds or token minting
- Consensus or safety violations  
- State inconsistencies
- Node slowdowns or crashes

However, the leaked information facilitates reconnaissance that could aid in launching more sophisticated attacks against the network infrastructure.

## Likelihood Explanation
**Likelihood: High**

The attack requires no special privileges or insider access. Any external actor can:
1. Connect to the publicly exposed gRPC endpoint (default port 50051)
2. Send `PingFullnodeRequest` messages
3. Receive unfiltered `FullnodeInfo` responses

The attack is trivially simple to execute and requires only a standard gRPC client.

## Recommendation
Implement authentication and authorization for the `FullnodeData` gRPC service:

1. **Add authentication interceptor** using Tonic's `with_interceptor()` mechanism
2. **Implement token-based authentication** similar to the patterns used in other indexer-grpc services
3. **Consider mutual TLS (mTLS)** for service-to-service authentication between the indexer-grpc-manager and fullnodes
4. **Add rate limiting** to prevent enumeration even for authenticated clients
5. **Restrict binding address** or use firewall rules to limit exposure to trusted networks only

Configuration should include authentication settings:
- API tokens/keys for authorized indexer-grpc-manager instances
- TLS certificates for mTLS
- IP whitelisting as defense-in-depth

## Proof of Concept
```rust
// PoC: Unauthenticated fullnode enumeration
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    PingFullnodeRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No authentication required - connect to any fullnode with indexer_grpc enabled
    let mut client = FullnodeDataClient::connect("http://[target-fullnode]:50051").await?;
    
    // Send unauthenticated ping request
    let request = tonic::Request::new(PingFullnodeRequest {});
    let response = client.ping(request).await?;
    
    if let Some(info) = response.into_inner().info {
        println!("Chain ID: {}", info.chain_id);
        println!("Known latest version: {:?}", info.known_latest_version);
        println!("Timestamp: {:?}", info.timestamp);
        // Attacker now knows this node's sync status for targeting
    }
    
    Ok(())
}
```

## Notes
While this is a valid information disclosure issue, it represents a design flaw in the indexer-grpc architecture where an internal API intended for trusted components (indexer-grpc-manager ↔ fullnodes) is exposed without proper access controls. The severity is limited because the information leaked does not directly enable high-impact attacks per the bug bounty criteria, and network-level DoS attacks are explicitly out of scope.

### Citations

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L56-66)
```text
message PingFullnodeRequest {
}

message PingFullnodeResponse {
    optional aptos.indexer.v1.FullnodeInfo info = 1;
}

service FullnodeData {
  rpc Ping(PingFullnodeRequest) returns (PingFullnodeResponse);
  rpc GetTransactionsFromNode(GetTransactionsFromNodeRequest) returns (stream TransactionsFromNodeResponse);
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

**File:** protos/proto/aptos/indexer/v1/grpc.proto (L51-55)
```text
message FullnodeInfo {
  uint64 chain_id = 1;
  optional aptos.util.timestamp.Timestamp timestamp = 2;
  optional uint64 known_latest_version = 3;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L108-112)
```rust
                let svc = FullnodeDataServer::new(server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
                tonic_server.add_service(svc)
```

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.tonic.rs (L209-217)
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
