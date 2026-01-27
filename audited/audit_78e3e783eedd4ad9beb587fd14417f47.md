# Audit Report

## Title
Missing gRPC File Descriptor Registration Causes Reflection Failures for FullnodeData Service

## Summary
The indexer-grpc-fullnode service exposes the `FullnodeData` gRPC service but fails to register its file descriptor set (`INTERNAL_FULLNODE_V1_FILE_DESCRIPTOR_SET`) with the reflection service. This causes gRPC reflection queries to fail at runtime, preventing clients that rely on reflection from discovering and connecting to the FullnodeData service.

## Finding Description
The gRPC reflection service in the fullnode runtime registers only three file descriptor sets, but the service exposes a fourth service whose descriptor is not registered: [1](#0-0) [2](#0-1) 

When `use_data_service_interface == false`, the runtime adds `FullnodeDataServer` to the gRPC server: [3](#0-2) 

However, `FullnodeDataServer` implements the `FullnodeData` service from the `aptos.internal.fullnode.v1` package: [4](#0-3) 

This proto file has its own file descriptor set: [5](#0-4) 

But this descriptor is never imported or registered in the fullnode runtime configuration. The code explicitly warns about this issue in its TODO comment: [6](#0-5) 

When clients attempt to use gRPC reflection to discover the `FullnodeData` service (via tools like grpcurl, Postman, or dynamic gRPC clients), the reflection query will fail because the service descriptor is not registered. This breaks the gRPC reflection contract and causes client connection failures.

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category. The impact includes:

1. **Client Connection Failures**: Any client using gRPC reflection to discover and connect to the FullnodeData service will fail
2. **Developer Tool Breakage**: Tools like grpcurl (with `-plaintext` without explicit proto files), Postman gRPC explorer, and other reflection-based tools cannot interact with the service
3. **Dynamic Client Failures**: Applications using reflection for dynamic service discovery will fail to connect when `use_data_service_interface == false`

While clients with pre-compiled proto stubs can still connect, this breaks an essential gRPC feature and violates user expectations for a production gRPC service.

## Likelihood Explanation
This issue occurs deterministically whenever:
1. The fullnode service is configured with `use_data_service_interface == false` (exposing FullnodeDataServer)
2. A client attempts to use gRPC reflection to discover the FullnodeData service

The likelihood is **HIGH** because:
- Reflection is a standard gRPC feature widely used by developers and tools
- The configuration that triggers this (`use_data_service_interface == false`) is a valid production configuration
- No automated tests catch this issue (the existing test uses explicit proto imports rather than reflection) [7](#0-6) 

## Recommendation
Import and register the `INTERNAL_FULLNODE_V1_FILE_DESCRIPTOR_SET` in the fullnode runtime:

**Fix for `ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs`:**

1. Add import at line 16:
```rust
internal::fullnode::v1::{
    fullnode_data_server::FullnodeDataServer,
    FILE_DESCRIPTOR_SET as INTERNAL_FULLNODE_V1_FILE_DESCRIPTOR_SET,
},
```

2. Register the descriptor at line 95:
```rust
.register_encoded_file_descriptor_set(INDEXER_V1_FILE_DESCRIPTOR_SET)
.register_encoded_file_descriptor_set(TRANSACTION_V1_TESTING_FILE_DESCRIPTOR_SET)
.register_encoded_file_descriptor_set(UTIL_TIMESTAMP_FILE_DESCRIPTOR_SET)
.register_encoded_file_descriptor_set(INTERNAL_FULLNODE_V1_FILE_DESCRIPTOR_SET) // Add this line
.build_v1()
```

Additionally, implement the suggested TODO by adding automated testing (e.g., in `build.rs` or integration tests) that validates all exposed services have their descriptors registered.

## Proof of Concept
**Test using grpcurl with reflection (will fail):**

```bash
# Start fullnode service with use_data_service_interface=false
# Then attempt reflection-based discovery:
grpcurl -plaintext localhost:50051 list aptos.internal.fullnode.v1.FullnodeData

# Expected result: ERROR - service descriptor not found
# Actual result with fix: Lists Ping and GetTransactionsFromNode methods
```

**Rust integration test:**

```rust
#[tokio::test]
async fn test_reflection_includes_all_services() {
    use tonic::transport::Channel;
    use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
    
    // Connect to fullnode service
    let channel = Channel::from_static("http://localhost:50051")
        .connect()
        .await
        .unwrap();
    
    let mut client = ServerReflectionClient::new(channel);
    
    // Request service descriptor via reflection
    let request = tonic::Request::new(futures::stream::once(async {
        tonic_reflection::pb::v1::ServerReflectionRequest {
            message_request: Some(
                tonic_reflection::pb::v1::server_reflection_request::MessageRequest::ListServices(String::new())
            ),
        }
    }));
    
    let mut response_stream = client.server_reflection_info(request).await.unwrap().into_inner();
    
    // Verify aptos.internal.fullnode.v1.FullnodeData is in the list
    while let Some(response) = response_stream.message().await.unwrap() {
        // Check that FullnodeData service is discoverable
        assert!(services_include("aptos.internal.fullnode.v1.FullnodeData"));
    }
}
```

## Notes
- The same pattern exists in `indexer-grpc-data-service` and `indexer-grpc-data-service-v2`, but they only expose services whose descriptors are already registered
- The issue only manifests when `use_data_service_interface == false`, which switches from RawDataServer to FullnodeDataServer
- This is a production configuration issue, not a theoretical vulnerability

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L12-19)
```rust
use aptos_protos::{
    indexer::v1::{
        raw_data_server::RawDataServer, FILE_DESCRIPTOR_SET as INDEXER_V1_FILE_DESCRIPTOR_SET,
    },
    internal::fullnode::v1::fullnode_data_server::FullnodeDataServer,
    transaction::v1::FILE_DESCRIPTOR_SET as TRANSACTION_V1_TESTING_FILE_DESCRIPTOR_SET,
    util::timestamp::FILE_DESCRIPTOR_SET as UTIL_TIMESTAMP_FILE_DESCRIPTOR_SET,
};
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L87-97)
```rust
        let reflection_service = tonic_reflection::server::Builder::configure()
            // Note: It is critical that the file descriptor set is registered for every
            // file that the top level API proto depends on recursively. If you don't,
            // compilation will still succeed but reflection will fail at runtime.
            //
            // TODO: Add a test for this / something in build.rs, this is a big footgun.
            .register_encoded_file_descriptor_set(INDEXER_V1_FILE_DESCRIPTOR_SET)
            .register_encoded_file_descriptor_set(TRANSACTION_V1_TESTING_FILE_DESCRIPTOR_SET)
            .register_encoded_file_descriptor_set(UTIL_TIMESTAMP_FILE_DESCRIPTOR_SET)
            .build_v1()
            .expect("Failed to build reflection service");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L106-121)
```rust
        let router = match use_data_service_interface {
            false => {
                let svc = FullnodeDataServer::new(server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
                tonic_server.add_service(svc)
            },
            true => {
                let svc = RawDataServer::new(localnet_data_server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
                tonic_server.add_service(svc)
            },
        };
```

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L63-66)
```text
service FullnodeData {
  rpc Ping(PingFullnodeRequest) returns (PingFullnodeResponse);
  rpc GetTransactionsFromNode(GetTransactionsFromNodeRequest) returns (stream TransactionsFromNodeResponse);
}
```

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L107-108)
```rust
/// Encoded file descriptor set for the `aptos.internal.fullnode.v1` package
pub const FILE_DESCRIPTOR_SET: &[u8] = &[
```

**File:** testsuite/indexer_grpc_local.py (L237-255)
```python
            res = context.shell.run(
                [
                    GRPCURL_PATH,
                    "-max-msg-sz",
                    "10000000",
                    "-d",
                    '{ "starting_version": 0 }',
                    "-H",
                    "x-aptos-data-authorization:dummy_token",
                    "-import-path",
                    "protos/proto",
                    "-proto",
                    "aptos/indexer/v1/raw_data.proto",
                    "-plaintext",
                    GRPC_DATA_SERVICE_NON_TLS_URL,
                    "aptos.indexer.v1.RawData/GetTransactions",
                ],
                timeout_secs=GRPC_PROGRESS_THRESHOLD_SECS,
            )
```
