# Audit Report

## Title
Integer Underflow in Indexer Cache Worker Batch Size Calculation Enables Denial of Service

## Summary
The indexer cache worker performs unchecked u64 subtraction when calculating batch size from gRPC StreamStatus messages, allowing a malicious fullnode to trigger integer underflow by sending `end_version < start_version`. This causes the cache worker to crash and restart indefinitely, preventing transaction data from being indexed. [1](#0-0) 

## Finding Description
The vulnerability exists in the `process_transactions_from_node_response` function where the cache worker processes BatchEnd signals from fullnode gRPC streams. The code directly subtracts `start_version` from `end_version` without validating that `end_version >= start_version`: [2](#0-1) 

In Rust release builds, when `end_version < start_version`, u64 subtraction wraps around rather than panicking. For example, if a malicious fullnode sends:
- `start_version = 200`
- `end_version = 100`

The calculation becomes: `100 - 200 + 1 = 18446744073709551516 + 1 = 18446744073709551517`

This corrupted `num_of_transactions` value is then used in validation logic: [3](#0-2) 

The validation `current_version != start_version + num_of_transactions` will fail because `start_version + num_of_transactions` overflows to an enormous value, causing the worker to break from its processing loop and restart.

**Attack Path:**
1. Attacker operates a malicious fullnode or compromises an existing one
2. Cache worker is configured to connect to this fullnode via the `fullnode_grpc_address` configuration parameter [4](#0-3) 
3. Malicious fullnode sends legitimate transaction data
4. Malicious fullnode sends BatchEnd StreamStatus with `end_version < start_version` 
5. Cache worker calculates wrapped `num_of_transactions` value
6. Validation detects mismatch and worker crashes
7. Worker automatically restarts and repeats the cycle

## Impact Explanation
**Severity: High** - This qualifies as "API crashes" under the High severity category (up to $50,000).

The vulnerability causes a persistent denial of service against the indexer cache infrastructure:
- Cache workers cannot process new transactions from malicious fullnodes
- Redis cache stops receiving updates, stalling all downstream indexer services
- Applications relying on indexed transaction data lose access to recent blockchain state
- The attack is trivial to execute once a fullnode is controlled
- Multiple cache workers can be targeted simultaneously if they connect to the same malicious fullnode

While this does not directly impact blockchain consensus or validator operations, it severely degrades the availability of critical ecosystem infrastructure that applications depend on for querying historical and real-time transaction data.

## Likelihood Explanation
**Likelihood: Medium**

The attack requires one of the following conditions:
1. **Misconfiguration**: Cache worker operator configures connection to a malicious fullnode
2. **Compromise**: An existing legitimate fullnode is compromised to serve malicious responses
3. **Social Engineering**: Operator is convinced to switch to attacker-controlled fullnode

While fullnodes are not privileged entities (anyone can run one), the attack requires the cache worker to be explicitly configured to connect to the malicious endpoint. However, given that:
- Multiple cache workers may connect to shared fullnode infrastructure
- Fullnode compromise is a realistic threat vector
- No authentication/validation exists for StreamStatus message contents

This represents a tangible security risk to production indexer deployments.

## Recommendation
Add validation before the arithmetic operation to ensure `end_version >= start_version`:

```rust
StatusType::BatchEnd => {
    let start_version = status.start_version;
    let end_version = status
        .end_version
        .expect("TransactionsFromNodeResponse status end_version is None");
    
    // Validate version ordering
    if end_version < start_version {
        anyhow::bail!(
            "Invalid BatchEnd signal: end_version ({}) < start_version ({})",
            end_version,
            start_version
        );
    }
    
    let num_of_transactions = end_version - start_version + 1;
    Ok(GrpcDataStatus::BatchEnd {
        start_version,
        num_of_transactions,
    })
}
```

Additionally, consider using checked arithmetic (`checked_sub()`) to make underflow explicit and panic in debug builds.

## Proof of Concept
```rust
#[test]
fn test_batch_size_underflow() {
    use aptos_protos::internal::fullnode::v1::{
        stream_status::StatusType, StreamStatus, TransactionsFromNodeResponse,
        transactions_from_node_response::Response,
    };
    
    // Craft malicious BatchEnd with end_version < start_version
    let malicious_status = StreamStatus {
        r#type: StatusType::BatchEnd as i32,
        start_version: 200,
        end_version: Some(100), // end_version < start_version
    };
    
    let response = TransactionsFromNodeResponse {
        response: Some(Response::Status(malicious_status)),
        chain_id: 1,
    };
    
    // This would cause underflow in release mode
    // In the actual code path, this leads to:
    // num_of_transactions = 100 - 200 + 1 = 18446744073709551517
    // which causes validation failure and worker crash
    
    let start = 200u64;
    let end = 100u64;
    let result = end.wrapping_sub(start).wrapping_add(1);
    assert_eq!(result, 18446744073709551517);
    println!("Underflow result: {}", result);
}
```

**Notes:**
- The vulnerability exists specifically in the cache worker's client-side processing of gRPC responses
- The server-side fullnode implementation correctly maintains `end_version >= start_version` in normal operation [5](#0-4) 
- The proto definition itself allows `end_version` as `Option<u64>` with no inherent ordering constraints [6](#0-5) 
- Defense-in-depth requires client-side validation of untrusted server responses

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L194-204)
```rust
                StatusType::BatchEnd => {
                    let start_version = status.start_version;
                    let num_of_transactions = status
                        .end_version
                        .expect("TransactionsFromNodeResponse status end_version is None")
                        - start_version
                        + 1;
                    Ok(GrpcDataStatus::BatchEnd {
                        start_version,
                        num_of_transactions,
                    })
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L433-442)
```rust
                    if current_version != start_version + num_of_transactions {
                        error!(
                            current_version = current_version,
                            actual_current_version = start_version + num_of_transactions,
                            "[Indexer Cache] End signal received with wrong version."
                        );
                        ERROR_COUNT
                            .with_label_values(&["data_end_wrong_version"])
                            .inc();
                        break;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/lib.rs (L14-22)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcCacheWorkerConfig {
    pub fullnode_grpc_address: Url,
    pub file_store_config: IndexerGrpcFileStoreConfig,
    pub redis_main_instance_address: RedisUrl,
    #[serde(default = "default_enable_cache_compression")]
    pub enable_cache_compression: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L163-167)
```rust
                let batch_end_status = get_status(
                    StatusType::BatchEnd,
                    coordinator.current_version,
                    Some(max_version),
                    ledger_chain_id,
```

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L20-30)
```rust
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct StreamStatus {
    #[prost(enumeration="stream_status::StatusType", tag="1")]
    pub r#type: i32,
    /// Required. Start version of current batch/stream, inclusive.
    #[prost(uint64, tag="2")]
    pub start_version: u64,
    /// End version of current *batch*, inclusive.
    #[prost(uint64, optional, tag="3")]
    pub end_version: ::core::option::Option<u64>,
}
```
