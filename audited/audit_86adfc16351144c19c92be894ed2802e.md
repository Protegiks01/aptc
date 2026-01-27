# Audit Report

## Title
Missing Version Validation in Indexer Cache Worker Enables Denial of Service

## Summary
The `process_transactions_from_node_response()` function in the indexer-grpc cache worker lacks validation to ensure `end_version >= start_version` before calculating `num_of_transactions`. This allows a malicious or buggy fullnode to send invalid `BatchEnd` status messages that trigger integer overflow panics, causing the cache worker to crash repeatedly. [1](#0-0) 

## Finding Description
When processing a `BatchEnd` status message from the fullnode gRPC stream, the cache worker calculates the number of transactions using the formula:
```
num_of_transactions = end_version - start_version + 1
```

However, there is **no validation** that `end_version >= start_version` before this calculation. Since Aptos builds with `overflow-checks = true` in the release profile [2](#0-1) , any arithmetic overflow will cause a panic.

**Attack Propagation:**
1. The cache worker establishes a gRPC stream connection to a fullnode [3](#0-2) 
2. The fullnode sends transaction data followed by `BatchEnd` status messages [4](#0-3) 
3. A malicious fullnode sends a `BatchEnd` with `end_version < start_version` (e.g., `start_version=1000`, `end_version=500`)
4. The subtraction `500 - 1000 + 1` causes integer underflow
5. The panic terminates the cache worker process
6. The worker automatically reconnects and repeats the cycle [5](#0-4) 

**Security Guarantees Broken:**
- **Input Validation Invariant**: External inputs from network sources must be validated before use
- **Defense in Depth**: Even trusted sources should be validated to prevent propagation of bugs or compromised components
- **Service Availability**: The indexer cache infrastructure must remain operational to serve blockchain data

## Impact Explanation
This vulnerability enables a **Denial of Service** attack on the indexer cache worker, which is critical infrastructure for serving blockchain data to applications and APIs.

**Severity Assessment: Medium**
Per Aptos bug bounty criteria:
- Does NOT affect consensus, validator operations, or funds (NOT Critical)
- Does NOT directly crash validator nodes or APIs (NOT High in the strictest sense)
- **DOES cause state inconsistencies requiring intervention** (Medium): The cache worker becomes unavailable, requiring manual intervention to switch to a trusted fullnode
- **DOES affect service availability**: Applications depending on the indexer cache will experience data unavailability

The impact is limited to off-chain indexing infrastructure rather than core blockchain consensus, justifying Medium severity as indicated in the security question.

## Likelihood Explanation
**Likelihood: Medium-Low**

**Attack Requirements:**
- Attacker must control the fullnode that the cache worker connects to, OR
- Attacker must perform a man-in-the-middle attack on the gRPC connection
- In typical production deployments, cache workers connect to trusted, operator-controlled fullnodes

**However:**
- Defense-in-depth principles dictate validating all external inputs regardless of trust
- Bugs in fullnode software could accidentally generate invalid version ranges
- If a fullnode is compromised, this becomes an immediate attack vector
- The validation is simple to add and its absence violates secure coding practices

**Mitigating Factors:**
- The cache worker automatically attempts to reconnect, allowing recovery if the fullnode begins behaving correctly
- Operators can detect repeated crashes and switch to a different fullnode
- The issue is contained to indexer infrastructure and does not propagate to consensus

## Recommendation
Add validation to ensure `end_version >= start_version` before performing the calculation:

```rust
StatusType::BatchEnd => {
    let start_version = status.start_version;
    let end_version = status
        .end_version
        .expect("TransactionsFromNodeResponse status end_version is None");
    
    // Validate version range
    if end_version < start_version {
        bail!(
            "[Indexer Cache] Invalid BatchEnd: end_version ({}) < start_version ({})",
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

Additionally, validate that the calculated `num_of_transactions` is reasonable (e.g., not exceeding expected batch sizes) to detect other anomalous conditions.

## Proof of Concept
The following test demonstrates the vulnerability:

```rust
#[tokio::test]
#[should_panic(expected = "attempt to subtract with overflow")]
async fn test_batch_end_with_invalid_version_range() {
    use aptos_protos::internal::fullnode::v1::{
        stream_status::StatusType, transactions_from_node_response::Response,
        StreamStatus, TransactionsFromNodeResponse,
    };
    
    // Create a malicious BatchEnd message with end_version < start_version
    let malicious_response = TransactionsFromNodeResponse {
        response: Some(Response::Status(StreamStatus {
            r#type: StatusType::BatchEnd as i32,
            start_version: 1000,
            end_version: Some(500), // Invalid: less than start_version
        })),
        chain_id: 1,
    };
    
    let mut cache_operator = /* initialize cache operator */;
    let download_start_time = std::time::Instant::now();
    
    // This will panic due to integer underflow
    let _result = process_transactions_from_node_response(
        malicious_response,
        &mut cache_operator,
        download_start_time,
    )
    .await;
}
```

To exploit in practice, an attacker controlling a fullnode would modify the `get_status()` function [6](#0-5)  to send invalid version ranges, causing connected cache workers to crash repeatedly.

## Notes
While the security question asks about validation for "continuous sequence without gaps," the analysis reveals a more fundamental issue: the lack of validation that `end_version >= start_version`. The downstream gap detection in the Lua script [7](#0-6)  would catch actual gaps in transaction sequences, but only if the calculation doesn't panic first. The immediate vulnerability is the integer overflow, which should be addressed with basic range validation.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L110-111)
```rust
        // Re-connect if lost.
        loop {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L147-161)
```rust
            // 2. Start streaming RPC.
            let request = tonic::Request::new(GetTransactionsFromNodeRequest {
                starting_version: Some(starting_version),
                ..Default::default()
            });

            let response = rpc_client
                .get_transactions_from_node(request)
                .await
                .with_context(|| {
                    format!(
                        "Failed to get transactions from node at starting version {}",
                        starting_version
                    )
                })?;
```

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

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L163-168)
```rust
                let batch_end_status = get_status(
                    StatusType::BatchEnd,
                    coordinator.current_version,
                    Some(max_version),
                    ledger_chain_id,
                );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L245-261)
```rust
pub fn get_status(
    status_type: StatusType,
    start_version: u64,
    end_version: Option<u64>,
    ledger_chain_id: u8,
) -> TransactionsFromNodeResponse {
    TransactionsFromNodeResponse {
        response: Some(transactions_from_node_response::Response::Status(
            StreamStatus {
                r#type: status_type as i32,
                start_version,
                end_version,
            },
        )),
        chain_id: ledger_chain_id as u32,
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L39-57)
```rust
const CACHE_SCRIPT_UPDATE_LATEST_VERSION: &str = r#"
    local latest_version = redis.call("GET", KEYS[1])
    local num_of_versions = tonumber(ARGV[1])
    local current_version = tonumber(ARGV[2])
    if latest_version then
        if tonumber(latest_version) + num_of_versions < current_version then
            return 2
        elseif tonumber(latest_version) + num_of_versions == current_version then
            redis.call("SET", KEYS[1], current_version)
            return 0
        else
            redis.call("SET", KEYS[1], math.max(current_version, tonumber(latest_version)))
            return 1
        end
    else
        redis.call("SET", KEYS[1], ARGV[1])
        return 0
    end
"#;
```
