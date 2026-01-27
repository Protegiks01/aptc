# Audit Report

## Title
Indexer gRPC Service Spawned Tasks Outlive Service Lifetime Leading to Uncontrolled Resource Access During Shutdown

## Summary
The `FullnodeDataService::get_transactions_from_node()` function spawns detached tokio tasks that can outlive the service lifetime. When the service is dropped during node shutdown, these tasks continue running and accessing database resources without any graceful termination mechanism, potentially causing panics, resource exhaustion, and preventing clean node shutdown.

## Finding Description

The `get_transactions_from_node()` function spawns a detached task using `tokio::spawn()` that processes and streams transactions to clients. [1](#0-0) 

This spawned task captures an `abort_handle` that is intended to signal when the task should stop. [2](#0-1) 

The task checks this abort handle during its execution loop. [3](#0-2) 

However, the `Drop` implementation for `FullnodeDataService` only prints a message and does NOT set the `abort_handle` to true or perform any cleanup. [4](#0-3) 

Investigation of the entire codebase reveals that **the `abort_handle` is never set to true anywhere in the code**. It is initialized as false and remains false for the entire lifetime of the service. [5](#0-4) 

The spawned task accesses the database through the `context` object throughout its execution, including multiple operations that use `.unwrap()` or `.expect()` which would panic on errors. [6](#0-5) 

When the node initiates shutdown, the gRPC server and `FullnodeDataService` may be dropped, but the spawned tasks continue running. These tasks will keep accessing the database, which may be in the process of shutting down, leading to:

1. **Database access errors and panics** - If the database is closed while tasks are still reading
2. **Resource exhaustion** - Tasks continue consuming CPU and memory after service should be stopped
3. **Delayed shutdown** - Running tasks prevent clean node shutdown
4. **Inconsistent state** - Task panics during shutdown may leave the system in an inconsistent state

**Attack Scenario**: An attacker can:
1. Open multiple long-running streaming connections (requesting millions of transactions)
2. Each connection spawns a detached task that will run for an extended period
3. When the node operator attempts to shutdown/restart the node (e.g., for maintenance or upgrades)
4. The spawned tasks are not signaled to stop and continue running
5. This delays shutdown, causes errors, and may trigger panics that crash the indexer service

## Impact Explanation

This vulnerability qualifies as **High Severity** according to the Aptos bug bounty criteria:

- **API crashes**: The spawned tasks may panic when accessing a closing database, causing the indexer gRPC service to crash during shutdown
- **Validator node slowdowns**: Multiple running tasks consuming resources during shutdown can significantly slow down node operations
- **Significant protocol violations**: The lack of graceful shutdown violates the expected lifecycle management of node services

While this does not directly affect consensus or transaction execution (the indexer-grpc service is a data layer), it impacts node availability, operational reliability, and creates an exploitable DoS vector during critical shutdown/restart operations.

## Likelihood Explanation

**Likelihood: High**

This issue will occur in any scenario where:
1. A client makes streaming requests to the indexer gRPC service (normal operation)
2. The node is shut down or restarted (routine maintenance operation)

The likelihood is high because:
- Normal indexer operations create these long-running tasks
- Node shutdowns/restarts are regular operational events
- No privileged access is required - any client can trigger this
- The abort mechanism is completely unused in the codebase
- The proper shutdown pattern (as demonstrated in `DBIndexer`) is not followed [7](#0-6) 

## Recommendation

Implement proper graceful shutdown for spawned tasks by:

1. **Set abort_handle in Drop implementation**:
```rust
impl Drop for FullnodeDataService {
    fn drop(&mut self) {
        println!("**** Dropping FullnodeDataService. ****");
        // Signal all spawned tasks to stop
        self.abort_handle.store(true, Ordering::SeqCst);
    }
}
```

2. **Use JoinHandle to track spawned tasks** (more robust approach):
```rust
pub struct FullnodeDataService {
    pub service_context: ServiceContext,
    pub abort_handle: Arc<AtomicBool>,
    // Track spawned tasks
    pub task_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Drop for FullnodeDataService {
    fn drop(&mut self) {
        // Signal all tasks to stop
        self.abort_handle.store(true, Ordering::SeqCst);
        
        // Optionally wait for tasks to complete
        // This should be done in a blocking context or with a timeout
        let handles = self.task_handles.lock().unwrap();
        for handle in handles.iter() {
            handle.abort(); // Force abort if necessary
        }
    }
}
```

3. **Follow the DBIndexer pattern**: Send a shutdown signal through a channel and join the task, similar to how `DBIndexer` properly implements graceful shutdown. [7](#0-6) 

## Proof of Concept

**Reproduction Steps**:

1. Start an Aptos node with indexer-grpc enabled
2. Connect a client and request a large number of transactions:
```rust
// Client code
let mut client = FullnodeDataClient::connect("http://localhost:50051").await?;
let request = GetTransactionsFromNodeRequest {
    starting_version: Some(0),
    transactions_count: Some(10_000_000), // Request 10M transactions
};
let stream = client.get_transactions_from_node(request).await?;
```

3. While the stream is active and processing transactions, initiate node shutdown (SIGTERM or graceful shutdown)

4. **Expected behavior**: The spawned task should receive the abort signal and stop cleanly

5. **Actual behavior**: The spawned task continues running because:
   - The abort_handle is never set to true
   - The Drop impl doesn't signal the task
   - The task only stops when it finishes naturally or the client disconnects

6. **Observable issues**:
   - Database access errors appear in logs as database closes
   - Shutdown takes longer than expected
   - Potential panics in spawned tasks if database operations fail
   - Resource cleanup is delayed

**Verification**:
Add logging to the Drop implementation and spawned task to observe the timing:
```rust
impl Drop for FullnodeDataService {
    fn drop(&mut self) {
        eprintln!("**** FullnodeDataService dropped at {:?} ****", std::time::Instant::now());
    }
}

// In spawned task
tokio::spawn(async move {
    eprintln!("Task started at {:?}", std::time::Instant::now());
    // ... existing code ...
    eprintln!("Task finished at {:?}", std::time::Instant::now());
});
```

This will show that the task continues running after the service is dropped.

## Notes

This is a classic async task lifetime management bug where detached tasks (created with `tokio::spawn`) are not properly synchronized with their parent object's lifetime. The `abort_handle` mechanism was correctly designed but never implemented - it is created but never used throughout the entire codebase. This violates Rust best practices for resource management and the proper shutdown patterns demonstrated elsewhere in the Aptos codebase (such as in `DBIndexer`).

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L41-45)
```rust
impl Drop for FullnodeDataService {
    fn drop(&mut self) {
        println!("**** Dropping FullnodeDataService. ****");
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L99-101)
```rust
        let abort_handle = self.abort_handle.clone();
        // This is the main thread handling pushing to the stream
        tokio::spawn(async move {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L139-142)
```rust
                if abort_handle.load(Ordering::SeqCst) {
                    info!("FullnodeDataService is aborted.");
                    break;
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L81-84)
```rust
        let server = FullnodeDataService {
            service_context: service_context.clone(),
            abort_handle: Arc::new(AtomicBool::new(false)),
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L119-128)
```rust
        let (_, _, block_event) = self
            .context
            .db
            .get_block_info_by_version(end_version as u64)
            .unwrap_or_else(|_| {
                panic!(
                    "[Indexer Fullnode] Could not get block_info for version {}",
                    end_version,
                )
            });
```

**File:** storage/indexer/src/db_indexer.rs (L313-324)
```rust
impl Drop for DBIndexer {
    fn drop(&mut self) {
        if let Some(handle) = self.committer_handle.take() {
            self.sender
                .send(None)
                .expect("Failed to send None to DBIndexer committer");
            handle
                .join()
                .expect("DBIndexer committer thread fails to join");
        }
    }
}
```
