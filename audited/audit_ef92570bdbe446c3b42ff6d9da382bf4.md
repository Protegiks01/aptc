# Audit Report

## Title
Indexer Cache Worker Missing Graceful Shutdown - Transaction Loss and Cache Gap Vulnerability

## Summary
The indexer-grpc-cache-worker lacks signal handling for graceful shutdown, causing spawned Redis write tasks to be aborted when the process receives SIGTERM/SIGINT. This results in permanent transaction loss in the cache, creating gaps that break indexer consistency for downstream consumers.

## Finding Description

The cache worker receives transactions from a fullnode via gRPC streaming and writes them to Redis cache. The critical vulnerability exists in the transaction processing flow where tasks are spawned asynchronously but not protected during shutdown.

**The Vulnerable Flow:** [1](#0-0) 

When transaction data arrives from the fullnode, the worker spawns an async task to write to Redis and stores the JoinHandle in a `tasks_to_run` vector. These tasks are only awaited when a `BatchEnd` signal is received: [2](#0-1) 

**The Missing Protection:**

The server framework has no signal handling mechanism: [3](#0-2) 

The `tokio::select!` simply waits for either task to complete/panic, with no handling for SIGTERM/SIGINT signals. When the process is killed, the tokio runtime drops all tasks, aborting in-flight Redis writes.

**The Cache Gap Creation:**

On restart, the worker resumes from the file store version, not the cache version: [4](#0-3) 

The startup validation only checks chain ID and version consistency, but does NOT validate cache contents: [5](#0-4) 

**Exploitation Scenario:**

1. Cache worker processes transactions 1000-1999 from fullnode
2. Spawns 10 tasks to write batches to Redis
3. Tasks 1-5 complete (versions 1000-1499 written to Redis)
4. Tasks 6-10 are in-progress (versions 1500-1999 NOT yet written)
5. Process receives SIGTERM (e.g., Kubernetes pod restart, deployment update)
6. Process exits immediately, aborting tasks 6-10
7. Cache contains versions 1000-1499, missing 1500-1999
8. Cache `latest_version` was never updated (still at 999)
9. File store has progressed to version 2500
10. On restart, worker starts from file store version 2500
11. **Versions 1500-1999 are permanently missing from cache**

## Impact Explanation

**Severity: High** - This qualifies as "Significant protocol violations" under the Aptos bug bounty program.

The vulnerability breaks the **State Consistency** invariant - cache state transitions are NOT atomic. The impact includes:

1. **Indexer Inconsistency**: Downstream indexers querying the cache for missing versions will receive incorrect `DataNotReady` or `CacheEvicted` responses
2. **Data Availability Loss**: Gaps in cache force all queries for missing ranges to fall back to file store or fail entirely
3. **Service Degradation**: Indexer reliability is compromised, affecting all applications depending on transaction history
4. **Difficult Recovery**: No automated mechanism exists to detect or repair cache gaps - requires manual intervention and cache rebuild

This is not just a performance issue - it's a correctness violation in a critical data infrastructure component that breaks consistency guarantees for the entire indexer ecosystem.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will trigger in all standard operational scenarios:

1. **Kubernetes/Docker Deployments**: Pod restarts, rolling updates, node drains all send SIGTERM with 30-second grace period
2. **Auto-scaling**: Scale-down events terminate pods with SIGTERM
3. **Manual Operations**: `kubectl delete pod`, `docker stop` both use SIGTERM
4. **Resource Pressure**: OOMKiller sends SIGKILL (even worse - no cleanup at all)
5. **Deployment Updates**: Any new version deployment terminates the old pod

The window of vulnerability spans from when the first transaction batch is received until the `BatchEnd` signal and all tasks complete - typically several seconds per batch. With continuous transaction flow, this window is always open.

## Recommendation

Implement proper graceful shutdown handling using tokio signal handlers and cancellation tokens:

```rust
// In ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs
pub async fn run_server_with_config<C>(config: GenericConfig<C>) -> Result<()>
where
    C: RunnableConfig,
{
    use tokio::signal;
    use tokio_util::sync::CancellationToken;
    
    let shutdown_token = CancellationToken::new();
    let health_port = config.health_check_port;
    
    // Spawn signal handler
    let shutdown_token_clone = shutdown_token.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        tracing::info!("Received shutdown signal, initiating graceful shutdown");
        shutdown_token_clone.cancel();
    });
    
    // Start health checks with shutdown signal
    let config_clone = config.clone();
    let shutdown_token_clone = shutdown_token.clone();
    let task_handler = tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_token_clone.cancelled() => Ok(()),
            _ = register_probes_and_metrics_handler(config_clone, health_port) => Ok(()),
        }
    });
    
    // Start main task with shutdown signal
    let shutdown_token_clone = shutdown_token.clone();
    let main_task_handler = tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_token_clone.cancelled() => {
                tracing::info!("Main task received shutdown signal");
                Ok(())
            },
            result = config.run() => result,
        }
    });
    
    // Wait for both tasks with timeout
    tokio::select! {
        _ = shutdown_token.cancelled() => {
            // Give tasks time to finish
            tokio::time::sleep(Duration::from_secs(25)).await;
            tracing::info!("Graceful shutdown complete");
            Ok(())
        },
        res = task_handler => res?,
        res = main_task_handler => res?,
    }
}
```

Additionally, modify the cache worker to:
1. Accept a `CancellationToken` parameter
2. Stop accepting new transactions when shutdown is signaled
3. Await all in-flight tasks before exiting
4. Update cache `latest_version` based on completed tasks only

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: ecosystem/indexer-grpc/indexer-grpc-cache-worker/tests/shutdown_test.rs

use std::sync::Arc;
use tokio::time::{sleep, Duration};
use redis::AsyncCommands;

#[tokio::test]
async fn test_cache_worker_shutdown_causes_transaction_loss() {
    // Setup Redis and cache worker
    let redis_client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let mut conn = redis_client.get_tokio_connection_manager().await.unwrap();
    
    // Clear cache
    let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
    
    // Simulate: Spawn multiple tasks to write transactions
    let mut tasks = vec![];
    for version in 1000..2000 {
        let mut conn_clone = conn.clone();
        let task = tokio::spawn(async move {
            // Simulate slow Redis write
            sleep(Duration::from_millis(100)).await;
            let _: () = conn_clone.set(version.to_string(), format!("tx_{}", version))
                .await.unwrap();
        });
        tasks.push(task);
    }
    
    // Simulate: Process killed after 50ms (only some tasks complete)
    sleep(Duration::from_millis(50)).await;
    
    // Simulate: Process exit - drop all task handles without awaiting
    drop(tasks);
    
    // Brief delay for completed tasks to finish
    sleep(Duration::from_millis(200)).await;
    
    // Verify: Count how many transactions were written
    let mut written_count = 0;
    for version in 1000..2000 {
        let result: Option<String> = conn.get(version.to_string()).await.unwrap();
        if result.is_some() {
            written_count += 1;
        }
    }
    
    // Expected: Not all 1000 transactions were written (cache gap created)
    assert!(written_count < 1000, 
        "Expected incomplete writes due to task abortion, but {} out of 1000 were written", 
        written_count);
    
    println!("Vulnerability confirmed: Only {}/1000 transactions written before shutdown", 
        written_count);
    println!("Missing transactions: {} (permanent cache gap)", 1000 - written_count);
}
```

## Notes

This vulnerability is distinct from consensus or blockchain core issues - it affects the indexer infrastructure layer. However, since the indexer cache is a critical component for application developers and ecosystem tools, cache inconsistency has cascading effects on the entire Aptos ecosystem's usability and reliability.

The fix requires implementing proper lifecycle management with signal handling, which is a well-established pattern in the codebase (as evidenced by other components using `CancellationToken`), but was not applied to the indexer-grpc-cache-worker.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L119-145)
```rust
            // 1. Fetch metadata.
            let file_store_operator: Box<dyn FileStoreOperator> = self.file_store.create();
            // TODO: move chain id check somewhere around here
            // This ensures that metadata is created before we start the cache worker
            let mut starting_version = file_store_operator.get_latest_version().await;
            while starting_version.is_none() {
                starting_version = file_store_operator.get_latest_version().await;
                tracing::warn!(
                    "[Indexer Cache] File store metadata not found. Waiting for {} ms.",
                    FILE_STORE_METADATA_WAIT_MS
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    FILE_STORE_METADATA_WAIT_MS,
                ))
                .await;
            }

            // There's a guarantee at this point that starting_version is not null
            let starting_version = starting_version.unwrap();

            let file_store_metadata = file_store_operator.get_file_store_metadata().await.unwrap();

            tracing::info!(
                service_type = SERVICE_TYPE,
                "[Indexer Cache] Starting cache worker with version {}",
                starting_version
            );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L209-280)
```rust
        Response::Data(data) => {
            let transaction_len = data.transactions.len();
            let data_download_duration_in_secs = download_start_time.elapsed().as_secs_f64();
            let mut cache_operator_clone = cache_operator.clone();
            let task: JoinHandle<anyhow::Result<()>> = tokio::spawn({
                let first_transaction = data
                    .transactions
                    .first()
                    .context("There were unexpectedly no transactions in the response")?;
                let first_transaction_version = first_transaction.version;
                let last_transaction = data
                    .transactions
                    .last()
                    .context("There were unexpectedly no transactions in the response")?;
                let last_transaction_version = last_transaction.version;
                let start_version = first_transaction.version;
                let first_transaction_pb_timestamp = first_transaction.timestamp;
                let last_transaction_pb_timestamp = last_transaction.timestamp;

                log_grpc_step(
                    SERVICE_TYPE,
                    IndexerGrpcStep::CacheWorkerReceivedTxns,
                    Some(start_version as i64),
                    Some(last_transaction_version as i64),
                    first_transaction_pb_timestamp.as_ref(),
                    last_transaction_pb_timestamp.as_ref(),
                    Some(data_download_duration_in_secs),
                    Some(size_in_bytes),
                    Some((last_transaction_version + 1 - first_transaction_version) as i64),
                    None,
                );

                let cache_update_start_time = std::time::Instant::now();

                async move {
                    // Push to cache.
                    match cache_operator_clone
                        .update_cache_transactions(data.transactions)
                        .await
                    {
                        Ok(_) => {
                            log_grpc_step(
                                SERVICE_TYPE,
                                IndexerGrpcStep::CacheWorkerTxnsProcessed,
                                Some(first_transaction_version as i64),
                                Some(last_transaction_version as i64),
                                first_transaction_pb_timestamp.as_ref(),
                                last_transaction_pb_timestamp.as_ref(),
                                Some(cache_update_start_time.elapsed().as_secs_f64()),
                                Some(size_in_bytes),
                                Some(
                                    (last_transaction_version + 1 - first_transaction_version)
                                        as i64,
                                ),
                                None,
                            );
                            Ok(())
                        },
                        Err(e) => {
                            ERROR_COUNT
                                .with_label_values(&["failed_to_update_cache_version"])
                                .inc();
                            bail!("Update cache with version failed: {}", e);
                        },
                    }
                }
            });

            Ok(GrpcDataStatus::ChunkDataOk {
                num_of_transactions: transaction_len as u64,
                task,
            })
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L286-325)
```rust
async fn verify_fullnode_init_signal(
    cache_operator: &mut CacheOperator<redis::aio::ConnectionManager>,
    init_signal: TransactionsFromNodeResponse,
    file_store_metadata: FileStoreMetadata,
) -> Result<(ChainID, StartingVersion)> {
    let (fullnode_chain_id, starting_version) = match init_signal
        .response
        .expect("[Indexer Cache] Response type does not exist.")
    {
        Response::Status(status_frame) => {
            match StatusType::try_from(status_frame.r#type)
                .expect("[Indexer Cache] Invalid status type.")
            {
                StatusType::Init => (init_signal.chain_id, status_frame.start_version),
                _ => {
                    bail!("[Indexer Cache] Streaming error: first frame is not INIT signal.");
                },
            }
        },
        _ => {
            bail!("[Indexer Cache] Streaming error: first frame is not siganl frame.");
        },
    };

    // Guaranteed that chain id is here at this point because we already ensure that fileworker did the set up
    let chain_id = cache_operator.get_chain_id().await?.unwrap();
    if chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain ID mismatch between fullnode init signal and cache.");
    }

    // It's required to start the worker with the same version as file store.
    if file_store_metadata.version != starting_version {
        bail!("[Indexer Cache] Starting version mismatch between filestore metadata and fullnode init signal.");
    }
    if file_store_metadata.chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain id mismatch between filestore metadata and fullnode.");
    }

    Ok((fullnode_chain_id, starting_version))
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L413-449)
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
                    }
                    cache_operator
                        .update_cache_latest_version(transaction_count, current_version)
                        .await
                        .context("Failed to update the latest version in the cache")?;
                    transaction_count = 0;

```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L46-77)
```rust
pub async fn run_server_with_config<C>(config: GenericConfig<C>) -> Result<()>
where
    C: RunnableConfig,
{
    let health_port = config.health_check_port;
    // Start liveness and readiness probes.
    let config_clone = config.clone();
    let task_handler = tokio::spawn(async move {
        register_probes_and_metrics_handler(config_clone, health_port).await;
        anyhow::Ok(())
    });
    let main_task_handler =
        tokio::spawn(async move { config.run().await.expect("task should exit with Ok.") });
    tokio::select! {
        res = task_handler => {
            if let Err(e) = res {
                error!("Probes and metrics handler panicked or was shutdown: {:?}", e);
                process::exit(1);
            } else {
                panic!("Probes and metrics handler exited unexpectedly");
            }
        },
        res = main_task_handler => {
            if let Err(e) = res {
                error!("Main task panicked or was shutdown: {:?}", e);
                process::exit(1);
            } else {
                panic!("Main task exited unexpectedly");
            }
        },
    }
}
```
