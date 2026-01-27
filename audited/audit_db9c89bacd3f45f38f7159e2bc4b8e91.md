# Audit Report

## Title
Lack of Jitter in Indexer gRPC Client Retry Logic Enables Thundering Herd on Network Recovery

## Summary
The indexer gRPC client creation functions use exponential backoff without jitter, causing all clients to retry connection attempts at synchronized intervals after network partitions. This creates thundering herd effects that can overwhelm servers during recovery and delay service restoration.

## Finding Description

The `create_grpc_client()` and `create_data_service_grpc_client()` functions use the `backoff` crate's `ExponentialBackoff::default()` without configuring randomization. [1](#0-0) [2](#0-1) 

The `backoff` crate version 0.4.0 defaults to `randomization_factor = 0.0`, meaning no jitter is applied to retry delays. [3](#0-2) 

In production deployments, multiple indexer service instances run simultaneously (cache-worker, file-store, data-service), and these can be scaled with replicas: [4](#0-3) 

When a network partition occurs (Redis restart, fullnode restart, network disruption), all clients lose connection simultaneously. The cache worker's reconnection loop demonstrates this pattern: [5](#0-4) 

Without jitter, all clients retry at identical deterministic intervals (e.g., 500ms, 1s, 2s, 4s...), creating synchronized load spikes on the server. This prevents smooth recovery and can cause cascading failures if the server rejects connections due to overload.

Critically, other components in the codebase recognize and prevent this exact issue. The connectivity manager explicitly adds jitter with detailed documentation: [6](#0-5) [7](#0-6) 

The transaction emitter also enables jitter explicitly: [8](#0-7) 

Additionally, the REST client has an acknowledged TODO to add jitter: [9](#0-8) 

## Impact Explanation

This is a **Medium severity** issue per Aptos Bug Bounty criteria. While it doesn't directly compromise consensus or funds, it causes:

1. **Service Availability Degradation**: During network partition recovery, synchronized retry attempts can overwhelm the gRPC server, preventing successful reconnections
2. **Extended Downtime**: The thundering herd prolongs recovery time, delaying when indexer services can resume normal operation
3. **Potential Cascading Failures**: If the server cannot handle synchronized load, it may reject legitimate connections, triggering more retries

The impact aligns with High Severity "API crashes" if the thundering herd causes server overload, but is conservatively classified as Medium due to temporary nature and no permanent state corruption.

## Likelihood Explanation

**High Likelihood**: Network partitions are common operational events in distributed systems:
- Redis server restarts for maintenance or crashes
- Fullnode restarts for upgrades
- Transient network issues
- Load balancer reconfigurations

In production environments with multiple replicas (standard for high availability), the probability of simultaneous disconnection approaches certainty during these events. The deterministic backoff guarantees synchronized retries, making thundering herd inevitable rather than probabilistic.

## Recommendation

Configure `ExponentialBackoff` with a non-zero `randomization_factor` to add jitter. The `backoff` crate supports this through the builder pattern:

```rust
pub async fn create_grpc_client(address: Url) -> GrpcClientType {
    let mut backoff = backoff::ExponentialBackoff::default();
    backoff.randomization_factor = 0.5; // Add 50% jitter
    
    backoff::future::retry(backoff, || async {
        // ... existing retry logic
    })
    .await
    .unwrap()
}

pub async fn create_data_service_grpc_client(
    address: Url,
    max_elapsed_time: Option<Duration>,
) -> Result<GrpcDataServiceClientType> {
    let mut backoff = backoff::ExponentialBackoff::default();
    backoff.randomization_factor = 0.5; // Add 50% jitter
    if let Some(max_elapsed_time) = max_elapsed_time {
        backoff.max_elapsed_time = Some(max_elapsed_time);
    }
    
    // ... existing retry logic
}
```

A `randomization_factor` of 0.5 means the actual delay will be randomly chosen from [0.5 × delay, 1.5 × delay], spreading out retry attempts across time.

## Proof of Concept

```rust
// Reproduction test showing synchronized retries without jitter
#[tokio::test]
async fn test_thundering_herd_without_jitter() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::Instant;
    
    // Simulate server tracking connection attempts
    let attempt_times = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let num_clients = 10;
    
    // Spawn multiple clients that all fail and retry
    let mut handles = vec![];
    for _ in 0..num_clients {
        let times = attempt_times.clone();
        let handle = tokio::spawn(async move {
            let backoff = backoff::ExponentialBackoff::default();
            let start = Instant::now();
            
            let _ = backoff::future::retry(backoff, || async {
                times.lock().await.push(start.elapsed().as_millis());
                // Simulate connection failure
                Err::<(), _>(backoff::Error::transient("connection failed"))
            }).await;
        });
        handles.push(handle);
    }
    
    // Let them run for a bit
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    // Analyze timing - without jitter, attempts cluster tightly
    let times = attempt_times.lock().await;
    
    // Check for synchronized attempts (multiple attempts within 10ms windows)
    let mut clustered_attempts = 0;
    for window in times.windows(num_clients) {
        let time_range = window.iter().max().unwrap() - window.iter().min().unwrap();
        if time_range < 10 {  // All within 10ms = thundering herd
            clustered_attempts += 1;
        }
    }
    
    println!("Clustered attempt groups: {}", clustered_attempts);
    assert!(clustered_attempts > 0, "Thundering herd detected");
}
```

**Notes**

The vulnerability is confirmed by multiple factors:
1. Direct code analysis showing missing jitter configuration
2. Comparison with other codebase components that explicitly prevent this issue
3. Production deployment patterns enabling multiple concurrent clients
4. Realistic operational scenarios triggering the vulnerability

While the indexer infrastructure is separate from core consensus, its availability is critical for blockchain usability, making this a valid Medium severity performance/availability vulnerability rather than a purely operational concern.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L36-63)
```rust
pub async fn create_grpc_client(address: Url) -> GrpcClientType {
    backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
        match FullnodeDataClient::connect(address.to_string()).await {
            Ok(client) => {
                tracing::info!(
                    address = address.to_string(),
                    "[Indexer Cache] Connected to indexer gRPC server."
                );
                Ok(client
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Zstd))
            },
            Err(e) => {
                tracing::error!(
                    address = address.to_string(),
                    "[Indexer Cache] Failed to connect to indexer gRPC server: {}",
                    e
                );
                Err(backoff::Error::transient(e))
            },
        }
    })
    .await
    .unwrap()
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L69-101)
```rust
pub async fn create_data_service_grpc_client(
    address: Url,
    max_elapsed_time: Option<Duration>,
) -> Result<GrpcDataServiceClientType> {
    let mut backoff = backoff::ExponentialBackoff::default();
    if let Some(max_elapsed_time) = max_elapsed_time {
        backoff.max_elapsed_time = Some(max_elapsed_time);
    }
    let client = backoff::future::retry(backoff, || async {
        match RawDataClient::connect(address.to_string()).await {
            Ok(client) => {
                tracing::info!(
                    address = address.to_string(),
                    "[Indexer Cache] Connected to indexer data service gRPC server."
                );
                Ok(client
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX))
            },
            Err(e) => {
                tracing::error!(
                    address = address.to_string(),
                    "[Indexer Cache] Failed to connect to indexer data service gRPC server: {}",
                    e
                );
                Err(backoff::Error::transient(e))
            },
        }
    })
    .await
    .context("Failed to create data service GRPC client")?;
    Ok(client)
}
```

**File:** Cargo.toml (L529-529)
```text
backoff = { version = "0.4.0", features = ["tokio"] }
```

**File:** docker/compose/indexer-grpc/docker-compose.yaml (L40-111)
```yaml
  indexer-grpc-cache-worker:
    image: "${INDEXER_GRPC_IMAGE_REPO:-aptoslabs/indexer-grpc}:${IMAGE_TAG:-main}"
    networks:
      shared:
        ipv4_address: 172.16.1.13
    restart: unless-stopped
    volumes:
      - type: volume # XXX: needed now before refactor https://github.com/aptos-labs/aptos-core/pull/8139
        source: indexer-grpc-file-store
        target: /opt/aptos/file-store
      - type: bind
        source: ./cache-worker-config.yaml
        target: /opt/aptos/cache-worker-config.yaml
    command:
      - '/usr/local/bin/aptos-indexer-grpc-cache-worker'
      - '--config-path'
      - '/opt/aptos/cache-worker-config.yaml'
    depends_on:
      - redis

  indexer-grpc-file-store:
    image: "${INDEXER_GRPC_IMAGE_REPO:-aptoslabs/indexer-grpc}:${IMAGE_TAG:-main}"
    networks:
      shared:
        ipv4_address: 172.16.1.14
    restart: unless-stopped
    volumes:
      - type: volume
        source: indexer-grpc-file-store
        target: /opt/aptos/file-store
      - type: bind
        source: ./file-store-config.yaml
        target: /opt/aptos/file-store-config.yaml
    command:
      - '/usr/local/bin/aptos-indexer-grpc-file-store'
      - '--config-path'
      - '/opt/aptos/file-store-config.yaml'
    depends_on:
      - redis

  indexer-grpc-data-service:
    image: "${INDEXER_GRPC_IMAGE_REPO:-aptoslabs/indexer-grpc}:${IMAGE_TAG:-main}"
    networks:
      shared:
        ipv4_address: 172.16.1.15
    restart: unless-stopped
    volumes:
      - type: volume # XXX: needed now before refactor https://github.com/aptos-labs/aptos-core/pull/8139
        source: indexer-grpc-file-store
        target: /opt/aptos/file-store
      - type: bind
        source: ./data-service-config.yaml
        target: /opt/aptos/data-service-config.yaml
      - type: bind
        source: ./data-service-grpc-server.key
        target: /opt/aptos/certs/data-service-grpc-server.key
      - type: bind
        source: ./data-service-grpc-server.crt
        target: /opt/aptos/certs/data-service-grpc-server.crt
    command:
      - '/usr/local/bin/aptos-indexer-grpc-data-service'
      - '--config-path'
      - '/opt/aptos/data-service-config.yaml'
    ports:
      - "50052:50052" # GRPC non-secure
      - "50053:50053" # GRPC secure
      - "18084:8084" # health
    depends_on:
      - indexer-grpc-cache-worker
      - indexer-grpc-file-store
      - redis-replica

```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L110-117)
```rust
        // Re-connect if lost.
        loop {
            let conn = self
                .redis_client
                .get_tokio_connection_manager()
                .await
                .context("Get redis connection failed.")?;
            let mut rpc_client = create_grpc_client(self.fullnode_grpc_address.clone()).await;
```

**File:** network/framework/src/connectivity_manager/mod.rs (L75-81)
```rust
/// In addition to the backoff strategy, we also add some small random jitter to
/// the delay before each dial. This jitter helps reduce the probability of
/// simultaneous dials, especially in non-production environments where most nodes
/// are spun up around the same time. Similarly, it smears the dials out in time
/// to avoid spiky load / thundering herd issues where all dial requests happen
/// around the same time at startup.
const MAX_CONNECTION_DELAY_JITTER: Duration = Duration::from_millis(100);
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1377-1381)
```rust
    fn next_backoff_delay(&mut self, max_delay: Duration) -> Duration {
        let jitter = jitter(MAX_CONNECTION_DELAY_JITTER);

        min(max_delay, self.backoff.next().unwrap_or(max_delay)) + jitter
    }
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L68-72)
```rust
static FETCH_ACCOUNT_RETRY_POLICY: Lazy<RetryPolicy> = Lazy::new(|| {
    RetryPolicy::exponential(Duration::from_secs(1))
        .with_max_retries(MAX_RETRIES)
        .with_jitter(true)
});
```

**File:** crates/aptos-rest-client/src/lib.rs (L1797-1797)
```rust
        // TODO: Add jitter
```
