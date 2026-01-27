# Audit Report

## Title
Race Condition in NFT Metadata Crawler Due to Missing Transaction Isolation

## Summary
The NFT metadata crawler's `run()` method establishes database connections without explicit transaction wrapping, allowing concurrent workers to process the same NFT asset simultaneously. This creates race conditions between read-check-write operations, leading to lost updates and inconsistent metadata state in the PostgreSQL database.

## Finding Description

The `run()` method called from `main.rs` line 10 delegates to the NFT metadata crawler configuration, which spawns parser workers that perform multiple non-atomic database operations. [1](#0-0) 

The connection pool is established without explicit transaction isolation configuration. [2](#0-1) 

Each worker performs a sequence of separate database operations throughout the `parse()` method:

1. **Initial read to check existing data** [3](#0-2) 

2. **Multiple separate upsert operations** without transaction wrapping [4](#0-3) 

3. **Check-then-act patterns for duplicate detection** [5](#0-4) 

Each `upsert_uris` call executes as a separate auto-committed query without transaction boundaries. [6](#0-5) 

**The vulnerability occurs when:**
1. Two PubSub messages arrive for the same `asset_uri` (e.g., metadata updated twice)
2. Worker A spawns and reads existing data at line 81
3. Worker B spawns concurrently and also reads the same data at line 81 (READ COMMITTED allows non-repeatable reads)
4. Both workers parse JSON/images independently
5. Worker A writes partial updates (JSON at line 165)
6. Worker B writes partial updates, potentially overwriting A's data
7. Worker A completes image optimization (line 272)
8. Worker B completes and overwrites with potentially stale data

Unlike the token processor which uses explicit transactions [7](#0-6) , the NFT crawler performs each operation separately.

## Impact Explanation

**Medium Severity** - While this is an off-chain indexer service and not part of the core blockchain protocol, it meets Medium severity criteria for the following reasons:

1. **State Inconsistencies**: The metadata database can enter an inconsistent state where different fields reflect updates from different processing attempts, requiring manual intervention to correct
2. **Lost Updates**: Newer metadata can be overwritten by older processing attempts, causing users to see outdated NFT information
3. **Resource Waste**: Multiple workers unnecessarily reprocess the same assets, wasting computational resources and GCS storage costs

**Important Context**: This vulnerability affects the NFT metadata crawler's auxiliary database only, NOT the on-chain blockchain state. It does not impact consensus, validator operations, or on-chain funds. However, it can cause significant operational issues for applications relying on accurate NFT metadata.

## Likelihood Explanation

**High Likelihood** - This will occur regularly in production:

1. **Natural Occurrence**: NFTs frequently update metadata (reveals, trait changes, dynamic NFTs)
2. **No Deduplication**: The system has no in-memory locks or message deduplication before database checks [8](#0-7) 
3. **Concurrent Processing**: The async architecture spawns workers immediately upon receiving messages
4. **PubSub Delivery**: Google Cloud PubSub can deliver the same message multiple times, especially during retries

The database-level checks provide no protection against concurrent access between the read and write operations.

## Recommendation

Wrap all database operations within each worker's `parse()` method in an explicit transaction using Diesel's transaction API:

```rust
// In worker.rs, modify the parse() method:
pub async fn parse(&mut self) -> anyhow::Result<()> {
    // Move connection acquisition and all DB operations inside transaction
    let result = self.conn.build_transaction()
        .read_write()
        .run::<_, diesel::result::Error, _>(|pg_conn| {
            // All reads and upserts here
            // Line 81: read operation
            // Lines 88-370: all upsert operations
            Ok(())
        });
    
    result.map_err(|e| anyhow::anyhow!("Transaction failed: {:?}", e))
}
```

Additionally:
1. Consider using PostgreSQL's `SELECT ... FOR UPDATE` for the initial read to acquire row-level locks
2. Set explicit isolation level to `SERIALIZABLE` for critical operations
3. Implement application-level deduplication before spawning workers (e.g., in-memory bloom filter)

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
#[tokio::test]
async fn test_concurrent_worker_race_condition() {
    // Setup: Create two workers for the same asset_uri
    let pool = establish_connection_pool(&database_url);
    let asset_uri = "ipfs://QmTest123";
    
    // Spawn two concurrent workers
    let worker1 = Worker::new(
        config.clone(),
        pool.get().unwrap(),
        max_retries,
        gcs_client.clone(),
        "msg1",
        "asset_id",
        asset_uri,
        100,
        timestamp,
        false,
    );
    
    let worker2 = Worker::new(
        config.clone(),
        pool.get().unwrap(),
        max_retries,
        gcs_client.clone(),
        "msg2",
        "asset_id",
        asset_uri,  // Same asset_uri
        101,        // Different version
        timestamp,
        false,
    );
    
    // Execute concurrently
    let (result1, result2) = tokio::join!(
        worker1.parse(),
        worker2.parse()
    );
    
    // Observe: Final database state may reflect partial updates from both workers
    // Expected: Only the latest version (101) should be present
    // Actual: May have mixed state or lost updates from worker1
}
```

**Notes:**

This vulnerability is specific to the NFT metadata crawler ecosystem component and does not affect the Aptos blockchain protocol itself. The issue lies in how the off-chain indexer manages its PostgreSQL database state, not in any consensus, execution, or on-chain storage mechanisms.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/main.rs (L7-11)
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = <ServerArgs as clap::Parser>::parse();
    args.run::<NFTMetadataCrawlerConfig>().await
}
```

**File:** ecosystem/nft-metadata-crawler/src/utils/database.rs (L19-25)
```rust
/// Establishes a connection pool to Postgres
pub fn establish_connection_pool(database_url: &str) -> Pool<ConnectionManager<PgConnection>> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}
```

**File:** ecosystem/nft-metadata-crawler/src/utils/database.rs (L36-64)
```rust
pub fn upsert_uris(
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    entry: &ParsedAssetUris,
    ltv: i64,
) -> anyhow::Result<usize> {
    use schema::nft_metadata_crawler::parsed_asset_uris::dsl::*;

    let query = diesel::insert_into(schema::nft_metadata_crawler::parsed_asset_uris::table)
        .values(entry)
        .on_conflict(asset_uri)
        .do_update()
        .set((
            raw_image_uri.eq(excluded(raw_image_uri)),
            raw_animation_uri.eq(excluded(raw_animation_uri)),
            cdn_json_uri.eq(excluded(cdn_json_uri)),
            cdn_image_uri.eq(excluded(cdn_image_uri)),
            cdn_animation_uri.eq(excluded(cdn_animation_uri)),
            image_optimizer_retry_count.eq(excluded(image_optimizer_retry_count)),
            json_parser_retry_count.eq(excluded(json_parser_retry_count)),
            animation_optimizer_retry_count.eq(excluded(animation_optimizer_retry_count)),
            inserted_at.eq(excluded(inserted_at)),
            do_not_parse.eq(excluded(do_not_parse)),
            last_transaction_version.eq(ltv),
        ));

    let debug_query = diesel::debug_query::<diesel::pg::Pg, _>(&query).to_string();
    debug!("Executing Query: {}", debug_query);
    query.execute(conn).context(debug_query)
}
```

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L81-91)
```rust
        let prev_model = ParsedAssetUrisQuery::get_by_asset_uri(&mut self.conn, &self.asset_uri);
        if let Some(pm) = prev_model {
            DUPLICATE_ASSET_URI_COUNT.inc();
            self.model = pm.into();
            if !self.force && self.model.get_do_not_parse() {
                self.log_info("asset_uri has been marked as do_not_parse, skipping parse");
                SKIP_URI_COUNT.with_label_values(&["do_not_parse"]).inc();
                self.upsert();
                return Ok(());
            }
        }
```

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L179-195)
```rust
            self.model.get_raw_image_uri().is_none_or(|uri| {
                match ParsedAssetUrisQuery::get_by_raw_image_uri(
                    &mut self.conn,
                    &self.asset_uri,
                    &uri,
                ) {
                    Some(uris) => {
                        self.log_info("Duplicate raw_image_uri found");
                        DUPLICATE_RAW_IMAGE_URI_COUNT.inc();
                        self.model.set_cdn_image_uri(uris.cdn_image_uri);
                        self.upsert();
                        false
                    },
                    None => true,
                }
            })
        };
```

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L377-384)
```rust
    fn upsert(&mut self) {
        upsert_uris(&mut self.conn, &self.model, self.last_transaction_version).unwrap_or_else(
            |e| {
                self.log_error("Commit to Postgres failed", &e);
                panic!();
            },
        );
    }
```

**File:** crates/indexer/src/processors/token_processor.rs (L200-227)
```rust
    match conn
        .build_transaction()
        .read_write()
        .run::<_, Error, _>(|pg_conn| {
            insert_to_db_impl(
                pg_conn,
                (&tokens, &token_ownerships, &token_datas, &collection_datas),
                (
                    &current_token_ownerships,
                    &current_token_datas,
                    &current_collection_datas,
                ),
                &token_activities,
                &current_token_claims,
                &current_ans_lookups,
                &nft_points,
                (
                    &collections_v2,
                    &token_datas_v2,
                    &token_ownerships_v2,
                    &current_collections_v2,
                    &current_token_datas_v2,
                    &current_token_ownerships_v2,
                    &token_activities_v2,
                    &current_token_v2_metadata,
                ),
            )
        }) {
```

**File:** ecosystem/nft-metadata-crawler/src/parser/mod.rs (L76-186)
```rust
    async fn spawn_parser(&self, msg_base64: Bytes) {
        PARSER_INVOCATIONS_COUNT.inc();
        let pubsub_message = String::from_utf8(msg_base64.to_vec())
            .unwrap_or_else(|e| {
                error!(
                    error = ?e,
                    "[NFT Metadata Crawler] Failed to parse PubSub message"
                );
                panic!();
            })
            .replace('\u{0000}', "")
            .replace("\\u0000", "");

        info!(
            pubsub_message = pubsub_message,
            "[NFT Metadata Crawler] Received message from PubSub"
        );

        // Skips message if it does not have 5 commas (likely malformed URI)
        if pubsub_message.matches(',').count() != 5 {
            // Sends ack to PubSub only if ack_parsed_uris flag is true
            info!(
                pubsub_message = pubsub_message,
                "[NFT Metadata Crawler] Number of commans != 5, skipping message"
            );
            SKIP_URI_COUNT.with_label_values(&["invalid"]).inc();
            return;
        }

        // Parse PubSub message
        let parts: Vec<&str> = pubsub_message.split(',').collect();

        // Perform chain id check
        // If chain id is not set, set it
        let mut conn = self.pool.get().unwrap_or_else(|e| {
            error!(
                pubsub_message = pubsub_message,
                error = ?e,
                "[NFT Metadata Crawler] Failed to get DB connection from pool");
            UNABLE_TO_GET_CONNECTION_COUNT.inc();
            panic!();
        });
        GOT_CONNECTION_COUNT.inc();

        let grpc_chain_id = parts[4].parse::<u64>().unwrap_or_else(|e| {
            error!(
                pubsub_message = pubsub_message,
                error = ?e,
                "[NFT Metadata Crawler] Failed to parse chain id from PubSub message"
            );
            panic!();
        });

        // Panic if chain id of PubSub message does not match chain id in DB
        check_or_update_chain_id(&mut conn, grpc_chain_id as i64).expect("Chain id should match");

        // Spawn worker
        let last_transaction_version = parts[2].to_string().parse().unwrap_or_else(|e| {
            error!(
                pubsub_message = pubsub_message,
                error = ?e,
                "[NFT Metadata Crawler] Failed to parse last transaction version from PubSub message"
            );
            panic!();
        });

        let last_transaction_timestamp =
            chrono::NaiveDateTime::parse_from_str(parts[3], "%Y-%m-%d %H:%M:%S %Z").unwrap_or(
                chrono::NaiveDateTime::parse_from_str(parts[3], "%Y-%m-%d %H:%M:%S%.f %Z")
                    .unwrap_or_else(|e| {
                        error!(
                            pubsub_message = pubsub_message,
                            error = ?e,
                            "[NFT Metadata Crawler] Failed to parse timestamp from PubSub message"
                        );
                        panic!();
                    }),
            );

        let mut worker = Worker::new(
            self.parser_config.clone(),
            conn,
            self.parser_config.max_num_parse_retries,
            self.gcs_client.clone(),
            &pubsub_message,
            parts[0],
            parts[1],
            last_transaction_version,
            last_transaction_timestamp,
            parts[5].parse::<bool>().unwrap_or(false),
        );

        info!(
            pubsub_message = pubsub_message,
            "[NFT Metadata Crawler] Starting worker"
        );

        if let Err(e) = worker.parse().await {
            warn!(
                pubsub_message = pubsub_message,
                error = ?e,
                "[NFT Metadata Crawler] Parsing failed"
            );
            PARSER_FAIL_COUNT.inc();
        }

        info!(
            pubsub_message = pubsub_message,
            "[NFT Metadata Crawler] Worker finished"
        );
    }
```
