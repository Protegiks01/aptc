# Audit Report

## Title
Async Cancellation Vulnerability: Untracked Background Tasks Lead to Resource Leaks and Inconsistent State in NFT Metadata Crawler

## Summary
The NFT metadata crawler's `AssetUploaderThrottlerContext` spawns untracked background tasks that perform database operations and external API calls. When the service is cancelled or receives a shutdown signal (SIGTERM), these tasks are abruptly terminated without cleanup, leading to database connection leaks, inconsistent database state, and orphaned in-progress work.

## Finding Description

The vulnerability exists in the async task spawning pattern used by the NFT metadata crawler. The service spawns fire-and-forget background tasks without implementing any graceful shutdown mechanism.

**The Issue Chain:**

1. The `main()` function calls `args.run()` which delegates to the indexer-grpc-server-framework [1](#0-0) 

2. The framework spawns tasks using `tokio::select!` but doesn't track JoinHandles or implement graceful shutdown [2](#0-1) 

3. The NFT crawler's `run()` method creates database connections and server contexts [3](#0-2) 

4. **Critical vulnerability**: The `AssetUploaderThrottlerContext::build_router()` spawns two untracked background tasks with infinite loops [4](#0-3) 

5. The first spawned task runs `handle_upload_assets()` in an infinite loop, continuously processing uploads from the queue [5](#0-4) 

6. Inside the upload loop, nested `tokio::spawn` calls are made for each asset upload operation [6](#0-5) 

**Exploitation Scenario:**

When the service receives SIGTERM (standard shutdown signal) or the tokio task is cancelled:
- Background tasks are immediately dropped without running any cleanup code
- Database connections held by these tasks are not returned to the pool
- If a task is mid-transaction when cancelled, partial writes may occur
- Assets marked as "in_progress_assets" remain in that state permanently
- The upload queue state is lost

**No Graceful Shutdown:**
- No signal handlers are registered (verified by grep search showing zero matches for "signal|shutdown|graceful|SIGTERM")
- No CancellationToken or shutdown coordination mechanism exists
- JoinHandles from spawned tasks are not stored or awaited
- Database transactions are not wrapped in Drop handlers

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

The impact includes:

1. **Database Connection Leaks**: When tasks holding pooled connections are abruptly cancelled, connections are not returned to the pool, eventually exhausting available connections and causing service unavailability

2. **Inconsistent Database State**: The `update_request_status()` function performs upserts without transaction boundaries. If cancelled mid-operation, the database may contain partial or inconsistent request status records [7](#0-6) 

3. **Orphaned In-Progress Assets**: Assets in the `in_progress_assets` set when cancellation occurs will never be processed or cleaned up, requiring manual database intervention

4. **Lost Work**: The in-memory upload queue is lost on cancellation, requiring re-discovery of failed uploads from the database

While this doesn't directly impact consensus or validator operations (the NFT metadata crawler is an ecosystem service, not a consensus-critical component), it causes operational issues requiring manual intervention to restore service integrity.

## Likelihood Explanation

**High Likelihood** - This occurs on every service restart or deployment:

1. **Normal Operations**: Standard deployment practices involve sending SIGTERM to gracefully stop services
2. **Container Orchestration**: Kubernetes and other orchestrators send SIGTERM when redeploying pods
3. **Manual Operations**: Operators routinely restart services for maintenance
4. **Automatic Triggers**: Health check failures or resource constraints trigger restarts

This is not a rare edge case but a guaranteed issue on every service shutdown that doesn't use SIGKILL.

## Recommendation

Implement proper graceful shutdown handling:

1. **Add Signal Handlers**:
```rust
use tokio::signal;
use tokio_util::sync::CancellationToken;

async fn run_with_shutdown() -> Result<()> {
    let shutdown_token = CancellationToken::new();
    
    // Spawn signal handler
    let shutdown_token_clone = shutdown_token.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        shutdown_token_clone.cancel();
    });
    
    // Pass shutdown token to all spawned tasks
    // ...
}
```

2. **Track Spawned Tasks**:
```rust
impl Server for AssetUploaderThrottlerContext {
    fn build_router(&self) -> Router {
        let self_arc = Arc::new(self.clone());
        
        // Store JoinHandles
        let handle1 = tokio::spawn(async move {
            self_arc_clone.handle_upload_assets().await;
        });
        
        let handle2 = tokio::spawn(async move {
            self_arc_clone.start_update_loop().await?;
            anyhow::Ok(())
        });
        
        // Store handles for graceful shutdown
        // (requires refactoring to return handles or use shared state)
    }
}
```

3. **Modify Infinite Loops to Check Cancellation**:
```rust
async fn handle_upload_assets(&self, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("Graceful shutdown initiated, cleaning up...");
                // Cleanup logic here
                break;
            }
            _ = self.process_next_upload() => {}
        }
    }
}
```

4. **Wrap Database Operations in Transactions**: Ensure atomicity even during cancellation

## Proof of Concept

**Reproduction Steps**:

1. Configure NFT metadata crawler with `AssetUploaderThrottler` server config:
```yaml
health_check_port: 8080
server_config:
  type: AssetUploaderThrottler
  cloudflare_account_id: "test"
  cloudflare_auth_key: "test"
  cloudflare_account_hash: "test"
  cloudflare_image_delivery_prefix: "https://test"
  cloudflare_default_variant: "public"
  asset_uploader_worker_uri: "http://localhost:8081"
  poll_interval_seconds: 10
  poll_rows_limit: 100
```

2. Start the service:
```bash
cargo run --bin aptos-nft-metadata-crawler -- --config-path config.yaml
```

3. Populate the database with asset upload requests

4. Observe background tasks spawned and processing uploads

5. Send SIGTERM:
```bash
kill -SIGTERM <pid>
```

6. Observe in logs:
   - "Main task panicked or was shutdown" error
   - No cleanup messages
   - Database connections not released (check `pg_stat_activity`)

7. Query database to confirm orphaned state:
```sql
    -- Assets stuck in progress (never completed due to abrupt termination)
SELECT COUNT(*) FROM asset_uploader_request_statuses 
WHERE status_code != 200;
```

**Expected Result**: Service terminates immediately, connections leak, some assets remain in inconsistent state

**Desired Result**: Service performs graceful shutdown, waits for in-flight requests, closes all connections cleanly

### Citations

**File:** ecosystem/nft-metadata-crawler/src/main.rs (L7-11)
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = <ServerArgs as clap::Parser>::parse();
    args.run::<NFTMetadataCrawlerConfig>().await
}
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

**File:** ecosystem/nft-metadata-crawler/src/config.rs (L86-104)
```rust
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

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/throttler/mod.rs (L205-305)
```rust
    async fn handle_upload_assets(&self) {
        let self_arc = Arc::new(self.clone());
        loop {
            // Wait until notified if rate limited
            while self.is_rate_limited.load(Ordering::Relaxed) {
                self.rate_limit_over_notify.notified().await;
                self.is_rate_limited.store(false, Ordering::Relaxed);
            }

            // Wait until notified if queue is empty
            while self.upload_queue.lock().await.asset_queue.is_empty() {
                self.inserted_notify.notified().await;
            }

            // Pop the first asset from the queue and add it to the in-progress set
            let mut upload_queue = self.upload_queue.lock().await;
            // Should be safe to unwrap because we checked if the queue is empty, but log in case
            let Some(asset) = upload_queue.asset_queue.pop_first() else {
                warn!(
                    queue = ?upload_queue,
                    "Asset queue is empty, despite being notified"
                );
                continue;
            };
            upload_queue.in_progress_assets.insert(asset.clone());
            drop(upload_queue);

            // Upload the asset in a separate task
            // If successful, remove the asset from the in-progress set and continue to next asset
            // If rate limited, sleep for 5 minutes then notify
            // If unsuccessful due to conflict, attempt to lookup the asset in Cloudflare
            // If unsuccessful for other reason, add the asset back to the queue
            let self_clone = self_arc.clone();
            tokio::spawn(async move {
                // Handle upload depending on previous attempt status.
                // If previous attempt resulted in a 409, the asset likely already exists, so we call a different endpoint on the worker to perform the lookup.
                let upload_res = match ReqwestStatusCode::from_u16(asset.status_code as u16)? {
                    ReqwestStatusCode::CONFLICT => {
                        self_clone.get_from_cloudflare(asset.clone()).await
                    },
                    _ => self_clone.upload_asset(asset.clone()).await,
                };

                let mut upload_queue = self_clone.upload_queue.lock().await;
                match upload_res {
                    Ok(asset) => {
                        let mut asset = asset;
                        match ReqwestStatusCode::from_u16(asset.status_code as u16)? {
                            ReqwestStatusCode::OK => {
                                // If success, remove asset from in-progress set and end early
                                upload_queue.in_progress_assets.remove(&asset);
                                anyhow::Ok(())
                            },
                            ReqwestStatusCode::TOO_MANY_REQUESTS => {
                                // If rate limited, sleep for 5 minutes then notify
                                self_clone.is_rate_limited.store(true, Ordering::Relaxed);
                                tokio::time::sleep(FIVE_MINUTES).await;
                                self_clone.rate_limit_over_notify.notify_one();
                                Ok(())
                            },
                            ReqwestStatusCode::CONFLICT => {
                                // If conflict, attempt to get cdn_image_uri from parsed_asset_uris table
                                if let Some(parsed_asset_uri) =
                                    ParsedAssetUrisQuery::get_by_asset_uri(
                                        &mut self_clone.pool.get()?,
                                        &asset.asset_uri,
                                    )
                                {
                                    // If cdn_image_uri found, update asset and request status
                                    if let Some(cdn_image_uri) = parsed_asset_uri.cdn_image_uri {
                                        asset.cdn_image_uri = Some(cdn_image_uri);
                                        self_clone.update_request_status(&asset)?;
                                        return Ok(());
                                    }
                                }

                                // If cdn_image_uri still not found and num_failures < 3, add asset back to queue.
                                if asset.cdn_image_uri.is_none() && asset.num_failures < 3 {
                                    self_clone.update_request_status(&asset)?;
                                    upload_queue.asset_queue.insert(asset);
                                    self_clone.inserted_notify.notify_one();
                                    return Ok(());
                                }

                                // Remove asset from in-progress set and end early.
                                // No point in retrying more than 3 times because the asset already exists and could not be found in Postgrs or Cloudflare.
                                upload_queue.in_progress_assets.remove(&asset);
                                Ok(())
                            },
                            _ => Ok(()),
                        }
                    },
                    Err(e) => {
                        error!(error = ?e, asset_uri = asset.asset_uri, "[Asset Uploader Throttler] Error uploading asset");
                        upload_queue.asset_queue.insert(asset);
                        Ok(())
                    },
                }
            });
        }
    }
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/throttler/mod.rs (L354-373)
```rust
    fn update_request_status(&self, asset: &AssetUploaderRequestStatuses) -> anyhow::Result<()> {
        use schema::nft_metadata_crawler::asset_uploader_request_statuses::dsl::*;

        let query = diesel::insert_into(asset_uploader_request_statuses)
            .values(asset)
            .on_conflict((idempotency_key, application_id, asset_uri))
            .do_update()
            .set((
                status_code.eq(excluded(status_code)),
                error_messages.eq(excluded(error_messages)),
                cdn_image_uri.eq(excluded(cdn_image_uri)),
                num_failures.eq(excluded(num_failures)),
                inserted_at.eq(excluded(inserted_at)),
            ));

        let debug_query = diesel::debug_query::<diesel::pg::Pg, _>(&query).to_string();
        debug!("Executing Query: {}", debug_query);
        query.execute(&mut self.pool.get()?)?;
        Ok(())
    }
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/throttler/mod.rs (L376-395)
```rust
impl Server for AssetUploaderThrottlerContext {
    fn build_router(&self) -> axum::Router {
        let self_arc = Arc::new(self.clone());

        let self_arc_clone = self_arc.clone();
        tokio::spawn(async move {
            self_arc_clone.handle_upload_assets().await;
        });

        let self_arc_clone = self_arc.clone();
        tokio::spawn(async move {
            self_arc_clone.start_update_loop().await?;
            anyhow::Ok(())
        });

        axum::Router::new()
            .route("/update_queue", post(Self::handle_update_queue))
            .layer(Extension(self_arc.clone()))
    }
}
```
