# Audit Report

## Title
GCS Rate Limit Not Enforced in File Store Backfiller Leading to Indexer Service Degradation

## Summary
The `max_update_frequency()` method returns 1.5 seconds to respect Google Cloud Storage (GCS) rate limits of one write per second per object, but this rate limit is completely ignored by the file store backfiller component. This can trigger GCS rate limiting errors (HTTP 429) causing indexer service failures and data availability issues.

## Finding Description

The `max_update_frequency()` method is designed to prevent GCS rate limit violations: [1](#0-0) 

This 1.5-second limit is intended to respect GCS's documented quota of "one write per second" per object, as confirmed in other parts of the codebase that implement retry logic for rate limit errors: [2](#0-1) 

However, the file store backfiller in `processor.rs` completely ignores this rate limiting. The `do_upload()` function directly calls `save_raw_file()` without any rate limiting checks: [3](#0-2) [4](#0-3) 

The backfiller spawns multiple concurrent tasks (default 16, configurable up to higher values) that all write to GCS simultaneously without coordination: [5](#0-4) 

When multiple tasks rapidly update metadata files or transaction files, especially for the same folder/batch, GCS returns HTTP 429 rate limit errors. The backfiller has no retry logic for these errors and will panic or fail, causing indexer service disruption.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **API Crashes/Service Degradation**: The indexer-grpc service provides critical APIs for querying blockchain transaction data. When the backfiller hits GCS rate limits, it fails and stops processing, causing data unavailability.

2. **State Inconsistencies**: Failed uploads create gaps in the indexed transaction history that require manual intervention to fix, meeting the Medium severity criterion of "state inconsistencies requiring intervention."

3. **Resource Limits Invariant Violation**: This breaks the documented invariant #9: "All operations must respect gas, storage, and computational limits." The code fails to respect external service (GCS) rate limits.

While this doesn't affect blockchain consensus or validator operations directly, the indexer is critical infrastructure that many applications depend on for data access.

## Likelihood Explanation

**Likelihood: High** during backfilling operations, **Medium** during normal operations.

- During backfilling with default configuration (16 concurrent tasks), rate limit violations are highly probable as tasks compete to write batch metadata files
- Each concurrent task can trigger independent writes to GCS for the same folder's metadata file when `end_batch` is true
- Operators running backfills with increased `backfill_processing_task_count` values will almost certainly trigger rate limits
- Normal steady-state indexing is less affected but can still hit limits during high transaction volume periods

The vulnerability requires no attacker action - it occurs naturally during legitimate operations.

## Recommendation

Implement proper rate limiting in the backfiller by:

1. **Respect `max_update_frequency()` in all upload paths**: Add rate limiting checks before all `save_raw_file()` calls in the backfiller
2. **Coordinate across concurrent tasks**: Use a shared rate limiter (tokio's `RwLock` + timestamp tracking) to coordinate writes across all concurrent backfill tasks
3. **Implement retry logic**: Add retry with exponential backoff for GCS 429 errors, similar to the table-info backup component
4. **Add per-folder write locks**: Prevent multiple tasks from simultaneously updating the same batch metadata file

Example fix structure:
```rust
// Add rate limiting state
struct BackfillRateLimiter {
    last_write_time: Arc<RwLock<Instant>>,
    max_frequency: Duration,
}

// In do_upload(), before each save_raw_file():
let mut last_write = self.rate_limiter.last_write_time.write().await;
let elapsed = Instant::now() - *last_write;
if elapsed < self.rate_limiter.max_frequency {
    tokio::time::sleep(self.rate_limiter.max_frequency - elapsed).await;
}
// Perform write
*last_write = Instant::now();
```

## Proof of Concept

To reproduce the rate limiting issue:

1. Configure the backfiller with high concurrency:
```yaml
backfill_processing_task_count: 32
```

2. Run the backfiller against a GCS bucket with transaction data
3. Monitor GCS API responses - you will observe HTTP 429 errors
4. The backfiller will panic/fail with "Failed to update metadata" or "Failed to save file" errors
5. Check GCS metrics to confirm rate limit violations

The issue is deterministic when `backfill_processing_task_count > 1` and batches are being processed that require metadata updates to the same folder within short time windows.

**Notes**

This vulnerability is specifically about the indexer-grpc infrastructure, not core blockchain consensus. However, the indexer is critical infrastructure that applications depend on for accessing transaction data. The lack of rate limiting enforcement represents a violation of the resource limits invariant and can cause significant service disruptions requiring manual intervention.

The `max_update_frequency()` method exists and returns the correct value, indicating the developers were aware of GCS rate limits, but the enforcement was never implemented in the backfiller code path. This represents a gap between design intent and implementation.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L139-142)
```rust
    fn max_update_frequency(&self) -> Duration {
        // NOTE: GCS has rate limiting on per object update rate at once per second.
        Duration::from_secs_f32(1.5)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L150-156)
```rust
                // https://cloud.google.com/storage/quotas
                // add retry logic due to: "Maximum rate of writes to the same object name: One write per second"
                Err(Error::Response(err)) if (err.is_retriable() && err.code == 429) => {
                    info!("Retried with rateLimitExceeded on gcs single object at epoch {} when updating the metadata", epoch);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L127-138)
```rust
            tokio_scoped::scope(|s| {
                for _ in 0..self.backfill_processing_task_count {
                    let task_version = version;
                    if task_version >= self.ending_version {
                        break;
                    }
                    let mut file_store_operator = FileStoreOperatorV2::new(
                        MAX_SIZE_PER_FILE,
                        self.num_transactions_per_folder,
                        version,
                        BatchMetadata::default(),
                    );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L241-243)
```rust
        self.file_store_writer
            .save_raw_file(path, data_file.into_inner())
            .await?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L250-255)
```rust
            self.file_store_writer
                .save_raw_file(
                    path,
                    serde_json::to_vec(&batch_metadata).map_err(anyhow::Error::msg)?,
                )
                .await?;
```
