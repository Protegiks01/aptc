# Audit Report

## Title
Concurrent Processing Race Condition Causes Permanent Transaction Loss in Indexer

## Summary
The indexer's concurrent batch processing logic updates the database checkpoint with the maximum processed version across all parallel tasks, even when intermediate version ranges remain unprocessed. If the indexer crashes before all tasks complete, transactions in the unfinished batches are permanently skipped on restart, causing irreversible data loss.

## Finding Description

The indexer processes transactions through concurrent tasks that can complete in any order. The vulnerability arises from a race condition between:

1. **Concurrent batch processing** where multiple tasks fetch non-sequential transaction batches from a channel
2. **Premature checkpoint updates** that use the maximum end version across completed tasks
3. **Inadequate restart logic** that doesn't detect gaps in processed versions

**Execution Flow:**

The main processing loop spawns multiple concurrent tasks: [1](#0-0) 

Each task independently fetches and processes transactions. Results are collected and the checkpoint is calculated using the maximum end version: [2](#0-1) 

The database checkpoint is updated with this maximum value: [3](#0-2) 

**The Critical Flaw:**

The code assumes all prior versions are processed successfully, as stated in the comment: [4](#0-3) 

This assumption is **false** under concurrent processing. Consider:
- Task A processes versions 100-199
- Task B processes versions 200-299  
- Task C processes versions 300-399

If Task C finishes first, then Task A finishes, but Task B is still processing when the checkpoint update occurs:
- `batch_end_version = max(199, 399) = 399`
- Database updated: `last_success_version = 399`
- **If crash occurs now**, versions 200-299 remain unprocessed
- On restart, indexer reads version 399 and continues from 400
- **Versions 200-299 are permanently lost**

**Why Existing Protections Fail:**

A gap detection function exists that could prevent this: [5](#0-4) 

However, this function is **never called** in the codebase. The restart logic uses the simpler version that only reads the checkpoint: [6](#0-5) 

The WHERE clause in the update only prevents backwards movement, not forward jumps with gaps: [7](#0-6) 

## Impact Explanation

**Severity: HIGH** (Up to $50,000 per Aptos Bug Bounty)

This qualifies as **"State inconsistencies requiring intervention"** under Medium severity, but elevated to **HIGH** due to:

1. **Permanent Data Loss**: Lost transactions cannot be recovered without manual intervention
2. **Silent Failure**: No error detection or alerting when gaps occur
3. **Cascading Impact**: Applications relying on the indexer API receive incomplete data
4. **Index Integrity Violation**: The indexer's core guarantee of complete transaction history is broken

While this doesn't affect consensus or validator operations directly, it violates the **State Consistency** invariant for the indexer subsystem. The indexer is a critical infrastructure component that many applications depend on for querying blockchain state.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability manifests under realistic conditions:

1. **Concurrent Processing is Default**: The `processor_tasks` configuration enables parallel processing by default
2. **Variable Processing Times**: Different transaction types have different processing complexities, making out-of-order completion common
3. **Crash Scenarios**: Any unplanned restart triggers the vulnerability:
   - Out-of-memory conditions
   - Container/pod restarts in Kubernetes
   - Manual service restarts
   - Power failures
   - Process crashes from other bugs

The vulnerability requires only timing - no attacker control is needed. It occurs naturally during normal operations when the indexer restarts while processing is ongoing.

## Recommendation

**Immediate Fix: Track Minimum Contiguous Version**

Instead of updating with the maximum version, only update with the highest version where **all** previous versions have completed successfully:

```rust
// In runtime.rs, replace lines 245-252 with:
let mut batch_versions: Vec<(u64, u64)> = vec![];
for (num_txn, res) in batches {
    let processed_result: ProcessingResult = match res {
        None => continue,
        Some(Ok(res)) => res,
        Some(Err(tpe)) => { /* error handling */ },
    };
    batch_versions.push((processed_result.start_version, processed_result.end_version));
    num_res += num_txn;
}

// Sort by start version
batch_versions.sort_by_key(|&(start, _)| start);

// Find the highest contiguous end version
let mut last_contiguous_version = tailer
    .get_start_version(&processor_name)
    .unwrap_or(Some(0))
    .unwrap_or(0) as u64;

for (start, end) in batch_versions {
    if start <= last_contiguous_version + 1 {
        last_contiguous_version = std::cmp::max(last_contiguous_version, end);
    } else {
        break; // Gap detected, stop here
    }
}

tailer.update_last_processed_version(&processor_name, last_contiguous_version)
    .unwrap_or_else(|e| { /* error handling */ });
```

**Long-term Fix: Use Gap Detection on Startup**

Replace the restart logic to use the gap-aware version: [8](#0-7) 

Change to use `get_start_version_long()` with appropriate lookback window.

## Proof of Concept

**Setup:**
1. Configure indexer with `processor_tasks = 3` and `batch_size = 50`
2. Start indexer at version 0
3. Wait for concurrent processing to begin

**Trigger Conditions:**
1. Monitor logs until you see batches processing with non-sequential versions (e.g., Task 1: 100-149, Task 2: 200-249, Task 3: 150-199)
2. Kill the indexer process immediately (SIGKILL) to simulate crash
3. Check `processor_status` table: `SELECT last_success_version FROM processor_status WHERE processor='default_processor';`
4. Check `processor_statuses` table: `SELECT COUNT(*) FROM processor_statuses WHERE name='default_processor' AND success=true;`
5. Restart indexer

**Expected Result:**
- The `processor_status` shows a higher version (e.g., 249) 
- The `processor_statuses` table has gaps (e.g., missing 150-199)
- Indexer restarts from 250, permanently skipping the gap
- Query APIs return incomplete data for the missing range

**Verification:**
```sql
-- Check for gaps after restart
SELECT version + 1 AS gap_start
FROM processor_statuses 
WHERE name = 'default_processor' 
  AND success = true
  AND NOT EXISTS (
    SELECT 1 FROM processor_statuses ps2 
    WHERE ps2.name = 'default_processor' 
      AND ps2.version = processor_statuses.version + 1
      AND ps2.success = true
  )
ORDER BY version;
```

## Notes

This vulnerability is particularly insidious because:

1. **The protection exists but isn't used**: `get_start_version_long()` could detect gaps but is never called
2. **The comment is misleading**: Line 168-169 claims gaps would cause panics, but no such validation exists in the concurrent processing path  
3. **Individual version tracking is bypassed**: While `processor_statuses` tracks each version, only `processor_status` V2 is checked on restart

The fix requires both preventing gaps during processing AND detecting existing gaps on restart to ensure complete data integrity.

### Citations

**File:** crates/indexer/src/runtime.rs (L163-172)
```rust
    let starting_version_from_db_short = tailer
        .get_start_version(&processor_name)
        .unwrap_or_else(|e| panic!("Failed to get starting version: {:?}", e))
        .unwrap_or_else(|| {
            info!(
                processor_name = processor_name,
                "No starting version from db so starting from version 0"
            );
            0
        }) as u64;
```

**File:** crates/indexer/src/runtime.rs (L209-215)
```rust
    loop {
        let mut tasks = vec![];
        for _ in 0..processor_tasks {
            let other_tailer = tailer.clone();
            let task = tokio::spawn(async move { other_tailer.process_next_batch().await });
            tasks.push(task);
        }
```

**File:** crates/indexer/src/runtime.rs (L245-252)
```rust
            batch_start_version =
                std::cmp::min(batch_start_version, processed_result.start_version);
            batch_end_version = std::cmp::max(batch_end_version, processed_result.end_version);
            num_res += num_txn;
        }

        tailer
            .update_last_processed_version(&processor_name, batch_end_version)
```

**File:** crates/indexer/src/indexer/tailer.rs (L168-169)
```rust
    /// Store last processed version from database. We can assume that all previously processed
    /// versions are successful because any gap would cause the processor to panic
```

**File:** crates/indexer/src/indexer/tailer.rs (L170-190)
```rust
    pub fn update_last_processed_version(&self, processor_name: &str, version: u64) -> Result<()> {
        let mut conn = self.connection_pool.get()?;

        let status = ProcessorStatusV2 {
            processor: processor_name.to_owned(),
            last_success_version: version as i64,
        };
        execute_with_better_error(
            &mut conn,
            diesel::insert_into(processor_status::table)
                .values(&status)
                .on_conflict(processor_status::processor)
                .do_update()
                .set((
                    processor_status::last_success_version
                        .eq(excluded(processor_status::last_success_version)),
                    processor_status::last_updated.eq(excluded(processor_status::last_updated)),
                )),
            Some(" WHERE processor_status.last_success_version <= EXCLUDED.last_success_version "),
        )?;
        Ok(())
```

**File:** crates/indexer/src/indexer/tailer.rs (L194-200)
```rust
    pub fn get_start_version(&self, processor_name: &String) -> Result<Option<i64>> {
        let mut conn = self.connection_pool.get()?;

        match ProcessorStatusV2Query::get_by_processor(processor_name, &mut conn)? {
            Some(status) => Ok(Some(status.last_success_version + 1)),
            None => Ok(None),
        }
```

**File:** crates/indexer/src/indexer/tailer.rs (L203-209)
```rust
    /// Get starting version from database. Starting version is defined as the first version that's either
    /// not successful or missing from the DB.
    pub fn get_start_version_long(
        &self,
        processor_name: &String,
        lookback_versions: i64,
    ) -> Option<i64> {
```
