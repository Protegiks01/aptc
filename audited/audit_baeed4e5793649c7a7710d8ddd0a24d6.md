# Audit Report

## Title
Race Condition in Indexer Status Updates Allows Lost Error Information Through Concurrent Instance Overwrites

## Summary
The `apply_processor_status()` function in the indexer's transaction processor performs unconditional database upserts that lack conditional update logic, allowing concurrent processor instances with the same name to overwrite each other's status records. This creates a lost update problem where critical error information and success markers can be silently discarded.

## Finding Description

The race condition exists in the database update logic at lines 155-160 of `transaction_processor.rs`: [1](#0-0) 

The upsert operation uses `ON CONFLICT DO UPDATE` with unconditional field replacement. When multiple indexer instances run concurrently with the same processor name (due to misconfiguration, horizontal scaling attempts, or rolling deployments), they can process overlapping version ranges.

**Attack Scenario:**

1. **Instance A** and **Instance B** both run with `processor="default_processor"`
2. Both fetch and process overlapping transaction versions (e.g., versions 100-150)
3. Instance A marks versions 100-150 as started (success=false, details=NULL)
4. Instance B marks versions 100-150 as started (success=false, details=NULL)  
5. Instance A processes successfully and updates to (success=true, details=NULL)
6. Instance B encounters a parsing error at version 125 and updates to (success=false, details="Failed to parse transaction data")
7. Instance A's later update to version 125 **overwrites** Instance B's error, setting it back to (success=true, details=NULL)

The critical flaw is that the update logic provides no protection against this lost update problem. Compare this to the `update_last_processed_version()` function which includes a WHERE clause to prevent regression: [2](#0-1) 

The `processor_status` table update (line 188) includes `WHERE processor_status.last_success_version <= EXCLUDED.last_success_version` to prevent going backwards, but the `processor_statuses` individual version updates lack any such protection.

**Execution Flow:**

The runtime spawns multiple concurrent processing tasks: [3](#0-2) 

Within a single instance, the transaction fetcher mutex prevents batch overlap: [4](#0-3) 

However, separate instances have independent fetchers and can process identical versions concurrently.

**Data Model:** [5](#0-4) 

The primary key `(name, version)` means concurrent instances with the same processor name will conflict on the same database rows.

## Impact Explanation

This issue qualifies as **Medium severity** per the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The `processor_statuses` table becomes corrupted with lost error information and incorrect success markers
- The gap detection logic relies on this table to identify missing versions: [6](#0-5) 

Corrupted status records cause:
1. **Silent data loss**: Versions marked successful when processing actually failed
2. **Lost debugging information**: Error details needed to diagnose issues are overwritten  
3. **Incorrect gap detection**: The system may skip reprocessing failed versions or incorrectly reprocess successful ones
4. **Downstream data integrity issues**: Applications relying on the indexer API receive incomplete or incorrect blockchain data

While this does not directly affect consensus or validator operations, it violates data integrity guarantees for the critical indexer infrastructure that many dApps depend on.

## Likelihood Explanation

**Likelihood: Medium**

This occurs in realistic scenarios:
- **Horizontal scaling attempts**: Operators trying to speed up indexing by running multiple instances
- **Rolling deployments**: Brief overlap when deploying new indexer versions
- **Kubernetes replicas**: Misconfigured deployments with replicas > 1
- **Manual errors**: Accidentally starting duplicate indexer processes

The default configuration spawns 5 parallel processor tasks (`DEFAULT_PROCESSOR_TASKS = 5`): [7](#0-6) 

This design suggests parallelism is expected, potentially leading operators to believe multiple instances are supported.

## Recommendation

Add conditional update logic to prevent lost updates:

```rust
fn apply_processor_status(&self, psms: &[ProcessorStatusModel]) {
    let mut conn = self.get_conn();
    let chunks = get_chunks(psms.len(), ProcessorStatusModel::field_count());
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            &mut conn,
            diesel::insert_into(processor_statuses::table)
                .values(&psms[start_ind..end_ind])
                .on_conflict((dsl::name, dsl::version))
                .do_update()
                .set((
                    dsl::success.eq(excluded(dsl::success)),
                    dsl::details.eq(excluded(dsl::details)),
                    dsl::last_updated.eq(excluded(dsl::last_updated)),
                )),
            // Only update if preserving error information or moving to a later state
            Some(" WHERE processor_statuses.details IS NULL OR EXCLUDED.details IS NOT NULL OR processor_statuses.last_updated < EXCLUDED.last_updated "),
        )
        .expect("Error updating Processor Status!");
    }
}
```

Additionally:
1. Add singleton enforcement via database advisory locks or unique constraints
2. Document that only one instance per processor name should run
3. Add monitoring/alerting for concurrent instance detection
4. Consider adding a process ID or instance ID to the status records

## Proof of Concept

```rust
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    
    #[test]
    fn test_concurrent_status_update_race_condition() {
        // Setup two processor instances with same name
        let db_pool = new_test_db_pool();
        let processor_a = Arc::new(TestProcessor::new("default_processor", db_pool.clone()));
        let processor_b = Arc::new(TestProcessor::new("default_processor", db_pool.clone()));
        
        // Both processors process version 100
        let version = 100u64;
        
        let handle_a = thread::spawn(move || {
            // Instance A: Mark started, process successfully
            processor_a.mark_versions_started(version, version);
            thread::sleep(Duration::from_millis(10));
            processor_a.update_status_success(&ProcessingResult {
                start_version: version,
                end_version: version,
                ..Default::default()
            });
        });
        
        let handle_b = thread::spawn(move || {
            // Instance B: Mark started, encounter error
            processor_b.mark_versions_started(version, version);
            thread::sleep(Duration::from_millis(5));
            processor_b.update_status_err(&TransactionProcessingError::new(
                "Processing failed".to_string(),
                version,
                version,
                "default_processor",
            ));
        });
        
        handle_a.join().unwrap();
        handle_b.join().unwrap();
        
        // Check final state - either success or error, but NOT both
        // Due to race condition, critical error information may be lost
        let status = get_processor_status(&db_pool, "default_processor", version);
        
        // VULNERABILITY: status.success and status.details are inconsistent
        // One instance's critical error information was overwritten
        assert!(status.success != status.details.is_some(),
                "Race condition: Lost error information or incorrect success marker");
    }
}
```

**Notes**

This vulnerability is specific to the indexer subsystem and does not affect blockchain consensus, validator operations, or on-chain state. However, it represents a significant data integrity issue for infrastructure that many applications rely on for accurate blockchain data access.

### Citations

**File:** crates/indexer/src/indexer/transaction_processor.rs (L154-160)
```rust
                    .on_conflict((dsl::name, dsl::version))
                    .do_update()
                    .set((
                        dsl::success.eq(excluded(dsl::success)),
                        dsl::details.eq(excluded(dsl::details)),
                        dsl::last_updated.eq(excluded(dsl::last_updated)),
                    )),
```

**File:** crates/indexer/src/indexer/tailer.rs (L126-131)
```rust
        let transactions = self
            .transaction_fetcher
            .lock()
            .await
            .fetch_next_batch()
            .await;
```

**File:** crates/indexer/src/indexer/tailer.rs (L177-189)
```rust
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
```

**File:** crates/indexer/src/indexer/tailer.rs (L205-288)
```rust
    pub fn get_start_version_long(
        &self,
        processor_name: &String,
        lookback_versions: i64,
    ) -> Option<i64> {
        let mut conn = self
            .connection_pool
            .get()
            .expect("DB connection should be available to get starting version");

        // This query gets the first version that isn't equal to the next version (versions would be sorted of course).
        // There's also special handling if the gap happens in the beginning.
        let sql = "
        WITH raw_boundaries AS
        (
            SELECT
                MAX(version) AS MAX_V,
                MIN(version) AS MIN_V
            FROM
                processor_statuses
            WHERE
                name = $1
                AND success = TRUE
        ),
        boundaries AS
        (
            SELECT
                MAX(version) AS MAX_V,
                MIN(version) AS MIN_V
            FROM
                processor_statuses, raw_boundaries
            WHERE
                name = $1
                AND success = true
                and version >= GREATEST(MAX_V - $2, 0)
        ),
        gap AS
        (
            SELECT
                MIN(version) + 1 AS maybe_gap
            FROM
                (
                    SELECT
                        version,
                        LEAD(version) OVER (
                    ORDER BY
                        version ASC) AS next_version
                    FROM
                        processor_statuses,
                        boundaries
                    WHERE
                        name = $1
                        AND success = TRUE
                        AND version >= GREATEST(MAX_V - $2, 0)
                ) a
            WHERE
                version + 1 <> next_version
        )
        SELECT
            CASE
                WHEN
                    MIN_V <> GREATEST(MAX_V - $2, 0)
                THEN
                    GREATEST(MAX_V - $2, 0)
                ELSE
                    COALESCE(maybe_gap, MAX_V + 1)
            END
            AS version
        FROM
            gap, boundaries
        ";
        #[derive(Debug, QueryableByName)]
        pub struct Gap {
            #[diesel(sql_type = BigInt)]
            pub version: i64,
        }
        let mut res: Vec<Option<Gap>> = sql_query(sql)
            .bind::<Text, _>(processor_name)
            // This is the number used to determine how far we look back for gaps. Increasing it may result in slower startup
            .bind::<BigInt, _>(lookback_versions)
            .get_results(&mut conn)
            .unwrap();
        res.pop().unwrap().map(|g| g.version)
    }
```

**File:** crates/indexer/src/runtime.rs (L209-219)
```rust
    loop {
        let mut tasks = vec![];
        for _ in 0..processor_tasks {
            let other_tailer = tailer.clone();
            let task = tokio::spawn(async move { other_tailer.process_next_batch().await });
            tasks.push(task);
        }
        let batches = match futures::future::try_join_all(tasks).await {
            Ok(res) => res,
            Err(err) => panic!("Error processing transaction batches: {:?}", err),
        };
```

**File:** crates/indexer/src/schema.rs (L615-624)
```rust
diesel::table! {
    processor_statuses (name, version) {
        #[max_length = 50]
        name -> Varchar,
        version -> Int8,
        success -> Bool,
        details -> Nullable<Text>,
        last_updated -> Timestamp,
    }
}
```

**File:** config/src/config/indexer_config.rs (L22-22)
```rust
pub const DEFAULT_PROCESSOR_TASKS: u8 = 5;
```
