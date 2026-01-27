# Audit Report

## Title
Stale Processor Status Records Cause False Positive Health Checks

## Summary
The health check mechanism for indexer processors only verifies that `last_success_version > 0` but completely ignores the `last_updated` timestamp field. This causes health checks to incorrectly report stuck or crashed processors as healthy when they still have old records in the `processor_status` table.

## Finding Description

The `HealthChecker::Processor` variant in both health checker implementations queries the `processor_status` table to determine if a processor is healthy. The check logic only examines whether `last_success_version > 0`, completely ignoring the `last_updated` timestamp field that tracks when the processor last successfully processed transactions. [1](#0-0) [2](#0-1) 

The `processor_status` table schema includes a `last_updated` timestamp field that is automatically updated whenever a processor successfully processes transactions: [3](#0-2) [4](#0-3) 

When a processor updates its status, both `last_success_version` and `last_updated` are modified via an UPSERT operation: [5](#0-4) 

**The Vulnerability Flow:**

1. A processor starts and successfully processes transaction version 0-100
2. The `processor_status` table records: `{processor: "default", last_success_version: 100, last_updated: "2024-01-01 10:00:00"}`
3. The processor crashes, hangs, or otherwise stops processing new transactions
4. Days/weeks later, the health check queries the database
5. It finds `last_success_version = 100 > 0` and returns `Ok(())`
6. The health check passes despite the processor being stuck for days
7. Operators see "healthy" status while the indexer serves stale data

The `last_updated` field exists in the table and is maintained correctly, but the health check logic never examines it.

## Impact Explanation

This issue falls under **Medium Severity** as indicated in the security question. It causes operational blindness where:

- **Undetected Service Degradation**: Operators cannot rely on health checks to detect stuck processors, leading to prolonged outages going unnoticed
- **Stale Data Served to Users**: The indexer API serves increasingly outdated blockchain data while reporting healthy status
- **Failed Automated Recovery**: Monitoring systems that depend on health checks won't trigger alerts or automatic restarts
- **Cascading Failures**: Other services depending on the indexer may make decisions based on stale data

While this doesn't directly cause consensus violations or fund loss, it represents a state inconsistency (monitoring state vs. actual operational state) that requires manual intervention to detect and resolve.

## Likelihood Explanation

This issue is **highly likely** to occur in production environments:

- **Common Trigger Conditions**: Processors can crash or hang due to bugs, resource exhaustion (OOM), database connection issues, network failures, or unhandled errors
- **No Special Prerequisites**: Requires no attacker interaction - happens naturally during operational failures
- **Persistent State**: Once a processor processes even one transaction, the record persists indefinitely
- **Long Detection Delay**: Without timestamp validation, the false positive can persist for days, weeks, or indefinitely until manual inspection

The health check is used during startup and by monitoring systems, making this a frequent code path. [6](#0-5) 

## Recommendation

Add timestamp-based staleness validation to the health check logic. The fix should verify that `last_updated` is within a reasonable threshold (e.g., 60 seconds, configurable based on expected processing intervals).

**Recommended Fix:**

```rust
HealthChecker::Processor(connection_string, processor_name) => {
    let mut connection = AsyncPgConnection::establish(connection_string)
        .await
        .context("Failed to connect to postgres to check processor status")?;
    
    let result = processor_status::table
        .select((
            processor_status::last_success_version,
            processor_status::last_updated,
        ))
        .filter(processor_status::processor.eq(processor_name))
        .first::<(i64, chrono::NaiveDateTime)>(&mut connection)
        .await
        .optional()
        .context("Failed to look up processor status")?;
    
    match result {
        Some((last_version, last_updated)) => {
            if last_version <= 0 {
                return Err(anyhow!(
                    "Processor {} found in DB but last_success_version is zero",
                    processor_name
                ));
            }
            
            // Check if processor updated recently (configurable threshold)
            let max_staleness_secs = 60; // Could be made configurable
            let now = chrono::Utc::now().naive_utc();
            let elapsed = now.signed_duration_since(last_updated);
            
            if elapsed.num_seconds() > max_staleness_secs {
                return Err(anyhow!(
                    "Processor {} has not updated in {} seconds (last update: {})",
                    processor_name,
                    elapsed.num_seconds(),
                    last_updated
                ));
            }
            
            info!(
                "Processor {} is healthy (version {}, updated {} seconds ago)",
                processor_name,
                last_version,
                elapsed.num_seconds()
            );
            Ok(())
        },
        None => Err(anyhow!(
            "Processor {} has not processed any transactions",
            processor_name
        )),
    }
}
```

Apply this same fix to both health checker implementations.

## Proof of Concept

```rust
#[tokio::test]
async fn test_stale_processor_status_false_positive() {
    // Setup: Create a test database and processor_status record
    let connection_string = "postgresql://test:test@localhost/test_db";
    let mut conn = AsyncPgConnection::establish(connection_string)
        .await
        .expect("Failed to connect to test database");
    
    // Insert a processor status from 24 hours ago
    let stale_timestamp = chrono::Utc::now().naive_utc() - chrono::Duration::hours(24);
    diesel::sql_query(
        "INSERT INTO processor_status (processor, last_success_version, last_updated) 
         VALUES ($1, $2, $3)
         ON CONFLICT (processor) DO UPDATE 
         SET last_success_version = EXCLUDED.last_success_version,
             last_updated = EXCLUDED.last_updated"
    )
    .bind::<diesel::sql_types::Text, _>("test_processor")
    .bind::<diesel::sql_types::BigInt, _>(100i64)
    .bind::<diesel::sql_types::Timestamp, _>(stale_timestamp)
    .execute(&mut conn)
    .await
    .expect("Failed to insert stale record");
    
    // Create health checker for the processor
    let health_checker = HealthChecker::Processor(
        connection_string.to_string(),
        "test_processor".to_string(),
    );
    
    // Current implementation: Health check PASSES (incorrect - false positive)
    let result = health_checker.check().await;
    assert!(result.is_ok(), "Current implementation incorrectly reports stale processor as healthy");
    
    // Expected behavior: Health check should FAIL for stale records
    // (After applying the recommended fix)
    // assert!(result.is_err(), "Health check should detect stale processor");
    // assert!(result.unwrap_err().to_string().contains("has not updated"));
}
```

## Notes

This vulnerability affects both health checker implementations in the codebase. The fix should be applied consistently to maintain uniform behavior across local testnet and production deployments. Consider making the staleness threshold configurable per processor type, as different processors may have different expected update intervals.

### Citations

**File:** crates/aptos-localnet/src/health_checker.rs (L86-117)
```rust
            HealthChecker::Processor(connection_string, processor_name) => {
                let mut connection = AsyncPgConnection::establish(connection_string)
                    .await
                    .context("Failed to connect to postgres to check processor status")?;
                let result = processor_status::table
                    .select((processor_status::last_success_version,))
                    .filter(processor_status::processor.eq(processor_name))
                    .first::<(i64,)>(&mut connection)
                    .await
                    .optional()
                    .context("Failed to look up processor status")?;
                match result {
                    Some(result) => {
                        // This is last_success_version.
                        if result.0 > 0 {
                            info!(
                                "Processor {} started processing successfully (currently at version {})",
                                processor_name, result.0
                            );
                            Ok(())
                        } else {
                            Err(anyhow!(
                                "Processor {} found in DB but last_success_version is zero",
                                processor_name
                            ))
                        }
                    },
                    None => Err(anyhow!(
                        "Processor {} has not processed any transactions",
                        processor_name
                    )),
                }
```

**File:** crates/aptos/src/node/local_testnet/health_checker.rs (L94-125)
```rust
            HealthChecker::Processor(connection_string, processor_name) => {
                let mut connection = AsyncPgConnection::establish(connection_string)
                    .await
                    .context("Failed to connect to postgres to check processor status")?;
                let result = processor_status::table
                    .select((processor_status::last_success_version,))
                    .filter(processor_status::processor.eq(processor_name))
                    .first::<(i64,)>(&mut connection)
                    .await
                    .optional()
                    .context("Failed to look up processor status")?;
                match result {
                    Some(result) => {
                        // This is last_success_version.
                        if result.0 > 0 {
                            info!(
                                "Processor {} started processing successfully (currently at version {})",
                                processor_name, result.0
                            );
                            Ok(())
                        } else {
                            Err(anyhow!(
                                "Processor {} found in DB but last_success_version is zero",
                                processor_name
                            ))
                        }
                    },
                    None => Err(anyhow!(
                        "Processor {} has not processed any transactions",
                        processor_name
                    )),
                }
```

**File:** crates/indexer/src/schema.rs (L607-612)
```rust
    processor_status (processor) {
        #[max_length = 50]
        processor -> Varchar,
        last_success_version -> Int8,
        last_updated -> Timestamp,
    }
```

**File:** crates/indexer/src/models/processor_status.rs (L15-22)
```rust
#[derive(AsChangeset, Debug, Queryable)]
#[diesel(table_name = processor_status)]
/// Only tracking the latest version successfully processed
pub struct ProcessorStatusV2Query {
    pub processor: String,
    pub last_success_version: i64,
    pub last_updated: chrono::NaiveDateTime,
}
```

**File:** crates/indexer/src/indexer/tailer.rs (L170-191)
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
    }
```

**File:** crates/aptos/src/node/local_testnet/processors.rs (L155-166)
```rust
    fn get_health_checkers(&self) -> HashSet<HealthChecker> {
        let connection_string = match &self.config.db_config {
            DbConfig::PostgresConfig(postgres_config) => postgres_config.connection_string.clone(),
            DbConfig::ParquetConfig(_) => {
                panic!("Parquet is not supported in the localnet");
            },
        };
        hashset! {HealthChecker::Processor(
            connection_string,
            self.config.processor_config.name().to_string(),
        ) }
    }
```
