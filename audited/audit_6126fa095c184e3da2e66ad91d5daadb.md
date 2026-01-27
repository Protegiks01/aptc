# Audit Report

## Title
Concurrent Indexer Instances Can Cause Phantom Reads and Duplicate Processing Due to READ COMMITTED Isolation Level

## Summary
The Aptos indexer lacks distributed coordination mechanisms to prevent multiple concurrent instances from processing the same blockchain version ranges. Combined with PostgreSQL's READ COMMITTED isolation level, this allows phantom reads where multiple indexer instances read the same `last_success_version`, process identical transaction batches, and write duplicate data to the database, causing resource waste and potential data inconsistencies.

## Finding Description

The indexer's processing workflow creates a race condition vulnerability when multiple instances run concurrently against the same PostgreSQL database: [1](#0-0) 

The `get_start_version()` method reads the last successfully processed version from the database without acquiring any lock. This read operation is separate from the subsequent processing and update operations, creating a Time-of-Check-Time-of-Use (TOCTOU) vulnerability. [2](#0-1) 

The main processing loop spawns multiple concurrent tasks, and while the `TransactionFetcher` is protected by a mutex within a single instance, there is no coordination between separate indexer instances running on different fullnodes. [3](#0-2) 

The `update_last_processed_version()` method attempts to prevent backward updates with a WHERE clause, but this doesn't prevent the race condition since the read and write are not in the same transaction.

The vulnerability exploitation path:
1. **Instance A** calls `get_start_version()` → reads `last_success_version = 1000`
2. **Instance B** calls `get_start_version()` concurrently → also reads `1000` (phantom read due to READ COMMITTED isolation)
3. **Instance A** fetches and processes transactions 1001-1500
4. **Instance B** fetches and processes transactions 1001-1500 (duplicate work)
5. Both instances write to database tables with ON CONFLICT clauses masking some duplicates
6. Both instances update `processor_status` successfully due to the `<=` condition [4](#0-3) 

The documentation acknowledges that processors should be idempotent, implicitly recognizing that duplicate processing may occur, but provides no mechanism to prevent it.

## Impact Explanation

**Severity Assessment: Low (Does Not Meet Bug Bounty Criteria)**

After thorough analysis, this issue does NOT meet the Aptos bug bounty severity criteria:

- **NOT Critical**: The indexer is a separate off-chain component that does not participate in consensus, transaction execution, or state commitment. Duplicate indexer processing cannot cause loss of funds, consensus violations, or network partitions.

- **NOT High**: This does not cause validator node slowdowns or API crashes affecting the blockchain. The indexer operates independently from the core protocol.

- **NOT Medium**: No funds loss or blockchain state inconsistencies. Only the external PostgreSQL database (used for queries) may have redundant processing.

The issue is purely operational:
- Wasted computational resources from duplicate transaction processing
- Increased database contention
- Potential PostgreSQL connection pool exhaustion
- No impact on blockchain security, consensus, or fund safety

## Likelihood Explanation

**Likelihood: Low in Production, Moderate in Development**

This occurs when operators either:
1. Accidentally run multiple fullnodes with the same processor configuration pointing to the same database
2. Attempt to horizontally scale indexers without proper coordination [5](#0-4) 

The documentation suggests running different processor types in separate fullnodes, but doesn't explicitly prevent running multiple instances of the same processor type.

## Recommendation

While this is not a security vulnerability, for operational efficiency, consider:

1. **Add PostgreSQL Advisory Locks** to coordinate between instances:
```rust
// At start of processing loop
SELECT pg_advisory_lock(hashtext('indexer_processor_<name>'));
```

2. **Implement health checks** to detect and warn about concurrent instances

3. **Document explicitly** that running multiple instances of the same processor against one database is unsupported

4. **Use SERIALIZABLE isolation** for the read-process-write cycle if strict once-only processing is required

## Proof of Concept

This vulnerability can be demonstrated by:
1. Starting two fullnode instances with identical indexer configurations
2. Both pointing to the same PostgreSQL database
3. Observing duplicate processing in logs and increased database write load

However, since this does not affect blockchain security or consensus, it falls outside the scope of security vulnerabilities per the bug bounty program criteria.

---

## Notes

**Critical Distinction**: The Aptos indexer is an **off-chain data indexing service** that reads from the blockchain and writes to PostgreSQL for query purposes. It does **not** participate in consensus, does **not** affect transaction execution, and does **not** modify blockchain state. Therefore, indexer issues cannot cause:
- Consensus safety violations
- Transaction execution errors  
- Fund loss or theft
- Network partitions

This is an **operational efficiency concern**, not a security vulnerability meeting the bug bounty criteria of Critical, High, or Medium severity.

### Citations

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

**File:** crates/indexer/src/indexer/tailer.rs (L194-201)
```rust
    pub fn get_start_version(&self, processor_name: &String) -> Result<Option<i64>> {
        let mut conn = self.connection_pool.get()?;

        match ProcessorStatusV2Query::get_by_processor(processor_name, &mut conn)? {
            Some(status) => Ok(Some(status.last_success_version + 1)),
            None => Ok(None),
        }
    }
```

**File:** crates/indexer/src/runtime.rs (L209-261)
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

        let mut batch_start_version = u64::MAX;
        let mut batch_end_version = 0;
        let mut num_res = 0;

        for (num_txn, res) in batches {
            let processed_result: ProcessingResult = match res {
                // When the batch is empty b/c we're caught up, continue to next batch
                None => continue,
                Some(Ok(res)) => res,
                Some(Err(tpe)) => {
                    let (err, start_version, end_version, _) = tpe.inner();
                    error!(
                        processor_name = processor_name,
                        start_version = start_version,
                        end_version = end_version,
                        error =? err,
                        "Error processing batch!"
                    );
                    panic!(
                        "Error in '{}' while processing batch: {:?}",
                        processor_name, err
                    );
                },
            };
            batch_start_version =
                std::cmp::min(batch_start_version, processed_result.start_version);
            batch_end_version = std::cmp::max(batch_end_version, processed_result.end_version);
            num_res += num_txn;
        }

        tailer
            .update_last_processed_version(&processor_name, batch_end_version)
            .unwrap_or_else(|e| {
                error!(
                    processor_name = processor_name,
                    end_version = batch_end_version,
                    error = format!("{:?}", e),
                    "Failed to update last processed version!"
                );
                panic!("Failed to update last processed version: {:?}", e);
            });
```

**File:** crates/indexer/README.md (L9-11)
```markdown
Each `TransactionProcessor` will need to be run in a separate fullnode. Please note that it may be difficult to run several transaction processors simultaneously in a single machine due to port conflicts. 

When developing your own, ensure each `TransactionProcessor` is idempotent, and being called with the same input won't result in an error if some or all of the processing had previously been completed.
```
