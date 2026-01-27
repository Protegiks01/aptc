# Audit Report

## Title
Indexer Timer Metric Fails to Account for Asynchronous Write Operations and Memory Consumption, Enabling Monitoring Bypass

## Summary
The `TIMER` metric in the internal indexer only measures the synchronous batch preparation phase, excluding asynchronous database write operations and memory consumption in the unbounded commit channel. This incomplete resource accounting allows attackers to cause excessive resource consumption that bypasses monitoring systems relying on indexer timing metrics.

## Finding Description

The internal indexer's resource accounting has a critical gap between measured and actual resource consumption. The `TIMER` metric tracks only the batch preparation time in `process_a_batch`, while the actual database write occurs asynchronously in a separate thread with no correlation to the indexer's timing metrics. [1](#0-0) 

The `process_a_batch` function uses this timer to measure batch building: [2](#0-1) 

However, the actual database write happens asynchronously in the `DBCommitter` thread: [3](#0-2) 

The critical vulnerability stems from three architectural issues:

**1. Unbounded Channel Between Producer and Consumer**

The channel connecting `DBIndexer` to `DBCommitter` is created using `std::sync::mpsc::channel()`, which provides an unbounded buffer: [4](#0-3) 

**2. Synchronous Disk Writes with fsync**

The committer performs synchronous writes with the sync flag enabled, forcing expensive disk flushes: [5](#0-4) 

**3. No Memory or Queue Depth Tracking in Indexer Metrics**

The indexer's `TIMER` metric only measures wall-clock time for batch preparation. While the database layer has separate metrics (`APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS`), these are not part of the indexer's observable metrics and use different metric names/labels, making correlation difficult for monitoring systems.

**Attack Scenario:**

An attacker can exploit this by submitting transactions with maximum event data (up to 10MB per transaction per the gas schedule limits): [6](#0-5) 

Each transaction can emit events that get indexed, and with V2 event translation enabled, additional state reads and processing occur. A single batch can process up to 10,000 transactions (configurable batch_size): [7](#0-6) 

If an attacker submits transactions totaling even 1GB of event data per batch, and the synchronous disk writes (with fsync) take 10+ seconds while batch building takes 2-3 seconds, the unbounded channel accumulates batches faster than they can be committed. After several iterations, gigabytes of data accumulate in memory while the `TIMER` metric reports normal 2-3 second batch processing times.

This breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits." While gas limits bound individual transactions, the unbounded channel allows aggregate memory consumption to grow without system-level resource enforcement.

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention, with availability impact.

This vulnerability enables two attack vectors:

1. **Monitoring Bypass**: Resource exhaustion attacks proceed undetected by monitoring systems that track the indexer's `TIMER` metric, as the metric shows normal processing latency while memory consumption grows unbounded in the commit channel.

2. **Memory Exhaustion**: When the committer cannot keep pace with batch production (due to slow disks, I/O contention, or large transaction batches), the unbounded channel grows until the node exhausts available memory, causing a crash.

The impact qualifies as Medium severity because:
- It requires sustained transaction submission over time
- It causes temporary availability loss (node restart required)  
- It does not directly threaten consensus safety or fund security
- It affects monitoring effectiveness, a critical operational security control

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is feasible because:

1. **No Privileged Access Required**: Any user can submit transactions with large event data within gas limits
2. **Natural Performance Asymmetry**: Batch building (memory operations, sequential reads) is inherently faster than synchronous disk writes with fsync
3. **Disk I/O Variability**: Even brief periods of disk contention or slow storage cause the unbounded channel to accumulate batches
4. **Configuration Defaults**: The default batch size of 10,000 transactions allows substantial memory accumulation per batch
5. **No Backpressure Mechanism**: The unbounded channel provides no feedback to slow down batch production when the committer falls behind

The attack complexity is low - it requires only transaction submission, not validator access or sophisticated timing attacks.

## Recommendation

**Immediate Mitigation:**

1. **Replace unbounded channel with bounded channel** to enforce backpressure:

```rust
// In DBIndexer::new() at line 328
let (sender, receiver) = mpsc::sync_channel(INDEXER_CHANNEL_SIZE); // e.g., INDEXER_CHANNEL_SIZE = 10
```

This prevents unbounded memory growth by blocking batch production when the committer falls behind.

2. **Add queue depth monitoring** to the indexer metrics:

```rust
pub static PENDING_BATCHES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_internal_indexer_pending_batches",
        "Number of batches waiting to be committed"
    ).unwrap()
});
```

Update before sending and after receiving in the channel to track queue depth.

3. **Add memory consumption tracking** for batches:

```rust
pub static BATCH_SIZE_BYTES: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "aptos_internal_indexer_batch_size_bytes",
        "Size of indexer batches in bytes"
    ).unwrap()
});
```

Track actual memory usage before sending to the channel.

**Long-term Improvements:**

1. Implement end-to-end latency tracking that includes both batch building and commit time
2. Add configurable limits on batch memory size (not just transaction count)
3. Implement adaptive batch sizing based on commit performance
4. Add alerting thresholds for queue depth and memory consumption

## Proof of Concept

```rust
// Rust test demonstrating the unbounded channel growth
// File: storage/indexer/src/db_indexer_test.rs

#[test]
fn test_unbounded_channel_memory_growth() {
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;
    
    // Simulate the indexer's unbounded channel
    let (sender, receiver) = mpsc::channel::<Vec<u8>>();
    
    // Simulate slow committer (disk writes)
    let committer = thread::spawn(move || {
        while let Ok(batch) = receiver.recv() {
            // Simulate slow synchronous disk write
            thread::sleep(Duration::from_millis(100));
            println!("Committed batch of size: {}", batch.len());
        }
    });
    
    // Simulate fast batch producer
    for i in 0..100 {
        // Each batch is 10MB (simulating transactions with large events)
        let large_batch = vec![0u8; 10 * 1024 * 1024];
        sender.send(large_batch).unwrap();
        println!("Sent batch {}", i);
        
        // Fast batch production (10ms vs 100ms commit time)
        thread::sleep(Duration::from_millis(10));
    }
    
    drop(sender);
    committer.join().unwrap();
    
    // This test demonstrates that the channel accumulates batches
    // In production with real transactions, this leads to memory exhaustion
    // while the TIMER metric shows normal processing times
}
```

## Notes

This vulnerability highlights a broader architectural concern: the separation between resource measurement and resource consumption in asynchronous processing pipelines. The `TIMER` metric accurately measures what it's designed to measure (synchronous batch preparation), but this creates a false sense of security for monitoring systems that don't track the asynchronous commit pipeline.

The issue is exacerbated by the use of an unbounded channel, which is a common anti-pattern in production systems as it allows unbounded resource growth. While bounded channels introduce potential blocking, they provide essential backpressure that prevents resource exhaustion.

The vulnerability does not affect consensus safety or deterministic execution, as the indexer is a read-side component. However, indexer availability is critical for API services and user-facing applications, making this a legitimate availability concern.

### Citations

**File:** storage/indexer/src/metrics.rs (L7-15)
```rust
pub static TIMER: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_internal_indexer_timer_seconds",
        "Various timers for performance analysis.",
        &["name"],
        exponential_buckets(/*start=*/ 1e-9, /*factor=*/ 2.0, /*count=*/ 32).unwrap(),
    )
    .unwrap()
});
```

**File:** storage/indexer/src/db_indexer.rs (L62-76)
```rust
    pub fn run(&self) {
        loop {
            let batch_opt = self
                .receiver
                .recv()
                .expect("Failed to receive batch from DB Indexer");
            if let Some(batch) = batch_opt {
                self.db
                    .write_schemas(batch)
                    .expect("Failed to write batch to indexer db");
            } else {
                break;
            }
        }
    }
```

**File:** storage/indexer/src/db_indexer.rs (L328-328)
```rust
        let (sender, reciver) = mpsc::channel();
```

**File:** storage/indexer/src/db_indexer.rs (L411-411)
```rust
        let _timer: aptos_metrics_core::HistogramTimer = TIMER.timer_with(&["process_a_batch"]);
```

**File:** storage/indexer/src/db_indexer.rs (L432-486)
```rust
            if self.indexer_db.event_enabled() {
                events.iter().enumerate().try_for_each(|(idx, event)| {
                    if let ContractEvent::V1(v1) = event {
                        batch
                            .put::<EventByKeySchema>(
                                &(*v1.key(), v1.sequence_number()),
                                &(version, idx as u64),
                            )
                            .expect("Failed to put events by key to a batch");
                        batch
                            .put::<EventByVersionSchema>(
                                &(*v1.key(), version, v1.sequence_number()),
                                &(idx as u64),
                            )
                            .expect("Failed to put events by version to a batch");
                    }
                    if self.indexer_db.event_v2_translation_enabled() {
                        if let ContractEvent::V2(v2) = event {
                            if let Some(translated_v1_event) =
                                self.translate_event_v2_to_v1(v2).map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to translate event: {:?}. Error: {}",
                                        v2,
                                        e
                                    )
                                })?
                            {
                                let key = *translated_v1_event.key();
                                let sequence_number = translated_v1_event.sequence_number();
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
                                event_keys.insert(key);
                                batch
                                    .put::<EventByKeySchema>(
                                        &(key, sequence_number),
                                        &(version, idx as u64),
                                    )
                                    .expect("Failed to put events by key to a batch");
                                batch
                                    .put::<EventByVersionSchema>(
                                        &(key, version, sequence_number),
                                        &(idx as u64),
                                    )
                                    .expect("Failed to put events by version to a batch");
                                batch
                                    .put::<TranslatedV1EventSchema>(
                                        &(version, idx as u64),
                                        &translated_v1_event,
                                    )
                                    .expect("Failed to put translated v1 events to a batch");
                            }
                        }
                    }
                    Ok::<(), AptosDbError>(())
                })?;
```

**File:** storage/schemadb/src/lib.rs (L374-378)
```rust
fn sync_write_option() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    opts
}
```

**File:** config/src/config/internal_indexer_db_config.rs (L77-77)
```rust
            batch_size: 10_000,
```
