# Audit Report

## Title
Indefinite Hang in Indexer Backfiller Due to Receiver Lifetime Management After Task Panics

## Summary
The `Processor::backfill()` function in the indexer-grpc file-store backfiller wraps the channel receiver in an `Arc<Mutex<>>` that remains alive in the main function scope even after all receiver tasks panic. This causes `sender.send().await` to hang indefinitely when the channel buffer fills up, as the channel is never closed despite no tasks actively receiving messages.

## Finding Description

The vulnerability exists in how the backfiller manages the channel receiver lifetime: [1](#0-0) [2](#0-1) 

The receiver is wrapped in `Arc<Mutex<>>` and cloned for each worker task: [3](#0-2) 

Each task can panic due to validation failures or upload errors: [4](#0-3) [5](#0-4) 

The critical issue is that after all tasks spawn, `receiver_ref` remains in scope in the main function. When all worker tasks panic:
1. Their `Arc` clones are dropped (refcount decreases)
2. But the original `receiver_ref` from line 171 keeps the receiver alive
3. The channel remains technically "open" from the sender's perspective
4. When the channel buffer fills (1000 items), the sender blocks waiting for space
5. No tasks are calling `recv()`, so space never becomes available
6. The send operation at line 298 hangs indefinitely: [6](#0-5) 

**Attack Vector**: An attacker can trigger this by:
- Compromising a fullnode to send malformed transaction data that fails validation
- Causing the file store backend to be unavailable (triggering upload failures)
- Exploiting any condition that causes all worker tasks to panic simultaneously

## Impact Explanation

This is a **Medium severity** vulnerability per Aptos bug bounty criteria:

- **Service Availability**: The backfiller process hangs indefinitely rather than crashing and restarting, causing the indexer data to become stale
- **State Inconsistencies Requiring Intervention**: The hung process requires manual detection and restart, meeting the Medium severity criteria
- **No Consensus Impact**: This affects only the indexer auxiliary service, not core blockchain consensus, execution, or validator operations
- **User Impact**: Users cannot query recent blockchain data via the indexer API until manual intervention occurs

While this doesn't affect funds or consensus safety (which would be Critical), it does create a persistent service degradation requiring operational intervention, qualifying as Medium severity.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is triggered when all receiver tasks panic, which can occur through:

1. **File Store Unavailability**: If the backend storage system experiences downtime, all tasks attempting upload will panic simultaneously (line 207 `.unwrap()`)

2. **Invalid Data from Fullnode**: If the gRPC stream provides malformed transaction batches (wrong count, wrong versioning), validation checks fail and tasks panic (lines 189-199)

3. **Network Partition**: Temporary network issues could cause upload failures across all tasks

The comment at line 203 indicates the developers expect failures to crash the process for Kubernetes restart, but the design flaw prevents this from working correctly when all tasks fail.

## Recommendation

**Fix: Drop the receiver reference before entering the main processing loop**

After spawning all tasks, explicitly drop `receiver_ref` to ensure the receiver is only held by the worker tasks:

```rust
// After line 216 (after spawning all tasks), add:
drop(receiver_ref);

// This ensures that when all tasks panic, the receiver is properly dropped
// and sender.send() will return an error instead of hanging
```

**Alternative Fix: Monitor task health and exit on panic**

Use `JoinHandle` to detect when tasks panic and exit the process gracefully:

```rust
// In the main loop, periodically check if tasks have died
for task_handle in &tasks {
    if task_handle.is_finished() {
        // At least one task has terminated (likely panicked)
        anyhow::bail!("Worker task terminated unexpectedly");
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_receiver_hang_on_task_panic() {
    use tokio::sync::{mpsc, Mutex};
    use std::sync::Arc;
    use std::time::Duration;
    
    let (sender, receiver) = mpsc::channel::<i32>(10);
    let receiver_ref = Arc::new(Mutex::new(receiver));
    
    // Spawn tasks that immediately panic
    for _ in 0..3 {
        let receiver_clone = receiver_ref.clone();
        tokio::spawn(async move {
            let _r = receiver_clone.lock().await;
            panic!("Task panic simulation");
        });
    }
    
    // Wait for tasks to panic
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Fill the buffer
    for i in 0..10 {
        sender.send(i).await.expect("Should send");
    }
    
    // This send will hang indefinitely because:
    // - receiver_ref still exists in this scope
    // - All tasks have panicked
    // - Buffer is full
    // - No one is receiving
    let timeout_result = tokio::time::timeout(
        Duration::from_secs(1),
        sender.send(100)
    ).await;
    
    assert!(timeout_result.is_err(), "Send should timeout (hang detected)");
    
    // Fix: Drop receiver_ref
    drop(receiver_ref);
    
    // Now send should fail with error instead of hanging
    let send_result = sender.send(101).await;
    assert!(send_result.is_err(), "Send should fail after receiver dropped");
}
```

## Notes

- This vulnerability is specific to the indexer-grpc auxiliary component and does not affect core blockchain consensus, validator operations, or transaction execution
- The issue demonstrates a resource management flaw where the intended crash-and-restart behavior is prevented by improper lifetime management
- The unique pattern of wrapping an mpsc receiver in `Arc<Mutex<>>` appears only in this file in the codebase, suggesting this is an isolated issue
- The Medium severity rating aligns with the bug bounty category of "State inconsistencies requiring intervention"

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L143-143)
```rust
        let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<Transaction>>(1000);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L171-171)
```rust
        let receiver_ref = std::sync::Arc::new(Mutex::new(receiver));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L173-177)
```rust
        for _ in 0..self.backfill_processing_task_count {
            tracing::info!("Creating a new task");
            let mut current_file_store_operator = file_store_operator.clone_box();
            let current_finished_starting_versions = finished_starting_versions.clone();
            let receiver_ref = receiver_ref.clone();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L189-199)
```rust
                        ensure!(transactions.len() == 1000, "Unexpected transaction count");
                        ensure!(
                            transactions[0].version % 1000 == 0,
                            "Unexpected starting version"
                        );
                        for (ide, t) in transactions.iter().enumerate() {
                            ensure!(
                                t.version == transactions[0].version + ide as u64,
                                "Unexpected version"
                            );
                        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L203-207)
```rust
                    // If uploading failure, crash the process and let k8s restart it.
                    current_file_store_operator
                        .upload_transaction_batch(chain_id, transactions)
                        .await
                        .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L298-298)
```rust
                        sender.send(transactions).await?;
```
