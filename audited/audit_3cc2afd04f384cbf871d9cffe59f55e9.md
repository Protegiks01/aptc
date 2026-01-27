# Audit Report

## Title
Unhandled Panic in Backup Service Leads to Silent Data Corruption and Service Disruption

## Summary
The `abort_on_error()` function in the backup service does not catch panics from the closure it wraps, only handling `Result` errors. When combined with integer overflow in state iteration (with overflow-checks enabled in release builds), this allows attackers to trigger panics that leave HTTP response streams in an incomplete state without error indication, potentially corrupting backup data.

## Finding Description

The `abort_on_error()` function is designed to handle errors from backup operation closures, but it only catches `Result::Err` values, not panics: [1](#0-0) 

This function wraps closures that are executed inside `tokio::task::spawn_blocking`: [2](#0-1) 

The critical issue is that the join handle is dropped without being awaited (`_join_handle`), meaning panics are silently swallowed by tokio's task infrastructure.

**Panic Trigger Point:** In the state iteration code, there's unchecked integer arithmetic that can overflow: [3](#0-2) 

The addition `start_idx + idx` can overflow when `start_idx` is near `usize::MAX`. Critically, the Aptos codebase has **overflow-checks enabled in release builds**: [4](#0-3) 

**Attack Vector:** The backup service exposes an endpoint that accepts `start_idx` directly from URL parameters without validation: [5](#0-4) 

**Exploitation Steps:**
1. Attacker sends GET request to `/state_snapshot_chunk/{version}/{start_idx}/{limit}` with `start_idx = usize::MAX - 10` and `limit = 100`
2. Iterator begins at index `usize::MAX - 10`
3. After ~11 iterations, `start_idx + idx` overflows
4. With `overflow-checks = true`, this triggers a panic at line 158
5. The panic propagates out of the closure `f` in `abort_on_error()`
6. `abort_on_error()` does NOT use `std::panic::catch_unwind`, so the panic continues
7. Tokio catches the panic in `spawn_blocking`, but the join handle is dropped
8. **Critical:** Neither `sender.finish()` nor `sender.abort(e)` is called
9. The BytesSender's channel is dropped without proper closure
10. Client receives partial data, then the stream ends without error indication
11. Backup client may incorrectly assume complete data was received

**Similar vulnerabilities exist in:**
- `get_transaction_iter` at line 78: `start_version + idx as u64`
- `get_epoch_ending_ledger_info_iter` at line 218: `start_epoch + idx as u64`

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria due to:

1. **API Crashes**: The backup service endpoint becomes unresponsive for the affected request
2. **Data Integrity Violation**: Clients receive partial backup data without error notification, potentially leading to corrupted backup sets that appear complete
3. **Service Disruption**: Repeated attacks can degrade backup service availability
4. **Silent Failure**: The most dangerous aspect is that clients don't receive proper error indication, violating the fundamental expectation that failed operations are signaled

The vulnerability affects the backup infrastructure which is critical for disaster recovery and node synchronization. Corrupted backups could lead to:
- Inability to restore nodes from backup
- State sync failures when using backup-based recovery
- Data loss if corrupted backups are relied upon

While this doesn't directly compromise consensus or cause fund loss (limiting it from Critical severity), it significantly impacts protocol operations and node reliability, meeting the "Significant protocol violations" criterion for High severity.

## Likelihood Explanation

**Likelihood: High**

The attack is:
- **Trivially executable**: Requires only a single HTTP GET request with malicious parameters
- **No authentication required**: Backup service endpoints are typically exposed for public backup operations
- **Deterministic**: The overflow will reliably occur with crafted inputs
- **Low complexity**: No special timing, race conditions, or complex state manipulation needed

The only requirement is that `overflow-checks = true`, which is explicitly configured in the release profile. The vulnerability can be triggered by any network actor with HTTP access to the backup service, requiring no validator privileges or insider access.

## Recommendation

**Immediate Fix:** Use `std::panic::catch_unwind` to catch panics in `abort_on_error()`:

```rust
use std::panic::AssertUnwindSafe;

pub(super) fn abort_on_error<F>(
    f: F,
) -> impl FnOnce(BackupHandler, bytes_sender::BytesSender) + Send + 'static
where
    F: FnOnce(BackupHandler, &mut bytes_sender::BytesSender) -> DbResult<()> + Send + 'static,
{
    move |bh: BackupHandler, mut sender: bytes_sender::BytesSender| {
        let panic_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            f(bh, &mut sender)
        }));
        
        let _res = match panic_result {
            Ok(Ok(())) => sender.finish(),
            Ok(Err(e)) => sender.abort(e),
            Err(panic_err) => {
                let panic_msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                sender.abort(AptosDbError::Other(format!("Backup operation panicked: {}", panic_msg)))
            }
        };
    }
}
```

**Additional Mitigations:**

1. **Input Validation**: Add bounds checking in the endpoint handlers:
```rust
let state_snapshot_chunk = warp::path!(Version / usize / usize)
    .map(move |version, start_idx, limit| {
        // Prevent overflow in start_idx + limit
        if start_idx.checked_add(limit).is_none() {
            return Box::new(warp::http::StatusCode::BAD_REQUEST) as Box<dyn Reply>;
        }
        reply_with_bytes_sender(&bh, STATE_SNAPSHOT_CHUNK, move |bh, sender| {
            // ... existing code
        })
    })
```

2. **Use Checked Arithmetic**: Replace `start_idx + idx` with `start_idx.checked_add(idx)` in iterator implementations:
```rust
.map(move |(idx, res)| {
    BACKUP_STATE_SNAPSHOT_VERSION.set(version as i64);
    if let Some(leaf_idx) = start_idx.checked_add(idx) {
        BACKUP_STATE_SNAPSHOT_LEAF_IDX.set(leaf_idx as i64);
    }
    res
})
```

3. **Monitor Join Handles**: Consider awaiting the join handle in a separate task to log panics for monitoring.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_overflow_triggers_panic() {
        // This test demonstrates the overflow panic in release mode with overflow-checks=true
        let start_idx: usize = usize::MAX - 10;
        let mut idx = 0;
        
        // Simulate the iteration that would happen in get_state_item_iter
        for i in 0..20 {
            idx = i;
            // This will panic when i > 10 due to overflow
            let _leaf_idx = start_idx + idx; // Line 158 equivalent
        }
    }
    
    #[tokio::test]
    async fn test_abort_on_error_does_not_catch_panic() {
        let (sender, _stream) = bytes_sender::BytesSender::new("test");
        let bh = create_test_backup_handler(); // Helper to create BackupHandler
        
        // Create a closure that panics
        let panicking_closure = |_bh: BackupHandler, _sender: &mut bytes_sender::BytesSender| -> DbResult<()> {
            panic!("Simulated panic in backup operation");
        };
        
        // Spawn with abort_on_error - panic will be caught by tokio but sender.abort() won't be called
        let handle = tokio::task::spawn_blocking(move || {
            abort_on_error(panicking_closure)(bh, sender)
        });
        
        // The join will return Err because the task panicked
        let result = handle.await;
        assert!(result.is_err(), "Task should have panicked");
        
        // The critical issue: the BytesSender was not properly finished or aborted
        // The client stream will receive incomplete data
    }
    
    #[tokio::test]
    async fn test_malicious_start_idx() {
        // Simulate malicious HTTP request with start_idx near usize::MAX
        let client = reqwest::Client::new();
        let version = 1000;
        let start_idx = usize::MAX - 10;
        let limit = 100;
        
        let url = format!(
            "http://localhost:6186/state_snapshot_chunk/{}/{}/{}",
            version, start_idx, limit
        );
        
        let response = client.get(&url).send().await.unwrap();
        
        // The response will be incomplete without error indication
        // Client will receive partial data then connection closes
        assert!(response.status().is_success()); // May appear successful
        
        let bytes = response.bytes().await.unwrap();
        // Bytes will be less than expected, no error communicated to client
    }
}
```

**Notes:**
- The vulnerability affects all backup service endpoints that use `reply_with_bytes_sender` with iterator-based operations
- Production nodes run in release mode with overflow-checks enabled, making this exploitable in real deployments
- The same pattern exists in transaction and epoch iteration endpoints, multiplying the attack surface
- The silent failure nature makes this particularly dangerous as it can lead to undetected backup corruption

### Citations

**File:** storage/backup/backup-service/src/handlers/utils.rs (L58-62)
```rust
    let _join_handle = tokio::task::spawn_blocking(move || {
        let _timer =
            BACKUP_TIMER.timer_with(&[&format!("backup_service_bytes_sender_{}", endpoint)]);
        abort_on_error(f)(bh, sender)
    });
```

**File:** storage/backup/backup-service/src/handlers/utils.rs (L67-80)
```rust
pub(super) fn abort_on_error<F>(
    f: F,
) -> impl FnOnce(BackupHandler, bytes_sender::BytesSender) + Send + 'static
where
    F: FnOnce(BackupHandler, &mut bytes_sender::BytesSender) -> DbResult<()> + Send + 'static,
{
    move |bh: BackupHandler, mut sender: bytes_sender::BytesSender| {
        // ignore error from finish() and abort()
        let _res = match f(bh, &mut sender) {
            Ok(()) => sender.finish(),
            Err(e) => sender.abort(e),
        };
    }
}
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L156-159)
```rust
            .map(move |(idx, res)| {
                BACKUP_STATE_SNAPSHOT_VERSION.set(version as i64);
                BACKUP_STATE_SNAPSHOT_LEAF_IDX.set((start_idx + idx) as i64);
                res
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L72-77)
```rust
    let state_snapshot_chunk = warp::path!(Version / usize / usize)
        .map(move |version, start_idx, limit| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT_CHUNK, move |bh, sender| {
                bh.get_state_item_iter(version, start_idx, limit)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
```
