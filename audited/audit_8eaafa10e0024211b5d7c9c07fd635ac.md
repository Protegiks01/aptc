# Audit Report

## Title
Backup Service State Snapshot Chunk Endpoint Lacks Input Validation Leading to Storage I/O Amplification Attack

## Summary
The `state_snapshot_chunk` endpoint in the backup service accepts arbitrary limit values without validation, enabling an attacker to spawn massive concurrent requests that overwhelm storage I/O operations and degrade or crash the validator node database.

## Finding Description

The backup service endpoint at `/state_snapshot_chunk/{version}/{start_idx}/{limit}` accepts user-supplied limit values without any validation or bounds checking. [1](#0-0) 

The endpoint directly passes the `limit` parameter to the `BackupHandler::get_state_item_iter` method: [2](#0-1) 

This method creates an iterator that calls `expect_value_by_version` for each state item, which performs RocksDB seek and read operations: [3](#0-2) 

**Violation of Invariant #9**: The system fails to enforce resource limits on storage operations, allowing unbounded database I/O.

**Attack Scenario:**
1. Attacker identifies a validator node with exposed backup service (port 6186)
2. Attacker spawns 10,000 concurrent HTTP requests: `GET /state_snapshot_chunk/1000000/0/1000000`
3. Each request attempts to read 1,000,000 state items = 10 billion total items
4. Each item triggers 2+ RocksDB operations (iterator seek + value fetch)
5. Total: 20+ billion database I/O operations overwhelm storage subsystem
6. Database performance degrades catastrophically, causing validator slowdown or crash

**Missing Protections:**
- No input validation on limit parameter (usize can be 2^64-1)
- No server-side rate limiting (only client-side via `concurrent_data_requests`) [4](#0-3) 

- No authentication/authorization on the backup service
- Legitimate client uses chunks of 100,000 items, but no enforcement: [5](#0-4) 

## Impact Explanation

**High Severity** - Meets "Validator node slowdowns" criteria per Aptos bug bounty. The attack causes:

1. **Storage I/O Exhaustion**: Billions of RocksDB operations saturate disk I/O bandwidth
2. **Memory Pressure**: Large iterators and buffering consume validator memory
3. **Service Degradation**: Legitimate backup operations, state sync, and transaction processing slow down
4. **Potential Critical Impact**: If database crashes due to resource exhaustion, this becomes "Total loss of liveness/network availability" (Critical severity)

The backup service is exposed via Kubernetes Service on port 6186: [6](#0-5) 

While default configuration binds to localhost, production deployments may expose this service for backup operations, making it accessible to attackers.

## Likelihood Explanation

**High Likelihood** if service is exposed:
- Simple HTTP GET requests, no authentication required
- No specialized tools or deep protocol knowledge needed
- Attack is deterministic and repeatable
- Service exposure depends on deployment configuration

**Mitigating Factors:**
- Default binding to localhost (127.0.0.1) limits exposure
- Requires misconfiguration or network access to exploit

However, the lack of input validation is a security bug regardless of deployment configuration.

## Recommendation

Implement strict input validation with maximum limit bounds:

```rust
// In storage/backup/backup-service/src/handlers/mod.rs
const MAX_CHUNK_LIMIT: usize = 100_000; // Match legitimate client usage

let state_snapshot_chunk = warp::path!(Version / usize / usize)
    .and_then(move |version, start_idx, limit| async move {
        // Validate limit parameter
        if limit > MAX_CHUNK_LIMIT {
            return Err(warp::reject::custom(InvalidLimitError {
                requested: limit,
                max_allowed: MAX_CHUNK_LIMIT,
            }));
        }
        
        Ok(reply_with_bytes_sender(&bh, STATE_SNAPSHOT_CHUNK, move |bh, sender| {
            bh.get_state_item_iter(version, start_idx, limit)?
                .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
        }))
    })
    .recover(handle_rejection);
```

**Additional Hardening:**
1. Implement server-side rate limiting (max concurrent requests per client)
2. Add authentication for backup service endpoints
3. Implement request timeout and cancellation mechanisms
4. Add monitoring/alerting for abnormal request patterns

## Proof of Concept

```bash
#!/bin/bash
# PoC: Amplification attack on backup service
# Assumes backup service exposed on localhost:6186

BACKUP_URL="http://localhost:6186/state_snapshot_chunk"
VERSION=1000000
LIMIT=1000000

# Spawn 100 concurrent requests (scaled down for demo)
for i in {1..100}; do
    START_IDX=$((i * 100000))
    curl -s "${BACKUP_URL}/${VERSION}/${START_IDX}/${LIMIT}" > /dev/null &
done

wait

# Monitor system resources during attack:
# - iostat -x 1  # Disk I/O saturation
# - top          # RocksDB process CPU/memory
# - Database slow query logs
```

**Expected Behavior (Vulnerable):**
- Disk I/O spikes to 100% utilization
- Database query latency increases dramatically
- Legitimate operations (state sync, transaction execution) slow down

**Expected Behavior (Fixed):**
- Requests with limit > 100,000 return HTTP 400 error
- Resource utilization remains stable

## Notes

This is an **application-level resource exhaustion vulnerability**, not a network-level DoS. The distinction is critical:
- Network-level DoS targets network stack (SYN floods, bandwidth exhaustion)
- This exploits legitimate API functionality with malicious parameters to exhaust application resources (database I/O)

The Aptos bug bounty explicitly lists "Validator node slowdowns" and "Total loss of liveness/network availability" as valid High and Critical severity impacts, confirming that application-level attacks causing these outcomes are in scope.

The vulnerability exists in the codebase regardless of deployment configuration. While default localhost binding provides defense-in-depth, production deployments requiring external backup access would be vulnerable.

### Citations

**File:** storage/backup/backup-service/src/handlers/mod.rs (L70-79)
```rust
    // GET state_snapshot_chunk/<version>/<start_idx>/<limit>
    let bh = backup_handler.clone();
    let state_snapshot_chunk = warp::path!(Version / usize / usize)
        .map(move |version, start_idx, limit| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT_CHUNK, move |bh, sender| {
                bh.get_state_item_iter(version, start_idx, limit)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L145-162)
```rust
    pub fn get_state_item_iter(
        &self,
        version: Version,
        start_idx: usize,
        limit: usize,
    ) -> Result<impl Iterator<Item = Result<(StateKey, StateValue)>> + Send + use<>> {
        let iterator = self
            .state_store
            .get_state_key_and_value_iter(version, start_idx)?
            .take(limit)
            .enumerate()
            .map(move |(idx, res)| {
                BACKUP_STATE_SNAPSHOT_VERSION.set(version as i64);
                BACKUP_STATE_SNAPSHOT_LEAF_IDX.set((start_idx + idx) as i64);
                res
            });
        Ok(Box::new(iterator))
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L374-402)
```rust
    pub(crate) fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        let mut read_opts = ReadOptions::default();

        // We want `None` if the state_key changes in iteration.
        read_opts.set_prefix_same_as_start(true);
        if !self.enabled_sharding() {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueSchema>(read_opts)?;
            iter.seek(&(state_key.clone(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        } else {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
            iter.seek(&(state_key.hash(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        }
    }
```

**File:** storage/backup/backup-service/src/lib.rs (L12-30)
```rust
pub fn start_backup_service(address: SocketAddr, db: Arc<AptosDB>) -> Runtime {
    let backup_handler = db.get_backup_handler();
    let routes = get_routes(backup_handler);

    let runtime = aptos_runtimes::spawn_named_runtime("backup".into(), None);

    // Ensure that we actually bind to the socket first before spawning the
    // server tasks. This helps in tests to prevent races where a client attempts
    // to make a request before the server task is actually listening on the
    // socket.
    //
    // Note: we need to enter the runtime context first to actually bind, since
    //       tokio TcpListener can only be bound inside a tokio context.
    let _guard = runtime.enter();
    let server = warp::serve(routes).bind(address);
    runtime.handle().spawn(server);
    info!("Backup service spawned.");
    runtime
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L276-276)
```rust
        const CHUNK_SIZE: usize = if cfg!(test) { 2 } else { 100_000 };
```

**File:** terraform/helm/fullnode/templates/service.yaml (L53-54)
```yaml
  - name: backup
    port: 6186
```
