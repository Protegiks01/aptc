# Audit Report

## Title
Unauthorized Access to Backup Service and DB Tool Operations Due to Missing Authorization Controls

## Summary
The Aptos backup service and db-tool lack authorization mechanisms, allowing unauthorized access to read blockchain data and potentially corrupt node databases. The backup service can be exposed on public interfaces without authentication, and the CLI tools perform critical operations without verifying operator permissions.

## Finding Description

The vulnerability consists of two related authorization bypasses:

**1. Backup Service Network Exposure Without Authentication**

The backup service HTTP endpoints expose sensitive database operations without any authentication or authorization checks: [1](#0-0) 

All endpoints (`db_state`, `state_snapshot_chunk`, `transactions`, `epoch_ending_ledger_infos`, etc.) are accessible via plain HTTP GET requests with no authentication. While the default configuration binds to localhost: [2](#0-1) 

Production deployments configure the service to bind to all interfaces: [3](#0-2) 

The BackupServiceClient also lacks authentication mechanisms: [4](#0-3) 

**2. DB-Tool CLI Authorization Bypass**

The `Command::run()` methods in backup and restore operations perform no authorization checks: [5](#0-4) [6](#0-5) 

Any user with CLI access can execute critical operations including reading all blockchain data via backup commands or corrupting the node database via restore commands. The restore operations accept arbitrary target database directories: [7](#0-6) 

## Impact Explanation

**Severity: High**

This issue qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Availability**: Unauthorized restore operations can corrupt the node's database, causing node crashes or requiring manual intervention, leading to validator node slowdowns or unavailability.

2. **Operational Data Exposure**: When the backup service is exposed on `0.0.0.0:6186`, any network actor can read the complete blockchain state including transaction data, state snapshots, and database metadata.

While this doesn't directly cause consensus violations or fund loss network-wide, it enables:
- Single-node denial of service through database corruption
- Information disclosure of operational data
- Potential for coordinated attacks if multiple nodes are compromised

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood varies based on deployment context:

1. **Backup Service Exposure** (High Likelihood):
   - Production configurations explicitly set `backup_service_address: "0.0.0.0:6186"`
   - No authentication is required
   - Attack requires only network access to port 6186

2. **CLI Tool Abuse** (Medium Likelihood):
   - Requires shell access to the node machine
   - In multi-tenant environments or shared infrastructure, multiple users may have CLI access
   - No application-level verification of operator role

The combination of public network exposure in production configs and complete lack of authentication makes exploitation straightforward for the backup service component.

## Recommendation

Implement multi-layered authorization controls:

**1. Add Authentication to Backup Service**
- Implement API key or mutual TLS authentication for backup service endpoints
- Add authorization middleware to verify operator credentials before serving requests
- Consider implementing IP whitelisting as an additional layer

**2. Add Authorization Checks to DB-Tool**
- Verify operator permissions before executing backup/restore commands
- Check user privileges against a configuration file or system permissions
- Add audit logging for all backup/restore operations

**3. Configuration Security**
- Add warnings when backup service is configured to bind to `0.0.0.0`
- Provide secure defaults and configuration validation
- Document security implications of public exposure

Example implementation for backup service authentication:

```rust
// Add to handlers/mod.rs
fn verify_auth_token(headers: &HeaderMap) -> Result<(), Rejection> {
    let token = headers.get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| warp::reject::custom(Unauthorized))?;
    
    if !validate_operator_token(token) {
        return Err(warp::reject::custom(Unauthorized));
    }
    Ok(())
}

// Add auth check to each route
let db_state = warp::header::headers_cloned()
    .and_then(verify_auth_token)
    .and(warp::path::end())
    .map(move || reply_with_bcs_bytes(DB_STATE, &bh.get_db_state()?))
    .map(unwrap_or_500)
    .recover(handle_rejection);
```

## Proof of Concept

**Step 1: Expose Backup Service (simulating production config)**
```bash
# Configure node with public backup service
cat > node.yaml <<EOF
storage:
  backup_service_address: "0.0.0.0:6186"
EOF
```

**Step 2: Unauthorized Backup Service Access**
```bash
# From any machine on the network
curl http://<node-ip>:6186/db_state

# Download state snapshot
curl http://<node-ip>:6186/state_snapshot_chunk/1000/0/10000

# Download transactions
curl http://<node-ip>:6186/transactions/0/1000
```

**Step 3: Unauthorized Restore Operation**
```bash
# Any user with CLI access can corrupt the database
aptos-db-tool restore bootstrap-db \
  --target-db-dir /opt/aptos/data/db \
  --metadata-cache-dir /tmp/backup-metadata \
  --command-adapter-config /path/to/malicious/backup/config.yaml
```

**Notes:**
- While blockchain data is generally public, the backup service may expose operational metadata and internal state that shouldn't be publicly accessible
- The lack of audit logging makes detecting unauthorized access difficult
- In environments where the node operator role should be restricted (e.g., managed validator services), the missing authorization allows any user with CLI access to perform privileged operations
- The default localhost-only binding provides some protection, but production configurations override this without adding authentication

### Citations

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

**File:** config/src/config/storage_config.rs (L436-436)
```rust
            backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
```

**File:** terraform/helm/fullnode/files/fullnode-base.yaml (L68-68)
```yaml
  backup_service_address: "0.0.0.0:6186"
```

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L38-84)
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

**File:** storage/db-tool/src/backup.rs (L168-256)
```rust
impl Command {
    pub async fn run(self) -> Result<()> {
        match self {
            Command::Oneoff(opt) => {
                let client = Arc::new(BackupServiceClient::new_with_opt(opt.client));
                let global_opt = opt.global;

                match opt.backup_type {
                    BackupType::EpochEnding { opt, storage } => {
                        EpochEndingBackupController::new(
                            opt,
                            global_opt,
                            client,
                            storage.init_storage().await?,
                        )
                        .run()
                        .await?;
                    },
                    BackupType::StateSnapshot { opt, storage } => {
                        StateSnapshotBackupController::new(
                            opt,
                            global_opt,
                            client,
                            storage.init_storage().await?,
                        )
                        .run()
                        .await?;
                    },
                    BackupType::Transaction { opt, storage } => {
                        TransactionBackupController::new(
                            opt,
                            global_opt,
                            client,
                            storage.init_storage().await?,
                        )
                        .run()
                        .await?;
                    },
                }
            },
            Command::Continuously(opt) => {
                BackupCoordinator::new(
                    opt.coordinator,
                    opt.global,
                    Arc::new(BackupServiceClient::new_with_opt(opt.client)),
                    opt.storage.init_storage().await?,
                )
                .run()
                .await?;
            },
            Command::Query(typ) => match typ {
                OneShotQueryType::NodeState(opt) => {
                    let client = BackupServiceClient::new_with_opt(opt.client);
                    if let Some(db_state) = client.get_db_state().await? {
                        println!("{}", db_state)
                    } else {
                        println!("DB not bootstrapped.")
                    }
                },
                OneShotQueryType::BackupStorageState(opt) => {
                    let view = cache::sync_and_load(
                        &opt.metadata_cache,
                        opt.storage.init_storage().await?,
                        opt.concurrent_downloads.get(),
                    )
                    .await?;
                    println!("{}", view.get_storage_state()?)
                },
            },
            Command::Verify(opt) => {
                VerifyCoordinator::new(
                    opt.storage.init_storage().await?,
                    opt.metadata_cache_opt,
                    opt.trusted_waypoints_opt,
                    opt.concurrent_downloads.get(),
                    opt.start_version.unwrap_or(0),
                    opt.end_version.unwrap_or(Version::MAX),
                    opt.state_snapshot_before_version.unwrap_or(Version::MAX),
                    opt.skip_epoch_endings,
                    opt.validate_modules,
                    opt.output_transaction_analysis,
                )?
                .run()
                .await?
            },
        }
        Ok(())
    }
}
```

**File:** storage/db-tool/src/restore.rs (L65-127)
```rust
impl Command {
    pub async fn run(self) -> Result<()> {
        match self {
            Command::Oneoff(oneoff) => {
                match oneoff {
                    Oneoff::EpochEnding {
                        storage,
                        opt,
                        global,
                    } => {
                        EpochEndingRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                        )
                        .run(None)
                        .await?;
                    },
                    Oneoff::StateSnapshot {
                        storage,
                        opt,
                        global,
                    } => {
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
                    },
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
                }
            },
            Command::BootstrapDB(bootstrap) => {
                RestoreCoordinator::new(
                    bootstrap.opt,
                    bootstrap.global.try_into()?,
                    bootstrap.storage.init_storage().await?,
                )
                .run()
                .await?;
            },
        }

        Ok(())
    }
}
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L133-167)
```rust
#[derive(Clone, Parser)]
pub struct GlobalRestoreOpt {
    #[clap(long, help = "Dry run without writing data to DB.")]
    pub dry_run: bool,

    #[clap(
        long = "target-db-dir",
        value_parser,
        conflicts_with = "dry_run",
        required_unless_present = "dry_run"
    )]
    pub db_dir: Option<PathBuf>,

    #[clap(
        long,
        help = "Content newer than this version will not be recovered to DB, \
        defaulting to the largest version possible, meaning recover everything in the backups."
    )]
    pub target_version: Option<Version>,

    #[clap(flatten)]
    pub trusted_waypoints: TrustedWaypointOpt,

    #[clap(flatten)]
    pub rocksdb_opt: RocksdbOpt,

    #[clap(flatten)]
    pub concurrent_downloads: ConcurrentDownloadsOpt,

    #[clap(flatten)]
    pub replay_concurrency_level: ReplayConcurrencyLevelOpt,

    #[clap(long, help = "Restore the state indices when restore the snapshot")]
    pub enable_state_indices: bool,
}
```
