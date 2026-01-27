# Audit Report

## Title
Indexer Database Desynchronization and Source Corruption via Flag Mismatch in create_checkpoint()

## Summary
The `create_checkpoint()` function lacks validation to ensure the source database has a corresponding indexer database when `enable_indexer_grpc=true` is specified. This allows RocksDB to silently create an empty indexer database in the source directory, causing permanent desynchronization between the main DB and indexer DB in both source and checkpoint locations.

## Finding Description

The vulnerability exists in the `create_checkpoint()` function which performs database checkpointing operations. When called with `enable_indexer_grpc=true`, the function unconditionally attempts to open and checkpoint the indexer database without verifying its existence or synchronization state. [1](#0-0) 

The critical flaw occurs at the indexer DB opening step. The function calls `open_db()` with `readonly=false`, which passes these parameters to RocksDB options generation: [2](#0-1) 

This configuration causes RocksDB to automatically create the database if it doesn't exist via `create_if_missing(true)`. The underlying schema DB implementation confirms this behavior: [3](#0-2) 

**Attack Scenario:**

1. User creates source DB WITHOUT indexer: `./benchmark CreateDb --data-dir=/source`
   - Main DB contains versions 0-10000
   - NO `index_async_v2_db` directory exists

2. User runs benchmark WITH indexer enabled: `./benchmark RunExecutor --enable-indexer-grpc --data-dir=/source --checkpoint-dir=/checkpoint`
   - `create_checkpoint()` attempts to open `/source/index_async_v2_db`
   - RocksDB creates NEW EMPTY database at `/source/index_async_v2_db` (version 0)
   - Checkpoints this EMPTY indexer DB to `/checkpoint/index_async_v2_db`
   - Checkpoints main DB (version 10000) to `/checkpoint`

3. **Result:** 
   - Source DB is now CORRUPTED: main DB at version 10000, indexer DB at version 0
   - Checkpoint has desynchronized databases: main DB at version 10000, indexer DB at version 0
   - Any subsequent indexer operations will be inconsistent

The CLI interface confirms these commands can be executed independently with different flags: [4](#0-3) 

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The main DB and indexer DB are no longer consistent representations of the same blockchain state.

## Impact Explanation

This is a **HIGH Severity** vulnerability per Aptos bug bounty criteria for the following reasons:

1. **State Inconsistencies Requiring Intervention**: The desynchronization creates permanent database corruption requiring manual intervention to fix. The indexer DB cannot automatically recover as it lacks historical transaction data.

2. **Silent Data Corruption**: The bug corrupts the source database without warning, affecting all future operations using that database.

3. **Operational Impact**: Any validator or node operator using these databases would experience:
   - Incorrect indexer query results
   - Failed state synchronization between main and indexer components
   - Potential cascading failures in dependent systems

4. **Wide Attack Surface**: The vulnerability can be triggered through simple CLI flag mismatches during routine operations (database creation, benchmarking, account addition).

The benchmark's indexer initialization attempts to use both databases together, expecting synchronization: [5](#0-4) 

## Likelihood Explanation

**Likelihood: HIGH**

1. **Easy to Trigger**: Requires only a CLI flag mismatch between two separate command invocations
2. **Common Operational Pattern**: Database creation and benchmarking are separate operations that may be performed by different team members or at different times with different configurations
3. **No Warnings**: The system provides no validation or warnings about the mismatch
4. **Silent Failure**: The corruption occurs silently without immediate errors, making it likely to go unnoticed until queries fail

## Recommendation

Add validation in `create_checkpoint()` to verify indexer DB existence and synchronization before attempting to checkpoint:

```rust
fn create_checkpoint(
    source_dir: impl AsRef<Path>,
    checkpoint_dir: impl AsRef<Path>,
    enable_storage_sharding: bool,
    enable_indexer_grpc: bool,
) {
    println!("Creating checkpoint for DBs.");
    
    if checkpoint_dir.as_ref().exists() {
        fs::remove_dir_all(checkpoint_dir.as_ref()).unwrap_or(());
    }
    std::fs::create_dir_all(checkpoint_dir.as_ref()).unwrap();

    if enable_indexer_grpc {
        let db_path = source_dir.as_ref().join(TABLE_INFO_DB_NAME);
        
        // VALIDATION: Check if indexer DB exists before opening
        if !db_path.exists() {
            panic!(
                "Indexer DB not found at {:?}. Cannot create checkpoint with enable_indexer_grpc=true \
                when source was created without indexer support. \
                Either disable indexer for checkpoint or recreate source DB with indexer enabled.",
                db_path
            );
        }
        
        // VALIDATION: Open in readonly mode to prevent accidental creation
        let indexer_db = open_db(db_path, &Default::default(), /*readonly=*/ true)
            .expect("Failed to open table info db in readonly mode.");
        
        // VALIDATION: Verify indexer version matches main DB
        // (Additional check - would require reading version from both DBs)
        
        indexer_db
            .create_checkpoint(checkpoint_dir.as_ref().join(TABLE_INFO_DB_NAME))
            .expect("Table info db checkpoint creation fails.");
    }

    AptosDB::create_checkpoint(source_dir, checkpoint_dir, enable_storage_sharding)
        .expect("db checkpoint creation fails.");

    println!("Checkpoint for DBs is done.");
}
```

Additionally, consider adding a metadata file to databases indicating whether they were created with indexer support, enabling automated validation.

## Proof of Concept

**Steps to Reproduce:**

```bash
# Step 1: Create source DB WITHOUT indexer
./aptos-executor-benchmark CreateDb \
    --data-dir=/tmp/test-source \
    --num-accounts=1000

# Verify: /tmp/test-source should contain main DB but NO index_async_v2_db directory
ls /tmp/test-source/
# Expected: Only main DB directories, no index_async_v2_db

# Step 2: Run benchmark WITH indexer enabled, triggering checkpoint
./aptos-executor-benchmark RunExecutor \
    --enable-indexer-grpc \
    --data-dir=/tmp/test-source \
    --checkpoint-dir=/tmp/test-checkpoint \
    --blocks=10

# Verify: Source DB is now corrupted
ls /tmp/test-source/
# Expected: index_async_v2_db directory NOW EXISTS (created by create_checkpoint)

# Step 3: Verify desynchronization
# The main DB has transactions, but indexer DB is empty (version 0)
# This can be verified by checking DB contents or attempting to query indexer
```

**Expected Behavior:** The operation should FAIL with a clear error message indicating the indexer DB doesn't exist in the source, rather than silently creating an empty database.

**Actual Behavior:** The operation succeeds but corrupts the source database by creating an empty indexer DB that doesn't match the main DB state.

## Notes

This vulnerability specifically affects the executor-benchmark tool but represents a broader pattern issue: any code path that conditionally opens databases based on runtime flags without validating existence or consistency can cause similar corruption. The root cause is the combination of:
1. RocksDB's `create_if_missing` behavior
2. Lack of validation before database operations
3. Separate control flow for main vs indexer databases

While this is currently in benchmark code, similar patterns could exist in production node code that should be audited.

### Citations

**File:** execution/executor-benchmark/src/lib.rs (L127-228)
```rust
fn init_indexer_wrapper(
    config: &NodeConfig,
    db: &DbReaderWriter,
    storage_test_config: &StorageTestConfig,
    start_version: u64,
) -> Option<(Arc<TableInfoService>, Arc<AtomicU64>, Arc<AtomicBool>)> {
    if !storage_test_config.enable_indexer_grpc {
        return None;
    }

    let db_path = config
        .storage
        .get_dir_paths()
        .default_root_path()
        .join(TABLE_INFO_DB_NAME);
    let rocksdb_config = config.storage.rocksdb_configs.index_db_config;
    let indexer_db = open_db(db_path, &rocksdb_config, /*readonly=*/ false)
        .expect("Failed to open indexer async v2 db");
    let indexer_async_v2 =
        Arc::new(IndexerAsyncV2::new(indexer_db).expect("Failed to initialize indexer async v2"));

    // Create API context for table_info_service
    let (mp_sender, _mp_receiver) = futures::channel::mpsc::channel(1);
    // Use ChainId::test() for benchmark
    let chain_id = aptos_types::chain_id::ChainId::test();
    let context = Arc::new(Context::new(
        chain_id,
        db.reader.clone(),
        mp_sender,
        config.clone(),
        Some(Arc::new(
            IndexerReaders::new(Some(indexer_async_v2.clone()), None).unwrap(),
        )),
    ));
    let service_context = ServiceContext {
        context: context.clone(),
        processor_task_count: config.indexer_grpc.processor_task_count.unwrap_or_else(|| {
            get_default_processor_task_count(config.indexer_grpc.use_data_service_interface)
        }),
        processor_batch_size: config.indexer_grpc.processor_batch_size,
        output_batch_size: config.indexer_grpc.output_batch_size,
        transaction_channel_size: config.indexer_grpc.transaction_channel_size,
        max_transaction_filter_size_bytes: config.indexer_grpc.max_transaction_filter_size_bytes,
    };

    // Spawn table_info_service in tokio runtime
    let indexer_async_v2_clone = indexer_async_v2.clone();
    let config_clone = config.clone();
    let indexer_runtime = tokio::runtime::Runtime::new().unwrap();
    let table_info_service = Arc::new(TableInfoService::new(
        context,
        indexer_async_v2_clone.next_version(),
        config_clone.indexer_table_info.parser_task_count,
        config_clone.indexer_table_info.parser_batch_size,
        None, // No backup/restore for benchmark
        indexer_async_v2_clone,
    ));
    let table_info_service_clone = table_info_service.clone();
    indexer_runtime.spawn(async move {
        println!(
            "**** Starting table_info_service at version {}.",
            table_info_service_clone.next_version()
        );
        table_info_service_clone.run().await;
    });
    let grpc_version = Arc::new(AtomicU64::new(0));
    let grpc_version_clone = grpc_version.clone();
    let abort_handle = Arc::new(AtomicBool::new(false));
    let abort_handle_clone = abort_handle.clone();
    indexer_runtime.spawn(async move {
        let grpc_service = FullnodeDataService {
            service_context,
            abort_handle,
        };
        println!("Starting grpc stream at version {start_version}.");
        let request = GetTransactionsFromNodeRequest {
            starting_version: Some(start_version),
            transactions_count: None,
        };
        let mut response = grpc_service
            .get_transactions_from_node(request.into_request())
            .await
            .unwrap()
            .into_inner();
        while let Some(item) = response.next().await {
            if let Ok(r) = item {
                if let Some(response) = r.response {
                    if let Response::Data(data) = response {
                        if let Some(txn) = data.transactions.last().as_ref() {
                            grpc_version_clone.store(txn.version, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    });

    // Keep runtime alive - it will be dropped when the function scope ends
    std::mem::forget(indexer_runtime);

    Some((table_info_service, grpc_version, abort_handle_clone))
}
```

**File:** execution/executor-benchmark/src/lib.rs (L230-256)
```rust
fn create_checkpoint(
    source_dir: impl AsRef<Path>,
    checkpoint_dir: impl AsRef<Path>,
    enable_storage_sharding: bool,
    enable_indexer_grpc: bool,
) {
    println!("Creating checkpoint for DBs.");
    // Create rocksdb checkpoint.
    if checkpoint_dir.as_ref().exists() {
        fs::remove_dir_all(checkpoint_dir.as_ref()).unwrap_or(());
    }
    std::fs::create_dir_all(checkpoint_dir.as_ref()).unwrap();

    if enable_indexer_grpc {
        let db_path = source_dir.as_ref().join(TABLE_INFO_DB_NAME);
        let indexer_db = open_db(db_path, &Default::default(), /*readonly=*/ false)
            .expect("Failed to open table info db.");
        indexer_db
            .create_checkpoint(checkpoint_dir.as_ref().join(TABLE_INFO_DB_NAME))
            .expect("Table info db checkpoint creation fails.");
    }

    AptosDB::create_checkpoint(source_dir, checkpoint_dir, enable_storage_sharding)
        .expect("db checkpoint creation fails.");

    println!("Checkpoint for DBs is done.");
}
```

**File:** storage/rocksdb-options/src/lib.rs (L38-41)
```rust
    if !readonly {
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
    }
```

**File:** storage/schemadb/src/lib.rs (L141-193)
```rust
    fn open_cf_impl(
        db_opts: &Options,
        path: impl AsRef<Path>,
        name: &str,
        cfds: Vec<ColumnFamilyDescriptor>,
        open_mode: OpenMode,
    ) -> DbResult<DB> {
        // ignore error, since it'll fail to list cfs on the first open
        let existing_cfs: HashSet<String> = rocksdb::DB::list_cf(db_opts, path.de_unc())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let requested_cfs: HashSet<String> =
            cfds.iter().map(|cfd| cfd.name().to_string()).collect();
        let missing_cfs: HashSet<&str> = requested_cfs
            .difference(&existing_cfs)
            .map(|cf| {
                warn!("Missing CF: {}", cf);
                cf.as_ref()
            })
            .collect();
        let unrecognized_cfs = existing_cfs.difference(&requested_cfs);

        let all_cfds = cfds
            .into_iter()
            .chain(unrecognized_cfs.map(Self::cfd_for_unrecognized_cf));

        let inner = {
            use rocksdb::DB;
            use OpenMode::*;

            match open_mode {
                ReadWrite => DB::open_cf_descriptors(db_opts, path.de_unc(), all_cfds),
                ReadOnly => {
                    DB::open_cf_descriptors_read_only(
                        db_opts,
                        path.de_unc(),
                        all_cfds.filter(|cfd| !missing_cfs.contains(cfd.name())),
                        false, /* error_if_log_file_exist */
                    )
                },
                Secondary(secondary_path) => DB::open_cf_descriptors_as_secondary(
                    db_opts,
                    path.de_unc(),
                    secondary_path,
                    all_cfds,
                ),
            }
        }
        .into_db_res()?;

        Ok(Self::log_construct(name, open_mode, inner))
    }
```

**File:** execution/executor-benchmark/src/main.rs (L486-593)
```rust
fn run<E>(opt: Opt)
where
    E: VMBlockExecutor + 'static,
{
    match opt.cmd {
        Command::CreateDb {
            data_dir,
            num_accounts,
            init_account_balance,
            enable_feature,
            disable_feature,
        } => {
            aptos_executor_benchmark::db_generator::create_db_with_accounts::<E>(
                num_accounts,
                init_account_balance,
                opt.block_size,
                data_dir,
                opt.storage_opt.storage_test_config(),
                opt.verify_sequence_numbers,
                opt.pipeline_opt
                    .pipeline_config(opt.storage_opt.enable_indexer_grpc),
                get_init_features(enable_feature, disable_feature),
                opt.use_keyless_accounts,
            );
        },
        Command::RunExecutor {
            blocks,
            main_signer_accounts,
            additional_dst_pool_accounts,
            transaction_type,
            transaction_weights,
            module_working_set_size,
            use_sender_account_pool,
            data_dir,
            checkpoint_dir,
            enable_feature,
            disable_feature,
        } => {
            // aptos_types::on_chain_config::hack_enable_default_features_for_genesis(enable_feature);
            // aptos_types::on_chain_config::hack_disable_default_features_for_genesis(
            //     disable_feature,
            // );

            let workload = if transaction_type.is_empty() {
                BenchmarkWorkload::Transfer {
                    connected_tx_grps: opt.connected_tx_grps,
                    shuffle_connected_txns: opt.shuffle_connected_txns,
                    hotspot_probability: opt.hotspot_probability,
                }
            } else {
                let mix_per_phase = TransactionTypeArg::args_to_transaction_mix_per_phase(
                    &transaction_type,
                    &transaction_weights,
                    &[],
                    module_working_set_size,
                    use_sender_account_pool,
                    WorkflowProgress::MoveByPhases,
                );
                assert!(mix_per_phase.len() == 1);
                BenchmarkWorkload::TransactionMix(mix_per_phase[0].clone())
            };

            if let Some(hotspot_probability) = opt.hotspot_probability {
                if !(0.5..1.0).contains(&hotspot_probability) {
                    panic!(
                        "Parameter hotspot-probability has to be a decimal number in [0.5, 1.0)."
                    );
                }
            }

            aptos_executor_benchmark::run_benchmark::<E>(
                opt.block_size,
                blocks,
                workload,
                opt.transactions_per_sender,
                main_signer_accounts,
                additional_dst_pool_accounts,
                data_dir,
                checkpoint_dir,
                opt.verify_sequence_numbers,
                opt.storage_opt.storage_test_config(),
                opt.pipeline_opt
                    .pipeline_config(opt.storage_opt.enable_indexer_grpc),
                get_init_features(enable_feature, disable_feature),
                opt.use_keyless_accounts,
            );
        },
        Command::AddAccounts {
            data_dir,
            checkpoint_dir,
            num_new_accounts,
            init_account_balance,
        } => {
            aptos_executor_benchmark::add_accounts::<E>(
                num_new_accounts,
                init_account_balance,
                opt.block_size,
                data_dir,
                checkpoint_dir,
                opt.storage_opt.storage_test_config(),
                opt.verify_sequence_numbers,
                opt.pipeline_opt
                    .pipeline_config(opt.storage_opt.enable_indexer_grpc),
                Features::default(),
                opt.use_keyless_accounts,
            );
        },
    }
```
