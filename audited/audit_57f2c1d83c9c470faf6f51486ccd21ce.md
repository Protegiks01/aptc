# Audit Report

## Title
Indexer Initialization Failure Causes Complete Node Crash Despite Being Optional Component

## Summary
The `bootstrap_indexer()` function follows an unsafe asynchronous initialization pattern where the runtime is returned before initialization completes. When the spawned initialization task encounters errors (database connection failures, migration errors, etc.), it triggers panics that invoke the global crash handler, causing the entire node process to exit with code 12. This violates fault isolation principles, allowing an optional indexer component to bring down critical consensus and execution systems.

## Finding Description
The vulnerability exists in the initialization flow of the indexer subsystem: [1](#0-0) 

This function calls `bootstrap_indexer_stream` which is actually the `bootstrap` function in the indexer runtime: [2](#0-1) 

The critical flaw is that `bootstrap()` creates a runtime and spawns an async task, then **returns immediately** (line 103) before any initialization has completed. The actual initialization occurs asynchronously in `run_forever()`: [3](#0-2) 

Throughout `run_forever()`, errors are handled with `.expect()` and `panic!()` calls that trigger on:
- Database connection pool creation failure (line 124)
- Processor instantiation failure (lines 132-144)
- Tailer creation failure (line 150)
- Migration execution failure (line 154)
- Chain ID validation failure (line 204)

Additionally, the main processing loop contains panic calls: [4](#0-3) 

When any panic occurs, the global panic handler executes: [5](#0-4) 

The handler calls `process::exit(12)`, terminating the **entire node process**, including consensus, execution, mempool, and all other critical components.

## Impact Explanation
This represents a **High Severity** vulnerability per the Aptos bug bounty criteria:

1. **Validator node slowdowns** - The actual impact is worse: complete node termination, not just slowdown
2. **Significant protocol violations** - Availability and liveness are core protocol requirements; allowing an optional component to kill the entire node violates these guarantees

The scope of impact includes:
- Complete loss of consensus participation (validator stops voting)
- All transaction execution halts
- State synchronization stops
- Mempool becomes unavailable
- All APIs and services terminate

For validator nodes, this causes them to be marked as offline, potentially incurring penalties. For fullnodes, this disrupts service availability. The node requires manual restart to recover.

## Likelihood Explanation
**Likelihood: High**

This vulnerability is highly likely to occur in production because:

1. **Common trigger conditions:**
   - PostgreSQL database unavailability (network partitions, DB crashes, maintenance)
   - Incorrect database credentials in configuration
   - Database schema migration failures
   - Network connectivity issues to database
   - Resource exhaustion on database server

2. **No defensive coding:**
   - No retry logic for transient failures
   - No graceful degradation
   - No isolation from critical components

3. **Operational complexity:**
   - Indexer requires external PostgreSQL database
   - Database must be properly configured before node start
   - Schema migrations can fail for various reasons

4. **Silent failure mode:**
   - Bootstrap appears to succeed (returns Ok)
   - Node initialization completes normally
   - Crash occurs asynchronously, appearing as unexpected behavior

## Recommendation

Implement proper error handling and fault isolation for the indexer subsystem:

**Option 1: Graceful Error Handling (Recommended)**
```rust
pub fn bootstrap(
    config: &NodeConfig,
    chain_id: ChainId,
    db: Arc<dyn DbReader>,
    mp_sender: MempoolClientSender,
) -> Option<anyhow::Result<Runtime>> {
    if !config.indexer.enabled {
        return None;
    }

    let runtime = aptos_runtimes::spawn_named_runtime("indexer".into(), None);
    let indexer_config = config.indexer.clone();
    let node_config = config.clone();

    runtime.spawn(async move {
        let context = Arc::new(Context::new(
            chain_id,
            db,
            mp_sender,
            node_config,
            None,
        ));
        
        // Wrap run_forever in error handling
        if let Err(e) = run_forever_safe(indexer_config, context).await {
            error!("Indexer failed: {:?}. Node will continue without indexer.", e);
            // Log error but don't panic - let node continue
        }
    });

    Some(Ok(runtime))
}

async fn run_forever_safe(config: IndexerConfig, context: Arc<Context>) -> Result<()> {
    let processor_name = config.processor.clone().unwrap();
    let db_uri = &config.postgres_uri.unwrap();
    
    // Use ? instead of expect() to propagate errors
    let conn_pool = new_db_pool(db_uri)
        .context("Failed to create connection pool")?;
    
    let processor_enum = Processor::from_string(&processor_name);
    let processor: Arc<dyn TransactionProcessor> = match processor_enum {
        Processor::DefaultProcessor => {
            Arc::new(DefaultTransactionProcessor::new(conn_pool.clone()))
        },
        // ... other processors
    };
    
    let options = TransactionFetcherOptions::new(None, None, Some(batch_size), None, fetch_tasks);
    let tailer = Tailer::new(context, conn_pool.clone(), processor, options)?;
    
    if !skip_migrations {
        tailer.run_migrations_safe()?;  // Return Result instead of panic
    }
    
    // Continue with processing...
    Ok(())
}
```

**Option 2: Separate Health Monitoring**
Implement a health check system that monitors indexer task status and reports failures without crashing the node.

**Option 3: Configuration Validation**
Add synchronous validation during bootstrap to fail fast if indexer is misconfigured, before spawning the async task.

## Proof of Concept

**Reproduction Steps:**

1. Configure an Aptos node with indexer enabled
2. Set incorrect PostgreSQL credentials in `indexer.postgres_uri`
3. Start the node

**Expected (current) behavior:**
```bash
# Node starts successfully
INFO aptos_node: Node started
INFO indexer: Starting indexer...
INFO indexer: Creating connection pool...
# Panic occurs when connection fails
ERROR crash_handler: thread 'tokio-runtime-worker' panicked at 'Failed to create connection pool'
# Entire node process exits with code 12
```

**Alternative trigger via migration failure:**
1. Corrupt the `__diesel_schema_migrations` table in PostgreSQL
2. Start node with indexer enabled
3. Node crashes when `run_migrations()` encounters corrupted state

**Code to reproduce:**
```rust
// In a test environment
#[tokio::test]
async fn test_indexer_crash_on_db_failure() {
    // Set up node config with invalid database URI
    let mut node_config = NodeConfig::default();
    node_config.indexer.enabled = true;
    node_config.indexer.postgres_uri = Some("postgresql://invalid:invalid@localhost:5432/nonexistent".to_string());
    
    // Attempt to bootstrap indexer
    let result = bootstrap_indexer(
        &node_config,
        ChainId::test(),
        Arc::new(MockDbReader::new()),
        MempoolClientSender::new(),
    );
    
    // Bootstrap succeeds (returns runtime)
    assert!(result.is_ok());
    
    // Wait for async task to execute
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // At this point, if no panic handler override, process would exit
    // In test, we can catch the panic but in production it kills the node
}
```

## Notes

This vulnerability also affects other indexer components with similar patterns: [6](#0-5) 

The internal indexer DB service has the same issue where `.unwrap()` on the async task will trigger the global panic handler and crash the entire node.

The core architectural flaw is that optional, auxiliary components (indexers) are not properly isolated from critical consensus/execution components. A well-designed system should allow non-critical components to fail without affecting core functionality.

### Citations

**File:** aptos-node/src/indexer.rs (L12-24)
```rust
pub fn bootstrap_indexer(
    node_config: &NodeConfig,
    chain_id: ChainId,
    aptos_db: Arc<dyn DbReader>,
    mp_client_sender: MempoolClientSender,
) -> Result<Option<Runtime>, anyhow::Error> {
    use aptos_indexer::runtime::bootstrap as bootstrap_indexer_stream;

    match bootstrap_indexer_stream(&node_config, chain_id, aptos_db, mp_client_sender) {
        None => Ok(None),
        Some(res) => res.map(Some),
    }
}
```

**File:** crates/indexer/src/runtime.rs (L77-104)
```rust
pub fn bootstrap(
    config: &NodeConfig,
    chain_id: ChainId,
    db: Arc<dyn DbReader>,
    mp_sender: MempoolClientSender,
) -> Option<anyhow::Result<Runtime>> {
    if !config.indexer.enabled {
        return None;
    }

    let runtime = aptos_runtimes::spawn_named_runtime("indexer".into(), None);

    let indexer_config = config.indexer.clone();
    let node_config = config.clone();

    runtime.spawn(async move {
        let context = Arc::new(Context::new(
            chain_id,
            db,
            mp_sender,
            node_config,
            None, /* table info reader */
        ));
        run_forever(indexer_config, context).await;
    });

    Some(Ok(runtime))
}
```

**File:** crates/indexer/src/runtime.rs (L106-156)
```rust
pub async fn run_forever(config: IndexerConfig, context: Arc<Context>) {
    // All of these options should be filled already with defaults
    let processor_name = config.processor.clone().unwrap();
    let check_chain_id = config.check_chain_id.unwrap();
    let skip_migrations = config.skip_migrations.unwrap();
    let fetch_tasks = config.fetch_tasks.unwrap();
    let processor_tasks = config.processor_tasks.unwrap();
    let emit_every = config.emit_every.unwrap();
    let batch_size = config.batch_size.unwrap();
    let lookback_versions = config.gap_lookback_versions.unwrap() as i64;

    info!(processor_name = processor_name, "Starting indexer...");

    let db_uri = &config.postgres_uri.unwrap();
    info!(
        processor_name = processor_name,
        "Creating connection pool..."
    );
    let conn_pool = new_db_pool(db_uri).expect("Failed to create connection pool");
    info!(
        processor_name = processor_name,
        "Created the connection pool... "
    );

    info!(processor_name = processor_name, "Instantiating tailer... ");

    let processor_enum = Processor::from_string(&processor_name);
    let processor: Arc<dyn TransactionProcessor> = match processor_enum {
        Processor::DefaultProcessor => {
            Arc::new(DefaultTransactionProcessor::new(conn_pool.clone()))
        },
        Processor::TokenProcessor => Arc::new(TokenTransactionProcessor::new(
            conn_pool.clone(),
            config.ans_contract_address,
            config.nft_points_contract,
        )),
        Processor::CoinProcessor => Arc::new(CoinTransactionProcessor::new(conn_pool.clone())),
        Processor::StakeProcessor => Arc::new(StakeTransactionProcessor::new(conn_pool.clone())),
    };

    let options =
        TransactionFetcherOptions::new(None, None, Some(batch_size), None, fetch_tasks as usize);

    let tailer = Tailer::new(context, conn_pool.clone(), processor, options)
        .expect("Failed to instantiate tailer");

    if !skip_migrations {
        info!(processor_name = processor_name, "Running migrations...");
        tailer.run_migrations();
    }

```

**File:** crates/indexer/src/runtime.rs (L209-243)
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
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L23-46)
```rust
pub fn bootstrap_internal_indexer_db(
    config: &NodeConfig,
    db_rw: DbReaderWriter,
    internal_indexer_db: Option<InternalIndexerDB>,
    update_receiver: Option<WatchReceiver<(Instant, Version)>>,
) -> Option<(Runtime, Arc<DBIndexer>)> {
    if !config.indexer_db_config.is_internal_indexer_db_enabled() || internal_indexer_db.is_none() {
        return None;
    }
    let runtime = aptos_runtimes::spawn_named_runtime("index-db".to_string(), None);
    // Set up db config and open up the db initially to read metadata
    let mut indexer_service = InternalIndexerDBService::new(
        db_rw.reader,
        internal_indexer_db.unwrap(),
        update_receiver.expect("Internal indexer db update receiver is missing"),
    );
    let db_indexer = indexer_service.get_db_indexer();
    // Spawn task for db indexer
    let config_clone = config.to_owned();
    runtime.spawn(async move {
        indexer_service.run(&config_clone).await.unwrap();
    });

    Some((runtime, db_indexer))
```
