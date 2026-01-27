# Audit Report

## Title
Indexer Initialization Failure Causes Total Validator Node Crash Affecting Consensus Participation

## Summary
The `bootstrap_indexer()` function spawns an asynchronous task that can panic during initialization (e.g., database connection failure), causing the global panic handler to terminate the entire validator node process via `process::exit(12)`, taking down consensus participation. The indexer should degrade gracefully without affecting core consensus operations.

## Finding Description

The vulnerability exists in the indexer initialization flow where failures in an auxiliary component (the indexer) cause total node failure:

**1. Global Panic Handler Setup:**
The node sets up a global panic handler that terminates the process on any panic. [1](#0-0) [2](#0-1) 

The panic handler only exempts `VMState::VERIFIER` and `VMState::DESERIALIZER` states from process termination.

**2. Indexer Bootstrap Returns Immediately:**
The `bootstrap_indexer()` function creates a runtime and spawns an asynchronous task, then returns `Ok(runtime)` immediately without waiting for initialization. [3](#0-2) [4](#0-3) 

**3. Asynchronous Initialization with Panics:**
The actual indexer initialization happens inside the spawned task in `run_forever()`, which contains multiple panic points: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

**4. Node Startup Sequence:**
The node starts consensus AFTER the indexer returns successfully, but BEFORE the indexer task completes initialization: [9](#0-8) [10](#0-9) [11](#0-10) 

**Attack Scenario:**
1. Validator node starts with indexer enabled
2. Node completes bootstrap, consensus starts
3. Indexer task executes asynchronously, attempts Postgres connection
4. Connection fails (DB unreachable, credentials invalid, network issue)
5. Task panics with `.expect("Failed to create connection pool")`
6. Global panic handler catches panic, calls `process::exit(12)`
7. Entire validator process terminates, removing validator from consensus participation

The indexer runs with default `VMState::OTHER`, so it is NOT protected by the panic handler's VMState exemptions. [12](#0-11) 

## Impact Explanation

**Severity: High**

This vulnerability meets the **High Severity** criteria from the Aptos bug bounty program:
- **Validator node slowdowns**: Validators become completely unavailable (worse than slowdown)
- **Significant protocol violations**: Violates the principle that auxiliary components should not affect consensus availability

**Impact Quantification:**
- Any validator with indexer enabled is vulnerable to total node failure
- Affects consensus participation: reduces active validator set
- If multiple validators experience simultaneous indexer failures (e.g., shared Postgres infrastructure issues), network liveness could be severely impacted
- Unlike graceful degradation (continuing without indexing), this causes catastrophic failure

**Broken Invariant:**
This violates the availability invariant that validators should remain operational for consensus participation even when non-critical auxiliary systems fail. The indexer is not essential to consensus safety or liveness, yet its failure brings down the entire node.

## Likelihood Explanation

**Likelihood: Medium-High**

Database connection failures are common in production environments:
- **Network partitions** between node and Postgres server
- **Postgres crashes or maintenance** windows
- **Resource exhaustion** on database server (connections, memory, disk)
- **Configuration errors** (wrong credentials, connection string)
- **Cloud infrastructure issues** affecting database availability
- **Database migration failures** (schema changes, constraints)

Factors increasing likelihood:
- Indexer is often enabled on full nodes and validators for observability
- Single point of failure if multiple nodes share one Postgres instance
- No retry logic or graceful degradation in initialization
- Synchronous panic behavior (no error recovery)

The vulnerability is triggered automatically by environmental conditions, requiring no sophisticated attack vector.

## Recommendation

**Solution: Implement graceful degradation for indexer failures**

The indexer bootstrap should handle initialization failures gracefully without crashing the node:

```rust
// In crates/indexer/src/runtime.rs
pub async fn run_forever(config: IndexerConfig, context: Arc<Context>) {
    // Wrap initialization in a catch_unwind or use Result propagation
    let conn_pool = match new_db_pool(&config.postgres_uri.unwrap()) {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to create indexer connection pool: {:?}. Indexer will not run.", e);
            // Return early - allow node to continue without indexer
            return;
        }
    };
    
    let tailer = match Tailer::new(context, conn_pool.clone(), processor, options) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to instantiate tailer: {:?}. Indexer will not run.", e);
            return;
        }
    };
    
    // Continue with similar error handling for all initialization steps...
}
```

**Alternative: Make indexer truly optional**

Update the node startup to gracefully handle indexer failures:

```rust
// In aptos-node/src/services.rs
let indexer_runtime = match indexer::bootstrap_indexer(...) {
    Ok(runtime) => runtime,
    Err(e) => {
        warn!("Indexer failed to bootstrap: {:?}. Continuing without indexer.", e);
        None
    }
};
```

**Key principles:**
1. Replace all `.expect()` and `.unwrap_or_else(panic)` with error logging and graceful returns
2. Consider adding health checks that expose indexer status without crashing
3. Implement retry logic with exponential backoff for transient failures
4. Add configuration option to mark indexer as critical vs. optional

## Proof of Concept

**Reproduction Steps:**

1. Configure a validator node with indexer enabled:
```yaml
# node.yaml
indexer:
  enabled: true
  postgres_uri: "postgresql://invalid_user:wrong_pass@nonexistent_host:5432/indexer_db"
  processor: "default_processor"
```

2. Start the node:
```bash
cargo run --release --bin aptos-node -- -f node.yaml
```

3. **Expected behavior (current):**
   - Node starts successfully
   - Consensus begins
   - Indexer task spawns asynchronously
   - Indexer attempts DB connection
   - Connection fails, task panics
   - Global panic handler executes
   - Process exits with code 12
   - Consensus participation terminates

4. **Expected behavior (after fix):**
   - Node starts successfully
   - Consensus begins
   - Indexer task spawns asynchronously
   - Indexer attempts DB connection
   - Connection fails, error logged
   - Indexer task exits gracefully
   - Node continues operating, consensus unaffected
   - Indexer marked as unavailable in health checks

**Log evidence:**
```
ERROR Failed to create connection pool: ... 
[crash-handler] Panic occurred: ...
Process exited with code 12
```

This vulnerability can be reproduced in any environment where the Postgres database is unavailable or misconfigured, demonstrating the critical failure mode of non-graceful degradation.

## Notes

The vulnerability affects the intersection of node availability and indexer reliability. While the indexer is designed to provide blockchain data indexing for APIs and analytics, it should not be in the critical path for consensus participation. The current implementation violates defense-in-depth principles by allowing an auxiliary component to take down the entire validator process.

This issue is particularly concerning because:
1. It creates operational fragility where database issues cascade to consensus failures
2. It violates operator expectations that consensus would continue even if indexing fails
3. It creates a potential DoS vector if attackers can interfere with validator database infrastructure
4. It makes multi-validator deployments fragile if they share database infrastructure

### Citations

**File:** aptos-node/src/lib.rs (L234-234)
```rust
    aptos_crash_handler::setup_panic_handler();
```

**File:** aptos-node/src/lib.rs (L787-795)
```rust
    ) = services::bootstrap_api_and_indexer(
        &node_config,
        db_rw.clone(),
        chain_id,
        indexer_db_opt,
        update_receiver,
        api_port_tx,
        indexer_grpc_port_tx,
    )?;
```

**File:** aptos-node/src/lib.rs (L841-851)
```rust
    let consensus_runtime = consensus::create_consensus_runtime(
        &node_config,
        db_rw.clone(),
        consensus_reconfig_subscription,
        consensus_network_interfaces,
        consensus_notifier.clone(),
        consensus_to_mempool_sender.clone(),
        vtxn_pool,
        consensus_publisher.clone(),
        &mut admin_service,
    );
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

**File:** crates/indexer/src/runtime.rs (L124-124)
```rust
    let conn_pool = new_db_pool(db_uri).expect("Failed to create connection pool");
```

**File:** crates/indexer/src/runtime.rs (L149-150)
```rust
    let tailer = Tailer::new(context, conn_pool.clone(), processor, options)
        .expect("Failed to instantiate tailer");
```

**File:** crates/indexer/src/runtime.rs (L163-172)
```rust
    let starting_version_from_db_short = tailer
        .get_start_version(&processor_name)
        .unwrap_or_else(|e| panic!("Failed to get starting version: {:?}", e))
        .unwrap_or_else(|| {
            info!(
                processor_name = processor_name,
                "No starting version from db so starting from version 0"
            );
            0
        }) as u64;
```

**File:** crates/indexer/src/runtime.rs (L201-205)
```rust
        tailer
            .check_or_update_chain_id()
            .await
            .expect("Failed to get chain ID");
    }
```

**File:** aptos-node/src/services.rs (L124-129)
```rust
    let indexer_runtime = indexer::bootstrap_indexer(
        node_config,
        chain_id,
        db_rw.reader.clone(),
        mempool_client_sender.clone(),
    )?;
```

**File:** third_party/move/move-core/types/src/state.rs (L15-25)
```rust
thread_local! {
    static STATE: RefCell<VMState> = const { RefCell::new(VMState::OTHER) };
}

pub fn set_state(state: VMState) -> VMState {
    STATE.with(|s| s.replace(state))
}

pub fn get_state() -> VMState {
    STATE.with(|s| *s.borrow())
}
```
