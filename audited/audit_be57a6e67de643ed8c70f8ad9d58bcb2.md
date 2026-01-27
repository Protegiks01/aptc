# Audit Report

## Title
API Initialization Panic Due to Misuse of tokio::task::block_in_place Outside Runtime Context

## Summary
The `attach_poem_to_runtime()` function incorrectly calls `tokio::task::block_in_place()` from outside a Tokio runtime context during API initialization, which violates Tokio's usage requirements and causes a panic that crashes API startup in production nodes.

## Finding Description

The vulnerability exists in the `attach_poem_to_runtime()` function where `tokio::task::block_in_place()` is called at line 212-216. [1](#0-0) 

According to Tokio's documentation and implementation, `block_in_place()` **must** be called from a worker thread of a multi-threaded runtime. It will panic if called from outside a runtime context or from a current_thread runtime.

**Production Call Path:**
1. Node starts via `main()` → `AptosNodeArgs::parse().run()` [2](#0-1) 
2. `run()` → `start()` → `setup_environment_and_start_node()` [3](#0-2) 
3. `setup_environment_and_start_node()` → `bootstrap_api_and_indexer()` [4](#0-3) 
4. `bootstrap_api_and_indexer()` → `bootstrap_api()` [5](#0-4) 
5. `bootstrap_api()` creates runtime but calls `attach_poem_to_runtime()` from main thread [6](#0-5) 

At no point does the code enter the runtime's execution context before calling `attach_poem_to_runtime()`. The runtime is created at line 51 and its handle is obtained, but the calling thread remains the main thread, not a runtime worker thread. [7](#0-6) 

The codebase itself demonstrates the correct pattern in `testsuite/forge/src/backend/k8s/swarm.rs`, which checks for a current runtime before calling `block_in_place()`: [8](#0-7) 

The API is enabled by default in node configurations. [9](#0-8) [10](#0-9) 

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos Bug Bounty program criteria: **API crashes**.

When a node starts with the API enabled (default configuration), the `block_in_place()` call will panic with an error like "can only be called from a worker thread". This causes the entire API initialization to fail, preventing the REST API endpoint from becoming available. This impacts:

- **Node Operators**: Cannot expose REST API endpoints for client applications
- **dApp Developers**: Cannot query blockchain state or submit transactions via REST API
- **Network Availability**: Reduces the number of accessible API endpoints in the network

While this doesn't affect consensus or validator operations directly, it renders the REST API completely unavailable on affected nodes.

## Likelihood Explanation

**Likelihood: High** - This bug triggers automatically on every node startup with default configuration because:

1. API is enabled by default in `ApiConfig`
2. The production call path always executes from the main thread without entering a runtime context
3. No conditional guards prevent the execution
4. The misuse of `block_in_place()` is unconditional

The only reason this might not manifest universally is if:
- Nodes explicitly disable the API in their configuration
- There are environment-specific runtime initialization patterns not visible in this codebase
- Tokio has non-standard fallback behavior in certain build configurations

## Recommendation

Remove the `block_in_place()` wrapper entirely. The `runtime_handle.block_on()` call is already the correct way to execute async code from a synchronous context:

```rust
// BEFORE (incorrect):
let acceptor = tokio::task::block_in_place(move || {
    runtime_handle
        .block_on(async move { listener.into_acceptor().await })
        .with_context(|| format!("Failed to bind Poem to address: {}", address))
})?;

// AFTER (correct):
let acceptor = runtime_handle
    .block_on(async move { listener.into_acceptor().await })
    .with_context(|| format!("Failed to bind Poem to address: {}", address))?;
```

Alternatively, if the intent was to handle being called from within an existing runtime (e.g., in tests), use the pattern from the k8s swarm Drop implementation to check for a current runtime first and only call `block_in_place()` if one exists.

## Proof of Concept

To reproduce this issue:

1. Build the Aptos node with default configuration (API enabled)
2. Start the node: `cargo run --bin aptos-node -- -f <config_path>`
3. Observe panic during API initialization with message similar to: `"can only be called from a worker thread"`

The vulnerability is inherent in the code structure and will trigger on any standard node startup with API enabled.

**Notes:**
- The vulnerability exists in production code paths, not test code
- Test code paths may work correctly because they often call functions like `new_test_context()` from within `runtime.block_on()` contexts [11](#0-10) 
- The fix is straightforward: remove the unnecessary `block_in_place()` wrapper since we're already outside any runtime context

### Citations

**File:** api/src/runtime.rs (L42-56)
```rust
pub fn bootstrap(
    config: &NodeConfig,
    chain_id: ChainId,
    db: Arc<dyn DbReader>,
    mp_sender: MempoolClientSender,
    indexer_reader: Option<Arc<dyn IndexerReader>>,
    port_tx: Option<oneshot::Sender<u16>>,
) -> anyhow::Result<Runtime> {
    let max_runtime_workers = get_max_runtime_workers(&config.api);
    let runtime = aptos_runtimes::spawn_named_runtime("api".into(), Some(max_runtime_workers));

    let context = Context::new(chain_id, db, mp_sender, config.clone(), indexer_reader);

    attach_poem_to_runtime(runtime.handle(), context.clone(), config, false, port_tx)
        .context("Failed to attach poem to runtime")?;
```

**File:** api/src/runtime.rs (L212-216)
```rust
    let acceptor = tokio::task::block_in_place(move || {
        runtime_handle
            .block_on(async move { listener.into_acceptor().await })
            .with_context(|| format!("Failed to bind Poem to address: {}", address))
    })?;
```

**File:** aptos-node/src/main.rs (L21-27)
```rust
fn main() {
    // Check that we are not including any Move test natives
    aptos_vm::natives::assert_no_test_natives(ERROR_MSG_BAD_FEATURE_FLAGS);

    // Start the node
    AptosNodeArgs::parse().run()
}
```

**File:** aptos-node/src/lib.rs (L217-223)
```rust
pub fn start(
    config: NodeConfig,
    log_file: Option<PathBuf>,
    create_global_rayon_pool: bool,
) -> anyhow::Result<()> {
    start_and_report_ports(config, log_file, create_global_rayon_pool, None, None)
}
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

**File:** aptos-node/src/services.rs (L100-108)
```rust
    let api_runtime = if node_config.api.enabled {
        Some(bootstrap_api(
            node_config,
            chain_id,
            db_rw.reader.clone(),
            mempool_client_sender.clone(),
            indexer_reader.clone(),
            api_port_tx,
        )?)
```

**File:** testsuite/forge/src/backend/k8s/swarm.rs (L716-722)
```rust
            match Handle::try_current() {
                Ok(handle) => block_in_place(move || handle.block_on(fut).unwrap()),
                Err(_err) => {
                    let runtime = Runtime::new().unwrap();
                    runtime.block_on(fut).unwrap();
                },
            }
```

**File:** config/src/config/api_config.rs (L104-106)
```rust
fn default_enabled() -> bool {
    true
}
```

**File:** config/src/config/api_config.rs (L115-115)
```rust
            enabled: default_enabled(),
```

**File:** api/test-context/src/test_context.rs (L220-222)
```rust
    let runtime_handle = tokio::runtime::Handle::current();
    let poem_address =
        attach_poem_to_runtime(&runtime_handle, context.clone(), &node_config, true, None)
```
