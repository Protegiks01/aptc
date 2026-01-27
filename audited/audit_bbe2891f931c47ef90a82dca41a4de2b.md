# Audit Report

## Title
Resource Leak and Improper Shutdown in AptosHandle - Orphaned Threads on Premature Drop

## Summary
The `AptosHandle` struct lacks a proper `Drop` implementation, leading to orphaned native OS threads and incomplete task cleanup if the handle is dropped prematurely. Multiple background threads spawned outside tokio runtimes will continue executing indefinitely, potentially causing resource leaks and state inconsistencies.

## Finding Description

The `AptosHandle` struct holds multiple tokio `Runtime` instances and other resources but has no `Drop` implementation. [1](#0-0) 

When `AptosHandle` is dropped (e.g., due to panic in the main thread or abnormal termination), several critical issues occur:

**1. Orphaned Native OS Threads:**

Multiple background threads are spawned using `thread::spawn` without capturing join handles:

- **Inspection Service Thread**: Spawned with no cleanup mechanism [2](#0-1) 

- **Logger Service Thread**: Spawned to process log messages indefinitely [3](#0-2) 

- **HotState Committer Thread**: Spawns without returning join handle [4](#0-3) 

**2. Global Rayon Thread Pool:**

A global rayon thread pool is created during node startup but never shut down: [5](#0-4) 

This is called during node initialization: [6](#0-5) 

**3. Incomplete Task Cancellation:**

When tokio `Runtime` instances are dropped, all spawned async tasks are cancelled without graceful completion. Critical operations may be interrupted mid-execution:

- State sync database writes
- Consensus voting operations  
- Network connection cleanup
- Block execution and commitment

The node handle is created and held indefinitely: [7](#0-6) 

## Impact Explanation

**Medium Severity** - This issue meets the "State inconsistencies requiring intervention" category, but with important caveats:

- **Resource Leaks**: Orphaned threads continue consuming CPU, memory, and file handles
- **Database Inconsistency**: The HotState committer thread may be in the middle of writing to the database when dropped, potentially leaving state corrupted
- **Restart Prevention**: Orphaned threads may hold database locks or file handles, preventing clean node restart
- **Port Conflicts**: The inspection service HTTP server may continue running on its port, blocking restarts

However, the impact is limited because:
- This requires abnormal termination (panic, crash, or premature drop)
- Normal node shutdown via SIGTERM would not trigger this
- No direct loss of funds or consensus violation occurs

## Likelihood Explanation

**Low to Medium Likelihood**:

- **Trigger Conditions**: Requires panic in main thread, out-of-memory condition, or other abnormal termination
- **Not Attacker-Controlled**: An external unprivileged attacker cannot directly trigger `AptosHandle` drop
- **Operational Risk**: More likely in testing/development scenarios with forced terminations or during crash scenarios

The likelihood is reduced because normal graceful shutdown wouldn't trigger this, but increased because:
- Rust panics can occur from various runtime errors
- System resource exhaustion could cause drops
- Integration testing may expose this issue

## Recommendation

Implement a proper `Drop` implementation for `AptosHandle` with graceful shutdown:

```rust
impl Drop for AptosHandle {
    fn drop(&mut self) {
        // Signal all runtimes to shut down gracefully
        // Note: Actual implementation would need shutdown channels
        
        // Explicitly shut down runtimes in reverse order
        // (opposite of initialization)
        
        // Wait for spawned threads to complete
        // This would require storing JoinHandles
    }
}
```

**Specific fixes needed:**

1. **Inspection Service**: Return and store `JoinHandle`, implement shutdown signal
2. **Logger Service**: Add graceful shutdown mechanism via channel
3. **HotState Committer**: Store `JoinHandle` in parent struct and join on drop
4. **Global Rayon Pool**: Add shutdown mechanism or use scoped pool

Alternatively, implement a graceful shutdown function that must be called before drop.

## Proof of Concept

```rust
#[test]
fn test_orphaned_threads_on_premature_drop() {
    use std::thread;
    use std::time::Duration;
    
    // Create minimal node config
    let config = NodeConfig::default();
    
    // Get initial thread count
    let initial_threads = thread_count();
    
    {
        // Create and immediately drop AptosHandle
        let _handle = setup_environment_and_start_node(
            config, None, None, None, None
        ).unwrap();
        
        // Allow threads to spawn
        thread::sleep(Duration::from_secs(1));
    } // AptosHandle dropped here
    
    // Force cleanup attempt
    thread::sleep(Duration::from_secs(2));
    
    let final_threads = thread_count();
    
    // Assert orphaned threads exist
    assert!(final_threads > initial_threads, 
        "Orphaned threads detected: {} initial vs {} final", 
        initial_threads, final_threads);
}

fn thread_count() -> usize {
    // Platform-specific implementation to count threads
    // On Linux: parse /proc/self/status or /proc/self/task/
    // On macOS: use task_threads() system call
    unimplemented!()
}
```

**Notes:**

While this is a legitimate resource management issue that violates proper cleanup invariants, it does **not** meet the strict criteria for an exploitable security vulnerability in the bug bounty context because:

1. An unprivileged external attacker cannot trigger `AptosHandle` drop
2. It requires abnormal termination scenarios (panic, crash, kill signal)
3. It's primarily an operational reliability concern rather than a direct security exploit

The issue is valid from a software engineering perspective but falls short of being a directly exploitable vulnerability for bounty purposes. It should be addressed to improve node reliability and proper resource cleanup, but does not constitute a critical security flaw exploitable by external attackers.

### Citations

**File:** aptos-node/src/lib.rs (L196-215)
```rust
/// Runtime handle to ensure that all inner runtimes stay in scope
pub struct AptosHandle {
    _admin_service: AdminService,
    _api_runtime: Option<Runtime>,
    _backup_runtime: Option<Runtime>,
    _consensus_observer_runtime: Option<Runtime>,
    _consensus_publisher_runtime: Option<Runtime>,
    _consensus_runtime: Option<Runtime>,
    _dkg_runtime: Option<Runtime>,
    _indexer_grpc_runtime: Option<Runtime>,
    _indexer_runtime: Option<Runtime>,
    _indexer_table_info_runtime: Option<Runtime>,
    _jwk_consensus_runtime: Option<Runtime>,
    _mempool_runtime: Runtime,
    _network_runtimes: Vec<Runtime>,
    _peer_monitoring_service_runtime: Runtime,
    _state_sync_runtimes: StateSyncRuntimes,
    _telemetry_runtime: Option<Runtime>,
    _indexer_db_runtime: Option<Runtime>,
}
```

**File:** aptos-node/src/lib.rs (L236-237)
```rust
    // Create global rayon thread pool
    utils::create_global_rayon_pool(create_global_rayon_pool);
```

**File:** aptos-node/src/lib.rs (L276-288)
```rust
    let _node_handle = setup_environment_and_start_node(
        config,
        remote_log_receiver,
        Some(logger_filter_update),
        api_port_tx,
        indexer_grpc_port_tx,
    )?;
    let term = Arc::new(AtomicBool::new(false));
    while !term.load(Ordering::Acquire) {
        thread::park();
    }

    Ok(())
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L75-100)
```rust
    thread::spawn(move || {
        // Create the service function that handles the endpoint requests
        let make_service = make_service_fn(move |_conn| {
            let node_config = node_config.clone();
            let aptos_data_client = aptos_data_client.clone();
            let peers_and_metadata = peers_and_metadata.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |request| {
                    serve_requests(
                        request,
                        node_config.clone(),
                        aptos_data_client.clone(),
                        peers_and_metadata.clone(),
                    )
                }))
            }
        });

        // Start and block on the server
        runtime
            .block_on(async {
                let server = Server::bind(&address).serve(make_service);
                server.await
            })
            .unwrap();
    });
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L461-462)
```rust
            thread::spawn(move || service.run());
            logger
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L173-178)
```rust
    fn spawn(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>) -> SyncSender<State> {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_HOT_STATE_COMMIT_BACKLOG);
        std::thread::spawn(move || Self::new(base, committed, rx).run());

        tx
    }
```

**File:** aptos-node/src/utils.rs (L32-39)
```rust
pub fn create_global_rayon_pool(create_global_rayon_pool: bool) {
    if create_global_rayon_pool {
        rayon::ThreadPoolBuilder::new()
            .thread_name(|index| format!("rayon-global-{}", index))
            .build_global()
            .expect("Failed to build rayon global thread pool.");
    }
}
```
