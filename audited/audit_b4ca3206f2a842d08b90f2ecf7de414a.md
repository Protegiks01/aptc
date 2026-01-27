# Audit Report

## Title
Panic-Induced Validator Node Crash During State Cache Priming in Block Execution

## Summary
The `prime_cache_for_keys()` function in `cached_state_view.rs` uses `rayon::scope` to spawn parallel tasks that call `get_state_value().expect("Must succeed.")`. When database read operations fail (due to pruning, IO errors, or corruption), the `.expect()` causes a panic in the worker thread. Due to rayon's panic propagation behavior, this panic is re-thrown in the calling thread, crashing the entire validator node during block execution.

## Finding Description

The vulnerability exists in the state cache priming logic that runs during block execution. [1](#0-0) 

This function is called during the critical block execution path: [2](#0-1) 

The execution flows through the consensus layer's `ExecutionProxy`, which uses the `BlockExecutor`: [3](#0-2) 

The `get_state_value()` method can fail for several legitimate reasons:

1. **Database Pruning**: The requested version has been pruned [4](#0-3) 

2. **Database Read Failures**: RocksDB iterator operations can fail [5](#0-4) 

3. **Pruning Check Failures**: Version validation before reads [6](#0-5) 

The underlying database read in `get_unmemorized()` can return errors: [7](#0-6) 

When any spawned rayon task panics, rayon::scope propagates the panic to the calling thread, which is executing the block. Since there is no panic handling in the block executor: [8](#0-7) 

The validator node crashes entirely, breaking consensus participation.

## Impact Explanation

**Critical Severity** - This meets the "Total loss of liveness/network availability" criterion from the Aptos bug bounty program. When a validator node crashes:

1. **Immediate consensus impact**: The validator cannot participate in voting, reducing the effective validator set size
2. **Network availability**: If multiple validators experience database issues simultaneously (e.g., during pruning windows), network liveness degrades
3. **No recovery mechanism**: The node must be manually restarted; there's no automatic recovery
4. **Consensus safety risk**: If enough validators crash, the network may fail to reach quorum

This violates the critical invariant: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" - while not Byzantine behavior, crashed nodes effectively reduce the active validator set.

## Likelihood Explanation

**High Likelihood** - This can be triggered without any attacker action:

1. **Normal pruning operations**: State pruner runs periodically and the cache priming may attempt to read pruned data if there's a timing mismatch
2. **Disk/IO failures**: Temporary disk issues, filesystem errors, or high I/O load can cause database reads to fail
3. **Database corruption**: RocksDB corruption from crashes or hardware issues will trigger read failures
4. **Race conditions**: Concurrent pruning and block execution can create windows where data becomes unavailable
5. **No error handling**: The `.expect()` guarantees a panic on any error, making this deterministic once an error occurs

The vulnerability is not theoretical - it's present in production code on the critical block execution path.

## Recommendation

Replace the `.expect("Must succeed.")` with proper error handling that propagates errors instead of panicking:

**Fixed Code:**
```rust
fn prime_cache_for_keys<'a, T: IntoIterator<Item = &'a StateKey> + Send>(
    &self,
    keys: T,
) -> Result<()> {
    let errors = Arc::new(Mutex::new(Vec::new()));
    rayon::scope(|s| {
        keys.into_iter().for_each(|key| {
            let errors = Arc::clone(&errors);
            s.spawn(move |_| {
                if let Err(e) = self.get_state_value(key) {
                    errors.lock().push((key.clone(), e));
                }
            })
        });
    });
    
    let collected_errors = errors.lock();
    if !collected_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Failed to prime cache for {} keys: {:?}",
            collected_errors.len(),
            collected_errors
        ));
    }
    Ok(())
}
```

This allows the error to propagate through the `?` operator chain back to consensus, where it can be handled gracefully (e.g., by retrying or failing the block execution non-fatally).

## Proof of Concept

```rust
#[cfg(test)]
mod test_panic_propagation {
    use super::*;
    use std::sync::Arc;
    
    // Mock DbReader that fails on reads
    struct FailingDbReader;
    impl DbReader for FailingDbReader {
        // Implement required methods, make get_state_value_with_version_by_version fail
        fn get_state_value_with_version_by_version(
            &self,
            _state_key: &StateKey,
            _version: Version,
        ) -> Result<Option<(Version, StateValue)>> {
            Err(anyhow::anyhow!("Simulated database pruning error"))
        }
        // ... other required trait methods
    }
    
    #[test]
    #[should_panic(expected = "Must succeed")]
    fn test_prime_cache_panics_on_db_error() {
        // Create a CachedStateView with a failing DB reader
        let failing_reader = Arc::new(FailingDbReader);
        let state = State::new_empty();
        
        let cached_view = CachedStateView::new_impl(
            StateViewId::Miscellaneous,
            failing_reader,
            Arc::new(EmptyHotState),
            state.clone(),
            state,
        );
        
        // Create some keys to prime
        let keys = vec![StateKey::raw(b"test_key")];
        
        // This should panic when get_state_value fails
        // In production, this panic crashes the validator node
        let _ = cached_view.prime_cache_for_keys(keys.iter());
    }
}
```

**Steps to reproduce:**
1. Set up a validator node with state pruning enabled
2. Execute blocks that trigger cache priming
3. Ensure pruner runs concurrently, creating a window where `prime_cache` attempts to read pruned data
4. Observe validator node crash with panic message from `.expect("Must succeed.")`

Alternatively, simulate disk failure or database corruption during block execution to trigger the same crash path.

### Citations

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L210-222)
```rust
    fn prime_cache_for_keys<'a, T: IntoIterator<Item = &'a StateKey> + Send>(
        &self,
        keys: T,
    ) -> Result<()> {
        rayon::scope(|s| {
            keys.into_iter().for_each(|key| {
                s.spawn(move |_| {
                    self.get_state_value(key).expect("Must succeed.");
                })
            });
        });
        Ok(())
    }
```

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L233-253)
```rust
    fn get_unmemorized(&self, state_key: &StateKey) -> Result<StateSlot> {
        COUNTER.inc_with(&["sv_unmemorized"]);

        let ret = if let Some(slot) = self.speculative.get_state_slot(state_key) {
            COUNTER.inc_with(&["sv_hit_speculative"]);
            slot
        } else if let Some(slot) = self.hot.get_state_slot(state_key) {
            COUNTER.inc_with(&["sv_hit_hot"]);
            slot
        } else if let Some(base_version) = self.base_version() {
            COUNTER.inc_with(&["sv_cold"]);
            StateSlot::from_db_get(
                self.cold
                    .get_state_value_with_version_by_version(state_key, base_version)?,
            )
        } else {
            StateSlot::ColdVacant
        };

        Ok(ret)
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L405-418)
```rust
        base_state_view.prime_cache(
            to_commit.state_update_refs(),
            if prime_state_cache {
                PrimingPolicy::All
            } else {
                // Most of the transaction reads should already be in the cache, but some module
                // reads in the transactions might be done via the global module cache instead of
                // cached state view, so they are not present in the cache.
                // Therfore, we must prime the cache for the keys that we are going to promote into
                // hot state, regardless of `prime_state_cache`, because the write sets have only
                // the keys, not the values.
                PrimingPolicy::MakeHotOnly
            },
        )?;
```

**File:** consensus/src/state_computer.rs (L54-67)
```rust
pub struct ExecutionProxy {
    executor: Arc<dyn BlockExecutorTrait>,
    txn_notifier: Arc<dyn TxnNotifier>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    write_mutex: AsyncMutex<LogicalTime>,
    txn_filter_config: Arc<BlockTransactionFilterConfig>,
    state: RwLock<Option<MutableState>>,
    enable_pre_commit: bool,
    secret_share_config: Option<SecretShareConfig>,
}

impl ExecutionProxy {
    pub fn new(
        executor: Arc<dyn BlockExecutorTrait>,
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L305-315)
```rust
    pub(super) fn error_if_state_kv_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.state_store.state_kv_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L644-655)
```rust
    fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        gauged_api("get_state_value_with_version_by_version", || {
            self.error_if_state_kv_pruned("StateValue", version)?;

            self.state_store
                .get_state_value_with_version_by_version(state_key, version)
        })
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L191-258)
```rust
    fn execute_and_update_state(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<()> {
        let _timer = BLOCK_EXECUTION_WORKFLOW_WHOLE.start_timer();
        let ExecutableBlock {
            block_id,
            transactions,
            auxiliary_info,
        } = block;
        let mut block_vec = self
            .block_tree
            .get_blocks_opt(&[block_id, parent_block_id])?;
        let parent_block = block_vec
            .pop()
            .expect("Must exist.")
            .ok_or(ExecutorError::BlockNotFound(parent_block_id))?;
        let parent_output = &parent_block.output;
        info!(
            block_id = block_id,
            first_version = parent_output.execution_output.next_version(),
            "execute_block"
        );
        let committed_block_id = self.committed_block_id();
        let execution_output =
            if parent_block_id != committed_block_id && parent_output.has_reconfiguration() {
                // ignore reconfiguration suffix, even if the block is non-empty
                info!(
                    LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
                    "reconfig_descendant_block_received"
                );
                parent_output.execution_output.reconfig_suffix()
            } else {
                let state_view = {
                    let _timer = OTHER_TIMERS.timer_with(&["get_state_view"]);
                    CachedStateView::new(
                        StateViewId::BlockExecution { block_id },
                        Arc::clone(&self.db.reader),
                        parent_output.result_state().latest().clone(),
                    )?
                };

                let _timer = GET_BLOCK_EXECUTION_OUTPUT_BY_EXECUTING.start_timer();
                fail_point!("executor::block_executor_execute_block", |_| {
                    Err(ExecutorError::from(anyhow::anyhow!(
                        "Injected error in block_executor_execute_block"
                    )))
                });

                DoGetExecutionOutput::by_transaction_execution(
                    &self.block_executor,
                    transactions,
                    auxiliary_info,
                    parent_output.result_state(),
                    state_view,
                    onchain_config.clone(),
                    TransactionSliceMetadata::block(parent_block_id, block_id),
                )?
            };

        let output = PartialStateComputeResult::new(execution_output);
        let _ = self
            .block_tree
            .add_block(parent_block_id, block_id, output)?;
        Ok(())
    }
```
