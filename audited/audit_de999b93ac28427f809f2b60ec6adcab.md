# Audit Report

## Title
State View Race Condition Causes Non-Deterministic Transaction Conversion in Indexer-GRPC Parallel Tasks

## Summary
The `convert_to_api_txns()` function in the indexer-grpc fullnode creates state view converters independently in each parallel task, allowing different tasks to operate on different checkpoint versions. This causes the same historical transactions to be converted into different API representations depending on when each task acquires its state view, breaking data consistency guarantees for downstream indexers.

## Finding Description

In `process_next_batch()`, the indexer spawns multiple parallel tasks to convert transactions to API format. Each task independently calls `convert_to_api_txns()`, which creates a new state view via `context.latest_state_view()`. [1](#0-0) 

The critical issue occurs in `convert_to_api_txns()`: [2](#0-1) 

The `latest_state_view()` method queries the current state checkpoint version: [3](#0-2) 

Which ultimately calls: [4](#0-3) 

And reads the latest checkpoint: [5](#0-4) 

The mutex is released immediately after reading the version. Between different parallel tasks calling `latest_state_view()`, the checkpoint can advance as new blocks commit. This results in different tasks creating `DbStateView` instances with different versions.

The `DbStateView` uses this version for all state queries: [6](#0-5) 

The `MoveConverter` created via `as_converter()` wraps this state view: [7](#0-6) 

This converter is used to resolve modules, resource groups, and table information, all of which depend on the state view's version: [8](#0-7) 

**Attack Scenario:**
1. Indexer fetches transactions at versions 1000-1100
2. Splits into 4 parallel tasks
3. Task 1 calls `latest_state_view()` → checkpoint version 2000
4. New block commits, checkpoint advances to 2001
5. Task 2 calls `latest_state_view()` → checkpoint version 2001
6. If a module was upgraded between versions 2000-2001, tasks produce different ABIs
7. Same transaction converts to different JSON representations
8. Downstream indexers receive inconsistent data for identical transactions

## Impact Explanation

**Medium Severity** - This creates state inconsistencies in the indexing infrastructure. While it doesn't directly affect consensus or cause funds loss, it breaks critical data consistency guarantees:

- Downstream indexers may receive different representations of the same transaction when queried at different times
- If modules are upgraded during parallel task execution, conversion may fail in some tasks but succeed in others, causing partial batch failures
- Indexer databases may become corrupted with inconsistent transaction data
- Requires manual intervention to identify and remediate inconsistent data

This qualifies as Medium severity under the "State inconsistencies requiring intervention" category, as external systems relying on deterministic indexer data will need to resync or repair their databases.

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally during normal operation:

- Fullnodes continuously process new blocks and create checkpoints
- Parallel tasks are spawned simultaneously but execute at different times
- The time window between task spawns (microseconds to milliseconds) is sufficient for checkpoint advancement
- No special conditions or attacker intervention required
- More likely with larger batch sizes or slower hardware where task execution is staggered

## Recommendation

Capture the state view version once before spawning parallel tasks and ensure all tasks use the same checkpoint version:

```rust
fn convert_to_api_txns(
    context: Arc<Context>,
    raw_txns: Vec<TransactionOnChainData>,
    state_view_version: Version,  // Pass version explicitly
) -> Vec<(APITransaction, TransactionSizeInfo)> {
    if raw_txns.is_empty() {
        return vec![];
    }
    
    // Use fixed version instead of latest
    let state_view = context.state_view_at_version(state_view_version).unwrap();
    let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());
    
    // ... rest of conversion logic
}
```

In `process_next_batch()`, acquire the state view version once:

```rust
// Before spawning tasks, capture the version
let state_view_version = context.latest_state_view()
    .unwrap()
    .next_version() - 1;  // Use the checkpoint version

for batch in task_batches {
    let context = self.context.clone();
    let filter = filter.clone();
    let task = tokio::task::spawn_blocking(move || {
        let raw_txns = batch;
        let api_txns = Self::convert_to_api_txns(context, raw_txns, state_view_version);
        // ...
    });
    tasks.push(task);
}
```

## Proof of Concept

```rust
// Reproduction steps (pseudo-code):

#[test]
fn test_inconsistent_converter_state() {
    // 1. Setup fullnode with indexer-grpc
    let mut coordinator = IndexerStreamCoordinator::new(/*...*/);
    
    // 2. Fetch a batch of historical transactions
    let txns = fetch_transactions(1000, 1100);
    
    // 3. Record current checkpoint version
    let version_before = context.latest_state_view().unwrap().next_version() - 1;
    
    // 4. Split into parallel tasks
    let task_batches = split_into_batches(txns);
    
    // 5. Simulate checkpoint advancement mid-execution
    // (This happens naturally as new blocks commit)
    
    // 6. Spawn tasks and collect state view versions used
    let mut versions = vec![];
    for batch in task_batches {
        let version = context.latest_state_view().unwrap().next_version() - 1;
        versions.push(version);
        // Convert batch...
    }
    
    // 7. Verify inconsistency
    assert!(versions.iter().any(|v| *v != versions[0]), 
            "Different tasks used different state view versions");
    
    // 8. Demonstrate different conversion results
    // If a module was upgraded between versions, the API output will differ
}
```

The vulnerability is confirmed by examining the code paths where `latest_state_checkpoint_version()` acquires and releases the mutex immediately, allowing the checkpoint to advance between parallel task executions.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L167-200)
```rust
        for batch in task_batches {
            let context = self.context.clone();
            let filter = filter.clone();
            let task = tokio::task::spawn_blocking(move || {
                let raw_txns = batch;
                let api_txns = Self::convert_to_api_txns(context, raw_txns);
                let pb_txns = Self::convert_to_pb_txns(api_txns);
                // Apply filter if present.
                let pb_txns = if let Some(ref filter) = filter {
                    pb_txns
                        .into_iter()
                        .filter(|txn| filter.matches(txn))
                        .collect::<Vec<_>>()
                } else {
                    pb_txns
                };
                let mut responses = vec![];
                // Wrap in stream response object and send to channel
                for chunk in pb_txns.chunks(output_batch_size as usize) {
                    for chunk in chunk_transactions(chunk.to_vec(), MESSAGE_SIZE_LIMIT) {
                        let item = TransactionsFromNodeResponse {
                            response: Some(transactions_from_node_response::Response::Data(
                                TransactionsOutput {
                                    transactions: chunk,
                                },
                            )),
                            chain_id: ledger_chain_id as u32,
                        };
                        responses.push(item);
                    }
                }
                responses
            });
            tasks.push(task);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L372-373)
```rust
        let state_view = context.latest_state_view().unwrap();
        let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());
```

**File:** api/src/context.rs (L156-158)
```rust
    pub fn latest_state_view(&self) -> Result<DbStateView> {
        Ok(self.db.latest_state_checkpoint_view()?)
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L27-46)
```rust
    fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
        if let Some(version) = self.version {
            if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
                // TODO(aldenhu): sample-verify proof inside DB
                // DB doesn't support returning proofs for buffered state, so only optionally
                // verify proof.
                // TODO: support returning state proof for buffered state.
                if let Ok((value, proof)) =
                    self.db.get_state_value_with_proof_by_version(key, version)
                {
                    proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
                }
            }
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L82-90)
```rust
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L812-819)
```rust
    fn get_latest_state_checkpoint_version(&self) -> Result<Option<Version>> {
        gauged_api("get_latest_state_checkpoint_version", || {
            Ok(self
                .state_store
                .current_state_locked()
                .last_checkpoint()
                .version())
        })
```

**File:** api/types/src/convert.rs (L97-110)
```rust
    pub fn is_resource_group(&self, tag: &StructTag) -> bool {
        if let Ok(Some(module)) = self.inner.view_module(&tag.module_id()) {
            if let Some(md) = get_metadata(&module.metadata) {
                if let Some(attrs) = md.struct_attributes.get(tag.name.as_ident_str().as_str()) {
                    return attrs
                        .iter()
                        .find(|attr| attr.is_resource_group())
                        .map(|_| true)
                        .unwrap_or(false);
                }
            }
        }
        false
    }
```

**File:** api/types/src/convert.rs (L1187-1195)
```rust
impl<R: StateView> AsConverter<R> for R {
    fn as_converter(
        &self,
        db: Arc<dyn DbReader>,
        indexer_reader: Option<Arc<dyn IndexerReader>>,
    ) -> MoveConverter<'_, R> {
        MoveConverter::new(self, db, indexer_reader)
    }
}
```
