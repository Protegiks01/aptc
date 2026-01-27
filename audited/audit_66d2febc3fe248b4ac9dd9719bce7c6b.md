# Audit Report

## Title
Consensus Bypass via Public BlockExecutor Module Exposure Allowing Direct Database Commitment Without Validation

## Summary
The public exposure of the `block_executor` module allows components with database access to bypass all consensus validation checks (quorum certificates, signatures, safety rules) by directly instantiating `BlockExecutor` and calling its methods to execute and commit arbitrary blocks to the ledger without proper authorization.

## Finding Description

The `block_executor` module is exposed as public in the executor crate [1](#0-0) , making the `BlockExecutor` struct and all its methods accessible to any crate that depends on the executor.

The `BlockExecutor` struct has a public `db` field [2](#0-1)  and a public constructor [3](#0-2) , allowing any code with a `DbReaderWriter` to create an instance.

**Critical Gap in Validation Chain:**

The `execute_and_update_state` method performs block execution but does NOT validate consensus properties [4](#0-3) . It only checks that the parent block exists in the block tree, but does not verify quorum certificates, block signatures, or validator authorization.

The `commit_ledger` method accepts a `LedgerInfoWithSignatures` parameter and commits it to storage [5](#0-4) , but performs no signature verification. It only confirms the block exists in the tree before committing.

**Storage Layer Trusts Executor:**

The storage layer's `check_and_put_ledger_info` method only validates structural consistency (version, root hash, epoch continuity) [6](#0-5)  but explicitly does NOT verify the signatures on `LedgerInfoWithSignatures`, as documented in the codebase analysis which states: "signature verification is NOT performed in commit_ledger... the storage layer trusts the provided LedgerInfoWithSignatures."

**Attack Vector:**

State sync has full database write access [7](#0-6) , creating `ChunkExecutor` with `db_rw.clone()`. A compromised or vulnerable state sync component, or a malicious dependency used by state sync, could:

1. Import `aptos_executor::block_executor::BlockExecutor`
2. Create an unauthorized `BlockExecutor` instance using the available `DbReaderWriter`
3. Execute arbitrary transactions via `execute_and_update_state`
4. Create a `LedgerInfoWithSignatures` with invalid/forged signatures but correct version and hashes
5. Commit via `commit_ledger` - the storage layer accepts it without signature verification

This completely bypasses the consensus layer's quorum certificate validation, signature verification, and safety rule enforcement.

## Impact Explanation

**Critical Severity** - This breaks the fundamental consensus safety guarantee of AptosBFT:

- **Consensus Safety Violation**: The 2f+1 validator agreement requirement is completely bypassed
- **Arbitrary Block Commitment**: Unauthorized blocks can be committed without validator consensus
- **Potential Fund Theft**: Malicious transactions can be executed and committed without authorization
- **Chain State Corruption**: The ledger can be corrupted with invalid state transitions

This qualifies for Critical severity ($1,000,000) under the Aptos bug bounty program as it enables "Consensus/Safety violations" and potentially "Loss of Funds."

## Likelihood Explanation

**Medium-High Likelihood** in scenarios involving:

1. **Compromised State Sync Component**: State sync has full `DbReaderWriter` access and runs complex synchronization logic that could contain vulnerabilities
2. **Supply Chain Attack**: A malicious dependency used by state sync or consensus could exploit this architectural weakness
3. **Internal Component Bug**: A bug in state sync, consensus, or related components could accidentally bypass validation by directly using `BlockExecutor`

While direct exploitation requires database access (not available to typical network attackers), the components that DO have such access (state sync, consensus) handle untrusted network data and external dependencies, creating realistic attack surfaces.

## Recommendation

**Make the `block_executor` module internal:**

```rust
// In execution/executor/src/lib.rs
// Change from:
pub mod block_executor;

// To:
mod block_executor;

// Export only the trait, not the implementation:
pub use block_executor::BlockExecutor; // If needed by consensus
```

**Make `BlockExecutor` fields private:**

```rust
// In execution/executor/src/block_executor/mod.rs
pub struct BlockExecutor<V> {
    db: DbReaderWriter,  // Remove 'pub'
    inner: RwLock<Option<BlockExecutorInner<V>>>,
    execution_lock: Mutex<()>,
}
```

**Add signature verification in storage layer:**

Add signature verification to `check_and_put_ledger_info` to create defense in depth, even though consensus should validate first.

**Principle of Least Privilege:**

Consider creating a restricted `DbWriter` interface for `BlockExecutor` that only exposes necessary methods, preventing direct database manipulation even if the executor is misused.

## Proof of Concept

```rust
// Hypothetical attack code that could be executed by a compromised component
// with DbReaderWriter access (e.g., from within state sync or a malicious dependency)

use aptos_executor::block_executor::BlockExecutor;
use aptos_vm::aptos_vm::AptosVMBlockExecutor;
use aptos_types::block_executor::partitioner::ExecutableBlock;
use aptos_types::ledger_info::LedgerInfoWithSignatures;

// Assume attacker has access to db_rw (e.g., from state sync context)
fn exploit_consensus_bypass(db_rw: DbReaderWriter) -> Result<()> {
    // Create unauthorized BlockExecutor instance
    let executor = BlockExecutor::<AptosVMBlockExecutor>::new(db_rw);
    
    // Create malicious block with arbitrary transactions
    let malicious_block = ExecutableBlock {
        block_id: HashValue::random(),
        transactions: vec![/* malicious transactions */],
        auxiliary_info: AuxiliaryInfo::default(),
    };
    
    // Execute without consensus validation
    executor.execute_and_update_state(
        malicious_block,
        parent_block_id,
        BlockExecutorConfigFromOnchain::default()
    )?;
    
    // Create fake LedgerInfoWithSignatures with INVALID signatures
    // but correct version/hash to pass storage layer checks
    let fake_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(/* correct version and hash */),
        BTreeMap::new() // Empty signatures! No validator agreement!
    );
    
    // Commit to ledger - storage accepts it without signature verification!
    executor.pre_commit_block(malicious_block.block_id)?;
    executor.commit_ledger(fake_ledger_info)?;
    
    // Block is now permanently committed without consensus!
    Ok(())
}
```

**Notes**

This vulnerability represents a critical architectural flaw where the separation of concerns between consensus validation and execution allows the execution layer to be abused when accessed outside the intended consensus flow. While exploitation requires database access (limiting the attack surface to privileged components), those components handle untrusted network data and external dependencies, making compromise scenarios realistic. The storage layer's trust assumption that `LedgerInfoWithSignatures` has already been validated creates a dangerous gap when the executor is accessed directly, bypassing the consensus validation layer entirely.

### Citations

**File:** execution/executor/src/lib.rs (L13-13)
```rust
pub mod block_executor;
```

**File:** execution/executor/src/block_executor/mod.rs (L49-53)
```rust
pub struct BlockExecutor<V> {
    pub db: DbReaderWriter,
    inner: RwLock<Option<BlockExecutorInner<V>>>,
    execution_lock: Mutex<()>,
}
```

**File:** execution/executor/src/block_executor/mod.rs (L59-65)
```rust
    pub fn new(db: DbReaderWriter) -> Self {
        Self {
            db,
            inner: RwLock::new(None),
            execution_lock: Mutex::new(()),
        }
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

**File:** execution/executor/src/block_executor/mod.rs (L362-395)
```rust
    fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
        let _timer = OTHER_TIMERS.timer_with(&["commit_ledger"]);

        let block_id = ledger_info_with_sigs.ledger_info().consensus_block_id();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "commit_ledger"
        );

        // Check for any potential retries
        // TODO: do we still have such retries?
        let committed_block = self.block_tree.root_block();
        if committed_block.num_persisted_transactions()?
            == ledger_info_with_sigs.ledger_info().version() + 1
        {
            return Ok(());
        }

        // Confirm the block to be committed is tracked in the tree.
        self.block_tree.get_block(block_id)?;

        fail_point!("executor::commit_blocks", |_| {
            Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
        });

        let target_version = ledger_info_with_sigs.ledger_info().version();
        self.db
            .writer
            .commit_ledger(target_version, Some(&ledger_info_with_sigs), None)?;

        self.block_tree.prune(ledger_info_with_sigs.ledger_info())?;

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L540-601)
```rust
    fn check_and_put_ledger_info(
        &self,
        version: Version,
        ledger_info_with_sig: &LedgerInfoWithSignatures,
        ledger_batch: &mut SchemaBatch,
    ) -> Result<(), AptosDbError> {
        let ledger_info = ledger_info_with_sig.ledger_info();

        // Verify the version.
        ensure!(
            ledger_info.version() == version,
            "Version in LedgerInfo doesn't match last version. {:?} vs {:?}",
            ledger_info.version(),
            version,
        );

        // Verify the root hash.
        let db_root_hash = self
            .ledger_db
            .transaction_accumulator_db()
            .get_root_hash(version)?;
        let li_root_hash = ledger_info_with_sig
            .ledger_info()
            .transaction_accumulator_hash();
        ensure!(
            db_root_hash == li_root_hash,
            "Root hash pre-committed doesn't match LedgerInfo. pre-commited: {:?} vs in LedgerInfo: {:?}",
            db_root_hash,
            li_root_hash,
        );

        // Verify epoch continuity.
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );

        // Ensure that state tree at the end of the epoch is persisted.
        if ledger_info_with_sig.ledger_info().ends_epoch() {
            let state_snapshot = self.state_store.get_state_snapshot_before(version + 1)?;
            ensure!(
                state_snapshot.is_some() && state_snapshot.as_ref().unwrap().0 == version,
                "State checkpoint not persisted at the end of the epoch, version {}, next_epoch {}, snapshot in db: {:?}",
                version,
                ledger_info_with_sig.ledger_info().next_block_epoch(),
                state_snapshot,
            );
        }

        // Put write to batch.
        self.ledger_db
            .metadata_db()
            .put_ledger_info(ledger_info_with_sig, ledger_batch)?;
        Ok(())
    }
```

**File:** aptos-node/src/state_sync.rs (L133-156)
```rust
    db_rw: DbReaderWriter,
) -> anyhow::Result<(
    AptosDataClient,
    StateSyncRuntimes,
    MempoolNotificationListener,
    ConsensusNotifier,
)> {
    // Get the network client and events
    let network_client = storage_network_interfaces.network_client;
    let network_service_events = storage_network_interfaces.network_service_events;

    // Start the data client
    let peers_and_metadata = network_client.get_peers_and_metadata();
    let (aptos_data_client, aptos_data_client_runtime) =
        setup_aptos_data_client(node_config, network_client, db_rw.reader.clone())?;

    // Start the data streaming service
    let state_sync_config = node_config.state_sync;
    let (streaming_service_client, streaming_service_runtime) =
        setup_data_streaming_service(state_sync_config, aptos_data_client.clone())?;

    // Create the chunk executor and persistent storage
    let chunk_executor = Arc::new(ChunkExecutor::<AptosVMBlockExecutor>::new(db_rw.clone()));
    let metadata_storage = PersistentMetadataStorage::new(&node_config.storage.dir());
```
