# Audit Report

## Title
Missing Duplicate Transaction Detection in ApplyExecutionOutput::run() Enables State Corruption via Double-Application

## Summary
The `ApplyExecutionOutput::run()` workflow in the execution layer does not validate whether `execution_output` contains duplicate transactions before applying state updates. This lack of defensive validation enables state corruption if duplicate transactions reach the execution layer through bugs in upstream deduplication or malicious state sync data.

## Finding Description

The `ApplyExecutionOutput::run()` function processes execution outputs without checking for duplicate transactions within the `to_commit` list: [1](#0-0) 

The workflow blindly passes all transactions to downstream processing:
1. **DoStateCheckpoint::run()** applies state updates for all transactions without duplicate detection [2](#0-1) 

2. **DoLedgerUpdate::run()** creates TransactionInfo entries for all transactions without duplicate detection [3](#0-2) 

While consensus layer performs deduplication using `TxnHashAndAuthenticatorDeduper`: [4](#0-3) 

This protection only applies to the normal consensus path. The execution layer lacks defensive validation, creating vulnerability through multiple attack vectors:

**Attack Vector 1: State Sync with Malicious/Buggy Data**

During state sync, nodes receive `TransactionOutputListWithProofV2` from peers through `enqueue_chunk_by_transaction_outputs()`: [5](#0-4) 

The verification only validates cryptographic proof correctness, not semantic properties like duplicate detection: [6](#0-5) 

If the source peer's ledger contains duplicate transactions due to bugs, the cryptographically valid proof would contain duplicates. The receiving node extracts transactions without checking for duplicates: [7](#0-6) 

These duplicates flow through `ChunkToApply` → `DoGetExecutionOutput::by_transaction_output()` → `Parser::parse()` without any duplicate detection: [8](#0-7) 

The `Parser::parse()` function creates `ExecutionOutput` from input transactions without duplicate checking: [9](#0-8) 

**Attack Vector 2: Consensus Deduplication Bypass**

If bugs exist in the consensus deduplication logic (race conditions, logic errors), duplicate transactions could reach execution despite the deduplication layer.

**Attack Vector 3: VM Execution Bug**

If the VM has a bug causing the same transaction to be executed multiple times, duplicates would flow through without detection.

**Impact Mechanism:**

When duplicates reach `ApplyExecutionOutput::run()`:
1. State updates are applied twice, corrupting account balances and smart contract state
2. Transaction infos are created for both copies at consecutive versions
3. The state root hash diverges from honest validators
4. Database commits duplicate transactions at different versions without uniqueness constraints

The `pre_commit_validation` only checks version sequencing, not duplicate transaction hashes: [10](#0-9) 

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention (per Aptos Bug Bounty criteria):

- **State Corruption**: Double-application of write sets corrupts ledger state, account balances, and smart contract storage
- **Consensus Divergence**: Nodes processing duplicates diverge from nodes with proper deduplication, breaking deterministic execution invariant
- **Recovery Required**: Manual intervention needed to identify and remediate corrupted state
- **Limited Scope**: Requires upstream bugs or malicious state sync data, not directly exploitable by transaction senders

This violates critical invariants:
- **Invariant #1 (Deterministic Execution)**: Nodes process different numbers of state updates for the same logical transaction set
- **Invariant #4 (State Consistency)**: State transitions are not atomic when duplicates cause double-application

## Likelihood Explanation

**Medium Likelihood**:

**Prerequisites:**
1. Bug in consensus deduplication logic (race condition, logic error), OR
2. Receipt of malicious/buggy state sync data from peer, OR  
3. VM bug causing duplicate transaction execution

**Feasibility:**
- State sync regularly processes external peer data
- Cryptographic proof verification cannot detect semantic duplicates
- No defensive validation exists in execution layer
- Historical precedent: many blockchain systems have had deduplication bugs

**Mitigation Factors:**
- Consensus deduplication is generally robust
- State sync peers are typically honest
- Multiple bugs required for end-to-end exploitation

**Defense-in-Depth Violation:**
The execution layer assumes perfect upstream deduplication without validation, violating security best practices.

## Recommendation

Add duplicate transaction detection in `ApplyExecutionOutput::run()` before processing:

```rust
impl ApplyExecutionOutput {
    pub fn run(
        execution_output: ExecutionOutput,
        base_view: LedgerSummary,
        reader: &(dyn DbReader + Sync),
    ) -> Result<PartialStateComputeResult> {
        // Validate no duplicate transactions in to_commit
        Self::validate_no_duplicates(&execution_output.to_commit)?;
        
        let state_checkpoint_output = DoStateCheckpoint::run(
            &execution_output,
            &base_view.state_summary,
            &ProvableStateSummary::new_persisted(reader)?,
            None,
        )?;
        let ledger_update_output = DoLedgerUpdate::run(
            &execution_output,
            &state_checkpoint_output,
            base_view.transaction_accumulator,
        )?;
        let output = PartialStateComputeResult::new(execution_output);
        output.set_state_checkpoint_output(state_checkpoint_output);
        output.set_ledger_update_output(ledger_update_output);

        Ok(output)
    }
    
    fn validate_no_duplicates(to_commit: &TransactionsToKeep) -> Result<()> {
        use std::collections::HashSet;
        use aptos_crypto::hash::CryptoHash;
        
        let mut seen_hashes = HashSet::with_capacity(to_commit.len());
        
        for (txn, _output, _aux_info) in to_commit.iter() {
            let txn_hash = txn.hash();
            ensure!(
                seen_hashes.insert(txn_hash),
                "Duplicate transaction detected: hash {:?}",
                txn_hash
            );
        }
        
        Ok(())
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_types::transaction::{Transaction, TransactionOutput, PersistedAuxiliaryInfo};
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    
    #[test]
    #[should_panic(expected = "Duplicate transaction detected")]
    fn test_duplicate_transaction_detection() {
        // Create a transaction
        let private_key = Ed25519PrivateKey::generate_for_testing();
        let public_key = private_key.public_key();
        let sender = AccountAddress::ZERO;
        let txn = Transaction::UserTransaction(get_test_signed_txn(
            sender,
            0,
            &private_key,
            public_key,
            None,
        ));
        
        // Create execution output with duplicate transaction
        let mut transactions = vec![txn.clone(), txn.clone()]; // DUPLICATE
        let outputs = vec![
            TransactionOutput::new_empty_success(),
            TransactionOutput::new_empty_success(),
        ];
        let aux_infos = vec![
            PersistedAuxiliaryInfo::V1 { transaction_index: 0 },
            PersistedAuxiliaryInfo::V1 { transaction_index: 1 },
        ];
        
        let to_commit = TransactionsToKeep::make(0, transactions, outputs, aux_infos);
        
        // This should fail with duplicate detection
        ApplyExecutionOutput::validate_no_duplicates(&to_commit).unwrap();
    }
}
```

**Notes:**

The vulnerability exists because:
1. `ApplyExecutionOutput::run()` lacks input validation for duplicates
2. State sync path processes externally-sourced data without semantic validation  
3. No defense-in-depth protection exists if upstream deduplication fails
4. Database storage is version-based, not hash-based, allowing duplicate transactions at different versions

This represents a violation of secure coding principles where critical system components must validate inputs rather than blindly trusting upstream processing.

### Citations

**File:** execution/executor/src/workflow/mod.rs (L22-43)
```rust
    pub fn run(
        execution_output: ExecutionOutput,
        base_view: LedgerSummary,
        reader: &(dyn DbReader + Sync),
    ) -> Result<PartialStateComputeResult> {
        let state_checkpoint_output = DoStateCheckpoint::run(
            &execution_output,
            &base_view.state_summary,
            &ProvableStateSummary::new_persisted(reader)?,
            None,
        )?;
        let ledger_update_output = DoLedgerUpdate::run(
            &execution_output,
            &state_checkpoint_output,
            base_view.transaction_accumulator,
        )?;
        let output = PartialStateComputeResult::new(execution_output);
        output.set_state_checkpoint_output(state_checkpoint_output);
        output.set_ledger_update_output(ledger_update_output);

        Ok(output)
    }
```

**File:** execution/executor/src/workflow/do_state_checkpoint.rs (L18-42)
```rust
    pub fn run(
        execution_output: &ExecutionOutput,
        parent_state_summary: &LedgerStateSummary,
        persisted_state_summary: &ProvableStateSummary,
        known_state_checkpoints: Option<Vec<Option<HashValue>>>,
    ) -> Result<StateCheckpointOutput> {
        let _timer = OTHER_TIMERS.timer_with(&["do_state_checkpoint"]);

        let state_summary = parent_state_summary.update(
            persisted_state_summary,
            &execution_output.hot_state_updates,
            execution_output.to_commit.state_update_refs(),
        )?;

        let state_checkpoint_hashes = Self::get_state_checkpoint_hashes(
            execution_output,
            known_state_checkpoints,
            &state_summary,
        )?;

        Ok(StateCheckpointOutput::new(
            state_summary,
            state_checkpoint_hashes,
        ))
    }
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L23-45)
```rust
    pub fn run(
        execution_output: &ExecutionOutput,
        state_checkpoint_output: &StateCheckpointOutput,
        parent_accumulator: Arc<InMemoryTransactionAccumulator>,
    ) -> Result<LedgerUpdateOutput> {
        let _timer = OTHER_TIMERS.timer_with(&["do_ledger_update"]);

        // Assemble `TransactionInfo`s
        let (transaction_infos, transaction_info_hashes) = Self::assemble_transaction_infos(
            &execution_output.to_commit,
            state_checkpoint_output.state_checkpoint_hashes.clone(),
        );

        // Calculate root hash
        let transaction_accumulator = Arc::new(parent_accumulator.append(&transaction_info_hashes));

        Ok(LedgerUpdateOutput::new(
            transaction_infos,
            transaction_info_hashes,
            transaction_accumulator,
            parent_accumulator,
        ))
    }
```

**File:** consensus/src/block_preparer.rs (L71-119)
```rust
    pub async fn prepare_block(
        &self,
        block: &Block,
        txns: Vec<SignedTransaction>,
        max_txns_from_block_to_execute: Option<u64>,
        block_gas_limit: Option<u64>,
    ) -> (Vec<SignedTransaction>, Option<u64>) {
        let start_time = Instant::now();

        let txn_filter_config = self.txn_filter_config.clone();
        let txn_deduper = self.txn_deduper.clone();
        let txn_shuffler = self.txn_shuffler.clone();

        let block_id = block.id();
        let block_author = block.author();
        let block_epoch = block.epoch();
        let block_timestamp_usecs = block.timestamp_usecs();

        // Transaction filtering, deduplication and shuffling are CPU intensive tasks, so we run them in a blocking task.
        let result = tokio::task::spawn_blocking(move || {
            let filtered_txns = filter_block_transactions(
                txn_filter_config,
                block_id,
                block_author,
                block_epoch,
                block_timestamp_usecs,
                txns,
            );
            let deduped_txns = txn_deduper.dedup(filtered_txns);
            let mut shuffled_txns = {
                let _timer = TXN_SHUFFLE_SECONDS.start_timer();

                txn_shuffler.shuffle(deduped_txns)
            };

            if let Some(max_txns_from_block_to_execute) = max_txns_from_block_to_execute {
                shuffled_txns.truncate(max_txns_from_block_to_execute as usize);
            }
            TXNS_IN_BLOCK
                .with_label_values(&["after_filter"])
                .observe(shuffled_txns.len() as f64);
            MAX_TXNS_FROM_BLOCK_TO_EXECUTE.observe(shuffled_txns.len() as f64);
            shuffled_txns
        })
        .await
        .expect("Failed to spawn blocking task for transaction generation");
        counters::BLOCK_PREPARER_LATENCY.observe_duration(start_time.elapsed());
        (result, block_gas_limit)
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L158-200)
```rust
    fn enqueue_chunk_by_transaction_outputs(
        &self,
        txn_output_list_with_proof: TransactionOutputListWithProofV2,
        verified_target_li: &LedgerInfoWithSignatures,
        epoch_change_li: Option<&LedgerInfoWithSignatures>,
    ) -> Result<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "enqueue_by_outputs"]);
        let _timer = APPLY_CHUNK.start_timer();

        // Verify input data.
        THREAD_MANAGER.get_exe_cpu_pool().install(|| {
            let _timer = CHUNK_OTHER_TIMERS.timer_with(&["apply_chunk__verify"]);
            txn_output_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_output_list_with_proof.get_first_output_version(),
            )
        })?;

        let (txn_output_list_with_proof, persisted_aux_info) =
            txn_output_list_with_proof.into_parts();
        // Compose enqueue_chunk parameters.
        let TransactionOutputListWithProof {
            transactions_and_outputs,
            first_transaction_output_version: v,
            proof: txn_infos_with_proof,
        } = txn_output_list_with_proof;
        let (transactions, transaction_outputs): (Vec<_>, Vec<_>) =
            transactions_and_outputs.into_iter().unzip();
        let chunk = ChunkToApply {
            transactions,
            transaction_outputs,
            persisted_aux_info,
            first_version: v.ok_or_else(|| anyhow!("first version is None"))?,
        };
        let chunk_verifier = Arc::new(StateSyncChunkVerifier {
            txn_infos_with_proof,
            verified_target_li: verified_target_li.clone(),
            epoch_change_li: epoch_change_li.cloned(),
        });

        // Call the shared implementation.
        self.with_inner(|inner| inner.enqueue_chunk(chunk, chunk_verifier, "apply"))
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L225-254)
```rust
    pub fn by_transaction_output(
        transactions: Vec<Transaction>,
        transaction_outputs: Vec<TransactionOutput>,
        auxiliary_infos: Vec<AuxiliaryInfo>,
        parent_state: &LedgerState,
        state_view: CachedStateView,
    ) -> Result<ExecutionOutput> {
        let out = Parser::parse(
            state_view.next_version(),
            transactions,
            transaction_outputs,
            auxiliary_infos,
            parent_state,
            state_view,
            true,  // prime state cache
            false, // is_block
        )?;

        let ret = out.clone();
        THREAD_MANAGER.get_background_pool().spawn(move || {
            let _timer = OTHER_TIMERS.timer_with(&["async_update_counters__by_output"]);
            metrics::update_counters_for_processed_chunk(
                &out.to_commit.transactions,
                &out.to_commit.transaction_outputs,
                "output",
            )
        });

        Ok(ret)
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L344-448)
```rust
impl Parser {
    fn parse(
        first_version: Version,
        mut transactions: Vec<Transaction>,
        mut transaction_outputs: Vec<TransactionOutput>,
        auxiliary_infos: Vec<AuxiliaryInfo>,
        parent_state: &LedgerState,
        base_state_view: CachedStateView,
        prime_state_cache: bool,
        is_block: bool,
    ) -> Result<ExecutionOutput> {
        let _timer = OTHER_TIMERS.timer_with(&["parse_raw_output"]);

        // Collect all statuses.
        let mut statuses_for_input_txns = {
            let _timer = OTHER_TIMERS.timer_with(&["parse_raw_output__all_statuses"]);
            transaction_outputs
                .iter()
                .map(|t| t.status())
                .cloned()
                .collect_vec()
        };

        let mut persisted_auxiliary_infos = auxiliary_infos
            .into_iter()
            .map(|info| info.into_persisted_info())
            .collect();

        // Isolate retries and discards.
        let (to_retry, to_discard) = Self::extract_retries_and_discards(
            &mut transactions,
            &mut transaction_outputs,
            &mut persisted_auxiliary_infos,
        );

        let mut block_end_info = None;
        if is_block {
            if let Some(Transaction::BlockEpilogue(payload)) = transactions.last() {
                block_end_info = payload.try_as_block_end_info().cloned();
                ensure!(statuses_for_input_txns.pop().is_some());
            }
        }

        // The rest is to be committed, attach block epilogue as needed and optionally get next EpochState.
        let to_commit = {
            let _timer = OTHER_TIMERS.timer_with(&["parse_raw_output__to_commit"]);
            let to_commit = TransactionsWithOutput::new(
                transactions,
                transaction_outputs,
                persisted_auxiliary_infos,
            );
            TransactionsToKeep::index(first_version, to_commit, is_block)
        };
        let next_epoch_state = {
            let _timer = OTHER_TIMERS.timer_with(&["parse_raw_output__next_epoch_state"]);
            to_commit
                .is_reconfig()
                .then(|| Self::ensure_next_epoch_state(&to_commit))
                .transpose()?
        };

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

        let (result_state, hot_state_updates) = parent_state.update_with_memorized_reads(
            base_state_view.persisted_hot_state(),
            base_state_view.persisted_state(),
            to_commit.state_update_refs(),
            base_state_view.memorized_reads(),
        );
        let state_reads = base_state_view.into_memorized_reads();

        let out = ExecutionOutput::new(
            is_block,
            first_version,
            statuses_for_input_txns,
            to_commit,
            to_discard,
            to_retry,
            result_state,
            state_reads,
            hot_state_updates,
            block_end_info,
            next_epoch_state,
            Planned::place_holder(),
        );
        let ret = out.clone();
        ret.subscribable_events
            .plan(THREAD_MANAGER.get_non_exe_cpu_pool(), move || {
                Self::get_subscribable_events(&out)
            });
        Ok(ret)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L245-261)
```rust
    fn pre_commit_validation(&self, chunk: &ChunkToCommit) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions_validation"]);

        ensure!(!chunk.is_empty(), "chunk is empty, nothing to save.");

        let next_version = self.state_store.current_state_locked().next_version();
        // Ensure the incoming committing requests are always consecutive and the version in
        // buffered state is consistent with that in db.
        ensure!(
            chunk.first_version == next_version,
            "The first version passed in ({}), and the next version expected by db ({}) are inconsistent.",
            chunk.first_version,
            next_version,
        );

        Ok(())
    }
```
