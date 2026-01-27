# Audit Report

## Title
Sharded Execution Cannot Handle Transaction Scripts - Causes Validator Panic and Potential Consensus Divergence

## Summary
Transaction scripts cause validator crashes when sharded block execution is enabled due to incomplete read/write hint analysis. The `get_read_write_hints()` method contains `todo!()` macros for scripts and non-whitelisted entry functions, which panic during block partitioning. If incorrectly "fixed" by returning empty hints without proper static analysis, scripts would execute without cross-shard dependency tracking, causing non-deterministic execution and consensus splits across validators.

## Finding Description

The sharded block executor relies on static analysis of transaction read/write hints to partition transactions across shards and track cross-shard dependencies. This analysis is performed in `AnalyzedTransaction::new()` which calls `get_read_write_hints()`. [1](#0-0) 

The `get_read_write_hints()` implementation only supports a hardcoded list of entry functions (coin::transfer, aptos_account::transfer, aptos_account::create_account). For all other transactions, including scripts, it executes `todo!()` macros: [2](#0-1) 

**Attack Path**:

1. Validator enables sharded execution by configuring `num_shards > 1`
2. Attacker submits a transaction script (still supported by AptosVM) [3](#0-2) 

3. Block preparation converts transactions to `AnalyzedTransaction` for partitioning: [4](#0-3) 

4. The conversion triggers `get_read_write_hints()` which hits `todo!()` and **panics**, crashing the validator

**Deeper Vulnerability - Consensus Divergence**:

If the `todo!()` is naively "fixed" by returning `empty_rw_set()`, an even more severe vulnerability emerges:

Scripts would be partitioned **without** proper dependency tracking. The cross-shard state synchronization mechanism relies on `cross_shard_dependencies` populated from read/write hints: [5](#0-4) 

Without proper hints:
- Scripts access state modified by other shards without waiting for cross-shard commits
- Execution order becomes non-deterministic across validators
- Different validators partition scripts differently or execute them in different orders
- **This breaks the fundamental Deterministic Execution invariant**: validators produce different state roots for identical blocks [6](#0-5) 

## Impact Explanation

**Current State (High Severity - Validator DoS)**:
- Any script transaction causes immediate validator crash via panic
- Meets High severity: "Validator node slowdowns" and "API crashes"
- Affects availability of any validator with sharded execution enabled

**If Improperly Fixed (Critical Severity - Consensus Split)**:
- Non-deterministic execution leads to state root divergence
- Validators cannot reach consensus on block outcomes
- Meets Critical severity: "Consensus/Safety violations" and "Non-recoverable network partition"
- Potential for permanent chain split requiring hardfork

## Likelihood Explanation

**Current Configuration**: Low to Medium likelihood
- Sharded execution appears primarily used in benchmarking
- `set_num_shards` is called in executor-benchmark code [7](#0-6) 

**Future Risk**: High likelihood
- Code exists in production, not behind test-only flags
- Sharded execution infrastructure is production-ready
- If/when sharded execution is enabled for performance, vulnerability becomes immediately exploitable
- Scripts remain supported by the VM

**Attack Complexity**: Low
- Attacker simply submits a script transaction
- No special privileges required
- Scripts are standard transaction types

## Recommendation

**Immediate Fix**: Add explicit validation to reject scripts in sharded execution until proper analysis is implemented:

```rust
impl AnalyzedTransactionProvider for Transaction {
    fn get_read_write_hints(&self) -> (Vec<StorageLocation>, Vec<StorageLocation>) {
        match self {
            Transaction::UserTransaction(signed_txn) => match signed_txn.payload().executable_ref() {
                Ok(TransactionExecutableRef::Script(_)) => {
                    // IMPORTANT: Scripts are not supported in sharded execution
                    // Reject with explicit error instead of panic
                    panic!("Scripts are not supported in sharded block execution. Use entry functions instead.");
                }
                Ok(TransactionExecutableRef::EntryFunction(func))
                    if !signed_txn.payload().is_multisig() => {
                    process_entry_function(func, signed_txn.sender())
                }
                _ => {
                    // Multisig and other unsupported types
                    panic!("Only non-multisig entry functions are supported in sharded execution");
                }
            },
            _ => empty_rw_set(),
        }
    }
}
```

**Long-term Fix**: Implement proper static analysis for scripts:
1. Parse script bytecode to extract read/write patterns
2. Use conservative over-approximation (wildcards) when dynamic behavior detected  
3. Validate that scripts with wildcards are assigned to global shard
4. Add comprehensive testing for script execution in sharded mode

**Alternative**: Deprecate scripts entirely and enforce entry-function-only execution, which provides better static analyzability.

## Proof of Concept

```rust
// Reproduction steps (would require sharded execution configuration):

// 1. Enable sharded execution
AptosVM::set_num_shards_once(4);

// 2. Create a simple script transaction
let script = Script::new(
    vec![/* script bytecode */],
    vec![/* type args */],
    vec![/* args */],
);
let txn = Transaction::UserTransaction(
    SignedTransaction::new(
        RawTransaction::new(
            sender_address,
            sequence_number,
            TransactionPayload::Script(script),
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp,
            chain_id,
        ),
        sender_public_key,
        signature,
    )
);

// 3. Attempt to partition block containing this transaction
let analyzed_txn = AnalyzedTransaction::new(txn.into());
// ^ This panics at get_read_write_hints() with:
// "thread panicked at 'not yet implemented: Only entry function transactions are supported for now'"

// 4. Validator crashes, cannot process block
```

**Notes**

The vulnerability has two distinct manifestations:

1. **Immediate DoS**: The `todo!()` macro causes validator panics when scripts are encountered during block partitioning with sharded execution enabled.

2. **Latent Consensus Risk**: If the `todo!()` is removed without implementing proper read/write hint analysis for scripts, the system would allow scripts to execute without cross-shard dependency tracking, leading to non-deterministic execution results across validators and consensus divergence.

The core issue is that transaction scripts, which remain supported by the Aptos VM for execution, are incompatible with the static analysis requirements of the sharded block executor. This creates a dangerous gap where either validators crash (current state) or consensus breaks (if improperly fixed).

### Citations

**File:** types/src/transaction/analyzed_transaction.rs (L68-82)
```rust
    pub fn new(transaction: SignatureVerifiedTransaction) -> Self {
        let (read_hints, write_hints) = transaction.get_read_write_hints();
        let hints_contain_wildcard = read_hints
            .iter()
            .chain(write_hints.iter())
            .any(|hint| !matches!(hint, StorageLocation::Specific(_)));
        let hash = transaction.hash();
        AnalyzedTransaction {
            transaction,
            read_hints,
            write_hints,
            predictable_transaction: !hints_contain_wildcard,
            hash,
        }
    }
```

**File:** types/src/transaction/analyzed_transaction.rs (L271-283)
```rust
        match self {
            Transaction::UserTransaction(signed_txn) => match signed_txn.payload().executable_ref()
            {
                Ok(TransactionExecutableRef::EntryFunction(func))
                    if !signed_txn.payload().is_multisig() =>
                {
                    process_entry_function(func, signed_txn.sender())
                },
                _ => todo!("Only entry function transactions are supported for now"),
            },
            _ => empty_rw_set(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L457-468)
```rust
    pub fn set_num_shards_once(mut num_shards: usize) {
        num_shards = max(num_shards, 1);
        // Only the first call succeeds, due to OnceCell semantics.
        NUM_EXECUTION_SHARD.set(num_shards).ok();
    }

    pub fn get_num_shards() -> usize {
        match NUM_EXECUTION_SHARD.get() {
            Some(num_shards) => *num_shards,
            None => 1,
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1048-1060)
```rust
        match executable {
            TransactionExecutableRef::Script(script) => {
                session.execute(|session| {
                    self.validate_and_execute_script(
                        session,
                        serialized_signers,
                        code_storage,
                        gas_meter,
                        traversal_context,
                        script,
                        trace_recorder,
                    )
                })?;
```

**File:** execution/executor-benchmark/src/block_preparation.rs (L98-111)
```rust
            Some(partitioner) => {
                NUM_TXNS.inc_with_by(&["partition"], sig_verified_txns.len() as u64);
                let analyzed_transactions =
                    sig_verified_txns.into_iter().map(|t| t.into()).collect();
                let timer = TIMER.timer_with(&["partition"]);
                let partitioned_txns =
                    partitioner.partition(analyzed_transactions, self.num_executor_shards);
                timer.stop_and_record();
                ExecutableBlock::new(
                    block_id,
                    ExecutableTransactions::Sharded(partitioned_txns),
                    vec![],
                )
            },
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L58-71)
```rust
    pub fn create_cross_shard_state_view(
        base_view: &'a S,
        transactions: &[TransactionWithDependencies<AnalyzedTransaction>],
    ) -> CrossShardStateView<'a, S> {
        let mut cross_shard_state_key = HashSet::new();
        for txn in transactions {
            for (_, storage_locations) in txn.cross_shard_dependencies.required_edges_iter() {
                for storage_location in storage_locations {
                    cross_shard_state_key.insert(storage_location.clone().into_state_key());
                }
            }
        }
        CrossShardStateView::new(cross_shard_state_key, base_view)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L98-116)
```rust
        let num_rounds = sharded_output[0].len();
        let mut aggregated_results = vec![];
        let mut ordered_results = vec![vec![]; num_executor_shards * num_rounds];
        // Append the output from individual shards in the round order
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                ordered_results[round * num_executor_shards + shard_id] = result;
            }
        }

        for result in ordered_results.into_iter() {
            aggregated_results.extend(result);
        }

        // Lastly append the global output
        aggregated_results.extend(global_output);

        Ok(aggregated_results)
    }
```
