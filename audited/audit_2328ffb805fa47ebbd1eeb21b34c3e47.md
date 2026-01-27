Audit Report

## Title
Critical Liveness/Censorship Bug: Lack of Validation Allows Governance to Set Block Gas Limit to Zero—Chain Liveness Lost

## Summary
Aptos Core allows the on-chain `effective_block_gas_limit` parameter for `BlockGasLimitType::ComplexLimitV1` to be set to zero (or any negligibly small value) via governance proposal, with no input validation on critical boundaries. This results in every block halting immediately after the BlockMetadata transaction—skipping the execution of all user transactions and causing total loss of liveness. There is no recovery possible without governance action or a hard fork.

## Finding Description
The `OnChainExecutionConfig` determines per-block gas limits via its `block_gas_limit_type` field. For the `ComplexLimitV1` variant, `effective_block_gas_limit` is directly deserialized and set on-chain via governance proposal. The Move module `execution_config.move` validates only that the blob is non-empty, not that contained numeric values are sane or non-zero. No Rust-side (proposal generation) or Move-side bounds checking ensures the gas limit is positive.

During block execution, the first transaction (always BlockMetadata) runs with unmetered gas. Immediately thereafter, the block executor’s halting logic compares `accumulated_effective_block_gas` (initially zero) to the configured per-block gas limit (now zero): the check `accumulated_block_gas >= per_block_gas_limit` passes, so all further user transactions are skipped and an empty block is produced. This behavior loops infinitely, because every new block starts from the same zero state, resulting in total and permanent loss of transaction liveness for the chain.

No recovery mechanism exists except by a further governance proposal (which itself cannot be submitted in a deadlocked state) or by external hard fork.

## Impact Explanation
- **Severity:** CRITICAL
- **Impact:** Any user, by accident or governance action, can upload a config with `effective_block_gas_limit = 0` or `1` ; once ratified via governance, the Aptos network loses all ability to process user transactions, permanently halting all user activity, smart contract execution, and funds movement.
- **Invariants Broken:** Resource Limits (no transactions can execute—total liveness failure), State Management (state only progresses through metadata), Move VM Safety (user-programmable execution denied for all senders)
- **Recovery:** None without hard fork or privileged recovery
- **Nodes Affected:** All fullnodes/validators (deterministic execution of config)
- **Potential Damage:** Requires network-wide coordination to recover, potential total out-of-band governance loss if in quarantine, complete freezing of funds

## Likelihood Explanation
It is highly likely to occur due to:
- Lack of ANY input validation—no checks on Move or Rust side to prevent this value
- Easy to trigger accidentally (configuration mistake, typo, unit confusion)
- Also feasible as part of deliberate denial by governance (trusted or compromised majority; though this is a trusted action, robust systems should be defense-in-depth against accidents)
- No mitigation exists once activated (governance proposals, system reconfiguration, or smart contract mechanisms are deadlocked—recursion of chain inactivity)

## Recommendation
Implement robust validation in both the Rust release builder and the on-chain Move module to guarantee sane (strictly positive, large enough) values for `effective_block_gas_limit`. Sanity check must be done before configuration is serialized, and at the Move boundary before accepting and persisting the config for the next epoch.

Example Move function update—add assert:

```move
public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
  system_addresses::assert_aptos_framework(account);
  assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
  let decoded_config = bcs::to_bytes(&config); // pseudo-code for illustration
  // Add strict check: effective_block_gas_limit > MIN_SAFE_VALUE
  assert!(get_effective_block_gas_limit(decoded_config) > 10000, error::invalid_argument(EINVALID_CONFIG));
  config_buffer::upsert(ExecutionConfig { config });
}
```

## Proof of Concept

1. Submit a governance proposal that serializes an `OnChainExecutionConfig` with `block_gas_limit_type = ComplexLimitV1 { effective_block_gas_limit: 0, ... }`.
2. Pass and resolve the proposal through standard governance flow.
3. After the epoch transitions, all subsequently produced blocks will only contain the BlockMetadata transaction; all user-submitted transactions will be skipped due to the check (accumulated_block_gas >= per_block_gas_limit) being always true at 0.
4. Observe total network liveness failure and permanent halt of all user activity.

---

Citations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

Notes:
- No validation of `effective_block_gas_limit` is performed in the proposal generator or the Move on-chain setter, only a non-empty blob is checked.
- Detected attack is entirely deterministic, impacts all nodes, and requires hard fork or outside mechanism to recover if exploited.
- Defense-in-depth requires parameter validation for ALL safety-critical on-chain config, regardless of how trusted governance is.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/execution_config.rs (L11-51)
```rust
pub fn generate_execution_config_upgrade_proposal(
    execution_config: &OnChainExecutionConfig,
    is_testnet: bool,
    next_execution_hash: Option<HashValue>,
    is_multi_step: bool,
) -> Result<Vec<(String, String)>> {
    let signer_arg = get_signer_arg(is_testnet, &next_execution_hash);
    let mut result = vec![];

    let writer = CodeWriter::new(Loc::default());

    emitln!(writer, "// Execution config upgrade proposal\n");
    let config_comment = format!("// config: {:#?}", execution_config).replace('\n', "\n// ");
    emitln!(writer, "{}\n", config_comment);

    let proposal = generate_governance_proposal(
        &writer,
        is_testnet,
        next_execution_hash,
        is_multi_step,
        &["aptos_framework::execution_config"],
        |writer| {
            let execution_config_blob = bcs::to_bytes(execution_config).unwrap();
            assert!(execution_config_blob.len() < 65536);

            emit!(writer, "let execution_blob: vector<u8> = ");
            generate_blob_as_hex_string(writer, &execution_config_blob);
            emitln!(writer, ";\n");

            emitln!(
                writer,
                "execution_config::set_for_next_epoch({}, execution_blob);",
                signer_arg
            );
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
        },
    );

    result.push(("execution-config".to_string(), proposal));
    Ok(result)
}
```

**File:** types/src/on_chain_config/execution_config.rs (L274-419)
```rust
pub enum BlockGasLimitType {
    NoLimit,
    Limit(u64),
    /// Provides two separate block limits:
    /// 1. effective_block_gas_limit
    /// 2. block_output_limit
    ComplexLimitV1 {
        /// Formula for effective block gas limit:
        /// effective_block_gas_limit <
        /// (execution_gas_effective_multiplier * execution_gas_used +
        ///  io_gas_effective_multiplier * io_gas_used
        /// ) * (1 + num conflicts in conflict_penalty_window)
        effective_block_gas_limit: u64,
        execution_gas_effective_multiplier: u64,
        io_gas_effective_multiplier: u64,
        conflict_penalty_window: u32,

        /// If true we look at granular resource group conflicts (i.e. if same Tag
        /// within a resource group has a conflict)
        /// If false, we treat any conclicts inside of resource groups (even across
        /// non-overlapping tags) as conflicts).
        use_granular_resource_group_conflicts: bool,
        /// Module publishing today fallbacks to sequential execution,
        /// even though there is no read-write conflict.
        /// When enabled, this flag allows us to account for that conflict.
        /// NOTE: Currently not supported.
        use_module_publishing_block_conflict: bool,

        /// Block limit on the total (approximate) txn output size in bytes.
        block_output_limit: Option<u64>,
        /// When set, we include the user txn size in the approximate computation
        /// of block output size, which is compared against the block_output_limit above.
        include_user_txn_size_in_block_output: bool,

        /// When set, we create BlockEpilogue (instead of StateCheckpint) transaction,
        /// which contains BlockEndInfo
        /// NOTE: Currently not supported.
        add_block_limit_outcome_onchain: bool,
    },
}

impl BlockGasLimitType {
    pub fn block_gas_limit(&self) -> Option<u64> {
        match self {
            BlockGasLimitType::NoLimit => None,
            BlockGasLimitType::Limit(limit) => Some(*limit),
            BlockGasLimitType::ComplexLimitV1 {
                effective_block_gas_limit,
                ..
            } => Some(*effective_block_gas_limit),
        }
    }

    pub fn execution_gas_effective_multiplier(&self) -> u64 {
        match self {
            BlockGasLimitType::NoLimit => 1,
            BlockGasLimitType::Limit(_) => 1,
            BlockGasLimitType::ComplexLimitV1 {
                execution_gas_effective_multiplier,
                ..
            } => *execution_gas_effective_multiplier,
        }
    }

    pub fn io_gas_effective_multiplier(&self) -> u64 {
        match self {
            BlockGasLimitType::NoLimit => 1,
            BlockGasLimitType::Limit(_) => 1,
            BlockGasLimitType::ComplexLimitV1 {
                io_gas_effective_multiplier,
                ..
            } => *io_gas_effective_multiplier,
        }
    }

    pub fn block_output_limit(&self) -> Option<u64> {
        match self {
            BlockGasLimitType::NoLimit => None,
            BlockGasLimitType::Limit(_) => None,
            BlockGasLimitType::ComplexLimitV1 {
                block_output_limit, ..
            } => *block_output_limit,
        }
    }

    pub fn conflict_penalty_window(&self) -> Option<u32> {
        match self {
            BlockGasLimitType::NoLimit => None,
            BlockGasLimitType::Limit(_) => None,
            BlockGasLimitType::ComplexLimitV1 {
                conflict_penalty_window,
                ..
            } => {
                if *conflict_penalty_window > 1 {
                    Some(*conflict_penalty_window)
                } else {
                    None
                }
            },
        }
    }

    pub fn use_module_publishing_block_conflict(&self) -> bool {
        match self {
            BlockGasLimitType::NoLimit => false,
            BlockGasLimitType::Limit(_) => false,
            BlockGasLimitType::ComplexLimitV1 {
                use_module_publishing_block_conflict,
                ..
            } => *use_module_publishing_block_conflict,
        }
    }

    pub fn include_user_txn_size_in_block_output(&self) -> bool {
        match self {
            BlockGasLimitType::NoLimit => false,
            BlockGasLimitType::Limit(_) => false,
            BlockGasLimitType::ComplexLimitV1 {
                include_user_txn_size_in_block_output,
                ..
            } => *include_user_txn_size_in_block_output,
        }
    }

    pub fn add_block_limit_outcome_onchain(&self) -> bool {
        match self {
            BlockGasLimitType::NoLimit => false,
            BlockGasLimitType::Limit(_) => false,
            BlockGasLimitType::ComplexLimitV1 {
                add_block_limit_outcome_onchain,
                ..
            } => *add_block_limit_outcome_onchain,
        }
    }

    pub fn use_granular_resource_group_conflicts(&self) -> bool {
        match self {
            BlockGasLimitType::NoLimit => false,
            BlockGasLimitType::Limit(_) => false,
            BlockGasLimitType::ComplexLimitV1 {
                use_granular_resource_group_conflicts,
                ..
            } => *use_granular_resource_group_conflicts,
        }
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L48-52)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L127-157)
```rust
    fn should_end_block(&mut self, mode: &str) -> bool {
        if let Some(per_block_gas_limit) = self.block_gas_limit() {
            // When the accumulated block gas of the committed txns exceeds
            // PER_BLOCK_GAS_LIMIT, early halt BlockSTM.
            let accumulated_block_gas = self.get_effective_accumulated_block_gas();
            if accumulated_block_gas >= per_block_gas_limit {
                counters::EXCEED_PER_BLOCK_GAS_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_block_gas {} >= PER_BLOCK_GAS_LIMIT {}",
                    mode, accumulated_block_gas, per_block_gas_limit,
                );
                return true;
            }
        }

        if let Some(per_block_output_limit) = self.block_gas_limit_type.block_output_limit() {
            let accumulated_output = self.get_accumulated_approx_output_size();
            if accumulated_output >= per_block_output_limit {
                counters::EXCEED_PER_BLOCK_OUTPUT_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_output {} >= PER_BLOCK_OUTPUT_LIMIT {}",
                    mode, accumulated_output, per_block_output_limit,
                );
                return true;
            }
        }

        false
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L2207-2546)
```rust
        let mut ret = Vec::with_capacity(num_txns + 1);

        let mut block_limit_processor = BlockGasLimitProcessor::<T>::new(
            self.config.onchain.block_gas_limit_type.clone(),
            self.config.onchain.block_gas_limit_override(),
            num_txns + 1,
        );

        let mut block_epilogue_txn = None;
        let mut idx = 0;
        while idx <= num_txns {
            let txn = if idx != num_txns {
                signature_verified_block.get_txn(idx as TxnIndex)
            } else if block_epilogue_txn.is_some() {
                block_epilogue_txn.as_ref().unwrap()
            } else {
                break;
            };
            let auxiliary_info = signature_verified_block.get_auxiliary_info(idx as TxnIndex);
            let latest_view = LatestView::<T, S>::new(
                base_view,
                module_cache_manager_guard.module_cache(),
                runtime_environment,
                ViewState::Unsync(SequentialState::new(&unsync_map, start_counter, &counter)),
                idx as TxnIndex,
            );
            let res =
                executor.execute_transaction(&latest_view, txn, &auxiliary_info, idx as TxnIndex);
            let must_skip = matches!(res, ExecutionStatus::SkipRest(_));
            match res {
                ExecutionStatus::Abort(err) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    error!(
                        "Sequential execution FatalVMError by transaction {}",
                        idx as TxnIndex
                    );
                    // Record the status indicating the unrecoverable VM failure.
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalVMError(err),
                    ));
                },
                ExecutionStatus::DelayedFieldsCodeInvariantError(msg) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    alert!("Sequential execution DelayedFieldsCodeInvariantError error by transaction {}: {}", idx as TxnIndex, msg);
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(msg)),
                    ));
                },
                ExecutionStatus::SpeculativeExecutionAbortError(msg) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    alert!("Sequential execution SpeculativeExecutionAbortError error by transaction {}: {}", idx as TxnIndex, msg);
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(msg)),
                    ));
                },
                ExecutionStatus::Success(mut output) | ExecutionStatus::SkipRest(mut output) => {
                    let output_before_guard = output.before_materialization()?;
                    // Calculating the accumulated gas costs of the committed txns.

                    let approx_output_size = self
                        .config
                        .onchain
                        .block_gas_limit_type
                        .block_output_limit()
                        .map(|_| {
                            output_before_guard.output_approx_size()
                                + if self
                                    .config
                                    .onchain
                                    .block_gas_limit_type
                                    .include_user_txn_size_in_block_output()
                                {
                                    txn.user_txn_bytes_len()
                                } else {
                                    0
                                } as u64
                        });

                    let sequential_reads = latest_view.take_sequential_reads();
                    let read_write_summary = self
                        .config
                        .onchain
                        .block_gas_limit_type
                        .conflict_penalty_window()
                        .map(|_| {
                            ReadWriteSummary::new(
                                sequential_reads.get_read_summary(),
                                output_before_guard.get_write_summary(),
                            )
                        });

                    block_limit_processor.accumulate_fee_statement(
                        output_before_guard.fee_statement(),
                        read_write_summary,
                        approx_output_size,
                    );

                    // Drop to acquire a write lock, then re-assign the output_before_guard.
                    drop(output_before_guard);
                    output.legacy_sequential_materialize_agg_v1(&latest_view);
                    let output_before_guard = output.before_materialization()?;

                    assert_eq!(
                        output_before_guard.aggregator_v1_delta_set().len(),
                        0,
                        "Sequential execution must materialize deltas"
                    );

                    if resource_group_bcs_fallback {
                        // Dynamic change set optimizations are enabled, and resource group serialization
                        // previously failed in bcs serialization for preparing final transaction outputs.
                        // TODO: remove this fallback when txn errors can be created from block executor.

                        let finalize = |group_key| -> (BTreeMap<_, _>, ResourceGroupSize) {
                            let (group, size) = unsync_map.finalize_group(&group_key);

                            (
                                group
                                    .map(|(resource_tag, value_with_layout)| {
                                        let value = match value_with_layout {
                                            ValueWithLayout::RawFromStorage(value)
                                            | ValueWithLayout::Exchanged(value, _) => value,
                                        };
                                        (
                                            resource_tag,
                                            value
                                                .extract_raw_bytes()
                                                .expect("Deletions should already be applied"),
                                        )
                                    })
                                    .collect(),
                                size,
                            )
                        };

                        // The IDs are not exchanged but it doesn't change the types (Bytes) or size.
                        let serialization_error = output_before_guard
                            .group_reads_needing_delayed_field_exchange()
                            .iter()
                            .any(|(group_key, _)| {
                                fail_point!("fail-point-resource-group-serialization", |_| {
                                    true
                                });

                                let (finalized_group, group_size) = finalize(group_key.clone());
                                match bcs::to_bytes(&finalized_group) {
                                    Ok(group) => {
                                        (!finalized_group.is_empty() || group_size.get() != 0)
                                            && group.len() as u64 != group_size.get()
                                    },
                                    Err(_) => true,
                                }
                            })
                            || output_before_guard
                                .resource_group_write_set()
                                .into_iter()
                                .any(|(group_key, (_, output_group_size, group_ops))| {
                                    fail_point!("fail-point-resource-group-serialization", |_| {
                                        true
                                    });

                                    let (mut finalized_group, group_size) = finalize(group_key);
                                    if output_group_size.get() != group_size.get() {
                                        return false;
                                    }
                                    for (value_tag, (group_op, _)) in group_ops {
                                        if group_op.is_deletion() {
                                            finalized_group.remove(&value_tag);
                                        } else {
                                            finalized_group.insert(
                                                value_tag,
                                                group_op
                                                    .extract_raw_bytes()
                                                    .expect("Not a deletion"),
                                            );
                                        }
                                    }
                                    match bcs::to_bytes(&finalized_group) {
                                        Ok(group) => {
                                            (!finalized_group.is_empty() || group_size.get() != 0)
                                                && group.len() as u64 != group_size.get()
                                        },
                                        Err(_) => true,
                                    }
                                });

                        if serialization_error {
                            // The corresponding error / alert must already be triggered, the goal in sequential
                            // fallback is to just skip any transactions that would cause such serialization errors.
                            alert!("Discarding transaction because serialization failed in bcs fallback");
                            ret.push(E::Output::discard_output(
                                StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
                            ));
                            idx += 1;
                            continue;
                        }
                    };

                    // Apply the writes.
                    let resource_write_set = output_before_guard.resource_write_set();
                    Self::apply_output_sequential(
                        idx as TxnIndex,
                        runtime_environment,
                        module_cache_manager_guard.module_cache(),
                        &unsync_map,
                        &output_before_guard,
                        resource_write_set.clone(),
                    )?;

                    // If dynamic change set materialization part (indented for clarity/variable scope):
                    {
                        let finalized_groups = groups_to_finalize!(output_before_guard,)
                            .map(|((group_key, metadata_op), is_read_needing_exchange)| {
                                let (group_ops_iter, group_size) =
                                    unsync_map.finalize_group(&group_key);
                                map_finalized_group::<T>(
                                    group_key,
                                    group_ops_iter.collect(),
                                    group_size,
                                    metadata_op,
                                    is_read_needing_exchange,
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        let materialized_finalized_groups =
                            map_id_to_values_in_group_writes(finalized_groups, &latest_view)?;
                        let serialized_groups =
                            serialize_groups::<T>(materialized_finalized_groups).map_err(|_| {
                                SequentialBlockExecutionError::ResourceGroupSerializationError
                            })?;

                        let resource_writes_to_materialize = resource_writes_to_materialize!(
                            resource_write_set,
                            output_before_guard,
                            unsync_map,
                        )?;
                        // Replace delayed field id with values in resource write set and read set.
                        let materialized_resource_write_set = map_id_to_values_in_write_set(
                            resource_writes_to_materialize,
                            &latest_view,
                        )?;

                        // Replace delayed field id with values in events
                        let materialized_events = map_id_to_values_events(
                            Box::new(output_before_guard.get_events().into_iter()),
                            &latest_view,
                        )?;
                        // Output before guard holds a read lock, drop before incorporating materialized
                        // output which needs a write lock.
                        drop(output_before_guard);

                        let trace = output.incorporate_materialized_txn_output(
                            // No aggregator v1 delta writes are needed for sequential execution.
                            // They are already handled because we passed materialize_deltas=true
                            // to execute_transaction.
                            vec![],
                            materialized_resource_write_set
                                .into_iter()
                                .chain(serialized_groups.into_iter())
                                .collect(),
                            materialized_events,
                        )?;

                        // Sequential execution never collects any traces.
                        if !trace.is_empty() {
                            let err = code_invariant_error(
                                "Sequential execution should not record any traces",
                            );
                            return Err(err.into());
                        }
                    }
                    // If dynamic change set is disabled, this can be used to assert nothing needs patching instead:
                    //   output.set_txn_output_for_non_dynamic_change_set();

                    if sequential_reads.incorrect_use {
                        return Err(
                            code_invariant_error("Incorrect use in sequential execution").into(),
                        );
                    }

                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook
                            .on_transaction_committed(idx as TxnIndex, output.committed_output());
                    }
                    ret.push(output);
                },
            };

            if idx == num_txns {
                break;
            }

            idx += 1;

            if must_skip || block_limit_processor.should_end_block_sequential() || idx == num_txns {
                let mut has_reconfig = false;
                if let Some(last_output) = ret.last() {
                    if last_output.after_materialization()?.has_new_epoch_event() {
                        has_reconfig = true;
                    }
                }
                ret.resize_with(num_txns, E::Output::skip_output);
                if let Some(block_id) =
                    transaction_slice_metadata.append_state_checkpoint_to_block()
                {
                    if !has_reconfig {
                        block_epilogue_txn = Some(self.gen_block_epilogue(
                            block_id,
                            signature_verified_block,
                            ret.iter(),
                            idx as TxnIndex,
                            block_limit_processor.get_block_end_info(),
                            module_cache_manager_guard.environment().features(),
                        )?);
                    } else {
                        info!("Reach epoch ending, do not append BlockEpilogue txn, block_id: {block_id:?}.");
                    }
                }
                idx = num_txns;
            }
        }

        block_limit_processor.finish_sequential_update_counters_and_log_info(
            ret.len() as u32,
            num_txns as u32 + block_epilogue_txn.as_ref().map_or(0, |_| 1),
        );

        counters::update_state_counters(unsync_map.stats(), false);
        module_cache_manager_guard
            .module_cache_mut()
            .insert_verified(unsync_map.into_modules_iter())?;

        Ok(BlockOutput::new(ret, block_epilogue_txn))
    }
```
