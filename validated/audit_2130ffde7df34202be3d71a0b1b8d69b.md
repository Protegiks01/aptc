> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L150-186)
```rust
    pub fn set_raw_base_values(
        &self,
        group_key: K,
        base_values: Vec<(T, V)>,
    ) -> anyhow::Result<()> {
        let mut group_sizes = self.group_sizes.entry(group_key.clone()).or_default();

        // Currently the size & value are written while holding the sizes lock.
        if let Vacant(entry) = group_sizes.size_entries.entry(ShiftedTxnIndex::zero_idx()) {
            // Perform group size computation if base not already provided.
            let group_size = group_size_as_sum::<T>(
                base_values
                    .iter()
                    .flat_map(|(tag, value)| value.bytes().map(|b| (tag.clone(), b.len()))),
            )
            .map_err(|e| {
                anyhow!(
                    "Tag serialization error in resource group at {:?}: {:?}",
                    group_key.clone(),
                    e
                )
            })?;

            entry.insert(SizeEntry::new(SizeAndDependencies::from_size(group_size)));

            let mut superset_tags = self.group_tags.entry(group_key.clone()).or_default();
            for (tag, value) in base_values.into_iter() {
                superset_tags.insert(tag.clone());
                self.values.set_base_value(
                    (group_key.clone(), tag),
                    ValueWithLayout::RawFromStorage(Arc::new(value)),
                );
            }
        }

        Ok(())
    }
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L436-458)
```rust
    pub fn fetch_tagged_data_and_record_dependency(
        &self,
        group_key: &K,
        tag: &T,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
    ) -> Result<(Version, ValueWithLayout<V>), MVGroupError> {
        let key_ref = GroupKeyRef { group_key, tag };

        // We are accessing group_sizes and values non-atomically, hence the order matters.
        // It is important that initialization check happens before fetch data below. O.w.
        // we could incorrectly get a TagNotFound error (do not find data, but then find
        // size initialized in between the calls). In fact, we always write size after data,
        // and sometimes (e.g. during initialization) even hold the sizes lock during writes.
        // It is fine to observe initialized = false, but find data, in convert_tagged_data.
        // TODO(BlockSTMv2): complete overhaul of initialization logic.
        let initialized = self.group_sizes.contains_key(group_key);

        let data_value =
            self.values
                .fetch_data_and_record_dependency(&key_ref, txn_idx, incarnation);
        self.convert_tagged_data(data_value, initialized)
    }
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L610-674)
```rust
    // Unified inner implementation interface for BlockSTMv1 and V2. A pair is returned,
    // where only the first element matters for V1, and the second element for V2.
    // For V1, the bool indicates whether a new tag was written as opposed to previous
    // incarnation (which necessitates certain validations).
    // For V2, the BTreeSet contains read dependencies (version of the txn that performed
    // the read) invalidated by writing the values.
    fn data_write_impl<const V2: bool>(
        &self,
        group_key: &K,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        values: impl IntoIterator<Item = (T, (V, Option<Arc<MoveTypeLayout>>))>,
        mut prev_tags: HashSet<&T>,
    ) -> Result<(bool, RegisteredReadDependencies), PanicError> {
        let mut ret_v1 = false;
        // Creating a RegisteredReadDependencies wrapper in order to do proper extending.
        let mut ret_v2 = RegisteredReadDependencies::new();
        let mut tags_to_write = vec![];

        {
            let superset_tags = self.group_tags.get(group_key).ok_or_else(|| {
                // Due to read-before-write.
                code_invariant_error("Group (tags) must be initialized to write to")
            })?;

            for (tag, (value, layout)) in values.into_iter() {
                if !superset_tags.contains(&tag) {
                    tags_to_write.push(tag.clone());
                }

                ret_v1 |= !prev_tags.remove(&tag);

                if V2 {
                    ret_v2.extend(self.values.write_v2::<false>(
                        (group_key.clone(), tag),
                        txn_idx,
                        incarnation,
                        Arc::new(value),
                        layout,
                    )?);
                } else {
                    self.values.write(
                        (group_key.clone(), tag),
                        txn_idx,
                        incarnation,
                        Arc::new(value),
                        layout,
                    );
                }
            }
        }

        if !tags_to_write.is_empty() {
            // We extend here while acquiring a write access (implicit lock), while the
            // processing above only requires a read access.
            self.group_tags
                .get_mut(group_key)
                .expect("Group must be initialized")
                .extend(tags_to_write);
        }

        self.remove_impl::<V2>(group_key, txn_idx, prev_tags, &mut ret_v2)?;

        Ok((ret_v1, ret_v2))
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L2548-2600)
```rust
    pub fn execute_block(
        &self,
        signature_verified_block: &TP,
        base_view: &S,
        transaction_slice_metadata: &TransactionSliceMetadata,
        module_cache_manager_guard: &mut AptosModuleCacheManagerGuard,
    ) -> BlockExecutionResult<BlockOutput<T, E::Output>, E::Error> {
        let _timer = BLOCK_EXECUTOR_INNER_EXECUTE_BLOCK.start_timer();

        if self.config.local.concurrency_level > 1 {
            let parallel_result = if self.config.local.blockstm_v2 {
                BLOCKSTM_VERSION_NUMBER.set(2);
                self.execute_transactions_parallel_v2(
                    signature_verified_block,
                    base_view,
                    transaction_slice_metadata,
                    module_cache_manager_guard,
                )
            } else {
                BLOCKSTM_VERSION_NUMBER.set(1);
                self.execute_transactions_parallel(
                    signature_verified_block,
                    base_view,
                    transaction_slice_metadata,
                    module_cache_manager_guard,
                )
            };

            // If parallel gave us result, return it
            if let Ok(output) = parallel_result {
                return Ok(output);
            }

            if !self.config.local.allow_fallback {
                panic!("Parallel execution failed and fallback is not allowed");
            }

            // All logs from the parallel execution should be cleared and not reported.
            // Clear by re-initializing the speculative logs.
            init_speculative_logs(signature_verified_block.num_txns() + 1);

            // Flush all caches to re-run from the "clean" state.
            module_cache_manager_guard
                .environment()
                .runtime_environment()
                .flush_all_caches();
            module_cache_manager_guard.module_cache_mut().flush();

            info!("parallel execution requiring fallback");
        }

        // If we didn't run parallel, or it didn't finish successfully - run sequential
        let sequential_result = self.execute_transactions_sequential(
```

**File:** types/src/block_executor/config.rs (L53-80)
```rust
pub struct BlockExecutorLocalConfig {
    // If enabled, uses BlockSTMv2 algorithm / scheduler for parallel execution.
    pub blockstm_v2: bool,
    pub concurrency_level: usize,
    // If specified, parallel execution fallbacks to sequential, if issue occurs.
    // Otherwise, if there is an error in either of the execution, we will panic.
    pub allow_fallback: bool,
    // If true, we will discard the failed blocks and continue with the next block.
    // (allow_fallback needs to be set)
    pub discard_failed_blocks: bool,
    pub module_cache_config: BlockExecutorModuleCacheLocalConfig,
}

impl BlockExecutorLocalConfig {
    /// Returns a new config with specified concurrency level and:
    ///   - Allowed fallback to sequential execution from parallel.
    ///   - Not allowed discards of failed blocks.
    ///   - Default module cache configs.
    pub fn default_with_concurrency_level(concurrency_level: usize) -> Self {
        Self {
            blockstm_v2: false,
            concurrency_level,
            allow_fallback: true,
            discard_failed_blocks: false,
            module_cache_config: BlockExecutorModuleCacheLocalConfig::default(),
        }
    }
}
```
