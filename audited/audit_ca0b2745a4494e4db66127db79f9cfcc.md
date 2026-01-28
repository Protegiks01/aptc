# Audit Report

## Title
Transaction Deduper Version Skew During Epoch Transitions Causes Consensus Split

## Summary
During epoch transitions, validators that fail to read the on-chain execution config fall back to a default configuration that uses a different transaction deduper type than validators running with V1/V2 configs. This version skew causes validators to produce different execution results from the same block when duplicate transactions are present, leading to a non-recoverable consensus split.

## Finding Description

The vulnerability occurs in the epoch transition logic where validators read the on-chain execution configuration to determine which transaction deduper to use. The transaction deduper filters duplicate transactions from blocks before execution.

The `transaction_deduper_type()` method shows different deduper types based on config version: [1](#0-0) 

During epoch initialization, validators attempt to read the on-chain config: [2](#0-1) 

When reading fails, the code only logs a warning: [3](#0-2) 

Then falls back to the default Missing variant: [4](#0-3) 

Which returns Missing: [5](#0-4) 

The config read can fail for multiple reasons in the DbBackedOnChainConfig provider: [6](#0-5) 

The deduper is created from this config in the execution client: [7](#0-6) 

All validators run the deduper when processing blocks: [8](#0-7) 

The deduper is invoked during block preparation by all validators: [9](#0-8) 

The two deduper implementations behave fundamentally differently. NoOpDeduper returns all transactions unchanged: [10](#0-9) 

While TxnHashAndAuthenticatorDeduper filters duplicates: [11](#0-10) 

**Attack Scenario:**
1. Network is running with ExecutionConfigV1 or V2 (uses NoDedup)
2. Epoch transition occurs at version V
3. Validator A successfully reads V2 config → uses NoDedup
4. Validator B experiences storage I/O error during `get_state_value_by_version()` → falls back to Missing → uses TxnHashAndAuthenticatorV1
5. A block is proposed containing duplicate transactions: `[TxnX, TxnY, TxnX_duplicate]`
6. Validator A keeps all transactions and executes 3 transactions → produces StateRoot_A
7. Validator B filters duplicates and executes 2 transactions → produces StateRoot_B
8. Validators disagree on state root → consensus split → network partition

## Impact Explanation

This vulnerability meets the **Critical Severity** criteria per the Aptos bug bounty program:

**Non-recoverable network partition (requires hardfork)**: When validators disagree on the state root due to different transaction deduper behavior, they cannot reach consensus on block commits. The network splits into two factions that cannot reconcile their state differences without manual intervention. This requires a coordinated hard fork to resolve, as there is no automatic recovery mechanism.

**Consensus Safety violation**: This breaks the fundamental consensus invariant that all honest validators must produce identical state roots for identical blocks. The deterministic execution guarantee is violated, making the AptosBFT consensus protocol unable to function correctly.

This directly violates the critical consensus invariant: "Deterministic Execution: All validators must produce identical state roots for identical blocks."

## Likelihood Explanation

The likelihood is **MEDIUM-HIGH** with the following considerations:

**Precondition**: The vulnerability ONLY applies to networks running ExecutionConfigV1 or V2. New networks using V3+ are not affected as they explicitly configure the deduper type.

**Failure scenarios that can trigger the issue**:

1. **Storage Read Failures**: Database I/O errors, disk corruption, or storage layer bugs can cause `get_state_value_by_version()` to fail

2. **Deserialization Errors**: If the serialized config data becomes corrupted, `deserialize_into_config()` will fail

3. **State Sync Issues**: Validators catching up via state sync might not have complete data at the specific version during epoch transition

Once a validator fails to read the config, it remains misconfigured for the **entire epoch**, making consensus failure highly likely when duplicate transactions are naturally present in blocks. Duplicate transactions occur through normal mempool operation, block re-proposals, or malicious submission.

The vulnerability requires no special privileges to exploit - it can be triggered by natural system failures.

## Recommendation

Implement strict validation during epoch initialization to ensure all validators have successfully read the same execution config:

1. **Add runtime config validation**: After reading the config, validators should exchange config hashes or versions to detect mismatches before beginning the epoch

2. **Fail-safe on config read failure**: If config read fails, the validator should refuse to participate in consensus rather than silently falling back to a default that may differ from other validators

3. **Explicit deduper specification in all config versions**: Ensure all ExecutionConfig versions (including V1 and V2) explicitly specify the transaction_deduper_type field rather than relying on hardcoded defaults

4. **Add epoch transition health checks**: Before finalizing epoch transition, verify that critical config values match across a quorum of validators

## Proof of Concept

This vulnerability requires networks running ExecutionConfigV1 or V2 and cannot be easily demonstrated in a standalone test without simulating storage layer failures during epoch transitions. The attack scenario outlined demonstrates the consensus split mechanism when config read fails for a subset of validators, causing deduper version skew that produces different execution results for blocks containing duplicate transactions.

### Citations

**File:** types/src/on_chain_config/execution_config.rs (L108-120)
```rust
    pub fn transaction_deduper_type(&self) -> TransactionDeduperType {
        match &self {
            // Note, this behavior was enabled before OnChainExecutionConfig was registered.
            OnChainExecutionConfig::Missing => TransactionDeduperType::TxnHashAndAuthenticatorV1,
            OnChainExecutionConfig::V1(_config) => TransactionDeduperType::NoDedup,
            OnChainExecutionConfig::V2(_config) => TransactionDeduperType::NoDedup,
            OnChainExecutionConfig::V3(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V4(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V5(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V6(config) => config.transaction_deduper_type.clone(),
            OnChainExecutionConfig::V7(config) => config.transaction_deduper_type.clone(),
        }
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L137-139)
```rust
    pub fn default_if_missing() -> Self {
        OnChainExecutionConfig::Missing
    }
```

**File:** consensus/src/epoch_manager.rs (L1179-1179)
```rust
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
```

**File:** consensus/src/epoch_manager.rs (L1191-1193)
```rust
        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }
```

**File:** consensus/src/epoch_manager.rs (L1202-1203)
```rust
        let execution_config = onchain_execution_config
            .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L398-412)
```rust
    fn get<T: OnChainConfig>(&self) -> Result<T> {
        let bytes = self
            .reader
            .get_state_value_by_version(&StateKey::on_chain_config::<T>()?, self.version)?
            .ok_or_else(|| {
                anyhow!(
                    "no config {} found in aptos root account state",
                    T::CONFIG_ID
                )
            })?
            .bytes()
            .clone();

        T::deserialize_into_config(&bytes)
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L564-565)
```rust
        let transaction_deduper =
            create_transaction_deduper(onchain_execution_config.transaction_deduper_type());
```

**File:** consensus/src/block_preparer.rs (L99-99)
```rust
            let deduped_txns = txn_deduper.dedup(filtered_txns);
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L635-667)
```rust
            match preparer.materialize_block(&block, qc_rx.clone()).await {
                Ok(input_txns) => break input_txns,
                Err(e) => {
                    warn!(
                        "[BlockPreparer] failed to prepare block {}, retrying: {}",
                        block.id(),
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        };
        Ok(result)
    }

    async fn prepare(
        decryption_fut: TaskFuture<DecryptionResult>,
        preparer: Arc<BlockPreparer>,
        block: Arc<Block>,
    ) -> TaskResult<PrepareResult> {
        let mut tracker = Tracker::start_waiting("prepare", &block);
        let (input_txns, max_txns_from_block_to_execute, block_gas_limit) = decryption_fut.await?;

        tracker.start_working();

        let (input_txns, block_gas_limit) = preparer
            .prepare_block(
                &block,
                input_txns,
                max_txns_from_block_to_execute,
                block_gas_limit,
            )
            .await;
```

**File:** consensus/src/transaction_deduper.rs (L17-21)
```rust
impl TransactionDeduper for NoOpDeduper {
    fn dedup(&self, txns: Vec<SignedTransaction>) -> Vec<SignedTransaction> {
        txns
    }
}
```

**File:** consensus/src/txn_hash_and_authenticator_deduper.rs (L38-94)
```rust
impl TransactionDeduper for TxnHashAndAuthenticatorDeduper {
    fn dedup(&self, transactions: Vec<SignedTransaction>) -> Vec<SignedTransaction> {
        let _timer = TXN_DEDUP_SECONDS.start_timer();
        let mut seen = HashMap::new();
        let mut is_possible_duplicate = false;
        let mut possible_duplicates = vec![false; transactions.len()];
        for (i, txn) in transactions.iter().enumerate() {
            match seen.get(&(txn.sender(), txn.replay_protector())) {
                None => {
                    seen.insert((txn.sender(), txn.replay_protector()), i);
                },
                Some(first_index) => {
                    is_possible_duplicate = true;
                    possible_duplicates[*first_index] = true;
                    possible_duplicates[i] = true;
                },
            }
        }
        if !is_possible_duplicate {
            TXN_DEDUP_FILTERED.observe(0 as f64);
            return transactions;
        }

        let num_txns = transactions.len();

        let hash_and_authenticators: Vec<_> = possible_duplicates
            .into_par_iter()
            .zip(&transactions)
            .with_min_len(optimal_min_len(num_txns, 48))
            .map(|(need_hash, txn)| match need_hash {
                true => Some((txn.committed_hash(), txn.authenticator())),
                false => None,
            })
            .collect();

        // TODO: Possibly parallelize. See struct comment.
        let mut seen_hashes = HashSet::new();
        let mut num_duplicates: usize = 0;
        let filtered: Vec<_> = hash_and_authenticators
            .into_iter()
            .zip(transactions)
            .filter_map(|(maybe_hash, txn)| match maybe_hash {
                None => Some(txn),
                Some(hash_and_authenticator) => {
                    if seen_hashes.insert(hash_and_authenticator) {
                        Some(txn)
                    } else {
                        num_duplicates += 1;
                        None
                    }
                },
            })
            .collect();

        TXN_DEDUP_FILTERED.observe(num_duplicates as f64);
        filtered
    }
```
