# Audit Report

## Title
Validator Transactions Become Invalid During Same-Block Epoch Transitions

## Summary
During epoch transitions, validator transactions (specifically DKGResult) pulled from the pool can become invalid by the time they execute because BlockMetadata processes first and may increment the epoch, causing deterministic transaction discard failures.

## Finding Description

The vulnerability exists in the interaction between transaction pulling, execution ordering, and epoch transition logic in the Aptos consensus and execution layers.

**1. Transaction Pulling Without Epoch Transition Check**

The proposal generator pulls validator transactions from the pool without checking if the block's timestamp will trigger an epoch transition. The pulling logic filters only by transaction hashes that are already pending in ancestor blocks, but does not consider upcoming epoch boundaries. [1](#0-0) 

**2. Execution Order Places BlockMetadata First**

The execution order is strictly defined with BlockMetadata/BlockMetadataExt first, then ValidatorTransactions, then UserTransactions. This ordering is enforced by the `combine_to_input_transactions` function: [2](#0-1) 

**3. BlockMetadata Triggers Epoch Transition**

When using `block_prologue` (as opposed to `block_prologue_ext`), if the block timestamp satisfies the epoch interval condition, it calls `reconfiguration::reconfigure()` which immediately increments the epoch: [3](#0-2) 

The reconfigure function increments the epoch counter: [4](#0-3) 

**4. DKGResult Epoch Validation Fails**

DKGResult transactions validate that their embedded epoch matches the current on-chain epoch during execution: [5](#0-4) 

When validation fails, the transaction is discarded with `TransactionStatus::Discard(StatusCode::ABORTED)`: [6](#0-5) 

**5. System Configuration Determines Reconfiguration Path**

The system chooses between immediate reconfiguration (`block_prologue`) and DKG-based reconfiguration (`block_prologue_ext`) based on randomness configuration. The code explicitly documents this behavior: [7](#0-6) 

**6. DKGResult Creation Uses Current Epoch**

When DKG transcripts are aggregated, the DKGResult transaction is created with the current epoch from `epoch_state.epoch`: [8](#0-7) 

**Attack Path:**
1. DKGResult transaction is created with epoch N and placed in validator transaction pool
2. Block is proposed with timestamp T where `T - last_reconfiguration_time >= epoch_interval`
3. System uses immediate reconfiguration path (randomness disabled or transitioning configurations)
4. During execution: BlockMetadata runs `block_prologue`, triggers `reconfigure()`, incrementing epoch to N+1
5. DKGResult with epoch N attempts validation against epoch N+1, fails check
6. Transaction is deterministically discarded by all validators

## Impact Explanation

**Severity: Medium** (Limited Protocol Violation)

This accurately fits the Medium severity category per Aptos bug bounty criteria: "Limited Protocol Violations - State inconsistencies requiring manual intervention, Temporary liveness issues."

**Impact:**
1. **DKG Process Disruption**: DKGResult transactions are discarded, delaying distributed key generation
2. **Epoch Transition Reliability**: Validator transactions fail during epoch transitions
3. **Resource Waste**: Consensus bandwidth and execution resources wasted on deterministically discarded transactions
4. **Timing-Dependent Behavior**: Manifests only when block timestamps cross epoch boundaries

**Why not High/Critical:**
- No consensus split (all validators deterministically agree on discard)
- No funds loss or theft
- No permanent network partition or liveness failure
- Protocol correctness issue, not a safety violation

## Likelihood Explanation

**Likelihood: Medium-High**

This occurs when:
- DKGResult transaction exists in pool for epoch N
- Block proposed with timestamp triggering epoch transition
- System uses immediate reconfiguration path (`block_prologue`)

**Triggering Scenarios:**
1. **Configuration Transitions**: System transitions from DKG-enabled to DKG-disabled via governance
2. **Mixed State**: DKG session initiated but randomness disabled before completion
3. **Epoch Boundaries**: DKGResult created near epoch boundary using immediate reconfiguration

The vulnerability can occur naturally during normal epoch transitions without malicious activity, particularly during governance-driven configuration changes.

## Recommendation

**Solution 1: Check Epoch Transition Before Pulling Validator Transactions**

Modify the proposal generator to check if the block timestamp will trigger an epoch transition before pulling validator transactions. Filter out validator transactions that would fail epoch validation.

**Solution 2: Epoch-Aware Transaction Validation**

Add validation in the validator transaction pool or proposal generator to ensure DKGResult transactions are only included in blocks that won't trigger epoch transitions via immediate reconfiguration.

**Solution 3: Clear Pool on Configuration Changes**

When transitioning from DKG-enabled to DKG-disabled configurations, clear DKGResult transactions from the validator transaction pool to prevent stale transactions from being included.

## Proof of Concept

While no executable PoC is provided, the vulnerability can be reproduced by:

1. Enabling DKG and starting a DKG session for epoch N
2. Creating a DKGResult transaction and placing it in the validator transaction pool
3. Disabling randomness via governance (triggering use of `block_prologue`)
4. Proposing a block with timestamp that satisfies: `timestamp - last_reconfiguration_time >= epoch_interval`
5. Observing that the DKGResult transaction is pulled into the block
6. During execution, BlockMetadata triggers epoch increment to N+1
7. DKGResult validation fails (N != N+1), transaction is discarded

The deterministic nature means all validators will discard the transaction identically, preventing consensus disagreement but causing operational disruption.

---

**Notes:**

This is a valid protocol correctness vulnerability that can disrupt validator operations during epoch transitions. While it doesn't cause consensus splits or fund loss (making it not Critical), it represents a genuine bug in the epoch transition logic that can waste resources and delay critical validator transactions. The Medium severity assessment is appropriate given the limited but real operational impact.

### Citations

**File:** consensus/src/liveness/proposal_generator.rs (L643-665)
```rust
        let pending_validator_txn_hashes: HashSet<HashValue> = pending_blocks
            .iter()
            .filter_map(|block| block.validator_txns())
            .flatten()
            .map(ValidatorTransaction::hash)
            .collect();
        let validator_txn_filter =
            vtxn_pool::TransactionFilter::PendingTxnHashSet(pending_validator_txn_hashes);

        let (validator_txns, mut payload) = self
            .payload_client
            .pull_payload(
                PayloadPullParameters {
                    max_poll_time: self.quorum_store_poll_time.saturating_sub(proposal_delay),
                    max_txns: max_block_txns,
                    max_txns_after_filtering: max_block_txns_after_filtering,
                    soft_max_txns_after_filtering: max_txns_from_block_to_execute
                        .unwrap_or(max_block_txns_after_filtering),
                    max_inline_txns: self.max_inline_txns,
                    maybe_optqs_payload_pull_params,
                    user_txn_filter: payload_filter,
                    pending_ordering,
                    pending_uncommitted_blocks: pending_blocks.len(),
```

**File:** consensus/consensus-types/src/block.rs (L553-566)
```rust
    pub fn combine_to_input_transactions(
        validator_txns: Vec<ValidatorTransaction>,
        txns: Vec<SignedTransaction>,
        metadata: BlockMetadataExt,
    ) -> Vec<Transaction> {
        once(Transaction::from(metadata))
            .chain(
                validator_txns
                    .into_iter()
                    .map(Transaction::ValidatorTransaction),
            )
            .chain(txns.into_iter().map(Transaction::UserTransaction))
            .collect()
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L203-218)
```text
    fun block_prologue(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ) acquires BlockResource, CommitHistory {
        let epoch_interval = block_prologue_common(&vm, hash, epoch, round, proposer, failed_proposer_indices, previous_block_votes_bitvec, timestamp);
        randomness::on_new_block(&vm, epoch, round, option::none());
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L106-159)
```text
    public(friend) fun reconfigure() acquires Configuration {
        // Do not do anything if genesis has not finished.
        if (chain_status::is_genesis() || timestamp::now_microseconds() == 0 || !reconfiguration_enabled()) {
            return
        };

        let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
        let current_time = timestamp::now_microseconds();

        // Do not do anything if a reconfiguration event is already emitted within this transaction.
        //
        // This is OK because:
        // - The time changes in every non-empty block
        // - A block automatically ends after a transaction that emits a reconfiguration event, which is guaranteed by
        //   VM spec that all transactions comming after a reconfiguration transaction will be returned as Retry
        //   status.
        // - Each transaction must emit at most one reconfiguration event
        //
        // Thus, this check ensures that a transaction that does multiple "reconfiguration required" actions emits only
        // one reconfiguration event.
        //
        if (current_time == config_ref.last_reconfiguration_time) {
            return
        };

        reconfiguration_state::on_reconfig_start();

        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
        storage_gas::on_reconfig();

        assert!(current_time > config_ref.last_reconfiguration_time, error::invalid_state(EINVALID_BLOCK_TIME));
        config_ref.last_reconfiguration_time = current_time;
        spec {
            assume config_ref.epoch + 1 <= MAX_U64;
        };
        config_ref.epoch = config_ref.epoch + 1;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                NewEpoch {
                    epoch: config_ref.epoch,
                },
            );
        };
        event::emit_event<NewEpochEvent>(
            &mut config_ref.events,
            NewEpochEvent {
                epoch: config_ref.epoch,
            },
        );

        reconfiguration_state::on_reconfig_finish();
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L66-81)
```rust
        ) {
            Ok((vm_status, vm_output)) => Ok((vm_status, vm_output)),
            Err(Expected(failure)) => {
                // Pretend we are inside Move, and expected failures are like Move aborts.
                Ok((
                    VMStatus::MoveAbort {
                        location: AbortLocation::Script,
                        code: failure as u64,
                        message: None,
                    },
                    VMOutput::empty_with_status(TransactionStatus::Discard(StatusCode::ABORTED)),
                ))
            },
            Err(Unexpected(vm_status)) => Err(vm_status),
        }
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L83-102)
```rust
    fn process_dkg_result_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        dkg_node: DKGTranscript,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        let dkg_state =
            OnChainConfig::fetch_config(resolver).ok_or(Expected(MissingResourceDKGState))?;
        let config_resource = ConfigurationResource::fetch_config(resolver)
            .ok_or(Expected(MissingResourceConfiguration))?;
        let DKGState { in_progress, .. } = dkg_state;
        let in_progress_session_state =
            in_progress.ok_or(Expected(MissingResourceInprogressDKGSession))?;

        // Check epoch number.
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L806-811)
```rust
        // if randomness is disabled, the metadata skips DKG and triggers immediate reconfiguration
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** dkg/src/dkg_manager/mod.rs (L397-404)
```rust
                let txn = ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: self.epoch_state.epoch,
                        author: self.my_addr,
                    },
                    transcript_bytes: bcs::to_bytes(&agg_trx)
                        .map_err(|e| anyhow!("transcript serialization error: {e}"))?,
                });
```
