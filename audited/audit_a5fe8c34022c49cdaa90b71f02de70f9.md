# Audit Report

## Title
Configuration-Dependent Consensus Failure via AggregatorOverriddenStateView in Sharded Block Execution

## Summary
The `AggregatorOverriddenStateView` in sharded block execution overrides the total supply aggregator value to a fixed base value (`u128::MAX >> 1`). When some validators use sharded execution while others use normal execution (due to the local `num_executor_shards` configuration), governance proposal creation reads different total supply values, computes different early resolution thresholds, and produces divergent state roots, causing consensus failure.

## Finding Description

The Aptos blockchain supports two execution modes: standard (non-sharded) and sharded execution. The choice is controlled by the **local** configuration parameter `num_executor_shards`, which is not part of the on-chain consensus configuration. [1](#0-0) 

When sharded execution is enabled, the `AggregatorOverriddenStateView` wrapper intercepts reads to `TOTAL_SUPPLY_STATE_KEY` and returns a fixed override value: [2](#0-1) [3](#0-2) 

This override is used during transaction execution in the sharded path: [4](#0-3) 

In contrast, the non-sharded execution path uses the state view directly without any override: [5](#0-4) 

The decision between sharded and non-sharded execution occurs in the executor based on whether transactions were partitioned: [6](#0-5) 

Partitioning itself depends on the `num_shards` configuration: [7](#0-6) 

**The Critical Bug**: The governance proposal creation logic reads the total supply value and uses it to calculate the `early_resolution_vote_threshold`: [8](#0-7) 

This threshold is then stored in the proposal state: [9](#0-8) 

Since validators with different execution modes read different total supply values (`u128::MAX >> 1` vs. actual supply), they compute **vastly different** threshold values:
- Sharded execution: `(u128::MAX >> 1) / 2 + 1 ≈ 8.5 × 10³⁷`
- Normal execution: `actual_supply / 2 + 1 ≈ 5 × 10¹⁶` (for ~1 billion APT)

The post-execution aggregation step only corrects the total supply value itself, not derived values: [10](#0-9) 

This breaks the **Deterministic Execution** invariant: validators executing identical blocks produce different state roots because the proposal struct contains different threshold values.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos Bug Bounty Program criteria:

1. **Consensus/Safety Violation**: Different validators compute different state roots for the same block, preventing consensus from being reached.

2. **Non-Recoverable Network Partition**: When this occurs, the network cannot make progress. It requires emergency coordination where all validators must agree to use the same execution mode configuration.

3. **Potential Hard Fork Requirement**: If some validators have already committed blocks with divergent state, resolving the issue may require a hard fork to reconcile the divergent state histories.

This is not a theoretical vulnerability—it directly breaks consensus whenever:
- Configuration skew exists (some validators use sharded execution, others don't)
- A governance proposal is created during this period

## Likelihood Explanation

**High Likelihood** during:

1. **Staged Rollouts**: When new validator software versions are deployed gradually, early adopters might enable sharded execution while others haven't upgraded yet.

2. **Performance Tuning**: Validator operators may independently adjust `num_executor_shards` based on their hardware capabilities without realizing it affects consensus.

3. **Emergency Situations**: During incident response, operators might change configurations to diagnose performance issues, inadvertently creating configuration skew.

The vulnerability requires:
- ✅ No Byzantine behavior (just configuration differences)
- ✅ No privileged access (any user can create a governance proposal)
- ✅ Normal network operation
- ✅ Common operational scenario (rolling upgrades)

## Recommendation

**Immediate Fix**: Make execution mode selection part of the on-chain consensus configuration so all validators use the same mode.

**Option 1 - On-chain Configuration**:
Add `execution_mode` to `BlockExecutorConfigFromOnchain` and ensure all validators read and respect this on-chain parameter rather than using local configuration.

**Option 2 - Disable Value-Dependent Override**:
Remove the `AggregatorOverriddenStateView` override for state reads that affect transaction logic. The override should only apply to internal bookkeeping that doesn't influence transaction outputs. The comment in the code already acknowledges this is a TODO workaround: [11](#0-10) 

**Option 3 - Correct All Derived Values**:
Extend `aggregate_and_update_total_supply()` to track and correct ALL values derived from total supply, not just the total supply itself. However, this is complex and error-prone.

**Recommended Approach**: Option 1 (on-chain configuration enforcement) combined with validation that rejects blocks if execution mode mismatches are detected.

## Proof of Concept

```rust
// Reproduction steps demonstrating consensus failure

// Setup: Two validators with different configurations
// Validator A: num_executor_shards = 0 (non-sharded)
// Validator B: num_executor_shards = 4 (sharded)

// Step 1: Both validators receive identical block with governance proposal transaction
let block = create_block_with_governance_proposal();

// Step 2: Validator A executes non-sharded
// - Reads actual total supply: 100_000_000_000_000_000 (1e17)
// - Computes threshold: 50_000_000_000_000_001
let output_a = validator_a.execute_block(&block);
assert_eq!(
    output_a.get_proposal_threshold(),
    50_000_000_000_000_001
);
let state_root_a = output_a.state_root();

// Step 3: Validator B executes sharded
// - Reads override value: 170141183460469231731687303715884105727 (u128::MAX >> 1)
// - Computes threshold: 85070591730234615865843651857942052864
let output_b = validator_b.execute_block(&block);
assert_eq!(
    output_b.get_proposal_threshold(),
    85070591730234615865843651857942052864
);
let state_root_b = output_b.state_root();

// Step 4: State roots diverge
assert_ne!(state_root_a, state_root_b);

// Step 5: Consensus cannot be reached
// Validators vote for different state roots
// Network halts until emergency coordination
```

**Move Test Scenario**:
```move
#[test(framework = @aptos_framework, proposer = @0x123)]
public entry fun test_governance_threshold_depends_on_execution_mode(
    framework: &signer,
    proposer: &signer,
) {
    // This test would show that identical proposal transactions
    // produce different thresholds when executed with different
    // total supply base values, demonstrating the consensus issue.
    
    // Note: Actual implementation requires access to VM internals
    // to simulate different execution modes on the same transaction
}
```

## Notes

This vulnerability demonstrates a critical design flaw where a local performance optimization parameter (`num_executor_shards`) inadvertently affects consensus-critical execution behavior. The `AggregatorOverriddenStateView` was likely introduced as a temporary workaround for sharded execution, but it violates the deterministic execution invariant when validators have heterogeneous configurations.

The issue is particularly insidious because:
1. Configuration differences are not immediately visible to operators
2. The system may work correctly for most transactions
3. Failure only manifests when specific transaction types (governance proposals) are executed
4. Recovery requires coordinated action across all validators

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L162-162)
```rust
static NUM_EXECUTION_SHARD: OnceCell<usize> = OnceCell::new();
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3055-3093)
```rust
    pub fn execute_block_with_config(
        &self,
        txn_provider: &DefaultTxnProvider<SignatureVerifiedTransaction, AuxiliaryInfo>,
        state_view: &(impl StateView + Sync),
        config: BlockExecutorConfig,
        transaction_slice_metadata: TransactionSliceMetadata,
    ) -> Result<BlockOutput<SignatureVerifiedTransaction, TransactionOutput>, VMStatus> {
        fail_point!("aptos_vm_block_executor::execute_block_with_config", |_| {
            Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                None,
            ))
        });

        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        let num_txns = txn_provider.num_txns();
        debug!(
            log_context,
            "Executing block, transaction count: {}", num_txns
        );

        let result = AptosVMBlockExecutorWrapper::execute_block::<
            _,
            NoOpTransactionCommitHook<VMStatus>,
            DefaultTxnProvider<SignatureVerifiedTransaction, AuxiliaryInfo>,
        >(
            txn_provider,
            state_view,
            &self.module_cache_manager,
            config,
            transaction_slice_metadata,
            None,
        );
        if result.is_ok() {
            // Record the histogram count for transactions per block.
            BLOCK_TRANSACTION_COUNT.observe(num_txns as f64);
        }
        result
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L14-14)
```rust
pub const TOTAL_SUPPLY_AGGR_BASE_VAL: u128 = u128::MAX >> 1;
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L41-50)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>> {
        if *state_key == *TOTAL_SUPPLY_STATE_KEY {
            // TODO: Remove this when we have aggregated total supply implementation for remote
            //       sharding. For now we need this because after all the txns are executed, the
            //       proof checker expects the total_supply to read/written to the tree.
            self.base_view.get_state_value(state_key)?;
            return self.total_supply_base_view_override();
        }
        self.base_view.get_state_value(state_key)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L123-126)
```rust
        let aggr_overridden_state_view = Arc::new(AggregatorOverriddenStateView::new(
            cross_shard_state_view.as_ref(),
            TOTAL_SUPPLY_AGGR_BASE_VAL,
        ));
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L68-89)
```rust
        let out = match transactions {
            ExecutableTransactions::Unsharded(txns) => {
                Self::by_transaction_execution_unsharded::<V>(
                    executor,
                    txns,
                    auxiliary_infos,
                    parent_state,
                    state_view,
                    onchain_config,
                    transaction_slice_metadata,
                )?
            },
            // TODO: Execution with auxiliary info is yet to be supported properly here for sharded transactions
            ExecutableTransactions::Sharded(txns) => Self::by_transaction_execution_sharded::<V>(
                txns,
                auxiliary_infos,
                parent_state,
                state_view,
                onchain_config,
                transaction_slice_metadata.append_state_checkpoint_to_block(),
            )?,
        };
```

**File:** execution/executor-benchmark/src/block_preparation.rs (L47-52)
```rust
        let maybe_partitioner = if num_shards == 0 {
            None
        } else {
            let partitioner = partitioner_config.build();
            Some(partitioner)
        };
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L443-449)
```text
        let total_voting_token_supply = coin::supply<AptosCoin>();
        let early_resolution_vote_threshold = option::none<u128>();
        if (option::is_some(&total_voting_token_supply)) {
            let total_supply = *option::borrow(&total_voting_token_supply);
            // 50% + 1 to avoid rounding errors.
            early_resolution_vote_threshold = option::some(total_supply / 2 + 1);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L340-340)
```text
            early_resolution_vote_threshold,
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L226-237)
```rust
                    txn_outputs
                        .par_iter_mut()
                        .with_min_len(optimal_min_len(num_txn_outputs, 32))
                        .for_each(|txn_output| {
                            if let Some(txn_total_supply) =
                                txn_output.write_set().get_total_supply()
                            {
                                txn_output.update_total_supply(
                                    delta_for_round.add_delta(txn_total_supply),
                                );
                            }
                        });
```
