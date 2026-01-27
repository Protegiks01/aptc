# Audit Report

## Title
Consensus Determinism Break via Divergent Transaction Filter Configurations

## Summary
The Aptos consensus layer uses node-local transaction filter configurations (`execution_filter` and `consensus_filter`) that are not synchronized across validators. Different validators can execute different transaction sets from identical blocks, breaking the fundamental consensus invariant of deterministic execution and causing state divergence.

## Finding Description

The vulnerability stems from the architecture of the transaction filtering system:

**Two Separate Filter Configurations:**

1. **Consensus Filter** (`consensus_txn_filter_config`) - Used during proposal voting [1](#0-0) 

2. **Execution Filter** (`txn_filter_config`) - Used during block execution [2](#0-1) 

Both configurations are loaded from node-local config files [3](#0-2)  and [4](#0-3) , with **no on-chain mechanism to enforce uniformity** across validators.

**Critical Code Path:**

During block preparation, the `filter_block_transactions()` function has an early return when filtering is disabled [5](#0-4) . When enabled, it filters transactions before execution [6](#0-5) .

These filtered transactions flow directly into execution [7](#0-6)  and [8](#0-7) .

**Defense Mechanism Insufficient:**

The `check_denied_inline_transactions()` mechanism only validates **inline transactions** during proposal voting [9](#0-8) . The function only extracts inline batches [10](#0-9) , **not** proof-based quorum store batches.

However, during execution, **all transactions** (both inline and proof-based) are retrieved [11](#0-10)  and filtered by the execution filter.

**Breaking Determinism:**

If validators have divergent filter configurations:
- Validator A: `execution_filter.is_enabled() = false` → executes all transactions
- Validator B: `execution_filter.is_enabled() = true` with rule X → filters out transactions matching rule X

Both validators vote for the same block, but during execution they process different transaction sets, computing different state roots.

## Impact Explanation

**Severity: Critical** ($1,000,000 category)

This vulnerability breaks **Consensus Safety**, a Critical severity impact per the Aptos bug bounty program. Specifically:

1. **Consensus Invariant Violation**: Breaks "Deterministic Execution: All validators must produce identical state roots for identical blocks"

2. **State Divergence**: Validators compute different state roots for the same block, preventing consensus on subsequent blocks

3. **Network Partition**: Requires manual intervention or hardfork to resolve once validators diverge, meeting the "Non-recoverable network partition" criterion

4. **Cascading Failure**: Once state roots diverge, all subsequent blocks will fail to reach consensus as validators cannot agree on the ledger state

## Likelihood Explanation

**Likelihood: Medium-Low**

While the vulnerability is architecturally present, exploitation requires:

1. **Configuration Divergence**: Multiple validators must have different filter configurations, which could occur through:
   - Operational errors during config updates
   - New validators joining with different default configs
   - Partial rollout of config changes across the validator set
   - Human error in configuration management

2. **No Runtime Detection**: There is no validation mechanism to detect or prevent configuration inconsistencies across validators

3. **Silent Failure Mode**: The issue manifests only when filtered transactions are included in blocks, making it difficult to detect until consensus breaks

However, the attack does **not** require:
- External attacker access (validators self-inflict through misconfiguration)
- Malicious validator behavior (can occur through accidental operational errors)
- Network manipulation or cryptographic breaks

## Recommendation

**Immediate Fix:** Make transaction filter configurations part of the on-chain consensus configuration to ensure all validators use identical filters.

**Implementation Approach:**

1. Add `BlockTransactionFilterConfig` to `OnChainConsensusConfig` structure
2. Update via governance proposals, ensuring atomic updates across all validators
3. Add validation during epoch transitions to verify all validators have consistent configs
4. Add metrics/alerts to detect configuration drift

**Alternative Mitigation:** If filters must remain node-local for operational flexibility:
- Add hash of filter config to block metadata
- Validators validate that block proposer's filter config matches their own
- Reject proposals from validators with divergent configs

## Proof of Concept

```rust
// Reproduction Steps:
// 1. Setup 4-validator testnet
// 2. Configure validators with divergent execution filters:

// Validator A & B: execution_filter.enabled = false
// Validator C & D: execution_filter.enabled = true with:
//   - Deny transactions from sender 0x123

// 3. Submit transactions from both 0x123 and 0x456
// 4. Observe consensus:
//   - All validators vote on block (inline check passes)
//   - Validators A,B execute all transactions
//   - Validators C,D filter out 0x123 transactions
//   - Different state roots computed
//   - Consensus stalls - cannot form QC for next block

// Key code demonstrating the split:
// File: consensus/src/block_preparer.rs
fn filter_block_transactions(...) -> Vec<SignedTransaction> {
    if !txn_filter_config.is_enabled() {
        return txns;  // A,B take this path
    }
    // C,D filter here, removing 0x123's transactions
    txn_filter_config.block_transaction_filter()
        .filter_block_transactions(...)
}
```

**Notes:**

The vulnerability is a **design flaw** in the configuration architecture rather than a classic exploitable bug. It requires validator operator involvement (misconfiguration) to manifest, placing it in a gray area regarding the trust model. However, it represents a systemic consensus safety risk that should be addressed through architectural changes to enforce configuration consistency across the validator set.

### Citations

**File:** consensus/src/epoch_manager.rs (L211-211)
```rust
        let consensus_txn_filter_config = node_config.transaction_filters.consensus_filter.clone();
```

**File:** consensus/src/state_computer.rs (L69-70)
```rust
        state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
        txn_filter_config: BlockTransactionFilterConfig,
```

**File:** consensus/src/consensus_provider.rs (L69-69)
```rust
        node_config.transaction_filters.execution_filter.clone(),
```

**File:** consensus/src/consensus_provider.rs (L162-162)
```rust
            node_config.transaction_filters.execution_filter.clone(),
```

**File:** consensus/src/block_preparer.rs (L132-134)
```rust
    if !txn_filter_config.is_enabled() {
        return txns;
    }
```

**File:** consensus/src/block_preparer.rs (L137-145)
```rust
    txn_filter_config
        .block_transaction_filter()
        .filter_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp_usecs,
            txns,
        )
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L799-799)
```rust
        let (user_txns, block_gas_limit) = prepare_fut.await?;
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L824-824)
```rust
            user_txns.as_ref().clone(),
```

**File:** consensus/src/round_manager.rs (L1204-1214)
```rust
        if let Err(error) = self
            .block_store
            .check_denied_inline_transactions(&proposal, &self.block_txn_filter_config)
        {
            counters::REJECTED_PROPOSAL_DENY_TXN_COUNT.inc();
            bail!(
                "[RoundManager] Proposal for block {} contains denied inline transactions: {}. Dropping proposal!",
                proposal.id(),
                error
            );
        }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L135-149)
```rust
            let mut all_txns = process_qs_payload(
                proof_with_data,
                self.batch_reader.clone(),
                block,
                &self.ordered_authors,
            )
            .await?;
            all_txns.append(
                &mut inline_batches
                    .iter()
                    // TODO: Can clone be avoided here?
                    .flat_map(|(_batch_info, txns)| txns.clone())
                    .collect(),
            );
            all_txns
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L568-598)
```rust
fn get_inline_transactions(block: &Block) -> Vec<SignedTransaction> {
    // If the block has no payload, return an empty vector
    let Some(payload) = block.payload() else {
        return vec![];
    };

    // Fetch the inline transactions from the payload
    match payload {
        Payload::QuorumStoreInlineHybrid(inline_batches, ..) => {
            // Flatten the inline batches and return the transactions
            inline_batches
                .iter()
                .flat_map(|(_batch_info, txns)| txns.clone())
                .collect()
        },
        Payload::QuorumStoreInlineHybridV2(inline_batches, ..) => {
            // Flatten the inline batches and return the transactions
            inline_batches
                .iter()
                .flat_map(|(_batch_info, txns)| txns.clone())
                .collect()
        },
        Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => p.inline_batches().transactions(),
        Payload::OptQuorumStore(OptQuorumStorePayload::V2(_p)) => {
            error!("OptQSPayload V2 is not expected");
            Vec::new()
        },
        _ => {
            vec![] // Other payload types do not have inline transactions
        },
    }
```
