# Audit Report

## Title
Consensus Split Due to Configuration-Dependent Gas Limit Processing During Epoch Transitions

## Summary
When validators have different `enable_payload_v2` configuration values, they process identical block payloads with different gas limits, causing non-deterministic transaction execution and producing different state roots. This logic bug violates consensus safety and can trigger a permanent chain split during network upgrades.

## Finding Description

The vulnerability exists in the consensus payload processing pipeline where the `enable_payload_v2` configuration controls payload reconstruction behavior independently on each validator.

**The Critical Logic Bug:**

The `enable_payload_v2` configuration is a per-validator setting stored in node configuration files, with no on-chain coordination mechanism. [1](#0-0) [2](#0-1) 

When a proposer creates a `Payload::QuorumStoreInlineHybridV2` with execution limits, the payload correctly contains both transaction and gas limits. [3](#0-2) 

However, during payload processing in `get_transactions_quorum_store_inline_hybrid()`, validators construct a `BlockTransactionPayload` using their **own local** `enable_payload_v2` configuration rather than the payload's actual type. [4](#0-3) 

The `new_quorum_store_inline_hybrid()` method creates different payload variants based on this flag. When `enable_payload_v2 = false`, it creates a `QuorumStoreInlineHybrid` V1 variant that **discards the gas_limit parameter**, storing only the transaction_limit. [5](#0-4) 

The `gas_limit()` accessor method returns `None` for V1 variants but returns the actual gas limit for V2 variants. [6](#0-5) 

This gas limit is propagated through the execution pipeline via `materialize_block()` and `prepare_block()`, then applied to the executor configuration. [7](#0-6) 

The `BlockGasLimitProcessor` uses this limit to determine when to halt execution. [8](#0-7)  When the gas limit is set, execution stops early via `should_end_block()`. [9](#0-8) 

**Consensus Split Scenario:**

For the same block with V2 payload containing gas_limit = 1000:
- Validators with `enable_payload_v2 = true`: Execute transactions until gas_limit reached → Stop at transaction N
- Validators with `enable_payload_v2 = false`: `gas_limit()` returns `None` → Execute all M transactions (M > N)

Result: Different state roots for identical input block, violating AptosBFT safety guarantees.

**Verification bypasses:** The `Payload::verify()` method treats both V1 and V2 variants identically, performing only signature and batch verification without checking configuration compatibility. [10](#0-9) 

## Impact Explanation

**Critical Severity** per Aptos Bug Bounty criteria:

1. **Consensus Safety Violation**: Different validators produce different state roots for the same block, breaking the fundamental AptosBFT guarantee that honest validators (< 2/3) reach agreement on state.

2. **Non-recoverable Network Partition**: Validators split into two groups based on their configuration. Neither group can achieve 2f+1 consensus with the other, requiring coordinated hardfork resolution.

3. **Chain Split**: The divergence is permanent because validators executing different transaction counts compute fundamentally incompatible state transitions.

This matches the Critical severity category: "Non-recoverable network partition (requires hardfork)" and "Consensus/Safety violations" from the Aptos Bug Bounty program.

## Likelihood Explanation

**High Likelihood** during network operations:

1. **Common Occurrence**: Network upgrades are routine operations where validators update node configurations independently over time windows (rolling upgrades).

2. **No Coordination Mechanism**: The `enable_payload_v2` setting is node-local configuration with no on-chain enforcement or validator synchronization. Different validators can and will have different values during upgrade windows.

3. **Automatic Trigger**: Any proposer with `enable_payload_v2 = true` creating a block under execution backpressure will trigger the vulnerability. No malicious intent or coordination required.

4. **Real-World Scenario**: This is a logic bug, not an exploit. It triggers naturally whenever configuration heterogeneity exists across the validator set during the transition period.

## Recommendation

**Immediate Fix:** Derive payload reconstruction behavior from the received payload's actual type, not from the validator's local configuration:

```rust
// In get_transactions_quorum_store_inline_hybrid()
// Instead of: self.enable_payload_v2
// Use: match on the original payload variant to determine the correct reconstruction

let enable_v2 = matches!(
    block.payload(),
    Some(Payload::QuorumStoreInlineHybridV2(..))
);

Ok(BlockTransactionPayload::new_quorum_store_inline_hybrid(
    all_transactions,
    proof_with_data.proofs.clone(),
    *max_txns_to_execute,
    *block_gas_limit_override,
    inline_batches,
    enable_v2, // Use payload's actual type
))
```

**Long-term Solution:** Either:
1. Tie `enable_payload_v2` to an on-chain feature flag with epoch-synchronized activation
2. Add validation that rejects payload variants incompatible with local configuration
3. Make payload reconstruction deterministic based solely on payload structure

## Proof of Concept

A complete PoC would require setting up validators with different `enable_payload_v2` configurations and demonstrating state root divergence. The code analysis above provides the execution trace showing:

1. Configuration source: `QuorumStoreConfig.enable_payload_v2` (node-local)
2. Payload creation: Uses proposer's configuration
3. Payload reconstruction: Uses receiver's configuration (bug)
4. Gas limit extraction: Returns different values per configuration
5. Execution outcome: Different transaction counts executed

This constitutes a deterministic execution invariant violation with consensus safety impact.

## Notes

The vulnerability stems from architectural confusion between:
- **On-chain feature flag**: `TRANSACTION_PAYLOAD_V2` (transaction-level format)
- **Off-chain configuration**: `enable_payload_v2` (consensus payload format)

These are independent settings with no synchronization mechanism, allowing validators to diverge in their interpretation of the same consensus payload during the critical period when configurations differ across the network.

### Citations

**File:** config/src/config/quorum_store_config.rs (L101-101)
```rust
    pub enable_payload_v2: bool,
```

**File:** config/src/config/quorum_store_config.rs (L143-143)
```rust
            enable_payload_v2: false,
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L155-162)
```rust
        Ok(BlockTransactionPayload::new_quorum_store_inline_hybrid(
            all_transactions,
            proof_with_data.proofs.clone(),
            *max_txns_to_execute,
            *block_gas_limit_override,
            inline_batches,
            self.enable_payload_v2,
        ))
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L497-509)
```rust
            Payload::QuorumStoreInlineHybridV2(
                inline_batches,
                proof_with_data,
                execution_limits,
            ) => {
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    &execution_limits.max_txns_to_execute(),
                    &execution_limits.block_gas_limit(),
                )
                .await?
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L533-556)
```rust
    pub fn new_quorum_store_inline_hybrid(
        transactions: Vec<SignedTransaction>,
        proofs: Vec<ProofOfStore<BatchInfo>>,
        transaction_limit: Option<u64>,
        gas_limit: Option<u64>,
        inline_batches: Vec<BatchInfo>,
        enable_payload_v2: bool,
    ) -> Self {
        let payload_with_proof = PayloadWithProof::new(transactions, proofs);
        if enable_payload_v2 {
            let proof_with_limits = TransactionsWithProof::TransactionsWithProofAndLimits(
                TransactionsWithProofAndLimits::new(
                    payload_with_proof,
                    transaction_limit,
                    gas_limit,
                ),
            );
            Self::QuorumStoreInlineHybridV2(proof_with_limits, inline_batches)
        } else {
            let proof_with_limit =
                PayloadWithProofAndLimit::new(payload_with_proof, transaction_limit);
            Self::QuorumStoreInlineHybrid(proof_with_limit, inline_batches)
        }
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L605-612)
```rust
    pub fn gas_limit(&self) -> Option<u64> {
        match self {
            BlockTransactionPayload::DeprecatedInQuorumStore(_)
            | BlockTransactionPayload::DeprecatedInQuorumStoreWithLimit(_)
            | BlockTransactionPayload::QuorumStoreInlineHybrid(_, _) => None,
            BlockTransactionPayload::QuorumStoreInlineHybridV2(payload, _)
            | BlockTransactionPayload::OptQuorumStore(payload, _) => payload.gas_limit(),
        }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L799-801)
```rust
        let (user_txns, block_gas_limit) = prepare_fut.await?;
        let onchain_execution_config =
            onchain_execution_config.with_block_gas_limit_override(block_gas_limit);
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L119-125)
```rust
    fn block_gas_limit(&self) -> Option<u64> {
        if self.block_gas_limit_override.is_some() {
            self.block_gas_limit_override
        } else {
            self.block_gas_limit_type.block_gas_limit()
        }
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

**File:** consensus/consensus-types/src/common.rs (L590-596)
```rust
            (true, Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _))
            | (true, Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _)) => {
                Self::verify_with_cache(&proof_with_data.proofs, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    inline_batches.iter().map(|(info, txns)| (info, txns)),
                )?;
                Ok(())
```
