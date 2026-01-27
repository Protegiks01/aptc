# Audit Report

## Title
Gas Limit Bypass in QuorumStore Inline Batches Due to Incompatible Configuration Flags

## Summary
When `allow_batches_without_pos_in_proposal` is enabled but `enable_payload_v2` is disabled (the default configuration), blocks with inline batches are created using the V1 payload format (`QuorumStoreInlineHybrid`), which cannot properly store or enforce block gas limits. This causes gas limit constraints to be silently dropped during payload transformation, allowing blocks to execute without resource limits and potentially causing validator node performance degradation. [1](#0-0) [2](#0-1) 

## Finding Description
The vulnerability stems from a semantic incompatibility between two configuration flags that control quorum store behavior. The `allow_batches_without_pos_in_proposal` flag enables including inline batches (transactions embedded directly in blocks) in proposals, while `enable_payload_v2` controls which payload format is used.

When a proposal is generated with inline batches enabled but using the V1 payload format, the following execution path occurs:

1. **Payload Creation**: The `ProofManager` pulls inline batches when the proof queue is fully utilized and creates a `Payload::QuorumStoreInlineHybrid` (V1) payload with `None` as the execution limit. [3](#0-2) [4](#0-3) 

2. **Gas Limit Application**: During proposal generation, if block gas limits are configured, the `transform_to_quorum_store_v2` method is called to apply execution limits to the payload. [5](#0-4) 

3. **Gas Limit Loss**: The transformation method for `QuorumStoreInlineHybrid` (V1) only updates the transaction count limit and **completely ignores** the `block_gas_limit_override` parameter. The gas limit is silently dropped and never stored in the payload. [6](#0-5) 

4. **Bypass Consequence**: When the block is executed, the payload manager extracts transactions but cannot provide a gas limit to the executor because it was never stored. [7](#0-6) 

In contrast, when `enable_payload_v2` is true, the V2 payload format properly stores both transaction and gas limits: [8](#0-7) 

This breaks the fundamental invariant that "All operations must respect gas, storage, and computational limits." Block gas limits are enforced by the `BlockGasLimitProcessor` during execution to prevent validators from being overwhelmed by computationally expensive blocks. Without these limits, maliciously crafted or naturally high-gas blocks can cause:

- Validator node slowdowns or stalls
- Consensus liveness issues if blocks take too long to execute
- Uneven resource consumption across the validator set
- Potential consensus timeouts

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdowns**: Blocks without gas limit enforcement can execute arbitrary amounts of computation, directly causing validator performance degradation. This matches the "Validator node slowdowns" category worth up to $50,000.

2. **Significant Protocol Violations**: The bypass of block gas limits violates the resource limit invariant (#9: "All operations must respect gas, storage, and computational limits"). Block gas limits are a critical protocol-level safeguard designed into Aptos' execution model.

3. **Default Configuration Affected**: The vulnerability exists in the default configuration shipped with Aptos, meaning all validators using default settings are potentially affected when block gas limits are enabled.

4. **Consensus Liveness Risk**: If multiple validators receive blocks that execute excessive gas, they may fail to complete execution within consensus timeouts, potentially causing temporary liveness failures.

The impact is not Critical severity because it does not directly cause fund loss, consensus safety violations (different state roots), or permanent network partition. However, it significantly degrades network performance and violates protocol invariants.

## Likelihood Explanation
The likelihood of this vulnerability manifesting is **HIGH** because:

1. **Default Configuration**: The problematic configuration (`allow_batches_without_pos_in_proposal=true`, `enable_payload_v2=false`) is the default setting in production code.

2. **Automatic Trigger**: When the proof queue becomes fully utilized (a common occurrence under high load), inline batches are automatically included in proposals. No attacker action is required beyond normal network usage.

3. **Block Gas Limits Usage**: While not all networks may enable `block_gas_limit_override`, this is a legitimate configuration option for production networks that need to control execution resource consumption.

4. **No Validation**: There is no configuration validation that warns operators about this incompatible flag combination or prevents it from being used.

The vulnerability will manifest whenever:
- A network is configured with block gas limits (via `ExecutionConfig`)
- Validators use default quorum store settings
- Network load causes the proof queue to fill up
- Proposals are generated with inline batches

## Recommendation
The issue can be fixed by enforcing consistency between the two configuration flags. I recommend:

1. **Configuration Validation**: Add a sanitizer check that rejects configurations where `allow_batches_without_pos_in_proposal=true` but `enable_payload_v2=false`:

```rust
// In config/src/config/quorum_store_config.rs
impl ConfigSanitizer for QuorumStoreConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.consensus.quorum_store;
        
        // Enforce: inline batches require payload v2 for proper gas limit support
        if config.allow_batches_without_pos_in_proposal && !config.enable_payload_v2 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "allow_batches_without_pos_in_proposal requires enable_payload_v2=true for gas limit support".to_string(),
            ));
        }
        
        // ... existing validation ...
    }
}
```

2. **Update Default Configuration**: Change the default to enable both flags together:

```rust
impl Default for QuorumStoreConfig {
    fn default() -> QuorumStoreConfig {
        QuorumStoreConfig {
            // ... other fields ...
            allow_batches_without_pos_in_proposal: true,
            enable_payload_v2: true,  // Changed from false
            // ... other fields ...
        }
    }
}
```

3. **Runtime Guard**: Add a defensive check in `proof_manager.rs` to prevent pulling inline batches when payload v2 is disabled:

```rust
let (inline_block, inline_block_size) =
    if self.allow_batches_without_pos_in_proposal 
        && self.enable_payload_v2  // Add this check
        && proof_queue_fully_utilized {
        // ... existing inline batch pulling logic ...
    } else {
        (Vec::new(), PayloadTxnsSize::zero())
    };
```

## Proof of Concept

The following demonstrates the vulnerability path:

```rust
// Configuration Setup (in validator node config)
// consensus.quorum_store.allow_batches_without_pos_in_proposal = true (default)
// consensus.quorum_store.enable_payload_v2 = false (default)
// execution.block_gas_limit = Some(1_000_000) (hypothetical production setting)

// Step 1: ProofManager creates payload with inline batches
// File: consensus/src/quorum_store/proof_manager.rs:156-234
// When proof_queue_fully_utilized=true, inline batches are pulled
// Payload created: QuorumStoreInlineHybrid(inline_batches, proofs, None)

// Step 2: ProposalGenerator applies gas limit transformation
// File: consensus/src/liveness/proposal_generator.rs:678-684
// block_gas_limit_override = Some(1_000_000)
// Calls: payload.transform_to_quorum_store_v2(None, Some(1_000_000))

// Step 3: Transformation drops gas limit
// File: consensus/consensus-types/src/common.rs:236-242
// For QuorumStoreInlineHybrid: returns QuorumStoreInlineHybrid(batches, proofs, None)
// Gas limit parameter is IGNORED - it's never stored anywhere

// Step 4: Block executes without gas limit
// File: consensus/src/payload_manager/quorum_store_payload_manager.rs:486-495
// get_transactions returns: (txns, None, None)
//                                     ^^^^ gas_limit is None!
// BlockGasLimitProcessor receives None and doesn't enforce any limit

// Result: Block with inline batches executes with unlimited gas
// Impact: Validator node slowdown, potential consensus timeout
```

To reproduce:
1. Configure a local testnet with default quorum store settings
2. Enable block gas limits in execution configuration  
3. Generate high transaction load to fill proof queue
4. Observe proposals with inline batches being created
5. Monitor block execution - gas limits are not enforced
6. Measure validator CPU/execution time vs expected limits

The vulnerability is deterministic and will occur on every proposal generated under these conditions.

## Notes

This vulnerability affects the interaction between the consensus layer's quorum store mechanism and the execution layer's resource metering. While both `allow_batches_without_pos_in_proposal` and `enable_payload_v2` are individually valid configuration options, their combination creates an unsafe state where critical execution limits are bypassed.

The V2 payload format was specifically designed to support comprehensive execution limits including gas limits, and inline batches should only be used with this enhanced format to maintain protocol invariants around resource consumption.

### Citations

**File:** config/src/config/quorum_store_config.rs (L98-101)
```rust
    pub allow_batches_without_pos_in_proposal: bool,
    pub enable_opt_quorum_store: bool,
    pub opt_qs_minimum_batch_age_usecs: u64,
    pub enable_payload_v2: bool,
```

**File:** config/src/config/quorum_store_config.rs (L140-143)
```rust
            allow_batches_without_pos_in_proposal: true,
            enable_opt_quorum_store: true,
            opt_qs_minimum_batch_age_usecs: Duration::from_millis(50).as_micros() as u64,
            enable_payload_v2: false,
```

**File:** consensus/src/quorum_store/proof_manager.rs (L156-184)
```rust
            if self.allow_batches_without_pos_in_proposal && proof_queue_fully_utilized {
                let mut max_inline_txns_to_pull = request
                    .max_txns
                    .saturating_sub(cur_txns)
                    .minimum(request.max_inline_txns);
                max_inline_txns_to_pull.set_count(min(
                    max_inline_txns_to_pull.count(),
                    request
                        .max_txns_after_filtering
                        .saturating_sub(cur_unique_txns),
                ));
                let (inline_batches, inline_payload_size, _) =
                    self.batch_proof_queue.pull_batches_with_transactions(
                        &excluded_batches
                            .iter()
                            .cloned()
                            .chain(proof_block.iter().map(|proof| proof.info().clone()))
                            .chain(opt_batches.clone())
                            .collect(),
                        max_inline_txns_to_pull,
                        request.max_txns_after_filtering,
                        request.soft_max_txns_after_filtering,
                        request.return_non_full,
                        request.block_timestamp,
                    );
                (inline_batches, inline_payload_size)
            } else {
                (Vec::new(), PayloadTxnsSize::zero())
            };
```

**File:** consensus/src/quorum_store/proof_manager.rs (L222-234)
```rust
            if self.enable_payload_v2 {
                Payload::QuorumStoreInlineHybridV2(
                    inline_block,
                    ProofWithData::new(proof_block),
                    PayloadExecutionLimit::None,
                )
            } else {
                Payload::QuorumStoreInlineHybrid(
                    inline_block,
                    ProofWithData::new(proof_block),
                    None,
                )
            }
```

**File:** consensus/src/liveness/proposal_generator.rs (L674-684)
```rust
        if !payload.is_direct()
            && max_txns_from_block_to_execute.is_some()
            && max_txns_from_block_to_execute.is_some_and(|v| payload.len() as u64 > v)
        {
            payload = payload.transform_to_quorum_store_v2(
                max_txns_from_block_to_execute,
                block_gas_limit_override,
            );
        } else if block_gas_limit_override.is_some() {
            payload = payload.transform_to_quorum_store_v2(None, block_gas_limit_override);
        }
```

**File:** consensus/consensus-types/src/common.rs (L236-242)
```rust
            Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _) => {
                Payload::QuorumStoreInlineHybrid(
                    inline_batches,
                    proof_with_data,
                    max_txns_to_execute,
                )
            },
```

**File:** consensus/consensus-types/src/common.rs (L258-267)
```rust
            Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _) => {
                Payload::QuorumStoreInlineHybridV2(
                    inline_batches,
                    proof_with_data,
                    PayloadExecutionLimit::TxnAndGasLimits(TxnAndGasLimits {
                        transaction_limit: max_txns_to_execute,
                        gas_limit: block_gas_limit_override,
                    }),
                )
            },
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L483-495)
```rust
            Payload::QuorumStoreInlineHybrid(
                inline_batches,
                proof_with_data,
                max_txns_to_execute,
            ) => {
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    max_txns_to_execute,
                    &None,
                )
                .await?
```
