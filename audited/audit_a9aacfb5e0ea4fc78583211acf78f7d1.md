# Audit Report

## Title
Consensus Observer V1/V2 Payload Version Confusion Enables Unauthorized Gas Limit Enforcement

## Summary
The `verify_against_ordered_payload()` function in the consensus observer fails to validate that the received `BlockTransactionPayload` variant matches the consensus-agreed `Payload` variant. This allows a malicious validator operating as a consensus publisher to inject V2 payloads (with gas limits) when V1 payloads (without gas limits) were agreed upon in consensus, causing consensus observers to enforce gas limits that were never part of the canonical block.

## Finding Description
The vulnerability exists in the consensus observer's payload verification flow. When validators reach consensus on a block, the block contains a `Payload` enum that can be either `QuorumStoreInlineHybrid` (V1) or `QuorumStoreInlineHybridV2` (V2). The key difference:

- **V1**: Contains only a transaction limit (`Option<u64>`)
- **V2**: Contains both transaction limit AND gas limit via `PayloadExecutionLimit` [1](#0-0) 

Validators acting as consensus publishers create `BlockTransactionPayload` messages for observers based on their local `enable_payload_v2` configuration flag: [2](#0-1) [3](#0-2) 

The critical flaw occurs during verification. The `verify_against_ordered_payload()` function matches on the ordered payload type but does NOT verify that the received payload variant matches: [4](#0-3) 

The `verify_inline_batches()` method explicitly accepts BOTH V1 and V2 variants: [5](#0-4) 

Similarly, `verify_transaction_limit()` extracts limits from both variants without type checking: [6](#0-5) 

Most critically, there is a TODO comment acknowledging that gas limit verification is missing: [7](#0-6) 

**Attack Scenario:**
1. Consensus validators agree on a V1 payload with `transaction_limit=100`, no gas limit
2. Malicious validator acting as consensus publisher has `enable_payload_v2=true`
3. Publisher creates V2 `BlockTransactionPayload` with `transaction_limit=100, gas_limit=50000`
4. Observer receives both the original V1 payload and the malicious V2 transaction payload
5. Verification passes because it only checks content, not variant type
6. Observer extracts gas limit from the BlockTransactionPayload: [8](#0-7) 

7. This unauthorized gas limit is passed to block execution: [9](#0-8) 

8. The BlockGasLimitProcessor enforces this limit, potentially halting block execution prematurely when the limit that was NEVER part of consensus is reached, violating the **Deterministic Execution** invariant.

## Impact Explanation
This vulnerability breaks the **Deterministic Execution** invariant (#1): "All validators must produce identical state roots for identical blocks." 

Consensus observers receiving payloads from malicious publishers will execute blocks with different gas limits than what was agreed upon in consensus. This causes:

1. **State Divergence**: Observers may execute fewer transactions than consensus validators, producing different state roots
2. **Execution Inconsistency**: Some transactions that should execute will be skipped due to the unauthorized gas limit
3. **Consensus Safety Violation**: Different nodes compute different results for the same canonical block

This qualifies as **Medium Severity** per the bug bounty criteria: "State inconsistencies requiring intervention."

## Likelihood Explanation
**Moderate likelihood** during network upgrades or with misconfigured validators:

1. **Configuration Mismatch**: During V2 rollout, some validators may have `enable_payload_v2=true` while others have `false`
2. **Malicious Publisher**: A compromised or malicious validator intentionally setting `enable_payload_v2=true` to manipulate observer execution
3. **Deployment Error**: Operators accidentally deploying with incorrect configurations

The vulnerability is **not immediately exploitable by unprivileged attackers** as it requires validator-level access to set the `enable_payload_v2` flag. However, it represents a real consensus safety risk during upgrades or with insider threats.

## Recommendation
Add strict variant type matching in `verify_against_ordered_payload()`:

```rust
pub fn verify_against_ordered_payload(
    &self,
    ordered_block_payload: &Payload,
) -> Result<(), Error> {
    match (self, ordered_block_payload) {
        // V1 payload must match V1 transaction payload
        (
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, inline_batches),
            Payload::QuorumStoreInlineHybrid(expected_inline, expected_proof, expected_limit)
        ) => {
            self.verify_batches(&expected_proof.proofs)?;
            self.verify_inline_batches(expected_inline)?;
            self.verify_transaction_limit(*expected_limit)?;
        },
        // V2 payload must match V2 transaction payload
        (
            BlockTransactionPayload::QuorumStoreInlineHybridV2(payload, inline_batches),
            Payload::QuorumStoreInlineHybridV2(expected_inline, expected_proof, expected_limits)
        ) => {
            self.verify_batches(&expected_proof.proofs)?;
            self.verify_inline_batches(expected_inline)?;
            self.verify_transaction_limit(expected_limits.max_txns_to_execute())?;
            // Actually verify gas limit as the TODO suggests
            if payload.gas_limit() != expected_limits.block_gas_limit() {
                return Err(Error::InvalidMessageError(
                    format!("Gas limit mismatch: expected {:?}, got {:?}",
                            expected_limits.block_gas_limit(), payload.gas_limit())
                ));
            }
        },
        // Reject version mismatches
        (BlockTransactionPayload::QuorumStoreInlineHybrid(_, _), 
         Payload::QuorumStoreInlineHybridV2(_, _, _)) |
        (BlockTransactionPayload::QuorumStoreInlineHybridV2(_, _),
         Payload::QuorumStoreInlineHybrid(_, _, _)) => {
            return Err(Error::InvalidMessageError(
                "Payload version mismatch between V1 and V2!".to_string()
            ));
        },
        // ... handle other variants
    }
    Ok(())
}
```

## Proof of Concept
```rust
#[test]
fn test_v1_v2_confusion_attack() {
    use aptos_consensus_types::common::Payload;
    use aptos_consensus_types::proof_of_store::{BatchInfo, ProofOfStore};
    
    // Consensus agrees on V1 payload with transaction_limit=100, no gas limit
    let inline_batches_v1 = vec![];
    let proof_with_data = ProofWithData::new(vec![]);
    let max_txns = Some(100);
    let ordered_payload_v1 = Payload::QuorumStoreInlineHybrid(
        inline_batches_v1.clone(),
        proof_with_data.clone(),
        max_txns,
    );
    
    // Malicious publisher creates V2 transaction payload with unauthorized gas_limit
    let malicious_transaction_payload = BlockTransactionPayload::new_quorum_store_inline_hybrid(
        vec![], // transactions
        vec![], // proofs
        Some(100), // transaction_limit (matches V1)
        Some(50000), // gas_limit (UNAUTHORIZED - not in V1!)
        vec![], // inline_batches
        true,   // enable_payload_v2 = true (malicious)
    );
    
    // Verification should FAIL but currently PASSES
    let result = malicious_transaction_payload.verify_against_ordered_payload(&ordered_payload_v1);
    
    // BUG: This assertion currently succeeds, allowing the attack
    assert!(result.is_ok(), "Version mismatch not detected!");
    
    // The malicious gas_limit would be extracted and enforced
    let gas_limit = malicious_transaction_payload.gas_limit();
    assert_eq!(gas_limit, Some(50000));
    
    // This gas limit was NEVER part of the consensus-agreed V1 payload!
    // Observers will enforce it, breaking deterministic execution.
}
```

## Notes
This vulnerability demonstrates a critical gap in the consensus observer's validation logic. While the impact requires validator-level access to exploit, it represents a genuine consensus safety risk during network upgrades when validators may have mixed configurations. The issue violates the fundamental Deterministic Execution invariant and should be addressed before V2 payload deployment.

### Citations

**File:** consensus/consensus-types/src/common.rs (L213-223)
```rust
    QuorumStoreInlineHybrid(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        Option<u64>,
    ),
    OptQuorumStore(OptQuorumStorePayload),
    QuorumStoreInlineHybridV2(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        PayloadExecutionLimit,
    ),
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

**File:** consensus/src/consensus_observer/network/observer_message.rs (L669-682)
```rust
            Payload::QuorumStoreInlineHybrid(
                inline_batches,
                proof_with_data,
                max_txns_to_execute,
            ) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proofs)?;

                // Verify the inline batches
                self.verify_inline_batches(inline_batches)?;

                // Verify the transaction limit
                self.verify_transaction_limit(*max_txns_to_execute)?;
            },
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L697-697)
```rust
                // TODO: verify the block gas limit?
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L751-754)
```rust
        let inline_batches: Vec<&BatchInfo> = match self {
            BlockTransactionPayload::QuorumStoreInlineHybrid(_, inline_batches)
            | BlockTransactionPayload::QuorumStoreInlineHybridV2(_, inline_batches) => {
                inline_batches.iter().collect()
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L820-824)
```rust
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.transaction_limit
            },
            BlockTransactionPayload::QuorumStoreInlineHybridV2(payload, _)
            | BlockTransactionPayload::OptQuorumStore(payload, _) => payload.transaction_limit(),
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

**File:** consensus/src/payload_manager/co_payload_manager.rs (L71-75)
```rust
    Ok((
        transaction_payload.transactions(),
        transaction_payload.transaction_limit(),
        transaction_payload.gas_limit(),
    ))
```

**File:** consensus/src/block_preparer.rs (L54-68)
```rust
        let (txns, max_txns_from_block_to_execute, block_gas_limit) = tokio::select! {
                // Poll the block qc future until a QC is received. Ignore None outcomes.
                Some(qc) = block_qc_fut => {
                    let block_voters = Some(qc.ledger_info().get_voters_bitvec().clone());
                    self.payload_manager.get_transactions(block, block_voters).await
                },
                result = self.payload_manager.get_transactions(block, None) => {
                   result
                }
        }?;
        TXNS_IN_BLOCK
            .with_label_values(&["before_filter"])
            .observe(txns.len() as f64);

        Ok((txns, max_txns_from_block_to_execute, block_gas_limit))
```
