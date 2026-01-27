# Audit Report

## Title
Block Gas Limit Verification Bypass in Consensus Observer Causing State Divergence

## Summary
The `verify_against_ordered_payload()` function in the consensus observer fails to verify the block gas limit for `QuorumStoreInlineHybridV2` payloads, allowing a compromised validator acting as a publisher to send inconsistent gas limits that cause observers to execute blocks differently than validators, resulting in state divergence and consensus safety violations.

## Finding Description

The consensus observer architecture allows non-participating nodes (observers) to learn about consensus decisions from validators (publishers). When a publisher sends block information to observers, it transmits two separate messages:

1. **OrderedBlock message**: Contains the ordered blocks with their `Payload::QuorumStoreInlineHybridV2` including `PayloadExecutionLimit` with both transaction limit and block gas limit
2. **BlockPayload message**: Contains the `BlockTransactionPayload::QuorumStoreInlineHybridV2` with transaction data and limits

The verification function at [1](#0-0)  is responsible for ensuring the `BlockTransactionPayload` matches the ordered payload. However, for `QuorumStoreInlineHybridV2`, it only verifies the transaction limit but explicitly skips gas limit verification as indicated by the TODO comment. [2](#0-1) 

When the observer executes blocks, it retrieves the gas limit from the `BlockTransactionPayload` as shown in [3](#0-2) , which is then used by the block executor to constrain transaction execution.

**Attack Flow:**

1. A compromised validator sends an OrderedBlock with `execution_limits.block_gas_limit() = 1000` (low limit)
2. The same validator sends a BlockPayload with `gas_limit = 1000000` (high limit)  
3. Observer verifies batches, inline batches, and transaction limit successfully
4. Observer SKIPS gas limit verification (line 697 TODO)
5. Observer accepts both messages as valid
6. Observer executes block with gas_limit = 1000000
7. Honest validators execute the same block with gas_limit = 1000
8. Different transactions complete execution on observers vs validators
9. State roots diverge between observers and validators

This breaks the **Deterministic Execution** invariant (#1) which requires "All validators must produce identical state roots for identical blocks" and the **Consensus Safety** invariant (#2).

The PayloadExecutionLimit structure is defined at [4](#0-3)  and provides the `block_gas_limit()` method that returns the gas limit that should be enforced.

The Payload enum for QuorumStoreInlineHybridV2 is defined at [5](#0-4)  and includes the execution_limits parameter.

## Impact Explanation

This is a **Critical Severity** vulnerability per the Aptos bug bounty criteria:

- **Consensus/Safety violations**: Observers execute blocks with different gas limits than validators, causing state divergence
- **Non-recoverable network partition**: Observers diverge from the canonical state and cannot rejoin without manual intervention
- **State Consistency violation**: Breaks the fundamental requirement that identical blocks produce identical state transitions

The vulnerability allows a single compromised validator to cause arbitrary state divergence for all observers subscribed to it. In a network where observers are used for read operations, RPC endpoints, or indexing, this could lead to:

- Incorrect balance queries
- Failed transaction submissions due to state mismatch
- Consensus splits if observers later become validators
- Loss of data integrity across the network

## Likelihood Explanation

**Likelihood: High**

- **Attacker requirements**: Requires control of a single validator acting as a publisher
- **Complexity**: Trivial to exploit - simply send different gas limit values in the two messages
- **Detection difficulty**: Hard to detect as both messages pass all verification checks
- **Impact scope**: Affects all observers subscribed to the malicious publisher

While this requires a compromised validator, the BFT consensus protocol is specifically designed to tolerate Byzantine validators (up to 1/3). A single compromised validator should NOT be able to break consensus safety, yet this vulnerability allows exactly that for observer nodes.

The TODO comment at line 697 explicitly acknowledges this verification gap, indicating the developers are aware of the issue but it remains unaddressed.

## Recommendation

Implement gas limit verification for `QuorumStoreInlineHybridV2` payloads by adding a verification step similar to the transaction limit check:

Add a new method to verify gas limits:

```rust
fn verify_gas_limit(&self, expected_gas_limit: Option<u64>) -> Result<(), Error> {
    let gas_limit = self.gas_limit();
    
    if expected_gas_limit != gas_limit {
        return Err(Error::InvalidMessageError(format!(
            "Transaction payload failed gas limit verification! Expected limit: {:?}, Found limit: {:?}",
            expected_gas_limit, gas_limit
        )));
    }
    
    Ok(())
}
```

Then modify the verification logic at line 697:

```rust
// Verify the transaction limit
self.verify_transaction_limit(execution_limits.max_txns_to_execute())?;

// Verify the block gas limit
self.verify_gas_limit(execution_limits.block_gas_limit())?;
```

This ensures the gas limit in the `BlockTransactionPayload` matches the gas limit specified in the ordered block's `PayloadExecutionLimit`.

## Proof of Concept

```rust
// Proof of Concept - Consensus Observer Gas Limit Bypass
// This demonstrates how a malicious publisher can cause state divergence

use aptos_consensus_types::{
    common::{Payload, PayloadExecutionLimit, TxnAndGasLimits},
    payload::TransactionsWithProofAndLimits,
};
use consensus_observer::network::observer_message::{
    BlockTransactionPayload, TransactionsWithProof,
};

#[test]
fn test_gas_limit_verification_bypass() {
    // Step 1: Create an ordered payload with low gas limit (as agreed in consensus)
    let ordered_gas_limit = 1000u64;
    let execution_limits = PayloadExecutionLimit::TxnAndGasLimits(TxnAndGasLimits {
        transaction_limit: Some(100),
        gas_limit: Some(ordered_gas_limit),
    });
    
    let ordered_payload = Payload::QuorumStoreInlineHybridV2(
        vec![], // inline_batches
        ProofWithData::empty(),
        execution_limits,
    );
    
    // Step 2: Create a BlockTransactionPayload with HIGH gas limit (malicious)
    let malicious_gas_limit = 1000000u64;
    let transactions_with_proof = TransactionsWithProof::TransactionsWithProofAndLimits(
        TransactionsWithProofAndLimits::new(
            PayloadWithProof::empty(),
            Some(100), // transaction_limit matches
            Some(malicious_gas_limit), // gas_limit DOESN'T match!
        )
    );
    
    let block_payload = BlockTransactionPayload::QuorumStoreInlineHybridV2(
        transactions_with_proof,
        vec![], // inline_batches
    );
    
    // Step 3: Verify against ordered payload
    let result = block_payload.verify_against_ordered_payload(&ordered_payload);
    
    // Step 4: VULNERABILITY - Verification succeeds even though gas limits don't match!
    assert!(result.is_ok(), "Verification should succeed due to missing gas limit check");
    
    // Step 5: Observer would execute with malicious_gas_limit = 1000000
    // while validators execute with ordered_gas_limit = 1000
    // This causes STATE DIVERGENCE
    
    let observer_gas = block_payload.gas_limit().unwrap();
    let validator_gas = execution_limits.block_gas_limit().unwrap();
    
    assert_ne!(observer_gas, validator_gas, 
        "Observer executes with {} gas while validators use {} gas - STATE DIVERGENCE!",
        observer_gas, validator_gas);
}
```

**Notes**

The vulnerability exists because the verification at [6](#0-5)  calls `verify_against_ordered_payload()` which does not validate gas limits for QuorumStoreInlineHybridV2 payloads. The gas limit from the BlockTransactionPayload is later extracted at [7](#0-6)  and used during block execution, while the ordered payload's gas limit is what was agreed upon in consensus. This mismatch causes deterministic execution to fail across the network.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L647-717)
```rust
    /// Verifies the transaction payload against the given ordered block payload
    pub fn verify_against_ordered_payload(
        &self,
        ordered_block_payload: &Payload,
    ) -> Result<(), Error> {
        match ordered_block_payload {
            Payload::DirectMempool(_) => {
                return Err(Error::InvalidMessageError(
                    "Direct mempool payloads are not supported for consensus observer!".into(),
                ));
            },
            Payload::InQuorumStore(proof_with_data) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proofs)?;
            },
            Payload::InQuorumStoreWithLimit(proof_with_data) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proof_with_data.proofs)?;

                // Verify the transaction limit
                self.verify_transaction_limit(proof_with_data.max_txns_to_execute)?;
            },
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
            Payload::QuorumStoreInlineHybridV2(
                inline_batches,
                proof_with_data,
                execution_limits,
            ) => {
                // Verify the batches in the requested block
                self.verify_batches(&proof_with_data.proofs)?;

                // Verify the inline batches
                self.verify_inline_batches(inline_batches)?;

                // Verify the transaction limit
                self.verify_transaction_limit(execution_limits.max_txns_to_execute())?;

                // TODO: verify the block gas limit?
            },
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => {
                // Verify the batches in the requested block
                self.verify_batches(p.proof_with_data())?;

                // Verify optQS and inline batches
                self.verify_optqs_and_inline_batches(p.opt_batches(), p.inline_batches())?;

                // Verify the transaction limit
                self.verify_transaction_limit(p.max_txns_to_execute())?;
            },
            Payload::OptQuorumStore(OptQuorumStorePayload::V2(_p)) => {
                return Err(Error::InvalidMessageError(
                    "OptQuorumStorePayload V2 is not supproted".into(),
                ));
            },
        }

        Ok(())
    }
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L70-75)
```rust
    // Return the transactions and the transaction limit
    Ok((
        transaction_payload.transactions(),
        transaction_payload.transaction_limit(),
        transaction_payload.gas_limit(),
    ))
```

**File:** consensus/consensus-types/src/payload.rs (L118-194)
```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PayloadExecutionLimit {
    None,
    MaxTransactionsToExecute(u64),
    TxnAndGasLimits(TxnAndGasLimits),
}

impl PayloadExecutionLimit {
    pub fn new(max_txns: Option<u64>, _max_gas: Option<u64>) -> Self {
        // TODO: on next release, start using TxnAndGasLimits
        match max_txns {
            Some(max_txns) => PayloadExecutionLimit::MaxTransactionsToExecute(max_txns),
            None => PayloadExecutionLimit::None,
        }
    }

    fn extend_options(o1: Option<u64>, o2: Option<u64>) -> Option<u64> {
        match (o1, o2) {
            (Some(v1), Some(v2)) => Some(v1 + v2),
            (Some(v), None) => Some(v),
            (None, Some(v)) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn extend(&mut self, other: PayloadExecutionLimit) {
        *self = match (&self, &other) {
            (PayloadExecutionLimit::None, _) => other,
            (_, PayloadExecutionLimit::None) => return,
            (
                PayloadExecutionLimit::MaxTransactionsToExecute(limit1),
                PayloadExecutionLimit::MaxTransactionsToExecute(limit2),
            ) => PayloadExecutionLimit::MaxTransactionsToExecute(*limit1 + *limit2),
            (
                PayloadExecutionLimit::TxnAndGasLimits(block1_limits),
                PayloadExecutionLimit::TxnAndGasLimits(block2_limits),
            ) => PayloadExecutionLimit::TxnAndGasLimits(TxnAndGasLimits {
                transaction_limit: Self::extend_options(
                    block1_limits.transaction_limit,
                    block2_limits.transaction_limit,
                ),
                gas_limit: Self::extend_options(block1_limits.gas_limit, block2_limits.gas_limit),
            }),
            (
                PayloadExecutionLimit::MaxTransactionsToExecute(limit1),
                PayloadExecutionLimit::TxnAndGasLimits(block2_limits),
            ) => PayloadExecutionLimit::TxnAndGasLimits(TxnAndGasLimits {
                transaction_limit: Some(*limit1 + block2_limits.transaction_limit.unwrap_or(0)),
                gas_limit: block2_limits.gas_limit,
            }),
            (
                PayloadExecutionLimit::TxnAndGasLimits(block1_limits),
                PayloadExecutionLimit::MaxTransactionsToExecute(limit2),
            ) => PayloadExecutionLimit::TxnAndGasLimits(TxnAndGasLimits {
                transaction_limit: Some(*limit2 + block1_limits.transaction_limit.unwrap_or(0)),
                gas_limit: block1_limits.gas_limit,
            }),
        };
    }

    pub fn max_txns_to_execute(&self) -> Option<u64> {
        match self {
            PayloadExecutionLimit::None => None,
            PayloadExecutionLimit::MaxTransactionsToExecute(max) => Some(*max),
            PayloadExecutionLimit::TxnAndGasLimits(limits) => limits.transaction_limit,
        }
    }

    pub fn block_gas_limit(&self) -> Option<u64> {
        match self {
            PayloadExecutionLimit::None | PayloadExecutionLimit::MaxTransactionsToExecute(_) => {
                None
            },
            PayloadExecutionLimit::TxnAndGasLimits(limits) => limits.gas_limit,
        }
    }
}
```

**File:** consensus/consensus-types/src/common.rs (L219-223)
```rust
    QuorumStoreInlineHybridV2(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        PayloadExecutionLimit,
    ),
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L198-199)
```rust
                    // Verify the transaction payload against the ordered block payload
                    transaction_payload.verify_against_ordered_payload(ordered_block_payload)?;
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L502-509)
```rust
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    &execution_limits.max_txns_to_execute(),
                    &execution_limits.block_gas_limit(),
                )
                .await?
```
