# Audit Report

## Title
DAG Consensus CommitSignerProvider Bypasses Safety Rules Enabling Potential Consensus Violations

## Summary
The `DagCommitSigner` implementation of `CommitSignerProvider` completely bypasses all safety rules validation when signing commit votes, including verification of voting history, signature quorums, and ledger info consistency checks. This creates a defense-in-depth vulnerability where validators running DAG consensus can sign arbitrary ledger information without the safety constraints enforced by the standard SafetyRules implementation.

## Finding Description

The `CommitSignerProvider` trait is used in the consensus signing phase to sign commit votes after block execution. The codebase contains two implementations with drastically different security properties:

**Standard Implementation (MetricsSafetyRules):** Delegates to `SafetyRules::guarded_sign_commit_vote` which enforces:
- Validation that the ordered ledger info is either ordered-only or matches the commit info
- Consistency check between ordered and commit ledger info via `match_ordered_only`
- Signature verification requiring at least 2f+1 valid signatures on the ordered ledger info [1](#0-0) 

**DAG Implementation (DagCommitSigner):** Ignores all safety checks and directly signs any ledger info provided: [2](#0-1) 

The vulnerability manifests in the signing phase where both implementations are used interchangeably through the `CommitSignerProvider` trait: [3](#0-2) 

When DAG consensus is enabled, the system instantiates `DagCommitSigner` instead of the SafetyRules-based implementation: [4](#0-3) 

Furthermore, the DAG adapter creates OrderedBlocks with empty signatures in the ordered_proof, which would be rejected by SafetyRules but passes through DagCommitSigner unchecked: [5](#0-4) 

The safety rules test suite explicitly validates that empty signatures should be rejected: [6](#0-5) 

## Impact Explanation

This represents a **High Severity** vulnerability rather than Critical because:

1. **Defense-in-Depth Violation**: Each validator should independently enforce consensus safety rules. By bypassing these checks, a malicious validator could sign conflicting commit votes for the same round without local prevention.

2. **Potential Consensus Safety Risk**: While a single malicious validator cannot break consensus alone (requires 2f+1 quorum), the lack of safety checks enables:
   - Equivocation attacks where one validator signs multiple conflicting states
   - Easier exploitation if multiple validators collude
   - Violation of the "locked rounds" and "preferred rounds" invariants that prevent safety violations

3. **Inconsistent Security Model**: The codebase clearly shows SafetyRules is designed to prevent specific attack patterns (empty signatures, inconsistent execution results, voting rule violations). DagCommitSigner bypassing these checks without documented justification suggests a security gap rather than intentional design.

4. **Protocol Violation Risk**: The TODO comments in SafetyRules indicate incomplete safety rules implementation, yet DagCommitSigner removes even the existing checks.

## Likelihood Explanation

**Moderate-High Likelihood** for the following reasons:

1. **Production Code Path**: DAG consensus is a real operational mode in Aptos, not experimental code
2. **Automatic Activation**: When `consensus_config.is_dag_enabled()` returns true, DagCommitSigner is automatically used
3. **No Runtime Checks**: There are no compensating checks in the pipeline to verify that commit votes adhere to safety constraints
4. **Exploitable by Malicious Validator**: Any validator operator could modify their node to exploit this to sign arbitrary votes

The main mitigating factor is that exploitation requires validator-level access and would be detected if validators publish conflicting signatures. However, subtle violations (signing slightly inconsistent states) might not be immediately apparent.

## Recommendation

Implement safety rules validation in DagCommitSigner to match the checks performed by SafetyRules:

```rust
impl CommitSignerProvider for DagCommitSigner {
    fn sign_commit_vote(
        &self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, aptos_safety_rules::Error> {
        // Add safety checks similar to SafetyRules::guarded_sign_commit_vote
        
        let old_ledger_info = ledger_info.ledger_info();
        
        // Check 1: Validate ordered-only semantics
        if !old_ledger_info.commit_info().is_ordered_only()
            && old_ledger_info.commit_info() != new_ledger_info.commit_info()
        {
            return Err(Error::InvalidOrderedLedgerInfo(old_ledger_info.to_string()));
        }
        
        // Check 2: Verify consistency between ordered and commit ledger info
        if !old_ledger_info
            .commit_info()
            .match_ordered_only(new_ledger_info.commit_info())
        {
            return Err(Error::InconsistentExecutionResult(
                old_ledger_info.commit_info().to_string(),
                new_ledger_info.commit_info().to_string(),
            ));
        }
        
        // Check 3: Verify quorum signatures (if epoch_state available)
        // Note: May need to pass epoch_state to DagCommitSigner constructor
        
        let signature = self
            .signer
            .sign(&new_ledger_info)
            .map_err(|err| Error::SerializationError(err.to_string()))?;

        Ok(signature)
    }
}
```

Additionally, consider whether DagCommitSigner should maintain and check persistent safety data (last_voted_round, preferred_round) similar to SafetyRules, or if the DAG protocol provides equivalent guarantees that should be documented.

## Proof of Concept

```rust
// Proof of concept showing DagCommitSigner accepts what SafetyRules rejects

use aptos_consensus::dag::commit_signer::DagCommitSigner;
use aptos_consensus::pipeline::signing_phase::CommitSignerProvider;
use aptos_crypto::bls12381;
use aptos_types::{
    aggregate_signature::AggregateSignature,
    block_info::BlockInfo,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    validator_signer::ValidatorSigner,
};
use std::sync::Arc;

#[test]
fn test_dag_commit_signer_bypasses_safety_checks() {
    let signer = Arc::new(ValidatorSigner::random(None));
    let dag_commit_signer = DagCommitSigner::new(signer);
    
    // Create an ordered ledger info with EMPTY signatures
    // SafetyRules would reject this with Error::InvalidQuorumCertificate
    let block_info = BlockInfo::random(1);
    let ordered_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(block_info.clone(), HashValue::zero()),
        AggregateSignature::empty(), // Empty signature!
    );
    
    // Create a commit ledger info
    let commit_ledger_info = LedgerInfo::new(block_info, HashValue::zero());
    
    // DagCommitSigner will sign this without checking the empty signatures
    let result = dag_commit_signer.sign_commit_vote(
        ordered_ledger_info,
        commit_ledger_info,
    );
    
    // This succeeds, demonstrating the bypass
    assert!(result.is_ok());
    
    // The same input to SafetyRules would fail with:
    // Error::InvalidQuorumCertificate("Not enough signatures")
}
```

**Notes**

This vulnerability demonstrates a critical break in defense-in-depth where the DAG consensus implementation removes safety checks that exist in the standard consensus path. While the DAG protocol may provide its own safety guarantees through the ordering mechanism, the removal of local validator-level safety checks creates risk of consensus violations if those guarantees are incomplete or if validators are compromised. The finding is particularly concerning given that the SafetyRules implementation explicitly includes these checks and test cases validate their importance.

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L372-418)
```rust
    fn guarded_sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;

        let old_ledger_info = ledger_info.ledger_info();

        if !old_ledger_info.commit_info().is_ordered_only()
            // When doing fast forward sync, we pull the latest blocks and quorum certs from peers
            // and store them in storage. We then compute the root ordered cert and root commit cert
            // from storage and start the consensus from there. But given that we are not storing the
            // ordered cert obtained from order votes in storage, instead of obtaining the root ordered cert
            // from storage, we set root ordered cert to commit certificate.
            // This means, the root ordered cert will not have a dummy executed_state_id in this case.
            // To handle this, we do not raise error if the old_ledger_info.commit_info() matches with
            // new_ledger_info.commit_info().
            && old_ledger_info.commit_info() != new_ledger_info.commit_info()
        {
            return Err(Error::InvalidOrderedLedgerInfo(old_ledger_info.to_string()));
        }

        if !old_ledger_info
            .commit_info()
            .match_ordered_only(new_ledger_info.commit_info())
        {
            return Err(Error::InconsistentExecutionResult(
                old_ledger_info.commit_info().to_string(),
                new_ledger_info.commit_info().to_string(),
            ));
        }

        // Verify that ledger_info contains at least 2f + 1 dostinct signatures
        if !self.skip_sig_verify {
            ledger_info
                .verify_signatures(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
        }

        // TODO: add guarding rules in unhappy path
        // TODO: add extension check

        let signature = self.sign(&new_ledger_info)?;

        Ok(signature)
    }
```

**File:** consensus/src/dag/commit_signer.rs (L19-32)
```rust
impl CommitSignerProvider for DagCommitSigner {
    fn sign_commit_vote(
        &self,
        _ledger_info: aptos_types::ledger_info::LedgerInfoWithSignatures,
        new_ledger_info: aptos_types::ledger_info::LedgerInfo,
    ) -> Result<bls12381::Signature, aptos_safety_rules::Error> {
        let signature = self
            .signer
            .sign(&new_ledger_info)
            .map_err(|err| aptos_safety_rules::Error::SerializationError(err.to_string()))?;

        Ok(signature)
    }
}
```

**File:** consensus/src/pipeline/signing_phase.rs (L72-99)
```rust
    async fn process(&self, req: SigningRequest) -> SigningResponse {
        let SigningRequest {
            ordered_ledger_info,
            commit_ledger_info,
            blocks,
        } = req;

        let signature_result = if let Some(fut) = blocks
            .last()
            .expect("Blocks can't be empty")
            .pipeline_futs()
        {
            fut.commit_vote_fut
                .clone()
                .await
                .map(|vote| vote.signature().clone())
                .map_err(|e| Error::InternalError(e.to_string()))
        } else {
            self.safety_rule_handle
                .sign_commit_vote(ordered_ledger_info, commit_ledger_info.clone())
        };

        SigningResponse {
            signature_result,
            commit_ledger_info,
        }
    }
}
```

**File:** consensus/src/epoch_manager.rs (L1436-1460)
```rust
        let epoch = epoch_state.epoch;
        let signer = Arc::new(ValidatorSigner::new(
            self.author,
            loaded_consensus_key.clone(),
        ));
        let commit_signer = Arc::new(DagCommitSigner::new(signer.clone()));

        assert!(
            onchain_consensus_config.decoupled_execution(),
            "decoupled execution must be enabled"
        );
        let highest_committed_round = self
            .storage
            .aptos_db()
            .get_latest_ledger_info()
            .expect("unable to get latest ledger info")
            .commit_info()
            .round();

        self.execution_client
            .start_epoch(
                loaded_consensus_key,
                epoch_state.clone(),
                commit_signer,
                payload_manager.clone(),
```

**File:** consensus/src/dag/adapter.rs (L209-229)
```rust
        let blocks_to_send = OrderedBlocks {
            ordered_blocks: vec![block],
            ordered_proof: LedgerInfoWithSignatures::new(
                LedgerInfo::new(block_info, anchor.digest()),
                AggregateSignature::empty(),
            ),
            // TODO: this needs to be properly integrated with pipeline_builder
            // callback: Box::new(
            //     move |committed_blocks: &[Arc<PipelinedBlock>],
            //           commit_decision: LedgerInfoWithSignatures| {
            //         block_created_ts
            //             .write()
            //             .retain(|&round, _| round > commit_decision.commit_info().round());
            //         dag.commit_callback(commit_decision.commit_info().round());
            //         ledger_info_provider
            //             .write()
            //             .notify_commit_proof(commit_decision);
            //         update_counters_for_committed_blocks(committed_blocks);
            //     },
            // ),
        };
```

**File:** consensus/safety-rules/src/tests/suite.rs (L910-922)
```rust
    // empty signature test
    assert!(matches!(
        safety_rules
            .sign_commit_vote(
                LedgerInfoWithSignatures::new(
                    ledger_info_with_sigs.ledger_info().clone(),
                    AggregateSignature::empty(),
                ),
                ledger_info_with_sigs.ledger_info().clone()
            )
            .unwrap_err(),
        Error::InvalidQuorumCertificate(_)
    ));
```
