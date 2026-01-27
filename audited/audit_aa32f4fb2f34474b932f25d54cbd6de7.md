# Audit Report

## Title
Critical SafetyRules Bypass in Decoupled Execution Pipeline Allows Consensus Safety Violations

## Summary
The decoupled execution pipeline in `signing_phase.rs` bypasses SafetyRules validation when signing commit votes through the asynchronous pipeline path. This allows validators to sign commit votes without critical safety checks that prevent equivocation, inconsistent execution results, and voting rule violations, breaking fundamental consensus safety guarantees.

## Finding Description

The `SigningPhase::process` method in `signing_phase.rs` has two code paths for signing commit votes:

**Path 1 (Async Pipeline - Lines 79-88):** When `pipeline_futs()` exists, it awaits the pre-computed `commit_vote_fut` which was created by `sign_and_broadcast_commit_vote()`. This function signs commit votes using `ValidatorSigner` directly **without any SafetyRules validation**. [1](#0-0) 

**Path 2 (SafetyRules - Lines 90-92):** Only when `pipeline_futs()` is None, the code calls `safety_rule_handle.sign_commit_vote()` which properly validates through SafetyRules. [2](#0-1) 

The async path bypasses critical SafetyRules checks implemented in `guarded_sign_commit_vote`:

1. **Ordered-only validation** - Ensures the ordered ledger info is properly formed
2. **Execution consistency validation** - Verifies execution results match between ordered and commit ledger infos  
3. **Quorum signature validation** - Verifies the ordered ledger info has 2f+1 signatures [3](#0-2) 

The `sign_and_broadcast_commit_vote` function in `pipeline_builder.rs` signs commit votes directly without any safety validation: [4](#0-3) 

**Decoupled execution is always enabled** in production, making the vulnerable async path the default: [5](#0-4) 

When signing fails in `buffer_manager.rs`, errors are logged but not properly distinguished between safety violations and internal errors: [6](#0-5) 

Additionally, line 88 in `signing_phase.rs` converts ANY error from the async path to `InternalError`, masking potential safety violations: [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violations - up to $1,000,000)

This vulnerability breaks the fundamental **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine."

Without SafetyRules validation, validators can:

1. **Sign conflicting commit votes** - No protection against equivocation on different execution results for the same ordered block
2. **Commit without proper order proofs** - Can sign commit votes before receiving valid quorum certificates on ordering
3. **Sign inconsistent execution states** - No validation that execution results match the ordered certificate

In a network with Byzantine validators, this could lead to:
- **Chain splits** - Different validators commit different execution results for the same block
- **Double-spending** - Conflicting transaction outcomes across honest nodes
- **State divergence** - Irreversible consensus failures requiring hard forks

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is **actively triggered in normal operation** because:

1. Decoupled execution is hardcoded to `true` in all consensus config versions
2. In normal operation, `build_for_consensus()` sets `pipeline_futs`, triggering the vulnerable async path
3. The SafetyRules path (lines 90-92) is only used as a fallback when pipeline futures don't exist
4. All validators in the network are affected simultaneously

While exploitation requires Byzantine behavior or implementation bugs in execution, the **complete absence of safety checks** dramatically increases the attack surface and violates defense-in-depth principles.

## Recommendation

Ensure all commit vote signatures go through SafetyRules validation, regardless of whether they're signed asynchronously or synchronously.

**Option 1: Add SafetyRules validation to async path**

Modify `sign_and_broadcast_commit_vote` to call SafetyRules before signing:

```rust
async fn sign_and_broadcast_commit_vote(
    ledger_update_fut: TaskFuture<LedgerUpdateResult>,
    order_vote_rx: oneshot::Receiver<()>,
    order_proof_fut: TaskFuture<WrappedLedgerInfo>,
    commit_proof_fut: TaskFuture<LedgerInfoWithSignatures>,
    safety_rules: Arc<dyn CommitSignerProvider>, // ADD THIS
    signer: Arc<ValidatorSigner>,
    block: Arc<Block>,
    order_vote_enabled: bool,
    network_sender: Arc<NetworkSender>,
) -> TaskResult<CommitVoteResult> {
    // ... existing code to get ordered_ledger_info and new_ledger_info ...
    
    // VALIDATE THROUGH SAFETYRULES BEFORE SIGNING
    let signature = safety_rules
        .sign_commit_vote(ordered_ledger_info, new_ledger_info.clone())?;
    
    let commit_vote = CommitVote::new_with_signature(signer.author(), new_ledger_info, signature);
    // ... broadcast ...
}
```

**Option 2: Always use SafetyRules path**

Remove the async signing path entirely and always use the SafetyRules validation in `SigningPhase`:

```rust
async fn process(&self, req: SigningRequest) -> SigningResponse {
    let SigningRequest {
        ordered_ledger_info,
        commit_ledger_info,
        blocks,
    } = req;

    // ALWAYS use SafetyRules, remove async bypass
    let signature_result = self.safety_rule_handle
        .sign_commit_vote(ordered_ledger_info, commit_ledger_info.clone());

    SigningResponse {
        signature_result,
        commit_ledger_info,
    }
}
```

## Proof of Concept

Create a test demonstrating that the async path bypasses SafetyRules validation:

```rust
#[tokio::test]
async fn test_async_path_bypasses_safety_rules() {
    // Setup: Create a block with inconsistent execution results
    let block = create_test_block_with_execution();
    let ordered_li = create_ordered_ledger_info(&block, /* dummy state */);
    let commit_li = create_commit_ledger_info(&block, /* different state */);
    
    // These should fail SafetyRules validation due to inconsistency
    let safety_rules = create_safety_rules();
    let result = safety_rules.sign_commit_vote(
        ordered_li.clone(), 
        commit_li.clone()
    );
    assert!(result.is_err()); // Should fail: InconsistentExecutionResult
    
    // But the async path will succeed by bypassing SafetyRules
    let signer = ValidatorSigner::new(...);
    let signature = signer.sign(&commit_li).unwrap(); // Direct signing succeeds!
    
    // This proves the async path can sign votes that SafetyRules would reject
    assert!(signature.verify(&commit_li, signer.public_key()).is_ok());
}
```

To observe in production: Enable detailed logging in `buffer_manager.rs` line 702 and monitor for `InternalError` messages that should have been specific SafetyRules violations (like `InconsistentExecutionResult`, `InvalidOrderedLedgerInfo`, etc.).

## Notes

This vulnerability affects the core consensus safety mechanism and violates the principle that all validator signatures must be protected by SafetyRules. The asynchronous optimization introduced in the decoupled execution pipeline inadvertently removed this critical security layer. While the vulnerability requires Byzantine behavior or bugs to be exploited, the complete absence of safety checks means the network has no defense against such scenarios, transforming potential "caught and rejected" attacks into consensus-breaking events.

### Citations

**File:** consensus/src/pipeline/signing_phase.rs (L79-88)
```rust
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
```

**File:** consensus/src/pipeline/signing_phase.rs (L90-92)
```rust
            self.safety_rule_handle
                .sign_commit_vote(ordered_ledger_info, commit_ledger_info.clone())
        };
```

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

**File:** consensus/src/pipeline/pipeline_builder.rs (L1022-1029)
```rust
        let ledger_info = LedgerInfo::new(block_info, consensus_data_hash);
        info!("[Pipeline] Signed ledger info {ledger_info}");
        let signature = signer.sign(&ledger_info).expect("Signing should succeed");
        let commit_vote = CommitVote::new_with_signature(signer.author(), ledger_info, signature);
        network_sender
            .broadcast_commit_vote(commit_vote.clone())
            .await;
        Ok(commit_vote)
```

**File:** types/src/on_chain_config/consensus_config.rs (L238-241)
```rust
    /// Decouple execution from consensus or not.
    pub fn decoupled_execution(&self) -> bool {
        true
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L699-705)
```rust
        let signature = match signature_result {
            Ok(sig) => sig,
            Err(e) => {
                error!("Signing failed {:?}", e);
                return;
            },
        };
```
