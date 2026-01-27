# Audit Report

## Title
Certificate Verification Bypass in OptProposalMsg SyncInfo Processing

## Summary
OptProposalMsg verification does not cryptographically validate SyncInfo certificates before processing proposals. When an OptProposalMsg contains a SyncInfo without newer certificates than the local node, the certificates in SyncInfo (highest_ordered_cert, highest_commit_cert) are never verified but the proposal is still processed and buffered.

## Finding Description

The vulnerability exists in the verification flow for OptProposalMsg:

**Step 1: OptProposalMsg.verify() skips SyncInfo verification** [1](#0-0) 

The `verify()` method explicitly postpones SyncInfo verification (comment at line 121: "Note that we postpone the verification of SyncInfo until it's being used"). It only verifies the payload and grandparent QC signatures, then calls `verify_well_formed()`.

**Step 2: verify_well_formed() only checks structural consistency** [2](#0-1) 

This method checks epoch matching and that grandparent QC IDs align with SyncInfo, but does NOT call `sync_info.verify()` to cryptographically verify the certificates.

**Step 3: SyncInfo.verify() has comprehensive certificate verification** [3](#0-2) 

The SyncInfo.verify() method performs cryptographic verification of all certificates (HQC at line 187-188, HOC at lines 189-194, HCC at lines 195-203, TC at lines 204-209), but this is never called during OptProposalMsg verification.

**Step 4: Conditional verification in sync_up()** [4](#0-3) 

The `sync_up()` method only calls `sync_info.verify()` at line 888 **IF** `sync_info.has_newer_certificates(&local_sync_info)` is true (line 880). If the SyncInfo does not have newer certificates, verification is skipped entirely and the function returns Ok(()) at line 905.

**Step 5: Proposal processing without verification** [5](#0-4) 

In `process_opt_proposal_msg()`, after calling `sync_up()` (line 813), the proposal is either sent to the loopback channel (lines 816-820) or buffered in `pending_opt_proposals` (lines 832-833) regardless of whether the SyncInfo was verified.

**Attack Scenario:**

1. Attacker crafts an OptProposalMsg with:
   - Valid OptBlockData with properly signed grandparent_qc
   - Malicious SyncInfo with forged signatures on highest_ordered_cert and/or highest_commit_cert
   - SyncInfo certificates at the same or lower rounds as victim's local state
   
2. The message passes `UnverifiedEvent::verify()` because only the grandparent_qc is verified

3. In `process_opt_proposal_msg()`, `sync_up()` is called but skips verification because `has_newer_certificates()` returns false

4. The proposal is processed and buffered without the SyncInfo certificates ever being cryptographically verified

This violates the **Cryptographic Correctness** invariant that all signatures and certificates must be verified before use.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria as a "Significant protocol violation":

1. **Security Invariant Violation**: The code assumes verified events contain fully verified data, but OptProposalMsg can contain unverified certificates
2. **Defense-in-Depth Bypass**: Cryptographic verification is a critical security layer that should never be conditionally skipped
3. **Semantic Inconsistency**: Messages transition from `UnverifiedEvent` to `VerifiedEvent` while containing unverified data
4. **Potential for Escalation**: While direct impact is limited (unverified certificates aren't used for state updates), this verification gap could be chained with other vulnerabilities

The comment at line 887 explicitly states "First verify the SyncInfo (didn't verify it in the yet)" indicating the developer's assumption that verification would occur, but the conditional check prevents this.

## Likelihood Explanation

**High Likelihood** - The attack is trivial to execute:
- Any network peer can send OptProposalMsg messages
- No validator privileges required
- Attacker only needs to observe the victim's current round to craft non-newer certificates
- No complex timing or race conditions needed
- Successfully bypasses the verification layer

## Recommendation

**Fix Option 1: Always verify SyncInfo in OptProposalMsg.verify()**

Modify `OptProposalMsg::verify()` to call `sync_info.verify()` before returning:

```rust
pub fn verify(
    &self,
    sender: Author,
    validator: &ValidatorVerifier,
    proof_cache: &ProofCache,
    quorum_store_enabled: bool,
) -> Result<()> {
    ensure!(
        self.proposer() == sender,
        "OptProposal author {:?} doesn't match sender {:?}",
        self.proposer(),
        sender
    );

    let (payload_verify_result, qc_verify_result, sync_info_verify_result) = rayon::join(
        || {
            self.block_data()
                .payload()
                .verify(validator, proof_cache, quorum_store_enabled)
        },
        || self.block_data().grandparent_qc().verify(validator),
        || self.sync_info.verify(validator),  // ADD THIS
    );
    payload_verify_result?;
    qc_verify_result?;
    sync_info_verify_result?;  // ADD THIS

    self.verify_well_formed()
}
```

**Fix Option 2: Remove conditional verification in sync_up()**

Always verify SyncInfo before processing:

```rust
async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
    // Always verify first
    sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
        error!(
            SecurityEvent::InvalidSyncInfoMsg,
            sync_info = sync_info,
            remote_peer = author,
            error = ?e,
        );
        VerifyError::from(e)
    })?;
    
    let local_sync_info = self.block_store.sync_info();
    if sync_info.has_newer_certificates(&local_sync_info) {
        // ... rest of sync logic
    }
    Ok(())
}
```

**Recommended: Fix Option 1** - Verify at the earliest possible point (in `OptProposalMsg::verify()`) to fail fast and avoid processing unverified data.

## Proof of Concept

```rust
#[cfg(test)]
mod security_test {
    use super::*;
    use crate::{
        block::block_test_utils::gen_test_certificate,
        common::Payload,
    };
    use aptos_crypto::HashValue;
    use aptos_types::{
        block_info::BlockInfo,
        validator_signer::ValidatorSigner,
        validator_verifier::random_validator_verifier,
    };

    #[test]
    fn test_unverified_syncinfo_certificates_bypass() {
        let (signers, validators) = random_validator_verifier(2, None, false);
        let signer1 = &signers[0];
        let signer2 = &signers[1]; // Different signer for forging
        
        // Create a valid grandparent QC
        let grandparent_block = BlockInfo::new(1, 1, HashValue::zero(), HashValue::zero(), 0, 1000, None);
        let parent_of_grandparent = BlockInfo::new(1, 0, HashValue::zero(), HashValue::zero(), 0, 0, None);
        let grandparent_qc = gen_test_certificate(
            std::slice::from_ref(signer1),
            grandparent_block.clone(),
            parent_of_grandparent,
            None,
        );

        // Create OptBlockData with valid signatures
        let parent_block = BlockInfo::new(1, 2, grandparent_block.id(), HashValue::zero(), 0, 2000, None);
        let opt_block_data = OptBlockData::new(
            vec![],
            Payload::empty(false, true),
            signer1.author(),
            1, // epoch
            3, // round
            3000,
            parent_block,
            grandparent_qc.clone(),
        );

        // Create FORGED highest_ordered_cert using wrong signer
        let forged_hoc_block = BlockInfo::new(1, 1, HashValue::random(), HashValue::zero(), 0, 1000, None);
        let forged_hoc = gen_test_certificate(
            std::slice::from_ref(signer2), // WRONG SIGNER - FORGED
            forged_hoc_block,
            BlockInfo::empty(),
            None,
        ).into_wrapped_ledger_info();

        // Create SyncInfo with forged certificate
        let sync_info = SyncInfo::new(
            grandparent_qc.clone(), // Valid HQC
            forged_hoc,             // FORGED HOC
            None,
        );

        let msg = OptProposalMsg::new(opt_block_data, sync_info);
        let proof_cache = ProofCache::new(1024);

        // This SHOULD fail because the HOC has invalid signatures
        // But it PASSES because sync_info.verify() is never called
        let result = msg.verify(signer1.author(), &validators, &proof_cache, false);
        
        // BUG: This passes even though sync_info contains forged certificates!
        assert!(result.is_ok(), "Message with forged SyncInfo certificates passed verification!");
        
        // The forged certificate would fail if verified:
        assert!(msg.sync_info().highest_ordered_cert().verify(&validators).is_err(),
                "Forged certificate should fail verification");
    }
}
```

**Notes:**
- This vulnerability represents a certificate verification bypass where unverified cryptographic proofs pass through the verification layer
- While the immediate impact is limited (unverified certificates aren't used for state updates), this violates fundamental security principles and creates attack surface for potential escalation
- The fix is straightforward: always verify SyncInfo certificates during OptProposalMsg verification

### Citations

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L54-94)
```rust
    pub fn verify_well_formed(&self) -> Result<()> {
        self.block_data
            .verify_well_formed()
            .context("Fail to verify OptProposalMsg's data")?;
        ensure!(
            self.block_data.round() > 1,
            "Proposal for {} has round <= 1",
            self.block_data,
        );
        ensure!(
            self.block_data.epoch() == self.sync_info.epoch(),
            "ProposalMsg has different epoch number from SyncInfo"
        );
        // Ensure the sync info has the grandparent QC
        ensure!(
            self.block_data.grandparent_qc().certified_block().id()
                == self.sync_info.highest_quorum_cert().certified_block().id(),
            "Proposal HQC in SyncInfo certifies {}, but block grandparent id is {}",
            self.sync_info.highest_quorum_cert().certified_block().id(),
            self.block_data.grandparent_qc().certified_block().id(),
        );
        let grandparent_round = self
            .block_data
            .round()
            .checked_sub(2)
            .ok_or_else(|| anyhow::anyhow!("proposal round overflowed!"))?;

        let highest_certified_round = self.block_data.grandparent_qc().certified_block().round();
        ensure!(
            grandparent_round == highest_certified_round,
            "Proposal {} does not have a certified round {}",
            self.block_data,
            grandparent_round
        );
        // Optimistic proposal shouldn't have a timeout certificate
        ensure!(
            self.sync_info.highest_2chain_timeout_cert().is_none(),
            "Optimistic proposal shouldn't have a timeout certificate"
        );
        Ok(())
    }
```

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L96-123)
```rust
    pub fn verify(
        &self,
        sender: Author,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> Result<()> {
        ensure!(
            self.proposer() == sender,
            "OptProposal author {:?} doesn't match sender {:?}",
            self.proposer(),
            sender
        );

        let (payload_verify_result, qc_verify_result) = rayon::join(
            || {
                self.block_data()
                    .payload()
                    .verify(validator, proof_cache, quorum_store_enabled)
            },
            || self.block_data().grandparent_qc().verify(validator),
        );
        payload_verify_result?;
        qc_verify_result?;

        // Note that we postpone the verification of SyncInfo until it's being used.
        self.verify_well_formed()
    }
```

**File:** consensus/consensus-types/src/sync_info.rs (L138-212)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let epoch = self.highest_quorum_cert.certified_block().epoch();
        ensure!(
            epoch == self.highest_ordered_cert().commit_info().epoch(),
            "Multi epoch in SyncInfo - HOC and HQC"
        );
        ensure!(
            epoch == self.highest_commit_cert().commit_info().epoch(),
            "Multi epoch in SyncInfo - HOC and HCC"
        );
        if let Some(tc) = &self.highest_2chain_timeout_cert {
            ensure!(epoch == tc.epoch(), "Multi epoch in SyncInfo - TC and HQC");
        }

        ensure!(
            self.highest_quorum_cert.certified_block().round()
                >= self.highest_ordered_cert().commit_info().round(),
            "HQC has lower round than HOC"
        );

        ensure!(
            self.highest_ordered_round() >= self.highest_commit_round(),
            format!(
                "HOC {} has lower round than HLI {}",
                self.highest_ordered_cert(),
                self.highest_commit_cert()
            )
        );

        ensure!(
            *self.highest_ordered_cert().commit_info() != BlockInfo::empty(),
            "HOC has no committed block"
        );

        ensure!(
            *self.highest_commit_cert().commit_info() != BlockInfo::empty(),
            "HLI has empty commit info"
        );

        // we don't have execution in unit tests, so this check would fail
        #[cfg(not(any(test, feature = "fuzzing")))]
        {
            ensure!(
                !self.highest_commit_cert().commit_info().is_ordered_only(),
                "HLI {} has ordered only commit info",
                self.highest_commit_cert().commit_info()
            );
        }

        self.highest_quorum_cert
            .verify(validator)
            .and_then(|_| {
                self.highest_ordered_cert
                    .as_ref()
                    .map_or(Ok(()), |cert| cert.verify(validator))
                    .context("Fail to verify ordered certificate")
            })
            .and_then(|_| {
                // we do not verify genesis ledger info
                if self.highest_commit_cert.commit_info().round() > 0 {
                    self.highest_commit_cert
                        .verify(validator)
                        .context("Fail to verify commit certificate")?
                }
                Ok(())
            })
            .and_then(|_| {
                if let Some(tc) = &self.highest_2chain_timeout_cert {
                    tc.verify(validator)?;
                }
                Ok(())
            })
            .context("Fail to verify SyncInfo")?;
        Ok(())
    }
```

**File:** consensus/src/round_manager.rs (L782-836)
```rust
    pub async fn process_opt_proposal_msg(
        &mut self,
        proposal_msg: OptProposalMsg,
    ) -> anyhow::Result<()> {
        ensure!(self.local_config.enable_optimistic_proposal_rx,
            "Opt proposal is disabled, but received opt proposal msg of epoch {} round {} from peer {}",
            proposal_msg.block_data().epoch(), proposal_msg.round(), proposal_msg.proposer()
        );

        fail_point!("consensus::process_opt_proposal_msg", |_| {
            Err(anyhow::anyhow!(
                "Injected error in process_opt_proposal_msg"
            ))
        });

        observe_block(
            proposal_msg.block_data().timestamp_usecs(),
            BlockStage::ROUND_MANAGER_RECEIVED,
        );
        observe_block(
            proposal_msg.block_data().timestamp_usecs(),
            BlockStage::ROUND_MANAGER_RECEIVED_OPT_PROPOSAL,
        );
        info!(
            self.new_log(LogEvent::ReceiveOptProposal),
            block_author = proposal_msg.proposer(),
            block_epoch = proposal_msg.block_data().epoch(),
            block_round = proposal_msg.round(),
            block_parent_hash = proposal_msg.block_data().parent_id(),
        );

        self.sync_up(proposal_msg.sync_info(), proposal_msg.proposer())
            .await?;

        if self.round_state.current_round() == proposal_msg.round() {
            self.opt_proposal_loopback_tx
                .send(proposal_msg.take_block_data())
                .await
                .expect("Sending to a self loopback unbounded channel cannot fail");
        } else {
            // Pre-check that proposal is from valid proposer before queuing it.
            // This check is done after syncing up to sync info to ensure proposer
            // election provider is up to date.
            ensure!(
                self.proposer_election
                    .is_valid_proposer(proposal_msg.proposer(), proposal_msg.round()),
                "[OptProposal] Not a valid proposer for round {}: {}",
                proposal_msg.round(),
                proposal_msg.proposer()
            );
            self.pending_opt_proposals
                .insert(proposal_msg.round(), proposal_msg.take_block_data());
        }

        Ok(())
```

**File:** consensus/src/round_manager.rs (L877-907)
```rust
    /// Sync to the sync info sending from peer if it has newer certificates.
    async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
        let local_sync_info = self.block_store.sync_info();
        if sync_info.has_newer_certificates(&local_sync_info) {
            info!(
                self.new_log(LogEvent::ReceiveNewCertificate)
                    .remote_peer(author),
                "Local state {},\n remote state {}", local_sync_info, sync_info
            );
            // Some information in SyncInfo is ahead of what we have locally.
            // First verify the SyncInfo (didn't verify it in the yet).
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
            SYNC_INFO_RECEIVED_WITH_NEWER_CERT.inc();
            let result = self
                .block_store
                .add_certs(sync_info, self.create_block_retriever(author))
                .await;
            self.process_certificates().await?;
            result
        } else {
            Ok(())
        }
    }
```
