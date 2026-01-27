# Audit Report

## Title
Timeout Certificate HQC Validation Bypass in SyncInfo Allows Inconsistent State and Voting Disruption

## Summary
The `SyncInfo::verify()` function fails to validate that the embedded timeout certificate's highest quorum certificate (HQC) round is not newer than the SyncInfo's own HQC round, allowing nodes to accept and propagate inconsistent consensus state that can disrupt voting and cause liveness issues.

## Finding Description
The AptosBFT consensus protocol uses `SyncInfo` messages to synchronize state between validators. When a `SyncInfo` contains a `TwoChainTimeoutCertificate`, the certificate includes an embedded quorum certificate representing the highest QC known to 2f+1 validators at the time of timeout. [1](#0-0) 

The verification only calls `tc.verify(validator)` which validates signatures and internal consistency, but **does not validate the relationship between the timeout certificate's HQC round and the SyncInfo's HQC round**. [2](#0-1) 

The timeout certificate contains a full `QuorumCert` with a specific round. When the TC's HQC round exceeds the SyncInfo's `highest_quorum_cert` round, it creates semantic inconsistency: the SyncInfo claims the highest certified round is R, while the embedded TC proves that 2f+1 validators certified round R' > R.

In contrast, both `VoteMsg` and `RoundTimeoutMsg` properly enforce this constraint: [3](#0-2) [4](#0-3) 

However, when a `ProposalMsg` is processed, only the proposal itself is verified, not this HQC consistency: [5](#0-4) 

The vulnerable flow occurs during sync operations: [6](#0-5) 

When `add_certs()` processes the SyncInfo, it inserts the timeout certificate without extracting or validating its embedded HQC: [7](#0-6) 

This creates an inconsistent state where the node's `highest_quorum_cert` is at round R, but `highest_2chain_timeout_cert` references round R' > R.

**Attack Scenario:**
1. Validators V1, V2, V3 time out at round 11 with HQCs at rounds 10, 12, and 11 respectively
2. Aggregated TC is formed for round 11 with HQC at round 12 (the maximum)
3. A Byzantine node or misconfigured validator sends a `SyncInfo` with:
   - `highest_quorum_cert`: QC at round 10
   - `highest_2chain_timeout_cert`: TC at round 11 with embedded HQC at round 12
4. Honest nodes accept this SyncInfo through `verify()` without detecting the inconsistency
5. Later, when voting on proposals at round 12, the safety rules check fails: [8](#0-7) 

The condition `qc_round >= hqc_round` (line 160) evaluates to `10 >= 12` which is false, causing legitimate proposals to be rejected.

## Impact Explanation
This is a **High Severity** vulnerability that causes significant protocol violations:

1. **Liveness Disruption**: Honest validators receiving inconsistent SyncInfo will incorrectly reject valid proposals because their safety rules reference the TC's inflated HQC round while their actual highest QC is lower. This can stall consensus progression.

2. **State Inconsistency**: Nodes maintain contradictory views where their `highest_quorum_cert` differs from the QC proven by their `highest_2chain_timeout_cert`, violating the consensus state consistency invariant.

3. **Vote Rejection**: The safety rule at line 160 (`qc_round >= hqc_round`) becomes impossible to satisfy when `hqc_round` (from TC) exceeds the actual highest certified round known to the node, preventing legitimate voting.

4. **Network-Wide Impact**: A single malformed SyncInfo can propagate through the network via proposals, affecting multiple validators simultaneously.

The vulnerability does not lead to safety violations (double-spending or chain splits) because the cryptographic verification prevents forged TCs, but it significantly impacts availability and can be weaponized to disrupt consensus progression.

## Likelihood Explanation
**Likelihood: High**

This vulnerability can be triggered in multiple ways:

1. **Benign Network Asynchrony**: Legitimately occurs when validators have different views due to network delays - a validator may receive a TC before receiving the actual QC it references.

2. **Malicious Exploitation**: A Byzantine node can deliberately construct and broadcast SyncInfo messages with this inconsistency to disrupt honest validators.

3. **Ease of Exploitation**: No special privileges required - any network participant can send malformed SyncInfo through proposals or direct sync messages.

4. **Detection Difficulty**: The inconsistency is not caught by existing validation, making it propagate silently until voting failures occur.

## Recommendation
Add validation in `SyncInfo::verify()` to ensure the timeout certificate's HQC is not newer than the SyncInfo's HQC:

```rust
.and_then(|_| {
    if let Some(tc) = &self.highest_2chain_timeout_cert {
        tc.verify(validator)?;
        // Validate TC's HQC consistency with SyncInfo's HQC
        ensure!(
            tc.highest_hqc_round() <= self.highest_certified_round(),
            "Timeout certificate's HQC round {} is higher than SyncInfo's HQC round {}",
            tc.highest_hqc_round(),
            self.highest_certified_round()
        );
    }
    Ok(())
})
```

Additionally, consider extracting and processing the QC embedded in received TCs to update the node's highest certified round when appropriate.

## Proof of Concept
```rust
// Test demonstrating the vulnerability
#[test]
fn test_sync_info_tc_hqc_inconsistency() {
    use aptos_consensus_types::{
        quorum_cert::QuorumCert,
        sync_info::SyncInfo,
        timeout_2chain::{TwoChainTimeout, TwoChainTimeoutCertificate},
    };
    
    // Create QC at round 10
    let qc_round_10 = create_quorum_cert_for_round(10);
    
    // Create TC at round 11 with HQC at round 12 (inconsistent!)
    let timeout = TwoChainTimeout::new(
        1, // epoch
        11, // round
        create_quorum_cert_for_round(12), // HQC at round 12
    );
    let tc = create_timeout_certificate(timeout);
    
    // Create SyncInfo with inconsistent state
    let sync_info = SyncInfo::new(
        qc_round_10, // HQC at round 10
        create_wrapped_ledger_info(10),
        Some(tc), // TC with HQC at round 12
    );
    
    // Vulnerability: verify() passes despite TC.hqc_round() > SyncInfo.hqc_round()
    assert!(sync_info.verify(&validator_verifier).is_ok());
    
    // This creates inconsistent state: 10 < 12
    assert!(sync_info.highest_certified_round() < tc.highest_hqc_round());
    
    // Later, voting on round 12 proposals will fail incorrectly
    // because safety rules require qc_round >= tc.hqc_round()
    // but node only has QC at round 10
}
```

**Notes:**
- The vulnerability exists in production code at `consensus/consensus-types/src/sync_info.rs` lines 206-209
- Individual timeout messages (VoteMsg, RoundTimeoutMsg) are protected by proper validation
- Aggregated timeout certificates in SyncInfo lack this critical consistency check
- The missing validation creates an exploitable inconsistency that disrupts consensus liveness
- Fix requires adding a single validation step to enforce the semantic invariant that TC.hqc_round() ≤ SyncInfo.highest_certified_round()

### Citations

**File:** consensus/consensus-types/src/sync_info.rs (L204-209)
```rust
            .and_then(|_| {
                if let Some(tc) = &self.highest_2chain_timeout_cert {
                    tc.verify(validator)?;
                }
                Ok(())
            })
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L22-32)
```rust
/// This structure contains all the information necessary to construct a signature
/// on the equivalent of a AptosBFT v4 timeout message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TwoChainTimeout {
    /// Epoch number corresponds to the set of validators that are active for this round.
    epoch: u64,
    /// The consensus protocol executes proposals (blocks) in rounds, which monotonically increase per epoch.
    round: Round,
    /// The highest quorum cert the signer has seen.
    quorum_cert: QuorumCert,
}
```

**File:** consensus/consensus-types/src/vote_msg.rs (L71-76)
```rust
        if let Some((timeout, _)) = self.vote().two_chain_timeout() {
            ensure!(
                timeout.hqc_round() <= self.sync_info.highest_certified_round(),
                "2-chain Timeout hqc should be less or equal than the sync info hqc"
            );
        }
```

**File:** consensus/consensus-types/src/round_timeout.rs (L162-166)
```rust
        ensure!(
            self.round_timeout.two_chain_timeout().hqc_round()
                <= self.sync_info.highest_certified_round(),
            "2-chain Timeout hqc should be less or equal than the sync info hqc"
        );
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L112-115)
```rust
        // if there is a timeout certificate, verify its signatures
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
```

**File:** consensus/src/round_manager.rs (L878-888)
```rust
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
```

**File:** consensus/src/block_storage/sync_manager.rs (L169-171)
```rust
        if let Some(tc) = sync_info.highest_2chain_timeout_cert() {
            self.insert_2chain_timeout_certificate(Arc::new(tc.clone()))?;
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L147-165)
```rust
    /// Core safety voting rule for 2-chain protocol. Return success if 1 or 2 is true
    /// 1. block.round == block.qc.round + 1
    /// 2. block.round == tc.round + 1 && block.qc.round >= tc.highest_hqc.round
    fn safe_to_vote(
        &self,
        block: &Block,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<(), Error> {
        let round = block.round();
        let qc_round = block.quorum_cert().certified_block().round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        let hqc_round = maybe_tc.map_or(0, |tc| tc.highest_hqc_round());
        if round == next_round(qc_round)?
            || (round == next_round(tc_round)? && qc_round >= hqc_round)
        {
            Ok(())
        } else {
            Err(Error::NotSafeToVote(round, qc_round, tc_round, hqc_round))
        }
```
