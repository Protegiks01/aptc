# Audit Report

## Title
Resource Exhaustion via Expensive Cryptographic Verification Before Structural Validation in Consensus Proposal Messages

## Summary
The `ProposalMsg::verify()` function performs expensive cryptographic operations (signature validation and payload verification) before executing cheap structural validation checks via `verify_well_formed()`. This ordering allows a Byzantine validator to craft malformed proposals that force honest validators to waste CPU cycles on cryptographic verification before failing basic structural checks. [1](#0-0) 

## Finding Description

The vulnerability exists in the verification flow of consensus proposal messages. When a validator receives a `ProposalMsg`, the `verify()` method is invoked with the following sequence:

1. **Author verification** (lines 89-96): Checks that the proposal author matches the sender
2. **Parallel cryptographic operations** (lines 97-110):
   - Payload verification: Validates ProofOfStore signatures for quorum store batches
   - Block signature validation: Verifies the proposer's signature and QuorumCert aggregate signatures
3. **Timeout certificate verification** (lines 113-115): Verifies timeout certificate signatures if present
4. **Structural validation** (line 117): Calls `verify_well_formed()` to check structural properties [2](#0-1) 

The `verify_well_formed()` method performs cheap structural checks including:
- Ensuring the proposal is not a NIL block
- Validating round progression (round > 0, correct increment from parent)
- Checking epoch consistency between proposal and sync_info
- Verifying parent_id matches the highest quorum cert
- Validating that the proposal has an author [3](#0-2) 

The cryptographic operations are computationally expensive:

**Block signature validation** performs parallel signature verification for the block signature and QuorumCert: [4](#0-3) 

**Payload verification** checks ProofOfStore signatures in parallel for potentially many batches: [5](#0-4) 

**QuorumCert verification** validates aggregate BLS signatures: [6](#0-5) 

### Attack Scenario

A Byzantine validator can exploit this by:

1. Crafting a proposal with structural violations that will fail `verify_well_formed()`:
   - Wrong epoch number between proposal and sync_info
   - Invalid round progression (round = 0, or incorrect increment)
   - Parent ID not matching the highest quorum cert
   - Proposing a NIL block

2. Including valid cryptographic signatures or valid-looking payload with multiple ProofOfStore batches

3. Broadcasting this malformed proposal to honest validators

4. Honest validators execute expensive cryptographic verifications first (BLS signature verification, aggregate signature checks, potentially verifying signatures for multiple batches)

5. Only after completing expensive crypto operations, the cheap structural checks fail

6. The Byzantine validator can amplify this attack by repeatedly sending such proposals

This breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This vulnerability falls under the **High Severity** category of "Validator node slowdowns" but is assessed as Medium because:

1. **Resource Exhaustion**: Byzantine validators can cause honest validators to waste CPU cycles on cryptographic verification for structurally invalid proposals
2. **Amplification**: The attack can be repeated, potentially causing significant CPU consumption during high-load periods
3. **Consensus Performance Degradation**: While this doesn't break consensus safety, it can slow down block processing and reduce overall network throughput
4. **Limited Scope**: The attack requires validator network access and is bounded by existing rate limiting mechanisms

The impact does NOT reach Critical or High severity because:
- No consensus safety violation (no double-spend, no chain splits)
- No permanent network partition or total liveness failure
- Existing network rate limiting and backpressure mechanisms provide partial mitigation
- Does not cause complete validator node failure [7](#0-6) 

## Likelihood Explanation

**Likelihood: Medium**

The attack is feasible but has practical constraints:

**Attack Requirements:**
1. Attacker must be a validator with network access (Byzantine validator within the < 1/3 Byzantine tolerance)
2. Consensus network uses mutual authentication, preventing external attackers [8](#0-7) 

**Mitigating Factors:**
- Network-level rate limiting exists but may not fully prevent resource exhaustion
- Backpressure mechanisms can slow down processing but don't prevent initial verification overhead
- Byzantine validators are expected in the threat model (protocol tolerates < 1/3 Byzantine)

**Enabling Factors:**
- Simple to implement: crafting structurally invalid but cryptographically valid proposals is straightforward
- Low cost to attacker: minimal resources needed to generate malformed proposals
- Repeatable: attack can be executed continuously

## Recommendation

**Fix: Reorder verification to perform cheap structural checks before expensive cryptographic operations**

Modify the `verify()` method to call `verify_well_formed()` immediately after the initial author check and before any cryptographic operations:

```rust
pub fn verify(
    &self,
    sender: Author,
    validator: &ValidatorVerifier,
    proof_cache: &ProofCache,
    quorum_store_enabled: bool,
) -> Result<()> {
    if let Some(proposal_author) = self.proposal.author() {
        ensure!(
            proposal_author == sender,
            "Proposal author {:?} doesn't match sender {:?}",
            proposal_author,
            sender
        );
    }
    
    // Perform cheap structural validation FIRST
    self.verify_well_formed()?;
    
    // Only if structurally valid, perform expensive crypto operations
    let (payload_result, sig_result) = rayon::join(
        || {
            self.proposal().payload().map_or(Ok(()), |p| {
                p.verify(validator, proof_cache, quorum_store_enabled)
            })
        },
        || {
            self.proposal()
                .validate_signature(validator)
                .map_err(|e| format_err!("{:?}", e))
        },
    );
    payload_result?;
    sig_result?;

    // if there is a timeout certificate, verify its signatures
    if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
        tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
    }
    
    Ok(())
}
```

This ensures that structurally invalid proposals are rejected immediately without consuming CPU cycles on signature verification.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::validator_verifier::random_validator_verifier;
    
    #[test]
    fn test_verify_ordering_resource_exhaustion() {
        // Setup: Create a validator verifier
        let (validator_signer, validator_verifier) = random_validator_verifier(4, None, false);
        let proof_cache = ProofCache::new(1000);
        
        // Create a proposal with STRUCTURAL invalidity:
        // - Wrong epoch between proposal and sync_info
        let mut proposal = create_valid_proposal(&validator_signer[0]);
        let mut sync_info = proposal.sync_info().clone();
        
        // Modify sync_info to have wrong epoch (structural error)
        sync_info.set_epoch(proposal.epoch() + 1); // Epoch mismatch
        
        let malformed_proposal = ProposalMsg::new(
            proposal.take_proposal(),
            sync_info,
        );
        
        // The proposal has valid signatures but fails structural checks
        // Current implementation: expensive crypto verification happens FIRST
        // Expected: Should fail fast on structural check
        
        let start = std::time::Instant::now();
        let result = malformed_proposal.verify(
            validator_signer[0].author(),
            &validator_verifier,
            &proof_cache,
            true,
        );
        let duration = start.elapsed();
        
        // Should fail due to epoch mismatch
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("epoch"));
        
        // With fix: duration should be minimal (< 1ms) for structural check
        // Without fix: duration includes expensive crypto verification
        println!("Verification failed after: {:?}", duration);
        
        // Demonstrate resource exhaustion by repeating
        for _ in 0..100 {
            let _ = malformed_proposal.verify(
                validator_signer[0].author(),
                &validator_verifier,
                &proof_cache,
                true,
            );
        }
    }
}
```

## Notes

While this vulnerability has limited practical impact due to network authentication requirements and existing rate limiting, it represents a suboptimal verification ordering that violates defensive programming principles. The fix is simple, has no downsides, and improves resilience against Byzantine validators operating within the protocol's threat model.

### Citations

**File:** consensus/consensus-types/src/proposal_msg.rs (L33-79)
```rust
    pub fn verify_well_formed(&self) -> Result<()> {
        ensure!(
            !self.proposal.is_nil_block(),
            "Proposal {} for a NIL block",
            self.proposal
        );
        self.proposal
            .verify_well_formed()
            .context("Fail to verify ProposalMsg's block")?;
        ensure!(
            self.proposal.round() > 0,
            "Proposal for {} has an incorrect round of 0",
            self.proposal,
        );
        ensure!(
            self.proposal.epoch() == self.sync_info.epoch(),
            "ProposalMsg has different epoch number from SyncInfo"
        );
        ensure!(
            self.proposal.parent_id()
                == self.sync_info.highest_quorum_cert().certified_block().id(),
            "Proposal HQC in SyncInfo certifies {}, but block parent id is {}",
            self.sync_info.highest_quorum_cert().certified_block().id(),
            self.proposal.parent_id(),
        );
        let previous_round = self
            .proposal
            .round()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("proposal round overflowed!"))?;

        let highest_certified_round = std::cmp::max(
            self.proposal.quorum_cert().certified_block().round(),
            self.sync_info.highest_timeout_round(),
        );
        ensure!(
            previous_round == highest_certified_round,
            "Proposal {} does not have a certified round {}",
            self.proposal,
            previous_round
        );
        ensure!(
            self.proposal.author().is_some(),
            "Proposal {} does not define an author",
            self.proposal
        );
        Ok(())
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L82-118)
```rust
    pub fn verify(
        &self,
        sender: Author,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> Result<()> {
        if let Some(proposal_author) = self.proposal.author() {
            ensure!(
                proposal_author == sender,
                "Proposal author {:?} doesn't match sender {:?}",
                proposal_author,
                sender
            );
        }
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
                })
            },
            || {
                self.proposal()
                    .validate_signature(validator)
                    .map_err(|e| format_err!("{:?}", e))
            },
        );
        payload_result?;
        sig_result?;

        // if there is a timeout certificate, verify its signatures
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
        // Note that we postpone the verification of SyncInfo until it's being used.
        self.verify_well_formed()
    }
```

**File:** consensus/consensus-types/src/block.rs (L425-464)
```rust
    pub fn validate_signature(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        match self.block_data.block_type() {
            BlockType::Genesis => bail!("We should not accept genesis from others"),
            BlockType::NilBlock { .. } => self.quorum_cert().verify(validator),
            BlockType::Proposal { author, .. } => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or_else(|| format_err!("Missing signature in Proposal"))?;
                let (res1, res2) = rayon::join(
                    || validator.verify(*author, &self.block_data, signature),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
            BlockType::ProposalExt(proposal_ext) => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or_else(|| format_err!("Missing signature in Proposal"))?;
                let (res1, res2) = rayon::join(
                    || validator.verify(*proposal_ext.author(), &self.block_data, signature),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
            BlockType::OptimisticProposal(p) => {
                // Note: Optimistic proposal is not signed by proposer unlike normal proposal
                let (res1, res2) = rayon::join(
                    || p.grandparent_qc().verify(validator),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
            BlockType::DAGBlock { .. } => bail!("We should not accept DAG block from others"),
        }
    }
```

**File:** consensus/consensus-types/src/common.rs (L517-539)
```rust
    fn verify_with_cache<T>(
        proofs: &[ProofOfStore<T>],
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
    ) -> anyhow::Result<()>
    where
        T: TBatchInfo + Send + Sync + 'static,
        BatchInfoExt: From<T>,
    {
        let unverified: Vec<_> = proofs
            .iter()
            .filter(|proof| {
                proof_cache
                    .get(&BatchInfoExt::from(proof.info().clone()))
                    .is_none_or(|cached_proof| cached_proof != *proof.multi_signature())
            })
            .collect();
        unverified
            .par_iter()
            .with_min_len(2)
            .try_for_each(|proof| proof.verify(validator, proof_cache))?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L119-148)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let vote_hash = self.vote_data.hash();
        ensure!(
            self.ledger_info().ledger_info().consensus_data_hash() == vote_hash,
            "Quorum Cert's hash mismatch LedgerInfo"
        );
        // Genesis's QC is implicitly agreed upon, it doesn't have real signatures.
        // If someone sends us a QC on a fake genesis, it'll fail to insert into BlockStore
        // because of the round constraint.
        if self.certified_block().round() == 0 {
            ensure!(
                self.parent_block() == self.certified_block(),
                "Genesis QC has inconsistent parent block with certified block"
            );
            ensure!(
                self.certified_block() == self.ledger_info().ledger_info().commit_info(),
                "Genesis QC has inconsistent commit block with certified block"
            );
            ensure!(
                self.ledger_info().get_num_voters() == 0,
                "Genesis QC should not carry signatures"
            );
            return Ok(());
        }
        self.ledger_info()
            .verify_signatures(validator)
            .context("Fail to verify QuorumCert")?;
        self.vote_data.verify()?;
        Ok(())
    }
```

**File:** consensus/src/round_manager.rs (L108-131)
```rust
    pub fn verify(
        self,
        peer_id: PeerId,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
        self_message: bool,
        max_num_batches: usize,
        max_batch_expiry_gap_usecs: u64,
    ) -> Result<VerifiedEvent, VerifyError> {
        let start_time = Instant::now();
        Ok(match self {
            UnverifiedEvent::ProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proposal"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProposalMsg(p)
            },
            UnverifiedEvent::OptProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
```

**File:** network/framework/src/noise/handshake.rs (L813-900)
```rust
    #[test]
    fn test_handshake_peer_roles_pfn_dials_vfn() {
        // Initialize the logger
        ::aptos_logger::Logger::init_for_testing();

        // Create a peers and metadata struct
        let network_ids = vec![NetworkId::Vfn, NetworkId::Public];
        let peers_and_metadata = PeersAndMetadata::new(&network_ids);

        // Create a client and server with mutual auth disabled
        let ((mut client, _), (mut server, server_public_key)) =
            build_peers(false, Some(peers_and_metadata.clone()));

        // Update the client network context
        let client_peer_id = client.network_context.peer_id();
        let client_network_context =
            NetworkContext::new(RoleType::FullNode, NetworkId::Public, client_peer_id);
        client.network_context = client_network_context;

        // Update the server network context
        let server_peer_id = server.network_context.peer_id();
        let server_network_context =
            NetworkContext::new(RoleType::FullNode, NetworkId::Public, server_peer_id);
        server.network_context = server_network_context;

        // Add the VFN to the trusted peers set
        let server_peer = (
            server_peer_id,
            Peer::new(
                vec![],
                [server_public_key].into_iter().collect(),
                PeerRole::ValidatorFullNode,
            ),
        );
        insert_new_trusted_peers(&peers_and_metadata, NetworkId::Public, vec![server_peer]);

        // Create an in-memory socket for testing
        let (dialer_socket, listener_socket) = MemorySocket::new_pair();

        // Create the client connection task
        let client_connection_task = async move {
            let (_, peer_role) = client
                .upgrade_outbound(
                    dialer_socket,
                    server_peer_id,
                    server_public_key,
                    AntiReplayTimestamps::now,
                )
                .await
                .unwrap();
            assert_eq!(peer_role, PeerRole::ValidatorFullNode);
        };

        // Create the server connection task
        let server_connection_task = async move {
            let (_, peer_id, peer_role) = server.upgrade_inbound(listener_socket).await.unwrap();
            assert_eq!(peer_id, client_peer_id);
            assert_eq!(peer_role, PeerRole::Unknown);
        };

        // Perform the handshake
        block_on(join(client_connection_task, server_connection_task));
    }

    #[test]
    fn test_handshake_peer_roles_validator_dials_validator() {
        // Initialize the logger
        ::aptos_logger::Logger::init_for_testing();

        // Create a client and server with mutual auth enabled
        let ((client, _), (server, server_public_key)) = build_peers(true, None);
        let server_peer_id = server.network_context.peer_id();

        // Create an in-memory socket for testing
        let (dialer_socket, listener_socket) = MemorySocket::new_pair();

        // Create the client connection task
        let client_peer_id = client.network_context.peer_id();
        let client_connection_task = async move {
            let (_, peer_role) = client
                .upgrade_outbound(
                    dialer_socket,
                    server_peer_id,
                    server_public_key,
                    AntiReplayTimestamps::now,
                )
                .await
                .unwrap();
```
