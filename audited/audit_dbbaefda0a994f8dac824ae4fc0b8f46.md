# Audit Report

## Title
ProposalExt Allows Unverified ObservedJWKUpdate Transactions at Consensus Time

## Summary
The `ProposalExt` extension mechanism fails to cryptographically verify `ObservedJWKUpdate` validator transactions during consensus validation, allowing malicious proposers to include arbitrary fake JWK updates that consume validator transaction slots and execution resources before being rejected during VM execution.

## Finding Description

The ProposalExt mechanism is designed to include validator transactions (DKG results and JWK updates) alongside regular user transactions in consensus blocks. However, a critical asymmetry exists in how different validator transaction types are verified during consensus. [1](#0-0) 

The `verify()` method for `ValidatorTransaction::ObservedJWKUpdate` returns `Ok(())` without performing any cryptographic validation, while `DKGResult` transactions undergo full verification. This deferred validation approach creates an exploitable gap.

During proposal processing, the consensus layer validates validator transactions: [2](#0-1) 

For `ObservedJWKUpdate` transactions, this validation passes trivially since `vtxn.verify()` returns `Ok()` without checking signatures, voting power, or version correctness.

The actual verification only occurs during VM execution: [3](#0-2) 

When validation fails during execution, the transaction is discarded with an ABORTED status: [4](#0-3) 

**Attack Path:**
1. Malicious proposer crafts a `ProposalExt` block with fabricated `ObservedJWKUpdate` transactions containing invalid multi-signatures or incorrect data
2. The proposer signs the `BlockData` (which includes these fake validator transactions)
3. Other validators receive and validate the proposal during consensus
4. The fake `ObservedJWKUpdate` passes all consensus-time checks because `verify()` returns `Ok()`
5. Count/byte limits are checked, allowing up to 2 validator transactions per block (default limit)
6. The block is accepted into consensus and committed to the blockchain
7. During execution, each fake transaction fails multi-signature verification and is discarded
8. The malicious proposer can repeat this attack every time they are the leader [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** based on the Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Every validator must execute the fake transactions, perform cryptographic multi-signature verification, and handle the abort logic, consuming CPU cycles and memory on all nodes in the network.

2. **Significant Protocol Violations**: The consensus layer accepts blocks containing transactions that are guaranteed to fail execution, violating the principle that consensus should only commit valid, executable state transitions.

3. **Denial of Service on Validator Transactions**: With a per-block limit of 2 validator transactions, a malicious proposer can fill both slots with fake `ObservedJWKUpdate` transactions, preventing legitimate DKG results or JWK updates from being included. This can delay critical validator operations like:
   - Distributed Key Generation for randomness
   - JSON Web Key updates for keyless account authentication

4. **Resource Exhaustion**: Repeated exploitation across multiple rounds where the malicious validator is the proposer can cause sustained resource waste across the network.

The vulnerability does not reach Critical Severity because it:
- Does not break consensus safety (blocks are still deterministically executed)
- Does not cause loss of funds
- Does not create an irrecoverable network partition
- Can be mitigated by epoch rotation removing the malicious validator

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to occur because:

1. **Low Barrier to Entry**: Any validator who becomes a proposer can execute this attack. With rotating leader election, even a single malicious validator will periodically get opportunities to propose.

2. **Easy Exploitation**: The attacker simply needs to:
   - Create a fake `QuorumCertifiedUpdate` with arbitrary data
   - Wrap it in `ValidatorTransaction::ObservedJWKUpdate`
   - Include it in a `ProposalExt` via `BlockData::new_proposal_ext()`
   - Sign the block with their validator key

3. **No Detection at Consensus Time**: The fake transactions are indistinguishable from legitimate ones during consensus validation, so honest validators cannot reject the proposal before committing it.

4. **Repeatable Attack**: The malicious proposer can execute this attack every round they are selected as leader, creating sustained impact.

5. **Low Cost**: The attacker faces minimal consequences—their block is still accepted and they receive normal rewards, while imposing costs on all other validators.

## Recommendation

Implement consensus-time verification for `ObservedJWKUpdate` transactions to match the rigor applied to `DKGResult` transactions.

**Option 1: Add Multi-Signature Verification at Consensus Time**

Modify `ValidatorTransaction::verify()` to perform cryptographic verification:

```rust
// In types/src/validator_txn.rs
pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
    match self {
        ValidatorTransaction::DKGResult(dkg_result) => dkg_result
            .verify(verifier)
            .context("DKGResult verification failed"),
        ValidatorTransaction::ObservedJWKUpdate(update) => {
            // Verify multi-signature
            let authors = update.multi_sig.get_signers_addresses(
                &verifier.get_ordered_account_addresses()
            );
            verifier.check_voting_power(authors.iter(), true)
                .context("Insufficient voting power for JWK update")?;
            verifier.verify_multi_signatures(&update.update, &update.multi_sig)
                .context("JWK update multi-signature verification failed")
        },
    }
}
```

**Option 2: Add Separate Consensus-Time Validation**

If full verification is too expensive at consensus time, add a lightweight check:

```rust
// In consensus/src/round_manager.rs, in process_proposal()
if let Some(vtxns) = proposal.validator_txns() {
    for vtxn in vtxns {
        let vtxn_type_name = vtxn.type_name();
        ensure!(
            is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
            "unexpected validator txn: {:?}",
            vtxn_type_name
        );
        // Add preliminary validation before full verify()
        vtxn.preliminary_verify()
            .context(format!("{} preliminary check failed", vtxn_type_name))?;
        vtxn.verify(self.epoch_state.verifier.as_ref())
            .context(format!("{} verify failed", vtxn_type_name))?;
    }
}
```

**Recommended Approach**: Implement Option 1 for complete security. The performance cost of multi-signature verification at consensus time is acceptable given that:
- Validator transactions are limited to 2 per block
- Multi-signature verification is already performed during execution
- This prevents resource waste on all nodes

## Proof of Concept

```rust
// Proof of concept demonstrating the vulnerability
// This would be added to consensus/src/round_manager_tests/

#[tokio::test]
async fn test_fake_jwk_update_passes_consensus() {
    // Setup test environment with JWK consensus enabled
    let mut test_env = TestEnvironment::new();
    let malicious_proposer = test_env.get_validator_signer(0);
    
    // Create a fake ObservedJWKUpdate with invalid multi-sig
    let fake_jwk_update = QuorumCertifiedUpdate {
        update: ProviderJWKs {
            issuer: b"https://fake.issuer".to_vec(),
            version: 999, // Wrong version
            jwks: vec![],
        },
        multi_sig: AggregateSignature::empty(), // Invalid signature!
    };
    
    let fake_vtxn = ValidatorTransaction::ObservedJWKUpdate(fake_jwk_update);
    
    // Create ProposalExt with fake validator transaction
    let block = Block::new_proposal_ext(
        vec![fake_vtxn],
        Payload::empty(true, true),
        1, // round
        test_env.current_timestamp(),
        test_env.get_qc(),
        &malicious_proposer,
        vec![],
    ).unwrap();
    
    // Verify the block passes consensus validation
    let proposal_msg = ProposalMsg::new(block, test_env.sync_info());
    
    // This should succeed at consensus time (demonstrating the vulnerability)
    let result = test_env.round_manager
        .process_proposal_msg(proposal_msg)
        .await;
    
    assert!(result.is_ok(), "Fake JWK update should pass consensus validation");
    
    // Execute the block
    let execution_result = test_env.execute_block(&block).await;
    
    // Verify the transaction was discarded during execution
    assert!(execution_result.validator_txns()[0].status().is_discarded(),
        "Fake JWK update should be discarded during execution");
}
```

**Notes:**
- This PoC demonstrates that consensus accepts blocks with fake `ObservedJWKUpdate` transactions
- The fake transaction only fails during VM execution, wasting resources
- A malicious proposer can exploit this repeatedly to DoS validator transaction processing
- The vulnerability exists because consensus-time verification is bypassed for JWK updates

### Citations

**File:** types/src/validator_txn.rs (L45-52)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            ValidatorTransaction::DKGResult(dkg_result) => dkg_result
                .verify(verifier)
                .context("DKGResult verification failed"),
            ValidatorTransaction::ObservedJWKUpdate(_) => Ok(()),
        }
    }
```

**File:** consensus/src/round_manager.rs (L1126-1137)
```rust
        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
        }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L78-88)
```rust
            Err(Expected(failure)) => {
                // Pretend we are inside Move, and expected failures are like Move aborts.
                debug!("Processing dkg transaction expected failure: {:?}", failure);
                Ok((
                    VMStatus::MoveAbort {
                        location: AbortLocation::Script,
                        code: failure as u64,
                        message: None,
                    },
                    VMOutput::empty_with_status(TransactionStatus::Discard(StatusCode::ABORTED)),
                ))
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-142)
```rust
        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }

        let authors = multi_sig.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;

        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;
```

**File:** types/src/on_chain_config/consensus_config.rs (L125-136)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 2;
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ValidatorTxnConfig {
    /// Disabled. In Jolteon, it also means to not use `BlockType::ProposalExt`.
    V0,
    /// Enabled. Per-block vtxn count and their total bytes are limited.
    V1 {
        per_block_limit_txn_count: u64,
        per_block_limit_total_bytes: u64,
    },
```
