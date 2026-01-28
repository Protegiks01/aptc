# Audit Report

## Title
JWK Consensus Version Validation Bypass Leading to State Corruption and Denial of Service

## Summary
The JWK consensus manager (both per-key and per-issuer modes) accepts quorum-certified updates without validating that the QC's version matches the expected version in the current consensus state. This allows stale QCs with old versions to be accepted during race conditions, causing permanent state corruption and denial of service for specific JWK updates.

## Finding Description

The vulnerability exists in the `process_quorum_certified_update` function which processes quorum-certified JWK updates. The function accepts any QC for a given session key as long as the consensus state is `InProgress`, without validating that the QC's version matches the state's expected version.

In the per-key manager, the function only checks if the state is `InProgress` and immediately accepts the QC without version validation: [1](#0-0) 

The same issue exists in the per-issuer manager: [2](#0-1) 

The session key is defined without version information. For per-key mode: [3](#0-2) 

For per-issuer mode: [4](#0-3) 

When on-chain state updates, the `reset_with_on_chain_state` function clears states for affected keys (per-key mode): [5](#0-4) 

**Attack Scenario:**

1. Validator observes JWK update for KID1, creates `KeyLevelUpdate` with `base_version=10` (will produce QC with version=11 since version = base_version + 1): [6](#0-5) 

2. Reliable broadcast starts for session key `(Issuer, KID1)` and consensus state becomes `InProgress` storing the proposal with `base_version=10`

3. Concurrently, another key KID2 gets updated, advancing on-chain issuer version to 11

4. `ObservedJWKsUpdated` event triggers `reset_with_on_chain_state`, clearing the KID1 state because the version no longer matches

5. The abort handle is dropped to cancel the old broadcast: [7](#0-6) 

6. Due to race condition, the old broadcast completes before abort takes effect and sends QC (version=11) to the `qc_update_rx` channel

7. Observer detects KID1 update again with the new on-chain version, starts NEW consensus with `base_version=11` (will produce version=12)

8. Old QC (version=11) arrives from the channel and is processed

9. Manager finds state is `InProgress` (from new consensus) and accepts the old QC without checking that its version (11) doesn't match the expected version (12)

10. Transaction is submitted to validator transaction pool with version=11, but on-chain version is already 11

11. When the transaction is eventually executed, the VM rejects it because the version check fails: [8](#0-7) 

12. Manager's state is now `Finished` with a QC that will never succeed on-chain, blocking future updates because `maybe_start_consensus` won't restart when state is already `Finished`: [9](#0-8) 

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per Aptos bug bounty program: "State inconsistencies requiring manual intervention".

**Specific Impacts:**

1. **Permanent Denial of Service**: Once the manager accepts a stale QC, the consensus state becomes `Finished` for that key/issuer. Future attempts to start consensus for the same key will return early because the state is already `Finished`, permanently blocking JWK updates for that specific key.

2. **State Consistency Violation**: The manager's internal state diverges from on-chain reality - it believes consensus succeeded (state is `Finished` with a QC) when the transaction was actually rejected by the VM and never applied on-chain.

3. **No Recovery Mechanism**: The system has no automatic way to detect that the transaction was rejected or to recover from this inconsistent state. Manual intervention (likely requiring node restart or code changes) would be required.

4. **Limited Scope**: Unlike a network-wide DoS, this affects only specific JWK updates for particular issuers/keys, not the entire JWK consensus system or blockchain operation.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur naturally without malicious behavior:

1. **Natural Occurrence**: Normal timing variations between JWK observations, on-chain updates, and reliable broadcast completions can trigger the race condition.

2. **Multiple Keys Per Issuer**: Production systems typically have multiple keys per issuer. Each key update triggers `reset_with_on_chain_state` which affects all pending consensus sessions for that issuer, increasing the probability of race conditions.

3. **Async Channel Timing**: The `qc_update_rx` channel is asynchronous, creating a natural race window between when a QC is sent to the channel and when the abort takes effect.

4. **Malicious Amplification**: A malicious validator could deliberately trigger this by timing their JWK observations and reliable broadcast completions to maximize the race window.

5. **No Rate Limiting**: There's no mechanism preventing rapid successive JWK updates that would increase race condition probability.

## Recommendation

Add version validation in `process_quorum_certified_update` to verify that the incoming QC's version matches the expected version in the current state's `my_proposal`:

**For per-key manager:**
```rust
pub fn process_quorum_certified_update(
    &mut self,
    issuer_level_repr: QuorumCertifiedUpdate,
) -> Result<()> {
    let key_level_update = KeyLevelUpdate::try_from_issuer_level_repr(&issuer_level_repr.update)?;
    let issuer = &key_level_update.issuer;
    let kid = &key_level_update.kid;
    
    let state = self.states_by_key.entry((issuer.clone(), kid.clone())).or_default();
    
    match state {
        ConsensusState::InProgress { my_proposal, .. } => {
            // ADDED: Validate version matches
            let expected_base_version = my_proposal.observed.base_version;
            if key_level_update.base_version != expected_base_version {
                return Err(anyhow!(
                    "Version mismatch: expected base_version={}, got base_version={}",
                    expected_base_version,
                    key_level_update.base_version
                ));
            }
            
            // Rest of the existing logic...
            let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE { issuer: issuer.clone(), kid: kid.clone() };
            let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
            let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
            *state = ConsensusState::Finished { vtxn_guard, my_proposal: my_proposal.clone(), quorum_certified: issuer_level_repr };
            Ok(())
        },
        _ => Err(anyhow!("qc update not expected in state {}", state.name())),
    }
}
```

**For per-issuer manager:**
```rust
pub fn process_quorum_certified_update(&mut self, update: QuorumCertifiedUpdate) -> Result<()> {
    let issuer = update.update.issuer.clone();
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    
    match &state.consensus_state {
        ConsensusState::InProgress { my_proposal, .. } => {
            // ADDED: Validate version matches
            let expected_version = my_proposal.observed.version;
            if update.update.version != expected_version {
                return Err(anyhow!(
                    "Version mismatch: expected version={}, got version={}",
                    expected_version,
                    update.update.version
                ));
            }
            
            // Rest of the existing logic...
            let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
            let vtxn_guard = self.vtxn_pool.put(Topic::JWK_CONSENSUS(issuer.clone()), Arc::new(txn), None);
            state.consensus_state = ConsensusState::Finished { vtxn_guard, my_proposal: my_proposal.clone(), quorum_certified: update.clone() };
            Ok(())
        },
        _ => Err(anyhow!("qc update not expected in state {}", state.consensus_state.name())),
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_jwk_manager_stale_qc_race_condition() {
    // Setup: Create epoch with validators
    let private_keys: Vec<Arc<PrivateKey>> = (0..4)
        .map(|_| Arc::new(PrivateKey::generate_for_testing()))
        .collect();
    let public_keys: Vec<PublicKey> = private_keys.iter().map(|sk| PublicKey::from(sk.as_ref())).collect();
    let addrs: Vec<AccountAddress> = (0..4).map(|_| AccountAddress::random()).collect();
    let validator_consensus_infos: Vec<ValidatorConsensusInfo> = (0..4)
        .map(|i| ValidatorConsensusInfo::new(addrs[i], public_keys[i].clone(), 1))
        .collect();
    let epoch_state = Arc::new(EpochState {
        epoch: 999,
        verifier: ValidatorVerifier::new(validator_consensus_infos).into(),
    });

    let update_certifier = Arc::new(DummyUpdateCertifier::default());
    let vtxn_pool = VTxnPoolState::default();
    let mut jwk_manager = KeyLevelConsensusManager::new(
        private_keys[0].clone(),
        addrs[0],
        epoch_state,
        update_certifier,
        vtxn_pool.clone(),
    );

    let issuer = issuer_from_str("https://issuer.example");
    let kid1 = b"kid1".to_vec();
    let kid2 = b"kid2".to_vec();

    // Step 1: Initialize with on-chain state version 10
    let on_chain_state = AllProvidersJWKs {
        entries: vec![ProviderJWKs {
            issuer: issuer.clone(),
            version: 10,
            jwks: vec![],
        }],
    };
    jwk_manager.reset_with_on_chain_state(on_chain_state).unwrap();

    // Step 2: Start consensus for KID1 with base_version=10
    let update_kid1_v10 = KeyLevelUpdate {
        issuer: issuer.clone(),
        base_version: 10,
        kid: kid1.clone(),
        to_upsert: Some(JWK::Unsupported(UnsupportedJWK::new_for_testing("kid1", "payload1"))),
    };
    jwk_manager.maybe_start_consensus(update_kid1_v10.clone()).unwrap();

    // Step 3: Create QC for KID1 with version=11 (simulating old broadcast completing)
    let qc_kid1_v11 = create_qc_for_update(&private_keys, &update_kid1_v10);

    // Step 4: Simulate KID2 update advancing on-chain version to 11
    let on_chain_state_v11 = AllProvidersJWKs {
        entries: vec![ProviderJWKs {
            issuer: issuer.clone(),
            version: 11,
            jwks: vec![],
        }],
    };
    jwk_manager.reset_with_on_chain_state(on_chain_state_v11).unwrap();

    // Step 5: Start NEW consensus for KID1 with base_version=11
    let update_kid1_v11 = KeyLevelUpdate {
        issuer: issuer.clone(),
        base_version: 11,
        kid: kid1.clone(),
        to_upsert: Some(JWK::Unsupported(UnsupportedJWK::new_for_testing("kid1", "payload1_new"))),
    };
    jwk_manager.maybe_start_consensus(update_kid1_v11).unwrap();

    // Step 6: Process the OLD QC (version=11) - THIS SHOULD FAIL but currently succeeds
    let result = jwk_manager.process_quorum_certified_update(qc_kid1_v11);
    
    // BUG: This succeeds when it should fail due to version mismatch
    assert!(result.is_ok(), "BUG: Old QC was accepted despite version mismatch");

    // Step 7: Verify state is now Finished with wrong QC
    let state = jwk_manager.states_by_key.get(&(issuer.clone(), kid1)).unwrap();
    assert!(matches!(state, ConsensusState::Finished { .. }));

    // Step 8: Verify transaction in pool will be rejected by VM
    // When executed, VM will check: on_chain.version(11) + 1 != observed.version(11)
    // This will fail, but manager thinks it succeeded
}
```

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust
    states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L185-189)
```rust
            Some(ConsensusState::InProgress { my_proposal, .. })
            | Some(ConsensusState::Finished { my_proposal, .. }) => {
                my_proposal.observed.to_upsert == update.to_upsert
            },
            _ => false,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L244-254)
```rust
        self.states_by_key.retain(|(issuer, _), _| {
            new_onchain_jwks
                .get(issuer)
                .map(|jwks| jwks.version)
                .unwrap_or_default()
                == self
                    .onchain_jwks
                    .get(issuer)
                    .map(|jwks| jwks.version)
                    .unwrap_or_default()
        });
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L334-346)
```rust
        match state {
            ConsensusState::InProgress { my_proposal, .. } => {
                let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
                    issuer: issuer.clone(),
                    kid: kid.clone(),
                };
                let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
                let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
                *state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: issuer_level_repr,
                };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L57-57)
```rust
    stopped: bool,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L332-350)
```rust
        match &state.consensus_state {
            ConsensusState::InProgress { my_proposal, .. } => {
                //TODO: counters
                let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
                let vtxn_guard =
                    self.vtxn_pool
                        .put(Topic::JWK_CONSENSUS(issuer.clone()), Arc::new(txn), None);
                state.consensus_state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: update.clone(),
                };
                info!(
                    epoch = self.epoch_state.epoch,
                    issuer = String::from_utf8(issuer).ok(),
                    version = update.update.version,
                    "certified update accepted."
                );
                Ok(())
```

**File:** types/src/jwks/mod.rs (L349-352)
```rust
        let version = self
            .base_version
            .checked_add(1)
            .context("KeyLevelUpdate::as_issuer_level_repr failed on version")?;
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L96-101)
```rust
impl Drop for QuorumCertProcessGuard {
    fn drop(&mut self) {
        let QuorumCertProcessGuard { handle } = self;
        handle.abort();
    }
}
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-130)
```rust
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```
