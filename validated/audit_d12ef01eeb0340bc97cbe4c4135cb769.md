# Audit Report

## Title
Consensus Safety Violation: Quorum-Certified JWK Updates Lost Due to Session Key Collision Between Delete and Upsert Operations

## Summary

The JWK consensus per-key mode fails to distinguish between delete and upsert operations when managing consensus sessions, using only `(Issuer, KID)` as the session key. When a key undergoes rapid state changes (delete → upsert or vice versa), the system overwrites finished consensus states, causing quorum-certified validator transactions to be removed from the transaction pool before blockchain commitment, directly violating Byzantine Fault Tolerance safety guarantees.

## Finding Description

The vulnerability exists in the session key design and state management of the per-key JWK consensus system.

**Session Key Extraction Without Operation Type:**

The session key extraction functions capture only the issuer and key ID, deliberately discarding the critical `to_upsert` field that distinguishes operations: [1](#0-0) [2](#0-1) 

The `KeyLevelUpdate` struct contains the operation-defining field where `None` indicates deletion and `Some(jwk)` indicates upsert: [3](#0-2) 

**Consensus State Management:**

The consensus state map uses only `(Issuer, KID)` as the key, creating ambiguity between different operations on the same key: [4](#0-3) 

**The Critical Flaw:**

The `maybe_start_consensus` function checks if consensus is already in progress by comparing the `to_upsert` field: [5](#0-4) 

When operations differ (`None != Some(jwk)`), the check fails and new consensus is started. The subsequent insert operation **overwrites** the existing state: [6](#0-5) 

**Attack Execution Path:**

1. Delete operation for `(issuer1, kid1)` reaches quorum
2. Transaction placed in pool with `ConsensusState::Finished { vtxn_guard, ... }`
3. Upsert observation arrives for same `(issuer1, kid1)` with JWK data
4. `maybe_start_consensus` called with `to_upsert: Some(jwk)`
5. Check at line 187 evaluates `None != Some(jwk)` → `false` (operations differ)
6. New `InProgress` state inserted at line 216, overwriting `Finished` state
7. Old `vtxn_guard` dropped, triggering automatic cleanup: [7](#0-6) 

8. Quorum-certified delete transaction removed from pool before blockchain commitment

**Compounding Factors:**

The transaction pool Topic also lacks operation distinction: [8](#0-7) 

When transactions share Topics, newer ones replace older ones: [9](#0-8) 

The QC delivery channel uses KLAST style with capacity 1, allowing concurrent QCs to overwrite each other: [10](#0-9) [11](#0-10) 

## Impact Explanation

This qualifies as **Critical Severity** under Aptos Bug Bounty category "Consensus/Safety violations."

**Broken BFT Invariant:** Byzantine Fault Tolerance fundamentally requires that once 2f+1 honest validators reach quorum on a decision, that decision must be irreversible and eventually committed to the blockchain. This vulnerability allows quorum-certified decisions to be silently discarded before commitment, breaking this core safety guarantee.

**Concrete Consensus Impacts:**
- Validators reach quorum on a JWK update, but the certified update never appears on-chain
- System behaves as if consensus never occurred, despite 2f+1 validator agreement
- Potential for validator state divergence if different validators track different certified updates
- Chain state may not reflect actual validator consensus decisions

**Security Implications:**
- If validators reach quorum on deleting a compromised JWK, a subsequent upsert could prevent that security-critical deletion from being committed
- Authentication system security depends on JWK state accurately reflecting validator consensus
- Undermines trust in the validator consensus mechanism itself
- Could enable authentication bypasses if compromised keys remain trusted

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Requirements:**
1. OIDC provider changes key state (delete or upsert)
2. Validators reach quorum on that change
3. Same provider changes the same key again before block commitment
4. Validators reach quorum on the second change

**Realistic Trigger Scenarios:**

1. **Malicious OIDC Provider:** An attacker controlling an OIDC provider endpoint could deliberately oscillate key availability to exploit this vulnerability, targeting specific key IDs for disruption

2. **Buggy Provider Implementation:** Providers with implementation bugs, race conditions, or load balancing issues could inadvertently expose/hide keys in rapid succession

3. **Network Timing Issues:** Network partitions or delays could cause different validators to observe different provider states at different times, triggering natural race conditions

4. **Operational Key Rotation:** Legitimate provider operations might delete expired keys and add new ones with identical key IDs in close succession during rotation procedures

5. **Provider Infrastructure Changes:** CDN failover, DNS changes, or load balancer updates could cause temporary key visibility fluctuations

**Feasibility Assessment:**

The timing window is measured in seconds (consensus round time for JWK updates). The per-key consensus mode was specifically designed to handle rapidly changing provider states, making the race condition window realistic and exploitable. No special privileges or stake requirements are needed—any OIDC provider (untrusted external actor) can trigger this condition.

## Recommendation

**Primary Fix:** Include the operation type in the session key to prevent different operations on the same key from colliding.

Modify the session key type to distinguish operations:

```rust
// Change ConsensusSessionKey from (Issuer, KID) to (Issuer, KID, bool)
// where bool indicates whether it's an upsert (true) or delete (false)
type ConsensusSessionKey = (Issuer, KID, bool);
```

Update session key extraction:

```rust
fn new_rb_request(epoch: u64, payload: &ProviderJWKs) -> anyhow::Result<ObservedKeyLevelUpdateRequest> {
    let KeyLevelUpdate { issuer, kid, to_upsert, .. } = 
        KeyLevelUpdate::try_from_issuer_level_repr(payload)?;
    Ok(ObservedKeyLevelUpdateRequest { 
        epoch, 
        issuer, 
        kid,
        is_upsert: to_upsert.is_some() // Add operation type
    })
}

fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<(Issuer, KID, bool)> {
    let KeyLevelUpdate { issuer, kid, to_upsert, .. } = 
        KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)?;
    Ok((issuer, kid, to_upsert.is_some()))
}
```

**Alternative Fix:** Modify `maybe_start_consensus` to preserve finished states:

```rust
fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
    match self.states_by_key.get(&(update.issuer.clone(), update.kid.clone())) {
        Some(ConsensusState::Finished { .. }) => {
            // Never overwrite finished consensus - it must be committed first
            return Ok(());
        },
        // ... rest of logic
    }
}
```

**Transaction Pool Topic Fix:** Include operation type in the Topic enum to prevent transaction replacement between different operations.

## Proof of Concept

The vulnerability is demonstrated through code logic analysis. A complete PoC would require:

1. Setting up a test OIDC provider that can rapidly change key state
2. Configuring validators to observe this provider
3. Triggering delete consensus → wait for Finished state → trigger upsert observation
4. Verifying that the quorum-certified delete transaction is removed from the pool
5. Confirming the delete never appears on-chain despite reaching quorum

The core logic flaw is evident in the code structure where `insert()` unconditionally overwrites map entries, and the RAII guard pattern automatically removes transactions on drop, creating an unintended state machine violation.

### Citations

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L36-39)
```rust
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(payload)
                .context("new_rb_request failed with repr translation")?;
        Ok(ObservedKeyLevelUpdateRequest { epoch, issuer, kid })
```

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L59-64)
```rust
    fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<(Issuer, KID)> {
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)
                .context("session_key_from_qc failed with repr translation")?;
        Ok((issuer, kid))
    }
```

**File:** types/src/jwks/mod.rs (L324-330)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct KeyLevelUpdate {
    pub issuer: Issuer,
    pub base_version: u64,
    pub kid: KID,
    pub to_upsert: Option<JWK>, // If none, it is a deletion.
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust
    states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L79-79)
```rust
        let (qc_update_tx, qc_update_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L179-194)
```rust
    fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
        let consensus_already_started = match self
            .states_by_key
            .get(&(update.issuer.clone(), update.kid.clone()))
            .cloned()
        {
            Some(ConsensusState::InProgress { my_proposal, .. })
            | Some(ConsensusState::Finished { my_proposal, .. }) => {
                my_proposal.observed.to_upsert == update.to_upsert
            },
            _ => false,
        };

        if consensus_already_started {
            return Ok(());
        }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L216-228)
```rust
        self.states_by_key.insert(
            (update.issuer.clone(), update.kid.clone()),
            ConsensusState::InProgress {
                my_proposal: ObservedKeyLevelUpdate {
                    author: self.my_addr,
                    observed: update,
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard {
                    handle: abort_handle,
                },
            },
        );
```

**File:** crates/validator-transaction-pool/src/lib.rs (L74-76)
```rust
        if let Some(old_seq_num) = pool.seq_nums_by_topic.insert(topic.clone(), seq_num) {
            pool.txn_queue.remove(&old_seq_num);
        }
```

**File:** crates/validator-transaction-pool/src/lib.rs (L202-206)
```rust
impl Drop for TxnGuard {
    fn drop(&mut self) {
        self.pool.lock().try_delete(self.seq_num);
    }
}
```

**File:** types/src/validator_txn.rs (L60-63)
```rust
    JWK_CONSENSUS_PER_KEY_MODE {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L70-73)
```rust
            let session_key = ConsensusMode::session_key_from_qc(&qc_update);
            match session_key {
                Ok(key) => {
                    let _ = qc_update_tx.push(key, qc_update);
```
