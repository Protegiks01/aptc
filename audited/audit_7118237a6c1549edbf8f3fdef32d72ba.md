# Audit Report

## Title
Double-Signing Vulnerability in JWK Per-Key Consensus Allows Validator Equivocation

## Summary
The `maybe_start_consensus()` function in `KeyLevelConsensusManager` fails to check if a validator has already signed a different update for the same `(issuer, kid, base_version)` triple. This allows validators to unintentionally equivocate by signing multiple conflicting JWK updates for the same base version, violating consensus safety and potentially causing consensus divergence.

## Finding Description

The vulnerability exists in the consensus state management and deduplication logic within the JWK per-key consensus protocol. The root cause is that the consensus state is stored in a HashMap keyed only by `(Issuer, KID)`, not by `(Issuer, KID, base_version)`: [1](#0-0) 

When `maybe_start_consensus()` is called, it checks if consensus has already started by looking up the state using only `(issuer, kid)` and comparing whether the `to_upsert` field matches: [2](#0-1) 

The critical flaw is that this check only compares `my_proposal.observed.to_upsert == update.to_upsert`. It **never verifies** if `my_proposal.observed.base_version == update.base_version`. When the check fails (different `to_upsert` values), the function proceeds to sign the new update: [3](#0-2) 

And then overwrites the previous state: [4](#0-3) 

**Attack Scenario:**

1. On-chain state for issuer "Alice" is at version 5
2. **Time T1:** Validator V's JWK observer fetches `JWK_A` for `kid="key1"` from the OIDC provider via periodic polling [5](#0-4) 
   - Creates `KeyLevelUpdate{issuer="Alice", base_version=5, kid="key1", to_upsert=Some(JWK_A)}`
   - Signs it and stores in `states_by_key[("Alice", "key1")]`
   - When peer P1 requests this validator's observation via RPC [6](#0-5) , it receives the signed update with `JWK_A`

3. **Time T2:** Before the on-chain state updates to version 6, the observer fetches `JWK_B` for `kid="key1"` (due to network instability, OIDC provider key rotation, or caching issues)
   - Creates `KeyLevelUpdate{issuer="Alice", base_version=5, kid="key1", to_upsert=Some(JWK_B)}`
   - The check finds existing state but compares `JWK_A != JWK_B` → returns `false`
   - `consensus_already_started = false`
   - **Signs the new update** (equivocation!)
   - Overwrites `states_by_key[("Alice", "key1")]` with new proposal containing `JWK_B`
   - When peer P2 requests this validator's observation, it receives the signed update with `JWK_B`

4. **Result:** Validator V has now signed TWO different updates for the same `(issuer="Alice", kid="key1", base_version=5)` triple

**Consensus Divergence Mechanism:**

Different peers collecting observations at different times will receive different signed updates from the equivocating validator. The observation aggregation requires matching views [7](#0-6) , so:
- Peers that collect early form a quorum around `(base_version=5, JWK_A)`
- Peers that collect later form a quorum around `(base_version=5, JWK_B)`

Both quorums pass VM validation because the version check only ensures `on_chain.version + 1 == observed.version` [8](#0-7) , which both satisfy. This allows different validators to commit different `QuorumCertifiedUpdate` transactions, leading to consensus divergence.

**Which Invariant is Broken:**

This violates the fundamental "Consensus Safety" invariant that validators must not equivocate by signing conflicting values for the same logical update. The JWK consensus protocol assumes validators sign at most one update per `(issuer, kid, base_version)` triple.

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This qualifies as **Critical** under the Aptos bug bounty program because it causes a **Consensus/Safety violation**:

- Different validators may collect different signed observations from the equivocating validator
- Multiple conflicting quorums can form for the same `(issuer, kid, base_version)` triple
- Different nodes may commit different `QuorumCertifiedUpdate` transactions to the blockchain
- This leads to consensus divergence where validators disagree on the correct chain state
- Recovery requires manual intervention or a hard fork

The vulnerability affects the core consensus mechanism for JWK updates, which is critical infrastructure for keyless authentication in Aptos. A consensus split in this system could prevent proper validation of keyless transactions across the network and fragment the validator set.

## Likelihood Explanation

**High Likelihood**

This vulnerability has a high likelihood of occurrence because:

1. **No malicious intent required**: Even honest validators will equivocate due to this bug
2. **Frequent trigger conditions**: 
   - JWK observers poll OIDC providers every 10 seconds [5](#0-4) 
   - Network instability when fetching from external OIDC providers is common
   - OIDC providers can update their keys between observation cycles
   - HTTP caching at various layers (CDN, proxy, client) can cause inconsistent responses
3. **Race condition window**: The window between observation cycles when the OIDC provider's response changes but before on-chain state updates creates a natural opportunity for equivocation
4. **No protective mechanisms**: There is no validation checking `base_version` consistency, no monitoring, and no alerting for this condition

The bug triggers during normal validator operation without any attack required.

## Recommendation

The fix should include checking the `base_version` field when determining if consensus has already started:

```rust
fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
    let consensus_already_started = match self
        .states_by_key
        .get(&(update.issuer.clone(), update.kid.clone()))
        .cloned()
    {
        Some(ConsensusState::InProgress { my_proposal, .. })
        | Some(ConsensusState::Finished { my_proposal, .. }) => {
            // FIX: Check both base_version AND to_upsert
            my_proposal.observed.base_version == update.base_version
                && my_proposal.observed.to_upsert == update.to_upsert
        },
        _ => false,
    };

    if consensus_already_started {
        return Ok(());
    }
    // ... rest of the function
}
```

Additionally, consider:
1. Keying the state by `(Issuer, KID, base_version)` to prevent any possibility of overwriting
2. Adding validation to reject signing multiple updates for the same base version
3. Implementing monitoring to detect equivocation attempts

## Proof of Concept

```rust
// Conceptual PoC showing the vulnerability flow:
// 
// 1. Initial state: on-chain version = 5, validator state empty
// 2. Observer fetches JWK_A from OIDC provider
//    -> Creates KeyLevelUpdate { base_version: 5, to_upsert: Some(JWK_A) }
//    -> maybe_start_consensus() finds no existing state
//    -> Signs update_A and stores in states_by_key[("Alice", "key1")]
//    -> Peer P1 requests observation, gets signed (base_version=5, JWK_A)
//
// 3. Before on-chain state updates, observer fetches JWK_B
//    -> Creates KeyLevelUpdate { base_version: 5, to_upsert: Some(JWK_B) }
//    -> maybe_start_consensus() finds existing state with JWK_A
//    -> Compares: JWK_A != JWK_B -> consensus_already_started = false
//    -> Signs update_B and OVERWRITES states_by_key[("Alice", "key1")]
//    -> Peer P2 requests observation, gets signed (base_version=5, JWK_B)
//
// 4. Result: Same validator has signed two conflicting updates for base_version=5
//    -> P1 can form quorum around (base_version=5, JWK_A)
//    -> P2 can form quorum around (base_version=5, JWK_B)
//    -> Both pass VM validation: on_chain.version(5) + 1 == observed.version(6)
//    -> Consensus divergence: different validators commit different state
```

**Notes:**

The vulnerability is triggered by normal operational conditions without requiring any malicious actors. The JWK observer's periodic polling combined with the possibility of OIDC provider responses changing creates a race condition that allows validators to unintentionally equivocate. The missing `base_version` check in the deduplication logic is the root cause that enables this consensus safety violation.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust
    states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L180-190)
```rust
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
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L192-203)
```rust
        if consensus_already_started {
            return Ok(());
        }

        let issuer_level_repr = update
            .try_as_issuer_level_repr()
            .context("initiate_key_level_consensus failed at repr conversion")?;
        let signature = self
            .consensus_key
            .sign(&issuer_level_repr)
            .context("crypto material error occurred during signing")?;

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

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L287-299)
```rust
                    ConsensusState::InProgress { my_proposal, .. }
                    | ConsensusState::Finished { my_proposal, .. } => Ok(
                        JWKConsensusMsg::ObservationResponse(ObservedUpdateResponse {
                            epoch: self.epoch_state.epoch,
                            update: ObservedUpdate {
                                author: self.my_addr,
                                observed: my_proposal
                                    .observed
                                    .try_as_issuer_level_repr()
                                    .context("process_peer_request failed with repr conversion")?,
                                signature: my_proposal.signature.clone(),
                            },
                        }),
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L399-399)
```rust
                        Duration::from_secs(10),
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-84)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-130)
```rust
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```
