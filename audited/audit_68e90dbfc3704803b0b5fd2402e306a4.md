# Audit Report

## Title
Missing Merkle Proof Verification in Remote Executor State Synchronization Allows Coordinator to Poison Shard Execution State

## Summary
The sharded block executor's remote execution architecture lacks cryptographic verification of state values transmitted from the coordinator to executor shards. A malicious or compromised coordinator can send arbitrary state values via `RemoteKVResponse` messages, causing shards to execute transactions with incorrect state and produce invalid outputs that violate consensus determinism.

## Finding Description

The sharded block executor architecture separates block execution into a coordinator and multiple executor shards communicating over the network. When shards need state values to execute transactions, they send `RemoteKVRequest` messages to the coordinator and receive `RemoteKVResponse` messages containing the requested state key-value pairs.

**Critical Security Gap:** The `RemoteKVResponse` structure contains only raw state values without any Merkle proofs or cryptographic commitments to verify their correctness. [1](#0-0) 

The coordinator fetches state from its local `CachedStateView` and sends it to shards without proof generation: [2](#0-1) 

Shards receive these responses, deserialize them without validation, and directly store the values: [3](#0-2) 

The `RemoteStateValue::set_value()` implementation has no validation logic: [4](#0-3) 

**Attack Scenario:**
1. A coordinator (compromised or malicious) receives a `RemoteKVRequest` for state keys
2. Instead of returning correct state values from its database, it fabricates incorrect values
3. The coordinator sends a `RemoteKVResponse` with poisoned state values
4. The executor shard receives and trusts these values without verification
5. The shard executes transactions using the poisoned state, producing invalid outputs
6. If different shards receive different poisoned values, validators produce non-deterministic results, breaking consensus

The `NetworkController` used for this communication also lacks authentication mechanisms: [5](#0-4) 

This violates Aptos's fundamental **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs" and the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

**Severity: Critical** (Consensus/Safety Violation)

This vulnerability enables consensus-breaking attacks by allowing non-deterministic execution across validators:

1. **Consensus Safety Violation**: If a malicious coordinator provides different state values to different validator's shards (or across multiple block executions), validators will compute different state roots for identical blocks, causing blockchain forks.

2. **Silent State Corruption**: A compromised coordinator can systematically corrupt execution state without detection, as there's no cryptographic proof to verify correctness against the committed Merkle root.

3. **Transaction Execution Manipulation**: By providing incorrect account balances, module code, or resource values, an attacker can cause transactions to execute with wrong preconditions, potentially enabling unauthorized state transitions.

The impact meets the **Critical Severity** category per Aptos bug bounty criteria: "Consensus/Safety violations" that could lead to "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**Likelihood: Medium-High**

While the coordinator is typically a trusted component within validator infrastructure, the likelihood is elevated by:

1. **Compromised Infrastructure**: Validator nodes are high-value targets. A compromised coordinator process can exploit this vulnerability to corrupt execution silently.

2. **No Defense-in-Depth**: The complete absence of verification means any coordinator compromise (software bug, supply chain attack, insider threat) immediately enables exploitation without detection.

3. **Complex Distributed Systems**: The remote execution architecture introduces additional attack surface through network communication between coordinator and shards.

4. **No Authentication**: The `NetworkController` lacks authentication, potentially allowing man-in-the-middle attacks if network security is compromised.

The explicit threat model in the security question asks about "a malicious coordinator", indicating this is a recognized threat scenario worth addressing.

## Recommendation

Implement Merkle proof-based state value verification in the remote executor protocol:

**1. Modify `RemoteKVResponse` to include proofs:**
```rust
pub struct RemoteKVResponse {
    pub(crate) inner: Vec<(StateKey, Option<StateValue>, SparseMerkleProof)>,
    pub(crate) state_version: Version,
    pub(crate) root_hash: HashValue,
}
```

**2. Update coordinator to generate proofs:**
In `RemoteStateViewService::handle_message()`, use the state view's proof generation capability:
```rust
let resp = state_keys
    .into_iter()
    .map(|state_key| {
        let (state_value, proof) = state_view
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .get_state_value_with_proof_by_version(&state_key, version)
            .unwrap();
        (state_key, state_value, proof)
    })
    .collect_vec();
```

**3. Update shard to verify proofs:**
In `RemoteStateValueReceiver::handle_message()`, verify each proof before storing:
```rust
response.inner.into_iter().for_each(|(state_key, state_value, proof)| {
    // Verify proof against known root hash
    proof.verify(response.root_hash, state_key.hash(), state_value.as_ref())
        .expect("State proof verification failed");
    state_view_lock.set_state_value(&state_key, state_value);
});
```

**4. Add authentication to NetworkController** or migrate to the authenticated network framework used by consensus.

## Proof of Concept

```rust
// Proof of Concept: Malicious coordinator sending poisoned state
// This would be implemented as a modified RemoteStateViewService

use aptos_types::state_store::state_value::StateValue;
use aptos_types::state_store::state_key::StateKey;

// Malicious coordinator that poisons specific account balances
fn malicious_handle_message(
    request: RemoteKVRequest,
    // ... other parameters
) {
    let (shard_id, state_keys) = request.into();
    
    let resp = state_keys
        .into_iter()
        .map(|state_key| {
            // Detect if this is a coin balance query
            if is_coin_balance_key(&state_key) {
                // Return a fabricated high balance instead of real value
                let poisoned_value = create_poisoned_balance(1_000_000_000);
                (state_key, Some(poisoned_value))
            } else {
                // Return correct values for other keys to avoid detection
                let correct_value = state_view.get_state_value(&state_key).unwrap();
                (state_key, correct_value)
            }
        })
        .collect();
    
    // Send poisoned response - will be accepted without verification
    let response = RemoteKVResponse::new(resp);
    // ... send response
}

// Result: Transactions execute with incorrect balance preconditions,
// producing invalid state transitions that break consensus if validators
// use different coordinators or the coordinator selectively poisons certain validators.
```

**Demonstration Steps:**
1. Set up a validator with remote sharded execution enabled
2. Intercept or replace the `RemoteStateViewService` with a malicious implementation
3. Configure it to return incorrect state values for specific keys
4. Observe that shards execute transactions using the poisoned values
5. Compare execution results with a validator using correct state - state roots will diverge

## Notes

While the coordinator is typically part of trusted validator infrastructure, the lack of cryptographic verification represents a severe defense-in-depth failure. The Aptos codebase contains extensive Merkle proof infrastructure for state verification, but this is not utilized in the remote executor protocol. Any compromise of the coordinator (whether through software vulnerabilities, supply chain attacks, or insider threats) can immediately corrupt execution without detection. This violates the fundamental blockchain principle that all state should be cryptographically verifiable.

### Citations

**File:** execution/executor-service/src/lib.rs (L83-92)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteKVResponse {
    pub(crate) inner: Vec<(StateKey, Option<StateValue>)>,
}

impl RemoteKVResponse {
    pub fn new(inner: Vec<(StateKey, Option<StateValue>)>) -> Self {
        Self { inner }
    }
}
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L95-107)
```rust
        let resp = state_keys
            .into_iter()
            .map(|state_key| {
                let state_value = state_view
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .get_state_value(&state_key)
                    .unwrap();
                (state_key, state_value)
            })
            .collect_vec();
```

**File:** execution/executor-service/src/remote_state_view.rs (L254-271)
```rust
        let response: RemoteKVResponse = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

        REMOTE_EXECUTOR_REMOTE_KV_COUNT
            .with_label_values(&[&shard_id.to_string(), "kv_responses"])
            .inc();
        let state_view_lock = state_view.read().unwrap();
        trace!(
            "Received state values for shard {} with size {}",
            shard_id,
            response.inner.len()
        );
        response
            .inner
            .into_iter()
            .for_each(|(state_key, state_value)| {
                state_view_lock.set_state_value(&state_key, state_value);
            });
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L22-27)
```rust
    pub fn set_value(&self, value: Option<StateValue>) {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        *status = RemoteValueStatus::Ready(value);
        cvar.notify_all();
    }
```

**File:** secure/net/src/network_controller/mod.rs (L94-100)
```rust
impl NetworkController {
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
```
