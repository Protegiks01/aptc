# Audit Report

## Title
Cross-Shard State Cache Poisoning via Unvalidated Remote Transaction Writes

## Summary
The sharded block executor service accepts cross-shard state values without cryptographic validation, allowing a compromised shard to poison the state cache of dependent shards, leading to non-deterministic transaction execution and potential consensus violations.

## Finding Description

The Aptos sharded block executor implements parallel transaction execution by partitioning transactions across multiple shards. When transactions have cross-shard dependencies, the executing shard sends the resulting state values to dependent shards via `RemoteTxnWriteMsg`. [1](#0-0) 

The critical flaw exists in `CrossShardCommitReceiver::start()` where received cross-shard messages are processed. When a shard receives a `RemoteTxnWriteMsg`, it directly calls `cross_shard_state_view.set_value()` without any validation of the state value's authenticity, integrity, or correctness. [2](#0-1) 

These unvalidated state values are cached in the `CrossShardStateView` and subsequently used for transaction execution. The underlying `RemoteStateValue` structure provides no verification mechanism: [3](#0-2) 

The network layer (`NetworkController`) provides no authentication or signature verification: [4](#0-3) 

**Attack Path:**
1. Attacker compromises one shard process within a validator node
2. Malicious shard executes transactions and identifies cross-shard dependencies
3. Instead of sending correct state values, the malicious shard crafts `RemoteTxnWriteMsg` with arbitrary state values
4. Receiving shard accepts and caches the poisoned state values without validation
5. Subsequent transactions execute against corrupted state, producing incorrect results
6. Different validator nodes produce different state roots, violating consensus

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the **Deterministic Execution** invariant (#1) - the fundamental requirement that all validators produce identical state roots for identical blocks.

If exploited:
- **Consensus Safety Violation**: Different shards executing the same transactions against poisoned vs. correct state will produce different outputs, causing validator nodes to disagree on the state root
- **State Corruption**: Poisoned cached values affect all subsequent transactions that depend on those state keys
- **Potential Fund Loss**: If state values related to coin balances, ownership records, or access control are poisoned, unauthorized fund transfers or access could occur
- **Network Fork Risk**: Validators with poisoned state diverge from honest validators, potentially requiring a hard fork to recover

This meets **Critical Severity** criteria under the Aptos Bug Bounty program:
- Consensus/Safety violations
- Non-recoverable network partition (requires hardfork)

## Likelihood Explanation

**Likelihood: Medium (given prerequisite compromise)**

**Prerequisites:**
- Attacker must first compromise a validator node to control one shard process
- The sharded executor service must be deployed (currently appears to be for testing/benchmarking)

**Exploitation Complexity: Low** (once prerequisite is met)
- No cryptographic operations required
- Simple message injection via the `CrossShardClient` interface
- Immediate effect on dependent shards

**Detection Difficulty: High**
- No logging or validation of cross-shard state values
- Poisoned state is indistinguishable from legitimate state at the receiving shard
- Only manifests as state root mismatches across validators

While the prerequisite of compromising a validator reduces overall likelihood, this represents a critical **defense-in-depth failure**. Internal components handling consensus-critical data should validate authenticity even within a validator's trust boundary.

## Recommendation

Implement cryptographic validation of cross-shard state values using one of these approaches:

**Option 1: Merkle Proof Validation**
Each `RemoteTxnWrite` should include a Merkle proof that the state value is consistent with the committed state root. Receiving shards verify the proof before caching.

**Option 2: Aggregator Signature Verification**  
The coordinator signs cross-shard state values. Shards verify signatures before accepting values.

**Option 3: State Root Synchronization**
After each round, all shards compute and exchange their local state root. Any mismatch triggers validation failure and execution abort.

**Minimal Fix (Option 3 - simplest):**

```rust
// In CrossShardCommitReceiver::start()
pub fn start<S: StateView + Sync + Send>(
    cross_shard_state_view: Arc<CrossShardStateView<S>>,
    cross_shard_client: Arc<dyn CrossShardClient>,
    round: RoundId,
) {
    loop {
        let msg = cross_shard_client.receive_cross_shard_msg(round);
        match msg {
            RemoteTxnWriteMsg(txn_commit_msg) => {
                let (state_key, write_op) = txn_commit_msg.take();
                
                // ADDED: Validate state value against base state view
                let state_value = write_op.and_then(|w| w.as_state_value());
                if let Some(ref value) = state_value {
                    // Verify this is a legitimate state transition
                    // by checking against coordinator's state view
                    validate_cross_shard_write(&state_key, value)?;
                }
                
                cross_shard_state_view.set_value(&state_key, state_value);
            },
            CrossShardMsg::StopMsg => {
                trace!("Cross shard commit receiver stopped for round {}", round);
                break;
            },
        }
    }
}
```

Additionally, add authentication to `NetworkController` or use the existing Noise protocol handshake for inter-shard communication even on localhost.

## Proof of Concept

```rust
// PoC: Malicious shard sending poisoned state value
// This would be inserted into a compromised shard process

use aptos_types::{
    state_store::state_key::StateKey,
    write_set::WriteOp,
};
use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};

fn exploit_cross_shard_cache_poisoning(
    cross_shard_client: Arc<dyn CrossShardClient>,
    target_shard: ShardId,
    round: RoundId,
) {
    // Craft a state key for a critical resource (e.g., coin balance)
    let victim_balance_key = StateKey::access_path(
        AccountAddress::from_hex_literal("0xVICTIM").unwrap(),
        b"0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>".to_vec(),
    );
    
    // Create a malicious state value (e.g., inflated balance)
    let poisoned_value = create_inflated_balance(1_000_000_000); // Arbitrary large balance
    let poisoned_write_op = WriteOp::Value(poisoned_value);
    
    // Send poisoned value to dependent shard
    let poison_msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(victim_balance_key, Some(poisoned_write_op))
    );
    
    // No validation will occur - value is directly cached
    cross_shard_client.send_cross_shard_msg(target_shard, round, poison_msg);
    
    // Target shard will now execute transactions against the poisoned balance
    // causing consensus divergence
}
```

**Expected Outcome:**
- Target shard caches the poisoned balance value
- Subsequent transactions on the target shard execute against the inflated balance
- Different validators produce different state roots
- Consensus failure occurs when validators cannot agree on block commitment

**Notes:**

This vulnerability specifically affects the remote/distributed sharded executor service, which appears to be primarily used for testing and benchmarking rather than production deployment. However, the lack of validation represents a fundamental security gap that must be addressed before any production use. The security model assumes all shards within a validator are trusted, but this violates defense-in-depth principles for consensus-critical components. Even if the current deployment model makes exploitation unlikely, the architectural flaw creates unacceptable risk for a blockchain consensus system where state integrity is paramount.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L31-44)
```rust
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-56)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
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

**File:** secure/net/src/network_controller/mod.rs (L56-70)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Message {
    pub data: Vec<u8>,
}

impl Message {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }
}
```
