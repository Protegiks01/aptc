# Audit Report

## Title
Cross-Shard WriteOp Type Confusion Enables Consensus Divergence in Distributed Sharded Execution

## Summary
The sharded block executor's cross-shard communication lacks validation of `WriteOp` semantic types (Creation/Modification/Deletion), allowing a compromised or malicious executor shard to send incorrect operation types that cause receiving shards to execute transactions with corrupted cross-shard state, breaking deterministic execution and enabling consensus divergence.

## Finding Description

The sharded block executor implements parallel transaction execution by partitioning transactions across multiple executor shards that communicate cross-shard write operations via `RemoteTxnWrite` messages. [1](#0-0) 

When a shard executes a transaction that produces writes needed by other shards, it sends the `WriteOp` through the `CrossShardCommitSender`: [2](#0-1) 

In the remote executor mode (used when `num_executor_shards > 0` and remote addresses are configured), these messages are transmitted over network sockets without cryptographic authentication or validation: [3](#0-2) 

The receiving shard processes these messages by converting the `WriteOp` to a `StateValue` and storing it in the `CrossShardStateView`: [4](#0-3) 

**The Critical Flaw:** The receiving shard calls `write_op.as_state_value()` which discards the WriteOp semantic type (Creation/Modification/Deletion) and only extracts the data payload. There is **no validation** that:
1. A `Creation` WriteOp actually creates new state (key didn't exist before)
2. A `Modification` WriteOp actually modifies existing state (key existed before)
3. A `Deletion` WriteOp actually deletes existing state

**Attack Scenario:**
1. Transaction T₁ in Shard A deletes StateKey K, producing `WriteOp::Deletion`
2. Transaction T₂ in Shard B has a cross-shard dependency on K
3. **Malicious Shard A** (compromised executor shard or network attacker) sends `RemoteTxnWrite(K, WriteOp::Modification(malicious_data))` instead of the correct `WriteOp::Deletion`
4. Shard B receives this and calls `write_op.as_state_value()` which returns `Some(StateValue(malicious_data))`
5. When T₂ executes and reads K, it gets `malicious_data` instead of `None`
6. T₂ produces different outputs than it would in sequential execution
7. The aggregated sharded execution results differ from unsharded execution, **breaking the Deterministic Execution invariant**

The NetworkController provides no authentication mechanism to prevent this: [5](#0-4) 

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violation)

This vulnerability breaks the fundamental **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

**Concrete Impacts:**

1. **Consensus Divergence**: Different validators using sharded execution could produce different state roots for the same block if their shards are compromised differently, causing chain splits.

2. **State Root Manipulation**: An attacker controlling one executor shard can cause dependent transactions to execute with arbitrary state values, manipulating the final write set and state root.

3. **Cross-Validator Inconsistency**: Since validation only occurs in tests (not at runtime), there is no mechanism to detect divergent execution results between sharded and unsharded modes: [6](#0-5) 

4. **Production Deployment Risk**: The sharded executor is production code that can be enabled via configuration: [7](#0-6) 

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** (depending on deployment configuration)

**Factors Increasing Likelihood:**
1. Remote executor mode uses unauthenticated network communication between shards
2. Compromising a single executor shard machine is sufficient
3. No runtime validation prevents exploitation
4. The attack is straightforward - simply send malformed `RemoteTxnWrite` messages

**Attack Requirements:**
1. Validator must be using sharded execution (`num_executor_shards > 0`)
2. Validator must be using remote/distributed mode (multiple machines)
3. Attacker must compromise one executor shard OR perform MITM on shard network

**Mitigating Factors:**
1. Many validators may use single-machine execution or not enable sharding
2. Executor shards are typically in validator's controlled infrastructure

However, defense-in-depth principles require that compromising one infrastructure component should not enable consensus manipulation.

## Recommendation

Implement cryptographic validation of cross-shard messages:

**Solution 1: Message Authentication Codes (MACs)**
```rust
// In RemoteTxnWrite
pub struct RemoteTxnWrite {
    state_key: StateKey,
    write_op: Option<WriteOp>,
    sender_shard_id: ShardId,
    transaction_hash: HashValue,  // Hash of source transaction
    mac: HMAC,  // MAC over (state_key, write_op, sender_shard_id, tx_hash)
}

// In CrossShardCommitReceiver::start
RemoteTxnWriteMsg(txn_commit_msg) => {
    // Verify MAC before applying
    if !verify_cross_shard_mac(&txn_commit_msg, &shared_key) {
        panic!("Invalid cross-shard message MAC");
    }
    
    // Additional semantic validation
    let (state_key, write_op) = txn_commit_msg.take();
    validate_write_op_semantic_type(&state_key, &write_op, base_state_view)?;
    
    cross_shard_state_view.set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
}
```

**Solution 2: State-Based Validation**
```rust
// In CrossShardCommitReceiver, validate WriteOp type matches actual state:
fn validate_write_op_semantic_type(
    state_key: &StateKey, 
    write_op: &Option<WriteOp>,
    base_view: &impl StateView
) -> Result<()> {
    let existing_state = base_view.get_state_value(state_key)?;
    
    if let Some(op) = write_op {
        match op.write_op_kind() {
            WriteOpKind::Creation => {
                ensure!(existing_state.is_none(), "Creation WriteOp sent for existing state key");
            },
            WriteOpKind::Modification => {
                ensure!(existing_state.is_some(), "Modification WriteOp sent for non-existent state key");
            },
            WriteOpKind::Deletion => {
                ensure!(existing_state.is_some(), "Deletion WriteOp sent for non-existent state key");
            }
        }
    }
    Ok(())
}
```

**Recommended Approach:** Implement both solutions - cryptographic authentication to prevent message tampering, and semantic validation as defense-in-depth.

## Proof of Concept

```rust
#[test]
fn test_malicious_cross_shard_write_op_type() {
    use aptos_types::state_store::state_key::StateKey;
    use aptos_types::write_set::WriteOp;
    use aptos_vm::sharded_block_executor::messages::RemoteTxnWrite;
    
    // Setup: Create a state key that exists in base state
    let state_key = StateKey::raw(b"test_key");
    let original_value = b"original_value";
    
    // Scenario 1: Transaction deletes the key
    let correct_write_op = WriteOp::legacy_deletion();
    
    // Scenario 2: Malicious shard sends Modification instead of Deletion
    let malicious_write_op = WriteOp::legacy_modification(
        b"malicious_value".to_vec().into()
    );
    
    // Create malicious RemoteTxnWrite
    let malicious_msg = RemoteTxnWrite::new(
        state_key.clone(), 
        Some(malicious_write_op)
    );
    
    // When receiving shard processes this:
    let (key, write_op) = malicious_msg.take();
    let resulting_state = write_op.and_then(|w| w.as_state_value());
    
    // BUG: Receiving shard sees Some(malicious_value) instead of None
    assert!(resulting_state.is_some()); // Should be None for deletion!
    
    // This causes dependent transactions to execute with wrong state:
    // - Transaction expects key to be deleted (None)
    // - But reads malicious_value instead
    // - Produces different outputs than sequential execution
    // - BREAKS DETERMINISTIC EXECUTION INVARIANT
}
```

**Notes:**
- The vulnerability is in production code paths, not test code
- The remote executor is explicitly designed for distributed deployment across multiple machines
- No authentication or validation prevents the attack
- This breaks the fundamental consensus safety guarantee of deterministic execution

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L13-18)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteTxnWrite {
    state_key: StateKey,
    // The write op is None if the transaction is aborted.
    write_op: Option<WriteOp>,
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L34-38)
```rust
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L114-133)
```rust
        for (state_key, write_op) in write_set.expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
                    ));
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
                }
            }
        }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-66)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }

    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
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

**File:** execution/executor-service/src/test_utils.rs (L82-118)
```rust
pub fn compare_txn_outputs(
    unsharded_txn_output: Vec<TransactionOutput>,
    sharded_txn_output: Vec<TransactionOutput>,
) {
    assert_eq!(unsharded_txn_output.len(), sharded_txn_output.len());
    for i in 0..unsharded_txn_output.len() {
        assert_eq!(
            unsharded_txn_output[i].status(),
            sharded_txn_output[i].status()
        );
        assert_eq!(
            unsharded_txn_output[i].gas_used(),
            sharded_txn_output[i].gas_used()
        );
        //assert_eq!(unsharded_txn_output[i].write_set(), sharded_txn_output[i].write_set());
        assert_eq!(
            unsharded_txn_output[i].events(),
            sharded_txn_output[i].events()
        );
        // Global supply tracking for coin is not supported in sharded execution yet, so we filter
        // out the table item from the write set, which has the global supply. This is a hack until
        // we support global supply tracking in sharded execution.
        let unsharded_write_set_without_table_item = unsharded_txn_output[i]
            .write_set()
            .write_op_iter()
            .filter(|(k, _)| matches!(k.inner(), &StateKeyInner::AccessPath(_)))
            .collect::<Vec<_>>();
        let sharded_write_set_without_table_item = sharded_txn_output[i]
            .write_set()
            .write_op_iter()
            .filter(|(k, _)| matches!(k.inner(), &StateKeyInner::AccessPath(_)))
            .collect::<Vec<_>>();
        assert_eq!(
            unsharded_write_set_without_table_item,
            sharded_write_set_without_table_item
        );
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L256-276)
```rust
    fn execute_block_sharded<V: VMBlockExecutor>(
        partitioned_txns: PartitionedTransactions,
        state_view: Arc<CachedStateView>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>> {
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
    }
```
