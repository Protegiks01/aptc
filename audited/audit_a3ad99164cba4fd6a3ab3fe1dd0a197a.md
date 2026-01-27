# Audit Report

## Title
Integer Overflow in Remote Executor Service Causes Out-of-Bounds Array Access and Node Crashes

## Summary
The remote executor service fails to validate integer fields (`shard_id` and `round`) from deserialized network messages before using them as array indices. A malicious coordinator or network peer can send crafted messages with out-of-range values, causing panic and crashing the executor service, leading to validator node unavailability.

## Finding Description

The remote sharded block executor system allows distributed execution across multiple shards. The `RemoteCrossShardClient` handles cross-shard communication by maintaining arrays of message channels indexed by `shard_id` and `round`. [1](#0-0) 

During initialization, these arrays are sized based on the actual number of shards and a constant `MAX_ALLOWED_PARTITIONING_ROUNDS` (which equals 8): [2](#0-1) [3](#0-2) 

The critical vulnerability occurs in the `send_cross_shard_msg` implementation, which directly uses deserialized `shard_id` and `round` values as array indices **without any bounds validation**: [4](#0-3) 

Similarly, the receive path has the same vulnerability: [5](#0-4) 

These integer values originate from `ShardedTxnIndex` structures embedded in transaction cross-shard dependencies, which are part of the serialized `SubBlocksForShard<AnalyzedTransaction>` received in `RemoteExecutionRequest` messages: [6](#0-5) [7](#0-6) 

The coordinator sends these messages to executor services, and they are deserialized without validation: [8](#0-7) 

When transactions with malicious cross-shard dependencies execute, the `CrossShardCommitSender` extracts `shard_id` and `round_id` values and calls `send_cross_shard_msg`: [9](#0-8) 

**Attack Path:**
1. Attacker crafts a `RemoteExecutionRequest::ExecuteBlock` message containing `SubBlocksForShard` with malicious transaction dependencies
2. The malicious `ShardedTxnIndex` contains `shard_id` ≥ number_of_shards OR `round_id` ≥ 8
3. Message is sent to the remote executor service (via compromised coordinator or network injection)
4. Executor deserializes the message without validation and begins execution
5. When transaction commits, `CrossShardCommitSender::send_remote_update_for_success` is triggered
6. Calls `send_cross_shard_msg(malicious_shard_id, malicious_round_id, message)`
7. Attempts to access `self.message_txs[malicious_shard_id][malicious_round_id]`
8. **Out-of-bounds array access causes panic**, crashing the executor service

**Secondary Vulnerability:**
A similar issue exists in the state view service where `shard_id` from deserialized `RemoteKVRequest` is used without validation: [10](#0-9) 

## Impact Explanation

**High Severity** - This vulnerability causes immediate validator node crashes, meeting the Aptos bug bounty criteria for "Validator node slowdowns" and "API crashes."

**Concrete Impact:**
- **Availability Violation**: Executor service crashes, making the shard unavailable
- **Consensus Impact**: If enough shards crash, block execution fails, potentially stalling consensus
- **Cascade Failures**: Crashed executor services may need manual restart, causing prolonged downtime
- **Denial of Service**: Attacker can repeatedly trigger crashes by sending malicious messages

This breaks the **Resource Limits** and **Deterministic Execution** invariants, as the system fails to handle malformed input gracefully and crashes instead of rejecting invalid data.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Prerequisites:**
- Ability to send messages to remote executor service endpoints
- Knowledge of message format (BCS serialization)
- No authentication shown in the code for message validation

**Factors Increasing Likelihood:**
1. **No Bounds Checking**: Code performs zero validation before array indexing
2. **Network-Exposed Service**: Remote executor service accepts network messages
3. **Straightforward Exploit**: Simply provide out-of-range integers (e.g., shard_id=1000, round=100)
4. **Insider Threat**: Compromised coordinator can easily inject malicious values
5. **Accidental Trigger**: Even bugs in legitimate code could cause this crash

**Factors Decreasing Likelihood:**
1. Remote executor service may be on internal/trusted network
2. Coordinator is typically a trusted component
3. May require knowledge of internal architecture

However, defense-in-depth principles dictate that even trusted inputs should be validated to prevent crashes.

## Recommendation

**Immediate Fix:** Add bounds validation before using integer fields as array indices.

```rust
// In remote_cross_shard_client.rs
impl CrossShardClient for RemoteCrossShardClient {
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        // Validate bounds before indexing
        if shard_id >= self.message_txs.len() {
            panic!("Invalid shard_id: {} (max: {})", shard_id, self.message_txs.len());
        }
        if round >= MAX_ALLOWED_PARTITIONING_ROUNDS {
            panic!("Invalid round: {} (max: {})", round, MAX_ALLOWED_PARTITIONING_ROUNDS);
        }
        
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }

    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        if current_round >= MAX_ALLOWED_PARTITIONING_ROUNDS {
            panic!("Invalid round: {} (max: {})", current_round, MAX_ALLOWED_PARTITIONING_ROUNDS);
        }
        
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
}
```

```rust
// In remote_state_view_service.rs
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
    let (shard_id, state_keys) = req.into();
    
    // Validate shard_id before indexing
    if shard_id >= kv_tx.len() {
        panic!("Invalid shard_id in KV request: {} (max: {})", shard_id, kv_tx.len());
    }
    
    // ... rest of function
    kv_tx[shard_id].send(message).unwrap();
}
```

**Better Approach:** Return `Result<_, Error>` instead of panicking, allowing graceful error handling and logging.

**Additional Recommendations:**
1. Add input validation at message deserialization boundaries
2. Implement authentication/authorization for network messages
3. Add comprehensive bounds checking for all array/vector indexing operations
4. Use `.get()` method instead of direct indexing where possible to avoid panics
5. Add integration tests that verify rejection of out-of-bounds values

## Proof of Concept

```rust
#[cfg(test)]
mod test_integer_overflow {
    use super::*;
    use aptos_types::block_executor::partitioner::{ShardId, RoundId};
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_out_of_bounds_shard_id() {
        // Setup: Create RemoteCrossShardClient with 4 shards
        let mut controller = NetworkController::new("test".to_string(), "127.0.0.1:8000".parse().unwrap(), 5000);
        let shard_addresses = vec![
            "127.0.0.1:8001".parse().unwrap(),
            "127.0.0.1:8002".parse().unwrap(),
            "127.0.0.1:8003".parse().unwrap(),
            "127.0.0.1:8004".parse().unwrap(),
        ];
        let client = RemoteCrossShardClient::new(&mut controller, shard_addresses);
        
        // Attack: Send message with shard_id = 100 (when only 4 shards exist)
        let malicious_shard_id: ShardId = 100;
        let valid_round: RoundId = 0;
        let msg = CrossShardMsg::StopMsg;
        
        // This will panic with "index out of bounds"
        client.send_cross_shard_msg(malicious_shard_id, valid_round, msg);
    }
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_out_of_bounds_round_id() {
        // Setup: Create RemoteCrossShardClient
        let mut controller = NetworkController::new("test".to_string(), "127.0.0.1:8000".parse().unwrap(), 5000);
        let shard_addresses = vec!["127.0.0.1:8001".parse().unwrap()];
        let client = RemoteCrossShardClient::new(&mut controller, shard_addresses);
        
        // Attack: Send message with round = 100 (when MAX is 8)
        let valid_shard_id: ShardId = 0;
        let malicious_round: RoundId = 100;
        let msg = CrossShardMsg::StopMsg;
        
        // This will panic with "index out of bounds"
        client.send_cross_shard_msg(valid_shard_id, malicious_round, msg);
    }
}
```

## Notes

This vulnerability demonstrates a critical failure in defensive programming - integer values from untrusted sources (deserialized network messages) are used directly for memory access without validation. While the remote executor service may be intended for internal use, the lack of bounds checking violates defense-in-depth principles and creates a crash vulnerability exploitable by compromised components, network attackers, or even accidental bugs in legitimate code.

The fix is straightforward but essential: validate all array indices derived from external input before use. This applies not just to the identified locations but as a general pattern throughout the codebase handling remote messages.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L14-19)
```rust
pub struct RemoteCrossShardClient {
    // The senders of cross-shard messages to other shards per round.
    message_txs: Arc<Vec<Vec<Mutex<Sender<Message>>>>>,
    // The receivers of cross shard messages from other shards per round.
    message_rxs: Arc<Vec<Mutex<Receiver<Message>>>>,
}
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L22-46)
```rust
    pub fn new(controller: &mut NetworkController, shard_addresses: Vec<SocketAddr>) -> Self {
        let mut message_txs = vec![];
        let mut message_rxs = vec![];
        // Create outbound channels for each shard per round.
        for remote_address in shard_addresses.iter() {
            let mut txs = vec![];
            for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
                let message_type = format!("cross_shard_{}", round);
                let tx = controller.create_outbound_channel(*remote_address, message_type);
                txs.push(Mutex::new(tx));
            }
            message_txs.push(txs);
        }

        // Create inbound channels for each round
        for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
            let message_type = format!("cross_shard_{}", round);
            let rx = controller.create_inbound_channel(message_type);
            message_rxs.push(Mutex::new(rx));
        }

        Self {
            message_txs: Arc::new(message_txs),
            message_rxs: Arc::new(message_rxs),
        }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** types/src/block_executor/partitioner.rs (L16-22)
```rust
pub type ShardId = usize;
pub type TxnIndex = usize;
pub type RoundId = usize;

pub static MAX_ALLOWED_PARTITIONING_ROUNDS: usize = 8;
pub static GLOBAL_ROUND_ID: usize = MAX_ALLOWED_PARTITIONING_ROUNDS + 1;
pub static GLOBAL_SHARD_ID: usize = usize::MAX;
```

**File:** types/src/block_executor/partitioner.rs (L24-29)
```rust
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ShardedTxnIndex {
    pub txn_index: TxnIndex,
    pub shard_id: ShardId,
    pub round_id: RoundId,
}
```

**File:** execution/executor-service/src/lib.rs (L44-53)
```rust
pub enum RemoteExecutionRequest {
    ExecuteBlock(ExecuteBlockCommand),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
}
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-93)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L103-134)
```rust
    fn send_remote_update_for_success(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();
        let write_set = txn_output
            .get()
            .expect("Committed output must be set")
            .write_set();

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
    }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L74-122)
```rust
    pub fn handle_message(
        message: Message,
        state_view: Arc<RwLock<Option<Arc<S>>>>,
        kv_tx: Arc<Vec<Sender<Message>>>,
    ) {
        // we don't know the shard id until we deserialize the message, so lets default it to 0
        let _timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_requests"])
            .start_timer();
        let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_req_deser"])
            .start_timer();
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

        let (shard_id, state_keys) = req.into();
        trace!(
            "remote state view service - received request for shard {} with {} keys",
            shard_id,
            state_keys.len()
        );
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
        let len = resp.len();
        let resp = RemoteKVResponse::new(resp);
        let bcs_ser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_resp_ser"])
            .start_timer();
        let resp = bcs::to_bytes(&resp).unwrap();
        drop(bcs_ser_timer);
        trace!(
            "remote state view service - sending response for shard {} with {} keys",
            shard_id,
            len
        );
        let message = Message::new(resp);
        kv_tx[shard_id].send(message).unwrap();
    }
```
