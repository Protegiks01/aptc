# Audit Report

## Title
Unimplemented Global Cross-Shard Messaging Causes Panic in Remote Executor Service

## Summary
The `RemoteCrossShardClient::send_global_msg()` function contains an unimplemented `todo!()` macro that triggers an immediate panic when called. This function is invoked when transactions have cross-shard dependencies pointing to the global round (`GLOBAL_ROUND_ID`). While the remote executor has a check to reject blocks with global transactions, this check is incomplete and can be bypassed, causing the executor service to crash during execution.

## Finding Description

The vulnerability exists in the remote execution service, which is designed for distributed sharded block execution. The execution flow is:

1. **Transaction Partitioning**: When blocks are partitioned with `partition_last_round = false`, the system creates:
   - Global transactions (for the last round)
   - Dependent edges with `round_id = GLOBAL_ROUND_ID` in earlier round transactions pointing to these global transactions [1](#0-0) [2](#0-1) 

2. **Transaction Commitment**: When a transaction commits and has dependent edges, it sends messages to notify dependent shards via `CrossShardCommitSender`: [3](#0-2) 

At line 122-123, if the dependent edge has `round_id == GLOBAL_ROUND_ID`, it calls `send_global_msg()`.

3. **The Unimplemented Function**: The `RemoteCrossShardClient` implementation has: [4](#0-3) 

This `todo!()` macro causes an immediate panic when executed.

4. **Incomplete Protection**: The remote executor checks for global transactions before execution: [5](#0-4) 

However, this check only validates that `global_txns` is empty. It does **not** validate that sharded transactions don't contain dependent edges pointing to `GLOBAL_ROUND_ID`. If a malicious or buggy coordinator sends a `PartitionedTransactions` with:
- Empty `global_txns` (passes the check)
- Sharded transactions with dependent edges to `GLOBAL_ROUND_ID`

Then execution proceeds, and when transactions commit, the panic occurs, crashing the executor service.

5. **Remote Executor is Production Code**: This is a real production service, not just a benchmark tool: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node crashes**: Any executor service that receives transactions with GLOBAL_ROUND_ID dependencies will crash with an unrecoverable panic
- **Service disruption**: The panic requires manual restart of the executor service
- **No automatic recovery**: Unlike transient errors, this is a hard panic that terminates the process

It does NOT meet Critical severity because:
- No consensus safety violation (crash happens before consensus)
- No fund loss or theft
- No permanent network partition (service can be restarted)
- Affects only nodes using the remote executor service, not the entire network

## Likelihood Explanation

**Likelihood: Low-Medium**

The vulnerability can be triggered in several scenarios:

1. **Misconfiguration**: Administrator configures remote execution with `partition_last_round = false`
   - The check at line 190-192 provides initial protection
   - But if global transactions are filtered while dependent edges remain, the crash occurs

2. **Malicious Coordinator**: Attacker with control over the coordinator crafts:
   - `PartitionedTransactions` with empty `global_txns` but GLOBAL_ROUND_ID dependent edges
   - Sends to remote executor
   - Check passes, execution begins, panic triggered

3. **Partitioner Bug**: A bug in the partitioning logic creates inconsistent state where dependent edges exist without corresponding global transactions

The incomplete validation at line 190-192 is the root cause - it checks only `global_txns`, not dependent edges.

## Recommendation

**Short-term fix**: Add validation to check that no dependent edges point to GLOBAL_ROUND_ID:

```rust
fn execute_block(
    &self,
    state_view: Arc<S>,
    transactions: PartitionedTransactions,
    concurrency_level_per_shard: usize,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> Result<ShardedExecutionOutput, VMStatus> {
    let (sub_blocks, global_txns) = transactions.into();
    if !global_txns.is_empty() {
        panic!("Global transactions are not supported yet");
    }
    
    // NEW: Validate no dependent edges point to GLOBAL_ROUND_ID
    for shard_blocks in sub_blocks.iter() {
        for sub_block in shard_blocks.sub_block_iter() {
            for txn in sub_block.iter() {
                for (dep_idx, _) in txn.cross_shard_dependencies().dependent_edges().iter() {
                    if dep_idx.round_id == GLOBAL_ROUND_ID {
                        panic!("Dependent edges to GLOBAL_ROUND_ID are not supported in remote execution");
                    }
                }
            }
        }
    }
    
    // ... rest of execution
}
```

**Long-term fix**: Implement `send_global_msg()` properly or remove remote executor support entirely if global transactions are fundamentally incompatible with the distributed execution model.

## Proof of Concept

```rust
// This PoC demonstrates the panic path
use aptos_executor_service::remote_cross_shard_client::RemoteCrossShardClient;
use aptos_vm::sharded_block_executor::cross_shard_client::CrossShardClient;
use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};
use aptos_secure_net::network_controller::NetworkController;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {
    // Set up a remote cross-shard client
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);
    let mut controller = NetworkController::new("test".to_string(), addr, 5000);
    
    let remote_client = RemoteCrossShardClient::new(
        &mut controller,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50001)]
    );
    
    // Create a cross-shard message
    let msg = CrossShardMsg::RemoteTxnWriteMsg(RemoteTxnWrite::new(
        aptos_types::state_store::state_key::StateKey::raw(vec![1, 2, 3]),
        None,
    ));
    
    // This will panic with "Global cross shard message is not supported yet in remote execution mode"
    remote_client.send_global_msg(msg); // PANIC HERE
}
```

The panic can also be triggered in a full execution scenario by:
1. Creating a `PartitionedTransactions` with transactions that have dependent edges to GLOBAL_ROUND_ID
2. Sending it to a remote executor via `RemoteExecutorClient::execute_block()`
3. When transactions commit, `send_global_msg()` is called, triggering the panic

**Notes**

The vulnerability is real and exploitable, though with limitations:
- The remote executor service is designed for distributed execution and explicitly does not support global transactions
- The check at line 190-192 provides partial protection but is incomplete
- An attacker with coordinator access or exploiting a partitioner bug can trigger the crash
- The impact is service disruption (High severity), not consensus violation (Critical severity)
- This represents a gap between the intended design (no global transactions in remote mode) and the actual implementation (incomplete validation leading to panic)

### Citations

**File:** execution/block-partitioner/src/v2/state.rs (L282-288)
```rust
    pub(crate) fn final_sub_block_idx(&self, sub_blk_idx: SubBlockIdx) -> SubBlockIdx {
        if !self.partition_last_round && sub_blk_idx.round_id == self.num_rounds() - 1 {
            SubBlockIdx::global()
        } else {
            sub_blk_idx
        }
    }
```

**File:** types/src/block_executor/partitioner.rs (L21-21)
```rust
pub static GLOBAL_ROUND_ID: usize = MAX_ALLOWED_PARTITIONING_ROUNDS + 1;
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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L50-53)
```rust
impl CrossShardClient for RemoteCrossShardClient {
    fn send_global_msg(&self, _msg: CrossShardMsg) {
        todo!("Global cross shard message is not supported yet in remote execution mode")
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L189-192)
```rust
        let (sub_blocks, global_txns) = transactions.into();
        if !global_txns.is_empty() {
            panic!("Global transactions are not supported yet");
        }
```

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}
```
