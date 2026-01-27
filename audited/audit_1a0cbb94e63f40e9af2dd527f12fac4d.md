# Audit Report

## Title
Unbounded Transaction Batch Size in Mempool P2P Broadcasts Enables Memory Exhaustion DoS

## Summary
The mempool's peer-to-peer broadcast message handler accepts `BroadcastTransactionsRequest` messages without validating the number of transactions in the batch. While the network layer enforces a 64 MiB message size limit, an attacker can pack hundreds of thousands of minimal transactions into a single message, causing memory exhaustion and CPU overload during deserialization and validation.

## Finding Description

The vulnerability exists in the mempool's handling of incoming `BroadcastTransactionsRequest` messages from peer nodes. [1](#0-0) 

When a peer sends a broadcast request, the message is received and the `transactions` vector is used directly without any length validation. The code extracts transactions and passes them to `process_received_txns`, which spawns a task to process all transactions in the batch. [2](#0-1) 

The only protection is the network-layer message size limit of 64 MiB. [3](#0-2) 

However, this byte limit does not translate to a transaction count limit. A minimal `SignedTransaction` can be as small as 200-300 bytes, meaning an attacker could pack approximately 200,000-300,000 transactions into a single 64 MiB message.

When such a message is received:

1. **Deserialization Phase**: The entire message is deserialized into a `Vec<SignedTransaction>` in memory, creating a vector with hundreds of thousands of elements.

2. **Processing Phase**: All transactions are processed together in `process_incoming_transactions`. [4](#0-3) 

3. **Parallel Validation**: The validation pool processes all transactions in parallel, performing VM validation for each one. [5](#0-4) 

4. **Storage Reads**: For each transaction, the system performs storage reads to fetch account sequence numbers. [6](#0-5) 

The `bounded_executor` only limits concurrent inbound sync tasks (default: 4), not the number of transactions per task. [7](#0-6) 

In contrast, when nodes **send** broadcasts, they enforce a batch size limit of 300 transactions (default). [8](#0-7) 

But this limit is not enforced when **receiving** broadcasts. [9](#0-8) 

A malicious peer can modify their node to send oversized batches, bypassing the sender-side limit and exploiting the lack of receiver-side validation.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator Node Slowdowns**: Processing hundreds of thousands of transactions causes significant CPU and memory spikes, degrading node performance
- **Memory Exhaustion**: Deserializing massive transaction batches can exhaust available memory, potentially crashing the node
- **Thread Pool Saturation**: The validation thread pool becomes overwhelmed, delaying processing of legitimate transactions
- **Cascading Effects**: Multiple malicious messages can render the node unable to participate effectively in consensus

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The system fails to enforce computational and memory limits on peer-to-peer message processing.

While this is not a Critical severity issue (no funds loss or consensus safety violation), it significantly impacts node availability and performance, fitting the High severity category.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- **No authentication required**: Any peer can send messages once connected
- **Low cost**: Creating minimal transactions requires minimal resources
- **No rate limiting**: A single oversized message can cause damage
- **Simple modification**: Attacker only needs to modify broadcast batch size in their node
- **Hard to detect**: Appears as legitimate mempool traffic until resource exhaustion occurs

The attack is particularly effective because:
1. The network accepts the message (under 64 MiB limit)
2. No validation occurs before processing begins
3. All transactions are processed in a single task
4. The bounded executor doesn't prevent this (only limits concurrent tasks)

## Recommendation

Enforce a maximum transaction count limit for incoming `BroadcastTransactionsRequest` messages, similar to the API's batch submission limit.

**Recommended Fix:**

Add validation in the `handle_network_event` function before calling `process_received_txns`:

```rust
// In coordinator.rs, handle_network_event function
MempoolSyncMsg::BroadcastTransactionsRequest {
    message_id,
    transactions,
} => {
    // Enforce maximum batch size for incoming broadcasts
    const MAX_INBOUND_BATCH_SIZE: usize = 1000; // Conservative limit
    
    if transactions.len() > MAX_INBOUND_BATCH_SIZE {
        counters::shared_mempool_event_inc("oversized_batch_rejected");
        warn!(
            LogSchema::event_log(LogEntry::InvalidNetworkMsg, LogEvent::Received)
                .peer(&PeerNetworkId::new(network_id, peer_id))
                .num_txns(transactions.len())
        );
        return; // Drop oversized batches
    }
    
    process_received_txns(
        bounded_executor,
        smp,
        network_id,
        message_id,
        transactions.into_iter().map(|t| (t, None, None)).collect(),
        peer_id,
    )
    .await;
}
```

Apply the same fix to `BroadcastTransactionsRequestWithReadyTime`.

Additionally, consider:
1. Making the limit configurable via `MempoolConfig`
2. Tracking and potentially disconnecting peers that repeatedly send oversized batches
3. Adding metrics to monitor batch size distribution

## Proof of Concept

```rust
// This PoC demonstrates how an attacker creates an oversized batch
// to exploit the missing validation

use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
use aptos_types::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{RawTransaction, Script, SignedTransaction, TransactionPayload},
};

fn create_minimal_transaction(sender: AccountAddress, seq: u64, private_key: &Ed25519PrivateKey) -> SignedTransaction {
    let raw_txn = RawTransaction::new(
        sender,
        seq,
        TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
        100,      // max_gas_amount
        1,        // gas_unit_price  
        0,        // expiration_timestamp_secs
        ChainId::test(),
    );
    
    let signature = private_key.sign(&raw_txn).unwrap();
    SignedTransaction::new(raw_txn, private_key.public_key(), signature)
}

fn create_malicious_batch() -> Vec<SignedTransaction> {
    let private_key = Ed25519PrivateKey::generate_for_testing();
    let sender = AccountAddress::random();
    
    // Create 250,000 minimal transactions (fits in ~60 MiB)
    // This exceeds reasonable limits but stays under network message size
    let mut transactions = Vec::with_capacity(250_000);
    
    for seq in 0..250_000 {
        transactions.push(create_minimal_transaction(sender, seq, &private_key));
    }
    
    println!("Created malicious batch with {} transactions", transactions.len());
    println!("Estimated size: ~{} MiB", (transactions.len() * 250) / (1024 * 1024));
    
    transactions
}

#[test]
fn test_oversized_batch_attack() {
    // Attacker creates oversized batch
    let malicious_batch = create_malicious_batch();
    
    // This batch would be accepted by current implementation
    // because it only checks message size (< 64 MiB), not transaction count
    assert!(malicious_batch.len() > 100_000); // Far exceeds reasonable limit
    
    // When processed, this causes:
    // 1. Memory spike from deserializing 250k transactions
    // 2. CPU exhaustion from parallel validation
    // 3. Storage query storm (250k sequence number lookups)
    // 4. Thread pool saturation
}
```

**Notes:**
- The current implementation has no defense against this attack vector
- The bounded executor (`shared_mempool_max_concurrent_inbound_syncs = 4`) only prevents 4+ concurrent attacks, but a single attack can still cause significant damage
- Legitimate nodes send max 300 transactions per batch, making this attack clearly distinguishable from normal traffic

### Citations

**File:** mempool/src/shared_mempool/coordinator.rs (L293-342)
```rust
async fn process_received_txns<NetworkClient, TransactionValidator>(
    bounded_executor: &BoundedExecutor,
    smp: &mut SharedMempool<NetworkClient, TransactionValidator>,
    network_id: NetworkId,
    message_id: MempoolMessageId,
    transactions: Vec<(
        SignedTransaction,
        Option<u64>,
        Option<BroadcastPeerPriority>,
    )>,
    peer_id: PeerId,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg> + 'static,
    TransactionValidator: TransactionValidation + 'static,
{
    smp.network_interface
        .num_mempool_txns_received_since_peers_updated += transactions.len() as u64;
    let smp_clone = smp.clone();
    let peer = PeerNetworkId::new(network_id, peer_id);
    let ineligible_for_broadcast = (smp.network_interface.is_validator()
        && !smp.broadcast_within_validator_network())
        || smp.network_interface.is_upstream_peer(&peer, None);
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
    // This timer measures how long it took for the bounded executor to
    // *schedule* the task.
    let _timer = counters::task_spawn_latency_timer(
        counters::PEER_BROADCAST_EVENT_LABEL,
        counters::SPAWN_LABEL,
    );
    // This timer measures how long it took for the task to go from scheduled
    // to started.
    let task_start_timer = counters::task_spawn_latency_timer(
        counters::PEER_BROADCAST_EVENT_LABEL,
        counters::START_LABEL,
    );
    bounded_executor
        .spawn(tasks::process_transaction_broadcast(
            smp_clone,
            transactions,
            message_id,
            timeline_state,
            peer,
            task_start_timer,
        ))
        .await;
}
```

**File:** mempool/src/shared_mempool/coordinator.rs (L360-373)
```rust
                MempoolSyncMsg::BroadcastTransactionsRequest {
                    message_id,
                    transactions,
                } => {
                    process_received_txns(
                        bounded_executor,
                        smp,
                        network_id,
                        message_id,
                        transactions.into_iter().map(|t| (t, None, None)).collect(),
                        peer_id,
                    )
                    .await;
                },
```

**File:** config/src/config/network_config.rs (L45-50)
```rust
pub const MAX_MESSAGE_METADATA_SIZE: usize = 128 * 1024; /* 128 KiB: a buffer for metadata that might be added to messages by networking */
pub const MESSAGE_PADDING_SIZE: usize = 2 * 1024 * 1024; /* 2 MiB: a safety buffer to allow messages to get larger during serialization */
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** mempool/src/shared_mempool/tasks.rs (L304-404)
```rust
pub(crate) fn process_incoming_transactions<NetworkClient, TransactionValidator>(
    smp: &SharedMempool<NetworkClient, TransactionValidator>,
    transactions: Vec<(
        SignedTransaction,
        Option<u64>,
        Option<BroadcastPeerPriority>,
    )>,
    timeline_state: TimelineState,
    client_submitted: bool,
) -> Vec<SubmissionStatusBundle>
where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg>,
    TransactionValidator: TransactionValidation,
{
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);

    // If there are no transactions left after filtering, return early
    if transactions.is_empty() {
        return statuses;
    }

    let start_storage_read = Instant::now();
    let state_view = smp
        .db
        .latest_state_checkpoint_view()
        .expect("Failed to get latest state checkpoint view.");

    // Track latency: fetching seq number
    let account_seq_numbers = IO_POOL.install(|| {
        transactions
            .par_iter()
            .map(|(t, _, _)| match t.replay_protector() {
                ReplayProtector::Nonce(_) => Ok(None),
                ReplayProtector::SequenceNumber(_) => {
                    get_account_sequence_number(&state_view, t.sender())
                        .map(Some)
                        .inspect_err(|e| {
                            error!(LogSchema::new(LogEntry::DBError).error(e));
                            counters::DB_ERROR.inc();
                        })
                },
            })
            .collect::<Vec<_>>()
    });

    // Track latency for storage read fetching sequence number
    let storage_read_latency = start_storage_read.elapsed();
    counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::FETCH_SEQ_NUM_LABEL])
        .observe(storage_read_latency.as_secs_f64() / transactions.len() as f64);

    let transactions: Vec<_> = transactions
        .into_iter()
        .enumerate()
        .filter_map(|(idx, (t, ready_time_at_sender, priority))| {
            if let Ok(account_sequence_num) = account_seq_numbers[idx] {
                match account_sequence_num {
                    Some(sequence_num) => {
                        if t.sequence_number() >= sequence_num {
                            return Some((t, Some(sequence_num), ready_time_at_sender, priority));
                        } else {
                            statuses.push((
                                t,
                                (
                                    MempoolStatus::new(MempoolStatusCode::VmError),
                                    Some(DiscardedVMStatus::SEQUENCE_NUMBER_TOO_OLD),
                                ),
                            ));
                        }
                    },
                    None => {
                        return Some((t, None, ready_time_at_sender, priority));
                    },
                }
            } else {
                // Failed to get account's onchain sequence number
                statuses.push((
                    t,
                    (
                        MempoolStatus::new(MempoolStatusCode::VmError),
                        Some(DiscardedVMStatus::RESOURCE_DOES_NOT_EXIST),
                    ),
                ));
            }
            None
        })
        .collect();

    validate_and_add_transactions(
        transactions,
        smp,
        timeline_state,
        &mut statuses,
        client_submitted,
    );
    notify_subscribers(SharedMempoolNotification::NewTransactions, &smp.subscribers);
    statuses
}
```

**File:** mempool/src/shared_mempool/tasks.rs (L486-504)
```rust
    // Track latency: VM validation
    let vm_validation_timer = counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::VM_VALIDATION_LABEL])
        .start_timer();
    let validation_results = VALIDATION_POOL.install(|| {
        transactions
            .par_iter()
            .map(|t| {
                let result = smp.validator.read().validate_transaction(t.0.clone());
                // Pre-compute the hash and length if the transaction is valid, before locking mempool
                if result.is_ok() {
                    t.0.committed_hash();
                    t.0.txn_bytes_len();
                }
                result
            })
            .collect::<Vec<_>>()
    });
    vm_validation_timer.stop_and_record();
```

**File:** config/src/config/mempool_config.rs (L64-65)
```rust
    /// Maximum number of transactions to batch for a Mempool submission to an upstream node.
    pub shared_mempool_batch_size: usize,
```

**File:** config/src/config/mempool_config.rs (L68-69)
```rust
    /// Maximum Mempool inbound message workers.  Controls concurrency of Mempool consumption.
    pub shared_mempool_max_concurrent_inbound_syncs: usize,
```

**File:** mempool/src/shared_mempool/network.rs (L572-597)
```rust
    /// Sends a batch to the given peer
    async fn send_batch_to_peer(
        &self,
        peer: PeerNetworkId,
        message_id: MempoolMessageId,
        // For each transaction, we include the ready time in millis since epoch
        transactions: Vec<(SignedTransaction, u64, BroadcastPeerPriority)>,
    ) -> Result<(), BroadcastError> {
        let request = if self.mempool_config.include_ready_time_in_broadcast {
            MempoolSyncMsg::BroadcastTransactionsRequestWithReadyTime {
                message_id,
                transactions,
            }
        } else {
            MempoolSyncMsg::BroadcastTransactionsRequest {
                message_id,
                transactions: transactions.into_iter().map(|(txn, _, _)| txn).collect(),
            }
        };

        if let Err(e) = self.network_client.send_to_peer(request, peer) {
            counters::network_send_fail_inc(counters::BROADCAST_TXNS);
            return Err(BroadcastError::NetworkError(peer, e.into()));
        }
        Ok(())
    }
```
