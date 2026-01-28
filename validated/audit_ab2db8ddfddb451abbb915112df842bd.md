# Audit Report

## Title
Consensus Liveness Failure: SecretShareManager Panics on Blocks Without Encrypted Transactions

## Summary
When secret sharing is enabled at the epoch level, the `SecretShareManager` unconditionally expects all blocks to have encrypted transactions requiring secret share derivation. However, blocks without encrypted transactions cause the decryption pipeline to drop the secret share channel sender without sending, resulting in a panic when `SecretShareManager` awaits the future. This causes validator node crashes and consensus liveness failure.

## Finding Description

The vulnerability occurs through the interaction of four components in the consensus execution pipeline:

**1. Decryption Pipeline Early Exit Without Notification**

When `decrypt_encrypted_txns` processes a block, it partitions transactions into encrypted and unencrypted types. If no encrypted transactions exist, the function returns early without sending any value through the `derived_self_key_share_tx` channel, causing the oneshot sender to be dropped. [1](#0-0) 

**2. Future Awaiting Dropped Channel Receiver**

The `secret_sharing_derive_self_fut` is constructed to await the receiver end of the oneshot channel. When the sender is dropped without sending, the receiver's `await` returns `Err(RecvError)`, which is then mapped to a `TaskError` through the error handler. [2](#0-1) 

**3. Unchecked Panic in SecretShareManager**

The `process_incoming_block` method uses two chained `.expect()` calls on the future result. The first `.expect()` expects the future to succeed, but when it receives the `TaskError` from the dropped channel, it immediately panics with the message "Decryption share computation is expected to succeed". [3](#0-2) 

**4. Unconditional Block Processing**

All blocks received by `SecretShareManager` are unconditionally processed through `process_incoming_blocks`, which calls `process_incoming_block` for each block without checking whether the blocks contain encrypted transactions. All block rounds are added to `pending_secret_key_rounds`. [4](#0-3) 

**Attack Scenario:**

1. Secret sharing is enabled at the epoch level via `SecretShareConfig` (legitimate configuration)
2. `SecretShareManager` is instantiated and started during epoch initialization [5](#0-4) 

3. All consensus blocks are routed to the SecretShareManager through the coordinator [6](#0-5) 

4. A block proposer creates a block containing only regular transactions (no encrypted ones)
5. All validators receive this block through consensus
6. Each validator's execution pipeline processes the block:
   - `decrypt_encrypted_txns` detects no encrypted transactions and returns early
   - The `derived_self_key_share_tx` sender is dropped without sending
   - `secret_sharing_derive_self_fut` awaits the receiver and gets `RecvError`
   - This is converted to `TaskError`
7. SecretShareManager awaits this future in `process_incoming_block`
8. The first `.expect()` on line 137 fails and the validator node **panics**
9. All validators crash simultaneously, causing **total consensus liveness failure**

This breaks the fundamental liveness guarantee of the consensus protocol: the network must be able to make progress under normal operation. The vulnerability requires no Byzantine behavior - it's triggered by a legitimate block that contains only regular transactions, which is the common case.

## Impact Explanation

This is a **Critical Severity** vulnerability meeting the Aptos bug bounty criteria for "Total Loss of Liveness/Network Availability":

- **Complete Network Halt**: When any validator proposes a block without encrypted transactions (the common case), all validators crash simultaneously when processing that block
- **Consensus Liveness Failure**: The network cannot commit any blocks until all nodes are manually restarted and the issue is fixed
- **No Byzantine Requirement**: This is triggered during normal, honest operation - no malicious actors needed
- **Deterministic Failure**: Every validator will crash with 100% certainty when processing such a block
- **Operational Severity**: Requires immediate manual intervention across all validators to restore network operation

The impact aligns with the Critical severity category: "Network halts due to protocol bug, all validators unable to progress".

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will occur with certainty under these conditions:

1. **Secret sharing is enabled**: This is a legitimate feature configuration that can be enabled at the epoch level through on-chain configuration
2. **Any block without encrypted transactions**: Most blocks in normal operation do not contain encrypted transactions, as transaction encryption is an optional feature

The vulnerability is **deterministic and requires no special privileges**:
- Any validator can propose a block without encrypted transactions during their turn
- No Byzantine collusion is needed
- No complex timing or state manipulation is required
- The crash occurs during normal consensus operation with regular transactions
- All validators will crash identically when processing the same block

This makes it an extremely severe operational risk. Even without malicious intent, the network will crash as soon as secret sharing is enabled and any normal block (without encrypted transactions) is proposed.

## Recommendation

The fix requires modifying the decryption pipeline to always send a value through the `derived_self_key_share_tx` channel, even when no encrypted transactions exist:

**Option 1: Send None when no encrypted transactions**
In `decrypt_encrypted_txns`, before the early return on line 49-54, send `None` through the channel:

```rust
if encrypted_txns.is_empty() {
    // Send None to indicate no encrypted transactions
    let _ = derived_self_key_share_tx.send(None);
    return Ok((
        unencrypted_txns,
        max_txns_from_block_to_execute,
        block_gas_limit,
    ));
}
```

**Option 2: Modify SecretShareManager to handle missing shares**
Alternatively, modify `process_incoming_block` to gracefully handle the case where secret sharing is not needed by checking if the future result is `None` instead of using `.expect()`.

## Proof of Concept

While a complete PoC would require setting up a full Aptos testnet with secret sharing enabled, the vulnerability can be demonstrated through the code path:

1. Deploy Aptos network with `SecretShareConfig` enabled
2. Propose a block containing only regular `SignedTransaction` entries (no encrypted payloads)
3. Observe all validators crash with panic message: "Decryption share computation is expected to succeed"

The code evidence provided in the citations clearly demonstrates the panic will occur when:
- `encrypted_txns.is_empty()` is true (line 49)
- The function returns early (lines 50-54)
- The sender is dropped without sending
- `process_incoming_block` awaits the future and calls `.expect()` (line 137)

### Citations

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L44-54)
```rust
        let (encrypted_txns, unencrypted_txns): (Vec<_>, Vec<_>) = input_txns
            .into_iter()
            .partition(|txn| txn.is_encrypted_txn());

        // TODO: figure out handling of
        if encrypted_txns.is_empty() {
            return Ok((
                unencrypted_txns,
                max_txns_from_block_to_execute,
                block_gas_limit,
            ));
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L447-455)
```rust
        let (derived_self_key_share_tx, derived_self_key_share_rx) = oneshot::channel();
        let secret_sharing_derive_self_fut = spawn_shared_fut(
            async move {
                derived_self_key_share_rx
                    .await
                    .map_err(|_| TaskError::from(anyhow!("commit proof tx cancelled")))
            },
            Some(&mut abort_handles),
        );
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L112-130)
```rust
    async fn process_incoming_blocks(&mut self, blocks: OrderedBlocks) {
        let rounds: Vec<u64> = blocks.ordered_blocks.iter().map(|b| b.round()).collect();
        info!(rounds = rounds, "Processing incoming blocks.");

        let mut share_requester_handles = Vec::new();
        let mut pending_secret_key_rounds = HashSet::new();
        for block in blocks.ordered_blocks.iter() {
            let handle = self.process_incoming_block(block).await;
            share_requester_handles.push(handle);
            pending_secret_key_rounds.insert(block.round());
        }

        let queue_item = QueueItem::new(
            blocks,
            Some(share_requester_handles),
            pending_secret_key_rounds,
        );
        self.block_queue.push_back(queue_item);
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L132-138)
```rust
    async fn process_incoming_block(&self, block: &PipelinedBlock) -> DropGuard {
        let futures = block.pipeline_futs().expect("pipeline must exist");
        let self_secret_share = futures
            .secret_sharing_derive_self_fut
            .await
            .expect("Decryption share computation is expected to succeed")
            .expect("Must not be None");
```

**File:** consensus/src/pipeline/execution_client.rs (L268-308)
```rust
    fn make_secret_sharing_manager(
        &self,
        epoch_state: &Arc<EpochState>,
        config: SecretShareConfig,
        secret_sharing_msg_rx: aptos_channel::Receiver<AccountAddress, IncomingSecretShareRequest>,
        highest_committed_round: u64,
        network_sender: &Arc<NetworkSender>,
    ) -> (
        UnboundedSender<OrderedBlocks>,
        futures_channel::mpsc::UnboundedReceiver<OrderedBlocks>,
        UnboundedSender<ResetRequest>,
    ) {
        let (ordered_block_tx, ordered_block_rx) = unbounded::<OrderedBlocks>();
        let (secret_ready_block_tx, secret_ready_block_rx) = unbounded::<OrderedBlocks>();

        let (reset_tx_to_secret_share_manager, reset_secret_share_manager_rx) =
            unbounded::<ResetRequest>();

        let secret_share_manager = SecretShareManager::new(
            self.author,
            epoch_state.clone(),
            config,
            secret_ready_block_tx,
            network_sender.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );

        tokio::spawn(secret_share_manager.start(
            ordered_block_rx,
            secret_sharing_msg_rx,
            reset_secret_share_manager_rx,
            self.bounded_executor.clone(),
            highest_committed_round,
        ));

        (
            ordered_block_tx,
            secret_ready_block_rx,
            reset_tx_to_secret_share_manager,
        )
```

**File:** consensus/src/pipeline/execution_client.rs (L311-365)
```rust
    fn make_coordinator(
        mut rand_manager_input_tx: UnboundedSender<OrderedBlocks>,
        mut rand_ready_block_rx: UnboundedReceiver<OrderedBlocks>,
        mut secret_share_manager_input_tx: UnboundedSender<OrderedBlocks>,
        mut secret_ready_block_rx: UnboundedReceiver<OrderedBlocks>,
    ) -> (
        UnboundedSender<OrderedBlocks>,
        futures_channel::mpsc::UnboundedReceiver<OrderedBlocks>,
    ) {
        let (ordered_block_tx, mut ordered_block_rx) = unbounded::<OrderedBlocks>();
        let (mut ready_block_tx, ready_block_rx) = unbounded::<OrderedBlocks>();

        tokio::spawn(async move {
            let mut inflight_block_tracker: HashMap<
                HashValue,
                (
                    OrderedBlocks,
                    /* rand_ready */ bool,
                    /* secret ready */ bool,
                ),
            > = HashMap::new();
            loop {
                let entry = select! {
                    Some(ordered_blocks) = ordered_block_rx.next() => {
                        let _ = rand_manager_input_tx.send(ordered_blocks.clone()).await;
                        let _ = secret_share_manager_input_tx.send(ordered_blocks.clone()).await;
                        let first_block_id = ordered_blocks.ordered_blocks.first().expect("Cannot be empty").id();
                        inflight_block_tracker.insert(first_block_id, (ordered_blocks, false, false));
                        inflight_block_tracker.entry(first_block_id)
                    },
                    Some(rand_ready_block) = rand_ready_block_rx.next() => {
                        let first_block_id = rand_ready_block.ordered_blocks.first().expect("Cannot be empty").id();
                        inflight_block_tracker.entry(first_block_id).and_modify(|result| {
                            result.1 = true;
                        })
                    },
                    Some(secret_ready_block) = secret_ready_block_rx.next() => {
                        let first_block_id = secret_ready_block.ordered_blocks.first().expect("Cannot be empty").id();
                        inflight_block_tracker.entry(first_block_id).and_modify(|result| {
                            result.2 = true;
                        })
                    },
                };
                let Entry::Occupied(o) = entry else {
                    unreachable!("Entry must exist");
                };
                if o.get().1 && o.get().2 {
                    let (_, (ordered_blocks, _, _)) = o.remove_entry();
                    let _ = ready_block_tx.send(ordered_blocks).await;
                }
            }
        });

        (ordered_block_tx, ready_block_rx)
    }
```
