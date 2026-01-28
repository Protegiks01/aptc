# Audit Report

## Title
Secret Sharing Replay Attack: Stale SecretSharedKey Values Used After Consensus Reset Causing Deterministic Execution Violations

## Summary
The Aptos consensus secret sharing protocol contains a critical vulnerability where stale secret share entries persist after `sync_to_target` resets, causing validators to apply mismatched decryption keys to blocks. The root cause is that the `reset()` method in ExecutionClient fails to reset the SecretShareManager during state sync, and even when reset is called, the `secret_share_map` is never cleared. This leads to consensus divergence when the same round is processed with a different block after synchronization.

## Finding Description

This vulnerability stems from multiple implementation gaps in the secret sharing reset mechanism:

**1. SecretShareManager Not Reset During State Sync**

During `sync_to_target`, the `reset()` method only resets the rand_manager and buffer_manager, completely omitting the secret_share_manager: [1](#0-0) 

The `reset_tx_to_secret_share_manager` channel exists in the handle but is never extracted or used during `ResetSignal::TargetRound` operations. It is only used during `ResetSignal::Stop` in `end_epoch`: [2](#0-1) 

**2. Missing Cleanup of secret_share_map**

Even when `process_reset` is called on SecretShareManager, it only updates the highest_known_round and clears the block_queue, but does NOT clear the `secret_share_map`: [3](#0-2) 

**3. Self-Share Addition Blocked in PendingDecision State**

When a stale entry exists in `PendingDecision` state for a round, attempting to add a new self share for a different block at the same round fails: [4](#0-3) 

**4. No Metadata Validation When Assigning Keys**

The `set_secret_shared_key` method accepts any `SecretSharedKey` without validating that its metadata (block_id, digest) matches the actual block: [5](#0-4) 

**5. No Validation in Decryption Pipeline**

The decryption pipeline computes a fresh digest from the current block's transactions but receives a `SecretSharedKey` through the oneshot channel without validating that the key's metadata matches: [6](#0-5) 

**Attack Flow:**

1. Validator processes round R with block B1 (block_id X, digest D1)
2. Secret shares for B1 are stored in `secret_share_map[R]` in `PendingDecision` state
3. State sync triggers `sync_to_target`, calling `reset()` with `ResetSignal::TargetRound(R)`
4. Only rand_manager and buffer_manager are reset; SecretShareManager is not reset
5. Block queue is cleared, but `secret_share_map[R]` retains B1's shares
6. Round R is processed again with block B2 (block_id Y, digest D2)
7. Node computes new self share for B2 but cannot add it (PendingDecision state error)
8. Stale shares for B1 reach threshold and aggregate into `SecretSharedKey` with B1's metadata
9. This key is sent to B2's decryption pipeline via `set_secret_shared_key`
10. Decryption pipeline uses key derived from D1 with locally computed digest D2
11. Decryption fails cryptographically, transactions marked as `FailedDecryption` [7](#0-6) 

**Consensus Divergence Mechanism:**

Validators fall into two categories:
- **Clean state validators:** Successfully synced and cleared all state, process B2 correctly with fresh shares, decrypt transactions successfully
- **Stale state validators:** Have residual shares from B1, cannot add new shares, use wrong key, decryption fails

The `executable()` method returns an error for `FailedDecryption` transactions, preventing execution: [8](#0-7) 

This produces different execution outcomes and divergent state roots, preventing consensus.

## Impact Explanation

**Severity: CRITICAL** (aligns with Aptos Bug Bounty "Consensus/Safety Violations" category worth up to $1,000,000)

This vulnerability causes direct consensus safety violations:

1. **State Root Divergence:** Validators with stale secret share state produce different execution results than validators with clean state for the identical block. Encrypted transactions that should decrypt and execute successfully instead fail on affected validators, leading to different state roots.

2. **Loss of Liveness:** When a sufficient number of validators are affected, they cannot form quorum certificates on the state root. The chain halts and requires manual intervention or coordinated restart to recover.

3. **Deterministic Execution Break:** This violates Aptos's fundamental invariant that all honest validators must produce identical state roots for identical blocks. The vulnerability is particularly severe because it affects consensus correctness rather than individual transaction validity.

4. **Production Impact:** Unlike theoretical attacks, this directly impacts mainnet operations whenever validators sync after falling behind, making it a realistic threat to network stability.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will trigger in common production scenarios:

1. **Frequent State Sync Operations:** The `sync_to_target` method is regularly invoked when validators fall behind and need to catch up: [9](#0-8) 

2. **Deterministic Trigger:** Once a validator has processed a round partially, falls behind, and then syncs back to that same round with a different block, the vulnerability triggers deterministically. No cryptographic breaking or precise timing is required.

3. **No Cleanup Mechanism:** Grep searches confirm there is no pruning or garbage collection of the `secret_share_map`. Stale entries persist indefinitely until epoch end.

4. **Common Network Patterns:** Validators experiencing temporary network issues, restarts, or lagging behind frequently trigger sync operations. This is expected behavior in distributed systems.

5. **Secret Sharing Enabled:** Networks using the secret sharing feature for encrypted transactions are directly affected whenever these conditions align.

## Recommendation

Implement the following fixes:

1. **Reset SecretShareManager during sync_to_target:** Modify the `reset()` method to include resetting the secret share manager:

```rust
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager, reset_tx_to_secret_share_manager) = {
        let handle = self.handle.read();
        (
            handle.reset_tx_to_rand_manager.clone(),
            handle.reset_tx_to_buffer_manager.clone(),
            handle.reset_tx_to_secret_share_manager.clone(),
        )
    };
    
    // Reset secret share manager first
    if let Some(mut reset_tx) = reset_tx_to_secret_share_manager {
        let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
        reset_tx.send(ResetRequest {
            tx: ack_tx,
            signal: ResetSignal::TargetRound(target.commit_info().round()),
        }).await.map_err(|_| Error::ResetDropped)?;
        ack_rx.await.map_err(|_| Error::ResetDropped)?;
    }
    
    // ... rest of reset logic
}
```

2. **Clear secret_share_map on reset:** Modify `process_reset` to clear stale entries:

```rust
fn process_reset(&mut self, request: ResetRequest) {
    let ResetRequest { tx, signal } = request;
    let target_round = match signal {
        ResetSignal::Stop => 0,
        ResetSignal::TargetRound(round) => round,
    };
    self.block_queue = BlockQueue::new();
    
    // Clear stale secret share entries
    let mut store = self.secret_share_store.lock();
    store.clear_rounds_before(target_round);
    store.update_highest_known_round(target_round);
    
    self.stop = matches!(signal, ResetSignal::Stop);
    let _ = tx.send(ResetAck::default());
}
```

3. **Add metadata validation:** Validate that `SecretSharedKey` metadata matches the block before applying:

```rust
pub fn set_secret_shared_key(&mut self, round: Round, key: SecretSharedKey) {
    let offset = self.offset(round);
    if self.pending_secret_key_rounds.contains(&round) {
        let block = &self.blocks()[offset];
        
        // Validate metadata matches
        if key.metadata.block_id != block.block().id() {
            warn!("SecretSharedKey block_id mismatch for round {}", round);
            return;
        }
        
        // ... rest of logic
    }
}
```

## Proof of Concept

A proof of concept would involve:

1. Setting up a test network with secret sharing enabled
2. Starting consensus with encrypted transactions in round R with block B1
3. Allowing shares to partially aggregate (but not complete)
4. Triggering `sync_to_target` with `ResetSignal::TargetRound(R)`
5. Proposing a different block B2 for round R
6. Observing that stale shares from B1 aggregate and are applied to B2
7. Verifying decryption failures on the affected validator
8. Confirming state root divergence between validators

The test would demonstrate that validators with stale state produce different execution results than those with clean state, causing consensus failure.

## Notes

- The report's claim about "decrypt to garbage data" is technically inaccurate; the cryptographic scheme will fail to decrypt rather than produce garbage when using a mismatched key and digest. However, the core vulnerability and its consensus impact remain valid and critical.
- The vulnerability is particularly severe because it affects the consensus layer directly rather than individual transaction processing.
- The issue exists in the interaction between multiple components (reset coordination, secret sharing, and decryption pipeline), making it a systemic design flaw rather than a simple coding error.

### Citations

**File:** consensus/src/pipeline/execution_client.rs (L661-672)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Reset the rand and buffer managers to the target round
        self.reset(&target).await?;

        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
        self.execution_proxy.sync_to_target(target).await
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L674-709)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };

        if let Some(mut reset_tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx: ack_tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::RandResetDropped)?;
            ack_rx.await.map_err(|_| Error::RandResetDropped)?;
        }

        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }

        Ok(())
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L734-745)
```rust
        if let Some(mut tx) = reset_tx_to_secret_share_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop secret share manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop secret share manager");
        }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L172-184)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.secret_share_store
            .lock()
            .update_highest_known_round(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L175-176)
```rust
            SecretShareItem::PendingDecision { .. } => {
                bail!("Cannot add self share in PendingDecision state");
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L64-77)
```rust
    pub fn set_secret_shared_key(&mut self, round: Round, key: SecretSharedKey) {
        let offset = self.offset(round);
        if self.pending_secret_key_rounds.contains(&round) {
            observe_block(
                self.blocks()[offset].timestamp_usecs(),
                BlockStage::SECRET_SHARING_ADD_DECISION,
            );
            let block = &self.blocks_mut()[offset];
            if let Some(tx) = block.pipeline_tx().lock().as_mut() {
                tx.secret_shared_key_tx.take().map(|tx| tx.send(Some(key)));
            }
            self.pending_secret_key_rounds.remove(&round);
        }
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L92-119)
```rust
        let (digest, proofs_promise) =
            FPTXWeighted::digest(&digest_key, &txn_ciphertexts, encryption_round)?;

        let metadata = SecretShareMetadata::new(
            block.epoch(),
            block.round(),
            block.timestamp_usecs(),
            block.id(),
            digest.clone(),
        );

        let derived_key_share = FPTXWeighted::derive_decryption_key_share(&msk_share, &digest)?;
        derived_self_key_share_tx
            .send(Some(SecretShare::new(
                author,
                metadata.clone(),
                derived_key_share,
            )))
            .expect("must send properly");

        // TODO(ibalajiarun): improve perf
        let proofs = FPTXWeighted::eval_proofs_compute_all(&proofs_promise, &digest_key);

        let maybe_decryption_key = secret_shared_key_rx
            .await
            .expect("decryption key should be available");
        // TODO(ibalajiarun): account for the case where decryption key is not available
        let decryption_key = maybe_decryption_key.expect("decryption key should be available");
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L140-145)
```rust
                } else {
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| p.into_failed_decryption(eval_proof).expect("must happen"))
                        .expect("must exist");
                }
```

**File:** types/src/transaction/encrypted_payload.rs (L75-80)
```rust
    pub fn executable(&self) -> Result<TransactionExecutable> {
        let Self::Decrypted { executable, .. } = self else {
            bail!("Transaction is encrypted");
        };
        Ok(executable.clone())
    }
```
