# Audit Report

## Title
Mixed-Epoch SyncInfo Generation During BlockStore Rebuild Causes Consensus Liveness Failure

## Summary
The `sync_info()` function returns a `SyncInfo` containing certificates from different epochs when `rebuild()` is called during epoch transitions. The old epoch's timeout certificate is rolled over without epoch validation, violating the invariant that all certificates in a `SyncInfo` must be from the same epoch, causing other nodes to reject messages and breaking consensus liveness.

## Finding Description

The vulnerability exists in the consensus layer's state synchronization mechanism. When a node syncs to a new epoch, it incorrectly rolls over the previous epoch's timeout certificate into the new epoch's `BlockTree` without epoch validation.

**Root Cause 1 - Timeout Certificate Rollover Without Epoch Check:**

The `rebuild()` method retrieves the old timeout certificate from the in-memory BlockTree and passes it to the new tree without checking if it matches the new epoch. [1](#0-0)  This bypasses the storage-level epoch filtering that only occurs during initial startup. [2](#0-1) 

**Root Cause 2 - Missing Epoch Validation in BlockTree Constructor:**

The `BlockTree::new()` constructor validates that the window root and ordered certificate are from the same epoch [3](#0-2) , but does NOT validate the `highest_2chain_timeout_cert` epoch when it's stored. [4](#0-3) 

**Root Cause 3 - Unvalidated SyncInfo Construction:**

The `sync_info()` method constructs a `SyncInfo` without calling `verify()`, allowing mixed-epoch certificates to be packaged together. [5](#0-4) 

**Why Old Timeout Certificate Persists:**

The `insert_2chain_timeout_certificate()` method only replaces the timeout certificate if the new one has a higher round. [6](#0-5)  Since rounds restart at each epoch, an old epoch's timeout certificate at round 100 will have a higher round than a new epoch's timeout certificate at round 5, causing the old certificate to persist.

**Attack Propagation:**

1. Node operates in epoch N with timeout certificate at round R
2. Epoch N ends
3. Node receives epoch N+1 blocks via sync protocol, triggering `add_certs()` [7](#0-6) 
4. `sync_to_highest_quorum_cert()` calls `rebuild()` [8](#0-7)  which then invokes [9](#0-8) 
5. New BlockTree created with epoch N+1 blocks but epoch N timeout certificate [10](#0-9) 
6. `sync_info()` returns mixed-epoch SyncInfo
7. Node broadcasts this in consensus messages [11](#0-10) 

**Verification Failure at Recipients:**

When other nodes receive the mixed-epoch `SyncInfo`, the verification fails with "Multi epoch in SyncInfo - TC and HQC" error [12](#0-11) , causing the message to be rejected. [13](#0-12) 

**Why Storage Filtering Doesn't Protect:**

While epoch filtering exists for timeout certificates loaded from storage during startup [14](#0-13)  and [15](#0-14) , `rebuild()` retrieves the timeout certificate from in-memory BlockTree data, completely bypassing this protection.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

1. **Consensus Liveness Violation**: If the affected node is a proposer, its proposals are rejected by all validators, blocking consensus progress for that round. This constitutes a significant protocol violation.

2. **Validator Operational Issues**: The affected validator cannot participate effectively in consensus, with all its messages systematically rejected until manual intervention (restart) or a new timeout certificate with higher round is created in the current epoch.

3. **Cascading Failures**: Multiple nodes experiencing this simultaneously during epoch transitions can cause network-wide sync failures, potentially approaching Critical severity if enough validators are affected.

4. **Persistent Issue**: The rolled-over timeout certificate persists across multiple rounds until explicit replacement, not self-correcting.

This meets the Aptos bug bounty **High Severity** category for "Validator Node Slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability triggers automatically during normal network operations:

**Triggering Conditions:**
1. **Epoch Transitions**: Occur regularly in Aptos (typically daily or governance-triggered)
2. **State Sync During Transition**: Node catching up via sync when epoch changes
3. **Pre-existing Timeout Certificate**: Node has timeout certificate from old epoch

**No Attacker Required**: This is a protocol-level bug manifesting during normal operations. Common scenarios include:
- Validators restarting during epoch transitions
- Nodes experiencing temporary network issues during epoch changes
- Fast state sync operations spanning epoch boundaries

**Frequency**: Given regular epoch transitions and common validator restart/sync patterns, affected nodes likely encounter this multiple times per year in production environments.

## Recommendation

Add epoch validation in three critical locations:

1. **In `rebuild()` method**: Filter out timeout certificates that don't match the new epoch before passing to `build()`:
```rust
let prev_2chain_htc = self
    .highest_2chain_timeout_cert()
    .filter(|tc| tc.epoch() == new_epoch)
    .map(|tc| tc.as_ref().clone());
```

2. **In `BlockTree::new()` constructor**: Add epoch validation for timeout certificate similar to the existing window root validation.

3. **In `insert_2chain_timeout_certificate()` method**: Add epoch check in addition to round check to prevent cross-epoch certificate replacement.

## Proof of Concept

A Rust integration test demonstrating this vulnerability would:

1. Initialize a BlockStore in epoch N with a timeout certificate at round 100
2. Simulate epoch N ending and epoch N+1 beginning
3. Trigger `rebuild()` via `sync_to_highest_quorum_cert()` with epoch N+1 blocks
4. Call `sync_info()` and verify it contains mixed-epoch certificates (epoch N TC, epoch N+1 HQC)
5. Attempt to verify the SyncInfo and observe the "Multi epoch in SyncInfo - TC and HQC" error
6. Demonstrate that consensus messages with this SyncInfo are rejected by other validators

## Notes

This vulnerability demonstrates a critical gap between the storage-layer epoch filtering (which correctly filters timeout certificates during startup recovery) and the in-memory state management (which lacks epoch validation during runtime rebuild operations). The root cause is the assumption that in-memory state is always epoch-consistent, which is violated during epoch transitions when `rebuild()` is called.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L313-314)
```rust
        &self,
        finality_proof: WrappedLedgerInfo,
```

**File:** consensus/src/block_storage/block_store.rs (L371-373)
```rust
        let prev_2chain_htc = self
            .highest_2chain_timeout_cert()
            .map(|tc| tc.as_ref().clone());
```

**File:** consensus/src/block_storage/block_store.rs (L374-392)
```rust
        let _ = Self::build(
            root,
            root_metadata,
            blocks,
            quorum_certs,
            prev_2chain_htc,
            self.execution_client.clone(),
            Arc::clone(&self.storage),
            max_pruned_blocks_in_mem,
            Arc::clone(&self.time_service),
            self.vote_back_pressure_limit,
            self.payload_manager.clone(),
            self.order_vote_enabled,
            self.window_size,
            self.pending_blocks.clone(),
            self.pipeline_builder.clone(),
            Some(self.inner.clone()),
        )
        .await;
```

**File:** consensus/src/block_storage/block_store.rs (L564-569)
```rust
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
```

**File:** consensus/src/block_storage/block_store.rs (L680-688)
```rust
    fn sync_info(&self) -> SyncInfo {
        SyncInfo::new_decoupled(
            self.highest_quorum_cert().as_ref().clone(),
            self.highest_ordered_cert().as_ref().clone(),
            self.highest_commit_cert().as_ref().clone(),
            self.highest_2chain_timeout_cert()
                .map(|tc| tc.as_ref().clone()),
        )
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L414-416)
```rust
            highest_2chain_timeout_certificate: match highest_2chain_timeout_cert {
                Some(tc) if tc.epoch() == epoch => Some(tc),
                _ => None,
```

**File:** consensus/src/persistent_liveness_storage.rs (L530-532)
```rust
        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
```

**File:** consensus/src/persistent_liveness_storage.rs (L559-568)
```rust
        match RecoveryData::new(
            last_vote,
            ledger_recovery_data.clone(),
            blocks,
            accumulator_summary.into(),
            quorum_certs,
            highest_2chain_timeout_cert,
            order_vote_enabled,
            window_size,
        ) {
```

**File:** consensus/src/block_storage/block_tree.rs (L113-113)
```rust
        assert_eq!(window_root.epoch(), root_ordered_cert.commit_info().epoch());
```

**File:** consensus/src/block_storage/block_tree.rs (L145-145)
```rust
            highest_2chain_timeout_cert,
```

**File:** consensus/src/block_storage/sync_manager.rs (L116-120)
```rust
    pub async fn add_certs(
        &self,
        sync_info: &SyncInfo,
        mut retriever: BlockRetriever,
    ) -> anyhow::Result<()> {
```

**File:** consensus/src/block_storage/sync_manager.rs (L127-132)
```rust
        self.sync_to_highest_quorum_cert(
            sync_info.highest_quorum_cert().clone(),
            sync_info.highest_commit_cert().clone(),
            &mut retriever,
        )
        .await?;
```

**File:** consensus/src/round_manager.rs (L879-879)
```rust
        let local_sync_info = self.block_store.sync_info();
```

**File:** consensus/src/round_manager.rs (L888-896)
```rust
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
```

**File:** consensus/consensus-types/src/sync_info.rs (L148-149)
```rust
        if let Some(tc) = &self.highest_2chain_timeout_cert {
            ensure!(epoch == tc.epoch(), "Multi epoch in SyncInfo - TC and HQC");
```
