# Audit Report

## Title
Version Mismatch in ContinuousTransactionOutputsWithProof Allows State Sync Manipulation

## Summary
A malicious peer can send `ContinuousTransactionOutputsWithProof` notifications with a `LedgerInfoWithSignatures` at a higher version than the actual transaction range in `TransactionOutputListWithProofV2`. This bypasses validation, causes transactions to be applied without proper ledger info finalization, and leads to state sync failures requiring manual intervention.

## Finding Description

The state sync system fails to validate that the ledger info's version matches the last transaction version in the proof before processing. The vulnerability exists in the proof verification flow: [1](#0-0) 

When a storage service constructs a `NewTransactionOutputsWithProof` response, it combines transaction outputs with a target ledger info without validating version compatibility.

The proof verification occurs in the chunk executor: [2](#0-1) 

This verification checks that the transaction outputs exist in the accumulator at the ledger info's version. Critically, because transaction accumulators are append-only and cumulative, a proof for transactions [V_start, V_end] will successfully verify against a ledger info at version V_high where V_high > V_end. This is because the accumulator at V_high contains all transactions from [0, V_high], including [V_start, V_end].

After successful verification and transaction application, the ledger info selection logic determines whether to commit the ledger info: [3](#0-2) 

The check at line 80 (`li.version() + 1 == txn_accumulator.num_leaves()`) fails when the ledger info version exceeds the last transaction version. When this fails, the function returns `Ok(None)` without error, meaning no ledger info is committed.

**Attack Flow:**

1. Malicious peer sends:
   - `LedgerInfoWithSignatures` for version 200 (with valid 2f+1 signatures)
   - `TransactionOutputListWithProofV2` for versions [95, 105] (11 transactions)

2. The continuous syncer verifies the payload: [4](#0-3) 

3. Merkle proof verification passes because transactions [95-105] ARE provably in the accumulator at version 200

4. Transactions are applied and synced_version is updated to 105: [5](#0-4) 

5. Ledger info commit fails silently - the version check `200 + 1 == 106` is false, so `Ok(None)` is returned

6. Node state becomes inconsistent: synced to version 105 but expecting to reach version 200, with no ledger info finalized

## Impact Explanation

This vulnerability breaks the **State Consistency** critical invariant: "State transitions must be atomic and verifiable via Merkle proofs." Transactions are applied without proper ledger info finalization, creating an incomplete sync state.

**Impact Classification: Medium Severity**

Per Aptos bug bounty criteria, this qualifies as "State inconsistencies requiring intervention" (Medium severity, up to $10,000). The node:
- Applies transactions without reaching the target ledger info
- Cannot progress beyond version 105 toward the expected version 200
- Requires manual intervention or stream reset to recover
- May experience cascading sync failures if multiple malicious responses are received

If this affects validator nodes, it could be elevated to **High Severity** as it causes "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: High**

The attack requires:
1. Attacker operates a malicious storage service node OR can inject responses via network manipulation
2. Target node connects to the malicious peer for state sync
3. Attacker sends crafted responses with version mismatches

This is highly feasible because:
- Any peer in the P2P network can serve as a storage service
- No privileged access or validator collusion is required
- The attack is deterministic once the malicious response is sent
- No rate limiting or special detection prevents this

## Recommendation

Add explicit validation to ensure the ledger info version matches the last transaction version in the proof:

**Fix Location 1**: Add validation in `enqueue_chunk_by_transaction_outputs`:

```rust
fn enqueue_chunk_by_transaction_outputs(
    &self,
    txn_output_list_with_proof: TransactionOutputListWithProofV2,
    verified_target_li: &LedgerInfoWithSignatures,
    epoch_change_li: Option<&LedgerInfoWithSignatures>,
) -> Result<()> {
    // NEW: Validate version range matches ledger info
    if let Some(first_version) = txn_output_list_with_proof.get_first_output_version() {
        let num_outputs = txn_output_list_with_proof.get_num_outputs() as u64;
        let last_version = first_version.checked_add(num_outputs)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| anyhow!("Version overflow"))?;
        
        ensure!(
            verified_target_li.ledger_info().version() == last_version,
            "Ledger info version ({}) does not match proof's last version ({})",
            verified_target_li.ledger_info().version(),
            last_version
        );
    }
    
    // Existing verification continues...
    txn_output_list_with_proof.verify(
        verified_target_li.ledger_info(),
        txn_output_list_with_proof.get_first_output_version(),
    )?;
    // ... rest of function
}
```

**Fix Location 2**: Add validation in storage service response construction: [1](#0-0) 

Before constructing the response, validate that `target_ledger_info.ledger_info().version()` equals the last version in `outputs_with_proof`.

## Proof of Concept

```rust
// Reproduction steps for state sync test:
#[tokio::test]
async fn test_version_mismatch_attack() {
    // Setup: Node at version 94, expecting to sync to version 200
    let mut continuous_syncer = setup_syncer(current_version: 94);
    
    // Malicious peer constructs mismatched notification:
    let ledger_info_v200 = create_ledger_info_at_version(200); // Valid signatures
    let outputs_95_to_105 = create_transaction_outputs_with_proof(
        start: 95,
        end: 105,
        proof_version: 200 // Proof verifies against accumulator at v200
    );
    
    // Send malicious notification
    let notification = DataNotification::new(
        1,
        DataPayload::ContinuousTransactionOutputsWithProof(
            ledger_info_v200,
            outputs_95_to_105
        )
    );
    
    // Process notification - should fail but currently succeeds
    let result = continuous_syncer.process_active_stream_notifications().await;
    
    // Verify vulnerability:
    // 1. Proof verification passes (transactions 95-105 proven in accumulator at v200)
    assert!(result.is_ok());
    
    // 2. Transactions applied successfully
    assert_eq!(continuous_syncer.get_synced_version(), 105);
    
    // 3. But ledger info NOT committed (version mismatch)
    let committed_li = continuous_syncer.get_latest_ledger_info();
    assert!(committed_li.is_none() || committed_li.version() < 105);
    
    // 4. Node stuck - cannot reach target version 200
    assert!(continuous_syncer.is_stuck());
}
```

## Notes

This vulnerability specifically affects continuous state sync operations where nodes receive streaming transaction data. The root cause is the missing validation that proof version ranges must exactly match ledger info versions. The cryptographic Merkle proof verification is correct but insufficient - it proves inclusion in the accumulator but not version boundary alignment.

### Citations

**File:** state-sync/storage-service/server/src/utils.rs (L125-129)
```rust
            Ok(DataResponse::TransactionOutputsWithProof(outputs_with_proof)) => {
                DataResponse::NewTransactionOutputsWithProof((
                    outputs_with_proof,
                    target_ledger_info,
                ))
```

**File:** execution/executor/src/chunk_executor/mod.rs (L168-174)
```rust
        THREAD_MANAGER.get_exe_cpu_pool().install(|| {
            let _timer = CHUNK_OTHER_TIMERS.timer_with(&["apply_chunk__verify"]);
            txn_output_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_output_list_with_proof.get_first_output_version(),
            )
        })?;
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L72-88)
```rust
    fn maybe_select_chunk_ending_ledger_info(
        &self,
        ledger_update_output: &LedgerUpdateOutput,
        next_epoch_state: Option<&EpochState>,
    ) -> Result<Option<LedgerInfoWithSignatures>> {
        let li = self.verified_target_li.ledger_info();
        let txn_accumulator = &ledger_update_output.transaction_accumulator;

        if li.version() + 1 == txn_accumulator.num_leaves() {
            // If the chunk corresponds to the target LI, the target LI can be added to storage.
            ensure!(
                li.transaction_accumulator_hash() == txn_accumulator.root_hash(),
                "Root hash in target ledger info does not match local computation. {:?} != {:?}",
                li,
                txn_accumulator,
            );
            Ok(Some(self.verified_target_li.clone()))
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L285-298)
```rust
        let payload_start_version = self
            .verify_payload_start_version(
                notification_metadata.notification_id,
                payload_start_version,
            )
            .await?;

        // Verify the given proof ledger info
        self.verify_proof_ledger_info(
            consensus_sync_request.clone(),
            notification_metadata.notification_id,
            &ledger_info_with_signatures,
        )
        .await?;
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L376-382)
```rust
        let synced_version = payload_start_version
            .checked_add(num_transactions_or_outputs as u64)
            .and_then(|version| version.checked_sub(1)) // synced_version = start + num txns/outputs - 1
            .ok_or_else(|| Error::IntegerOverflow("The synced version has overflown!".into()))?;
        let speculative_stream_state = self.get_speculative_stream_state()?;
        speculative_stream_state.update_synced_version(synced_version);
        speculative_stream_state.maybe_update_epoch_state(ledger_info_with_signatures);
```
