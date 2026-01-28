# Audit Report

## Title
V1/V2 Protocol Conversion Drops Auxiliary Info Causing Verification Failures in State Sync

## Summary
The storage service's V1/V2 conversion mechanism discards `PersistedAuxiliaryInfo` data while retaining references to it in `TransactionInfo` objects, creating an inconsistent state that causes verification to fail. This breaks state synchronization for nodes using the V1 protocol, preventing them from syncing transaction outputs.

## Finding Description

The vulnerability occurs in the round-trip conversion between V1 and V2 transaction output formats in state sync:

**Step 1: Server-side V2 → V1 conversion**

The storage service handler receives V2 data from storage and calls `consume_output_list_with_proof()` which extracts only the V1 proof and discards the auxiliary info: [1](#0-0) 

The `consume_output_list_with_proof()` method implementation: [2](#0-1) 

**Step 2: Network transmission**

The V1 data sent over the network contains `TransactionInfo` objects with `auxiliary_info_hash = Some(hash)` from the original committed data, but the actual `PersistedAuxiliaryInfo` data is lost.

**Step 3: Client-side V1 → V2 conversion**

The client converts the V1 response back to V2 using `new_from_v1()`: [3](#0-2) 

This calls the conversion method that creates dummy auxiliary infos: [4](#0-3) 

**Step 4: Verification failure**

When verification is performed during state sync in the chunk executor: [5](#0-4) 

And in the bootstrapper: [6](#0-5) 

The verification logic checks auxiliary info consistency: [7](#0-6) 

The check expects that if `PersistedAuxiliaryInfo::None`, then `auxiliary_info_hash` must be `None`. However, the transaction infos still have `auxiliary_info_hash = Some(hash)` from the original committed data, causing verification to fail.

**Why this happens:**

Normal block execution creates transactions with `PersistedAuxiliaryInfo::V1 { transaction_index }`: [8](#0-7) 

This results in `auxiliary_info_hash = Some(hash)` being set in TransactionInfo: [9](#0-8) [10](#0-9) 

## Impact Explanation

**High Severity** - This meets the criteria for significant protocol violations causing validator node failures:

1. **State Sync Failure**: Any node using V1 protocol cannot verify and apply transaction outputs, breaking state synchronization
2. **Node Availability**: Affected nodes cannot catch up to the network, reducing validator availability  
3. **Network Partition Risk**: Nodes may become isolated if they cannot sync, potentially affecting consensus participation
4. **Backward Compatibility Broken**: The V1 protocol path is completely broken for any transactions with auxiliary info (which is all normal transactions)

This aligns with High severity per Aptos bug bounty criteria as it causes significant protocol violations leading to node failures and availability issues, though it doesn't directly cause consensus safety violations or fund loss.

## Likelihood Explanation

**High Likelihood** - This occurs automatically under normal conditions:

1. **Common scenario**: Whenever `is_transaction_v2_enabled()` returns false (V1 protocol in use), as checked here: [11](#0-10) 

2. **Affects all transactions**: Normal block execution sets `PersistedAuxiliaryInfo::V1` for all transactions
3. **No attacker action required**: The bug triggers during normal state sync operations
4. **Deterministic failure**: Every V1 sync request for transaction outputs will fail verification

The V1 protocol path is explicitly supported and tested throughout the codebase, indicating it must remain functional for backward compatibility.

## Recommendation

Fix the V1 to V2 conversion to preserve auxiliary info consistency. When the server converts V2 to V1, it should either:

1. **Option 1**: Clear the `auxiliary_info_hash` in `TransactionInfo` objects when serving V1 responses, or
2. **Option 2**: Include the auxiliary info data in V1 responses through a backward-compatible extension, or
3. **Option 3**: Have the client-side conversion set auxiliary info hashes to `None` in the reconstructed `TransactionInfo` objects to match the dummy `PersistedAuxiliaryInfo::None` values

## Proof of Concept

A PoC would involve:
1. Configure a node with `enable_transaction_data_v2 = false` in the data client config
2. Request transaction outputs from a peer that has committed transactions with `PersistedAuxiliaryInfo::V1`
3. Observe the verification failure in `chunk_executor/mod.rs:170-174` with error message: "The transaction info has an auxiliary info hash: {:?}, but the persisted auxiliary info is None!"

The verification failure is deterministic and will occur on every V1 transaction output sync request for blocks containing normal transactions.

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L520-525)
```rust
        Ok(DataResponse::TransactionOutputsWithProof(
            response
                .transaction_output_list_with_proof
                .unwrap()
                .consume_output_list_with_proof(),
        ))
```

**File:** types/src/transaction/mod.rs (L2674-2681)
```rust
    /// Consumes and returns the inner transaction output list
    pub fn consume_output_list_with_proof(self) -> TransactionOutputListWithProof {
        match self {
            Self::TransactionOutputListWithAuxiliaryInfos(output_list_with_auxiliary_infos) => {
                output_list_with_auxiliary_infos.transaction_output_list_with_proof
            },
        }
    }
```

**File:** types/src/transaction/mod.rs (L2771-2781)
```rust
    fn new_from_v1(transaction_output_list_with_proof: TransactionOutputListWithProof) -> Self {
        let num_transaction_infos = transaction_output_list_with_proof
            .proof
            .transaction_infos
            .len();
        let persisted_auxiliary_infos = vec![PersistedAuxiliaryInfo::None; num_transaction_infos];

        Self {
            transaction_output_list_with_proof,
            persisted_auxiliary_infos,
        }
```

**File:** types/src/transaction/mod.rs (L2829-2837)
```rust
            match aux_info {
                PersistedAuxiliaryInfo::None
                | PersistedAuxiliaryInfo::TimestampNotYetAssignedV1 { .. } => {
                    ensure!(
                        txn_info.auxiliary_info_hash().is_none(),
                        "The transaction info has an auxiliary info hash: {:?}, \
                             but the persisted auxiliary info is None!",
                        txn_info.auxiliary_info_hash()
                    );
```

**File:** state-sync/storage-service/types/src/responses.rs (L485-487)
```rust
            DataResponse::TransactionOutputsWithProof(output_list_with_proof) => Ok(
                TransactionOutputListWithProofV2::new_from_v1(output_list_with_proof),
            ),
```

**File:** execution/executor/src/chunk_executor/mod.rs (L170-174)
```rust
            txn_output_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_output_list_with_proof.get_first_output_version(),
            )
        })?;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1294-1310)
```rust
                match transaction_outputs_with_proof.verify(
                    ledger_info_to_sync.ledger_info(),
                    Some(expected_start_version),
                ) {
                    Ok(()) => {
                        self.state_value_syncer
                            .set_transaction_output_to_sync(transaction_outputs_with_proof);
                    },
                    Err(error) => {
                        self.reset_active_stream(Some(NotificationAndFeedback::new(
                            notification_id,
                            NotificationFeedback::PayloadProofFailed,
                        )))
                        .await?;
                        return Err(Error::VerificationError(format!(
                            "Transaction outputs with proof is invalid! Error: {:?}",
                            error
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L367-370)
```rust
        let mut persisted_auxiliary_infos = auxiliary_infos
            .into_iter()
            .map(|info| info.into_persisted_info())
            .collect();
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L61-67)
```rust
                let auxiliary_info_hash = match persisted_auxiliary_info {
                    PersistedAuxiliaryInfo::None => None,
                    PersistedAuxiliaryInfo::V1 { .. } => {
                        Some(CryptoHash::hash(persisted_auxiliary_info))
                    },
                    PersistedAuxiliaryInfo::TimestampNotYetAssignedV1 { .. } => None,
                };
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L77-88)
```rust
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
                    event_root_hash,
                    state_checkpoint_hash,
                    txn_output.gas_used(),
                    txn_output
                        .status()
                        .as_kept_status()
                        .expect("Already sorted."),
                    auxiliary_info_hash,
                );
```

**File:** state-sync/aptos-data-client/src/client.rs (L1063-1076)
```rust
        let data_request = if self.is_transaction_v2_enabled() {
            DataRequest::get_transaction_output_data_with_proof(
                proof_version,
                start_version,
                end_version,
                self.get_max_response_bytes(),
            )
        } else {
            DataRequest::GetTransactionOutputsWithProof(TransactionOutputsWithProofRequest {
                proof_version,
                start_version,
                end_version,
            })
        };
```
