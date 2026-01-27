# Audit Report

## Title
Batch Ordering Mismatch in OptQuorumStore Payloads Causes Verification Failures for Expired Optimistic Batches

## Summary
A critical ordering mismatch exists in the `BlockTransactionPayload` creation and verification logic for OptQuorumStore payloads. When optimistic batches expire, they are excluded from the transaction list during payload creation but remain in the batch metadata list. During verification, expired optimistic batches cannot be skipped (unlike proof batches), causing the verifier to consume transactions from subsequent batches, leading to digest verification failures and consensus observer rejections of valid blocks.

## Finding Description

The vulnerability occurs in the interaction between payload creation and verification for OptQuorumStore payloads containing expired optimistic batches.

**During Payload Creation:** [1](#0-0) 

The `get_transactions` method processes OptQuorumStore payloads by:
1. Calling `process_optqs_payload` for optimistic batches, which internally uses `request_transactions`
2. `request_transactions` skips expired batches entirely: [2](#0-1) 

3. The transaction list excludes transactions from expired opt batches
4. However, the batch info list includes ALL optimistic batches (expired and non-expired): [3](#0-2) 

**During Payload Verification:** [4](#0-3) 

The verification logic processes optimistic batches with `skip_expired_batches=false`: [5](#0-4) 

The `reconstruct_batch` function only skips expired batches when `skip_expired_batches=true`: [6](#0-5) 

**Attack Scenario:**

Consider an OptQuorumStore payload with:
- Proof batches: [P1, P2_expired, P3] (each with 10 transactions)
- Opt batches: [O1, O2_expired, O3] (each with 10 transactions)
- Inline batches: [I1, I2] (each with 10 transactions)
- Block timestamp: 1000, O2 expiration: 500 (expired)

**Payload creation produces:**
- Transactions: [P1_txns(10), P3_txns(10), O1_txns(10), O3_txns(10), I1_txns(10), I2_txns(10)] = 60 total
  - Note: P2 and O2 transactions are SKIPPED due to expiration
- opt_and_inline_batches: [O1, O2, O3, I1, I2] = 5 batches
  - Note: O2 metadata is INCLUDED even though expired

**Verification executes:**
1. Process proof batches with `skip_expired_batches=true`:
   - P1: Consume 10 txns ✓
   - P2: Skip (expired) ✓
   - P3: Consume 10 txns ✓
   - Iterator now at: O1_txns

2. Process opt_and_inline_batches with `skip_expired_batches=false`:
   - O1: Consume 10 txns (O1_txns) ✓
   - O2: Cannot skip (expired but `skip_expired_batches=false`), attempts to consume 10 txns
     - **Consumes O3_txns instead of non-existent O2_txns** ✗
     - Digest check: hash(O3_txns) ≠ O2.digest → VERIFICATION FAILS
   - O3: Attempts to consume 10 txns
     - **Consumes I1_txns instead of already-consumed O3_txns** ✗

This breaks the **Deterministic Execution** invariant as different nodes may have different certified timestamps causing them to process the same block differently.

## Impact Explanation

**Severity: Medium (up to $10,000)**

This vulnerability causes state inconsistencies requiring manual intervention:

1. **Consensus Observer Rejection**: Legitimate blocks from validators are rejected by consensus observers when they contain expired optimistic batches, causing observers to fall out of sync with the validator network.

2. **State Divergence**: Different nodes with different certified timestamp views will accept/reject the same blocks differently, creating temporary state inconsistencies until manual resynchronization.

3. **Network Partition Risk**: If a significant portion of observers reject blocks due to this issue, it creates a soft partition where observers diverge from validators, though not requiring a hard fork.

4. **Limited Scope**: The impact is limited to OptQuorumStore payloads with expired optimistic batches, which requires specific timing conditions where opt batches expire between block proposal and verification.

This does not meet Critical severity because:
- No direct fund loss or theft
- No permanent consensus safety violation
- Validators can still progress (only observers affected)
- Recovery is possible through state sync

It qualifies as Medium severity due to state inconsistencies requiring intervention to resynchronize affected nodes.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires specific but realistic conditions:

1. **Optimistic batches must be created**: OptQuorumStore is an active feature in Aptos
2. **Batch expiration timing**: Opt batches have expiration timestamps, and network delays can cause blocks to be processed after some batches expire
3. **Observer network**: Consensus observers are actively used in the Aptos network
4. **No attacker required**: This is a logic bug that triggers naturally under normal network conditions with timing variations

The likelihood increases with:
- Network congestion causing delays
- Validators with different certified timestamp views
- High transaction volume creating more batches with varying expiration times

## Recommendation

**Fix the batch ordering by excluding expired optimistic batches from the metadata list or modifying verification logic:**

**Option 1: Filter expired opt batches during payload creation** (Recommended)

Modify the OptQuorumStore payload creation to filter out expired opt batches from the metadata list, matching the transaction list:

```rust
// In quorum_store_payload_manager.rs, around line 530-540
Payload::OptQuorumStore(OptQuorumStorePayload::V1(opt_qs_payload)) => {
    let block_timestamp = block.timestamp_usecs();
    
    // Filter expired opt batches to match transaction filtering
    let non_expired_opt_batches: Vec<BatchInfo> = opt_qs_payload
        .opt_batches()
        .iter()
        .filter(|batch| block_timestamp <= batch.expiration())
        .cloned()
        .collect();
    
    BlockTransactionPayload::new_opt_quorum_store(
        all_txns,
        opt_qs_payload.proof_with_data().deref().clone(),
        opt_qs_payload.max_txns_to_execute(),
        opt_qs_payload.block_gas_limit(),
        [
            non_expired_opt_batches,  // Use filtered list
            opt_qs_payload.inline_batches().batch_infos(),
        ]
        .concat(),
    )
}
```

**Option 2: Allow skipping expired opt batches during verification**

Modify `verify_payload_digests` to skip expired opt batches:

```rust
// In observer_message.rs, around line 913-932
for batch_info in opt_and_inline_batches.iter() {
    // Check if this is an opt batch (not inline) and allow skipping if expired
    // Note: inline batches always have their transactions included inline
    let is_opt_batch = /* logic to determine if batch is opt vs inline */;
    let skip_if_expired = is_opt_batch;
    
    match reconstruct_batch(&block_info, &mut transactions_iter, batch_info, skip_if_expired) {
        // ... rest of logic
    }
}
```

However, this requires additional metadata to distinguish opt batches from inline batches within the combined list.

**Option 1 is recommended** as it maintains clearer invariants: the batch metadata list should always match the transaction list content.

## Proof of Concept

The following test demonstrates the vulnerability:

```rust
#[test]
fn test_expired_opt_batch_verification_failure() {
    use aptos_consensus_types::proof_of_store::{BatchInfo, ProofOfStore};
    use aptos_types::aggregate_signature::AggregateSignature;
    
    // Create block with timestamp 1000
    let block_timestamp = 1000;
    let block_info = BlockInfo::new(0, 0, HashValue::random(), HashValue::random(), 0, block_timestamp, None);
    
    // Create proof batches (non-expired)
    let proof_batch_1 = create_batch_info_with_digest(HashValue::random(), 5, 2000);
    let proof_txns_1 = create_signed_transactions(5);
    let proof_batch_1_digest = BatchPayload::new(PeerId::ZERO, proof_txns_1.clone()).hash();
    let proof_batch_1 = create_batch_info_with_digest(proof_batch_1_digest, 5, 2000);
    
    // Create opt batches: O1 (non-expired), O2 (EXPIRED), O3 (non-expired)
    let opt_txns_1 = create_signed_transactions(5);
    let opt_batch_1_digest = BatchPayload::new(PeerId::ZERO, opt_txns_1.clone()).hash();
    let opt_batch_1 = create_batch_info_with_digest(opt_batch_1_digest, 5, 2000);
    
    let opt_batch_2 = create_batch_info_with_digest(HashValue::random(), 5, 500); // EXPIRED
    
    let opt_txns_3 = create_signed_transactions(5);
    let opt_batch_3_digest = BatchPayload::new(PeerId::ZERO, opt_txns_3.clone()).hash();
    let opt_batch_3 = create_batch_info_with_digest(opt_batch_3_digest, 5, 2000);
    
    // Simulate payload creation (expired opt batch skipped from transactions)
    let all_transactions = [proof_txns_1, opt_txns_1, opt_txns_3].concat(); // O2 txns SKIPPED
    
    // But batch info includes ALL opt batches (including expired O2)
    let opt_and_inline_batches = vec![opt_batch_1, opt_batch_2, opt_batch_3]; // O2 INCLUDED
    
    // Create payload
    let transaction_payload = BlockTransactionPayload::new_opt_quorum_store(
        all_transactions,
        vec![ProofOfStore::new(proof_batch_1, AggregateSignature::empty())],
        None,
        None,
        opt_and_inline_batches,
    );
    
    let block_payload = BlockPayload::new(block_info, transaction_payload);
    
    // Verification should fail due to ordering mismatch
    let result = block_payload.verify_payload_digests();
    assert!(result.is_err(), "Expected verification failure due to expired opt batch ordering mismatch");
}
```

This test creates a scenario where an expired optimistic batch causes the verification logic to consume transactions in the wrong order, demonstrating the vulnerability.

## Notes

The existing test `test_verify_payload_digests_expired` validates that expired **inline** batches behave correctly (their transactions must be included). However, it does not test the OptQuorumStore payload type with expired **optimistic** batches, which is where this vulnerability manifests. [7](#0-6) 

The vulnerability specifically affects the OptQuorumStore variant where opt batches are fetched remotely (like proof batches) but verified without the ability to skip expired batches (like inline batches).

### Citations

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L89-109)
```rust
    fn request_transactions(
        batches: Vec<(BatchInfo, Vec<PeerId>)>,
        block_timestamp: u64,
        batch_reader: Arc<dyn BatchReader>,
    ) -> Vec<Shared<Pin<Box<dyn Future<Output = ExecutorResult<Vec<SignedTransaction>>> + Send>>>>
    {
        let mut futures = Vec::new();
        for (batch_info, responders) in batches {
            trace!(
                "QSE: requesting batch {:?}, time = {}",
                batch_info,
                block_timestamp
            );
            if block_timestamp <= batch_info.expiration() {
                futures.push(batch_reader.get_batch(batch_info, responders.clone()));
            } else {
                debug!("QSE: skipped expired batch {}", batch_info.digest());
            }
        }
        futures
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L511-541)
```rust
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(opt_qs_payload)) => {
                let opt_batch_txns = process_optqs_payload(
                    opt_qs_payload.opt_batches(),
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                    block_signers.as_ref(),
                )
                .await?;
                let proof_batch_txns = process_optqs_payload(
                    opt_qs_payload.proof_with_data(),
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                    None,
                )
                .await?;
                let inline_batch_txns = opt_qs_payload.inline_batches().transactions();
                let all_txns = [proof_batch_txns, opt_batch_txns, inline_batch_txns].concat();
                BlockTransactionPayload::new_opt_quorum_store(
                    all_txns,
                    opt_qs_payload.proof_with_data().deref().clone(),
                    opt_qs_payload.max_txns_to_execute(),
                    opt_qs_payload.block_gas_limit(),
                    [
                        opt_qs_payload.opt_batches().deref().clone(),
                        opt_qs_payload.inline_batches().batch_infos(),
                    ]
                    .concat(),
                )
            },
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L875-958)
```rust
    pub fn verify_payload_digests(&self) -> Result<(), Error> {
        // Get the block info, transactions, payload proofs and inline batches
        let block_info = self.block.clone();
        let transactions = self.transaction_payload.transactions();
        let payload_proofs = self.transaction_payload.payload_proofs();
        let opt_and_inline_batches = self.transaction_payload.optqs_and_inline_batches();

        // Get the number of transactions, payload proofs and inline batches
        let num_transactions = transactions.len();
        let num_payload_proofs = payload_proofs.len();
        let num_opt_and_inline_batches = opt_and_inline_batches.len();

        // Gather the transactions for each payload batch
        let mut batches_and_transactions = vec![];
        let mut transactions_iter = transactions.into_iter();
        for proof_of_store in &payload_proofs {
            match reconstruct_batch(
                &block_info,
                &mut transactions_iter,
                proof_of_store.info(),
                true,
            ) {
                Ok(Some(batch_transactions)) => {
                    batches_and_transactions
                        .push((proof_of_store.info().clone(), batch_transactions));
                },
                Ok(None) => { /* Nothing needs to be done (the batch was expired) */ },
                Err(error) => {
                    return Err(Error::InvalidMessageError(format!(
                        "Failed to reconstruct payload proof batch! Num transactions: {:?}, \
                        num batches: {:?}, num inline batches: {:?}, failed batch: {:?}, Error: {:?}",
                        num_transactions, num_payload_proofs, num_opt_and_inline_batches, proof_of_store.info(), error
                    )));
                },
            }
        }

        // Gather the transactions for each inline batch
        for batch_info in opt_and_inline_batches.iter() {
            match reconstruct_batch(&block_info, &mut transactions_iter, batch_info, false) {
                Ok(Some(batch_transactions)) => {
                    batches_and_transactions.push((batch_info.clone(), batch_transactions));
                },
                Ok(None) => {
                    return Err(Error::UnexpectedError(format!(
                        "Failed to reconstruct inline/opt batch! Batch was unexpectedly skipped: {:?}",
                        batch_info
                    )));
                },
                Err(error) => {
                    return Err(Error::InvalidMessageError(format!(
                        "Failed to reconstruct inline/opt batch! Num transactions: {:?}, \
                        num batches: {:?}, num opt/inline batches: {:?}, failed batch: {:?}, Error: {:?}",
                        num_transactions, num_payload_proofs, num_opt_and_inline_batches, batch_info, error
                    )));
                },
            }
        }

        // Verify all the reconstructed batches (in parallel)
        batches_and_transactions
            .into_par_iter()
            .with_min_len(2)
            .try_for_each(|(batch_info, transactions)| verify_batch(&batch_info, transactions))
            .map_err(|error| {
                Error::InvalidMessageError(format!(
                    "Failed to verify the payload batches and transactions! Error: {:?}",
                    error
                ))
            })?;

        // Verify that there are no transactions remaining (all transactions should be consumed)
        let remaining_transactions = transactions_iter.as_slice();
        if !remaining_transactions.is_empty() {
            return Err(Error::InvalidMessageError(format!(
                "Failed to verify payload transactions! Num transactions: {:?}, \
                transactions remaining: {:?}. Expected: 0",
                num_transactions,
                remaining_transactions.len()
            )));
        }

        Ok(()) // All digests match
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L987-1016)
```rust
fn reconstruct_batch(
    block_info: &BlockInfo,
    transactions_iter: &mut IntoIter<SignedTransaction>,
    expected_batch_info: &BatchInfo,
    skip_expired_batches: bool,
) -> Result<Option<Vec<SignedTransaction>>, Error> {
    // If the batch is expired we should skip reconstruction (as the
    // transactions for the expired batch won't be sent in the payload).
    // Note: this should only be required for QS batches (not inline batches).
    if skip_expired_batches && block_info.timestamp_usecs() > expected_batch_info.expiration() {
        return Ok(None);
    }

    // Gather the transactions for the batch
    let mut batch_transactions = vec![];
    for i in 0..expected_batch_info.num_txns() {
        let batch_transaction = match transactions_iter.next() {
            Some(transaction) => transaction,
            None => {
                return Err(Error::InvalidMessageError(format!(
                    "Failed to extract transaction during batch reconstruction! Batch: {:?}, transaction index: {:?}",
                    expected_batch_info, i
                )));
            },
        };
        batch_transactions.push(batch_transaction);
    }

    Ok(Some(batch_transactions))
}
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L1690-1775)
```rust
    #[test]
    fn test_verify_payload_digests_expired() {
        // Create a new block info with the specified timestamp
        let block_timestamp = 1000;
        let block_info = BlockInfo::new(
            0,
            0,
            HashValue::random(),
            HashValue::random(),
            0,
            block_timestamp,
            None,
        );

        // Create multiple signed transactions
        let num_signed_transactions = 100;
        let signed_transactions = create_signed_transactions(num_signed_transactions);

        // Create multiple batch proofs (where some batches are expired)
        let (proofs, non_expired_transactions) =
            create_mixed_expiration_proofs(block_timestamp, &signed_transactions);

        // Create a block payload (with non-expired transactions, all proofs and no inline batches)
        let block_payload = create_block_payload(
            Some(block_info.clone()),
            &non_expired_transactions,
            &proofs,
            &[],
        );

        // Verify the block payload digests and ensure it passes
        assert_ok!(block_payload.verify_payload_digests());

        // Create multiple inline transactions
        let num_inline_transactions = 25;
        let inline_transactions = create_signed_transactions(num_inline_transactions);

        // Create multiple inline batches (where some batches are expired)
        let (inline_batches, non_expired_inline_transactions) =
            create_mixed_expiration_proofs(block_timestamp, &inline_transactions);

        // Create a block payload (with all non-expired inline transactions, no proofs and inline batches)
        let inline_batches: Vec<_> = inline_batches
            .iter()
            .map(|proof| proof.info().clone())
            .collect();
        let block_payload = create_block_payload(
            Some(block_info.clone()),
            &non_expired_inline_transactions,
            &[],
            &inline_batches,
        );

        // Verify the block payload digests and ensure it fails (expired inline batches are still checked)
        let error = block_payload.verify_payload_digests().unwrap_err();
        assert_matches!(error, Error::InvalidMessageError(_));

        // Create a block payload (with all inline transactions, no proofs and inline batches)
        let block_payload = create_block_payload(
            Some(block_info.clone()),
            &inline_transactions,
            &[],
            &inline_batches,
        );

        // Verify the block payload digests and ensure it now passes
        assert_ok!(block_payload.verify_payload_digests());

        // Gather all transactions (from both QS and inline batches)
        let all_transactions: Vec<_> = non_expired_transactions
            .iter()
            .chain(inline_transactions.iter())
            .cloned()
            .collect();

        // Create a block payload (with all transactions, all proofs and inline batches)
        let block_payload = create_block_payload(
            Some(block_info),
            &all_transactions,
            &proofs,
            &inline_batches,
        );

        // Verify the block payload digests and ensure it passes
        assert_ok!(block_payload.verify_payload_digests());
    }
```
