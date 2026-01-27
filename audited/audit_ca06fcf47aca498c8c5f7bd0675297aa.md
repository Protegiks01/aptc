# Audit Report

## Title
Unsigned Transaction Smuggling via Batch Verification Bypass Leading to Network Resource Exhaustion

## Summary
The `Batch::verify()` function in the quorum store consensus layer validates batch metadata (author, digest, transaction counts) but does NOT verify individual transaction signatures. This allows malicious validators to create and broadcast batches containing unsigned or invalid transactions that pass verification, consume network resources, occupy block space, and are only rejected during the later execution phase's signature verification step.

## Finding Description

The vulnerability exists in the batch verification flow where transaction signatures are not validated until late in the consensus pipeline:

**Step 1: Malicious Batch Creation**
A Byzantine validator creates `SignedTransaction` objects with invalid/missing signatures and packages them into a `Batch`. The batch's digest is computed as a hash of the entire payload including the invalid transactions. [1](#0-0) 

**Step 2: Batch Verification Bypass**
When other validators receive the batch via `BatchMsg`, the verification only checks metadata consistency but NOT transaction signatures: [2](#0-1) 

The verification checks payload hash matches digest (line 268), transaction counts match (line 272), and gas prices are valid (line 281), but has NO signature verification for individual transactions.

**Step 3: Batch Storage with Invalid Transactions**
The batch with invalid transactions passes verification and gets persisted with full transaction payloads: [3](#0-2) [4](#0-3) 

**Step 4: Block Proposal Inclusion**
Any validator (not just the malicious one) can include these batches in block proposals, as the proof manager pulls from the shared batch queue: [5](#0-4) 

**Step 5: Transaction Extraction**
During block materialization, transactions are extracted from batches without signature checks: [6](#0-5) [7](#0-6) 

**Step 6: Delayed Signature Verification**
Signatures are only verified in the prepare phase of the pipeline, AFTER batches have consumed network and storage resources: [8](#0-7) 

**Step 7: Execution Rejection**
Invalid transactions are marked as `SignatureVerifiedTransaction::Invalid` and immediately fail during execution: [9](#0-8) [10](#0-9) 

**Critical Gap**: Unsigned transactions successfully traverse through network broadcast → batch verification → storage → block proposal → extraction before being caught at signature verification. This wastes resources across all validators.

## Impact Explanation

**High Severity** - This vulnerability enables:

1. **Network Resource Exhaustion**: Invalid batches consume bandwidth during broadcast to all validators
2. **Storage Bloat**: Invalid transactions are persisted in batch storage across all nodes
3. **Block Space Denial of Service**: Invalid transactions occupy block space, preventing valid transactions from being included and reducing network throughput
4. **CPU Waste**: All validators must perform signature verification on invalid transactions during the prepare phase
5. **Consensus Performance Degradation**: Blocks filled with invalid transactions slow down the network

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations." While not reaching Critical severity (no fund loss or permanent network partition), it allows a Byzantine validator to significantly degrade network performance and availability.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Low Attack Complexity**: A malicious validator simply creates batches with unsigned transactions and broadcasts them through normal consensus channels
2. **No Collusion Required**: A single Byzantine validator (within the 1/3 BFT threshold) can execute this attack
3. **Difficult to Attribute**: Other validators will include these batches in proposals unknowingly, making the attack harder to trace to the source
4. **Repeatable**: The attacker can continuously broadcast invalid batches
5. **No Prevention Mechanism**: The current codebase has no signature verification in `Batch::verify()` to prevent this attack

## Recommendation

Add transaction signature verification to the `Batch::verify()` method to reject batches with invalid transactions at the earliest possible point:

```rust
pub fn verify(&self) -> anyhow::Result<()> {
    ensure!(
        self.payload.author() == self.author(),
        "Payload author doesn't match the info"
    );
    ensure!(
        self.payload.hash() == *self.digest(),
        "Payload hash doesn't match the digest"
    );
    ensure!(
        self.payload.num_txns() as u64 == self.num_txns(),
        "Payload num txns doesn't match batch info"
    );
    ensure!(
        self.payload.num_bytes() as u64 == self.num_bytes(),
        "Payload num bytes doesn't match batch info"
    );
    
    // NEW: Verify transaction signatures
    for txn in self.payload.txns() {
        ensure!(
            txn.verify_signature().is_ok(),
            "Transaction signature verification failed for txn: {}",
            txn.committed_hash()
        );
        ensure!(
            txn.gas_unit_price() >= self.gas_bucket_start(),
            "Payload gas unit price doesn't match batch info"
        );
        ensure!(
            !txn.payload().is_encrypted_variant(),
            "Encrypted transaction is not supported yet"
        );
    }
    Ok(())
}
```

**Alternative Optimization**: If signature verification is too expensive for the network message handling path, consider:
1. Performing signature verification in parallel during batch reception
2. Rate-limiting batches from validators that send invalid signatures
3. Slashing validators who consistently send batches with invalid signatures

## Proof of Concept

```rust
#[cfg(test)]
mod batch_signature_smuggling_poc {
    use super::*;
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{RawTransaction, Script, SignedTransaction, TransactionPayload},
    };

    #[test]
    fn test_batch_accepts_unsigned_transactions() {
        // Create a transaction with an INVALID signature
        let sender = AccountAddress::random();
        let raw_txn = RawTransaction::new(
            sender,
            0, // sequence number
            TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
            100_000, // max gas
            1, // gas price
            u64::MAX, // expiration
            ChainId::test(),
        );

        // Sign with one key but pretend sender is different (invalid signature)
        let wrong_key = Ed25519PrivateKey::generate_for_testing();
        let invalid_txn = SignedTransaction::new(
            raw_txn.clone(),
            wrong_key.public_key(),
            wrong_key.sign(&raw_txn).unwrap(),
        );

        // Verify the signature is actually invalid
        assert!(invalid_txn.verify_signature().is_err(), 
                "Transaction should have invalid signature");

        // Create a batch with this invalid transaction
        let batch = Batch::new(
            BatchId::new(1),
            vec![invalid_txn],
            1, // epoch
            u64::MAX, // expiration
            sender, // batch_author
            1, // gas_bucket_start
        );

        // The batch verification PASSES despite invalid transaction signature!
        assert!(batch.verify().is_ok(), 
                "Batch verification should pass even with invalid transaction signature");

        // Extract transactions - unsigned transaction is successfully retrieved
        let transactions = batch.into_transactions();
        assert_eq!(transactions.len(), 1);
        
        // This proves unsigned transactions can be smuggled through batch verification
        println!("SUCCESS: Unsigned transaction smuggled through batch verification!");
    }
}
```

**Execution Steps**:
1. Add the above test to `consensus/src/quorum_store/types.rs`
2. Run: `cargo test test_batch_accepts_unsigned_transactions`
3. Observe that batch verification succeeds despite containing a transaction with an invalid signature

This demonstrates that the `Batch::verify()` function does not validate transaction signatures, allowing unsigned transactions to be smuggled into the consensus layer.

## Notes

While mempool validates signatures before accepting transactions, this protection does not apply to remote batches received from other validators. The vulnerability specifically affects the Byzantine fault tolerance properties of the system, as it allows malicious validators to inject resource-consuming invalid transactions that survive until late-stage verification. The fix should balance security (early rejection) with performance (verification cost).

### Citations

**File:** consensus/consensus-types/src/common.rs (L715-724)
```rust
impl CryptoHash for BatchPayload {
    type Hasher = BatchPayloadHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::new();
        let bytes = bcs::to_bytes(&self).expect("Unable to serialize batch payload");
        self.num_bytes.get_or_init(|| bytes.len());
        state.update(&bytes);
        state.finish()
    }
```

**File:** consensus/consensus-types/src/common.rs (L736-738)
```rust
    pub fn into_transactions(self) -> Vec<SignedTransaction> {
        self.txns
    }
```

**File:** consensus/src/quorum_store/types.rs (L262-290)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.payload.author() == self.author(),
            "Payload author doesn't match the info"
        );
        ensure!(
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
        ensure!(
            self.payload.num_txns() as u64 == self.num_txns(),
            "Payload num txns doesn't match batch info"
        );
        ensure!(
            self.payload.num_bytes() as u64 == self.num_bytes(),
            "Payload num bytes doesn't match batch info"
        );
        for txn in self.payload.txns() {
            ensure!(
                txn.gas_unit_price() >= self.gas_bucket_start(),
                "Payload gas unit price doesn't match batch info"
            );
            ensure!(
                !txn.payload().is_encrypted_variant(),
                "Encrypted transaction is not supported yet"
            );
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/types.rs (L302-304)
```rust
    pub fn into_transactions(self) -> Vec<SignedTransaction> {
        self.payload.into_transactions()
    }
```

**File:** consensus/src/quorum_store/types.rs (L406-414)
```rust
impl<T: TBatchInfo> From<Batch<T>> for PersistedValue<T> {
    fn from(value: Batch<T>) -> Self {
        let Batch {
            batch_info,
            payload,
        } = value;
        PersistedValue::new(batch_info, Some(payload.into_transactions()))
    }
}
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L228-244)
```rust
        let mut persist_requests = vec![];
        for batch in batches.into_iter() {
            // TODO: maybe don't message batch generator if the persist is unsuccessful?
            if let Err(e) = self
                .sender_to_batch_generator
                .send(BatchGeneratorCommand::RemoteBatch(batch.clone()))
                .await
            {
                warn!("Failed to send batch to batch generator: {}", e);
            }
            persist_requests.push(batch.into());
        }
        counters::RECEIVED_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        if author != self.my_peer_id {
            counters::RECEIVED_REMOTE_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        }
        self.persist_and_send_digests(persist_requests, approx_created_ts_usecs);
```

**File:** consensus/src/quorum_store/proof_manager.rs (L103-122)
```rust
    pub(crate) fn handle_proposal_request(&mut self, msg: GetPayloadCommand) {
        let GetPayloadCommand::GetPayloadRequest(request) = msg;

        let excluded_batches: HashSet<_> = match request.filter {
            PayloadFilter::Empty => HashSet::new(),
            PayloadFilter::DirectMempool(_) => {
                unreachable!()
            },
            PayloadFilter::InQuorumStore(batches) => batches,
        };

        let (proof_block, txns_with_proof_size, cur_unique_txns, proof_queue_fully_utilized) =
            self.batch_proof_queue.pull_proofs(
                &excluded_batches,
                request.max_txns,
                request.max_txns_after_filtering,
                request.soft_max_txns_after_filtering,
                request.return_non_full,
                request.block_timestamp,
            );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L669-680)
```rust
        let sig_verification_start = Instant::now();
        let sig_verified_txns: Vec<SignatureVerifiedTransaction> = SIG_VERIFY_POOL.install(|| {
            let num_txns = input_txns.len();
            input_txns
                .into_par_iter()
                .with_min_len(optimal_min_len(num_txns, 32))
                .map(|t| Transaction::UserTransaction(t).into())
                .collect::<Vec<_>>()
        });
        counters::PREPARE_BLOCK_SIG_VERIFICATION_TIME
            .observe_duration(sig_verification_start.elapsed());
        Ok((Arc::new(sig_verified_txns), block_gas_limit))
```

**File:** types/src/transaction/signature_verified_transaction.rs (L129-138)
```rust
impl From<Transaction> for SignatureVerifiedTransaction {
    fn from(txn: Transaction) -> Self {
        match txn {
            Transaction::UserTransaction(txn) => match txn.verify_signature() {
                Ok(_) => SignatureVerifiedTransaction::Valid(Transaction::UserTransaction(txn)),
                Err(_) => SignatureVerifiedTransaction::Invalid(Transaction::UserTransaction(txn)),
            },
            _ => SignatureVerifiedTransaction::Valid(txn),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2881-2884)
```rust
        if let SignatureVerifiedTransaction::Invalid(_) = txn {
            let vm_status = VMStatus::error(StatusCode::INVALID_SIGNATURE, None);
            let discarded_output = discarded_output(vm_status.status_code());
            return Ok((vm_status, discarded_output));
```
