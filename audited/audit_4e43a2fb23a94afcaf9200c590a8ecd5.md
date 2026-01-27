# Audit Report

## Title
Insufficient Validation of OptQuorumStore Batch Metadata Enables Consensus Observer Desynchronization

## Summary
The `verify_opt_batches()` function only validates that batch authors are valid validators, but does not verify batch digests, transaction counts, or byte sizes. This allows malicious block proposers to include `opt_batches` with incorrect metadata (e.g., wrong `num_txns` or `num_bytes`), causing consensus observers to fail validation while consensus validators process the blocks successfully, creating a permanent divergence between validators and observers. [1](#0-0) 

## Finding Description

In the OptQuorumStore payload verification flow, there is a critical asymmetry between how inline batches and opt batches are validated:

**Inline Batches** undergo full validation where the digest is computed from transactions and verified: [2](#0-1) 

**Opt Batches** receive only minimal validation - checking if the author is a valid validator: [1](#0-0) 

This validation gap allows a malicious proposer to craft an `OptQuorumStorePayload` containing opt batches with:
1. Valid validator addresses as authors
2. Valid digests pointing to existing batches
3. **Incorrect `num_txns` or `num_bytes` values** that don't match the actual batch content

When such a block is processed by `process_optqs_payload()`: [3](#0-2) 

The malicious `BatchInfo` objects are extracted via `summary.info().clone()` at line 627 and used to fetch transactions by digest. Since transactions are fetched by digest (not by metadata), consensus validators retrieve and execute the correct transactions despite the incorrect metadata.

However, when this payload reaches consensus observers for verification, the `reconstruct_batch()` function uses `num_txns()` from the malicious `BatchInfo` to determine how many transactions to extract: [4](#0-3) 

At line 1002, the loop iterates `num_txns()` times. If this value doesn't match the actual transaction count:
- **Too high**: Fails with "Failed to extract transaction during batch reconstruction" (line 1006-1010)
- **Too low**: Leaves transactions unconsumed, failing with "transactions remaining" (line 948-954) [5](#0-4) 

This creates a **persistent divergence** where consensus validators advance while observers cannot sync.

## Impact Explanation

This vulnerability has **High Severity** impact according to Aptos bug bounty criteria:

1. **Significant Protocol Violation**: Consensus validators and observers diverge on valid blocks, violating the assumption that all nodes can verify consensus output. Observers become unable to track chain state.

2. **Validator Node/Observer Slowdowns**: Observers continuously fail to sync, requiring restarts or manual intervention. This affects:
   - Full nodes serving RPC requests
   - Indexers and analytics infrastructure
   - Third-party integrations relying on observers

3. **Breaks Deterministic Execution Invariant**: While validators execute the same transactions (by digest), the payload verification produces different results between validators and observers, violating the invariant that "all nodes must agree on block validity."

Unlike a simple DoS, this is **exploitable without self-harm**: A malicious proposer can include correctly-referenced batches (correct digest, correct transactions fetched) but with tampered metadata. Their block is accepted by validators and committed to the chain, while observers permanently reject it.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Only requires being elected as block proposer (happens regularly in validator rotation)
- **Complexity: Low**: Simply construct `OptQuorumStorePayload` with valid digests but incorrect `num_txns` values
- **Detection: Difficult**: Validators process blocks successfully; only observers notice issues through failed verification
- **No Existing Protection**: Current code has no validation to prevent this

Any malicious validator can execute this attack during their proposal turn without detection by consensus validators.

## Recommendation

Add comprehensive validation to `verify_opt_batches()` similar to `verify_inline_batches()`: [1](#0-0) 

**Recommended Fix:**
```rust
pub fn verify_opt_batches<T: TBatchInfo>(
    verifier: &ValidatorVerifier,
    opt_batches: &OptBatches<T>,
    batch_reader: &dyn BatchReader, // Need access to verify batches exist
) -> anyhow::Result<()> {
    let authors = verifier.address_to_validator_index();
    for batch_info in &opt_batches.batch_summary {
        // Existing author check
        ensure!(
            authors.contains_key(&batch_info.author()),
            "Invalid author {} for batch {}",
            batch_info.author(),
            batch_info.digest()
        );
        
        // NEW: Verify the batch exists and metadata matches
        let persisted_batch = batch_reader.get_batch_from_local(batch_info.digest())
            .context("Opt batch digest not found in batch store")?;
        
        ensure!(
            persisted_batch.num_txns() == batch_info.num_txns(),
            "Opt batch num_txns mismatch: expected {}, got {}",
            persisted_batch.num_txns(),
            batch_info.num_txns()
        );
        
        ensure!(
            persisted_batch.num_bytes() == batch_info.num_bytes(),
            "Opt batch num_bytes mismatch: expected {}, got {}",
            persisted_batch.num_bytes(),
            batch_info.num_bytes()
        );
        
        ensure!(
            persisted_batch.author() == batch_info.author(),
            "Opt batch author mismatch: expected {}, got {}",
            persisted_batch.author(),
            batch_info.author()
        );
    }
    Ok(())
}
```

Alternatively, require opt batches to be signed like inline batches to prevent metadata tampering.

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability
#[test]
fn test_malicious_opt_batch_metadata() {
    // Setup: Create a valid batch in the store
    let real_batch_info = BatchInfo::new(
        validator_a,
        batch_id,
        epoch,
        expiration,
        valid_digest,
        100, // real num_txns
        5000, // real num_bytes
        gas_bucket,
    );
    batch_store.persist(real_batch_info.clone());
    
    // Attack: Proposer creates OptQuorumStorePayload with wrong metadata
    let malicious_batch_info = BatchInfo::new(
        validator_a, // Valid author (passes verify_opt_batches)
        batch_id,
        epoch,
        expiration,
        valid_digest, // Same digest (fetches correct transactions)
        50, // WRONG num_txns (half of actual)
        2500, // WRONG num_bytes
        gas_bucket,
    );
    
    let opt_batches = OptBatches::new(vec![malicious_batch_info]);
    let payload = OptQuorumStorePayload::new(
        InlineBatches::from(vec![]),
        opt_batches,
        ProofBatches::from(vec![]),
        PayloadExecutionLimit::None,
    );
    
    // Verify: Passes validation on consensus validators
    assert!(payload.verify(&validator_verifier, &proof_cache).is_ok());
    
    // Process: Validators fetch correct transactions by digest
    let txns = process_optqs_payload(&opt_batches, batch_reader, block).await.unwrap();
    assert_eq!(txns.len(), 100); // Correct transactions fetched
    
    // Observer verification: FAILS due to metadata mismatch
    let observer_message = ConsensusObserverMessage::new_block_payload_message(
        block_info,
        transaction_payload,
    );
    
    // This fails because reconstruct_batch tries to extract 50 txns but there are 100
    assert!(observer_message.verify_payload_digests().is_err());
    
    // Result: Validators commit block, observers cannot sync
}
```

## Notes

The vulnerability stems from the design decision to treat opt batches as "optimistic" (unverified) while inline batches are fully verified. However, both types are included in committed blocks and must be verifiable by all nodes. The validation gap creates a trust boundary violation where proposers can inject invalid metadata that passes consensus but fails observer verification.

### Citations

**File:** consensus/consensus-types/src/common.rs (L541-556)
```rust
    pub fn verify_inline_batches<'a, T: TBatchInfo + 'a>(
        inline_batches: impl Iterator<Item = (&'a T, &'a Vec<SignedTransaction>)>,
    ) -> anyhow::Result<()> {
        for (batch, payload) in inline_batches {
            // TODO: Can cloning be avoided here?
            let computed_digest = BatchPayload::new(batch.author(), payload.clone()).hash();
            ensure!(
                computed_digest == *batch.digest(),
                "Hash of the received inline batch doesn't match the digest value for batch {:?}: {} != {}",
                batch,
                computed_digest,
                batch.digest()
            );
        }
        Ok(())
    }
```

**File:** consensus/consensus-types/src/common.rs (L558-572)
```rust
    pub fn verify_opt_batches<T: TBatchInfo>(
        verifier: &ValidatorVerifier,
        opt_batches: &OptBatches<T>,
    ) -> anyhow::Result<()> {
        let authors = verifier.address_to_validator_index();
        for batch in &opt_batches.batch_summary {
            ensure!(
                authors.contains_key(&batch.author()),
                "Invalid author {} for batch {}",
                batch.author(),
                batch.digest()
            );
        }
        Ok(())
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L601-637)
```rust
async fn process_optqs_payload<T: TDataInfo>(
    data_ptr: &BatchPointer<T>,
    batch_reader: Arc<dyn BatchReader>,
    block: &Block,
    ordered_authors: &[PeerId],
    additional_peers_to_request: Option<&BitVec>,
) -> ExecutorResult<Vec<SignedTransaction>> {
    let mut signers = Vec::new();
    if let Some(peers) = additional_peers_to_request {
        for i in peers.iter_ones() {
            if let Some(author) = ordered_authors.get(i) {
                signers.push(*author);
            }
        }
    }
    if let Some(author) = block.author() {
        signers.push(author);
    }

    let batches_and_responders = data_ptr
        .batch_summary
        .iter()
        .map(|summary| {
            let mut signers = signers.clone();
            signers.append(&mut summary.signers(ordered_authors));

            (summary.info().clone(), signers)
        })
        .collect();

    QuorumStorePayloadManager::request_and_wait_transactions(
        batches_and_responders,
        block.timestamp_usecs(),
        batch_reader,
    )
    .await
}
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L946-955)
```rust
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
