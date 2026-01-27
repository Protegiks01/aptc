# Audit Report

## Title
Missing Batch Payload Verification Allows Unreliable Audit Trails in Admin Service

## Summary
The `dump_blocks()` function in the admin service can return incorrect transactions for blocks when the quorum store database contains batches with payloads that don't match their digests. This occurs because batches received from the network are never verified against their claimed digest before being persisted, and no verification occurs when retrieving batches from the database for audit trail generation.

## Finding Description

The vulnerability exists in the batch request/storage flow and manifests in the admin service's block dumping functionality:

**1. Batch Receipt Without Verification**

When a node requests a batch from a peer, the response is accepted without verifying that the payload matches the requested digest: [1](#0-0) 

The batch is immediately converted to transactions without any digest verification, even though the `Batch` type provides a `verify_with_digest()` method for this purpose: [2](#0-1) 

**2. Unverified Batch Persistence**

The unverified payload is then persisted by creating a new `PersistedValue` with the original `batch_info` (containing the digest from the block's proof) but the unverified payload from the network: [3](#0-2) 

This breaks the critical invariant that a batch's digest must equal the cryptographic hash of its payload: [4](#0-3) 

**3. Admin Service Returns Unverified Data**

When `dump_blocks()` retrieves batches from the database, it trusts the stored data without verification: [5](#0-4) 

The `extract_txns_from_block()` function simply looks up batches by digest and returns their payloads: [6](#0-5) 

**Attack Scenario (Database Corruption or Software Bug):**

1. A software bug or database corruption causes a batch to be stored with digest X but incorrect payload [D, E, F] instead of the original [A, B, C]
2. Alternatively, a peer responds with a corrupted batch (due to its own database issues) which is accepted without verification
3. The corrupted batch is persisted to the local quorum store database
4. Later, when an operator runs the admin service dump to investigate issues or generate audit trails, `dump_blocks()` returns the incorrect transactions [D, E, F] for any block referencing digest X
5. Audit trails become unreliable, post-incident forensics is compromised, and debugging efforts are misled

## Impact Explanation

This vulnerability represents a **High severity** issue under the "Significant protocol violations" category. While it doesn't directly cause consensus divergence during normal operation, it severely compromises the integrity of audit mechanisms:

1. **Audit Trail Integrity**: The admin service is used for debugging, forensics, and compliance auditing. Returning incorrect transactions for blocks makes these functions unreliable
2. **Post-Incident Investigation**: After security incidents, accurate transaction logs are critical for understanding what occurred. Corrupted audit trails could hide evidence or mislead investigators  
3. **Compliance and Transparency**: Blockchain audit trails are often required for regulatory compliance. Unreliable data undermines trust in the system

The vulnerability doesn't require byzantine behavior - simple database corruption, storage bugs, or software errors could trigger it, making it a realistic threat to operational integrity.

## Likelihood Explanation

The likelihood is **Medium to High** because:

1. **No Validation**: There are multiple code paths that create and persist `PersistedValue` objects without verifying the digest matches the payload
2. **Database Corruption**: Storage systems can experience corruption, especially under adverse conditions (crashes, disk errors, bugs)
3. **Software Bugs**: Bugs in batch handling code could inadvertently store mismatched digest/payload pairs
4. **Network Issues**: Corrupted data from peers (due to their own issues) is accepted without verification

The vulnerability is not theoretical - the complete absence of verification means any corruption or bug that causes digest/payload mismatch will propagate unchecked.

## Recommendation

**Add digest verification at critical points:**

1. **Verify batches received from network** - In `batch_requester.rs`, verify the batch before using its payload:

```rust
Ok(BatchResponse::Batch(batch)) => {
    counters::RECEIVED_BATCH_RESPONSE_COUNT.inc();
    // Verify batch matches requested digest
    if let Err(e) = batch.verify_with_digest(digest) {
        counters::RECEIVED_BATCH_VERIFICATION_FAILED_COUNT.inc();
        debug!("QS: batch verification failed, digest:{}, error:{:?}", digest, e);
        continue; // Try next peer
    }
    let payload = batch.into_transactions();
    return Ok(payload);
}
```

2. **Verify on database retrieval** - When retrieving batches from the database, verify the digest matches the payload, at least in the admin service code path

3. **Add integrity checks** - Periodically verify stored batches have valid digest/payload mappings as part of database health checks

## Proof of Concept

```rust
// Reproduction steps (pseudo-code):

// 1. Create a valid batch with digest X and payload [txn1, txn2]
let batch = Batch::new(batch_id, vec![txn1, txn2], epoch, expiration, author, gas);
let correct_digest = *batch.digest(); // Digest X

// 2. Simulate corruption: Create PersistedValue with wrong payload
let corrupted_payload = vec![txn3, txn4]; // Different transactions!
let persisted = PersistedValue::new(
    batch.batch_info().clone(), // Contains digest X
    Some(corrupted_payload),    // But wrong payload!
);

// 3. Save to database (no verification performed)
quorum_store_db.save_batch(persisted).unwrap();

// 4. Later, admin service dump retrieves it
let all_batches = quorum_store_db.get_all_batches()?;
let retrieved = all_batches.get(&correct_digest).unwrap();

// 5. Returns wrong transactions!
assert_eq!(retrieved.payload(), &Some(vec![txn3, txn4])); // ✗ Wrong data
// Should have been vec![txn1, txn2]

// The admin dump will show txn3, txn4 for any block referencing digest X,
// making audit trails unreliable.
```

## Notes

The vulnerability affects audit integrity rather than real-time consensus safety. However, reliable audit trails are critical for:
- Security incident response
- Regulatory compliance
- Debugging and troubleshooting
- Maintaining trust in the blockchain's transparency

The fix is straightforward: add the existing `verify_with_digest()` checks at batch receipt and retrieval points. This ensures the cryptographic invariant (digest = hash(payload)) is maintained throughout the system's lifetime.

### Citations

**File:** consensus/src/quorum_store/batch_requester.rs (L136-139)
```rust
                            Ok(BatchResponse::Batch(batch)) => {
                                counters::RECEIVED_BATCH_RESPONSE_COUNT.inc();
                                let payload = batch.into_transactions();
                                return Ok(payload);
```

**File:** consensus/src/quorum_store/types.rs (L268-270)
```rust
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
```

**File:** consensus/src/quorum_store/types.rs (L293-300)
```rust
    pub fn verify_with_digest(&self, requested_digest: HashValue) -> anyhow::Result<()> {
        ensure!(
            requested_digest == *self.digest(),
            "Response digest doesn't match the request"
        );
        self.verify()?;
        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L704-707)
```rust
                        batch_store.persist(vec![PersistedValue::new(
                            batch_info.into(),
                            Some(payload.clone()),
                        )]);
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L186-194)
```rust
    let all_batches = quorum_store_db.get_all_batches()?;

    let (_, _, blocks, _) = consensus_db.consensus_db().get_data()?;

    for block in blocks {
        let id = block.id();
        if block_id.is_none() || id == block_id.unwrap() {
            body.push_str(&format!("Block ({id:?}): \n\n"));
            match extract_txns_from_block(&block, &all_batches) {
```

**File:** consensus/src/util/db_tool.rs (L69-86)
```rust
fn extract_txns_from_quorum_store(
    digests: impl Iterator<Item = HashValue>,
    all_batches: &HashMap<HashValue, PersistedValue<BatchInfo>>,
) -> anyhow::Result<Vec<&SignedTransaction>> {
    let mut block_txns = Vec::new();
    for digest in digests {
        if let Some(batch) = all_batches.get(&digest) {
            if let Some(txns) = batch.payload() {
                block_txns.extend(txns);
            } else {
                bail!("Payload is not found for batch ({digest}).");
            }
        } else {
            bail!("Batch ({digest}) is not found.");
        }
    }
    Ok(block_txns)
}
```
