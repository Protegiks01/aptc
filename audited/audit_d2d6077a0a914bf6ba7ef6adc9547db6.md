# Audit Report

## Title
Missing Transaction Info Integrity Validation During Validator Restart Allows Silent Storage Corruption to Persist

## Summary
During validator restart, the system reconstructs the transaction accumulator from frozen subtree hashes stored on disk but does NOT validate that persisted `transaction_infos` match the accumulator leaf hashes. This allows corrupted `transaction_infos` to persist undetected through restart, enabling the validator to rejoin consensus before corruption is discovered, potentially causing state sync failures and service degradation.

## Finding Description

The vulnerability exists in the validator restart flow where storage integrity is not comprehensively validated before rejoining consensus.

**Storage Architecture:**
Aptos stores transaction metadata in separate database schemas:
- `TransactionInfoSchema`: Individual `TransactionInfo` objects keyed by version
- `TransactionAccumulatorSchema`: Merkle accumulator nodes keyed by position  
- `TransactionAccumulatorRootHashSchema`: Cached root hashes keyed by version [1](#0-0) 

**Restart Flow Analysis:**

1. **Accumulator Summary Retrieval** - When a validator restarts, `StorageWriteProxy::start()` retrieves the accumulator summary which reads ONLY the frozen subtree hashes from `TransactionAccumulatorSchema`: [2](#0-1) 

The `get_accumulator_summary` implementation reconstructs the accumulator from stored subtree hashes without touching `transaction_infos`: [3](#0-2) 

2. **Block Store Validation** - The `BlockStore::build()` validates accumulator internal consistency but NOT against individual transaction_infos: [4](#0-3) 

This only validates that the reconstructed accumulator's root hash matches the stored `accu_hash`, not that transaction_infos match accumulator leaves.

3. **No Transaction Info Validation** - A manual debugging tool exists to check transaction_info integrity but is NOT invoked during startup: [5](#0-4) 

**Attack Scenario:**

If `transaction_infos` become corrupted on disk (through disk failure, bit flips, filesystem bugs, or malicious modification with privileged access):

1. Corrupted `TransactionInfo` objects remain in `TransactionInfoSchema`
2. Accumulator nodes in `TransactionAccumulatorSchema` remain intact
3. On restart, `get_accumulator_summary` reads only accumulator nodes
4. Accumulator root hash validation passes (comparing stored hash vs stored frozen subtrees)
5. Validator rejoins consensus successfully
6. Corruption is only detected when serving state sync requests, causing verification failures for syncing peers: [6](#0-5) 

**Broken Invariant:**
This violates the **State Consistency** invariant (#4) which requires that "state transitions must be atomic and verifiable via Merkle proofs." The stored transaction_infos MUST cryptographically match the accumulator, but this invariant is not enforced at restart.

## Impact Explanation

**Severity Assessment: Medium**

While the security question labels this as "(High)", careful analysis reveals this is a **Medium severity** issue under the Aptos bug bounty criteria:

**Why Not Critical:**
- No consensus safety violation - the validator participates correctly using the (uncorrupted) accumulator root hash
- No fund loss or theft
- No network partition - other validators continue normally

**Why Not High:**  
- No significant protocol violation - corrupted state does NOT propagate due to proof verification
- Validator continues operating and producing blocks

**Why Medium:**
- **State inconsistency requiring intervention**: The validator has corrupted historical data requiring manual recovery
- **Service degradation**: Peers attempting to sync from this validator will fail verification, reducing network resilience
- **Defense-in-depth failure**: Missing integrity validation that should catch corruption early

**Limited Impact:**
The corruption does not propagate because state sync verification validates transaction_info hashes against accumulator proofs. Requesting peers will detect mismatches and reject the data: [7](#0-6) 

## Likelihood Explanation

**Likelihood: Low to Medium**

The likelihood depends on the corruption source:

**Natural Occurrence (Low):**
- Cosmic ray bit flips: Rare but documented
- Disk hardware failures: Uncommon with ECC memory and redundant storage
- Filesystem bugs: Rare with mature filesystems

**Malicious Exploitation (Low):**
- Requires privileged access to validator filesystem
- If attacker has root access, more direct attacks are available
- Not exploitable by external unprivileged attackers

**Detection Gap (High):**
Once corruption occurs, the detection gap is 100% - restart will NOT detect it before rejoining consensus.

## Recommendation

Implement integrity validation during validator startup before rejoining consensus:

```rust
// In consensus/src/persistent_liveness_storage.rs StorageWriteProxy::start()
// After line 556, add validation:

let latest_version = latest_ledger_info.ledger_info().version();

// Validate transaction_infos match accumulator (sample check)
let sample_interval = 10000; // Check every 10k transactions
let start_version = latest_version.saturating_sub(100000).max(0);

for version in (start_version..=latest_version).step_by(sample_interval as usize) {
    let txn_info = self.aptos_db
        .get_transaction_info(version)
        .context("Failed to read transaction info during integrity check")?;
    
    let accumulator_leaf = self.aptos_db
        .transaction_accumulator_db()
        .get::<TransactionAccumulatorSchema>(
            &Position::from_leaf_index(version)
        )
        .context("Failed to read accumulator leaf")?
        .context("Accumulator leaf missing")?;
    
    let txn_info_hash = txn_info.hash();
    
    ensure!(
        txn_info_hash == accumulator_leaf,
        "Storage corruption detected at version {}: transaction_info hash {:?} != accumulator leaf {:?}. 
        Refusing to start. Run aptos-db-tool to investigate.",
        version, txn_info_hash, accumulator_leaf
    );
}

info!("Transaction info integrity validation passed for {} sampled versions", 
      (latest_version - start_version) / sample_interval);
```

**Alternative:** Make the manual validation tool run automatically at startup for validators.

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability exists by showing no validation occurs

#[test]
fn test_corrupted_transaction_info_not_detected_on_restart() {
    // Setup: Create a validator with some committed transactions
    let (mut node, db) = setup_test_validator_node();
    
    // Commit some blocks normally
    for i in 0..100 {
        node.commit_block_with_txns(vec![create_test_txn(i)]);
    }
    
    let version_to_corrupt = 50;
    
    // Simulate corruption: Directly modify transaction_info in database
    let mut corrupted_txn_info = db.get_transaction_info(version_to_corrupt).unwrap();
    corrupted_txn_info.gas_used = 999999; // Corrupt a field
    
    // Write corrupted data back
    let mut batch = SchemaBatch::new();
    TransactionInfoDb::put_transaction_info(
        version_to_corrupt, 
        &corrupted_txn_info, 
        &mut batch
    ).unwrap();
    db.transaction_info_db().write_schemas(batch).unwrap();
    
    // Restart the validator
    drop(node);
    let node = restart_validator_node(db);
    
    // VULNERABILITY: Node restarts successfully without detecting corruption
    assert!(node.consensus_state().is_participating());
    
    // Corruption is only detected when serving state sync
    let sync_request = create_state_sync_request(version_to_corrupt);
    let result = node.handle_sync_request(sync_request);
    
    // Receiving node will detect corruption during verification
    assert!(result.is_err() || verify_sync_response(&result.unwrap()).is_err(),
            "Corruption should be detected by receiving peer, not at restart");
}
```

**Notes:**
- This vulnerability requires existing storage corruption (low likelihood)
- Does not enable unprivileged exploitation
- Impact limited by proof verification preventing propagation
- Represents a defense-in-depth gap rather than critical security flaw

### Citations

**File:** storage/aptosdb/src/ledger_db/transaction_info_db.rs (L86-92)
```rust
    pub(crate) fn put_transaction_info(
        version: Version,
        transaction_info: &TransactionInfo,
        batch: &mut SchemaBatch,
    ) -> Result<()> {
        batch.put::<TransactionInfoSchema>(&version, transaction_info)
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L553-556)
```rust
        let accumulator_summary = self
            .aptos_db
            .get_accumulator_summary(latest_ledger_info.ledger_info().version())
            .expect("Failed to get accumulator summary.");
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L857-868)
```rust
    fn get_accumulator_summary(
        &self,
        ledger_version: Version,
    ) -> Result<TransactionAccumulatorSummary> {
        let num_txns = ledger_version + 1;
        let frozen_subtrees = self
            .ledger_db
            .transaction_accumulator_db()
            .get_frozen_subtree_hashes(num_txns)?;
        TransactionAccumulatorSummary::new(InMemoryAccumulator::new(frozen_subtrees, num_txns)?)
            .map_err(Into::into)
    }
```

**File:** consensus/src/block_storage/block_store.rs (L210-217)
```rust
        let result = StateComputeResult::new_dummy_with_accumulator(Arc::new(
            InMemoryTransactionAccumulator::new(
                root_metadata.frozen_root_hashes,
                root_metadata.num_leaves,
            )
            .expect("Failed to recover accumulator."),
        ));
        assert_eq!(result.root_hash(), root_metadata.accu_hash);
```

**File:** storage/aptosdb/src/db_debugger/ledger/check_txn_info_hashes.rs (L39-51)
```rust
            let leaf_hash =
                ledger_db
                    .transaction_accumulator_db_raw()
                    .get::<TransactionAccumulatorSchema>(&Position::from_leaf_index(version))?;
            let txn_info_hash = txn_info.hash();

            ensure!(
                leaf_hash.as_ref() == Some(&txn_info_hash),
                "Found mismatch: version: {}, txn_info_hash: {:?}, leaf_hash: {:?}",
                version,
                txn_info_hash,
                leaf_hash,
            );
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L60-63)
```rust
            // Verify transaction infos match
            ledger_update_output
                .ensure_transaction_infos_match(&self.txn_infos_with_proof.transaction_infos)?;

```

**File:** types/src/transaction/mod.rs (L1898-1908)
```rust
        let write_set_hash = CryptoHash::hash(self.write_set());
        ensure!(
            write_set_hash == txn_info.state_change_hash(),
            "{}: version:{}, write_set_hash:{:?}, expected:{:?}, write_set: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
            write_set_hash,
            txn_info.state_change_hash(),
            self.write_set,
            expected_write_set,
        );
```
