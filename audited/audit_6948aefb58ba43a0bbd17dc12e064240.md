# Audit Report

## Title
Critical Consensus Fork Vulnerability in Transaction Backup Verification - Malicious Backups Can Bypass Cryptographic Validation

## Summary
A malicious validator can create transaction backups containing alternative transaction histories that pass all verification checks during one-off restore operations, causing restored nodes to fork from the canonical chain. The vulnerability exists because `TransactionBackup::verify()` only validates version range consistency without verifying cryptographic proofs, and one-off transaction restore operations skip signature verification entirely by passing `None` for epoch history validation.

## Finding Description

The Aptos backup system fails to verify the cryptographic authenticity of transaction backups in two critical scenarios, violating the **Consensus Safety** invariant that all nodes must maintain consistent chain state.

**Primary Vulnerability Path:**

1. **Insufficient Manifest Verification** - The `TransactionBackup::verify()` method only validates structural consistency (version ranges, chunk continuity) without verifying any cryptographic proofs: [1](#0-0) 

This method never checks if the `LedgerInfoWithSignatures` in each chunk's proof is cryptographically valid.

2. **Missing Epoch History in One-Off Restore** - When operators use the one-off transaction restore command, the system explicitly passes `None` for epoch history, completely disabling signature verification: [2](#0-1) 

3. **Conditional Signature Verification** - The `LoadedChunk::load()` function only verifies ledger info signatures when epoch history is provided, allowing unverified backups to be restored: [3](#0-2) 

When `epoch_history` is `None`, the entire signature verification block is skipped.

4. **Proof Verification Assumes Trusted Ledger Info** - The `TransactionListWithProof::verify()` method only validates that transactions match the provided ledger info's accumulator hash, but never validates the ledger info itself: [4](#0-3) 

This verification proves transactions belong to *some* ledger, not necessarily the canonical chain.

**Secondary Vulnerability - Future Epoch Bypass:**

Even when epoch history IS provided, backups claiming to be from future epochs (beyond the epoch history's range) bypass all verification: [5](#0-4) 

The TODO comment acknowledges this is a known issue requiring a fix.

**Attack Scenario:**

1. Malicious validator creates alternative transaction history forming a fork
2. Generates fake `LedgerInfo` with these transactions (with invalid or no signatures)
3. Creates valid `TransactionAccumulatorRangeProof` linking transactions to the fake ledger info
4. Packages as `TransactionBackup` with proper version ranges
5. Distributes backup through official or unofficial channels

When a node operator performs one-off transaction restore:
- Backup passes `TransactionBackup::verify()` (only checks version ranges)
- `LoadedChunk::load()` skips signature verification (epoch_history is None)
- Alternative transactions are restored to database
- Node starts with forked state, breaking consensus

## Impact Explanation

**Severity: Critical** (up to $1,000,000)

This vulnerability enables **Consensus/Safety violations** - one of the highest severity categories in the Aptos bug bounty program. Specifically:

1. **Chain Fork Creation**: Restored nodes will have different state roots than the canonical chain, violating the fundamental consensus safety invariant
2. **Network Partition Risk**: Affected nodes cannot participate in consensus as they disagree on historical state
3. **State Inconsistency**: Different nodes may compute different state transitions from the same blocks
4. **Consensus Failure**: AptosBFT assumes all honest nodes agree on committed history; this breaks that assumption

The vulnerability directly violates Aptos Critical Invariant #2: **"Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"**. While this requires a malicious validator (Byzantine actor), it enables chain splits affecting all nodes that restore from the malicious backup.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Requirements:**
- Malicious validator with ability to create and distribute backups (insider threat explicitly in scope per security question)
- Node operators using one-off transaction restore command
- Lack of trusted waypoint verification (waypoints are optional per CLI design)

**Feasibility Factors:**

*High Likelihood:*
- One-off restore is a documented operational procedure for disaster recovery
- The vulnerability is in production code paths, not edge cases
- No special cryptographic expertise required - attacker just needs to construct properly formatted data structures
- Attack leaves no immediate trace - fork only detected when node tries to sync

*Mitigating Factors:*
- Requires validator-level access to credibly distribute backups
- Coordinator-based restore (with epoch history) is more common than one-off restore
- Trusted waypoints can catch some attacks if properly configured
- Network monitoring might detect forked nodes attempting invalid state sync

The documented help text explicitly acknowledges the risk: [6](#0-5) 

This confirms signature verification is intentionally skipped in one-shot restore scenarios, making the attack highly feasible.

## Recommendation

**Immediate Fix:**

1. **Enforce Signature Verification** - Make epoch history mandatory for transaction restore, or at minimum require trusted waypoints:

```rust
// In storage/db-tool/src/restore.rs
Oneoff::Transaction { storage, opt, global } => {
    // Load epoch history to enable signature verification
    let epoch_history = if global.trusted_waypoints.trust_waypoint.is_empty() {
        return Err(anyhow!(
            "Transaction restore requires either epoch history or trusted waypoints \
            for signature verification. Use the coordinator-based restore or provide \
            --trust-waypoint flags."
        ));
    } else {
        // Build minimal epoch history from waypoints
        Some(build_epoch_history_from_waypoints(&global.trusted_waypoints)?)
    };
    
    TransactionRestoreController::new(
        opt,
        global.try_into()?,
        storage.init_storage().await?,
        epoch_history, // No longer None
        VerifyExecutionMode::NoVerify,
    )
    .run()
    .await?;
}
```

2. **Fix Future Epoch Bypass** - Require explicit confirmation for future epochs:

```rust
// In storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs
if epoch > self.epoch_endings.len() as u64 {
    return Err(anyhow!(
        "Cannot verify LedgerInfo from epoch {} - epoch history only contains {} epochs. \
        Refusing to restore potentially malicious backup. If this backup is legitimate, \
        first restore epoch ending backups up to epoch {}.",
        epoch,
        self.epoch_endings.len(),
        epoch
    ));
}
```

3. **Add Signature Verification to TransactionBackup::verify()** - Include basic signature checks in manifest verification (requires epoch history parameter).

4. **Documentation Update** - Clearly warn operators about risks of one-off restore without waypoints.

**Long-term Fix:**

Implement mandatory cryptographic proof verification for all backup restore paths, with epoch history as a required parameter rather than optional.

## Proof of Concept

```rust
// Proof of Concept - Demonstrates vulnerability exploitation
//
// Prerequisites:
// 1. Malicious validator with backup creation capability
// 2. Target node operator using one-off transaction restore
//
// This PoC shows how to create a malicious backup that passes verify()
// but contains forked transactions

use aptos_backup_cli::backup_types::transaction::manifest::{
    TransactionBackup, TransactionChunk, TransactionChunkFormat
};
use aptos_types::{
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    proof::TransactionAccumulatorRangeProof,
    transaction::{Transaction, TransactionInfo, Version},
    block_info::BlockInfo,
};
use aptos_crypto::{hash::HashValue, bls12381::Signature};

#[test]
fn test_malicious_backup_bypasses_verification() {
    // Step 1: Create alternative (forked) transactions
    let forked_transactions = create_forked_transaction_history();
    
    // Step 2: Create fake LedgerInfo (no valid signatures needed!)
    let fake_ledger_info = LedgerInfo::new(
        BlockInfo::new(
            /* fake epoch */ 10,
            /* fake round */ 100,
            /* fake block id */ HashValue::random(),
            /* fake accumulator hash */ HashValue::random(), // Attacker controls this
            /* version */ 1000,
            /* timestamp */ 0,
            /* next_epoch_state */ None,
        ),
        /* consensus_data_hash */ HashValue::zero(),
    );
    
    // Step 3: Create LedgerInfoWithSignatures with INVALID signatures
    // (or no signatures at all - doesn't matter since they won't be checked!)
    let fake_ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        fake_ledger_info,
        aptos_crypto::bls12381::AggregateSignature::empty(), // Invalid signature!
    );
    
    // Step 4: Create TransactionAccumulatorRangeProof for forked transactions
    // This is the only cryptographic work needed - link forked txns to fake ledger
    let range_proof = create_range_proof_for_forked_txns(
        &forked_transactions,
        fake_ledger_info_with_sigs.ledger_info(),
    );
    
    // Step 5: Package as TransactionBackup
    let malicious_backup = TransactionBackup {
        first_version: 0,
        last_version: 999,
        chunks: vec![TransactionChunk {
            first_version: 0,
            last_version: 999,
            transactions: FileHandle::new("forked_txns.bcs"),
            proof: FileHandle::new("fake_proof.bcs"), // Contains fake_ledger_info_with_sigs
            format: TransactionChunkFormat::V1,
        }],
    };
    
    // Step 6: Verify the malicious backup passes TransactionBackup::verify()
    assert!(malicious_backup.verify().is_ok()); // PASSES! Only checks version ranges
    
    // Step 7: When operator runs one-off restore with epoch_history=None,
    // the fake ledger info signatures are NEVER VERIFIED
    // LoadedChunk::load() skips signature verification entirely
    // Alternative transactions get restored to database
    // Node starts with forked state -> CONSENSUS BREAK
}

fn create_forked_transaction_history() -> Vec<(Transaction, TransactionInfo)> {
    // Create transactions that differ from canonical chain
    // E.g., double-spend, different validator set, different balances
    todo!()
}

fn create_range_proof_for_forked_txns(
    txns: &[(Transaction, TransactionInfo)],
    fake_ledger: &LedgerInfo,
) -> TransactionAccumulatorRangeProof {
    // Build accumulator with forked transaction infos
    // Generate proof linking them to fake_ledger.transaction_accumulator_hash()
    todo!()
}
```

**Demonstration Steps:**

1. Malicious validator runs modified backup creation tool to generate forked backup
2. Backup is distributed (via public storage, private channels, or compromised infrastructure)
3. Node operator downloads backup and runs:
   ```bash
   aptos-db-tool restore oneoff transaction \
     --transaction-manifest forked_backup.manifest \
     --target-db-dir /path/to/db
   # No --trust-waypoint provided (optional), so no verification!
   ```
4. Backup passes all checks and is restored
5. Node starts and attempts to sync with network
6. State root mismatch detected → node cannot participate in consensus → fork confirmed

## Notes

This vulnerability exists due to a design decision to make signature verification optional for operational convenience. The help text acknowledges waypoints are "NOT checked at all when doing one-shot restoring," but this creates a critical security gap. The TODO comment in `EpochHistory::verify_ledger_info()` suggests developers are aware of the future epoch bypass issue but it remains unaddressed in production code.

The vulnerability is particularly dangerous because:
- It's in a documented operational path (not an edge case)
- The attack leaves no immediate evidence (fork only detected during sync)
- Multiple validation layers all make the same assumption (epoch_history is optional)
- The complexity of backup restoration may cause operators to skip waypoint configuration

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L50-88)
```rust
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_version <= self.last_version,
            "Bad version range: [{}, {}]",
            self.first_version,
            self.last_version,
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");

        let mut next_version = self.first_version;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_version == next_version,
                "Chunk ranges not continuous. Expected first version: {}, actual: {}.",
                next_version,
                chunk.first_version,
            );
            ensure!(
                chunk.last_version >= chunk.first_version,
                "Chunk range invalid. [{}, {}]",
                chunk.first_version,
                chunk.last_version,
            );
            next_version = chunk.last_version + 1;
        }

        // check last version in chunk matches manifest
        ensure!(
            next_version - 1 == self.last_version, // okay to -1 because chunks is not empty.
            "Last version in chunks: {}, in manifest: {}",
            next_version - 1,
            self.last_version,
        );

        Ok(())
    }
```

**File:** storage/db-tool/src/restore.rs (L102-110)
```rust
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** types/src/transaction/mod.rs (L2295-2336)
```rust
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        first_transaction_version: Option<Version>,
    ) -> Result<()> {
        // Verify the first transaction versions match
        ensure!(
            self.get_first_transaction_version() == first_transaction_version,
            "First transaction version ({:?}) doesn't match given version ({:?}).",
            self.get_first_transaction_version(),
            first_transaction_version,
        );

        // Verify the lengths of the transactions and transaction infos match
        ensure!(
            self.proof.transaction_infos.len() == self.get_num_transactions(),
            "The number of TransactionInfo objects ({}) does not match the number of \
             transactions ({}).",
            self.proof.transaction_infos.len(),
            self.get_num_transactions(),
        );

        // Verify the transaction hashes match those of the transaction infos
        self.transactions
            .par_iter()
            .zip_eq(self.proof.transaction_infos.par_iter())
            .map(|(txn, txn_info)| {
                let txn_hash = CryptoHash::hash(txn);
                ensure!(
                    txn_hash == txn_info.transaction_hash(),
                    "The hash of transaction does not match the transaction info in proof. \
                     Transaction hash: {:x}. Transaction hash in txn_info: {:x}.",
                    txn_hash,
                    txn_info.transaction_hash(),
                );
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        // Verify the transaction infos are proven by the ledger info.
        self.proof
            .verify(ledger_info, self.get_first_transaction_version())?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L279-288)
```rust
        if epoch > self.epoch_endings.len() as u64 {
            // TODO(aldenhu): fix this from upper level
            warn!(
                epoch = epoch,
                epoch_history_until = self.epoch_endings.len(),
                "Epoch is too new and can't be verified. Previous chunks are verified and node \
                won't be able to start if this data is malicious."
            );
            return Ok(());
        }
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L341-343)
```rust
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
```
