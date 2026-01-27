# Audit Report

## Title
Epoch History Bypass Allows Unverified LedgerInfo Acceptance During Backup Restore

## Summary
The `verify_ledger_info()` function in the epoch ending restore module bypasses all cryptographic verification (both waypoint and signature checks) for LedgerInfo entries claiming epochs beyond the current epoch history, unconditionally accepting them with only a warning log. This violates the **State Consistency** and **Cryptographic Correctness** invariants.

## Finding Description

**Direct Answer to Security Question**: The waypoint comparison DOES check cryptographic properties, not just version numbers. The `Waypoint` struct contains both a version number and a cryptographic hash value. [1](#0-0)  The hash is computed from critical LedgerInfo fields including epoch, root_hash, version, timestamp, and next_epoch_state. [2](#0-1)  When waypoints are compared using the `==` operator, the derived `PartialEq` implementation checks both the version AND the cryptographic hash. [3](#0-2) 

**However, Critical Vulnerability Found**: The `verify_ledger_info()` function contains a bypass that completely skips verification for LedgerInfo entries with epochs exceeding the length of the epoch history. [4](#0-3) 

When this condition is met:
1. No waypoint validation occurs (cryptographic hash is not checked)
2. No signature verification occurs (BLS signatures are not validated)
3. The function immediately returns `Ok()` after logging a warning
4. The TODO comment indicates this is a known issue requiring a fix

**Attack Path**:
1. Attacker obtains or creates malicious backup data (transaction or state snapshot backups)
2. The backup contains a LedgerInfo claiming epoch N+k where k > 1 and the restored epoch history only extends to epoch N
3. During restore, `EpochHistory::verify_ledger_info()` is called [5](#0-4) 
4. The check `epoch > self.epoch_endings.len()` evaluates to true, triggering the bypass
5. The malicious LedgerInfo is accepted without cryptographic verification
6. This LedgerInfo is then used to verify transaction proofs or state snapshot proofs [6](#0-5) 
7. The attacker can craft matching proofs that validate against their malicious LedgerInfo
8. Malicious transactions or corrupted state are restored into the database

This breaks the **State Consistency** invariant (state transitions must be verifiable via Merkle proofs) and the **Cryptographic Correctness** invariant (signatures and hash operations must be secure).

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria for "Significant protocol violations")

This vulnerability enables:

1. **State Corruption**: Attackers can inject unverified state data during restore operations, corrupting the node's blockchain state
2. **Consensus Violations**: If multiple nodes restore from manipulated backups, they could diverge on state, leading to consensus failures
3. **Transaction Injection**: Malicious transactions can be injected by crafting LedgerInfo and corresponding proofs
4. **Bypass of Trust Model**: The trusted waypoint mechanism is completely bypassed for future epochs
5. **Protocol Violation**: The fundamental requirement that all state transitions must be cryptographically verified is violated

While the comment suggests "node won't be able to start if this data is malicious," this is not a reliable safeguard:
- It assumes downstream validation will catch all issues
- State corruption may not be detected until much later
- The node may start with corrupted state and propagate invalid data
- This creates a denial-of-service vector even if corruption is eventually detected

## Likelihood Explanation

**Likelihood: MEDIUM**

The attack requires:
1. Attacker control or manipulation of backup data sources
2. Knowledge of the epoch history extent on target nodes
3. Ability to craft malicious backup manifests and data files

However:
- Backup systems are often less protected than live nodes
- Cloud storage compromises could expose backup data
- Insider threats or supply chain attacks on backup infrastructure
- The attack is straightforward once backup access is obtained
- No sophisticated cryptographic attacks are required
- The TODO comment indicates developers are aware this is problematic

## Recommendation

**Immediate Fix**: Remove the early return bypass and enforce proper verification for all epochs. If the epoch is beyond known history, the verification should fail explicitly rather than silently accepting unverified data.

```rust
pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
    let epoch = li_with_sigs.ledger_info().epoch();
    ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.");
    
    // FIXED: Reject epochs beyond known history instead of bypassing verification
    ensure!(
        epoch <= self.epoch_endings.len() as u64,
        "Epoch {} is beyond known epoch history (up to epoch {}). Cannot verify.",
        epoch,
        self.epoch_endings.len() - 1
    );
    
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
            .ok_or_else(|| anyhow!("Shouldn't contain non-epoch bumping LIs."))?
            .verify(li_with_sigs)?;
    };
    Ok(())
}
```

**Alternative Approach**: If accepting future epochs is necessary for incremental restore scenarios, require explicit trusted waypoints for those epochs rather than bypassing verification entirely.

## Proof of Concept

```rust
// This demonstrates the bypass vulnerability
// File: storage/backup/backup-cli/src/backup_types/epoch_ending/restore_test.rs

#[test]
fn test_epoch_bypass_vulnerability() {
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        aggregate_signature::AggregateSignature,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    
    // Setup: Create epoch history with epochs 0-9
    let mut epoch_endings = Vec::new();
    for epoch in 0..10 {
        let li = LedgerInfo::new(
            BlockInfo::new(
                epoch,
                0,
                HashValue::random(),
                HashValue::random(),
                100 * epoch,
                1000,
                if epoch < 9 { Some(EpochState::empty()) } else { None },
            ),
            HashValue::zero(),
        );
        epoch_endings.push(li);
    }
    
    let epoch_history = EpochHistory {
        epoch_endings,
        trusted_waypoints: Arc::new(HashMap::new()),
    };
    
    // Attack: Create malicious LedgerInfo claiming epoch 100 (far beyond known history)
    let malicious_li = LedgerInfo::new(
        BlockInfo::new(
            100, // Epoch far beyond known history
            0,
            HashValue::random(), // Attacker-controlled hash
            HashValue::random(), // Attacker-controlled state root
            10000,
            1000,
            None,
        ),
        HashValue::zero(),
    );
    
    // Create LedgerInfoWithSignatures with no valid signatures
    let malicious_li_with_sigs = LedgerInfoWithSignatures::new(
        malicious_li,
        AggregateSignature::empty(), // No valid signatures!
    );
    
    // Vulnerability: This passes without any verification
    let result = epoch_history.verify_ledger_info(&malicious_li_with_sigs);
    
    // BUG: Malicious LedgerInfo is accepted despite:
    // 1. No signature verification
    // 2. No waypoint verification  
    // 3. Epoch far beyond known history
    // 4. Attacker-controlled hashes
    assert!(result.is_ok(), "Vulnerability: Unverified LedgerInfo accepted!");
    
    // This malicious LedgerInfo can now be used to "verify" fake transactions
    // during restore operations, leading to state corruption.
}
```

## Notes

The waypoint comparison mechanism itself is cryptographically sound - it properly checks both version numbers and cryptographic hash values of LedgerInfo data. However, the bypass for future epochs undermines this security by allowing complete circumvention of verification. The TODO comment at line 280 confirms this is a known issue requiring architectural changes to properly handle incremental restore scenarios without sacrificing security guarantees.

### Citations

**File:** types/src/waypoint.rs (L28-35)
```rust
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct Waypoint {
    /// The version of the reconfiguration transaction that is being approved by this waypoint.
    version: Version,
    /// The hash of the chosen fields of LedgerInfo.
    value: HashValue,
}
```

**File:** types/src/waypoint.rs (L129-148)
```rust
#[derive(Deserialize, Serialize, CryptoHasher, BCSCryptoHash)]
struct Ledger2WaypointConverter {
    epoch: u64,
    root_hash: HashValue,
    version: Version,
    timestamp_usecs: u64,
    next_epoch_state: Option<EpochState>,
}

impl Ledger2WaypointConverter {
    pub fn new(ledger_info: &LedgerInfo) -> Self {
        Self {
            epoch: ledger_info.epoch(),
            root_hash: ledger_info.transaction_accumulator_hash(),
            version: ledger_info.version(),
            timestamp_usecs: ledger_info.timestamp_usecs(),
            next_epoch_state: ledger_info.next_epoch_state().cloned(),
        }
    }
}
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L294-304)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L167-167)
```rust
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```
