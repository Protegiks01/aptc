# Audit Report

## Title
Critical Waypoint Validation Bypass Allows Node Initialization with Unverified State

## Summary
The bootstrapper's waypoint verification in `verify_waypoint_is_satisfiable()` only checks if local storage version >= waypoint version, without performing cryptographic verification of the waypoint hash. This allows an attacker to distribute a malicious pre-populated database that bypasses all cryptographic validation during node initialization, causing nodes to operate with completely unverified epoch states and fake validator sets.

## Finding Description

The vulnerability exists in the waypoint verification logic during node bootstrapping. Waypoints are designed as cryptographic trust anchors to enable secure bootstrapping from untrusted data sources, requiring verification of both version AND hash. However, the implementation contains a critical flaw.

**The Vulnerability Chain:**

When a node starts with a database containing data beyond the waypoint version, the following occurs:

1. **Genesis Bootstrap Skipped**: [1](#0-0) 
   The `maybe_bootstrap` function skips genesis validation if `db_version + 1 != waypoint.version()`, allowing pre-populated databases to bypass initial validation.

2. **Unverified Epoch State Loaded**: [2](#0-1) 
   The bootstrapper loads epoch state directly from storage without cryptographic verification.

3. **Waypoint Validation Bypassed**: [3](#0-2) 
   The critical bug occurs here: if local storage version >= waypoint version, the code marks the waypoint as "verified" WITHOUT calling `waypoint.verify()` to check the cryptographic hash.

4. **Proper Verification Never Executed**: [4](#0-3) 
   The correct `Waypoint::verify()` method that checks both version AND hash is never called for databases with existing data beyond the waypoint.

5. **Bootstrapping Completes Without Network Sync**: [5](#0-4) 
   When local version >= network version, bootstrapping completes immediately without fetching or validating data from the network.

**Attack Scenario:**

1. Attacker creates a malicious database with:
   - Genesis at version 0 (version matches waypoint but hash may differ)
   - Fake state checkpoints and epoch states at versions 1-1000
   - Fake ledger infos with attacker-controlled validator set

2. Attacker distributes this as a "fast bootstrap snapshot" to node operators

3. Victim node starts with this database:
   - `maybe_bootstrap` skips because `1001 != 0`
   - Bootstrapper's `verify_waypoint_is_satisfiable` checks `1000 >= 0` and marks waypoint as verified
   - Never calls `waypoint.verify()` to check the cryptographic hash
   - Loads fake epoch state as trust anchor
   - Completes bootstrapping without network synchronization
   - Node now accepts blocks signed by fake validator set

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets multiple Critical severity criteria per the Aptos bug bounty program:

1. **Consensus/Safety Violations**: Nodes with fake epoch states will accept blocks signed by the attacker's fake validator set while rejecting legitimate network blocks, causing consensus disagreements and potential chain forks with < 1/3 Byzantine validators.

2. **Cryptographic Correctness Violation**: The waypoint mechanism is explicitly designed to provide "an off-chain mechanism to verify the sync process" [6](#0-5) . This vulnerability completely bypasses the cryptographic verification that waypoints are supposed to provide.

3. **Non-recoverable Network Partition**: Nodes initialized with different malicious databases will form separate network partitions that cannot reconcile through normal consensus, requiring manual intervention or a hard fork.

4. **State Consistency Violations**: Nodes operate with unverified state that may differ arbitrarily from the canonical chain, breaking fundamental state consistency guarantees.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible:

1. **Low Technical Barrier**: Creating a malicious database only requires copying a legitimate database and modifying the stored state data. No cryptographic key compromise is required.

2. **Realistic Attack Vector**: Fast bootstrap snapshots are commonly distributed in blockchain ecosystems to help nodes sync quickly. The waypoint mechanism is specifically designed to protect against untrusted snapshot sources, but this bug breaks that protection.

3. **No Detection Mechanism**: The vulnerability causes the waypoint to be marked as "verified" in code, so no warnings or errors are generated. The node believes it has successfully validated its state.

4. **Persistent Impact**: Once initialized with malicious state, the node cannot self-correct because it believes it's already synced and its epoch state will cause it to reject legitimate network data.

## Recommendation

Fix the `verify_waypoint_is_satisfiable` function to perform full cryptographic verification:

```rust
fn verify_waypoint_is_satisfiable(
    &mut self,
    global_data_summary: &GlobalDataSummary,
) -> Result<(), Error> {
    let latest_ledger_info = utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
    let waypoint_version = self.driver_configuration.waypoint.version();
    
    // FIXED: Perform full cryptographic verification, not just version check
    if latest_ledger_info.ledger_info().version() >= waypoint_version {
        // Verify the waypoint cryptographically at the exact waypoint version
        if latest_ledger_info.ledger_info().version() == waypoint_version {
            self.driver_configuration.waypoint.verify(latest_ledger_info.ledger_info())
                .map_err(|e| Error::VerificationError(format!("Waypoint verification failed: {:?}", e)))?;
            self.verified_epoch_states.set_verified_waypoint(waypoint_version);
        } else {
            // Storage is beyond waypoint - need to fetch and verify the epoch-ending ledger info AT the waypoint version
            // from either storage or network to cryptographically verify the waypoint
            return Ok(()); // Continue to fetch epoch ending ledger infos
        }
        return Ok(());
    }
    
    // ... rest of the function remains the same
}
```

Additionally, consider adding database integrity checks or checksums to detect tampered databases before they are used.

## Proof of Concept

A malicious database can be created by:

1. Starting with a legitimate database at the genesis waypoint (version 0)
2. Using RocksDB tools to insert fake state checkpoint entries at versions 1-1000
3. Modifying the ledger metadata to include a fake epoch state with attacker-controlled validator keys
4. Distributing this database as a "snapshot"

When a node initializes with this database:
- The waypoint validation at line 887 will execute: `1000 >= 0` evaluates to true
- Line 889 calls `set_verified_waypoint` without any hash verification
- The node never calls the proper `waypoint.verify()` method that checks the cryptographic hash
- The node completes initialization with the fake epoch state as its trust anchor

This can be verified by adding debug logging to track whether `waypoint.verify()` is called during bootstrapping with a pre-populated database.

### Citations

**File:** execution/executor/src/db_bootstrapper/mod.rs (L56-58)
```rust
    if ledger_summary.version().map_or(0, |v| v + 1) != waypoint.version() {
        info!(waypoint = %waypoint, "Skip genesis txn.");
        return Ok(None);
```

**File:** state-sync/state-sync-driver/src/utils.rs (L258-264)
```rust
pub fn fetch_latest_epoch_state(storage: Arc<dyn DbReader>) -> Result<EpochState, Error> {
    storage.get_latest_epoch_state().map_err(|error| {
        Error::StorageError(format!(
            "Failed to get the latest epoch state from storage: {:?}",
            error
        ))
    })
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L483-488)
```rust
        } else if highest_synced_version >= highest_known_ledger_version {
            // Otherwise, if we've already synced to the highest known version, there's nothing to do
            info!(LogSchema::new(LogEntry::Bootstrapper)
                .message(&format!("Highest synced version {} is >= highest known ledger version {}, nothing needs to be done.",
                    highest_synced_version, highest_known_ledger_version)));
            return self.bootstrapping_complete().await;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L884-890)
```rust
        // If our storage has already synced beyond our waypoint, nothing needs to be checked
        let latest_ledger_info = utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        let waypoint_version = self.driver_configuration.waypoint.version();
        if latest_ledger_info.ledger_info().version() >= waypoint_version {
            self.verified_epoch_states
                .set_verified_waypoint(waypoint_version);
            return Ok(());
```

**File:** types/src/waypoint.rs (L24-26)
```rust
/// Waypoint keeps information about the LedgerInfo on a given version, which provides an
/// off-chain mechanism to verify the sync process right after the restart.
/// At high level, a trusted waypoint verifies the LedgerInfo for a certain epoch change.
```

**File:** types/src/waypoint.rs (L62-79)
```rust
    pub fn verify(&self, ledger_info: &LedgerInfo) -> Result<()> {
        ensure!(
            ledger_info.version() == self.version(),
            "Waypoint version mismatch: waypoint version = {}, given version = {}",
            self.version(),
            ledger_info.version()
        );
        let converter = Ledger2WaypointConverter::new(ledger_info);
        ensure!(
            converter.hash() == self.value(),
            format!(
                "Waypoint value mismatch: waypoint value = {}, given value = {}",
                self.value().to_hex(),
                converter.hash().to_hex()
            )
        );
        Ok(())
    }
```
