# Audit Report

## Title
Missing Cryptographic Verification of State Checkpoint Version at Node Initialization

## Summary
The state sync driver factory loads the `synced_version` from storage at node startup and uses it to read on-chain configurations without cryptographically verifying that the state checkpoint matches a trusted ledger info. This creates an unverified state view that could propagate manipulated on-chain configurations to consensus and other critical subsystems if an attacker gains database-level access.

## Finding Description
At node initialization in `driver_factory.rs`, the system retrieves `synced_version` from storage and immediately uses it to notify event subscribers of on-chain configurations: [1](#0-0) 

This `synced_version` is obtained from the state store's in-memory checkpoint without any cryptographic verification: [2](#0-1) 

The version is then used to create a state view for reading on-chain configurations: [3](#0-2) 

**Critical Issue:** The code uses `state_view_at_version()` which creates an **unverified** state view: [4](#0-3) 

Note that `maybe_verify_against_state_root_hash` is set to `None`, meaning **no Merkle proof verification** occurs when reading state values.

**Verified Alternative Exists:** The codebase provides `verified_state_view_at_version()` which does perform cryptographic verification: [5](#0-4) 

This method verifies the transaction against the ledger info and extracts the state checkpoint hash for verification, but is **not used** in the initialization path.

**Attack Scenario:**
1. Attacker gains filesystem access to a validator node's database (e.g., compromised backup, malicious database restoration, insider threat)
2. Attacker modifies the state Merkle DB to inject a fake state checkpoint at a specific version
3. Attacker modifies state values to include malicious on-chain configurations (validator set, feature flags, governance parameters)
4. Node starts up and loads the fake `synced_version` from storage
5. System creates unverified state view at this version
6. Malicious on-chain configs are read and distributed to consensus, mempool, and other subsystems
7. Validator operates with corrupted state, potentially causing consensus divergence

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs."

## Impact Explanation
This qualifies as **Critical Severity** under the Aptos bug bounty program for the following reasons:

**Consensus/Safety Violations:** If multiple validators load different manipulated states, they would have divergent views of the validator set and on-chain configurations, leading to consensus failures and potential chain splits.

**Non-recoverable State Corruption:** Once initialized with manipulated configs, the validator would propagate invalid state, requiring manual intervention and potentially a network-wide recovery procedure.

The vulnerability enables:
- Manipulation of the active validator set
- Tampering with feature flags that control critical protocol behaviors
- Corruption of governance parameters affecting proposal execution
- Injection of invalid epoch state information

## Likelihood Explanation
**Moderate-to-Low Likelihood** with **High Impact:**

**Attack Requirements:**
- Filesystem-level access to validator database files (requires compromised node operator account, malicious database restoration, or physical access)
- Knowledge of database structure to craft valid-looking fake state checkpoints
- Ability to restart the validator node

**Realistic Scenarios:**
1. **Malicious Database Restoration:** Validator restores from a compromised backup or snapshot from an untrusted source
2. **Compromised Operator:** Attacker gains access to validator operator credentials
3. **Supply Chain Attack:** Malicious snapshot distributed through compromised backup service

While direct database manipulation requires elevated privileges, defense-in-depth principles dictate that cryptographic verification should occur even for data loaded from local storage, especially when that data controls critical security parameters.

## Recommendation
Replace the unverified `state_view_at_version()` call with `verified_state_view_at_version()` in the initialization path.

**Proposed Fix:**

In `state-sync/inter-component/event-notifications/src/lib.rs`, modify the `read_on_chain_configs` method:

```rust
fn read_on_chain_configs(
    &self,
    version: Version,
) -> Result<OnChainConfigPayload<DbBackedOnChainConfig>, Error> {
    // Fetch the latest ledger info to verify against
    let ledger_info = self
        .storage
        .read()
        .reader
        .get_latest_ledger_info()
        .map_err(|error| {
            Error::UnexpectedErrorEncountered(format!(
                "Failed to get latest ledger info: {:?}",
                error
            ))
        })?;
    
    // Use verified state view instead of unverified
    let db_state_view = &self
        .storage
        .read()
        .reader
        .verified_state_view_at_version(Some(version), ledger_info.ledger_info())
        .map_err(|error| {
            Error::UnexpectedErrorEncountered(format!(
                "Failed to create verified state view: {:?}",
                error
            ))
        })?;
    
    // Continue with existing config reading logic...
}
```

This ensures that:
1. The transaction at `version` is verified against the latest ledger info
2. The state checkpoint hash is extracted and used for Merkle proof verification
3. All state reads are cryptographically verified against the trusted ledger info

## Proof of Concept

**Database Manipulation PoC (Conceptual):**

```rust
// This is a conceptual PoC showing how the vulnerability could be exploited
// Actual exploitation would require database-level access

// Step 1: Attacker modifies AptosDB files directly
// - Inject fake state checkpoint in StateMerkleDb at version V
// - Modify StateKvDb to return malicious ConfigurationResource
// - Ensure fake version >= waypoint to pass basic checks

// Step 2: Node startup sequence
fn main() {
    // AptosDB opens without verification
    let storage = AptosDB::open(...);
    
    // State checkpoint loaded from manipulated DB
    let synced_version = storage
        .reader
        .get_latest_state_checkpoint_version() // Returns fake version V
        .unwrap();
    
    // Unverified state view created
    let state_view = storage
        .reader
        .state_view_at_version(Some(synced_version)) // NO VERIFICATION!
        .unwrap();
    
    // Malicious configs read from manipulated state
    let config = ConfigurationResource::fetch_config(&state_view); // Returns fake validator set
    
    // Corrupted state propagated to consensus
    notify_subscribers(config); // Consensus receives invalid validator set
}

// Demonstration of missing verification:
#[test]
fn test_missing_state_verification() {
    // Create unverified state view
    let unverified_view = db_reader.state_view_at_version(Some(version)).unwrap();
    // maybe_verify_against_state_root_hash is None - NO VERIFICATION!
    
    // Compare with verified version
    let ledger_info = db_reader.get_latest_ledger_info().unwrap();
    let verified_view = db_reader
        .verified_state_view_at_version(Some(version), ledger_info.ledger_info())
        .unwrap();
    // maybe_verify_against_state_root_hash is Some(hash) - WITH VERIFICATION!
    
    // The initialization path uses the unverified variant
}
```

**Validation:**
- ✓ Vulnerability in Aptos Core production code
- ✗ **Requires privileged database access (insider threat)**
- ✓ Breaks State Consistency invariant
- ✓ Critical severity impact (consensus violations)
- ✗ **Cannot be exploited remotely without privileged access**

**Note:** This vulnerability requires insider access or compromised infrastructure to exploit, which may place it outside the standard bug bounty scope depending on Aptos' trust model for validator operators. However, the missing verification represents a defense-in-depth failure that should be addressed regardless of threat model assumptions.

### Citations

**File:** state-sync/state-sync-driver/src/driver_factory.rs (L103-112)
```rust
        match storage.reader.get_latest_state_checkpoint_version() {
            Ok(Some(synced_version)) => {
                if let Err(error) =
                    event_subscription_service.notify_initial_configs(synced_version)
                {
                    panic!(
                        "Failed to notify subscribers of initial on-chain configs: {:?}",
                        error
                    )
                }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L812-820)
```rust
    fn get_latest_state_checkpoint_version(&self) -> Result<Option<Version>> {
        gauged_api("get_latest_state_checkpoint_version", || {
            Ok(self
                .state_store
                .current_state_locked()
                .last_checkpoint()
                .version())
        })
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L285-295)
```rust
        let db_state_view = &self
            .storage
            .read()
            .reader
            .state_view_at_version(Some(version))
            .map_err(|error| {
                Error::UnexpectedErrorEncountered(format!(
                    "Failed to create account state view {:?}",
                    error
                ))
            })?;
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L97-104)
```rust
impl DbStateViewAtVersion for Arc<dyn DbReader> {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version,
            maybe_verify_against_state_root_hash: None,
        })
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L115-138)
```rust
impl VerifiedStateViewAtVersion for Arc<dyn DbReader> {
    fn verified_state_view_at_version(
        &self,
        version: Option<Version>,
        ledger_info: &LedgerInfo,
    ) -> StateViewResult<DbStateView> {
        let db = self.clone();

        if let Some(version) = version {
            let txn_with_proof =
                db.get_transaction_by_version(version, ledger_info.version(), false)?;
            txn_with_proof.verify(ledger_info)?;

            let state_root_hash = txn_with_proof
                .proof
                .transaction_info
                .state_checkpoint_hash()
                .ok_or_else(|| StateViewError::NotFound("state_checkpoint_hash".to_string()))?;

            Ok(DbStateView {
                db,
                version: Some(version),
                maybe_verify_against_state_root_hash: Some(state_root_hash),
            })
```
