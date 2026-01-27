# Audit Report

## Title
Trusted Waypoint Version Ordering and Epoch Boundary Validation Bypass Leading to State Inconsistencies

## Summary
The `TrustedWaypointOpt::verify()` function fails to validate that waypoint versions are in ascending order and correspond to epoch boundaries, allowing operators to provide waypoints at arbitrary versions. This enables signature verification bypass for non-epoch-boundary LedgerInfos during backup restoration, potentially leading to state inconsistencies when restoring from malicious or compromised backup sources.

## Finding Description
The `TrustedWaypointOpt::verify()` function only checks for duplicate waypoint versions but does not enforce two critical security properties: [1](#0-0) 

The function stores waypoints in a HashMap without validating:
1. **Version ordering**: Waypoints could be provided in descending or arbitrary order
2. **Epoch boundary alignment**: Waypoints could be at non-epoch-boundary versions

During transaction and state snapshot restoration, the `EpochHistory::verify_ledger_info()` function skips signature verification when a trusted waypoint exists at a LedgerInfo's version: [2](#0-1) 

Critically, this uses `Waypoint::new_any()` which does NOT verify the LedgerInfo ends an epoch, unlike `Waypoint::new_epoch_boundary()` used during epoch ending restore: [3](#0-2) 

The documentation explicitly states waypoints should be at "epoch ending" versions: [4](#0-3) 

However, this requirement is not enforced by the code.

**Attack Scenario:**
1. An operator obtains "trusted" waypoints from a source (e.g., documentation, blockchain explorer, or social engineering)
2. Some waypoints are mistakenly at non-epoch-boundary versions (e.g., [100, 150, 300, 350, 500] instead of [100, 200, 300, 400, 500])
3. The operator provides these via `--trust-waypoint` CLI flags
4. A malicious or compromised backup source provides fake LedgerInfos at these non-epoch-boundary versions
5. During transaction restore, these fake LedgerInfos match the trusted waypoints
6. Signature verification is bypassed (lines 294-304)
7. Malicious transaction data certified by fake LedgerInfos is accepted into the restored state
8. State inconsistencies occur between the restored node and honest nodes

This is called during both transaction and state snapshot restoration: [5](#0-4) [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: Nodes restoring from malicious backups with misaligned waypoints will have different states than honest nodes
- **Consensus safety violation potential**: If multiple validators restore from the same compromised backup using misconfigured waypoints, they could diverge from the canonical chain
- **Violates documented behavior**: The code comment explicitly requires "epoch ending LedgerInfo" but the implementation accepts any version

While this doesn't directly cause fund loss or complete network failure, it breaks the State Consistency invariant ("State transitions must be atomic and verifiable via Merkle proofs") and could require manual intervention to recover affected nodes.

## Likelihood Explanation
**Likelihood: MEDIUM**

This vulnerability requires:
1. **Operator misconfiguration**: The operator must provide waypoints at incorrect versions (realistic if documentation is unclear or during emergency restoration)
2. **Compromised backup source**: The backup must contain malicious data matching the misconfigured waypoints (realistic if backup storage is untrusted)
3. **No secondary validation**: The operator doesn't manually verify waypoint-to-epoch alignment (realistic under time pressure)

The likelihood increases in scenarios where:
- Operators follow outdated documentation
- Multiple operators use shared/public backup sources
- Emergency restoration is performed under time constraints
- Waypoints are distributed through unofficial channels

## Recommendation
Add validation in `TrustedWaypointOpt::verify()` to enforce ascending version order and warn about potential epoch boundary misalignment:

```rust
pub fn verify(self) -> Result<HashMap<Version, Waypoint>> {
    let mut trusted_waypoints = HashMap::new();
    let mut versions: Vec<Version> = Vec::new();
    
    for w in self.trust_waypoint {
        trusted_waypoints
            .insert(w.version(), w)
            .map_or(Ok(()), |w| {
                Err(AptosDbError::Other(format!(
                    "Duplicated waypoints at version {}",
                    w.version()
                )))
            })?;
        versions.push(w.version());
    }
    
    // Validate ascending order
    versions.sort_unstable();
    for i in 1..versions.len() {
        ensure!(
            versions[i] > versions[i - 1],
            "Waypoint versions must be in ascending order. Found {} after {}",
            versions[i],
            versions[i - 1]
        );
    }
    
    // Warn if waypoints are too close (likely not epoch boundaries)
    for i in 1..versions.len() {
        let gap = versions[i] - versions[i - 1];
        if gap < 1000 {  // Configurable threshold
            warn!(
                "Waypoints at versions {} and {} are very close (gap: {}). \
                Ensure these correspond to actual epoch boundaries.",
                versions[i - 1],
                versions[i],
                gap
            );
        }
    }
    
    Ok(trusted_waypoints)
}
```

Additionally, consider adding epoch boundary validation during transaction restore by checking if the LedgerInfo has `next_epoch_state` when a trusted waypoint is used, or at minimum logging a warning.

## Proof of Concept
```rust
#[test]
fn test_waypoint_ordering_validation() {
    use aptos_types::waypoint::Waypoint;
    use aptos_crypto::HashValue;
    
    // Test 1: Out-of-order waypoints should be rejected
    let wp1 = Waypoint::new(100, HashValue::random());
    let wp2 = Waypoint::new(500, HashValue::random());
    let wp3 = Waypoint::new(300, HashValue::random()); // Out of order
    
    let opt = TrustedWaypointOpt {
        trust_waypoint: vec![wp1, wp2, wp3],
    };
    
    // Currently this passes, but should fail
    let result = opt.verify();
    assert!(result.is_ok()); // BUG: Should be is_err()
    
    // Test 2: Non-epoch-boundary waypoints bypass signature verification
    // Create a LedgerInfo at non-epoch-boundary version 150
    let mut li = LedgerInfo::new(
        BlockInfo::new(0, 150, HashValue::zero(), HashValue::zero(), 150, 1000, None), // No next_epoch_state
        HashValue::zero(),
    );
    let li_with_sigs = LedgerInfoWithSignatures::new(li, AggregateSignature::empty());
    
    let wp_at_150 = Waypoint::new_any(&li);
    let trusted_waypoints = HashMap::from([(150, wp_at_150)]);
    
    let epoch_history = EpochHistory {
        epoch_endings: vec![genesis_li],
        trusted_waypoints: Arc::new(trusted_waypoints),
    };
    
    // This will pass signature verification because the waypoint exists
    // even though version 150 is not an epoch boundary
    let result = epoch_history.verify_ledger_info(&li_with_sigs);
    assert!(result.is_ok()); // BUG: Bypasses signature check for non-epoch-boundary
}
```

## Notes
This vulnerability exemplifies a defense-in-depth failure where user-provided trust anchors (waypoints) lack sufficient validation. While the operator is the trusted party providing waypoints, the system should validate that these waypoints conform to documented requirements (epoch boundaries) to prevent configuration errors from causing state inconsistencies. The mismatch between documented behavior ("epoch ending LedgerInfo") and actual implementation (any version accepted) creates a security gap exploitable through operator error combined with malicious backup sources.

### Citations

**File:** storage/backup/backup-cli/src/utils/mod.rs (L333-345)
```rust
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
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L348-363)
```rust
impl TrustedWaypointOpt {
    pub fn verify(self) -> Result<HashMap<Version, Waypoint>> {
        let mut trusted_waypoints = HashMap::new();
        for w in self.trust_waypoint {
            trusted_waypoints
                .insert(w.version(), w)
                .map_or(Ok(()), |w| {
                    Err(AptosDbError::Other(format!(
                        "Duplicated waypoints at version {}",
                        w.version()
                    )))
                })?;
        }
        Ok(trusted_waypoints)
    }
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

**File:** types/src/waypoint.rs (L48-51)
```rust
    pub fn new_epoch_boundary(ledger_info: &LedgerInfo) -> Result<Self> {
        ensure!(ledger_info.ends_epoch(), "No validator set");
        Ok(Self::new_any(ledger_info))
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```
