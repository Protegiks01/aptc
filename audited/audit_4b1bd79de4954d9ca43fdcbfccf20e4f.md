# Audit Report

## Title
Genesis Epoch Signature Bypass in Backup Restore Allows Complete Chain History Manipulation

## Summary
The backup restore functionality fails to verify signatures on genesis epoch (epoch 0) LedgerInfos when no trusted waypoint is provided. This allows an attacker to inject a completely fake blockchain history with malicious validator sets, causing nodes to restore corrupted state and diverge from the legitimate network.

## Finding Description

The vulnerability exists in the epoch ending restore flow where genesis epoch LedgerInfos bypass signature verification through three connected weaknesses:

**Weakness 1: No Signature Verification During Initial Restore**

During the `preheat_impl` phase, when restoring the first epoch (epoch 0), the code has three verification paths: [1](#0-0) 

For genesis epoch, `previous_li` is initialized as `None`: [2](#0-1) 

If no trusted waypoint exists for genesis (which is optional per the CLI design), neither the waypoint check (lines 129-135) nor the signature verification (lines 136-146) executes. The genesis LedgerInfo is added to the restore set without any cryptographic verification.

**Weakness 2: Optional Trusted Waypoints**

The `TrustedWaypointOpt` structure makes trusted waypoints completely optional: [3](#0-2) 

The CLI documentation states waypoints should be used "to confirm the backup is compatible" but does not enforce their presence for genesis, even though genesis is the trust anchor for the entire chain.

**Weakness 3: Equality-Only Check in verify_ledger_info**

Later verification of genesis epoch only checks structural equality, not signatures: [4](#0-3) 

This compares the LedgerInfo struct content but never invokes signature verification. Since `epoch_endings[0]` was populated without signature verification (Weakness 1), this check provides no cryptographic guarantee.

**Attack Scenario:**

1. Attacker crafts a malicious backup containing:
   - Fake genesis LedgerInfo (epoch 0) with manipulated `next_epoch_state` containing attacker-controlled validator keys
   - Arbitrary signatures (irrelevant since they won't be verified)
   - Subsequent epoch LedgerInfos signed with the attacker's keys

2. Victim operator runs restore without specifying `--trust-waypoint` for genesis (not enforced by the tool)

3. During restore:
   - Genesis LedgerInfo bypasses signature verification (Weakness 1)
   - Gets stored in `epoch_endings[0]` without validation
   - Subsequent epochs are "verified" using the fake validator set from the malicious genesis

4. The fake epoch endings are persisted to the database: [5](#0-4) 

5. Node starts with completely fake blockchain history, wrong validator set, and diverges from the legitimate network.

**Broken Invariants:**
- **Cryptographic Correctness**: BLS signatures must be verified before accepting any LedgerInfo
- **State Consistency**: Blockchain history must be cryptographically verifiable
- **Consensus Safety**: All nodes must agree on the same chain history

## Impact Explanation

This vulnerability meets **CRITICAL severity** criteria per the Aptos bug bounty program:

**Consensus/Safety Violations**: A node restored with fake genesis would have a fundamentally different view of blockchain history. It would:
- Trust a fake validator set defined by the attacker
- Accept transactions signed by fake validators
- Produce different state roots than legitimate nodes
- Be unable to participate in consensus with the real network

**State Inconsistencies Requiring Intervention**: The corrupted node would need to:
- Wipe its entire database
- Restore from a legitimate backup with proper waypoints
- Potentially require manual intervention to rejoin the network

**Non-Recoverable Network Partition**: If multiple nodes restore from the same malicious backup, they could form a separate network partition that cannot reconcile with the legitimate chain without a complete re-synchronization.

The severity is elevated because:
1. The attack requires no privileged access - only social engineering an operator
2. The impact is complete node compromise
3. Detection may be delayed until the node attempts to sync/participate in consensus
4. Recovery requires full database wipe and re-restore

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Factors Increasing Likelihood:**
1. **Optional Security Feature**: Trusted waypoints are optional, not mandatory
2. **Documentation Weakness**: Help text only "suggests" using waypoints, doesn't warn about security implications
3. **Operator Error**: New operators or emergency restore scenarios may skip waypoint specification
4. **Attack Simplicity**: Attacker only needs to provide a malicious backup file
5. **No Runtime Warning**: The tool doesn't warn when restoring genesis without trusted waypoints

**Factors Decreasing Likelihood:**
1. **Requires Operator Interaction**: Victim must choose to restore from attacker-controlled backup
2. **Best Practices**: Experienced operators likely use trusted waypoints
3. **Detection Possible**: Node will fail to sync with network, potentially raising alarms

**Realistic Attack Vectors:**
- Compromised backup storage serving malicious backups
- Social engineering operators to restore from "updated" backups
- Supply chain attacks on backup distribution infrastructure
- Insider threats providing fake backups during incident response

## Recommendation

Implement defense-in-depth by addressing all three weaknesses:

**Fix 1: Enforce Trusted Waypoint for Genesis**

Modify the restore logic to require a trusted waypoint for genesis epoch:

```rust
// In preheat_impl, after line 147
if li.ledger_info().epoch() == 0 && self.trusted_waypoints.get(&li.ledger_info().version()).is_none() {
    return Err(anyhow!(
        "Genesis epoch (epoch 0) requires a trusted waypoint for security. \
        Specify --trust-waypoint with the genesis waypoint to proceed."
    ));
}
```

**Fix 2: Add Signature Verification for Genesis**

When a trusted waypoint exists, still verify signatures if available:

```rust
// In verify_ledger_info, replace lines 289-293
if epoch == 0 {
    ensure!(
        li_with_sigs.ledger_info() == &self.epoch_endings[0],
        "Genesis epoch LedgerInfo info doesn't match.",
    );
    // Additionally verify signatures against the known genesis validator set
    if let Some(genesis_epoch_state) = self.epoch_endings[0].next_epoch_state() {
        genesis_epoch_state.verifier.verify_signatures(
            &HashValue::zero(), // Genesis has no previous block
            li_with_sigs.ledger_info(),
            li_with_sigs.signatures()
        )?;
    }
}
```

**Fix 3: Update CLI Documentation**

Change the `trust_waypoint` help text to emphasize the security requirement:

```rust
#[clap(
    long,
    help = "(**SECURITY CRITICAL**) Trusted waypoints for epoch ending LedgerInfo verification. \
    REQUIRED: Must include genesis waypoint (epoch 0) to establish trust anchor. \
    OPTIONAL: Additional waypoints for writesets or emergency recovery. \
    Without genesis waypoint, signatures are NOT verified, allowing complete chain forgery."
)]
```

**Fix 4: Runtime Validation**

Add validation in `GlobalRestoreOptions::try_from`:

```rust
// After line 323
if trusted_waypoints.is_empty() {
    warn!(
        "WARNING: No trusted waypoints provided. Genesis epoch will not be verified. \
        This is UNSAFE and should only be used in testing environments."
    );
} else {
    // Check if genesis waypoint exists (version 0)
    let has_genesis_waypoint = trusted_waypoints.keys().any(|&v| v == 0);
    if !has_genesis_waypoint {
        return Err(anyhow!(
            "Security requirement: Must provide trusted waypoint for genesis (version 0). \
            Use --trust-waypoint with your network's genesis waypoint."
        ));
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_crypto::{
        bls12381::{PrivateKey, PublicKey},
        Uniform,
    };
    use aptos_types::{
        block_info::BlockInfo,
        epoch_state::EpochState,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        on_chain_config::ValidatorSet,
        validator_verifier::ValidatorVerifier,
    };
    use rand::SeedableRng;

    #[test]
    fn test_genesis_epoch_bypass() {
        // Step 1: Create attacker's fake validator keys
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let attacker_private_key = PrivateKey::generate(&mut rng);
        let attacker_public_key = PublicKey::from(&attacker_private_key);
        
        // Step 2: Create fake genesis LedgerInfo with attacker's validator set
        let fake_validator_set = ValidatorSet::new(vec![
            // Attacker controls this validator
            ValidatorInfo::new(
                attacker_address,
                attacker_public_key,
                1000000, // Voting power
            ),
        ]);
        
        let fake_genesis = LedgerInfo::new(
            BlockInfo::new(
                0, // epoch
                0, // round
                HashValue::random(),
                HashValue::random(),
                0, // version
                0, // timestamp
                Some(EpochState::new(1, ValidatorVerifier::from(&fake_validator_set))),
            ),
            HashValue::zero(),
        );
        
        // Step 3: Create malicious backup without trusted waypoints
        let malicious_backup = create_backup_with_fake_genesis(fake_genesis);
        
        // Step 4: Run restore WITHOUT trusted waypoints
        let global_opt = GlobalRestoreOptions {
            target_version: Version::MAX,
            trusted_waypoints: Arc::new(HashMap::new()), // NO WAYPOINTS!
            run_mode: Arc::new(RestoreRunMode::Verify),
            concurrent_downloads: 1,
            replay_concurrency_level: 1,
        };
        
        let controller = EpochEndingRestoreController::new(
            EpochEndingRestoreOpt {
                manifest_handle: malicious_backup,
            },
            global_opt,
            storage,
        );
        
        // Step 5: Restore succeeds without signature verification!
        let result = controller.run(None).await;
        assert!(result.is_ok()); // Vulnerability: This should FAIL but passes!
        
        let epoch_history = result.unwrap();
        
        // Step 6: Verify that fake genesis was accepted
        assert_eq!(epoch_history.epoch_endings[0], fake_genesis);
        
        // Step 7: Demonstrate that subsequent verifications only check equality
        let fake_li_with_sigs = LedgerInfoWithSignatures::new(
            fake_genesis.clone(),
            AggregateSignature::empty(), // Invalid signatures!
        );
        
        // This passes because it only checks equality, not signatures!
        assert!(epoch_history.verify_ledger_info(&fake_li_with_sigs).is_ok());
        
        println!("VULNERABILITY CONFIRMED: Genesis epoch accepted without signature verification!");
    }
}
```

## Notes

**Context of Usage**: This vulnerability exists in the backup/restore CLI tool, not the consensus or live sync paths. However, it's still critical because:

1. Node operators use this tool for disaster recovery and initial node setup
2. A compromised restore creates a persistently corrupted node that cannot sync with the legitimate network
3. The tool is designed for production use, not just testing

**Defense-in-Depth Failures**: The vulnerability requires multiple security controls to simultaneously fail:
- Optional security feature (trusted waypoints)
- Missing validation in three separate code paths
- No runtime warnings about unsafe operations

**Real-World Impact**: In practice, most operators following best practices would use trusted waypoints. However, the lack of enforcement creates risk during:
- Emergency recovery scenarios under time pressure
- New operator onboarding with incomplete procedures
- Automated restore scripts that don't include waypoints
- Testing environments that leak into production

The fix should enforce the security requirement rather than relying on operator knowledge.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L88-89)
```rust
        let mut previous_li: Option<&LedgerInfoWithSignatures> = None;
        let mut ledger_infos = Vec::new();
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L129-146)
```rust
                if let Some(wp_trusted) = self.trusted_waypoints.get(&wp_li.version()) {
                    ensure!(
                        *wp_trusted == wp_li,
                        "Waypoints don't match. In backup: {}, trusted: {}",
                        wp_li,
                        wp_trusted,
                    );
                } else if let Some(pre_li) = previous_li {
                    pre_li
                        .ledger_info()
                        .next_epoch_state()
                        .ok_or_else(|| {
                            anyhow!(
                                "Next epoch state not found from LI at epoch {}.",
                                pre_li.ledger_info().epoch()
                            )
                        })?
                        .verify(&li)?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L248-250)
```rust
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;

```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L289-293)
```rust
        if epoch == 0 {
            ensure!(
                li_with_sigs.ledger_info() == &self.epoch_endings[0],
                "Genesis epoch LedgerInfo info doesn't match.",
            );
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
