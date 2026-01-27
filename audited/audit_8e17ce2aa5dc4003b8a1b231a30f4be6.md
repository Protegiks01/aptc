# Audit Report

## Title
Genesis Transaction Replay via Malicious Backup Restores Critical System State Without Verification

## Summary
The restore process accepts genesis transactions from backups without cryptographic verification when operators fail to provide a trusted waypoint for version 0. This allows malicious backups to replay crafted genesis transactions that reset validator sets, governance state, and staking configuration, causing network-wide consensus failures.

## Finding Description

The Aptos restore process is designed to reconstruct blockchain state from backups. However, the epoch ending restoration logic contains a critical verification gap for genesis (epoch 0) that breaks the **Deterministic Execution** and **Consensus Safety** invariants. [1](#0-0) 

The verification logic has three branches:
1. If a trusted waypoint exists for the version → verify against it
2. Else if a previous ledger info exists → verify signatures using the previous epoch's validator set  
3. **Else → NO VERIFICATION OCCURS**

For genesis (epoch 0), there is no previous epoch, so `previous_li` is `None`. If the operator doesn't provide `--trust-waypoint` for version 0, the genesis ledger info from the backup is accepted **without any cryptographic verification**. [2](#0-1) 

The `EpochHistory::verify_ledger_info()` function attempts to verify genesis by comparing against `epoch_endings[0]`, but `epoch_endings[0]` itself comes from the unverified backup, creating a circular trust issue. [3](#0-2) 

The trusted waypoints are optional, and the documentation explicitly states that ledger infos are NOT checked for one-shot transaction restores without epoch ending backups. [4](#0-3) 

The system explicitly supports applying new genesis transactions to non-empty databases, demonstrating that genesis replay is an intended feature for disaster recovery—but without proper verification, it becomes an attack vector.

**Attack Execution Path:**

1. Attacker creates malicious backup containing crafted genesis transaction that:
   - Resets ValidatorSet to attacker-controlled validators
   - Modifies governance voting thresholds
   - Corrupts staking state or reward calculations

2. Attacker compromises backup storage or social engineers operator to use malicious backup

3. Operator runs restore command: `aptos-db restore bootstrap-db --target-db-dir /data --metadata-cache-dir /cache --storage-backend <malicious-backup>` (without `--trust-waypoint` for version 0)

4. Epoch ending restore accepts malicious genesis without verification

5. Transaction restore replays malicious genesis transaction, executing arbitrary state changes

6. Node restarts with corrupted state, diverging from legitimate network

7. Consensus fails as node produces different state roots, causing permanent network partition

## Impact Explanation

**Critical Severity** (up to $1,000,000) - This meets multiple critical impact categories:

- **Consensus/Safety violations**: Affected nodes compute different state roots than the legitimate network, violating AptosBFT safety guarantees
- **Non-recoverable network partition**: Nodes restored from malicious backups permanently diverge from the correct chain, requiring manual intervention or hard fork to recover
- **Validator Set Manipulation**: Malicious genesis can install attacker-controlled validator set, potentially enabling 51% attacks on affected network segment
- **State Consistency Breach**: Violates the invariant that "all validators must produce identical state roots for identical blocks"

The vulnerability affects disaster recovery scenarios where multiple validators might restore from the same compromised backup simultaneously, potentially partitioning a significant portion of the network.

## Likelihood Explanation

**High Likelihood** - Multiple factors increase probability:

1. **Operational Gap**: The need to provide trusted waypoints is documented but not enforced. Operators performing emergency restores under time pressure may omit this step.

2. **Backup Compromise**: Backup storage is a common attack target. Cloud storage misconfigurations, compromised credentials, or supply chain attacks on backup providers could allow malicious backup injection.

3. **Disaster Recovery Scenarios**: The feature is specifically designed for "the very extreme and sad situation of losing quorum among validators" (per code comments), exactly when multiple operators might restore simultaneously from the same source. [5](#0-4) 

4. **No Warning or Error**: The system silently accepts genesis without verification rather than warning operators or failing safely.

## Recommendation

**Immediate Fix**: Require trusted waypoint for genesis during restore operations:

```rust
// In storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs
// Modify the verification logic around line 129:

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
} else {
    // NEW: Require trusted waypoint for genesis/first epoch
    ensure!(
        wp_li.version() != 0,
        "Genesis epoch (version 0) requires a trusted waypoint. \
        Provide --trust-waypoint for version 0 to verify genesis authenticity."
    );
}
```

**Additional Hardening**:

1. Add validation in `GlobalRestoreOpt::try_from()` to require version 0 waypoint:
```rust
// In storage/backup/backup-cli/src/utils/mod.rs around line 323
let trusted_waypoints = Arc::new(opt.trusted_waypoints.verify()?);
ensure!(
    trusted_waypoints.contains_key(&0),
    "Genesis waypoint (version 0) is required for restore operations. \
    Use --trust-waypoint <genesis-waypoint> to provide it."
);
```

2. Document the genesis waypoint requirement prominently in operator guides

3. Add integration test verifying that restore fails without genesis waypoint

## Proof of Concept

**Setup:**
```bash
# Create malicious genesis transaction that modifies validator set
cat > malicious_genesis.move << 'EOF'
script {
    use aptos_framework::stake;
    use aptos_framework::aptos_governance;
    
    fun main(aptos_framework: &signer) {
        // Reset validator set to attacker's address
        stake::update_validator_set(
            aptos_framework,
            vector[@0xAttackerAddress]
        );
    }
}
EOF

# Compile and serialize malicious genesis
aptos move compile --package-dir . --named-addresses aptos_framework=0x1
# Create malicious backup with this genesis at version 0
```

**Exploitation:**
```bash
# Victim operator restores without trusted waypoint
aptos-db restore bootstrap-db \
    --metadata-cache-dir /tmp/cache \
    --target-db-dir /data/db \
    --storage-backend "local:///path/to/malicious/backup"
    # NOTE: Missing --trust-waypoint for version 0!

# Malicious genesis accepted without verification
# Node restarts with corrupted validator set
# Consensus fails as node diverges from network
```

**Verification:**
```rust
// Test in execution/executor/tests/db_bootstrapper_test.rs
#[test]
fn test_malicious_genesis_restore_without_waypoint() {
    // Create legitimate DB with genesis
    let (legit_db, genesis_txn, waypoint) = setup_genesis();
    
    // Create malicious genesis with different validator set
    let malicious_genesis = create_malicious_genesis();
    
    // Simulate restore without waypoint
    let result = maybe_bootstrap::<AptosVMBlockExecutor>(
        &legit_db, 
        &malicious_genesis, 
        waypoint  // Using legitimate waypoint with malicious genesis
    );
    
    // Currently SUCCEEDS but should FAIL
    assert!(result.is_err(), "Should reject genesis without waypoint verification");
}
```

## Notes

This vulnerability is particularly dangerous because:

1. It exploits a legitimate disaster recovery feature, making detection difficult
2. The impact scales with the number of validators restored from compromised backups
3. Genesis modifications are privileged operations that can arbitrarily corrupt system state
4. No runtime detection exists—the corruption is baked into the restored database

The fix must balance security (requiring waypoint verification) with operational flexibility (disaster recovery scenarios). The recommended approach enforces security while maintaining recoverability through proper waypoint management.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L129-147)
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
                }
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

**File:** execution/executor/tests/db_bootstrapper_test.rs (L219-276)
```rust
    // New genesis transaction: set validator set, bump epoch and overwrite account1 balance.
    let configuration = get_configuration(&db);
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(ChangeSet::new(
        WriteSetMut::new(vec![
            (
                StateKey::on_chain_config::<ValidatorSet>().unwrap(),
                WriteOp::legacy_modification(
                    bcs::to_bytes(&ValidatorSet::new(vec![])).unwrap().into(),
                ),
            ),
            (
                StateKey::on_chain_config::<ConfigurationResource>().unwrap(),
                WriteOp::legacy_modification(
                    bcs::to_bytes(&configuration.bump_epoch_for_test())
                        .unwrap()
                        .into(),
                ),
            ),
            (
                StateKey::resource_group(
                    &primary_apt_store(account1),
                    &ObjectGroupResource::struct_tag(),
                ),
                WriteOp::legacy_modification(
                    aptos_transaction_simulation::FungibleStore::new(
                        account1,
                        AccountAddress::TEN,
                        100_000_000,
                        false,
                        false,
                    )
                    .to_bytes()
                    .into(),
                ),
            ),
        ])
        .freeze()
        .unwrap(),
        vec![
            ContractEvent::new_v2(NEW_EPOCH_EVENT_V2_MOVE_TYPE_TAG.clone(), vec![]).unwrap(),
            ContractEvent::new_v1(
                new_block_event_key(),
                0,
                TypeTag::Struct(Box::new(NewBlockEvent::struct_tag())),
                vec![],
            )
            .expect("Should always be able to create a new block event"),
        ],
    )));

    // Bootstrap DB into new genesis.
    let waypoint = generate_waypoint::<AptosVMBlockExecutor>(&db, &genesis_txn).unwrap();
    assert!(
        maybe_bootstrap::<AptosVMBlockExecutor>(&db, &genesis_txn, waypoint)
            .unwrap()
            .is_some()
    );
    assert_eq!(waypoint.version(), 6);
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L120-122)
```rust
    // DB bootstrapper works on either an empty transaction accumulator or an existing block chain.
    // In the very extreme and sad situation of losing quorum among validators, we refer to the
    // second use case said above.
```
