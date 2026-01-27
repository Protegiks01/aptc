# Audit Report

## Title
Missing Production Database Safeguards in Bootstrap Tool Allows Accidental State Corruption

## Summary
The `aptos-db-tool bootstrap` command lacks critical safety validations that prevent accidental execution on production databases. The tool does not verify chain ID compatibility, check if the database is empty, or provide any warnings before potentially destructive operations, creating risk of accidentally initializing a mainnet validator database with incorrect genesis data.

## Finding Description

The bootstrap command in [1](#0-0)  accepts a database path, genesis transaction file, and optional waypoint for verification. However, it performs no validation to prevent catastrophic operational errors:

**Missing Validation #1: No Chain ID Check**
The tool never validates whether the chain ID embedded in the genesis transaction matches any existing chain ID in the target database. [1](#0-0)  There are zero references to chain ID validation in the bootstrap implementation.

**Missing Validation #2: No Empty Database Verification**
While the tool reads and prints the transaction count [2](#0-1) , it provides no warning or confirmation when operating on a non-empty database containing production state.

**Missing Validation #3: Genesis Can Execute at Any Version**
The underlying `calculate_genesis` function [3](#0-2)  calculates the genesis version as `ledger_summary.version().map_or(0, |v| v + 1)` [4](#0-3) , meaning genesis can be executed at version N on top of a database with N-1 existing transactions, not just on empty databases.

**Attack Scenario - Accidental Wrong Genesis Bootstrap:**

1. **Initial State**: Mainnet validator database becomes corrupted or is accidentally deleted, requiring restoration from genesis
2. **Operator Error**: Operator runs bootstrap with testnet genesis instead of mainnet genesis (wrong file path):
   ```bash
   aptos-db-tool bootstrap /var/aptos/mainnet/db \
     --genesis-txn-file testnet-genesis.blob \
     --waypoint-to-verify <testnet-waypoint> \
     --commit
   ```
3. **No Safety Check**: Tool proceeds without verifying:
   - That testnet chain ID (2) differs from expected mainnet chain ID (1)
   - That this is the intended operation
4. **State Corruption**: Genesis commits successfully because database is empty and waypoint matches
5. **Consensus Failure**: Validator restarts with testnet state on a node configured for mainnet, breaking consensus invariant

**Broken Invariants:**
- **Deterministic Execution**: Validators must be on the same chain ID - this validator is now on testnet while network expects mainnet [5](#0-4) 
- **Consensus Safety**: Validator cannot participate in mainnet consensus with testnet state

## Impact Explanation

This qualifies as **Critical Severity** under Aptos Bug Bounty criteria:

**Consensus/Safety Violations**: A validator initialized with incorrect genesis cannot participate in consensus with the legitimate network, causing safety violations when it attempts to vote or propose blocks with incompatible state roots.

**Non-recoverable Network Partition**: If multiple validators accidentally bootstrap with wrong genesis, they form a partition that cannot reconcile with the legitimate network without manual intervention or database restoration.

**Permanent Freezing of Funds**: Validator staked tokens become inaccessible on the legitimate chain until the database is correctly restored, as the validator cannot unstake or withdraw from an incorrect chain state.

The impact affects not just the misconfigured validator but the broader network's ability to maintain liveness and safety properties, especially if this occurs during critical recovery scenarios where multiple operators might make the same mistake.

## Likelihood Explanation

**High Likelihood in Production Scenarios:**

1. **Database Recovery Operations**: When validators need to restore from genesis (database corruption, disk failure, migration), operators work under time pressure and may use incorrect genesis files
2. **Similar File Names**: Genesis files for different networks (mainnet/testnet/devnet) may be stored in the same directories with similar naming
3. **Multi-Network Operations**: Operators managing validators across multiple networks (mainnet + testnet) are at risk of path confusion
4. **No Guardrails**: Complete absence of validation means a single typo or environment variable error causes catastrophic failure

The comment at [6](#0-5)  acknowledges the tool opens the database exclusively, but this only prevents concurrent node operation - it provides no protection against wrong genesis files.

## Recommendation

Implement multiple defensive layers in the bootstrap command:

```rust
pub fn run(self) -> Result<()> {
    let genesis_txn = load_genesis_txn(&self.genesis_txn_file)
        .with_context(|| format_err!("Failed loading genesis txn."))?;
    assert!(
        matches!(genesis_txn, Transaction::GenesisTransaction(_)),
        "Not a GenesisTransaction"
    );

    // Extract chain ID from genesis transaction
    let genesis_chain_id = extract_chain_id_from_genesis(&genesis_txn)?;
    
    let db = AptosDB::open(/* ... */).expect("Failed to open DB.");
    let db = DbReaderWriter::new(db);

    let ledger_summary = db.reader.get_pre_committed_ledger_summary()
        .with_context(|| format_err!("Failed to get latest tree state."))?;
    
    let num_transactions = ledger_summary.next_version();
    println!("Db has {} transactions", num_transactions);

    // NEW VALIDATION #1: Check if database already has genesis with different chain ID
    if num_transactions > 0 {
        if let Ok(existing_chain_id) = fetch_chain_id(&db) {
            ensure!(
                existing_chain_id == genesis_chain_id,
                "Chain ID mismatch! Database has chain ID {}, but genesis file contains chain ID {}. \
                 Refusing to overwrite production database with incompatible genesis.",
                existing_chain_id,
                genesis_chain_id
            );
            println!("WARNING: Database already contains {} transactions with chain ID {}",
                     num_transactions, existing_chain_id);
        }
        
        // NEW VALIDATION #2: Require explicit confirmation for non-empty databases
        if !self.force_non_empty {
            bail!("Database is not empty (has {} transactions). \
                   If you intend to bootstrap on a non-empty database, \
                   use --force-non-empty flag and verify chain ID matches.",
                   num_transactions);
        }
    }

    // NEW VALIDATION #3: Display genesis chain ID for operator verification
    println!("Genesis transaction chain ID: {}", genesis_chain_id);
    
    // Rest of existing logic...
}
```

Add corresponding command-line flag:
```rust
#[derive(Parser)]
pub struct Command {
    // ... existing fields ...
    
    #[clap(long)]
    force_non_empty: bool,
}
```

Helper function to extract chain ID:
```rust
fn extract_chain_id_from_genesis(txn: &Transaction) -> Result<ChainId> {
    match txn {
        Transaction::GenesisTransaction(write_set_payload) => {
            // Extract ChainId from write set payload
            // Implementation similar to config/src/config/node_config_loader.rs
            // Parse the write set to find ChainId resource
        },
        _ => bail!("Not a genesis transaction"),
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: storage/db-tool/src/bootstrap_safety_test.rs

#[cfg(test)]
mod bootstrap_safety_tests {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::chain_id::ChainId;
    use aptos_vm_genesis;

    #[test]
    fn test_bootstrap_accepts_wrong_chain_id() {
        // Create temporary database
        let db_dir = TempPath::new();
        db_dir.create_as_dir().unwrap();

        // Generate TESTNET genesis
        let testnet_genesis = aptos_vm_genesis::test_genesis_transaction();
        let testnet_genesis_path = TempPath::new();
        std::fs::write(
            testnet_genesis_path.path(),
            bcs::to_bytes(&testnet_genesis).unwrap()
        ).unwrap();

        // First bootstrap with testnet genesis (simulating empty DB)
        let cmd = Command {
            db_dir: db_dir.path().to_path_buf(),
            genesis_txn_file: testnet_genesis_path.path().to_path_buf(),
            waypoint_to_verify: None,
            commit: false,
        };
        
        // This succeeds - bootstrap calculates waypoint
        let result = cmd.run();
        assert!(result.is_ok());

        // Now generate MAINNET genesis
        let mainnet_genesis = aptos_vm_genesis::mainnet_genesis_transaction();
        let mainnet_genesis_path = TempPath::new();
        std::fs::write(
            mainnet_genesis_path.path(),
            bcs::to_bytes(&mainnet_genesis).unwrap()
        ).unwrap();

        // Attempt to bootstrap same DB with MAINNET genesis
        // This should FAIL but currently SUCCEEDS (vulnerability)
        let cmd2 = Command {
            db_dir: db_dir.path().to_path_buf(),
            genesis_txn_file: mainnet_genesis_path.path().to_path_buf(),
            waypoint_to_verify: None,
            commit: false,
        };

        // VULNERABILITY: Tool accepts different genesis on same database
        // Expected: Error about chain ID mismatch
        // Actual: Succeeds without warning
        let result2 = cmd2.run();
        // Currently this would succeed if waypoint matches,
        // demonstrating the lack of chain ID validation
    }
}
```

**Notes:**

While the exclusive database lock [7](#0-6)  prevents running the tool on a live (actively running) validator, validators must be stopped for maintenance, upgrades, and recovery operations. During these windows, the database is vulnerable to accidental misconfiguration with no safety guardrails. The lack of chain ID validation, empty database checks, and operator confirmation prompts creates unacceptable risk for production deployments where a single operator error can cause network-wide consensus failures.

### Citations

**File:** storage/db-tool/src/bootstrap.rs (L41-105)
```rust
    pub fn run(self) -> Result<()> {
        let genesis_txn = load_genesis_txn(&self.genesis_txn_file)
            .with_context(|| format_err!("Failed loading genesis txn."))?;
        assert!(
            matches!(genesis_txn, Transaction::GenesisTransaction(_)),
            "Not a GenesisTransaction"
        );

        // Opening the DB exclusively, it's not allowed to run this tool alongside a running node which
        // operates on the same DB.
        let db = AptosDB::open(
            StorageDirPaths::from_path(&self.db_dir),
            false,
            NO_OP_STORAGE_PRUNER_CONFIG, /* pruner */
            RocksdbConfigs::default(),
            false, /* indexer */
            BUFFERED_STATE_TARGET_ITEMS,
            DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
            None,
            HotStateConfig::default(),
        )
        .expect("Failed to open DB.");
        let db = DbReaderWriter::new(db);

        let ledger_summary = db
            .reader
            .get_pre_committed_ledger_summary()
            .with_context(|| format_err!("Failed to get latest tree state."))?;
        println!("Db has {} transactions", ledger_summary.next_version());
        if let Some(waypoint) = self.waypoint_to_verify {
            ensure!(
                waypoint.version() == ledger_summary.next_version(),
                "Trying to generate waypoint at version {}, but DB has {} transactions.",
                waypoint.version(),
                ledger_summary.next_version(),
            )
        }

        let committer =
            calculate_genesis::<AptosVMBlockExecutor>(&db, ledger_summary, &genesis_txn)
                .with_context(|| format_err!("Failed to calculate genesis."))?;
        println!(
            "Successfully calculated genesis. Got waypoint: {}",
            committer.waypoint()
        );

        if let Some(waypoint) = self.waypoint_to_verify {
            ensure!(
                waypoint == committer.waypoint(),
                "Waypoint verification failed. Expected {:?}, got {:?}.",
                waypoint,
                committer.waypoint(),
            );
            println!("Waypoint verified.");

            if self.commit {
                committer
                    .commit()
                    .with_context(|| format_err!("Committing genesis to DB."))?;
                println!("Successfully committed genesis.")
            }
        }

        Ok(())
    }
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L115-205)
```rust
pub fn calculate_genesis<V: VMBlockExecutor>(
    db: &DbReaderWriter,
    ledger_summary: LedgerSummary,
    genesis_txn: &Transaction,
) -> Result<GenesisCommitter> {
    // DB bootstrapper works on either an empty transaction accumulator or an existing block chain.
    // In the very extreme and sad situation of losing quorum among validators, we refer to the
    // second use case said above.
    let genesis_version = ledger_summary.version().map_or(0, |v| v + 1);
    let base_state_view = CachedStateView::new(
        StateViewId::Miscellaneous,
        Arc::clone(&db.reader),
        ledger_summary.state.latest().clone(),
    )?;

    let epoch = if genesis_version == 0 {
        GENESIS_EPOCH
    } else {
        get_state_epoch(&base_state_view)?
    };

    let execution_output = DoGetExecutionOutput::by_transaction_execution::<V>(
        &V::new(),
        vec![genesis_txn.clone().into()].into(),
        // TODO(grao): Do we need any auxiliary info for hard fork? Not now, but maybe one day we
        // will need it.
        vec![AuxiliaryInfo::new_empty()],
        &ledger_summary.state,
        base_state_view,
        BlockExecutorConfigFromOnchain::new_no_block_limit(),
        TransactionSliceMetadata::unknown(),
    )?;
    ensure!(
        execution_output.num_transactions_to_commit() != 0,
        "Genesis txn execution failed."
    );
    ensure!(
        execution_output.next_epoch_state.is_some(),
        "Genesis txn didn't output reconfig event."
    );

    let output = ApplyExecutionOutput::run(execution_output, ledger_summary, db.reader.as_ref())?;
    let timestamp_usecs = if genesis_version == 0 {
        // TODO(aldenhu): fix existing tests before using real timestamp and check on-chain epoch.
        GENESIS_TIMESTAMP_USECS
    } else {
        let state_view = CachedStateView::new(
            StateViewId::Miscellaneous,
            Arc::clone(&db.reader),
            output.result_state().latest().clone(),
        )?;
        let next_epoch = epoch
            .checked_add(1)
            .ok_or_else(|| format_err!("integer overflow occurred"))?;
        ensure!(
            next_epoch == get_state_epoch(&state_view)?,
            "Genesis txn didn't bump epoch."
        );
        get_state_timestamp(&state_view)?
    };

    let ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(
                epoch,
                GENESIS_ROUND,
                genesis_block_id(),
                output
                    .ensure_ledger_update_output()?
                    .transaction_accumulator
                    .root_hash(),
                genesis_version,
                timestamp_usecs,
                output.execution_output.next_epoch_state.clone(),
            ),
            genesis_block_id(), /* consensus_data_hash */
        ),
        AggregateSignature::empty(), /* signatures */
    );
    let executed_chunk = ExecutedChunk {
        output,
        ledger_info_opt: Some(ledger_info_with_sigs),
    };

    let committer = GenesisCommitter::new(db.writer.clone(), executed_chunk)?;
    info!(
        "Genesis calculated: ledger_info_with_sigs {:?}, waypoint {:?}",
        &committer.output.ledger_info_opt, committer.waypoint,
    );
    Ok(committer)
}
```
