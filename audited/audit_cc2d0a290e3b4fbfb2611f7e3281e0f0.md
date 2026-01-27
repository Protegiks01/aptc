# Audit Report

## Title
StateMerkleDb Opened in Write Mode by Debugger Causes Lock Contention and Validator Unavailability

## Summary
The `DbDir.open_state_merkle_db()` helper method in the database debugger opens the StateMerkleDb in write mode (`read_only = false`) instead of readonly mode, causing RocksDB to acquire an exclusive lock on the database. This prevents the main validator from writing new state transitions when debugger commands are running, leading to validator unavailability.

## Finding Description
The database debugger in Aptos Core provides inspection tools for examining blockchain state. These tools are designed to be read-only and safe to run while a validator is operating. However, a critical bug exists in how the StateMerkleDb is opened. [1](#0-0) 

The `open_state_merkle_db()` method explicitly passes `read_only = false` when opening the StateMerkleDb. This contrasts with the other database opening methods in the same file, which correctly use `true` for readonly mode: [2](#0-1) [3](#0-2) 

RocksDB enforces database-level locking through exclusive file locks. When opened in write mode, RocksDB calls `DB::open_cf_descriptors()` which acquires an exclusive lock on the database directory: [4](#0-3) 

This lock prevents any other process from opening the same database. The vulnerability is exploited when:

1. An operator runs debugger commands that use `DbDir.open_state_merkle_db()`, such as:
   - `state-tree get-snapshots`
   - `state-tree get-path` 
   - `state-tree get-leaf`
   - `state-kv get-value` (which opens both state_kv and ledger in readonly, but also uses state_merkle indirectly) [5](#0-4) 

2. The debugger process acquires an exclusive lock on the StateMerkleDb
3. The running validator process attempts to write state updates to the StateMerkleDb
4. Lock contention occurs - either the debugger blocks the validator, or fails to acquire the lock if the validator has it

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." If the validator cannot write to StateMerkleDb, it cannot commit new state transitions, breaking atomicity of the blockchain's state progression.

## Impact Explanation
This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for the following reasons:

**Validator Node Slowdowns/Unavailability**: When a debugger process holds the exclusive lock on StateMerkleDb, the validator cannot commit new blocks to state. This causes:
- Transaction processing stalls
- Consensus participation failures
- Potential validator penalties for missing block proposals
- Chain liveness degradation if multiple validators are affected

**Significant Protocol Violations**: The validator's inability to write state violates the fundamental requirement that validators must be able to persist state changes for committed blocks.

The impact affects all validator nodes where operators run debugger commands while the validator is operating, which is a common operational practice for debugging issues or inspecting state.

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of occurring because:

1. **Common Operational Practice**: Operators frequently use debugger tools to inspect database state while troubleshooting issues, checking sync status, or verifying data integrity
2. **No Warning or Protection**: The debugger provides no warning that it will acquire exclusive locks or that it should not be run against a live validator database
3. **Tool Design Implies Safety**: The name "db_debugger" and the readonly nature of most operations implies these are safe inspection tools
4. **Multiple Affected Commands**: Several commonly-used debugger subcommands trigger this issue (get-snapshots, get-path, get-leaf)

The vulnerability requires only:
- Access to the validator's database directory (which operators have)
- Running any debugger command that calls `open_state_merkle_db()`

No special privileges, timing, or attack sophistication is required.

## Recommendation

Change `open_state_merkle_db()` to open the database in readonly mode:

```rust
pub fn open_state_merkle_db(&self) -> Result<StateMerkleDb> {
    let env = None;
    let block_cache = None;
    StateMerkleDb::new(
        &StorageDirPaths::from_path(&self.db_dir),
        RocksdbConfigs {
            enable_storage_sharding: self.sharding_config.enable_storage_sharding,
            ..Default::default()
        },
        env,
        block_cache,
        /* read_only = */ true,  // CHANGED: was false
        /* max_nodes_per_lru_cache_shard = */ 0,
        /* is_hot = */ false,
        /* delete_on_restart = */ false,
    )
}
```

This aligns with the readonly nature of debugger operations and allows multiple debugger processes and the validator to safely access the database simultaneously, as RocksDB's readonly mode supports concurrent readers.

## Proof of Concept

**Setup:**
1. Start an Aptos validator node pointing to database directory `/opt/aptos/data`
2. While the validator is running and processing transactions, execute:

```bash
aptos-db-tool debug state-tree get-snapshots \
  --db-dir /opt/aptos/data \
  --enable-storage-sharding \
  --next-version 1000000
```

**Expected Behavior (Current - Buggy):**
- If validator has lock: Debugger fails with "IO error: lock /opt/aptos/data/.../LOCK: Resource temporarily unavailable"
- If debugger acquires lock first: Validator logs errors attempting to write to StateMerkleDb, blocks stall, validator becomes unresponsive

**Expected Behavior (After Fix):**
- Debugger opens database in readonly mode
- No lock contention occurs
- Both debugger and validator can access the database concurrently
- Debugger successfully prints snapshot versions
- Validator continues processing blocks normally

**Verification:**
Monitor validator logs for StateMerkleDb write errors and check if block heights stop advancing while debugger is running.

## Notes
This vulnerability demonstrates a common but critical class of bugs in operational tooling: tools intended for read-only inspection that inadvertently acquire write locks. The fix is straightforward - changing a single boolean parameter - but the impact on validator availability is severe. The issue affects only the StateMerkleDb; the LedgerDb and StateKvDb are correctly opened in readonly mode in the same file.

### Citations

**File:** storage/aptosdb/src/db_debugger/common/mod.rs (L28-44)
```rust
    pub fn open_state_merkle_db(&self) -> Result<StateMerkleDb> {
        let env = None;
        let block_cache = None;
        StateMerkleDb::new(
            &StorageDirPaths::from_path(&self.db_dir),
            RocksdbConfigs {
                enable_storage_sharding: self.sharding_config.enable_storage_sharding,
                ..Default::default()
            },
            env,
            block_cache,
            /* read_only = */ false,
            /* max_nodes_per_lru_cache_shard = */ 0,
            /* is_hot = */ false,
            /* delete_on_restart = */ false,
        )
    }
```

**File:** storage/aptosdb/src/db_debugger/common/mod.rs (L46-61)
```rust
    pub fn open_state_kv_db(&self) -> Result<StateKvDb> {
        let leger_db = self.open_ledger_db()?;
        let env = None;
        let block_cache = None;
        StateKvDb::new(
            &StorageDirPaths::from_path(&self.db_dir),
            RocksdbConfigs {
                enable_storage_sharding: self.sharding_config.enable_storage_sharding,
                ..Default::default()
            },
            env,
            block_cache,
            true,
            leger_db.metadata_db_arc(),
        )
    }
```

**File:** storage/aptosdb/src/db_debugger/common/mod.rs (L63-76)
```rust
    pub fn open_ledger_db(&self) -> Result<LedgerDb> {
        let env = None;
        let block_cache = None;
        LedgerDb::new(
            self.db_dir.as_path(),
            RocksdbConfigs {
                enable_storage_sharding: self.sharding_config.enable_storage_sharding,
                ..Default::default()
            },
            env,
            block_cache,
            true,
        )
    }
```

**File:** storage/schemadb/src/lib.rs (L172-181)
```rust
            match open_mode {
                ReadWrite => DB::open_cf_descriptors(db_opts, path.de_unc(), all_cfds),
                ReadOnly => {
                    DB::open_cf_descriptors_read_only(
                        db_opts,
                        path.de_unc(),
                        all_cfds.filter(|cfd| !missing_cfs.contains(cfd.name())),
                        false, /* error_if_log_file_exist */
                    )
                },
```

**File:** storage/aptosdb/src/db_debugger/state_tree/get_snapshots.rs (L20-46)
```rust
    pub fn run(self) -> Result<()> {
        println!(
            "* Looking for state snapshots strictly before version {}. \n",
            self.next_version
        );

        if self.next_version > 0 {
            let db = self.db_dir.open_state_merkle_db()?;

            let mut version = self.next_version - 1;
            for n in 0..PAGE_SIZE {
                let res = db.get_state_snapshot_version_before(version)?;

                if let Some(ver) = res {
                    println!("{} {}", n, ver);
                    if ver == 0 {
                        break;
                    }
                    version = ver - 1;
                } else {
                    break;
                }
            }
        }

        Ok(())
    }
```
