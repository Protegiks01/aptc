# Audit Report

## Title
Aptos Debugger Tool Lacks Access Controls Enabling Unauthorized Access to Sensitive Validator and Consensus Data

## Summary
The `aptos-debugger` tool provides unrestricted read access to sensitive blockchain data including pending transactions, validator state, and consensus internals. Any user with command-line access and filesystem read permissions to the database directory can extract this data without authentication or authorization checks.

## Finding Description

The aptos-debugger tool exposes multiple subcommands that directly access sensitive blockchain databases without implementing any access control mechanisms:

1. **DumpPendingTxns Command** - Directly reads consensus database and quorum store to dump all pending transactions: [1](#0-0) 

2. **AptosDb Debug StateKv GetValue** - Allows reading any state value for any account at any version: [2](#0-1) 

3. **AptosDb Debug StateKv ScanSnapshot** - Enables complete enumeration of entire blockchain state at any version: [3](#0-2) 

4. **AptosDb Debug Examine PrintRawDataByVersion** - Exposes all transaction data, events, and write sets: [4](#0-3) 

The tool's main entry point performs no authentication: [5](#0-4) 

The database access layer simply opens databases from any user-provided path without validation: [6](#0-5) 

**Attack Scenario:**
1. Attacker gains limited shell access (compromised service account, container escape, shared system access)
2. Attacker identifies database directory path (typically predictable: `/opt/aptos/data/db`)
3. Attacker executes: `aptos-debugger dump-pending-txns --db-dir /opt/aptos/data/db`
4. Attacker extracts pending transactions before they become public
5. Attacker executes: `aptos-debugger aptos-db debug state-kv scan-snapshot --db-dir /opt/aptos/data/db --version 1000000`
6. Attacker enumerates all on-chain state including validator configurations, staking data, and governance information

**Invariants Broken:**
- **Access Control Invariant**: The tool bypasses normal API access controls and allows direct database access
- **Principle of Least Privilege**: Users with limited command-line access can read validator-level operational data
- **Defense in Depth**: No authentication layer between command-line access and sensitive data access

## Impact Explanation

**Severity Assessment: Low to Medium**

While this is a legitimate security concern, it does not meet the Critical or High severity thresholds defined in the Aptos bug bounty program:

- **Not Critical** - Does not directly cause loss of funds, consensus violations, network partition, or RCE
- **Not High** - Does not directly cause validator slowdowns, API crashes, or protocol violations  
- **Low Severity** - Information disclosure that could aid attackers but requires existing shell access and filesystem permissions

The exposed information includes:
- Pending transactions (potential frontrunning opportunity)
- Validator consensus state (voting patterns, QCs, blocks)
- On-chain state snapshots (staking, governance, account data)

However, this is fundamentally an **information disclosure** vulnerability rather than a direct exploitation path. The attacker still requires:
1. Shell access to the validator system
2. Filesystem read permissions to database directories
3. The data exposed is largely public blockchain data (just accessed before normal publication)

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires:
- **Attacker Prerequisites**: Command-line access + database directory read permissions
- **Common Scenarios**: Container escape, compromised service account, shared hosting environments
- **Mitigating Factors**: Proper deployment security (filesystem permissions, user isolation) prevents exploitation

In properly secured deployments where:
- Database files have restrictive permissions (owner-only read)
- The debugger binary is restricted to administrator accounts
- OS-level access controls are properly configured

This vulnerability is NOT exploitable. However, in less secure deployments or after partial compromise, it provides an easy path to sensitive data extraction.

## Recommendation

**Implement Access Controls in the Debugger Tool:**

1. **Add Authentication Check** - Verify user identity before granting access:
   - Require explicit opt-in via configuration file readable only by administrators
   - Check effective UID matches validator operator UID
   - Implement token-based authentication for remote debugging scenarios

2. **Add Authorization Check** - Verify user has permission for requested operation:
   - Maintain allowlist of authorized users
   - Implement role-based access control (RBAC)
   - Log all debugger access attempts

3. **Restrict Sensitive Operations** - Limit exposure of critical data:
   - Redact or hash sensitive fields in pending transactions
   - Implement read quotas to prevent bulk extraction
   - Add audit logging for all database access

4. **Security Warnings** - Alert operators about security implications:
   - Display warning on tool startup about sensitive data access
   - Require explicit confirmation for bulk operations
   - Document security considerations in deployment guides

**Example Implementation:**
Add an authentication check in the main function before executing commands, verifying against a configuration file that only administrators can modify.

## Proof of Concept

**Setup:**
1. Deploy Aptos validator node with default configuration
2. Create non-privileged user account: `useradd -m limited_user`
3. Grant read access to database directory: `chmod o+r /opt/aptos/data/db`

**Exploitation:**
```bash
# As limited_user (non-administrator)
$ aptos-debugger dump-pending-txns --db-dir /opt/aptos/data/db
# Successfully dumps all pending transactions

$ aptos-debugger aptos-db debug state-kv get-value \
  --db-dir /opt/aptos/data/db \
  --address 0x1 \
  --struct-tag "0x1::stake::ValidatorSet" \
  --version 1000000
# Successfully reads validator set configuration

$ aptos-debugger aptos-db debug state-kv scan-snapshot \
  --db-dir /opt/aptos/data/db \
  --version 1000000
# Successfully enumerates entire blockchain state
```

**Expected Result**: Tool executes without authentication and exposes sensitive data.

**Expected Secure Behavior**: Tool should require authentication and verify user authorization before granting database access.

---

**Notes:**

While this is a legitimate security design issue, it operates more as a **defense-in-depth** concern rather than a direct critical vulnerability. The tool is designed for administrative debugging and expects OS-level access controls to restrict its use. However, from a security best practices perspective, implementing application-level access controls would provide additional protection against privilege escalation scenarios where attackers have gained limited system access.

The severity rating reflects that this is information disclosure requiring existing privileged access, rather than a direct path to critical impact like consensus violations or fund theft.

### Citations

**File:** consensus/src/util/db_tool.rs (L37-66)
```rust
    pub async fn run(self) -> Result<()> {
        let txns = self.dump_pending_txns()?;
        println!("{txns:?}");

        Ok(())
    }

    pub fn dump_pending_txns(&self) -> Result<Vec<Transaction>> {
        let quorum_store_db = QuorumStoreDB::new(self.db_dir.clone());
        let all_batches = quorum_store_db.get_all_batches().unwrap();

        let consensus_db = ConsensusDB::new(self.db_dir.clone());
        let (_, _, blocks, _) = consensus_db.get_data()?;

        let mut txns = Vec::new();
        for block in blocks {
            let id = block.id();
            #[allow(clippy::unwrap_in_result)]
            if self.block_id.is_none() || id == self.block_id.unwrap() {
                txns.extend(
                    extract_txns_from_block(&block, &all_batches)?
                        .into_iter()
                        .cloned()
                        .map(Transaction::UserTransaction),
                );
            }
        }

        Ok(txns)
    }
```

**File:** storage/aptosdb/src/db_debugger/state_kv/get_value.rs (L35-92)
```rust
    pub fn run(self) -> Result<()> {
        /*
        let key_vec = hex::decode(&self.key_hex).unwrap();
        let key: StateKey = bcs::from_bytes(&key_vec)?;
        println!(
            "{}",
            format!(
                "* Get state value for key {:?} at version {}. \n",
                key, self.version,
            )
            .yellow()
        );*/

        let address = AccountAddress::from_hex_literal(&self.address).unwrap();
        let struct_tag = StructTag::from_str(&self.struct_tag)?;
        let key = StateKey::resource(&address, &struct_tag)?;

        let ledger_db = self.db_dir.open_ledger_db()?;
        let db = self.db_dir.open_state_kv_db()?;
        let latest_version = ledger_db
            .metadata_db()
            .get_synced_version()?
            .expect("DB is empty.");
        println!("latest version: {latest_version}");
        if self.version != Version::MAX && self.version > latest_version {
            println!(
                "{}",
                format!(
                    "warning: version {} is greater than latest version {}",
                    self.version, latest_version
                )
                .red()
            );
        }

        let mut start_version = self.version;
        let mut count = 0;
        while count < 10 {
            match db.get_state_value_with_version_by_version(&key, start_version)? {
                None => {
                    if count == 0 {
                        println!("{}", "Value not found.".to_string().yellow());
                    }
                    break;
                },
                Some((version, value)) => {
                    Self::print_value(version, value);
                    count += 1;
                    if version == 0 {
                        break;
                    }
                    start_version = version - 1;
                },
            }
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs (L39-90)
```rust
    pub fn run(self) -> Result<()> {
        println!(
            "{}",
            format!(
                "* Scan all key values in snapshot at version {} in the key hash value order. \n",
                self.version,
            )
            .yellow()
        );

        let state_kv_db = Arc::new(self.db_dir.open_state_kv_db()?);
        let state_merkle_db = Arc::new(self.db_dir.open_state_merkle_db()?);
        let total_leaves = state_merkle_db.get_leaf_count(self.version)?;
        println!("total leaves: {}", total_leaves);

        let (range_tx, range_rx) = crossbeam_channel::bounded::<(usize, usize)>(1024);
        let (result_tx, result_rx) = mpsc::channel();

        let workers: Vec<_> = (0..self.concurrency)
            .map(|_| {
                let range_rx = range_rx.clone();
                let state_merkle_db = state_merkle_db.clone();
                let state_kv_db = state_kv_db.clone();
                let result_tx = result_tx.clone();
                thread::spawn(move || {
                    while let Ok((start, len)) = range_rx.recv() {
                        let range_iter = JellyfishMerkleIterator::new_by_index(
                            state_merkle_db.clone(),
                            self.version,
                            start,
                        )
                        .unwrap()
                        .take(len);

                        for (n, leaf_res) in range_iter.enumerate() {
                            let (_key_hash, (key, key_version)) = leaf_res.unwrap();
                            let index = start + n;

                            let t = Instant::now();

                            let mut read_opts = ReadOptions::default();
                            // We want `None` if the state_key changes in iteration.
                            read_opts.set_prefix_same_as_start(true);

                            let enable_sharding = state_kv_db.enabled_sharding();

                            let (value_version, value) = if enable_sharding {
                                let mut iter = state_kv_db
                                    .db_shard(key.get_shard_id())
                                    .iter::<StateValueByKeyHashSchema>()
                                    .unwrap();
                                iter.seek(&(key.hash(), key_version)).unwrap();
```

**File:** storage/aptosdb/src/db_debugger/examine/print_raw_data_by_version.rs (L24-79)
```rust
    pub fn run(self) -> Result<()> {
        let rocksdb_config = RocksdbConfigs {
            enable_storage_sharding: self.sharding_config.enable_storage_sharding,
            ..Default::default()
        };
        let env = None;
        let block_cache = None;

        let (ledger_db, _, _, _) = AptosDB::open_dbs(
            &StorageDirPaths::from_path(&self.db_dir),
            rocksdb_config,
            env,
            block_cache,
            /*readonly=*/ true,
            /*max_num_nodes_per_lru_cache_shard=*/ 0,
            /*reset_hot_state=*/ false,
        )?;

        println!(
            "Transaction: {:?}",
            ledger_db.transaction_db().get_transaction(self.version)?
        );

        println!(
            "PersistedAuxiliaryInfo: {:?}",
            ledger_db
                .persisted_auxiliary_info_db()
                .get_persisted_auxiliary_info(self.version)?
        );

        println!(
            "WriteSet: {:?}",
            ledger_db.write_set_db().get_write_set(self.version)?
        );

        println!(
            "Events: {:?}",
            ledger_db.event_db().get_events_by_version(self.version)?
        );

        println!(
            "TransactionInfo: {:?}",
            ledger_db
                .transaction_info_db()
                .get_transaction_info(self.version)?
        );

        println!(
            "TransactionAccumulatorHash: {:?}",
            ledger_db
                .transaction_accumulator_db()
                .get_root_hash(self.version)?
        );

        Ok(())
    }
```

**File:** crates/aptos-debugger/src/main.rs (L14-20)
```rust
#[tokio::main]
async fn main() -> Result<()> {
    Logger::new().level(Level::Info).init();
    let _mp = MetricsPusher::start(vec![]);

    Cmd::parse().run().await
}
```

**File:** storage/aptosdb/src/db_debugger/common/mod.rs (L27-77)
```rust
impl DbDir {
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
}
```
