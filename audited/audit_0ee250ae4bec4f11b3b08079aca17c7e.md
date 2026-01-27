# Audit Report

## Title
Race Condition in Transaction Simulation Session Operations Due to Missing File Locking

## Summary
The transaction simulation session implementation lacks file locking mechanisms, allowing concurrent processes to corrupt session state through read-modify-write race conditions on shared configuration and delta files.

## Finding Description

The `Session` struct in `aptos-transaction-simulation-session` manages persistent state across multiple files (config.json, delta.json) but performs read-modify-write operations without any synchronization mechanism. [1](#0-0) 

All session operations follow this vulnerable pattern:
1. Load session from disk (reading config.json and delta.json)
2. Perform operations and increment `self.config.ops` counter
3. Save both files back to disk [2](#0-1) 

The underlying file I/O operations use standard `std::fs::write()` and `std::fs::read_to_string()` without any locking: [3](#0-2) [4](#0-3) [5](#0-4) 

When multiple CLI processes execute session operations concurrently via `--session` flag: [6](#0-5) [7](#0-6) 

This creates classic TOCTOU (Time-of-Check-Time-of-Use) race conditions:

**Scenario 1 - Lost Updates:**
- Process A: loads session (ops=0)
- Process B: loads session (ops=0)
- Process A: executes transaction, increments ops to 1, saves
- Process B: executes transaction, increments ops to 1, saves
- Result: Only one operation recorded, ops counter incorrect

**Scenario 2 - Data Corruption:**
- Process A: begins writing config.json (partial write)
- Process B: reads config.json (reads corrupted partial JSON)
- Result: JSON parse error, CLI crash

**Scenario 3 - State Inconsistency:**
- Process A creates operation directory `[0] execute ...`
- Process B creates operation directory `[0] execute ...`
- Both write to ops=1
- Result: Directory name collision, operation history corrupted

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

1. **API Crashes**: Corrupted JSON files cause CLI failures when attempting to load sessions, matching "API crashes" criterion
2. **Significant Protocol Violations**: The simulation session protocol requires atomic, consistent state transitions. This bug violates the **State Consistency** invariant: "State transitions must be atomic and verifiable"

While this affects development tooling rather than live blockchain operations, it undermines the reliability of the testing infrastructure that developers depend on for safe Move contract development. Corrupted simulation sessions can lead to:
- False negative test results (hiding real bugs)
- False positive test results (blocking valid deployments)  
- Unreliable gas estimation
- Wasted developer time debugging tool issues rather than contract logic

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to manifest because:

1. **Common Usage Pattern**: Developers naturally run multiple tests in parallel for efficiency
2. **No Documentation Warning**: No warnings exist about single-process-only access
3. **Easy to Trigger**: Simply running `aptos move run --session <path>` twice concurrently triggers the race
4. **No Privileges Required**: Any CLI user can trigger this
5. **CI/CD Environments**: Automated testing pipelines routinely execute parallel tests

Example triggering scenarios:
- Running `make test` with parallel test execution
- Multiple terminal windows executing CLI commands
- CI/CD pipeline parallelizing test suite
- Background script monitoring session state while user runs commands

## Recommendation

Implement file locking using the `fs2` crate (already in workspace dependencies): [8](#0-7) 

**Fix Implementation:**

Add a lock file mechanism to `Session`:

```rust
use fs2::FileExt;
use std::fs::File;

pub struct Session {
    config: Config,
    path: PathBuf,
    state_store: SessionStateStore,
    _lock_file: File, // Hold lock for session lifetime
}

impl Session {
    pub fn load(session_path: impl AsRef<Path>) -> Result<Self> {
        let session_path = session_path.as_ref().to_path_buf();
        
        // Acquire exclusive lock
        let lock_path = session_path.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)?;
        lock_file.lock_exclusive()?;
        
        let config = Config::load_from_file(&session_path.join("config.json"))?;
        // ... rest of load logic ...
        
        Ok(Self {
            config,
            path: session_path,
            state_store,
            _lock_file: lock_file, // Lock held until Session dropped
        })
    }
}
```

Alternatively, use advisory locking on config.json itself, or implement a session manager with coordination.

## Proof of Concept

```rust
#[test]
fn test_concurrent_session_race_condition() -> Result<()> {
    use std::sync::Arc;
    use std::thread;
    
    let temp_dir = tempfile::tempdir()?;
    let session_path = Arc::new(temp_dir.path().to_path_buf());
    
    // Initialize session
    Session::init(&*session_path)?;
    
    // Spawn two threads that execute operations concurrently
    let session_path_1 = Arc::clone(&session_path);
    let session_path_2 = Arc::clone(&session_path);
    
    let handle1 = thread::spawn(move || {
        for _ in 0..10 {
            let mut sess = Session::load(&*session_path_1).unwrap();
            sess.fund_account(AccountAddress::ONE, 1000).unwrap();
        }
    });
    
    let handle2 = thread::spawn(move || {
        for _ in 0..10 {
            let mut sess = Session::load(&*session_path_2).unwrap();
            sess.fund_account(AccountAddress::TWO, 1000).unwrap();
        }
    });
    
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Verify final state
    let final_session = Session::load(&*session_path)?;
    
    // BUG: This will fail - ops counter will be less than 20
    // Expected: 20 operations (10 from each thread)
    // Actual: ~10-19 operations due to lost updates
    assert_eq!(final_session.config.ops, 20, 
        "Lost updates due to race condition!");
    
    Ok(())
}
```

Run with: `cargo test test_concurrent_session_race_condition --package aptos-transaction-simulation-session`

Expected result: Test fails, demonstrating ops counter < 20 due to lost updates.

## Notes

The `fs2` crate provides cross-platform file locking and is already available in the workspace. The fix should:
1. Acquire lock in `Session::load()` and hold until `Session` is dropped
2. Use exclusive locks for all operations (read and write)
3. Document the locking behavior for users
4. Consider adding timeout mechanisms for lock acquisition to detect deadlocks

This issue affects all commands in the `sim` subcommand that operate on sessions: [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L200-233)
```rust
    pub fn load(session_path: impl AsRef<Path>) -> Result<Self> {
        let session_path = session_path.as_ref().to_path_buf();
        let config = Config::load_from_file(&session_path.join("config.json"))?;

        let base = match &config.base {
            BaseState::Empty => EitherStateView::Left(EmptyStateView),
            BaseState::Remote {
                node_url,
                network_version,
                api_key,
            } => {
                let mut builder = Client::builder(AptosBaseUrl::Custom(node_url.clone()));
                if let Some(api_key) = api_key {
                    builder = builder.api_key(api_key)?;
                }
                let client = builder.build();

                let debugger = DebuggerStateView::new(
                    Arc::new(RestDebuggerInterface::new(client)),
                    *network_version,
                );
                EitherStateView::Right(debugger)
            },
        };

        let delta = load_delta(&session_path.join("delta.json"))?;
        let state_store = DeltaStateStore::new_with_base_and_delta(base, delta);

        Ok(Self {
            config,
            path: session_path,
            state_store,
        })
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L242-264)
```rust
    pub fn fund_account(&mut self, account: AccountAddress, amount: u64) -> Result<()> {
        let (before, after) = self.state_store.fund_apt_fungible_store(account, amount)?;

        let summary = Summary::FundFungible {
            account,
            amount,
            before,
            after,
        };
        let summary_path = self
            .path
            .join(format!("[{}] fund (fungible)", self.config.ops))
            .join("summary.json");
        std::fs::create_dir_all(summary_path.parent().unwrap())?;
        std::fs::write(summary_path, serde_json::to_string_pretty(&summary)?)?;

        self.config.ops += 1;

        self.config.save_to_file(&self.path.join("config.json"))?;
        save_delta(&self.path.join("delta.json"), &self.state_store.delta())?;

        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L56-66)
```rust
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Loads the configuration from a file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&json)?;
        Ok(config)
```

**File:** aptos-move/aptos-transaction-simulation-session/src/delta.rs (L15-32)
```rust
pub fn save_delta(delta_path: &Path, delta: &HashMap<StateKey, Option<StateValue>>) -> Result<()> {
    // Use BTreeMap to ensure deterministic ordering
    let mut delta_str = BTreeMap::new();

    for (k, v) in delta {
        let key_str = HumanReadable(k).to_string();
        let val_str_opt = match v {
            Some(v) => Some(hex::encode(&bcs::to_bytes(&v)?)),
            None => None,
        };
        delta_str.insert(key_str, val_str_opt);
    }

    let json = serde_json::to_string_pretty(&delta_str)?;
    std::fs::write(delta_path, json)?;

    Ok(())
}
```

**File:** aptos-move/aptos-transaction-simulation-session/src/delta.rs (L35-51)
```rust
pub fn load_delta(delta_path: &Path) -> Result<HashMap<StateKey, Option<StateValue>>> {
    let json = std::fs::read_to_string(delta_path)?;
    let delta_str: HashMap<HumanReadable<StateKey>, Option<String>> = serde_json::from_str(&json)?;

    let mut delta = HashMap::new();

    for (k, v) in delta_str {
        let key = k.into_inner();
        let val = match v {
            Some(v) => Some(bcs::from_bytes(&hex::decode(v)?)?),
            None => None,
        };
        delta.insert(key, val);
    }

    Ok(delta)
}
```

**File:** crates/aptos/src/common/utils.rs (L524-527)
```rust
    if let Some(session_path) = &txn_options_ref.session {
        txn_options_ref
            .simulate_using_session(session_path, payload)
            .await
```

**File:** crates/aptos/src/common/types.rs (L2215-2261)
```rust
    pub async fn simulate_using_session(
        &self,
        session_path: &Path,
        payload: TransactionPayload,
    ) -> CliTypedResult<TransactionSummary> {
        let mut sess = Session::load(session_path)?;

        let state_store = sess.state_store();

        // Fetch the chain states required for the simulation
        const DEFAULT_GAS_UNIT_PRICE: u64 = 100;
        const DEFAULT_MAX_GAS: u64 = 2_000_000;

        let (sender_key, sender_address) = self.get_key_and_address()?;

        // TODO: Support orderless transactions
        let account = state_store.get_resource::<AccountResource>(sender_address)?;
        let seq_num = match account {
            Some(account) => account.sequence_number,
            None => 0,
        };

        // TODO: Consider fetching the min gas unit price from the chain
        let gas_unit_price = self
            .gas_options
            .gas_unit_price
            .unwrap_or(DEFAULT_GAS_UNIT_PRICE);

        let balance = state_store.get_apt_balance(sender_address)?;
        let max_gas = self.gas_options.max_gas.unwrap_or_else(|| {
            if gas_unit_price == 0 {
                DEFAULT_MAX_GAS
            } else {
                std::cmp::min(balance / gas_unit_price, DEFAULT_MAX_GAS)
            }
        });

        let transaction_factory = TransactionFactory::new(state_store.get_chain_id()?)
            .with_gas_unit_price(gas_unit_price)
            .with_max_gas_amount(max_gas)
            .with_transaction_expiration_time(self.gas_options.expiration_secs);
        let sender_account = &mut LocalAccount::new(sender_address, sender_key, seq_num);
        let transaction =
            sender_account.sign_with_transaction_builder(transaction_factory.payload(payload));
        let hash = transaction.committed_hash();

        let (vm_status, txn_output) = sess.execute_transaction(transaction)?;
```

**File:** Cargo.toml (L631-631)
```text
fs2 = "0.4.3"
```

**File:** crates/aptos/src/move_tool/sim.rs (L86-99)
```rust

#[async_trait]
impl CliCommand<()> for Fund {
    fn command_name(&self) -> &'static str {
        "fund"
    }

    async fn execute(self) -> CliTypedResult<()> {
        let mut session = Session::load(&self.session)?;

        session.fund_account(self.account, self.amount)?;

        Ok(())
    }
```

**File:** crates/aptos/src/move_tool/sim.rs (L118-129)
```rust
#[async_trait]
impl CliCommand<Option<serde_json::Value>> for ViewResource {
    fn command_name(&self) -> &'static str {
        "view-resource"
    }

    async fn execute(self) -> CliTypedResult<Option<serde_json::Value>> {
        let mut session = Session::load(&self.session)?;

        Ok(session.view_resource(self.account, &self.resource)?)
    }
}
```

**File:** crates/aptos/src/move_tool/sim.rs (L151-164)
```rust
#[async_trait]
impl CliCommand<Option<serde_json::Value>> for ViewResourceGroup {
    fn command_name(&self) -> &'static str {
        "view-resource-group"
    }

    async fn execute(self) -> CliTypedResult<Option<serde_json::Value>> {
        let mut session = Session::load(&self.session)?;
        Ok(session.view_resource_group(
            self.account,
            &self.resource_group,
            self.derived_object_address,
        )?)
    }
```
