# Audit Report

## Title
Non-Atomic File Write in Transaction Simulation Session Causes State Corruption on Crash

## Summary
The `save_delta()` function in the transaction simulation session uses non-atomic `std::fs::write()`, allowing crashes during write operations to leave partially written JSON files that corrupt simulation state and prevent session recovery.

## Finding Description

The `save_delta()` function uses `std::fs::write()` which is not an atomic operation: [1](#0-0) 

This function is called after every critical session operation:
- After genesis initialization: [2](#0-1) 
- After remote state initialization: [3](#0-2) 
- After funding accounts: [4](#0-3) 
- After executing transactions: [5](#0-4) 

When a crash or power failure occurs during `std::fs::write()`, the file may contain partial JSON data. On subsequent session load, the `load_delta()` function attempts to parse this corrupted file: [6](#0-5) 

The JSON deserialization at line 37 will fail on malformed data, causing the entire session load to fail and rendering all accumulated simulation state unrecoverable.

The codebase demonstrates awareness of this issue through the proper atomic write pattern used elsewhere: [7](#0-6) 

Additional files with the same vulnerability:
- Config persistence: [8](#0-7) 
- Write set output: [9](#0-8) 
- Event output: [10](#0-9) 

## Impact Explanation

**Severity: Medium** - "State inconsistencies requiring intervention"

This vulnerability causes loss of simulation session state requiring manual intervention to recover. While this affects a development/testing tool rather than the production blockchain, it meets the Medium severity criteria because:

1. **State Loss**: All accumulated simulation work is lost when corruption occurs
2. **Intervention Required**: Users cannot recover the session and must recreate from scratch
3. **Data Integrity**: Violates the expectation that persisted session data remains consistent

The impact is limited to development workflows and does not affect consensus, validators, or production blockchain operations.

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood is elevated because:

1. **Frequent Writes**: `save_delta()` and `config.save_to_file()` are called after every session operation (fund, execute_transaction, view)
2. **Development Environment**: Crashes are more common during development/testing
3. **Multiple Opportunities**: Each operation creates two write opportunities (delta + config), increasing exposure
4. **No Recovery**: Unlike transient failures, file corruption persists across restarts

## Recommendation

Implement atomic file writes using the tempfile + rename pattern:

```rust
pub fn save_delta(delta_path: &Path, delta: &HashMap<StateKey, Option<StateValue>>) -> Result<()> {
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
    
    // Create temporary file in same directory for atomic rename
    let temp_path = delta_path.parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid delta path"))?;
    let mut temp_file = tempfile::NamedTempFile::new_in(temp_path)?;
    
    // Write all data
    temp_file.as_file().write_all(json.as_bytes())?;
    
    // Optional: Ensure data is synced to disk for durability
    temp_file.as_file().sync_all()?;
    
    // Atomic rename
    temp_file.persist(delta_path)?;
    
    Ok(())
}
```

Apply the same fix to `Config::save_to_file()`, `save_write_set()`, and `save_events()`.

## Proof of Concept

```rust
#[test]
fn test_crash_during_save_corrupts_state() -> Result<()> {
    use std::io::Write;
    use tempfile::TempDir;
    
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir.path();
    
    // Create and use a session
    let mut session = Session::init(session_path)?;
    let account = AccountAddress::from_hex_literal("0xcafe")?;
    session.fund_account(account, 1000)?;
    
    // Simulate crash during write by truncating delta.json mid-write
    let delta_path = session_path.join("delta.json");
    let contents = std::fs::read_to_string(&delta_path)?;
    let corrupted = &contents[..contents.len() / 2]; // Partial JSON
    
    let mut file = std::fs::File::create(&delta_path)?;
    file.write_all(corrupted.as_bytes())?;
    drop(file);
    
    // Attempt to load corrupted session
    let result = Session::load(session_path);
    
    // This will fail with JSON parse error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("EOF while parsing"));
    
    Ok(())
}
```

## Notes

This vulnerability is confirmed in the transaction simulation session infrastructure. The non-atomic write pattern leaves files vulnerable to corruption during system crashes or power failures. While the codebase contains proper atomic write patterns in other modules, the simulation session components do not utilize them, creating an unnecessary reliability risk for developers using this tooling.

### Citations

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

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L143-143)
```rust
        save_delta(&delta_path, &state_store.delta())?;
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L178-178)
```rust
        save_delta(&delta_path, &HashMap::new())?;
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L261-261)
```rust
        save_delta(&self.path.join("delta.json"), &self.state_store.delta())?;
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L349-349)
```rust
        save_delta(&self.path.join("delta.json"), &self.state_store.delta())?;
```

**File:** secure/storage/src/on_disk.rs (L64-70)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L56-60)
```rust
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/txn_output.rs (L109-109)
```rust
    std::fs::write(write_set_path, serde_json::to_string_pretty(&entries)?)?;
```

**File:** aptos-move/aptos-transaction-simulation-session/src/txn_output.rs (L158-158)
```rust
    std::fs::write(events_path, serde_json::to_string_pretty(&entries)?)?;
```
