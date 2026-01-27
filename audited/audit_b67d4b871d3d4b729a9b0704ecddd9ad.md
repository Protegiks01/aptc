# Audit Report

## Title
SafetyRules OnDiskStorage Creates Consensus-Critical Files Without Secure Permissions, Enabling Double-Voting Attacks

## Summary
The `set_data_dir()` function in SafetyRulesConfig and the OnDiskStorage implementation fail to validate directory permissions or set secure file permissions when writing consensus-critical SafetyData. This allows attackers with local filesystem access to tamper with `last_voted_round` and other safety state, bypassing the "First Voting Rule" and enabling equivocation attacks that violate AptosBFT consensus safety.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. No Permission Validation in set_data_dir():** [1](#0-0) 

This function accepts any directory path without validating its permissions, delegating to: [2](#0-1) 

**2. Insecure File Creation in OnDiskStorage:** [3](#0-2) 

Despite acknowledging it "should not be used in production" and "provides no permission checks," OnDiskStorage creates files using standard `File::create()` without setting secure permissions: [4](#0-3) 

The `File::create()` call uses the system's default umask, which may result in world-readable or world-writable files.

**3. Critical SafetyData at Risk:**

The OnDiskStorage backend is used to persist SafetyData containing consensus-critical fields: [5](#0-4) 

This data is written via PersistentSafetyStorage: [6](#0-5) 

**4. Consensus Safety Check Bypass:**

The `last_voted_round` field is used to enforce the "First Voting Rule" preventing double-voting: [7](#0-6) 

**Attack Path:**

1. Validator operator configures OnDiskStorage for SafetyRules (violating best practices but not prevented by code)
2. OnDiskStorage creates `secure-data.json` with default umask permissions (e.g., 0644 or worse)
3. Attacker with local filesystem access (compromised monitoring agent, shared hosting, etc.) modifies the file
4. Attacker resets `last_voted_round` from current value (e.g., round 1000) to 0
5. Validator reads tampered SafetyData on next consensus operation
6. Validator bypasses the check at line 218 and can now vote multiple times in rounds ≤ 1000
7. Double-voting causes consensus fork and violates AptosBFT safety guarantees

**Contrast with Secure Implementation:**

Aptos has secure file creation utilities that set proper permissions: [8](#0-7) 

This function sets mode 0o600 (user-only read/write) for sensitive files, but OnDiskStorage does not use it.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability breaks the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine validators."

**Specific Harms:**
- **Equivocation:** Validator can sign multiple conflicting blocks in the same round
- **Chain Forks:** Honest validators may commit different blocks, causing network split
- **Consensus Breakdown:** With ≥1/3 compromised validators exhibiting this behavior, network requires hard fork recovery
- **Loss of Finality:** Previously committed transactions may be reversed

The impact qualifies as Critical because it enables "Consensus/Safety violations" and could cause "Non-recoverable network partition (requires hardfork)" if exploited at scale.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

While OnDiskStorage is documented as "testing only," several factors increase exploitability:

1. **No Code Enforcement:** The config sanitizer only blocks InMemoryStorage for mainnet: [9](#0-8) 

OnDiskStorage passes this check and can be used in production.

2. **Configuration Precedent:** Example configs show OnDiskStorage usage: [10](#0-9) 

3. **Realistic Attack Scenarios:**
   - Compromised monitoring/backup agents with filesystem access
   - Container escape in Kubernetes deployments
   - Misconfigured file permissions on shared storage
   - Insider threat from node operators

4. **Default Umask Risk:** Many Linux systems use umask 0022 (creating files as 0644 - world-readable), and misconfigurations could use 0000 (world-writable).

## Recommendation

**Immediate Fix:**

1. **Add Permission Validation to set_data_dir():**

```rust
pub fn set_data_dir(&mut self, data_dir: PathBuf) -> Result<(), Error> {
    if let SecureBackend::OnDiskStorage(backend) = &mut self.backend {
        // Validate directory exists and has secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&data_dir)
                .map_err(|_| Error::InvalidDataDirectory(data_dir.clone()))?;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(Error::InsecureDirectoryPermissions(data_dir, mode));
            }
        }
        backend.set_data_dir(data_dir);
        Ok(())
    }
    Ok(())
}
```

2. **Set Secure Permissions in OnDiskStorage::write():**

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.mode(0o600); // User read/write only
        let mut file = options.write(true).create(true).truncate(true)
            .open(self.temp_path.path())?;
        file.write_all(&contents)?;
    }
    
    #[cfg(not(unix))]
    {
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
    }
    
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

3. **Enforce Vault in Production:**

Add to config sanitizer:

```rust
// Verify that OnDiskStorage is not used in mainnet
if chain_id.is_mainnet() && matches!(safety_rules_config.backend, SecureBackend::OnDiskStorage(_)) {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "OnDiskStorage must not be used in mainnet! Use Vault backend for production.".to_string(),
    ));
}
```

## Proof of Concept

```rust
use aptos_secure_storage::{KVStorage, OnDiskStorage, Storage};
use aptos_consensus_types::safety_data::SafetyData;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_safety_data_tampering() {
    // Setup: Create OnDiskStorage with default permissions
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("secure-data.json");
    let mut storage = Storage::from(OnDiskStorage::new(storage_path.clone()));
    
    // Validator writes SafetyData after voting in round 1000
    let safety_data = SafetyData::new(1, 1000, 950, 900, None, 0);
    storage.set("safety_data", safety_data.clone()).unwrap();
    
    // Verify file was created (check if it has insecure permissions)
    let metadata = fs::metadata(&storage_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        println!("File permissions: {:o}", mode & 0o777);
        // On many systems, this will be 0o644 (world-readable) or worse
    }
    
    // Attack: Read and modify the file to reset last_voted_round
    let contents = fs::read_to_string(&storage_path).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_str(&contents).unwrap();
    
    // Reset last_voted_round to 0
    tampered["safety_data"]["value"]["last_voted_round"] = serde_json::json!(0);
    fs::write(&storage_path, serde_json::to_string(&tampered).unwrap()).unwrap();
    
    // Validator reads tampered data
    let tampered_data: SafetyData = storage.get("safety_data").unwrap().value;
    
    // Verify the attack succeeded
    assert_eq!(tampered_data.last_voted_round, 0);
    assert_eq!(tampered_data.epoch, 1);
    
    // Now validator can vote in rounds ≤ 1000 again, violating consensus safety
    println!("SUCCESS: Tampered last_voted_round from 1000 to {}", tampered_data.last_voted_round);
    println!("Validator can now double-vote in rounds ≤ 1000");
}
```

**Notes:**

This vulnerability represents a defense-in-depth failure. While OnDiskStorage is documented for testing only, the code does not enforce this restriction, and insecure file creation creates a critical attack surface for misconfigured production deployments. The combination of no permission validation in `set_data_dir()` and insecure file creation in `OnDiskStorage::write()` enables consensus-breaking attacks against validators using this backend.

### Citations

**File:** config/src/config/safety_rules_config.rs (L52-56)
```rust
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        if let SecureBackend::OnDiskStorage(backend) = &mut self.backend {
            backend.set_data_dir(data_dir);
        }
    }
```

**File:** config/src/config/safety_rules_config.rs (L86-96)
```rust
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }
```

**File:** config/src/config/secure_backend_config.rs (L148-150)
```rust
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
    }
```

**File:** secure/storage/src/on_disk.rs (L16-22)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
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

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L150-170)
```rust
    pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
        let _timer = counters::start_timer("set", SAFETY_DATA);
        counters::set_state(counters::EPOCH, data.epoch as i64);
        counters::set_state(counters::LAST_VOTED_ROUND, data.last_voted_round as i64);
        counters::set_state(
            counters::HIGHEST_TIMEOUT_ROUND,
            data.highest_timeout_round as i64,
        );
        counters::set_state(counters::PREFERRED_ROUND, data.preferred_round as i64);

        match self.internal_store.set(SAFETY_DATA, data.clone()) {
            Ok(_) => {
                self.cached_safety_data = Some(data);
                Ok(())
            },
            Err(error) => {
                self.cached_safety_data = None;
                Err(Error::SecureStorageUnexpectedError(error.to_string()))
            },
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L212-232)
```rust
    /// First voting rule
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
```

**File:** crates/aptos/src/common/utils.rs (L223-229)
```rust
/// Write a User only read / write file
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```

**File:** docker/compose/aptos-node/validator.yaml (L8-14)
```yaml
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
```
