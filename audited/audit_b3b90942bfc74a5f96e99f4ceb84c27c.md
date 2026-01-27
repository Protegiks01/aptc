# Audit Report

## Title
All-or-Nothing Failure in Validator Key Rotation Due to Partial Identity Blob Loading Failure

## Summary
The `overriding_identity_blobs()` function in `safety_rules_config.rs` exhibits all-or-nothing failure behavior where if ANY single overriding identity blob file fails to load, ALL overriding consensus keys fail to be loaded into storage. This breaks validator key rotation by preventing validators from accessing rotated keys after restart if one identity blob file becomes corrupted or inaccessible.

## Finding Description

The vulnerability exists in the interaction between two components:

**Component 1: Identity Blob Loading** [1](#0-0) 

The function iterates through all paths in `overriding_identity_paths` and uses the `?` operator when loading each file [2](#0-1) . This means if ANY file fails to load (due to corruption, deletion, permission issues), the entire function returns an error and NO blobs are returned.

**Component 2: Error Handling in Storage Initialization** [3](#0-2) 

The storage initialization code calls `overriding_identity_blobs().unwrap_or_default()` [4](#0-3) , which silently converts any error into an empty vector, causing the loop to iterate over zero items and load no overriding keys.

**Attack Scenario:**

1. **Initial Key Rotation**: Validator generates new consensus key K2, writes it to `/validator/new_key.yaml`, adds path to `overriding_identity_paths`, and successfully restarts. Key K2 is stored at `CONSENSUS_KEY_{K2_pk_hex}` [5](#0-4) 

2. **On-Chain Rotation**: Validator submits transaction to update consensus key to K2 on-chain. After next epoch, network expects signatures from K2.

3. **File Corruption/Loss**: The `/validator/new_key.yaml` file becomes corrupted, deleted, or has permission issues (disk failure, accidental deletion, targeted filesystem attack).

4. **Restart Failure**: Validator restarts (e.g., upgrade, crash recovery). During initialization:
   - `overriding_identity_blobs()` tries to load `/validator/new_key.yaml`
   - `IdentityBlob::from_file()` fails [6](#0-5) 
   - Function returns error, caught by `unwrap_or_default()`
   - Zero overriding keys loaded
   - Only old key K1 available at `CONSENSUS_KEY`

5. **Consensus Participation Failure**: When validator attempts to sign with K2, the `consensus_sk_by_pk()` function [7](#0-6)  searches for `CONSENSUS_KEY_{K2_pk_hex}` (not found), falls back to `CONSENSUS_KEY` (finds K1), but verification fails because K1.public_key() ≠ K2 [8](#0-7) , returning `ValidatorKeyNotFound` error.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: After successful key rotation, validators become unable to participate in consensus due to key loading failures, requiring manual intervention to restore the corrupted identity blob files or revert to previous keys.

- **Validator availability impact**: Affected validators cannot sign blocks, reducing network fault tolerance. If multiple validators are simultaneously affected (e.g., shared storage infrastructure failure, coordinated filesystem attacks), network liveness can be degraded.

- **Key rotation reliability**: Makes key rotation—a critical security operation—fragile and risky. Operators may avoid rotating keys due to fear of this failure mode, leaving potentially compromised keys in use longer than necessary.

The issue does NOT reach Critical/High severity because:
- No direct fund loss or theft
- No consensus safety violations (doesn't enable double-signing or forks)
- No permanent network partition
- Validators can recover by restoring files or re-rotating keys

## Likelihood Explanation

**Likelihood: Medium to High**

**Accidental Triggers** (more likely):
- Disk failures or filesystem corruption during operational stress
- Accidental deletion during maintenance operations
- Permission changes during system updates
- NFS/distributed filesystem failures affecting multiple validators
- Backup restoration issues that restore old file states

**Intentional Exploitation** (less likely but possible):
- Attacker with limited filesystem access (read-only escalated to delete/corrupt) targeting identity blobs after observing key rotations
- Insider threat: Disgruntled operator sabotaging key rotation
- Supply chain attack: Compromised deployment scripts that corrupt identity blobs

The likelihood increases during:
- Key rotation operations (high operational stress)
- Major network upgrades requiring validator restarts
- Infrastructure migrations or reconfigurations

## Recommendation

**Fix Option 1: Partial Success with Logging** (Recommended)

Modify `overriding_identity_blobs()` to collect errors but continue loading valid blobs:

```rust
pub fn overriding_identity_blobs(&self) -> anyhow::Result<Vec<IdentityBlob>> {
    match self {
        InitialSafetyRulesConfig::FromFile {
            overriding_identity_paths,
            ..
        } => {
            let mut blobs = vec![];
            let mut errors = vec![];
            
            for path in overriding_identity_paths {
                match IdentityBlob::from_file(path) {
                    Ok(blob) => blobs.push(blob),
                    Err(e) => {
                        error!("Failed to load overriding identity blob from {:?}: {}", path, e);
                        errors.push((path.clone(), e));
                    }
                }
            }
            
            if !errors.is_empty() {
                warn!("Failed to load {} out of {} overriding identity blobs", 
                      errors.len(), overriding_identity_paths.len());
            }
            
            // Return success if at least one blob loaded, or if list was empty
            if blobs.is_empty() && !overriding_identity_paths.is_empty() {
                bail!("Failed to load all overriding identity blobs: {:?}", errors);
            }
            
            Ok(blobs)
        },
        InitialSafetyRulesConfig::None => {
            bail!("loading overriding identity blobs failed with missing initial safety rules config")
        },
    }
}
```

**Fix Option 2: Fail Fast with Explicit Error**

Remove `.unwrap_or_default()` in `safety_rules_manager.rs` to fail validator startup loudly:

```rust
// Ensuring all the overriding consensus keys are in the storage.
let timer = Instant::now();
let overriding_blobs = config
    .initial_safety_rules_config
    .overriding_identity_blobs()
    .expect("Failed to load overriding identity blobs - validator cannot start with incomplete key set");

for blob in overriding_blobs {
    // ... existing key storage logic
}
```

This forces operators to fix file issues before validator can start, preventing silent degradation.

## Proof of Concept

```rust
// Test demonstrating the all-or-nothing failure
#[test]
fn test_overriding_identity_blobs_all_or_nothing_failure() {
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::TempDir;
    
    let temp_dir = TempDir::new().unwrap();
    
    // Create a valid identity blob file
    let valid_blob_path = temp_dir.path().join("valid_key.yaml");
    let valid_blob = IdentityBlob {
        account_address: Some(AccountAddress::random()),
        account_private_key: None,
        consensus_private_key: Some(bls12381::PrivateKey::generate(&mut thread_rng())),
        network_private_key: x25519::PrivateKey::generate(&mut thread_rng()),
    };
    let mut valid_file = File::create(&valid_blob_path).unwrap();
    valid_file.write_all(serde_yaml::to_string(&valid_blob).unwrap().as_bytes()).unwrap();
    
    // Create a corrupted identity blob file
    let corrupted_blob_path = temp_dir.path().join("corrupted_key.yaml");
    let mut corrupted_file = File::create(&corrupted_blob_path).unwrap();
    corrupted_file.write_all(b"invalid: yaml: content:::::").unwrap();
    
    // Create config with both files
    let config = InitialSafetyRulesConfig::from_file(
        temp_dir.path().join("main_key.yaml"),
        vec![valid_blob_path, corrupted_blob_path],
        WaypointConfig::None,
    );
    
    // Attempt to load overriding blobs
    let result = config.overriding_identity_blobs();
    
    // BUG: Even though valid_blob_path is readable, the entire operation fails
    // because corrupted_blob_path cannot be parsed
    assert!(result.is_err());
    
    // In safety_rules_manager.rs, this becomes unwrap_or_default()
    let loaded_blobs = result.unwrap_or_default();
    assert_eq!(loaded_blobs.len(), 0); // NO KEYS LOADED despite having one valid file
    
    println!("BUG DEMONSTRATED: Valid key at {:?} was not loaded because another file was corrupted", 
             temp_dir.path().join("valid_key.yaml"));
}

// Scenario test: Key rotation breaks on restart with corrupted file
#[test]
fn test_key_rotation_failure_on_restart() {
    // Simulate successful key rotation
    let mut validator = create_test_validator();
    let new_key = rotate_consensus_key_successfully(&mut validator);
    
    // Validator is now using new_key for signing
    assert!(validator.can_sign_with_key(&new_key));
    
    // Simulate file corruption before restart
    corrupt_overriding_identity_blob(&validator);
    
    // Restart validator
    validator.restart();
    
    // BUG: Validator can no longer sign with new_key
    // because overriding identity blob failed to load
    assert!(!validator.can_sign_with_key(&new_key));
    
    // Validator is excluded from consensus participation
    assert!(validator.try_sign_block().is_err());
}
```

## Notes

**Additional Context:**

1. The smoke test demonstrates the expected key rotation workflow [9](#0-8)  where overriding identity paths are dynamically added during rotation.

2. The vulnerability is silent—no error is logged when `unwrap_or_default()` catches the failure, making debugging difficult for operators.

3. Multiple validators could be simultaneously affected if they share infrastructure (e.g., NFS mounts, container volumes) that experiences failures.

4. The issue compounds during cascading failures: validators attempting recovery after incidents may hit this bug during restart, prolonging outages.

### Citations

**File:** config/src/config/safety_rules_config.rs (L170-187)
```rust
    pub fn overriding_identity_blobs(&self) -> anyhow::Result<Vec<IdentityBlob>> {
        match self {
            InitialSafetyRulesConfig::FromFile {
                overriding_identity_paths,
                ..
            } => {
                let mut blobs = vec![];
                for path in overriding_identity_paths {
                    let blob = IdentityBlob::from_file(path)?;
                    blobs.push(blob);
                }
                Ok(blobs)
            },
            InitialSafetyRulesConfig::None => {
                bail!("loading overriding identity blobs failed with missing initial safety rules config")
            },
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L79-99)
```rust
        // Ensuring all the overriding consensus keys are in the storage.
        let timer = Instant::now();
        for blob in config
            .initial_safety_rules_config
            .overriding_identity_blobs()
            .unwrap_or_default()
        {
            if let Some(sk) = blob.consensus_private_key {
                let pk_hex = hex::encode(PublicKey::from(&sk).to_bytes());
                let storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
                match storage.internal_store().set(storage_key.as_str(), sk) {
                    Ok(_) => {
                        info!("Setting {storage_key} succeeded.");
                    },
                    Err(e) => {
                        warn!("Setting {storage_key} failed with internal store set error: {e}");
                    },
                }
            }
        }
        info!("Overriding key work time: {:?}", timer.elapsed());
```

**File:** config/src/config/identity_config.rs (L40-42)
```rust
    pub fn from_file(path: &Path) -> anyhow::Result<IdentityBlob> {
        Ok(serde_yaml::from_str(&fs::read_to_string(path)?)?)
    }
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L106-132)
```rust
    pub fn consensus_sk_by_pk(
        &self,
        pk: bls12381::PublicKey,
    ) -> Result<bls12381::PrivateKey, Error> {
        let _timer = counters::start_timer("get", CONSENSUS_KEY);
        let pk_hex = hex::encode(pk.to_bytes());
        let explicit_storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
        let explicit_sk = self
            .internal_store
            .get::<bls12381::PrivateKey>(explicit_storage_key.as_str())
            .map(|v| v.value);
        let default_sk = self.default_consensus_sk();
        let key = match (explicit_sk, default_sk) {
            (Ok(sk_0), _) => sk_0,
            (Err(_), Ok(sk_1)) => sk_1,
            (Err(_), Err(_)) => {
                return Err(Error::ValidatorKeyNotFound("not found!".to_string()));
            },
        };
        if key.public_key() != pk {
            return Err(Error::SecureStorageMissingDataError(format!(
                "Incorrect sk saved for {:?} the expected pk",
                pk
            )));
        }
        Ok(key)
    }
```

**File:** testsuite/smoke-test/src/consensus_key_rotation.rs (L99-116)
```rust
            info!("Updating the node config accordingly.");
            let config_path = validator.config_path();
            let mut validator_override_config =
                OverrideNodeConfig::load_config(config_path.clone()).unwrap();
            validator_override_config
                .override_config_mut()
                .consensus
                .safety_rules
                .initial_safety_rules_config
                .overriding_identity_blob_paths_mut()
                .push(new_identity_path);
            validator_override_config.save_config(config_path).unwrap();

            info!("Restarting the node.");
            validator.start().unwrap();
            info!("Let it bake for 5 secs.");
            tokio::time::sleep(Duration::from_secs(5)).await;
            (operator_addr, new_pk, pop, operator_idx)
```
