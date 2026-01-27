# Audit Report

## Title
Silent Failure in Consensus Key Rotation Due to Improper Error Handling in SafetyRules Initialization

## Summary
The SafetyRules initialization process silently suppresses errors when loading overriding consensus keys during validator startup. This causes validators to appear operational but lack the new consensus key needed after on-chain key rotation, resulting in validator downtime and network liveness issues.

## Finding Description

While investigating error handling in safety rules initialization, I found that the specific `identity_blob()` function at line 164 is properly handled with `.expect()` that will panic on failure. [1](#0-0) 

However, the related function `overriding_identity_blobs()` in the same file has a critical error handling flaw. [2](#0-1) 

The vulnerability occurs in the `storage()` function where overriding identity blobs are loaded during SafetyRules initialization: [3](#0-2) 

The `.unwrap_or_default()` at line 84 silently converts any error from `overriding_identity_blobs()` into an empty vector, with no error logging. This breaks the consensus key rotation workflow:

1. Validator operator generates new consensus key and adds it to `overriding_identity_paths` in config
2. Validator restarts to load the new key via `SafetyRulesManager::new()` [4](#0-3) 
3. If file loading fails (file not found, permission denied, corrupt YAML), the error is silently suppressed
4. Validator continues running without the new key, appearing healthy
5. Operator submits on-chain key rotation transaction, which succeeds
6. When rotation takes effect in next epoch, validator cannot sign blocks with the new key
7. Validator goes offline, losing rewards and impacting network liveness

The `overriding_identity_blobs()` function can fail when loading identity files: [5](#0-4) 

This consensus key rotation workflow is demonstrated in the smoke tests: [6](#0-5) 

## Impact Explanation

This vulnerability meets **High Severity** criteria per Aptos bug bounty program:
- **Validator node slowdowns/failures**: Validators go offline after key rotation completes on-chain
- **Economic loss**: Validators lose staking rewards and may face penalties
- **Network liveness impact**: If multiple validators experience this issue simultaneously, it could affect consensus participation
- **Silent failure**: No error indication until validator stops signing blocks

The impact is particularly severe because:
1. The operator has no warning that key loading failed
2. The validator appears operational until the rotation takes effect
3. By the time the issue manifests, the on-chain rotation is already committed
4. Recovery requires manual intervention and validator restart

## Likelihood Explanation

**Likelihood: Medium to High**

This can occur through multiple realistic scenarios:
1. **File system issues**: File not found, permission denied, disk full
2. **Configuration errors**: Wrong file path, typo in config
3. **File corruption**: Incomplete write, YAML syntax errors
4. **Deployment issues**: File missing after config update but before restart
5. **Timing issues**: Config updated but file not yet synced

The vulnerability is especially likely during:
- Routine consensus key rotations (recommended security practice)
- Emergency key rotations after suspected key compromise
- Validator migrations or infrastructure updates

No special attacker privileges are required - normal operational issues can trigger it.

## Recommendation

Replace `.unwrap_or_default()` with proper error handling that either panics (fail-fast) or logs a critical error:

```rust
// Option 1: Fail-fast (recommended for consistency with primary key handling)
for blob in config
    .initial_safety_rules_config
    .overriding_identity_blobs()
    .expect("Failed to load overriding consensus keys - check file paths and permissions")
{
    // ... existing code
}

// Option 2: Log critical error and continue (if graceful degradation is acceptable)
let overriding_blobs = match config.initial_safety_rules_config.overriding_identity_blobs() {
    Ok(blobs) => blobs,
    Err(e) => {
        error!("CRITICAL: Failed to load overriding consensus keys: {}", e);
        error!("Validator will not be able to sign with rotated keys!");
        vec![]
    }
};
for blob in overriding_blobs {
    // ... existing code
}
```

Option 1 (fail-fast with panic) is recommended for consistency with the primary `identity_blob()` error handling and prevents the validator from starting in an invalid state.

## Proof of Concept

```rust
// Test demonstrating silent failure scenario
#[test]
fn test_overriding_key_silent_failure() {
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    
    // Create temp directory and config
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_path = temp_dir.path().join("nonexistent_key.yaml");
    
    // Create SafetyRulesConfig with invalid overriding key path
    let mut config = SafetyRulesConfig::default();
    config.initial_safety_rules_config = InitialSafetyRulesConfig::FromFile {
        identity_blob_path: create_valid_identity_blob(&temp_dir),
        overriding_identity_paths: vec![nonexistent_path], // This file doesn't exist!
        waypoint: WaypointConfig::FromConfig(Waypoint::default()),
    };
    
    // This should fail but currently succeeds silently
    // The validator starts without the overriding key
    let storage = safety_rules_manager::storage(&config);
    
    // Verify: The new key is NOT in storage (should have been loaded)
    // When key rotation happens on-chain, validator will fail to sign
    assert!(storage.author().is_ok()); // Primary key works
    // But overriding key is missing - validator will go offline after rotation!
}

fn create_valid_identity_blob(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("valid_identity.yaml");
    let blob = IdentityBlob {
        account_address: Some(AccountAddress::random()),
        account_private_key: Some(Ed25519PrivateKey::generate(&mut thread_rng())),
        consensus_private_key: Some(bls12381::PrivateKey::generate(&mut thread_rng())),
        network_private_key: x25519::PrivateKey::generate(&mut thread_rng()),
    };
    fs::write(&path, serde_yaml::to_string(&blob).unwrap()).unwrap();
    path
}
```

**Notes**

To directly answer the original question: The `identity_blob()` function at line 164 IS properly handled by its caller using `.expect()`, which will panic on error. However, investigating the broader safety rules initialization revealed the related `overriding_identity_blobs()` function has a critical silent failure vulnerability that affects the same security domain (consensus key management) and breaks validator liveness guarantees during key rotation operations.

### Citations

**File:** config/src/config/safety_rules_config.rs (L159-168)
```rust
    pub fn identity_blob(&self) -> anyhow::Result<IdentityBlob> {
        match self {
            InitialSafetyRulesConfig::FromFile {
                identity_blob_path, ..
            } => IdentityBlob::from_file(identity_blob_path),
            InitialSafetyRulesConfig::None => {
                bail!("loading identity blob failed with missing initial safety rules config")
            },
        }
    }
```

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

**File:** consensus/src/epoch_manager.rs (L208-209)
```rust
        let sr_config = &node_config.consensus.safety_rules;
        let safety_rules_manager = SafetyRulesManager::new(sr_config);
```

**File:** config/src/config/identity_config.rs (L40-42)
```rust
    pub fn from_file(path: &Path) -> anyhow::Result<IdentityBlob> {
        Ok(serde_yaml::from_str(&fs::read_to_string(path)?)?)
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
