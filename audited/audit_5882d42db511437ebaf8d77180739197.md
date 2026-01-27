# Audit Report

## Title
CAS Protection Bypass During Validator Restart in VaultStorage

## Summary
The `secret_versions` in-memory HashMap in VaultStorage loses all version tracking upon validator restart, causing the first write to each secret to bypass CAS (Check-And-Set) protection entirely rather than fail. This occurs specifically during validator initialization when overriding consensus keys are written without prior reads, potentially allowing concurrent writes from multiple validator instances to succeed without conflict detection.

## Finding Description

The VaultStorage implementation uses an in-memory HashMap (`secret_versions`) to track secret versions for CAS operations. When `use_cas=true`, this is intended to provide Compare-And-Swap protection against concurrent modifications. However, this cache is entirely volatile and lost on restart. [1](#0-0) 

When a write operation occurs without a prior read after restart, the version lookup returns `None`, causing the write to bypass CAS entirely: [2](#0-1) 

The Vault client interprets `version=None` as "no CAS check required": [3](#0-2) 

**Critical Code Path**: During every validator startup, the safety rules manager writes overriding consensus keys WITHOUT reading them first: [4](#0-3) 

Line 89 performs `internal_store().set()` without any prior `get()`, meaning after restart these writes will have `version=None` and bypass CAS protection.

**Vulnerability Flow**:
1. Validator configured with Vault backend and `use_cas=true` 
2. Multiple overriding consensus keys stored in Vault (versions 5, 5, 5...)
3. Validator restarts → `secret_versions` HashMap is empty
4. Startup code (lines 79-99) writes all overriding keys
5. Each write passes `version=None` to Vault (line 171 returns None)
6. Vault writes succeed WITHOUT CAS check (line 456 in lib.rs)
7. If a duplicate validator instance is also starting/running, both write successfully
8. This violates the intended CAS protection mechanism

**Why CAS Bypass (Not Failure)**: The question asks about "CAS failures until secrets are re-read." The actual behavior is worse - there are no failures at all. Writes succeed unconditionally, bypassing the protection that CAS was meant to provide. Normal voting paths correctly read before writing [5](#0-4) , but initialization paths do not.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This issue qualifies as "State inconsistencies requiring intervention" because:

1. **Consensus Key Corruption**: Multiple validator instances writing overriding consensus keys concurrently without CAS protection could corrupt the key storage, requiring manual intervention
2. **Safety Guarantee Violation**: The entire point of `use_cas` flag is to prevent concurrent modifications - this bypass defeats that guarantee during critical initialization
3. **Operational Impact**: Split-brain scenarios (two validator instances accidentally running) would not be detected, potentially leading to double-signing attempts or key confusion

The impact is limited to Medium rather than Critical/High because:
- Requires operational misconfiguration (multiple instances) or split-brain scenario
- Doesn't directly cause consensus safety violations (SafetyData reads before writes)
- Primary risk is reliability/availability rather than security breach

## Likelihood Explanation

**Likelihood: Medium**

This issue WILL occur in the following realistic scenarios:

1. **Operator Error**: Validator operator accidentally starts two instances (e.g., old instance didn't fully shut down, or automated restart system creates duplicate)
2. **Split-Brain**: Network partition causes orchestration system to start duplicate validator instance
3. **Testing/Staging**: Forge tests or staging environments where storage is reused across multiple runs (the code even mentions this: "This can happen in environments like forge")

The overriding_identity_blobs feature is documented for production use when validators need multiple consensus keys across epochs, making this code path active in production deployments.

Frequency: Every validator restart executes lines 79-99, meaning every restart creates a window where CAS protection is bypassed for these keys.

## Recommendation

**Solution**: Always read current version before writing, even during initialization:

```rust
// In safety_rules_manager.rs, lines 79-99:
for blob in config
    .initial_safety_rules_config
    .overriding_identity_blobs()
    .unwrap_or_default()
{
    if let Some(sk) = blob.consensus_private_key {
        let pk_hex = hex::encode(PublicKey::from(&sk).to_bytes());
        let storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
        
        // FIX: Read first to populate version cache
        let _ = storage.internal_store().get::<bls12381::PrivateKey>(storage_key.as_str());
        
        match storage.internal_store().set(storage_key.as_str(), sk) {
            Ok(_) => {
                info!("Setting {storage_key} succeeded.");
            },
            Err(e) => {
                warn!("Setting {storage_key} failed: {e}");
            },
        }
    }
}
```

**Alternative**: Make version tracking persistent by storing it alongside secrets in Vault metadata, or use Vault's native version from read responses to populate cache on first read.

## Proof of Concept

```rust
// Rust test demonstrating CAS bypass after restart
#[test]
fn test_cas_bypass_on_restart() {
    // Setup Vault with CAS enabled
    let mut vault = VaultStorage::new(
        vault_host, 
        token, 
        None, 
        None, 
        true, // use_cas = true
        None, 
        None
    );
    
    // Write initial value
    vault.set("consensus_key_abc123", test_key_1).unwrap();
    assert_eq!(vault.get::<PrivateKey>("consensus_key_abc123").unwrap().value, test_key_1);
    
    // Simulate restart - create new VaultStorage instance (secret_versions is now empty)
    let mut vault_after_restart = VaultStorage::new(
        vault_host, 
        token, 
        None, 
        None, 
        true, // use_cas = true
        None, 
        None
    );
    
    // Write WITHOUT reading first (mimics overriding_identity_blobs path)
    // This should fail with CAS error, but will succeed due to version=None
    vault_after_restart.set("consensus_key_abc123", test_key_2).unwrap(); // ❌ SUCCEEDS (should fail)
    
    // Verify the key was overwritten
    assert_eq!(vault_after_restart.get::<PrivateKey>("consensus_key_abc123").unwrap().value, test_key_2);
    
    // Expected behavior: set() should have returned a CAS conflict error
    // Actual behavior: set() succeeds, bypassing CAS protection
}
```

**Notes**

This vulnerability contradicts the question's premise. The question asks about "CAS failures" but the actual issue is CAS *bypasses* - writes succeed when they should fail. The root cause is the architectural decision to use an in-memory cache for version tracking combined with initialization code that writes without reading first. While most consensus code paths correctly read-before-write [6](#0-5) , the overriding consensus key initialization path does not, creating a window of vulnerability on every validator restart.

### Citations

**File:** secure/storage/src/vault.rs (L39-39)
```rust
    secret_versions: RwLock<HashMap<String, u32>>,
```

**File:** secure/storage/src/vault.rs (L167-182)
```rust
    fn set<T: Serialize>(&mut self, key: &str, value: T) -> Result<(), Error> {
        let secret = key;
        let key = self.unnamespaced(key);
        let version = if self.use_cas {
            self.secret_versions.read().get(key).copied()
        } else {
            None
        };
        let new_version =
            self.client()
                .write_secret(secret, key, &serde_json::to_value(&value)?, version)?;
        self.secret_versions
            .write()
            .insert(key.to_string(), new_version);
        Ok(())
    }
```

**File:** secure/storage/vault/src/lib.rs (L453-457)
```rust
        let payload = if let Some(version) = version {
            json!({ "data": { key: value }, "options": {"cas": version} })
        } else {
            json!({ "data": { key: value } })
        };
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L66-66)
```rust
        let mut safety_data = self.persistent_storage.safety_data()?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L92-92)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```
