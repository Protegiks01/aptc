# Audit Report

## Title
Validator Consensus Key Name Disclosure in Storage Error Messages

## Summary
The `OnDiskStorage::get()` function in `secure/storage/src/on_disk.rs` includes the full key name in `Error::KeyNotSet` error messages, which can leak operational information about validator consensus key structure and usage patterns to attackers with access to validator logs.

## Finding Description

The vulnerability exists in the storage layer's error handling mechanism. When a key lookup fails, the error message includes the complete key name that was requested. [1](#0-0) 

The `Error::KeyNotSet` variant is defined to include the key name in its display output: [2](#0-1) 

For consensus keys during key rotation, the storage system uses key names in the format `consensus_{pk_hex}` where `pk_hex` is the hex-encoded public key: [3](#0-2) 

When consensus key lookup fails, the error propagates through the error conversion chain. The storage error is converted to a safety rules error: [4](#0-3) 

And eventually causes a panic in epoch transitions with the full error message: [5](#0-4) 

This leaks operational information including:
- Specific consensus public keys a validator is attempting to use
- Timing of key rotation attempts
- Key lookup failures indicating misconfigurations
- Which validators are experiencing storage issues

## Impact Explanation

This qualifies as **Low Severity** according to Aptos bug bounty criteria as a "minor information leak." While the question categorizes this as Medium severity, the actual impact aligns with Low severity because:

1. **No Direct Harm**: Does not lead to loss of funds, consensus violations, or network compromise
2. **Public Keys Are Public**: Consensus public keys are already stored on-chain in ValidatorSet and are publicly accessible
3. **Reconnaissance Value Only**: Information only aids attackers in understanding validator infrastructure and identifying potential targets
4. **Requires Log Access**: Exploitation requires the attacker to already have access to validator logs through monitoring systems, exposed endpoints, or compromised infrastructure

The leaked information could help attackers:
- Identify misconfigured validators as potential targets
- Understand key rotation patterns and timing
- Map validator infrastructure for planning sophisticated attacks

However, it does not directly compromise cryptographic key material or enable immediate exploitation.

## Likelihood Explanation

The likelihood of exploitation is **Medium to Low**:

**Prerequisites for Attack:**
- Attacker must gain access to validator logs through compromised monitoring infrastructure, exposed logging endpoints, or leaked log files
- Key lookup failures must occur (during key rotation, misconfiguration, or storage issues)
- Attacker must correlate leaked information with other reconnaissance data

**Frequency of Exposure:**
- Error occurs during legitimate operational scenarios (key rotation, storage failures)
- Panic messages with full error details are logged to validator stderr/logs
- Many validators use centralized log aggregation services that could be compromised

## Recommendation

Implement sanitized error messages that omit sensitive key identifiers from logged errors while preserving diagnostic information for operators:

```rust
// In secure/storage/src/on_disk.rs
fn get<V: DeserializeOwned>(&self, key: &str) -> Result<GetResponse<V>, Error> {
    let mut data = self.read()?;
    data.remove(key)
        .ok_or_else(|| {
            // Redact sensitive key patterns before logging
            let sanitized_key = if key.starts_with("consensus_") {
                "consensus_[REDACTED]"
            } else {
                key
            };
            Error::KeyNotSet(sanitized_key.to_string())
        })
        .and_then(|value| serde_json::from_value(value).map_err(|e| e.into()))
}
```

Alternatively, use separate internal and external error representations, logging the full key internally for diagnostics while exposing sanitized messages externally.

## Proof of Concept

```rust
// Test demonstrating key name leakage in error messages
#[cfg(test)]
mod key_leakage_test {
    use super::*;
    use aptos_crypto::{bls12381, PrivateKey};
    use aptos_temppath::TempPath;
    
    #[test]
    fn test_consensus_key_name_leakage() {
        // Create test storage
        let temp_path = TempPath::new();
        temp_path.create_as_file().unwrap();
        let storage = OnDiskStorage::new(temp_path.path().to_path_buf());
        
        // Generate a test consensus public key
        let private_key = bls12381::PrivateKey::generate_for_testing();
        let public_key = bls12381::PublicKey::from(&private_key);
        let pk_hex = hex::encode(public_key.to_bytes());
        
        // Construct the key name that would be used for overriding consensus keys
        let storage_key = format!("consensus_{}", pk_hex);
        
        // Attempt to retrieve non-existent key
        let result = storage.get::<bls12381::PrivateKey>(&storage_key);
        
        // Verify the error message contains the full key name including public key hex
        assert!(result.is_err());
        let error = result.unwrap_err();
        let error_msg = format!("{}", error);
        
        // The error message will be "Key not set: consensus_{pk_hex}"
        // This leaks the public key that was attempted to be loaded
        assert!(error_msg.contains(&storage_key));
        assert!(error_msg.contains(&pk_hex));
        
        println!("Leaked error message: {}", error_msg);
        println!("Exposed public key hex: {}", pk_hex);
    }
}
```

## Notes

While consensus public keys are already publicly available on-chain through the ValidatorSet, the error message leakage still provides operational intelligence about:
- Which specific keys validators are actively attempting to use
- Timing of key operations and failures  
- Configuration state of individual validator nodes

The vulnerability classification as Low severity (rather than Medium as suggested in the question) aligns with the Aptos bug bounty program's explicit categorization of "minor information leaks" under Low Severity (up to $1,000).

### Citations

**File:** secure/storage/src/on_disk.rs (L78-83)
```rust
    fn get<V: DeserializeOwned>(&self, key: &str) -> Result<GetResponse<V>, Error> {
        let mut data = self.read()?;
        data.remove(key)
            .ok_or_else(|| Error::KeyNotSet(key.to_string()))
            .and_then(|value| serde_json::from_value(value).map_err(|e| e.into()))
    }
```

**File:** secure/storage/src/error.rs (L16-17)
```rust
    #[error("Key not set: {0}")]
    KeyNotSet(String),
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L86-96)
```rust
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
```

**File:** consensus/safety-rules/src/error.rs (L92-95)
```rust
            aptos_secure_storage::Error::KeyVersionNotFound(_, _)
            | aptos_secure_storage::Error::KeyNotSet(_) => {
                Self::SecureStorageMissingDataError(error.to_string())
            },
```

**File:** consensus/src/epoch_manager.rs (L1228-1233)
```rust
        let loaded_consensus_key = match self.load_consensus_key(&epoch_state.verifier) {
            Ok(k) => Arc::new(k),
            Err(e) => {
                panic!("load_consensus_key failed: {e}");
            },
        };
```
