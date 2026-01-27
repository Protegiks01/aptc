# Audit Report

## Title
Indefinite Validity of Consensus Private Keys Due to Missing Key Expiration Mechanism

## Summary
The Aptos secure storage system lacks any key expiration or time-based invalidation mechanism for cryptographic keys, including validator consensus private keys. Once stored, keys remain valid indefinitely with no automated expiration, allowing compromised keys to be used until manual rotation occurs, which only takes effect at epoch boundaries.

## Finding Description

The `CryptoStorage` trait and its implementations (`CryptoKVStorage`, `VaultStorage`, `OnDiskStorage`) provide no mechanism for automatic key expiration or time-based validity checks. [1](#0-0) 

Keys are stored with a `last_update` timestamp, but this is only for tracking purposes, not enforcement. [2](#0-1) 

When validator consensus keys are loaded for signing consensus messages, no expiration validation occurs: [3](#0-2) 

The system retrieves keys from `PersistentSafetyStorage` without any time-based checks: [4](#0-3) 

Even when keys are rotated via the staking module, the rotation only takes effect at the next epoch boundary (delayed response), and previous key versions remain accessible: [5](#0-4) 

The `rotate_key` implementation stores the old key with a `_previous` suffix, keeping it indefinitely accessible: [6](#0-5) 

## Impact Explanation

This constitutes a **Medium Severity** issue as it violates defense-in-depth security principles and extends the window of exposure for compromised cryptographic material. While it doesn't directly enable an attack without key compromise, it removes a critical security layer that should limit the damage from such incidents. The impact includes:

- Compromised consensus keys remain valid indefinitely until manual intervention
- Delayed invalidation due to epoch boundary constraints
- Previous key versions persist in storage after rotation
- No automated protection against long-term key exposure

This falls under "State inconsistencies requiring intervention" in the Medium Severity category, as responding to compromised keys requires manual operator intervention with inherent delays.

## Likelihood Explanation

The likelihood is **Medium** because:

1. Key compromise scenarios occur through multiple realistic vectors: backup exposure, storage system breaches, memory dumps, insider threats, or configuration errors
2. The cryptocurrency ecosystem has documented cases of validator key compromises
3. Without expiration, the exposure window extends from the moment of compromise until detection AND the next epoch boundary
4. The system provides no automated defense against this class of incidents

## Recommendation

Implement a key expiration system with the following components:

1. **Add expiration metadata** to stored keys in `GetResponse`:
```rust
pub struct GetResponse<T> {
    pub last_update: u64,
    pub value: T,
    pub expires_at: Option<u64>, // Unix timestamp
}
```

2. **Enforce expiration checks** in key retrieval methods in `CryptoKVStorage`:
```rust
fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
    let response = self.get(name)?;
    if let Some(expires_at) = response.expires_at {
        let now = current_timestamp();
        if now >= expires_at {
            return Err(Error::KeyExpired(name.into()));
        }
    }
    Ok(response.value)
}
```

3. **Add key lifecycle management** with configurable TTL policies for consensus keys

4. **Implement automated rotation alerts** before expiration deadlines

5. **Add emergency revocation mechanism** that invalidates keys immediately without waiting for epoch boundaries (for disaster recovery scenarios)

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_crypto::ed25519::Ed25519PrivateKey;
    use aptos_secure_storage::InMemoryStorage;
    
    #[test]
    fn test_compromised_key_remains_valid_indefinitely() {
        // Create storage and import a "compromised" key
        let mut storage = Storage::from(InMemoryStorage::new());
        let compromised_key = Ed25519PrivateKey::generate_for_testing();
        
        storage.import_private_key("consensus_key", compromised_key.clone()).unwrap();
        
        // Simulate time passing (e.g., 1 year = 31536000 seconds)
        // In a real implementation with expiration, this should fail
        std::thread::sleep(std::time::Duration::from_secs(1));
        
        // Key is still retrievable after any amount of time
        let retrieved_key = storage.export_private_key("consensus_key").unwrap();
        assert_eq!(compromised_key.to_bytes(), retrieved_key.to_bytes());
        
        // Even after rotation, old key remains accessible
        let _new_pubkey = storage.rotate_key("consensus_key").unwrap();
        let old_key = storage.export_private_key("consensus_key_previous").unwrap();
        assert_eq!(compromised_key.to_bytes(), old_key.to_bytes());
        
        // Demonstrates: No expiration enforcement exists
        // In a secure system, at least one of these retrievals should fail
    }
}
```

**Notes**

This vulnerability represents a violation of cryptographic key management best practices (NIST SP 800-57, ISO 27001) rather than a direct protocol-level exploit. The absence of key expiration mechanisms increases the blast radius of key compromise incidents by removing temporal limits on key validity. While the AptosBFT consensus protocol's Byzantine fault tolerance (< 1/3 assumption) provides some protection, defense-in-depth principles dictate that cryptographic keys should have limited cryptoperiods to contain the impact of security breaches.

The current design requires operators to manually detect compromises and initiate rotation, which only takes effect at epoch boundaries. Modern key management systems should provide automated expiration, proactive rotation, and emergency revocation capabilities to minimize exposure windows.

### Citations

**File:** secure/storage/src/crypto_kv_storage.rs (L13-110)
```rust
/// CryptoKVStorage offers a CryptoStorage implementation by extending a key value store (KVStorage)
/// to create and manage cryptographic keys. This is useful for providing a simple CryptoStorage
/// implementation based upon an existing KVStorage engine (e.g. for test purposes).
pub trait CryptoKVStorage: KVStorage {}

impl<T: CryptoKVStorage> CryptoStorage for T {
    fn create_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        // Generate and store the new named key pair
        let (private_key, public_key) = new_ed25519_key_pair();
        self.import_private_key(name, private_key)?;
        Ok(public_key)
    }

    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
        self.get(name).map(|v| v.value)
    }

    fn export_private_key_for_version(
        &self,
        name: &str,
        version: Ed25519PublicKey,
    ) -> Result<Ed25519PrivateKey, Error> {
        let current_private_key = self.export_private_key(name)?;
        if current_private_key.public_key().eq(&version) {
            return Ok(current_private_key);
        }

        match self.export_private_key(&get_previous_version_name(name)) {
            Ok(previous_private_key) => {
                if previous_private_key.public_key().eq(&version) {
                    Ok(previous_private_key)
                } else {
                    Err(Error::KeyVersionNotFound(name.into(), version.to_string()))
                }
            },
            Err(Error::KeyNotSet(_)) => {
                Err(Error::KeyVersionNotFound(name.into(), version.to_string()))
            },
            Err(e) => Err(e),
        }
    }

    fn import_private_key(&mut self, name: &str, key: Ed25519PrivateKey) -> Result<(), Error> {
        self.set(name, key)
    }

    fn get_public_key(&self, name: &str) -> Result<PublicKeyResponse, Error> {
        let response = self.get(name)?;
        let key: Ed25519PrivateKey = response.value;

        Ok(PublicKeyResponse {
            last_update: response.last_update,
            public_key: key.public_key(),
        })
    }

    fn get_public_key_previous_version(&self, name: &str) -> Result<Ed25519PublicKey, Error> {
        match self.export_private_key(&get_previous_version_name(name)) {
            Ok(previous_private_key) => Ok(previous_private_key.public_key()),
            Err(Error::KeyNotSet(_)) => Err(Error::KeyVersionNotFound(
                name.into(),
                "previous version".into(),
            )),
            Err(e) => Err(e),
        }
    }

    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        let private_key: Ed25519PrivateKey = self.get(name)?.value;
        let (new_private_key, new_public_key) = new_ed25519_key_pair();
        self.set(&get_previous_version_name(name), private_key)?;
        self.set(name, new_private_key)?;
        Ok(new_public_key)
    }

    fn sign<U: CryptoHash + Serialize>(
        &self,
        name: &str,
        message: &U,
    ) -> Result<Ed25519Signature, Error> {
        let private_key = self.export_private_key(name)?;
        private_key
            .sign(message)
            .map_err(|err| Error::SerializationError(err.to_string()))
    }

    fn sign_using_version<U: CryptoHash + Serialize>(
        &self,
        name: &str,
        version: Ed25519PublicKey,
        message: &U,
    ) -> Result<Ed25519Signature, Error> {
        let private_key = self.export_private_key_for_version(name, version)?;
        private_key
            .sign(message)
            .map_err(|err| Error::SerializationError(err.to_string()))
    }
}
```

**File:** secure/storage/src/kv_storage.rs (L54-63)
```rust
/// A container for a get response that contains relevant metadata and the value stored at the
/// given key.
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "data")]
pub struct GetResponse<T> {
    /// Time since Unix Epoch in seconds.
    pub last_update: u64,
    /// Value stored at the provided key
    pub value: T,
}
```

**File:** consensus/src/epoch_manager.rs (L1971-1980)
```rust
    fn load_consensus_key(&self, vv: &ValidatorVerifier) -> anyhow::Result<PrivateKey> {
        match vv.get_public_key(&self.author) {
            Some(pk) => self
                .key_storage
                .consensus_sk_by_pk(pk)
                .map_err(|e| anyhow!("could not find sk by pk: {:?}", e)),
            None => {
                warn!("could not find my pk in validator set, loading default sk!");
                self.key_storage
                    .default_consensus_sk()
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L98-132)
```rust
    pub fn default_consensus_sk(
        &self,
    ) -> Result<bls12381::PrivateKey, aptos_secure_storage::Error> {
        self.internal_store
            .get::<bls12381::PrivateKey>(CONSENSUS_KEY)
            .map(|v| v.value)
    }

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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L909-952)
```text
    /// Rotate the consensus key of the validator, it'll take effect in next epoch.
    public entry fun rotate_consensus_key(
        operator: &signer,
        pool_address: address,
        new_consensus_pubkey: vector<u8>,
        proof_of_possession: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);

        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));

        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_consensus_pubkey = validator_info.consensus_pubkey;
        // Checks the public key has a valid proof-of-possession to prevent rogue-key attacks.
        let pubkey_from_pop = &bls12381::public_key_from_bytes_with_pop(
            new_consensus_pubkey,
            &proof_of_possession_from_bytes(proof_of_possession)
        );
        assert!(option::is_some(pubkey_from_pop), error::invalid_argument(EINVALID_PUBLIC_KEY));
        validator_info.consensus_pubkey = new_consensus_pubkey;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                RotateConsensusKey {
                    pool_address,
                    old_consensus_pubkey,
                    new_consensus_pubkey,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.rotate_consensus_key_events,
                RotateConsensusKeyEvent {
                    pool_address,
                    old_consensus_pubkey,
                    new_consensus_pubkey,
                },
            );
        };
    }
```
