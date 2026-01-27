# Audit Report

## Title
Multiple Private Key Copies in Memory Due to ConfigKey Cloning During Network Transport Initialization

## Summary
The `ConfigKey<T>` wrapper implements cloning through BCS serialization/deserialization, creating multiple unzeroed copies of private keys in memory. When `NetworkConfig::identity_key()` is called during network transport initialization, the x25519 private key is cloned rather than moved, leaving cryptographic key material in multiple memory locations without guaranteed cleanup.

## Finding Description

The vulnerability exists in the key handling flow during network transport creation. The issue spans three key files: [1](#0-0) 

The `ConfigKey::private_key()` method explicitly clones the key by calling `self.clone().key`. [2](#0-1) 

The `Clone` implementation uses BCS serialization/deserialization, creating intermediate byte arrays of the private key that are not guaranteed to be zeroized. [3](#0-2) 

When `identity_key()` is called with `Identity::FromConfig`, it invokes `config.key.private_key()`, triggering the clone operation. [4](#0-3) 

During `NetworkBuilder::create()`, the identity key is extracted via `config.identity_key()`, creating a cloned copy that is then moved into `AuthenticationMode`.

This creates multiple copies of the private key in memory:
1. The original key in `NetworkConfig.identity.FromConfig.key`
2. Intermediate BCS-serialized byte arrays during cloning
3. The deserialized copy returned from `private_key()`
4. The final copy moved into `NoiseConfig` for cryptographic operations

While x25519_dalek::StaticSecret implements zeroization on drop, the intermediate serialized byte arrays created during BCS encoding are not guaranteed to be zeroized, and the original key persists in the config structure.

## Impact Explanation

**Medium Severity** - This constitutes a cryptographic key hygiene violation that increases attack surface:

- **Memory Disclosure Risk**: Process memory dumps, core dumps, or memory scanning attacks could reveal multiple copies of the validator's network private key
- **Attack Surface Expansion**: Each additional copy provides another opportunity for key extraction through side-channel attacks or memory access vulnerabilities
- **Violates Security Best Practices**: Cryptographic keys should exist in minimal copies with guaranteed zeroization

However, this does NOT reach High or Critical severity because:
- Exploitation requires memory access (process dump, debugger, or side-channel), not remote exploitation
- No direct impact on consensus safety, funds, or network availability
- Does not enable privilege escalation or validator set manipulation [5](#0-4) 

The comment acknowledges this is for "testing or low security requirements" and recommends key managers for production.

## Likelihood Explanation

**Medium-Low Likelihood** in production environments:

The Aptos documentation recommends using `Identity::FromStorage` with secure key managers for production validators, which avoids this issue entirely by creating keys from storage without cloning. [6](#0-5) 

The `FromStorage` path exports the key from secure storage and converts it, creating a new instance without cloning an existing ConfigKey.

However, deployments using `Identity::FromConfig` (which may occur in non-production or simplified setups) are vulnerable. The likelihood increases if:
- Operators use file-based configs with embedded keys
- Memory dumps occur due to crashes or debugging
- The host system is compromised

## Recommendation

Implement a move-only semantic for network identity keys to prevent cloning:

1. **Refactor ConfigKey to support take-once semantics**:
```rust
pub struct ConfigKey<T: PrivateKey + Serialize> {
    key: Option<T>,
}

impl<T: PrivateKey + Serialize> ConfigKey<T> {
    pub fn take_private_key(&mut self) -> Result<T, Error> {
        self.key.take().ok_or(Error::KeyAlreadyConsumed)
    }
}
```

2. **Make NetworkConfig.identity mutable during build**:
Modify `identity_key()` to take `&mut self` and consume the key on first access.

3. **Add runtime assertion**:
Enforce that `identity_key()` can only be called once per config instance.

4. **Documentation**:
Explicitly document that `FromConfig` is only for testing and that production deployments MUST use `FromStorage` with external key management.

Alternatively, remove `Clone` from `ConfigKey` entirely and require explicit serialization for config persistence, forcing developers to handle key material explicitly.

## Proof of Concept

```rust
// Demonstrates the cloning behavior
use aptos_config::config::NetworkConfig;
use aptos_crypto::{x25519, Uniform};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let key = x25519::PrivateKey::generate(&mut rng);
    
    // Create config with embedded key (FromConfig)
    let mut config = NetworkConfig::default();
    config.identity = Identity::from_config(key, PeerId::random());
    
    // First call to identity_key() - creates clone #1
    let key1 = config.identity_key();
    println!("Got key copy 1: {:?}", key1.public_key());
    
    // Second call - creates clone #2 (original still in config!)
    let key2 = config.identity_key();
    println!("Got key copy 2: {:?}", key2.public_key());
    
    // At this point: 
    // - Original key still in config.identity
    // - key1 exists
    // - key2 exists
    // - Intermediate BCS serialization buffers were created
    
    println!("Config still has key: {:?}", config.peer_id());
    // Demonstrates multiple copies exist simultaneously
}
```

This PoC shows that `identity_key()` can be called multiple times, each creating a new cloned copy through BCS serialization, while the original remains accessible in the config.

## Notes

While this is a legitimate key hygiene issue, the codebase acknowledges this design choice explicitly for configuration flexibility in low-security contexts. Production deployments using `FromStorage` with external key managers are not affected. The real-world impact depends on deployment practices and whether operators follow the recommended security architecture of using key managers rather than config-embedded keys.

### Citations

**File:** config/src/keys.rs (L20-24)
```rust
/// ConfigKey places a clonable wrapper around PrivateKeys for config purposes only. The only time
/// configs have keys is either for testing or for low security requirements. We recommend that
/// keys be stored in key managers. If we make keys unclonable, then the configs must be mutable
/// and that becomes a requirement strictly as a result of supporting test environments, which is
/// undesirable. Hence this internal wrapper allows for keys to be clonable but only from configs.
```

**File:** config/src/keys.rs (L36-38)
```rust
    pub fn private_key(&self) -> T {
        self.clone().key
    }
```

**File:** config/src/keys.rs (L49-53)
```rust
impl<T: DeserializeOwned + PrivateKey + Serialize> Clone for ConfigKey<T> {
    fn clone(&self) -> Self {
        bcs::from_bytes(&bcs::to_bytes(self).unwrap()).unwrap()
    }
}
```

**File:** config/src/config/network_config.rs (L187-206)
```rust
    pub fn identity_key(&self) -> x25519::PrivateKey {
        let key = match &self.identity {
            Identity::FromConfig(config) => Some(config.key.private_key()),
            Identity::FromStorage(config) => {
                let storage: Storage = (&config.backend).into();
                let key = storage
                    .export_private_key(&config.key_name)
                    .expect("Unable to read key");
                let key = x25519::PrivateKey::from_ed25519_private_bytes(&key.to_bytes())
                    .expect("Unable to convert key");
                Some(key)
            },
            Identity::FromFile(config) => {
                let identity_blob: IdentityBlob = IdentityBlob::from_file(&config.path).unwrap();
                Some(identity_blob.network_private_key)
            },
            Identity::None => None,
        };
        key.expect("identity key should be present")
    }
```

**File:** network/builder/src/builder.rs (L168-175)
```rust
        let peer_id = config.peer_id();
        let identity_key = config.identity_key();

        let authentication_mode = if config.mutual_authentication {
            AuthenticationMode::Mutual(identity_key)
        } else {
            AuthenticationMode::MaybeMutual(identity_key)
        };
```
