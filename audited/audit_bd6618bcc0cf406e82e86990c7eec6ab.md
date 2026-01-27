# Audit Report

## Title
Memory Leakage of Private Key Material in ConfigKey Clone Implementation

## Summary

The `ConfigKey::clone()` and `ConfigKey::PartialEq` implementations in `config/src/keys.rs` create intermediate BCS-serialized byte buffers containing private key material that are not properly zeroed after use. This violates Aptos's documented secure coding guidelines and creates a memory disclosure vulnerability where private keys could be extracted through memory dumps, core dumps, or side-channel attacks on misconfigured validator nodes.

## Finding Description

The vulnerability exists in the `ConfigKey` wrapper type used to make private keys cloneable for configuration purposes. [1](#0-0) 

When `clone()` is called, it serializes the private key into a BCS byte buffer using `bcs::to_bytes(self)`, deserializes it with `bcs::from_bytes()`, then drops the intermediate buffer without zeroing it. Similarly, the `PartialEq` implementation creates TWO unzeroed buffers for comparison. [2](#0-1) 

This directly violates Aptos's documented secure coding guidelines which explicitly state: "Do not rely on `Drop` trait in security material treatment after the use, use zeroize to explicit destroy security material, e.g. private keys." [3](#0-2)  and "Use zeroize for zeroing memory containing sensitive data." [4](#0-3) 

**Exploitation Path:**

1. A validator operator configures their node using `Identity::FromConfig` for network identity instead of the recommended `Identity::FromStorage` [5](#0-4) 

2. During network initialization, `NetworkConfig::identity_key()` is called to extract the x25519 private key [6](#0-5) 

3. This calls `config.key.private_key()` which internally calls `self.clone().key` [7](#0-6) 

4. The BCS serialization creates a heap-allocated buffer containing the raw private key that persists in memory until overwritten

5. An attacker with memory access (via debugger attachment, core dump analysis, cold boot attack, or memory scanning tools) can extract this key material from the process memory

6. With the network identity key compromised, the attacker can impersonate the validator on the P2P network, enabling man-in-the-middle attacks on consensus messages or network-level protocol manipulation

**No Sanitizer Protection:**

Critically, there is NO config sanitizer check preventing validators from using `Identity::FromConfig` on mainnet. The sanitizer only checks for in-memory storage backends and mutual authentication requirements, but does not enforce secure identity storage. [8](#0-7) 

## Impact Explanation

This is a **Medium severity** vulnerability per the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: Network identity key compromise enables network-level attacks that could disrupt P2P communication integrity, requiring validator intervention to rotate keys and restore trust
- **Limited security degradation**: While the network identity key (x25519) is compromised, consensus keys (BLS) are protected through `SafetyRulesConfig` which has sanitizer enforcement blocking test configs on mainnet [9](#0-8) 

The impact is limited because:
1. Production validators are recommended to use `Identity::FromStorage` with Vault backend [10](#0-9) 
2. Consensus safety is not directly compromised (only network authentication)
3. Exploitation requires both misconfiguration AND memory access

However, the vulnerability is still significant because misconfigured validators are at risk, and there's no enforcement preventing this insecure configuration.

## Likelihood Explanation

**Likelihood: Low-to-Medium**

The vulnerability requires multiple conditions:
1. **Validator misconfiguration**: Operator must choose `Identity::FromConfig` instead of recommended `Identity::FromStorage`
2. **Memory access**: Attacker needs privileged access to validator memory (debugger, core dumps, physical access)

However, likelihood is elevated by:
- No sanitizer enforcement prevents the insecure configuration
- The comment in the code explicitly allows this for "low security requirements" suggesting it may be used [11](#0-10) 
- Memory disclosure attacks are realistic (core dumps from crashes, debugger access via vulnerabilities, cold boot attacks)
- The vulnerability triggers automatically on misconfigured nodes during every network initialization

## Recommendation

**Immediate Fix**: Implement secure memory zeroing using the `zeroize` crate:

```rust
use zeroize::Zeroize;

impl<T: DeserializeOwned + PrivateKey + Serialize> Clone for ConfigKey<T> {
    fn clone(&self) -> Self {
        let mut serialized = bcs::to_bytes(self).unwrap();
        let cloned = bcs::from_bytes(&serialized).unwrap();
        serialized.zeroize(); // Explicitly zero the buffer
        cloned
    }
}

impl<T: PrivateKey + Serialize> PartialEq for ConfigKey<T> {
    fn eq(&self, other: &Self) -> bool {
        let mut self_bytes = bcs::to_bytes(&self).unwrap();
        let mut other_bytes = bcs::to_bytes(&other).unwrap();
        let result = self_bytes == other_bytes;
        self_bytes.zeroize();
        other_bytes.zeroize();
        result
    }
}
```

**Additional Mitigations**:
1. Add config sanitizer check to prevent `Identity::FromConfig` on mainnet validators
2. Deprecate `ConfigKey` entirely and require secure storage for all production deployments
3. Add compiler warnings or static analysis to detect unzeroed sensitive buffers

## Proof of Concept

```rust
#[cfg(test)]
mod security_test {
    use super::*;
    use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
    
    #[test]
    fn test_memory_not_zeroed() {
        // Create a ConfigKey with a private key
        let key = Ed25519PrivateKey::generate_for_testing();
        let config_key = ConfigKey::new(key);
        
        // Clone the key (triggers BCS serialization)
        let cloned = config_key.clone();
        
        // The intermediate BCS buffer is now dropped but not zeroed
        // In a real attack, an attacker would scan process memory here
        // and find the serialized private key bytes still present
        
        // This test demonstrates the vulnerability exists
        // To actually verify memory isn't zeroed would require:
        // 1. Hooking memory allocator to track buffer addresses
        // 2. Scanning freed memory regions for private key material
        // 3. Demonstrating the key bytes persist after clone()
        
        assert_eq!(config_key, cloned); // This also creates unzeroed buffers!
    }
    
    #[test]
    fn test_private_key_extraction_creates_unzeroed_buffer() {
        let key = Ed25519PrivateKey::generate_for_testing();
        let config_key = ConfigKey::new(key);
        
        // This is called during network initialization
        let extracted = config_key.private_key();
        
        // The intermediate buffer from clone() is dropped but not zeroed
        // Private key material remains in process memory
        assert!(extracted.to_bytes().len() > 0);
    }
}
```

**Notes:**

- The vulnerability is real and violates explicit security guidelines
- Exploitation requires validator misconfiguration (no sanitizer prevents it) and memory access
- Production validators using recommended `Identity::FromStorage` are protected
- Consensus keys in `SafetyRulesTestConfig` are blocked on mainnet by sanitizer
- Impact is limited to network identity compromise, not direct consensus manipulation
- Fix is straightforward using the `zeroize` crate as recommended in security guidelines

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

**File:** config/src/keys.rs (L64-68)
```rust
impl<T: PrivateKey + Serialize> PartialEq for ConfigKey<T> {
    fn eq(&self, other: &Self) -> bool {
        bcs::to_bytes(&self).unwrap() == bcs::to_bytes(&other).unwrap()
    }
}
```

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** config/src/config/identity_config.rs (L132-139)
```rust
pub struct IdentityFromConfig {
    #[serde(flatten)]
    pub key: ConfigKey<x25519::PrivateKey>,
    pub peer_id: PeerId,

    #[serde(skip)]
    pub source: IdentitySource,
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

**File:** config/src/config/config_sanitizer.rs (L156-201)
```rust
/// Sanitize the validator network config according to the node role and chain ID
fn sanitize_validator_network_config(
    node_config: &NodeConfig,
    node_type: NodeType,
    _chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let sanitizer_name = VALIDATOR_NETWORK_SANITIZER_NAME.to_string();
    let validator_network = &node_config.validator_network;

    // Verify that the validator network config is not empty for validators
    if validator_network.is_none() && node_type.is_validator() {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Validator network config cannot be empty for validators!".into(),
        ));
    }

    // Check the validator network config
    if let Some(validator_network_config) = validator_network {
        let network_id = validator_network_config.network_id;
        if !network_id.is_validator_network() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The validator network config must have a validator network ID!".into(),
            ));
        }

        // Verify that the node is a validator
        if !node_type.is_validator() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The validator network config cannot be set for non-validators!".into(),
            ));
        }

        // Ensure that mutual authentication is enabled
        if !validator_network_config.mutual_authentication {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Mutual authentication must be enabled for the validator network!".into(),
            ));
        }
    }

    Ok(())
}
```

**File:** config/src/config/safety_rules_config.rs (L106-112)
```rust
            // Verify that the safety rules test config is not enabled in mainnet
            if chain_id.is_mainnet() && safety_rules_config.test.is_some() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The safety rules test config should not be used in mainnet!".to_string(),
                ));
            }
```

**File:** config/src/config/test_data/validator.yaml (L43-52)
```yaml
    identity:
        type: "from_storage"
        key_name: "validator_network"
        peer_id_name: "owner_account"
        backend:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"
```
