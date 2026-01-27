# Audit Report

## Title
Peer Identity Forgery via Public Key Set Manipulation in Seed Configuration

## Summary
The `ExtractPeer::execute()` function generates YAML seed configurations with a cryptographically-derived `peer_id` and a single public key. However, the system lacks validation to ensure all public keys in the `keys` HashSet derive to the same `peer_id`. An attacker who can modify the YAML configuration before it's loaded can inject additional public keys, allowing them to authenticate as a peer identity they don't control, breaking mutual authentication in validator networks. [1](#0-0) 

## Finding Description
The vulnerability exists in the relationship between three components:

1. **Peer ID Derivation**: The `from_identity_public_key()` function derives a `peer_id` by taking only the last 16 bytes of an x25519 public key, creating a lossy one-way mapping. [2](#0-1) 

2. **Missing Validation**: The `verify_seeds()` function only validates that seeds have non-empty keys, but never verifies that all keys in the `keys` HashSet derive to the same `peer_id` as the HashMap key. [3](#0-2) 

3. **Authentication Without Key Binding**: During mutual authentication, `authenticate_inbound()` only checks if the remote public key exists in `peer.keys`, without verifying that `from_identity_public_key(remote_public_key)` matches the claimed `peer_id`. [4](#0-3) 

**Attack Path:**
1. Validator A generates seed configuration: `{peer_id_A: {keys: [public_key_A], ...}}`
2. Validator A shares YAML with Validator B over insecure channel (email, chat, etc.)
3. Attacker intercepts and modifies YAML: `{peer_id_A: {keys: [public_key_A, attacker_public_key], ...}}`
4. Validator B loads modified configuration via file discovery or manual configuration
5. Attacker connects to B claiming `peer_id_A` with `attacker_public_key`
6. Authentication succeeds because `attacker_public_key ∈ peer.keys`, even though `from_identity_public_key(attacker_public_key) ≠ peer_id_A`
7. Attacker is now authenticated as Validator A on Validator B's node [5](#0-4) 

## Impact Explanation
**Critical Severity** - This vulnerability meets multiple Critical criteria:

1. **Consensus Safety Violations**: An attacker authenticated as a legitimate validator can participate in consensus protocol, potentially:
   - Send malicious votes or proposals
   - Equivocate without being detected as the true malicious party
   - Increase effective Byzantine validator count beyond 1/3 threshold
   - Cause safety violations or chain splits

2. **Network Partition**: In validator networks with mutual authentication, this allows unauthorized peers to infiltrate the trusted network, potentially causing:
   - Message flooding or DoS attacks from "trusted" peers
   - Consensus liveness failures if multiple validators are impersonated
   - State divergence if different validators trust different key sets

3. **Validator Identity Theft**: Legitimate validators could be blamed for malicious actions performed by attackers using their `peer_id`, causing reputation damage and potential slashing.

The vulnerability breaks the fundamental **Cryptographic Correctness** invariant that peer identities must be cryptographically bound to their keys, and the **Consensus Safety** invariant that mutual authentication must prevent unauthorized participation.

## Likelihood Explanation
**High Likelihood** due to:

1. **Common Attack Vector**: Seed configurations are frequently shared between validators via insecure channels (email, Slack, Discord), making MITM attacks practical.

2. **No Technical Barriers**: Attack requires only:
   - YAML editing capability (trivial)
   - Access to modify config before it's loaded (MITM or local system compromise)
   - Standard cryptographic key generation (no special capabilities needed)

3. **Silent Failure**: Modified configurations pass all validation checks, giving no warning to operators that configuration has been tampered with.

4. **Operational Reality**: During network setup or validator onboarding, configuration files are routinely transmitted over insecure channels, creating numerous exploitation opportunities.

## Recommendation
Implement strict validation in `verify_seeds()` to ensure all keys in each peer's `keys` HashSet derive to the correct `peer_id`:

```rust
pub fn verify_seeds(&self) -> Result<(), Error> {
    for (peer_id, addrs) in self.seed_addrs.iter() {
        for addr in addrs {
            Self::verify_address(peer_id, addr)?;
        }
    }

    for (peer_id, seed) in self.seeds.iter() {
        for addr in seed.addresses.iter() {
            Self::verify_address(peer_id, addr)?;
        }

        // Require there to be a pubkey somewhere
        if seed.keys.is_empty() && seed.addresses.is_empty() {
            return Err(Error::InvariantViolation(format!(
                "Seed peer {} has no pubkeys",
                peer_id.short_str(),
            )));
        }

        // NEW: Validate that all keys derive to the same peer_id
        for public_key in seed.keys.iter() {
            let derived_peer_id = aptos_types::account_address::from_identity_public_key(*public_key);
            if derived_peer_id != *peer_id {
                return Err(Error::InvariantViolation(format!(
                    "Seed peer {} has public key {} that derives to different peer_id {}",
                    peer_id.short_str(),
                    hex::encode(public_key.as_slice()),
                    derived_peer_id.short_str(),
                )));
            }
        }
    }
    Ok(())
}
```

Additionally, add defense-in-depth validation in `authenticate_inbound()`:

```rust
fn authenticate_inbound(
    remote_peer_short: ShortHexStr,
    peer: &Peer,
    remote_public_key: &x25519::PublicKey,
    expected_peer_id: PeerId,
) -> Result<PeerRole, NoiseHandshakeError> {
    if !peer.keys.contains(remote_public_key) {
        return Err(NoiseHandshakeError::UnauthenticatedClientPubkey(
            remote_peer_short,
            hex::encode(remote_public_key.as_slice()),
        ));
    }
    
    // NEW: Verify peer_id matches the public key
    let derived_peer_id = aptos_types::account_address::from_identity_public_key(*remote_public_key);
    if derived_peer_id != expected_peer_id {
        return Err(NoiseHandshakeError::PeerIdKeyMismatch(
            remote_peer_short,
            expected_peer_id,
            derived_peer_id,
        ));
    }
    
    Ok(peer.role)
}
```

## Proof of Concept

```rust
#[test]
fn test_peer_id_key_mismatch_rejected() {
    use aptos_crypto::x25519::PrivateKey;
    use aptos_types::account_address::from_identity_public_key;
    use aptos_config::config::{Peer, PeerRole, NetworkConfig};
    use std::collections::{HashMap, HashSet};
    
    // Generate two different key pairs
    let mut rng = rand::rngs::OsRng;
    let key_a = PrivateKey::generate(&mut rng);
    let pubkey_a = key_a.public_key();
    let peer_id_a = from_identity_public_key(pubkey_a);
    
    let key_b = PrivateKey::generate(&mut rng);
    let pubkey_b = key_b.public_key();
    let peer_id_b = from_identity_public_key(pubkey_b);
    
    // Attacker creates malicious seed config with pubkey_b under peer_id_a
    let mut malicious_keys = HashSet::new();
    malicious_keys.insert(pubkey_a);
    malicious_keys.insert(pubkey_b); // Attacker's key added!
    
    let mut seeds = HashMap::new();
    seeds.insert(
        peer_id_a,
        Peer::new(vec![], malicious_keys, PeerRole::Validator)
    );
    
    let mut config = NetworkConfig::default();
    config.seeds = seeds;
    
    // This should FAIL but currently SUCCEEDS
    let result = config.verify_seeds();
    assert!(result.is_err(), "Should reject seed with mismatched peer_id and keys");
}
```

**Notes:**
- This vulnerability requires the attacker to modify configuration files before they're loaded, but this is a realistic attack vector during validator onboarding or network setup.
- The fix adds cryptographic binding between `peer_id` and all associated public keys, preventing identity forgery.
- The vulnerability affects all networks using mutual authentication, particularly validator networks where peer identity is critical for consensus safety.

### Citations

**File:** crates/aptos/src/op/key.rs (L97-99)
```rust
        let peer_id = from_identity_public_key(public_key);
        let mut public_keys = HashSet::new();
        public_keys.insert(public_key);
```

**File:** types/src/account_address.rs (L140-146)
```rust
pub fn from_identity_public_key(identity_public_key: x25519::PublicKey) -> AccountAddress {
    let mut array = [0u8; AccountAddress::LENGTH];
    let pubkey_slice = identity_public_key.as_slice();
    // keep only the last 16 bytes
    array.copy_from_slice(&pubkey_slice[x25519::PUBLIC_KEY_SIZE - AccountAddress::LENGTH..]);
    AccountAddress::new(array)
}
```

**File:** config/src/config/network_config.rs (L319-340)
```rust
    pub fn verify_seeds(&self) -> Result<(), Error> {
        for (peer_id, addrs) in self.seed_addrs.iter() {
            for addr in addrs {
                Self::verify_address(peer_id, addr)?;
            }
        }

        for (peer_id, seed) in self.seeds.iter() {
            for addr in seed.addresses.iter() {
                Self::verify_address(peer_id, addr)?;
            }

            // Require there to be a pubkey somewhere, either in the address (assumed by `is_aptosnet_addr`)
            if seed.keys.is_empty() && seed.addresses.is_empty() {
                return Err(Error::InvariantViolation(format!(
                    "Seed peer {} has no pubkeys",
                    peer_id.short_str(),
                )));
            }
        }
        Ok(())
    }
```

**File:** network/framework/src/noise/handshake.rs (L488-500)
```rust
    fn authenticate_inbound(
        remote_peer_short: ShortHexStr,
        peer: &Peer,
        remote_public_key: &x25519::PublicKey,
    ) -> Result<PeerRole, NoiseHandshakeError> {
        if !peer.keys.contains(remote_public_key) {
            return Err(NoiseHandshakeError::UnauthenticatedClientPubkey(
                remote_peer_short,
                hex::encode(remote_public_key.as_slice()),
            ));
        }
        Ok(peer.role)
    }
```

**File:** network/discovery/src/file.rs (L50-53)
```rust
fn load_file(path: &Path) -> Result<PeerSet, DiscoveryError> {
    let contents = std::fs::read_to_string(path).map_err(DiscoveryError::IO)?;
    serde_yaml::from_str(&contents).map_err(|err| DiscoveryError::Parsing(err.to_string()))
}
```
