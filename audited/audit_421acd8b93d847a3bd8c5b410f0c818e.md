# Audit Report

## Title
MultiEd25519 Deserialization Allows Duplicate Public Keys, Weakening Multisig Security Guarantees

## Summary
The `TryFrom<&[u8]>` implementation for `MultiEd25519PublicKey` does not validate that public keys are unique, allowing an attacker to create a k-of-n multisig containing duplicate keys. This effectively reduces the required number of distinct signers, converting (for example) a 3-of-4 multisig into a 1-of-2 security model. [1](#0-0) 

## Finding Description

The deserialization flow for `MultiEd25519PublicKey` performs the following validation:

1. **Threshold validation** via `check_and_get_threshold`: Checks that `threshold ∈ [1, num_keys]` and `num_keys ∈ [1, MAX_NUM_OF_KEYS]` [2](#0-1) 

2. **Individual key validation**: Each `Ed25519PublicKey` is deserialized via `try_from`, which only checks for valid curve points but not uniqueness [3](#0-2) 

3. **No duplicate check**: The implementation directly constructs the struct without verifying key uniqueness

**Attack Scenario:**
1. Attacker creates a `MultiEd25519PublicKey` with bytes encoding `[A, A, A, B]` (key A repeated 3 times) with `threshold=3`
2. Deserialization succeeds because each individual key is valid and threshold checks pass
3. During signature verification, the attacker provides `signatures=[sig_A, sig_A, sig_A]` with `bitmap=0b11100000` [4](#0-3) 

4. Verification succeeds: each `sig_A` is verified against its corresponding position in the public key array (all containing key A)
5. The attacker controls the account with only 1 private key instead of the expected 3 distinct keys

**Propagation Through the System:**
- **Account Creation/Rotation**: Users can create accounts with weak multisig via `rotate_authentication_key` [5](#0-4) 

- **Transaction Validation**: The native function `signature_verify_strict_internal` uses the flawed deserialization [6](#0-5) 

## Impact Explanation

**Severity: Medium**

This vulnerability meets the Medium severity criteria of "Limited funds loss or manipulation" because:

1. **Trust Model Violation**: Systems or users expecting k-of-n multisig semantics (k distinct signers) are misled
2. **Custody Weakness**: Multi-party custody solutions could be compromised if one party inserts duplicate keys during setup
3. **Self-Inflicted Primary Impact**: The main harm is to the account owner themselves, limiting severity

This does NOT reach High/Critical because:
- No consensus or validator operations are affected (validators use BLS12-381, not MultiEd25519) [7](#0-6) 
- No direct theft from other users' accounts
- The network remains operational

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is easily triggered:
- No special privileges required
- Can be exploited during normal account creation or key rotation flows
- The Move framework provides direct access via `new_unvalidated_public_key_from_bytes` [8](#0-7) 

However, exploitation requires the attacker to intentionally weaken their own account, making accidental occurrence unlikely.

## Recommendation

Add duplicate key validation to the `TryFrom<&[u8]>` implementation:

```rust
fn try_from(bytes: &[u8]) -> std::result::Result<MultiEd25519PublicKey, CryptoMaterialError> {
    if bytes.is_empty() {
        return Err(CryptoMaterialError::WrongLengthError);
    }
    let (threshold, _) = check_and_get_threshold(bytes, ED25519_PUBLIC_KEY_LENGTH)?;
    let public_keys: Result<Vec<Ed25519PublicKey>, _> = bytes
        .chunks_exact(ED25519_PUBLIC_KEY_LENGTH)
        .map(Ed25519PublicKey::try_from)
        .collect();
    
    let public_keys = public_keys?;
    
    // NEW: Check for duplicate keys
    let mut seen = std::collections::HashSet::new();
    for pk in &public_keys {
        if !seen.insert(pk.to_bytes()) {
            return Err(CryptoMaterialError::ValidationError);
        }
    }
    
    Ok(MultiEd25519PublicKey {
        public_keys,
        threshold,
    })
}
```

Also add the same check to the `new()` constructor for consistency: [9](#0-8) 

## Proof of Concept

```rust
#[test]
fn test_duplicate_keys_bypass() {
    use aptos_crypto::ed25519::Ed25519PrivateKey;
    use aptos_crypto::multi_ed25519::MultiEd25519PublicKey;
    use aptos_crypto::traits::{PrivateKey, Uniform};
    
    // Generate a single key pair
    let mut rng = rand::thread_rng();
    let priv_key = Ed25519PrivateKey::generate(&mut rng);
    let pub_key = priv_key.public_key();
    
    // Create bytes with duplicate public keys [A, A, A] threshold=2
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pub_key.to_bytes());
    bytes.extend_from_slice(&pub_key.to_bytes());
    bytes.extend_from_slice(&pub_key.to_bytes());
    bytes.push(2u8); // threshold
    
    // This should fail but currently succeeds
    let multi_pk = MultiEd25519PublicKey::try_from(bytes.as_slice());
    assert!(multi_pk.is_ok(), "Duplicate keys were accepted!");
    
    let multi_pk = multi_pk.unwrap();
    assert_eq!(multi_pk.public_keys().len(), 3);
    assert_eq!(*multi_pk.threshold(), 2);
    
    // The multisig appears to require 2-of-3, but actually only needs 1 key
    println!("Successfully created weak multisig with duplicate keys");
}
```

### Citations

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L88-103)
```rust
    pub fn new(
        public_keys: Vec<Ed25519PublicKey>,
        threshold: u8,
    ) -> std::result::Result<Self, CryptoMaterialError> {
        let num_of_public_keys = public_keys.len();
        if threshold == 0 || num_of_public_keys < threshold as usize {
            Err(CryptoMaterialError::ValidationError)
        } else if num_of_public_keys > MAX_NUM_OF_KEYS {
            Err(CryptoMaterialError::WrongLengthError)
        } else {
            Ok(MultiEd25519PublicKey {
                public_keys,
                threshold,
            })
        }
    }
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L296-316)
```rust
impl TryFrom<&[u8]> for MultiEd25519PublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize a MultiEd25519PublicKey. This method will also check for threshold validity.
    /// This method will NOT ensure keys are safe against small subgroup attacks, since our signature
    /// verification API will automatically prevent it.
    fn try_from(bytes: &[u8]) -> std::result::Result<MultiEd25519PublicKey, CryptoMaterialError> {
        if bytes.is_empty() {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        let (threshold, _) = check_and_get_threshold(bytes, ED25519_PUBLIC_KEY_LENGTH)?;
        let public_keys: Result<Vec<Ed25519PublicKey>, _> = bytes
            .chunks_exact(ED25519_PUBLIC_KEY_LENGTH)
            .map(Ed25519PublicKey::try_from)
            .collect();
        public_keys.map(|public_keys| MultiEd25519PublicKey {
            public_keys,
            threshold,
        })
    }
}
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L544-556)
```rust
        let mut bitmap_index = 0;
        // TODO: Eventually switch to deterministic batch verification
        for sig in &self.signatures {
            while !bitmap_get_bit(self.bitmap, bitmap_index) {
                bitmap_index += 1;
            }
            let pk = public_key
                .public_keys
                .get(bitmap_index)
                .ok_or_else(|| anyhow::anyhow!("Public key index {bitmap_index} out of bounds"))?;
            sig.verify_arbitrary_msg(message, pk)?;
            bitmap_index += 1;
        }
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L591-610)
```rust
pub fn check_and_get_threshold(
    bytes: &[u8],
    key_size: usize,
) -> std::result::Result<(u8, u8), CryptoMaterialError> {
    let payload_length = bytes.len();
    if bytes.is_empty() {
        return Err(CryptoMaterialError::WrongLengthError);
    }
    let threshold_num_of_bytes = payload_length % key_size;
    let num_of_keys = payload_length / key_size;
    let threshold_byte = bytes[bytes.len() - 1];

    if num_of_keys == 0 || num_of_keys > MAX_NUM_OF_KEYS || threshold_num_of_bytes != 1 {
        Err(CryptoMaterialError::WrongLengthError)
    } else if threshold_byte == 0 || threshold_byte > num_of_keys as u8 {
        Err(CryptoMaterialError::ValidationError)
    } else {
        Ok((threshold_byte, num_of_keys as u8))
    }
}
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L295-304)
```rust
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Ed25519PublicKey. This method will NOT check for key validity, which means
    /// the returned public key could be in a small subgroup. Nonetheless, our signature
    /// verification implicitly checks if the public key lies in a small subgroup, so canonical
    /// uses of this library will not be susceptible to small subgroup attacks.
    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        Ed25519PublicKey::from_bytes_unchecked(bytes)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L476-478)
```text
        } else if (scheme == MULTI_ED25519_SCHEME) {
            let from_pk = multi_ed25519::new_unvalidated_public_key_from_bytes(new_public_key_bytes);
            new_auth_key = multi_ed25519::unvalidated_public_key_to_authentication_key(&from_pk);
```

**File:** aptos-move/framework/src/natives/cryptography/multi_ed25519.rs (L134-139)
```rust
    let pk = match multi_ed25519::MultiEd25519PublicKey::try_from(pubkey.as_slice()) {
        Ok(pk) => pk,
        Err(_) => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1-50)
```text
///
/// Validator lifecycle:
/// 1. Prepare a validator node set up and call stake::initialize_validator
/// 2. Once ready to deposit stake (or have funds assigned by a staking service in exchange for ownership capability),
/// call stake::add_stake (or *_with_cap versions if called from the staking service)
/// 3. Call stake::join_validator_set (or _with_cap version) to join the active validator set. Changes are effective in
/// the next epoch.
/// 4. Validate and gain rewards. The stake will automatically be locked up for a fixed duration (set by governance) and
/// automatically renewed at expiration.
/// 5. At any point, if the validator operator wants to update the consensus key or network/fullnode addresses, they can
/// call stake::rotate_consensus_key and stake::update_network_and_fullnode_addresses. Similar to changes to stake, the
/// changes to consensus key/network/fullnode addresses are only effective in the next epoch.
/// 6. Validator can request to unlock their stake at any time. However, their stake will only become withdrawable when
/// their current lockup expires. This can be at most as long as the fixed lockup duration.
/// 7. After exiting, the validator can either explicitly leave the validator set by calling stake::leave_validator_set
/// or if their stake drops below the min required, they would get removed at the end of the epoch.
/// 8. Validator can always rejoin the validator set by going through steps 2-3 again.
/// 9. An owner can always switch operators by calling stake::set_operator.
/// 10. An owner can always switch designated voter by calling stake::set_designated_voter.
module aptos_framework::stake {
    use std::error;
    use std::features;
    use std::option::{Self, Option};
    use std::signer;
    use std::vector;
    use aptos_std::bls12381;
    use aptos_std::math64::min;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_std::table::Table;
    use aptos_framework::aggregator_v2::{Self, Aggregator};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::account;
    use aptos_framework::coin::{Self, Coin, MintCapability};
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::timestamp;
    use aptos_framework::system_addresses;
    use aptos_framework::staking_config::{Self, StakingConfig, StakingRewardsConfig};
    use aptos_framework::chain_status;
    use aptos_framework::permissioned_signer;

    friend aptos_framework::block;
    friend aptos_framework::genesis;
    friend aptos_framework::reconfiguration;
    friend aptos_framework::reconfiguration_with_dkg;
    friend aptos_framework::transaction_fee;

    /// Validator Config not published.
    const EVALIDATOR_CONFIG: u64 = 1;
    /// Not enough stake to join validator set.
    const ESTAKE_TOO_LOW: u64 = 2;
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_ed25519.move (L128-135)
```text
    public fun new_unvalidated_public_key_from_bytes(bytes: vector<u8>): UnvalidatedPublicKey {
        let len = bytes.length();
        let num_sub_pks = len / INDIVIDUAL_PUBLIC_KEY_NUM_BYTES;

        assert!(num_sub_pks <= MAX_NUMBER_OF_PUBLIC_KEYS, error::invalid_argument(E_WRONG_PUBKEY_SIZE));
        assert!(len % INDIVIDUAL_PUBLIC_KEY_NUM_BYTES == THRESHOLD_SIZE_BYTES, error::invalid_argument(E_WRONG_PUBKEY_SIZE));
        UnvalidatedPublicKey { bytes }
    }
```
