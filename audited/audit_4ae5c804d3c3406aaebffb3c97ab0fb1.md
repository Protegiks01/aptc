# Audit Report

## Title
Lack of Forward Secrecy in DKG Due to Deterministic Key Derivation from Long-Term Consensus Keys

## Summary
The Aptos DKG system does not provide cryptographic forward secrecy. Validators derive their DKG decryption keys deterministically from their long-term BLS consensus private keys, and without mandatory key rotation, the same decryption keys are reused across multiple DKG sessions spanning different epochs. If a validator's consensus private key is compromised at any point, an attacker can decrypt that validator's shares from all historical DKG transcripts where the same key was used, potentially enabling reconstruction of past randomness secrets.

## Finding Description

The DKG trait design and implementation violate forward secrecy through the following chain:

**1. Deterministic Key Derivation** [1](#0-0) 

The `NewValidatorDecryptKey` is derived directly from the validator's BLS consensus private key through a simple byte-order reversal. This derivation is deterministic and reversible.

**2. Decryption Key Reuse Without Rotation Enforcement** [2](#0-1) 

The `DKGTrait` defines `NewValidatorDecryptKey` as a type but imposes no requirements for ephemeral generation, time-based expiration, or per-session uniqueness. The trait allows implementations to reuse the same decryption key indefinitely.

**3. Optional Consensus Key Rotation** [3](#0-2) 

Consensus key rotation via `rotate_consensus_key()` is entirely optional. Validators can operate for multiple epochs without rotating keys, meaning they use identical DKG decryption keys across all those epochs.

**4. Transcript Storage and Accessibility** [4](#0-3) 

DKG transcripts containing encrypted shares are stored on-chain as `vector<u8>`, making them permanently accessible to any party monitoring the blockchain or accessing historical state.

**Attack Scenario:**
1. Validator V operates in epochs 100-105 without rotating their consensus key
2. DKG transcripts from these epochs contain shares encrypted under V's encryption public key (derived from their static decryption key)
3. At epoch 106, V's node is compromised and their consensus private key is stolen
4. Attacker derives V's DKG decryption key using `maybe_dk_from_bls_sk()`
5. Attacker retrieves historical transcripts from epochs 100-105 from on-chain storage
6. Attacker decrypts V's shares from all historical transcripts
7. If attacker compromises sufficient validators' keys (≥ threshold), they can reconstruct the dealt secret keys from past epochs, potentially compromising historical randomness generation

**Cryptographic Forward Secrecy Violation:**
True forward secrecy requires that compromise of long-term keys does NOT compromise past session keys. Here:
- Long-term key: BLS consensus private key
- Session key: DKG decryption key (and transitively, shares of the dealt secret)
- Relationship: Session key = f(Long-term key) where f is deterministic

Therefore: Compromise of long-term key ⇒ Compromise of all session keys ⇒ No forward secrecy

## Impact Explanation

This issue represents a **cryptographic design weakness** rather than a directly exploitable vulnerability. However, it violates critical cryptographic principles:

**Security Impact:**
- **Historical Randomness Compromise**: If sufficient validator keys are compromised (even months/years later), past randomness values can be reconstructed, potentially enabling retroactive analysis or prediction of randomness-dependent outcomes
- **Cascading Key Compromise**: A single validator key compromise exposes that validator's participation in ALL historical DKG sessions where the key was used
- **No Cryptographic Isolation Between Epochs**: Different epochs are not cryptographically isolated if validators don't rotate keys

**Severity Assessment:**
This is classified as **High severity** based on:
- Violation of cryptographic forward secrecy property explicitly questioned in the audit scope
- Significant protocol-level security weakness affecting the randomness subsystem
- Requires validator key compromise (external event) but amplifies damage through lack of session isolation
- Affects the security model of the entire on-chain randomness system

Note: This does NOT meet "Critical" severity because it requires prerequisite validator key compromise and does not directly enable fund theft, consensus violations, or network partition without that external failure.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors Increasing Likelihood:**
1. **Operational Convenience**: Validators typically avoid key rotation due to operational complexity, downtime risks, and coordination overhead. Many validators will operate with the same consensus key for extended periods (months to years).

2. **No Mandatory Rotation**: The protocol does not enforce or incentivize key rotation. There are no automatic rotation mechanisms, expiration times, or alerts for stale keys.

3. **Historical Transcript Persistence**: All DKG transcripts are permanently stored on-chain and freely accessible, creating an ever-growing attack surface of historical encrypted data.

4. **Node Compromise Risk**: Validator nodes face ongoing security threats (infrastructure vulnerabilities, supply chain attacks, insider threats, key extraction through side channels). Over long operational periods, the probability of at least one key compromise event increases significantly.

**Factors Decreasing Likelihood:**
- Requires actual validator key compromise as a prerequisite
- Attackers need to compromise threshold number of validators to reconstruct dealt secrets
- Modern validator operations include security best practices like HSM usage and key isolation

## Recommendation

Implement proper forward secrecy through one or more of the following approaches:

**1. Ephemeral Per-Session Decryption Keys (Preferred Solution)**

Modify the DKG trait to require fresh decryption keys for each DKG session:

```rust
pub trait DKGTrait: Debug {
    // ... existing types ...
    
    // Add session ID to key generation
    type SessionId: Clone + Send + Sync;
    
    // Modified to accept session context
    fn generate_new_validator_decrypt_key<R: CryptoRng + RngCore>(
        rng: &mut R,
        session_id: &Self::SessionId,
        consensus_key: &Self::DealerPrivateKey,
    ) -> Self::NewValidatorDecryptKey;
    
    // Require proof that key is session-specific
    fn verify_key_is_ephemeral(
        key: &Self::NewValidatorDecryptKey,
        session_id: &Self::SessionId,
    ) -> Result<()>;
}
```

Implementation should use HKDF or similar key derivation with session-specific context:
```rust
decrypt_key = HKDF(consensus_key, session_id || epoch || "DKG-DECRYPTION-KEY-v1")
```

**2. Mandatory Key Rotation Policy**

Add on-chain enforcement of maximum key age: [3](#0-2) 

Modify the staking module to track key age and enforce rotation:
```move
struct ValidatorConfig has key {
    consensus_pubkey: vector<u8>,
    consensus_key_rotation_epoch: u64,  // NEW: Track when key was last rotated
    // ... other fields
}

// Add check in validator eligibility
const MAX_KEY_AGE_EPOCHS: u64 = 90;  // Force rotation every ~90 days

public fun is_validator_eligible(pool_address: address): bool {
    let config = borrow_global<ValidatorConfig>(pool_address);
    let current_epoch = reconfiguration::current_epoch();
    let key_age = current_epoch - config.consensus_key_rotation_epoch;
    
    key_age <= MAX_KEY_AGE_EPOCHS  // Validator becomes ineligible if key too old
}
```

**3. Hybrid Approach**

Combine consensus key with per-session randomness:
```rust
pub fn derive_session_decrypt_key(
    consensus_sk: &PrivateKey,
    epoch: u64,
    session_nonce: &[u8],
) -> DecryptPrivKey {
    // Use KDF with session-specific inputs
    let session_context = [
        b"APTOS-DKG-SESSION-KEY",
        &epoch.to_le_bytes(),
        session_nonce,
    ].concat();
    
    HKDF::derive(consensus_sk.to_bytes(), &session_context)
}
```

**4. Add Trait-Level Guarantees**

Extend the trait to make forward secrecy explicit:
```rust
/// Trait marker indicating forward secrecy support
pub trait ForwardSecureDKG: DKGTrait {
    /// Verify that decryption keys from different sessions are cryptographically independent
    fn verify_session_independence(
        key1: &Self::NewValidatorDecryptKey,
        session1: &Self::SessionId,
        key2: &Self::NewValidatorDecryptKey,
        session2: &Self::SessionId,
    ) -> Result<()>;
}
```

## Proof of Concept

```rust
// File: types/src/dkg/forward_secrecy_test.rs
#[cfg(test)]
mod forward_secrecy_vulnerability_poc {
    use super::*;
    use aptos_crypto::{bls12381::PrivateKey, Uniform};
    use types::dkg::{real_dkg::maybe_dk_from_bls_sk, DefaultDKG, DKGTrait};
    
    #[test]
    fn demonstrate_forward_secrecy_violation() {
        let mut rng = rand::thread_rng();
        
        // Simulate validator using same consensus key across epochs
        let consensus_sk = PrivateKey::generate(&mut rng);
        
        // Epoch 100: Derive decryption key
        let decrypt_key_epoch_100 = maybe_dk_from_bls_sk(&consensus_sk).unwrap();
        
        // ... validator participates in DKG, transcript_100 is created and stored on-chain ...
        
        // Epoch 105: Validator STILL using same consensus key (no rotation)
        let decrypt_key_epoch_105 = maybe_dk_from_bls_sk(&consensus_sk).unwrap();
        
        // VULNERABILITY: Keys are identical across epochs
        assert_eq!(
            decrypt_key_epoch_100.to_bytes(),
            decrypt_key_epoch_105.to_bytes(),
            "Forward secrecy violation: Same decryption key used across different DKG sessions"
        );
        
        // Simulate key compromise at epoch 110
        println!("Attacker compromises consensus_sk at epoch 110");
        let compromised_key = consensus_sk.clone();
        
        // Attacker can now derive decryption keys for ALL past epochs
        let recovered_key_100 = maybe_dk_from_bls_sk(&compromised_key).unwrap();
        let recovered_key_105 = maybe_dk_from_bls_sk(&compromised_key).unwrap();
        
        assert_eq!(
            decrypt_key_epoch_100.to_bytes(),
            recovered_key_100.to_bytes(),
            "Attacker can derive historical decryption keys from compromised consensus key"
        );
        
        assert_eq!(
            decrypt_key_epoch_105.to_bytes(), 
            recovered_key_105.to_bytes(),
            "All historical sessions compromised by single key breach"
        );
        
        // With these recovered keys, attacker can decrypt historical transcript shares
        // If threshold validators are compromised, dealt secrets can be reconstructed
        println!("SUCCESS: Forward secrecy violation demonstrated");
        println!("Single consensus key compromise exposes all historical DKG sessions");
    }
    
    #[test]
    fn verify_no_session_isolation() {
        // This test demonstrates the lack of cryptographic isolation between sessions
        let mut rng = rand::thread_rng();
        let consensus_sk = PrivateKey::generate(&mut rng);
        
        // Generate keys for 10 different epochs
        let mut keys = Vec::new();
        for _epoch in 0..10 {
            keys.push(maybe_dk_from_bls_sk(&consensus_sk).unwrap());
        }
        
        // All keys are identical - no session isolation
        for i in 1..keys.len() {
            assert_eq!(
                keys[0].to_bytes(),
                keys[i].to_bytes(),
                "No cryptographic isolation between DKG sessions"
            );
        }
    }
}
```

**Notes:**
- This PoC demonstrates the cryptographic property violation, not a direct exploit
- Actual exploitation requires validator key compromise (separate security failure)
- The vulnerability is in the design allowing deterministic, non-ephemeral key derivation
- Forward secrecy violation means the DKG system does not provide session-level cryptographic isolation

### Citations

**File:** types/src/dkg/real_dkg/mod.rs (L597-604)
```rust
pub fn maybe_dk_from_bls_sk(
    sk: &PrivateKey,
) -> anyhow::Result<<WTrx as Transcript>::DecryptPrivKey> {
    let mut bytes = sk.to_bytes(); // in big-endian
    bytes.reverse();
    <WTrx as Transcript>::DecryptPrivKey::try_from(bytes.as_slice())
        .map_err(|e| anyhow!("dk_from_bls_sk failed with dk deserialization error: {e}"))
}
```

**File:** types/src/dkg/mod.rs (L178-232)
```rust
pub trait DKGTrait: Debug {
    type DealerPrivateKey;
    type DealerPublicKey; // This is the public key associated with `DealerPrivateKey`
    type PublicParams: Clone + Debug + Send + Sync + MayHaveRoundingSummary;
    type Transcript: Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>;
    type InputSecret: Uniform;
    type DealtSecret;
    type DealtSecretShare;
    type DealtPubKeyShare;
    type NewValidatorDecryptKey: Uniform;

    fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> Self::PublicParams;
    fn aggregate_input_secret(secrets: Vec<Self::InputSecret>) -> Self::InputSecret;
    fn dealt_secret_from_input(
        pub_params: &Self::PublicParams,
        input: &Self::InputSecret,
    ) -> Self::DealtSecret;
    fn generate_transcript<R: CryptoRng + RngCore>(
        rng: &mut R,
        params: &Self::PublicParams,
        input_secret: &Self::InputSecret,
        my_index: u64,
        sk: &Self::DealerPrivateKey,
        pk: &Self::DealerPublicKey,
    ) -> Self::Transcript;

    /// NOTE: used in VM.
    fn verify_transcript(params: &Self::PublicParams, trx: &Self::Transcript) -> Result<()>;

    fn verify_transcript_extra(
        trx: &Self::Transcript,
        verifier: &ValidatorVerifier,
        checks_voting_power: bool,
        ensures_single_dealer: Option<AccountAddress>,
    ) -> Result<()>;

    fn aggregate_transcripts(
        params: &Self::PublicParams,
        accumulator: &mut Self::Transcript,
        element: Self::Transcript,
    );

    fn decrypt_secret_share_from_transcript(
        pub_params: &Self::PublicParams,
        trx: &Self::Transcript,
        player_idx: u64,
        dk: &Self::NewValidatorDecryptKey,
    ) -> Result<(Self::DealtSecretShare, Self::DealtPubKeyShare)>;

    fn reconstruct_secret_from_shares(
        pub_params: &Self::PublicParams,
        player_share_pairs: Vec<(u64, Self::DealtSecretShare)>,
    ) -> Result<Self::DealtSecret>;
    fn get_dealers(transcript: &Self::Transcript) -> BTreeSet<u64>;
}
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L910-952)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L33-37)
```text
    struct DKGSessionState has copy, store, drop {
        metadata: DKGSessionMetadata,
        start_time_us: u64,
        transcript: vector<u8>,
    }
```
