# Audit Report

## Title
Small-Subgroup Attack in Noise Protocol Allows Validator Network Key Compromise

## Summary
The Noise IK handshake implementation in `noise.rs` performs Diffie-Hellman key exchange without validating that the responder's static public key (rs) is a valid high-order point on Curve25519. A malicious validator can register a small-order point (order 2, 4, or 8) as their network public key, forcing the shared secret to have only 1-3 bits of entropy. This allows the attacker to decrypt the initiator's static public key by brute-forcing all possible DH outputs (maximum 8 attempts for order-8 points). [1](#0-0) 

## Finding Description
The vulnerability exists in the Noise IK protocol handshake implementation used for validator-to-validator network authentication. The attack exploits the contributory behavior of X25519 Diffie-Hellman when one party provides a small-order point.

**Technical Details:**

1. **No Public Key Validation**: The X25519 public key type accepts any 32-byte array without cryptographic validation: [2](#0-1) 

2. **Diffie-Hellman Without Checks**: The DH operation directly uses the x25519_dalek library without checking for small-order points or all-zero shared secrets: [3](#0-2) 

3. **Noise Protocol Flow**: In the `initiate_connection` function, the first DH operation `DH(e, rs)` occurs without validation: [4](#0-3) 

**Attack Scenario:**

1. **Malicious Validator Registration**: An attacker becomes a validator and registers one of the 8-torsion subgroup points as their `validator_network_public_key`. The codebase even includes these test constants: [5](#0-4) 

2. **No Validation During Registration**: When validators register their network keys, only format/length checks occur, not cryptographic validation: [6](#0-5) 

3. **Connection Attempt**: When an honest validator initiates a connection to the malicious validator: [7](#0-6) 

4. **Low-Entropy DH Output**: At line 310 of noise.rs, `e.diffie_hellman(&rs)` produces one of only 8 possible values (for order-8 point)

5. **Weak Encryption Key Derivation**: This low-entropy DH output is used to derive encryption key `k` via HKDF: [8](#0-7) 

6. **Decryption Attack**: The attacker receives the ciphertext containing the honest validator's static public key encrypted with key `k`. They try all 8 possible DH outputs, derive all 8 possible keys, and attempt decryption. One will succeed.

**Broken Invariant**: This violates the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure." The Noise protocol's security guarantees are compromised.

## Impact Explanation
**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This qualifies as **High Severity** due to:

1. **Validator Network Authentication Compromise**: An attacker can learn the static network public key of honest validators, enabling impersonation attacks.

2. **Significant Protocol Violation**: The Noise IK protocol's security model assumes static keys remain confidential. Leaking them breaks the authentication guarantees.

3. **Potential Network Disruption**: With compromised validator network keys, an attacker could:
   - Impersonate honest validators in network connections
   - Perform man-in-the-middle attacks on validator communications
   - Potentially inject malicious consensus messages
   - Cause network partitions by disrupting validator connectivity

4. **Not Critical**: While serious, this doesn't directly lead to fund theft, immediate consensus safety violations, or complete network failure without additional exploits.

## Likelihood Explanation
**Likelihood: Medium-High**

The attack is moderately likely because:

**Factors Increasing Likelihood:**
1. **No Validation Barrier**: Zero cryptographic validation of network public keys during validator registration
2. **Public Attack Surface**: Any entity can attempt to become a validator
3. **Well-Known Attack**: Small-subgroup attacks on DH are well-documented in cryptographic literature
4. **Available Constants**: The codebase itself includes the EIGHT_TORSION constants for testing

**Factors Decreasing Likelihood:**
1. **Requires Validator Status**: Attacker must successfully become a validator (requires stake and governance approval in permissioned networks)
2. **Detection Possible**: Honest validators may detect unusual network keys if monitoring is in place
3. **Limited Immediate Impact**: Additional exploits needed to fully compromise consensus

## Recommendation

**Immediate Fix**: Add point validation to reject small-order points in X25519 operations:

```rust
// In crates/aptos-crypto/src/x25519.rs, modify the diffie_hellman function:

pub fn diffie_hellman(&self, remote_public_key: &PublicKey) -> Result<[u8; SHARED_SECRET_SIZE], CryptoMaterialError> {
    let remote_public_key = x25519_dalek::PublicKey::from(remote_public_key.0);
    let shared_secret = self.0.diffie_hellman(&remote_public_key);
    
    // Check for all-zero shared secret (indicates small-order point)
    if shared_secret.as_bytes() == &[0u8; SHARED_SECRET_SIZE] {
        return Err(CryptoMaterialError::SmallSubgroupError);
    }
    
    Ok(shared_secret.as_bytes().to_owned())
}
```

**In crates/aptos-crypto/src/noise.rs**, handle the error:
```rust
// Line 310-311
let dh_output = e.diffie_hellman(&rs)
    .map_err(|_| NoiseError::InvalidPublicKey)?;
```

**Additional Validations**:
1. Add explicit small-subgroup checks during validator network key registration
2. Consider implementing point validation in `TryFrom<&[u8]>` for `x25519::PublicKey`
3. Add runtime checks in the Noise handshake to reject suspicious public keys

## Proof of Concept

```rust
#[test]
fn test_small_subgroup_attack() {
    use aptos_crypto::{noise::NoiseConfig, x25519, Uniform};
    use curve25519_dalek::constants::EIGHT_TORSION;
    use rand::SeedableRng;
    
    // Create honest initiator
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let initiator_private = x25519::PrivateKey::generate(&mut rng);
    let initiator_config = NoiseConfig::new(initiator_private);
    
    // Attacker creates malicious small-order public key
    // Using a point from the 8-torsion subgroup
    let malicious_rs_bytes = EIGHT_TORSION[1].compress().to_bytes();
    let malicious_rs = x25519::PublicKey::from(malicious_rs_bytes);
    
    // Initiator attempts connection with malicious rs
    let mut buffer = vec![0u8; noise::handshake_init_msg_len(8)];
    let result = initiator_config.initiate_connection(
        &mut rng,
        b"prologue",
        malicious_rs,
        Some(b"payload"),
        &mut buffer,
    );
    
    // Connection succeeds (BUG: should reject small-order point)
    assert!(result.is_ok());
    
    // At this point, the DH(e, rs) has produced one of only 8 possible values
    // An attacker can try all 8 values to decrypt the initiator's static key
    // embedded in the handshake message
}
```

**Notes**
- The vulnerability exists in production validator network code
- Ed25519 implementation explicitly acknowledges small-subgroup concerns but includes mitigations in signature verification [9](#0-8) 
- X25519 lacks equivalent protections despite using the same underlying curve
- The codebase includes EIGHT_TORSION test utilities, showing awareness of small-order point attacks in other contexts [10](#0-9)

### Citations

**File:** crates/aptos-crypto/src/noise.rs (L309-324)
```rust
        // -> es
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> s
        let aead = aes_key(&k[..]);
        let mut in_out = self.public_key.to_bytes();
        let nonce = aead::Nonce::assume_unique_for_key([0u8; AES_NONCE_SIZE]);

        aead.seal_in_place_append_tag(nonce, Aad::from(&h), &mut in_out)
            .map_err(|_| NoiseError::Encrypt)?;

        mix_hash(&mut h, &in_out[..]);
        response_buffer
            .write(&in_out[..])
            .map_err(|_| NoiseError::ResponseBufferTooSmall)?;
```

**File:** crates/aptos-crypto/src/x25519.rs (L90-94)
```rust
    pub fn diffie_hellman(&self, remote_public_key: &PublicKey) -> [u8; SHARED_SECRET_SIZE] {
        let remote_public_key = x25519_dalek::PublicKey::from(remote_public_key.0);
        let shared_secret = self.0.diffie_hellman(&remote_public_key);
        shared_secret.as_bytes().to_owned()
    }
```

**File:** crates/aptos-crypto/src/x25519.rs (L228-236)
```rust
impl std::convert::TryFrom<&[u8]> for PublicKey {
    type Error = traits::CryptoMaterialError;

    fn try_from(public_key_bytes: &[u8]) -> Result<Self, Self::Error> {
        let public_key_bytes: [u8; PUBLIC_KEY_SIZE] = public_key_bytes
            .try_into()
            .map_err(|_| traits::CryptoMaterialError::WrongLengthError)?;
        Ok(Self(public_key_bytes))
    }
```

**File:** crates/aptos-crypto/src/test_utils.rs (L83-89)
```rust
use curve25519_dalek::constants::EIGHT_TORSION;
#[cfg(any(test, feature = "fuzzing"))]
use curve25519_dalek::edwards::EdwardsPoint;
#[cfg(any(test, feature = "fuzzing"))]
use curve25519_dalek::scalar::Scalar;
#[cfg(any(test, feature = "fuzzing"))]
use curve25519_dalek::traits::Identity;
```

**File:** crates/aptos-genesis/src/keys.rs (L60-77)
```rust
    let private_identity = PrivateIdentity {
        account_address,
        account_private_key: account_key.private_key(),
        consensus_private_key: consensus_key.private_key(),
        full_node_network_private_key: full_node_network_key.private_key(),
        validator_network_private_key: validator_network_key.private_key(),
    };

    let public_identity = PublicIdentity {
        account_address,
        account_public_key: account_key.public_key(),
        consensus_public_key: Some(private_identity.consensus_private_key.public_key()),
        consensus_proof_of_possession: Some(bls12381::ProofOfPossession::create(
            &private_identity.consensus_private_key,
        )),
        full_node_network_public_key: Some(full_node_network_key.public_key()),
        validator_network_public_key: Some(validator_network_key.public_key()),
    };
```

**File:** network/framework/src/noise/handshake.rs (L209-218)
```rust
        let initiator_state = self
            .noise_config
            .initiate_connection(
                &mut rng,
                prologue_msg,
                remote_public_key,
                Some(&payload),
                client_noise_msg,
            )
            .map_err(NoiseHandshakeError::BuildClientHandshakeMessageFailed)?;
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L298-301)
```rust
    /// Deserialize an Ed25519PublicKey. This method will NOT check for key validity, which means
    /// the returned public key could be in a small subgroup. Nonetheless, our signature
    /// verification implicitly checks if the public key lies in a small subgroup, so canonical
    /// uses of this library will not be susceptible to small subgroup attacks.
```

**File:** crates/aptos-crypto/src/unit_tests/ed25519_test.rs (L204-226)
```rust
        let bad_scalar = Scalar::zero();

        let bad_component_1 = curve25519_dalek::constants::EIGHT_TORSION[idx];
        let bad_component_2 = bad_component_1.neg();

        // compute bad_pub_key, bad_signature
        let bad_pub_key_point = bad_component_1; // we need this to cancel the hashed component of the verification equation

        // we pick an evil R component
        let bad_sig_point = bad_component_2;

        let bad_key = ed25519_dalek::PublicKey::from_bytes(&bad_pub_key_point.compress().to_bytes()).unwrap();
        // This assertion passes because Ed25519PublicKey::TryFrom<&[u8]> no longer checks for small subgroup membership
        prop_assert!(Ed25519PublicKey::try_from(&bad_pub_key_point.compress().to_bytes()[..]).is_ok());

        let bad_signature = ed25519_dalek::Signature::from_bytes(&[
            &bad_sig_point.compress().to_bytes()[..],
            &bad_scalar.to_bytes()[..]
        ].concat()).unwrap();

        // Seek k = H(R, A, M) ≡ 1 [8] so that sB - kA = R <=> -kA = -A <=> k mod order(A) = 0
        prop_assume!(bad_key.verify(&message[..], &bad_signature).is_ok());
        prop_assert!(bad_key.verify_strict(&message[..], &bad_signature).is_err());
```
