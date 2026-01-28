# Audit Report

## Title
Missing Low-Order Point Validation in x25519 Public Key Handling for Noise IK Protocol

## Summary
The x25519 public keys extracted from NetworkAddress for the Noise IK handshake lack validation to reject low-order (small subgroup) curve points. While invalid keys do not cause panics, they create a cryptographic weakness where malicious nodes can use low-order points to enable brute-force attacks on session keys.

## Finding Description

When parsing a NetworkAddress in `parse_dial_addr()`, the code extracts a raw x25519::PublicKey from the NoiseIK protocol without any validation. [1](#0-0) 

The x25519::PublicKey type accepts any 32-byte array without checking if it represents a valid curve point or validating against low-order points. The TryFrom implementation only checks length, wrapping any 32 bytes directly. [2](#0-1) 

This unvalidated public key is then used directly in Diffie-Hellman operations during the Noise IK handshake. In the initiator's handshake, the remote static key is used in multiple DH operations for the es (ephemeral-to-static) exchange [3](#0-2)  and the ss (static-to-static) exchange. [4](#0-3) 

The responder side also performs DH with the initiator's static key without validation. [5](#0-4) [6](#0-5) [7](#0-6) 

**Attack Path:**
1. Attacker generates a low-order x25519 point (e.g., order-8 point) and uses it as their network static key
2. Attacker advertises this in their NetworkAddress via discovery
3. When honest nodes dial the attacker's address, they extract the unvalidated key [8](#0-7)  and pass it to upgrade_outbound [9](#0-8) 
4. The handshake proceeds using this low-order key [10](#0-9) 
5. DH operations with the attacker's low-order static key produce outputs from a small set (≤8 values)
6. Attacker brute-forces all possible session keys (at most 8 attempts)
7. Attacker decrypts handshake messages and session traffic

**Why no panics occur:**
The x25519_dalek library performs scalar multiplication on any 32-byte input without validation, returning a result (possibly weak) rather than panicking. [11](#0-10) 

## Impact Explanation

This constitutes a **Medium severity** cryptographic protocol violation per the bug bounty program's "Limited Protocol Violations" category. While it doesn't directly lead to funds loss or consensus breaks, it violates the Noise IK protocol's security guarantees:

- **Confidentiality compromise**: Attacker can decrypt handshake messages and session traffic directed to them
- **Limited scope**: Only affects sessions where honest nodes connect TO the malicious node  
- **Network layer weakness**: Could expose validator communication metadata or peer discovery information

The issue does not meet Critical/High severity because:
- No direct funds theft or consensus safety violation
- Attacker cannot forge messages without also controlling the peer
- Limited to specific attack scenarios (malicious node operator)
- No impact on validator performance or API availability

## Likelihood Explanation

**Moderate likelihood** of exploitation:
- Requires attacker to operate a network node and control its identity key
- Attacker must successfully advertise malicious public key via NetworkAddress discovery
- Other nodes must initiate connections to the attacker
- Detection is possible through monitoring for known low-order points

Importantly, Ed25519 implementations within the same codebase perform explicit small subgroup validation, demonstrating that this validation is considered necessary for elliptic curve keys. [12](#0-11)  The codebase also maintains test constants for the 8-torsion subgroup. [13](#0-12) 

This creates an inconsistency where Ed25519 keys are validated for low-order points but x25519 keys are not, despite both being used for cryptographic operations on the same elliptic curve (Curve25519).

## Recommendation

Add low-order point validation for x25519 public keys before using them in cryptographic operations. The validation should:

1. Check if the point is one of the known low-order points on Curve25519
2. Reject any public key that fails validation before DH operations
3. Apply this validation consistently in:
   - `x25519::PublicKey::try_from()` for deserialization
   - `parse_dial_addr()` after extracting the NoiseIK public key
   - Before any Diffie-Hellman operations in the Noise handshake

This can be implemented using the same approach as Ed25519 validation, checking against the 8-torsion subgroup points or using point validation functions from the underlying curve25519_dalek library.

## Proof of Concept

A proof of concept would involve:

1. Generating one of the 8 low-order points on Curve25519 (e.g., the identity point or other torsion points)
2. Creating a NetworkAddress with this low-order point as the NoiseIK public key
3. Running a malicious node that advertises this NetworkAddress
4. Observing that honest nodes successfully complete the Noise IK handshake without rejecting the low-order point
5. Demonstrating that the DH outputs fall within a small set, enabling brute-force attacks on the session key

The presence of the `EIGHT_TORSION` constant in test files provides the exact byte representations of all 8 low-order points that should be rejected.

## Notes

This vulnerability demonstrates a critical inconsistency in cryptographic key validation within the Aptos codebase. The explicit validation of Ed25519 keys for small subgroup attacks, combined with the maintenance of `EIGHT_TORSION` test constants, proves that the development team understands the risks of low-order curve points. The absence of equivalent validation for x25519 keys, despite their use in security-critical Noise IK handshakes, represents an oversight that weakens the protocol's cryptographic guarantees.

While x25519 is designed to be "safe by default" through scalar clamping, the Noise protocol framework benefits from contributory behavior where both parties contribute to key derivation. Low-order points break this property, allowing one party to force weak shared secrets.

### Citations

**File:** types/src/network_address/mod.rs (L643-645)
```rust
            "noise-ik" => Protocol::NoiseIK(x25519::PublicKey::from_encoded_string(
                args.next().ok_or(ParseError::UnexpectedEnd)?,
            )?),
```

**File:** crates/aptos-crypto/src/x25519.rs (L90-94)
```rust
    pub fn diffie_hellman(&self, remote_public_key: &PublicKey) -> [u8; SHARED_SECRET_SIZE] {
        let remote_public_key = x25519_dalek::PublicKey::from(remote_public_key.0);
        let shared_secret = self.0.diffie_hellman(&remote_public_key);
        shared_secret.as_bytes().to_owned()
    }
```

**File:** crates/aptos-crypto/src/x25519.rs (L228-237)
```rust
impl std::convert::TryFrom<&[u8]> for PublicKey {
    type Error = traits::CryptoMaterialError;

    fn try_from(public_key_bytes: &[u8]) -> Result<Self, Self::Error> {
        let public_key_bytes: [u8; PUBLIC_KEY_SIZE] = public_key_bytes
            .try_into()
            .map_err(|_| traits::CryptoMaterialError::WrongLengthError)?;
        Ok(Self(public_key_bytes))
    }
}
```

**File:** crates/aptos-crypto/src/noise.rs (L310-311)
```rust
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L327-328)
```rust
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L449-450)
```rust
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L469-470)
```rust
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L531-532)
```rust
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** network/framework/src/transport/mod.rs (L549-549)
```rust
        let (base_addr, pubkey, handshake_version) = Self::parse_dial_addr(&addr)?;
```

**File:** network/framework/src/transport/mod.rs (L566-566)
```rust
        let upgrade_fut = upgrade_outbound(self.ctxt.clone(), fut_socket, addr, peer_id, pubkey);
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

**File:** third_party/move/move-examples/diem-framework/crates/crypto/src/ed25519.rs (L373-377)
```rust
        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(CryptoMaterialError::SmallSubgroupError);
        }
```

**File:** crates/aptos-crypto/src/unit_tests/ed25519_test.rs (L514-547)
```rust
pub const EIGHT_TORSION: [[u8; 32]; 8] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128,
    ],
    [
        38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172,
        5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
    ],
    [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ],
    [
        38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172,
        5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
    ],
];
```
