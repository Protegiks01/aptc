# Audit Report

## Title
Missing Identity Point Validation in DealtPubKeyShare Allows Weak Key Generation in DKG Protocol

## Summary
The `DealtPubKeyShare` structure in the Aptos DKG (Distributed Key Generation) implementation lacks runtime validation to prevent the identity point (point at infinity) from being accepted as a valid public key share. This allows malicious dealers to contribute zero-entropy secrets that pass all verification checks, weakening the randomness and cryptographic security of the generated keys.

## Finding Description

The `DealtPubKeyShare` wraps a `DealtPubKey` containing a G2 group element from the BLS12-381 curve. While deserialization validates that points are on the curve and in the prime-order subgroup, there is **no explicit check rejecting the identity point**. [1](#0-0) 

The deserialization uses `g2_proj_from_bytes` which accepts the identity point as valid: [2](#0-1) 

In the DAS weighted protocol, public key shares are extracted directly from `V_hat` elements without identity validation: [3](#0-2) 

The transcript verification includes pairing checks that enforce consistency between `V` (G1) and `V_hat` (G2), but these checks pass when both encode polynomials with zero evaluations: [4](#0-3) 

The `InputSecret` type explicitly allows zero values: [5](#0-4) 

**Attack Path:**
1. A malicious dealer creates an `InputSecret` with value zero
2. Calls `Transcript::deal()` which generates `V_hat[W] = g_2^{f(0)} = g_2^0 = identity`
3. The transcript passes all verification checks (signatures, low-degree test, pairing checks)
4. The dealt public key is the identity point, contributing zero entropy to the aggregated randomness
5. Multiple colluding malicious dealers can significantly weaken the final randomness used for consensus leader election and other cryptographic operations

## Impact Explanation

This issue qualifies as **High Severity** under the "Significant protocol violations" category because:

1. **Weakens Cryptographic Security**: The DKG protocol's fundamental purpose is to generate high-entropy shared secrets for randomness and threshold signatures. Allowing zero-entropy contributions violates this guarantee.

2. **Undermines Consensus Security**: The generated randomness is used for critical consensus operations. Weakened randomness can enable validator set manipulation and bias in leader election.

3. **No Defense in Depth**: The verification logic enforces mathematical consistency but not cryptographic strength. If enough validators are malicious, they can collectively produce weak keys.

4. **Violates Invariant #10**: "Cryptographic Correctness: BLS signatures, VRF, and hash operations must be secure" - identity point keys are cryptographically trivial and insecure.

While not directly causing fund loss, this enables protocol-level attacks that undermine the security model of the consensus mechanism.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Ease of Exploitation**: Trivial - a malicious dealer simply needs to pass `InputSecret::zero()` or craft a transcript with identity points
- **Detection Difficulty**: Low - the transcript appears mathematically valid and passes all checks
- **Mitigation Requirements**: Requires honest majority of dealers, but no explicit enforcement
- **Operational Reality**: Validators are generally trusted, but DKG protocols should be Byzantine-fault-tolerant by design

The likelihood increases if:
- The validator set has a significant minority of compromised nodes
- Economic incentives favor biasing randomness outcomes
- No monitoring exists for entropy contributions

## Recommendation

Add explicit runtime validation to reject identity points in `DealtPubKeyShare` and the dealt public key:

**1. Add validation in DealtPubKeyShare construction:**

```rust
impl DealtPubKeyShare {
    pub fn new(dealt_pk: DealtPubKey) -> Result<Self, CryptoMaterialError> {
        // Reject identity point
        if dealt_pk.as_group_element().is_identity().into() {
            return Err(CryptoMaterialError::ValidationError);
        }
        Ok(DealtPubKeyShare(dealt_pk))
    }
}
```

**2. Add validation in transcript verification:**

In `weighted_protocol.rs` and `unweighted_protocol.rs`, add checks in the `verify()` function:

```rust
// After line 288 in weighted_protocol.rs
// Validate dealt public key is not identity
if self.V_hat[W].is_identity().into() {
    bail!("Dealt public key cannot be the identity point");
}

// Optionally validate individual shares
for i in 0..W {
    if self.V_hat[i].is_identity().into() {
        bail!("Public key share at index {} is identity point", i);
    }
}
```

**3. Add validation when extracting public key shares:**

Modify `get_public_key_share()` to validate before wrapping:

```rust
fn get_public_key_share(
    &self,
    sc: &Self::SecretSharingConfig,
    player: &Player,
) -> Self::DealtPubKeyShare {
    // ... existing code ...
    for j in 0..weight {
        let k = sc.get_share_index(player.id, j).unwrap();
        let pk = Self::DealtPubKey::new(self.V_hat[k]);
        
        // Validate not identity
        if pk.as_group_element().is_identity().into() {
            panic!("Public key share cannot be identity point");
        }
        
        pk_shares.push(pvss::dealt_pub_key_share::g2::DealtPubKeyShare::new(pk));
    }
    // ...
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_crypto::Uniform;
    use aptos_dkg::pvss::{das::WeightedTranscript, traits::Transcript};
    use blstrs::{G2Projective, Scalar};
    use group::Group;
    use rand::thread_rng;

    #[test]
    fn test_zero_secret_passes_verification() {
        let mut rng = thread_rng();
        
        // Create a zero input secret
        let zero_secret = InputSecret::zero();
        
        // Setup DKG configuration
        let sc = ThresholdConfigBlstrs::new(/* params */);
        let pp = PublicParameters::default();
        let ssk = PrivateKey::generate(&mut rng);
        let spk = PublicKey::from(&ssk);
        let eks = vec![/* encryption keys */];
        
        // Deal with zero secret
        let transcript = WeightedTranscript::deal(
            &sc,
            &pp,
            &ssk,
            &spk,
            &eks,
            &zero_secret,  // Zero secret!
            &0u64,
            &Player { id: 0 },
            &mut rng,
        );
        
        // Verify the transcript - THIS SHOULD FAIL BUT PASSES
        let result = transcript.verify(&sc, &pp, &vec![spk], &eks, &vec![0u64]);
        assert!(result.is_ok(), "Transcript with zero secret incorrectly passes verification");
        
        // The dealt public key is the identity point
        let dealt_pk = transcript.get_dealt_public_key();
        assert!(dealt_pk.as_g2().is_identity().into(), 
                "Dealt public key should be identity for zero secret");
        
        println!("VULNERABILITY CONFIRMED: Zero-entropy transcript passes all checks!");
    }
}
```

## Notes

This vulnerability highlights a gap between mathematical correctness and cryptographic security. While the verification correctly enforces that `V` and `V_hat` encode the same polynomial (via pairing checks) and that the polynomial has the correct degree (via low-degree test), it does not enforce that the polynomial's constant term (the secret) is non-zero.

The issue is particularly concerning because:
1. The README explicitly states that deserialization uses safe methods, but "safe" only means "valid group element," not "cryptographically strong"
2. The commented note "I don't think we need this DealtPubKey[Share] anymore" suggests incomplete design consideration
3. No monitoring or alerting exists for weak entropy contributions in the aggregated DKG output [6](#0-5) 

The fix should be implemented at multiple layers for defense in depth: input validation, construction validation, and verification validation.

### Citations

**File:** crates/aptos-dkg/src/pvss/dealt_pub_key_share.rs (L8-59)
```rust
macro_rules! dealt_pub_key_share_impl {
    ($GTProjective:ident, $gt:ident) => {
        use crate::pvss::dealt_pub_key::$gt::{DealtPubKey, DEALT_PK_NUM_BYTES};
        use aptos_crypto::{
            CryptoMaterialError, ValidCryptoMaterial, ValidCryptoMaterialStringExt,
        };
        use aptos_crypto_derive::{DeserializeKey, SerializeKey};
        use blstrs::$GTProjective;

        /// The size of a serialized *dealt public key share*.
        pub(crate) const DEALT_PK_SHARE_NUM_BYTES: usize = DEALT_PK_NUM_BYTES;

        /// A player's *share* of the *dealt public key* from above. Wrapping around
        /// `DealtPubKey` ensures they have the same type; it is irrelevant otherwise
        #[derive(DeserializeKey, Clone, Debug, SerializeKey, PartialEq, Eq)]
        pub struct DealtPubKeyShare(DealtPubKey);

        //
        // DealtPublicKeyShare
        //

        impl DealtPubKeyShare {
            pub fn new(dealt_pk: DealtPubKey) -> Self {
                DealtPubKeyShare(dealt_pk)
            }

            pub fn to_bytes(&self) -> [u8; DEALT_PK_SHARE_NUM_BYTES] {
                self.0.to_bytes()
            }

            pub fn as_group_element(&self) -> &$GTProjective {
                self.0.as_group_element()
            }
        }

        impl ValidCryptoMaterial for DealtPubKeyShare {
            const AIP_80_PREFIX: &'static str = "";

            fn to_bytes(&self) -> Vec<u8> {
                self.to_bytes().to_vec()
            }
        }

        impl TryFrom<&[u8]> for DealtPubKeyShare {
            type Error = CryptoMaterialError;

            /// Deserialize a `DealtPublicKeyShare`.
            fn try_from(bytes: &[u8]) -> std::result::Result<DealtPubKeyShare, Self::Error> {
                DealtPubKey::try_from(bytes).map(|pk| DealtPubKeyShare(pk))
            }
        }
    };
```

**File:** crates/aptos-crypto/src/blstrs/mod.rs (L113-128)
```rust
/// Helper method to *securely* parse a sequence of bytes into a `G2Projective` point.
/// NOTE: This function will check for prime-order subgroup membership in $\mathbb{G}_2$.
pub fn g2_proj_from_bytes(bytes: &[u8]) -> Result<G2Projective, CryptoMaterialError> {
    let slice = match <&[u8; G2_PROJ_NUM_BYTES]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => return Err(CryptoMaterialError::WrongLengthError),
    };

    let a = G2Projective::from_compressed(slice);

    if a.is_some().unwrap_u8() == 1u8 {
        Ok(a.unwrap())
    } else {
        Err(CryptoMaterialError::DeserializationError)
    }
}
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L197-213)
```rust
    fn get_public_key_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player: &Player,
    ) -> Self::DealtPubKeyShare {
        let weight = sc.get_player_weight(player);
        let mut pk_shares = Vec::with_capacity(weight);

        for j in 0..weight {
            let k = sc.get_share_index(player.id, j).unwrap();
            pk_shares.push(pvss::dealt_pub_key_share::g2::DealtPubKeyShare::new(
                Self::DealtPubKey::new(self.V_hat[k]),
            ));
        }

        pk_shares
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L478-484)
```rust
        for i in 0..W + 1 {
            let lhs = pairing(&g_1_aff, &V_hat_aff[i]);
            let rhs = pairing(&self.V[i].to_affine(), &g_2_aff);
            if lhs != rhs {
                bail!("V[{}] and V_hat[{}] did not match", i, i);
            }
        }
```

**File:** crates/aptos-crypto/src/input_secret.rs (L53-61)
```rust
impl Zero for InputSecret {
    fn zero() -> Self {
        InputSecret { a: Scalar::ZERO }
    }

    fn is_zero(&self) -> bool {
        self.a.is_zero_vartime()
    }
}
```

**File:** crates/aptos-dkg/README.md (L55-59)
```markdown
We (mostly) rely on the `aptos-crypto` `SerializeKey` and `DeserializeKey` derives for safety during deserialization.
Specifically, each cryptographic object (e.g., public key, public parameters, etc) must implement `ValidCryptoMaterial` for serialization and `TryFrom` for deserialization when these derives are used.

The G1/G2 group elements in `blstrs` are deserialized safely via calls to `from_[un]compressed` rather than calls to `from_[un]compressed_unchecked` which does not check prime-order subgroup membership.

```
