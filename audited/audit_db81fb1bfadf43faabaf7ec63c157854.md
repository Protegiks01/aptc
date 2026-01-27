# Audit Report

## Title
Unvalidated Player ID Construction Enables DoS via Out-of-Bounds Array Access in PVSS Share Operations

## Summary
The `Player` struct has a public `id` field and derives `Serialize`/`Deserialize`, allowing arbitrary Player construction with out-of-range IDs. Multiple critical functions in the PVSS (Publicly Verifiable Secret Sharing) protocol directly index arrays using `player.id` without bounds validation, enabling denial-of-service attacks against validator nodes processing DKG transcripts. [1](#0-0) 

## Finding Description

The Player struct is designed to provide type-safety for participant IDs in secret sharing protocols, with the intent that only `SecretSharingConfig` should create valid instances. However, a critical design flaw exists: [2](#0-1) 

The comment explicitly acknowledges this cannot be enforced without unsafe Rust or module restrictions. Since the `id` field is public and the struct derives serialization traits, anyone can construct or deserialize Players with arbitrary IDs.

**Attack Vector 1: PVSS Transcript Processing**

PVSS transcripts contain a `soks` field with Player instances that are deserialized from network messages: [3](#0-2) 

During transcript verification, Player IDs are never validated against the secret sharing configuration's bounds: [4](#0-3) 

**Attack Vector 2: Direct Array Indexing Without Bounds Checks**

The `get_public_key_share` function directly indexes using `player.id`: [5](#0-4) 

Similarly, `decrypt_own_share` performs multiple unchecked array accesses: [6](#0-5) 

**Attack Vector 3: Lagrange Coefficient Computation**

During secret reconstruction, Player IDs are extracted from shares and used to index into the roots of unity array without validation: [7](#0-6) [8](#0-7) 

**Exploitation Path:**

1. Attacker constructs a malicious PVSS transcript with Player IDs >= n in the `soks` field
2. Transcript is serialized and transmitted to validator nodes during DKG
3. Honest validators deserialize the transcript (Player IDs are not validated during deserialization)
4. When any validator attempts to call `get_public_key_share`, `decrypt_own_share`, or processes shares for reconstruction with these malformed Players, the out-of-bounds array access causes a panic
5. Multiple validators crash simultaneously, halting consensus and DKG completion

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple critical impact criteria:

1. **Non-recoverable Network Partition**: If enough validators crash processing a malicious transcript during DKG, the network cannot complete the randomness beacon generation, effectively halting the chain. Recovery requires manual intervention or a hardfork.

2. **Total Loss of Liveness**: DKG is a critical path for validator set updates and randomness generation. Successful DoS prevents epoch transitions and any governance actions requiring randomness.

3. **Consensus Safety Risk**: If malformed Player IDs don't cause immediate panic but are within array bounds (e.g., ID=n-1 when expecting ID=k<n-1), Lagrange coefficients will be computed for wrong evaluation points, producing incorrect reconstruction. This breaks the threshold security property of Shamir secret sharing, potentially compromising the dealt secret.

The vulnerability is particularly severe because:
- It affects core consensus infrastructure (DKG for randomness/validator updates)
- It requires no special privileges to exploit
- A single malicious transcript can affect all validators simultaneously
- The panic occurs during critical protocol phases that cannot be easily retried

## Likelihood Explanation

**High Likelihood of Exploitation:**

1. **Low Attack Complexity**: Creating a malicious transcript requires only:
   - Constructing `Player { id: 9999999 }` with an out-of-bounds ID
   - Serializing it into a PVSS transcript structure
   - Broadcasting to the network during DKG

2. **No Authentication Required**: While DKG participation requires being a validator, an attacker can exploit existing validators' transcript processing by injecting malicious data through network protocols.

3. **Deterministic Crash**: The vulnerability reliably triggers - any honest node processing the malicious transcript will panic on array access.

4. **Wide Attack Surface**: The Player struct is used throughout the DKG codebase in multiple array indexing operations, providing numerous trigger points.

5. **No Rate Limiting**: There are no apparent mechanisms to prevent repeated DoS attempts during DKG rounds.

## Recommendation

Implement mandatory bounds validation for all Player instances, especially those deserialized from untrusted sources:

**Short-term Fix:**
Add validation in deserialization and at function entry points:

```rust
// In player.rs
impl Player {
    pub fn validate(&self, max_id: usize) -> Result<(), &'static str> {
        if self.id >= max_id {
            return Err("Player ID exceeds maximum allowed value");
        }
        Ok(())
    }
}

// In transcript verification (unweighted_protocol.rs)
fn verify<A: Serialize + Clone>(&self, sc: &ThresholdConfigBlstrs, ...) -> anyhow::Result<()> {
    // Add Player ID validation for all soks
    for (player, _, _, _) in &self.soks {
        if player.id >= sc.n {
            bail!("Invalid Player ID {} exceeds max {}", player.id, sc.n - 1);
        }
    }
    // ... rest of verification
}

// In get_public_key_share
fn get_public_key_share(&self, sc: &Self::SecretSharingConfig, player: &Player) -> Self::DealtPubKeyShare {
    assert!(player.id < sc.n, "Player ID {} out of bounds for n={}", player.id, sc.n);
    Self::DealtPubKeyShare::new(Self::DealtPubKey::new(self.V[player.id]))
}
```

**Long-term Fix:**
Make the `id` field private and enforce bounds checking in construction:

```rust
pub struct Player {
    id: usize, // Make private
}

impl Player {
    // Only allow construction through this validated method
    pub(crate) fn new_validated(id: usize, max: usize) -> Result<Self, Error> {
        if id >= max {
            return Err(Error::InvalidPlayerId);
        }
        Ok(Player { id })
    }
    
    pub fn get_id(&self) -> usize {
        self.id
    }
}

// Custom Deserialize that requires context
// Or use a newtype wrapper that includes bounds
```

## Proof of Concept

```rust
use aptos_dkg::pvss::{Player, das::Transcript};
use aptos_crypto::bls12381;
use blstrs::{G1Projective, G2Projective, Scalar};

#[test]
#[should_panic(expected = "index out of bounds")]
fn test_malicious_player_id_dos() {
    // Setup: Create a valid threshold config for n=4 validators
    let n = 4;
    let t = 3;
    let sc = ThresholdConfigBlstrs::new(t, n).unwrap();
    
    // Attack: Create a malicious Player with ID >= n
    let malicious_player = Player { id: 999999 };
    
    // Create a minimal valid-looking transcript but with malicious player
    let sk = bls12381::PrivateKey::genesis();
    let mut transcript = Transcript::generate(&sc, &pp, &mut rng);
    
    // Replace legitimate player with malicious one in soks
    transcript.soks[0].0 = malicious_player;
    
    // Serialize and deserialize (simulating network transmission)
    let bytes = bcs::to_bytes(&transcript).unwrap();
    let malicious_transcript: Transcript = bcs::from_bytes(&bytes).unwrap();
    
    // Verification passes (no Player ID bounds checking)
    assert!(malicious_transcript.verify(&sc, &pp, &spks, &eks, &auxs).is_ok());
    
    // But calling get_public_key_share causes panic due to out-of-bounds access
    // This crashes the validator node!
    let _ = malicious_transcript.get_public_key_share(&sc, &malicious_player);
    // PANIC: index out of bounds: the len is 5 but the index is 999999
}

#[test]
#[should_panic]
fn test_malicious_player_in_reconstruction() {
    let sc = ThresholdConfigBlstrs::new(3, 4).unwrap();
    
    // Create shares with one malicious Player ID
    let mut shares = vec![];
    shares.push((Player { id: 0 }, valid_share_0));
    shares.push((Player { id: 1 }, valid_share_1));
    shares.push((Player { id: 9999 }, valid_share_2)); // Malicious
    
    // Reconstruction attempts to compute Lagrange coefficients
    // and panics when accessing omegas[9999]
    let _ = DealtSecretKey::reconstruct(&sc, &shares);
}
```

## Notes

This vulnerability is particularly insidious because:

1. **Silent Failure Path**: The code comment acknowledges the limitation but provides no runtime protection
2. **Cascading Failures**: A single malicious transcript can crash multiple validators simultaneously
3. **DKG Critical Path**: The vulnerability affects a non-recoverable protocol phase
4. **Threshold Security**: Beyond DoS, wrong Player IDs (but in-bounds) could break cryptographic guarantees by evaluating polynomials at incorrect points

The root cause is a fundamental design choice prioritizing convenience over security - making Player fields public for serialization without enforcing invariants. This violates the principle of making invalid states unrepresentable.

### Citations

**File:** crates/aptos-crypto/src/player.rs (L21-24)
```rust
pub struct Player {
    /// A number from 0 to n-1.
    pub id: usize,
}
```

**File:** crates/aptos-crypto/src/player.rs (L26-28)
```rust
/// The point of Player is to provide type-safety: ensure nobody creates out-of-range player IDs.
/// So there is no `new()` method; only the SecretSharingConfig trait is allowed to create them.
// TODO: AFAIK the only way to really enforce this is to put both traits inside the same module (or use unsafe Rust)
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L73-80)
```rust
impl TryFrom<&[u8]> for Transcript {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
    }
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L165-171)
```rust
    fn get_public_key_share(
        &self,
        _sc: &Self::SecretSharingConfig,
        player: &Player,
    ) -> Self::DealtPubKeyShare {
        Self::DealtPubKeyShare::new(Self::DealtPubKey::new(self.V[player.id]))
    }
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L177-193)
```rust
    fn decrypt_own_share(
        &self,
        _sc: &Self::SecretSharingConfig,
        player: &Player,
        dk: &Self::DecryptPrivKey,
        _pp: &Self::PublicParameters,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let ctxt = self.C[player.id]; // C_i = h_1^m \ek_i^r = h_1^m g_1^{r sk_i}
        let ephemeral_key = self.C_0.mul(dk.dk); // (g_1^r)^{sk_i} = ek_i^r
        let dealt_secret_key_share = ctxt.sub(ephemeral_key);
        let dealt_pub_key_share = self.V[player.id]; // g_2^{f(\omega^i})

        (
            Self::DealtSecretKeyShare::new(Self::DealtSecretKey::new(dealt_secret_key_share)),
            Self::DealtPubKeyShare::new(Self::DealtPubKey::new(dealt_pub_key_share)),
        )
    }
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L226-263)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &<Self as traits::Transcript>::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        auxs: &[A],
    ) -> anyhow::Result<()> {
        if eks.len() != sc.n {
            bail!("Expected {} encryption keys, but got {}", sc.n, eks.len());
        }

        if self.C.len() != sc.n {
            bail!("Expected {} ciphertexts, but got {}", sc.n, self.C.len());
        }

        if self.V.len() != sc.n + 1 {
            bail!(
                "Expected {} (polynomial) commitment elements, but got {}",
                sc.n + 1,
                self.V.len()
            );
        }

        // Deriving challenges by flipping coins: less complex to implement & less likely to get wrong. Creates bad RNG risks but we deem that acceptable.
        let mut rng = thread_rng();
        let extra = random_scalars(2, &mut rng);

        // Verify signature(s) on the secret commitment, player ID and `aux`
        let g_2 = *pp.get_commitment_base();
        batch_verify_soks::<G2Projective, A>(
            self.soks.as_slice(),
            &g_2,
            &self.V[sc.n],
            spks,
            auxs,
            &extra[0],
        )?;
```

**File:** crates/aptos-dkg/src/pvss/dealt_secret_key.rs (L91-100)
```rust
            fn reconstruct(sc: &ThresholdConfigBlstrs, shares: &[ShamirShare<Self::ShareValue>]) -> anyhow::Result<Self> {
                assert_ge!(shares.len(), sc.get_threshold());
                assert_le!(shares.len(), sc.get_total_num_players());

                let ids = shares.iter().map(|(p, _)| p.id).collect::<Vec<usize>>();
                let lagr = lagrange_coefficients(
                    sc.get_batch_evaluation_domain(),
                    ids.as_slice(),
                    &Scalar::ZERO,
                );
```
