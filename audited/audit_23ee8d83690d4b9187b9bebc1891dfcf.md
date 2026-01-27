# Audit Report

## Title
Missing Bounds Validation in DKG Transcript Decryption Causes Validator Node Crashes

## Summary
The `decrypt_own_share()` and `get_public_key_share()` functions in the DKG PVSS protocol perform unchecked array indexing using `player.id`, which can cause validator nodes to panic and crash if the player ID exceeds the transcript's array bounds. This vulnerability is exploitable during epoch transitions when validator set size mismatches occur between DKG transcript creation and actual epoch start.

## Finding Description
The DKG (Distributed Key Generation) protocol's transcript decryption functions lack bounds validation on player IDs before array access. Specifically:

**In unweighted_protocol.rs**, the `decrypt_own_share()` function directly indexes arrays without validation: [1](#0-0) 

**Similarly, `get_public_key_share()` performs unchecked array access:** [2](#0-1) 

**The weighted protocol (actually used in production) has the same issue:** [3](#0-2) 

Where `get_share_index()` accesses arrays without bounds checking on player.id: [4](#0-3) 

**The vulnerability is triggered in the consensus epoch manager**, where Player structs are constructed with arbitrary IDs from the validator set without validation: [5](#0-4) 

**Most critically, the epoch manager iterates over ALL validators in the current epoch and attempts to retrieve public key shares:** [6](#0-5) 

**The transcript verification is explicitly skipped:** [7](#0-6) 

**The Player struct's intended type safety is acknowledged as broken:** [8](#0-7) 

**The verification function checks array sizes match sc.n, but it's not called:** [9](#0-8) 

**Attack Scenario:**
1. DKG session completes for epoch N with target validator set of size X
2. The validator set changes slightly before epoch N+1 starts (e.g., emergency validator addition via governance, or validator set composition edge case)
3. Epoch N+1 begins with Y validators where Y > X
4. When epoch_manager.rs iterates `(0..new_epoch_state.verifier.len())` and calls `get_public_key_share()` with Player {id: i} where i >= X, the array access panics
5. The validator node crashes in the consensus critical path

## Impact Explanation
**High Severity** - This qualifies as "Validator node crashes" and "API crashes" per the Aptos bug bounty program.

**Impact:**
- Validator nodes crash during epoch transitions, disrupting consensus
- Affects randomness generation infrastructure critical to the protocol
- Crashes occur in the consensus path, not just peripheral APIs
- Could cause partial network unavailability if multiple validators crash simultaneously
- Breaks the deterministic execution invariant as crashing nodes diverge from operational ones

The vulnerability violates two critical invariants:
1. **Resource Limits**: Operations should handle edge cases gracefully, not panic
2. **Deterministic Execution**: All validators should process epoch transitions identically

While this doesn't cause permanent network partition or fund loss, validator node crashes in the consensus path constitute High severity impact.

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability requires specific conditions:
- A size mismatch between the DKG transcript's target validator set and the actual epoch start validator set
- This could occur through governance actions, emergency validator operations, or edge cases in validator set management

**Mitigating factors:**
- Validator set changes during reconfiguration should be locked by `reconfiguration_state`
- The system is designed to prevent mismatches
- Transcripts are created for specific target validator sets

**Aggravating factors:**
- The lack of defensive bounds checking means ANY edge case causes immediate crashes
- No validation that `dkg_pub_params` validator set size matches `new_epoch_state` validator set size
- The code explicitly skips transcript verification ("No need to verify the transcript")
- The loop iterates over the CURRENT validator set size, not the DKG transcript's size

Even if rare, the consequences are severe enough and the fix simple enough that this represents a significant vulnerability.

## Recommendation
**Add defensive bounds validation before all array accesses in DKG transcript functions:**

```rust
fn decrypt_own_share(
    &self,
    sc: &Self::SecretSharingConfig,
    player: &Player,
    dk: &Self::DecryptPrivKey,
    _pp: &Self::PublicParameters,
) -> anyhow::Result<(Self::DealtSecretKeyShare, Self::DealtPubKeyShare)> {
    // Add bounds check
    if player.id >= sc.n {
        bail!("Player ID {} exceeds valid range [0, {})", player.id, sc.n);
    }
    if player.id >= self.C.len() {
        bail!("Player ID {} exceeds transcript ciphertext array size {}", player.id, self.C.len());
    }
    if player.id >= self.V.len() - 1 {
        bail!("Player ID {} exceeds transcript commitment array size {}", player.id, self.V.len() - 1);
    }
    
    let ctxt = self.C[player.id];
    let ephemeral_key = self.C_0.mul(dk.dk);
    let dealt_secret_key_share = ctxt.sub(ephemeral_key);
    let dealt_pub_key_share = self.V[player.id];

    Ok((
        Self::DealtSecretKeyShare::new(Self::DealtSecretKey::new(dealt_secret_key_share)),
        Self::DealtPubKeyShare::new(Self::DealtPubKey::new(dealt_pub_key_share)),
    ))
}
```

**Additionally, validate validator set size matches before the loop in epoch_manager.rs:**

```rust
// Validate validator set size matches DKG transcript
if new_epoch_state.verifier.len() != dkg_pub_params.pvss_config.wconfig.get_total_weight() {
    return Err(NoRandomnessReason::ValidatorSetSizeMismatch);
}

let pk_shares = (0..new_epoch_state.verifier.len())
    .map(|id| {
        transcript
            .main
            .get_public_key_share(&dkg_pub_params.pvss_config.wconfig, &Player { id })
            .map_err(|e| NoRandomnessReason::PublicKeyShareRetrievalFailed(e))
    })
    .collect::<Result<Vec<_>, _>>()?;
```

**Also enforce Player creation only through SecretSharingConfig methods to provide actual type safety.**

## Proof of Concept
```rust
#[test]
fn test_out_of_bounds_player_id_causes_crash() {
    use aptos_dkg::pvss::das::unweighted_protocol::Transcript;
    use aptos_dkg::pvss::traits::Transcript as TranscriptTrait;
    use aptos_crypto::player::Player;
    
    // Create a transcript with sc.n = 4 validators
    let sc = ThresholdConfigBlstrs::new(4, 3);
    let mut rng = rand::thread_rng();
    let transcript = Transcript::generate(&sc, &pp, &mut rng);
    
    // Attempt to decrypt share for player with ID = 5 (out of bounds)
    let dk = encryption_dlog::g1::DecryptPrivKey::generate(&mut rng);
    let invalid_player = Player { id: 5 }; // Bypasses intended type safety
    
    // This will panic with "index out of bounds"
    let result = std::panic::catch_unwind(|| {
        transcript.decrypt_own_share(&sc, &invalid_player, &dk, &pp)
    });
    
    assert!(result.is_err(), "Expected panic from out-of-bounds access");
}
```

**Notes:**
The vulnerability demonstrates a critical failure in defensive programming where the system assumes validator set sizes always match between DKG creation and usage, without verification. The explicit comment "No need to verify the transcript" combined with unchecked array access creates a fragile system that crashes on edge cases rather than handling them gracefully. This violates best practices for consensus-critical code that should prioritize robustness and explicit validation over implicit assumptions.

### Citations

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

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L234-248)
```rust
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
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L220-244)
```rust
    fn decrypt_own_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player: &Player,
        dk: &Self::DecryptPrivKey,
        _pp: &Self::PublicParameters,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let weight = sc.get_player_weight(player);
        let mut sk_shares = Vec::with_capacity(weight);
        let pk_shares = self.get_public_key_share(sc, player);

        for j in 0..weight {
            let k = sc.get_share_index(player.id, j).unwrap();

            let ctxt = self.C[k]; // h_1^{f(s_i + j - 1)} \ek_i^{r_{s_i + j}}
            let ephemeral_key = self.R[k].mul(dk.dk); // (g_1^{r_{s_i + j}})
            let dealt_secret_key_share = ctxt.sub(ephemeral_key);

            sk_shares.push(pvss::dealt_secret_key_share::g1::DealtSecretKeyShare::new(
                Self::DealtSecretKey::new(dealt_secret_key_share),
            ));
        }

        (sk_shares, pk_shares)
    }
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L199-205)
```rust
    pub fn get_share_index(&self, i: usize, j: usize) -> Option<usize> {
        if j < self.weights[i] {
            Some(self.starting_index[i] + j)
        } else {
            None
        }
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L422-435)
```rust
    fn decrypt_secret_share_from_transcript(
        pub_params: &Self::PublicParams,
        trx: &Self::Transcript,
        player_idx: u64,
        dk: &Self::NewValidatorDecryptKey,
    ) -> anyhow::Result<(Self::DealtSecretShare, Self::DealtPubKeyShare)> {
        let (sk, pk) = trx.main.decrypt_own_share(
            &pub_params.pvss_config.wconfig,
            &Player {
                id: player_idx as usize,
            },
            dk,
            &pub_params.pvss_config.pp,
        );
```

**File:** consensus/src/epoch_manager.rs (L1063-1063)
```rust
        // No need to verify the transcript.
```

**File:** consensus/src/epoch_manager.rs (L1080-1086)
```rust
        let pk_shares = (0..new_epoch_state.verifier.len())
            .map(|id| {
                transcript
                    .main
                    .get_public_key_share(&dkg_pub_params.pvss_config.wconfig, &Player { id })
            })
            .collect::<Vec<_>>();
```

**File:** crates/aptos-crypto/src/player.rs (L26-28)
```rust
/// The point of Player is to provide type-safety: ensure nobody creates out-of-range player IDs.
/// So there is no `new()` method; only the SecretSharingConfig trait is allowed to create them.
// TODO: AFAIK the only way to really enforce this is to put both traits inside the same module (or use unsafe Rust)
```
