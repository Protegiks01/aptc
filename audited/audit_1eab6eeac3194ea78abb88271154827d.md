# Audit Report

## Title
Array Out-of-Bounds Panic in DKG Share Decryption Causing Validator Node Crashes

## Summary
Multiple PVSS transcript implementations lack bounds checking when accessing arrays with `player.id`, allowing out-of-bounds array access that causes validator nodes to panic and crash during epoch transitions with randomness enabled. This affects both the test-only `insecure_field` implementation and the production `das::WeightedTranscript` implementation used in consensus.

## Finding Description

The vulnerability exists in the DKG (Distributed Key Generation) transcript decryption logic where player IDs are used as array indices without validation.

**Vulnerable Code Locations:**

1. **insecure_field implementation** (test-only but demonstrates the pattern): [1](#0-0) 

The `decrypt_own_share` function directly accesses `self.C[player.id]` without checking if `player.id < self.C.len()`.

2. **Production das::WeightedTranscript implementation**: [2](#0-1) 

This calls `sc.get_share_index(player.id, j).unwrap()` which accesses arrays without bounds validation.

3. **Root cause in WeightedConfig**: [3](#0-2) 

The `get_share_index` function accesses `self.weights[i]` at line 200 WITHOUT validating that `i < self.weights.len()`.

4. **Vulnerable usage in consensus**: [4](#0-3) 

This code iterates over `new_epoch_state.verifier.len()` validators and creates `Player { id }` objects for each, calling `get_public_key_share` on the transcript without validating that the transcript was created for the same number of validators.

**Attack Vector:**

The `Player` struct has a public `id` field, undermining intended type safety: [5](#0-4) 

Despite comments indicating "there is no `new()` method; only the SecretSharingConfig trait is allowed to create them," the public `id` field allows arbitrary `Player` construction.

**Exploitation Scenario:**

When a validator node starts a new epoch with randomness enabled, it:
1. Retrieves the completed DKG transcript from on-chain storage
2. Deserializes the transcript WITHOUT re-validation (line 1063 comment: "No need to verify the transcript") [6](#0-5) 

3. Attempts to get public key shares for ALL validators in the new epoch
4. If `new_epoch_state.verifier.len() > dkg_pub_params.pvss_config.wconfig.tc.n`, creating `Player { id: n }` and calling array access functions causes an out-of-bounds panic

This breaks the **Consensus Safety** invariant by causing validator nodes to crash during epoch transitions, potentially preventing the network from progressing if enough validators are affected.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node crashes**: A panic in `try_get_rand_config_for_new_epoch` causes the validator process to terminate
- **Consensus disruption**: If multiple validators crash simultaneously during an epoch transition, the network could lose liveness
- **Deterministic but avoidable**: The crash only occurs when randomness is enabled and specific conditions are met, but the lack of bounds checking creates a persistent attack surface

The impact is HIGH rather than CRITICAL because:
- It requires specific conditions (validator set size mismatch or corrupted state)
- It doesn't directly cause fund loss or permanent network partition
- Recovery is possible by restarting validators or disabling randomness features

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered through several scenarios:

1. **Validator set mismatch**: If `new_epoch_state.verifier` contains more validators than the DKG transcript was created for, the out-of-bounds access occurs
   - While validator set changes are restricted during DKG sessions, the validation at line 1043-1045 only checks epoch numbers, not validator set sizes [7](#0-6) 

2. **Storage corruption**: The transcript is deserialized from on-chain bytes without re-validation. If storage is corrupted or there's a deserialization bug, mismatched array sizes could cause panics

3. **State inconsistency**: Race conditions or bugs in epoch management could cause `new_epoch_state` to reflect a different validator set than expected

The likelihood is NOT higher because:
- Transcripts are validated before on-chain storage: [8](#0-7) 
- The validation includes size checks via `check_sizes()`: [9](#0-8) 

However, the lack of defensive bounds checking creates vulnerability to edge cases and state corruption.

## Recommendation

**Immediate Fix: Add bounds checking before array access**

1. In `weighted_config.rs`, validate the player index:
```rust
pub fn get_share_index(&self, i: usize, j: usize) -> Option<usize> {
    if i >= self.weights.len() {
        return None; // Add this check
    }
    if j < self.weights[i] {
        Some(self.starting_index[i] + j)
    } else {
        None
    }
}
```

2. In `epoch_manager.rs`, validate before calling `get_public_key_share`:
```rust
let expected_validator_count = dkg_pub_params.pvss_config.wconfig.get_total_num_players();
if new_epoch_state.verifier.len() != expected_validator_count {
    return Err(NoRandomnessReason::ValidatorSetMismatch);
}
```

3. Make the `Player::id` field private and enforce construction through `SecretSharingConfig`:
```rust
pub struct Player {
    id: usize, // Remove 'pub'
}
```

4. Add re-validation of transcripts when loaded from storage in critical paths as defense-in-depth.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_out_of_bounds_player_access() {
    use aptos_crypto::weighted_config::WeightedConfig;
    use aptos_dkg::pvss::{Player, das::WeightedTranscript};
    
    // Create a transcript for 10 validators
    let mut rng = rand::thread_rng();
    let stakes = vec![100u64; 10];
    let wconfig = WeightedConfig::new(...); // tc.n = 10
    
    let transcript = WeightedTranscript::generate(&wconfig, &pp, &mut rng);
    
    // Try to access with player id = 10 (out of bounds, valid indices are 0-9)
    let invalid_player = Player { id: 10 };
    
    // This will panic with out-of-bounds access
    let _ = transcript.get_public_key_share(&wconfig, &invalid_player);
}
```

**Notes:**
- The `insecure_field` implementation mentioned in the security question is test-only but demonstrates the same vulnerability pattern
- The production vulnerability exists in `das::WeightedTranscript` and `weighted_config.rs`
- The root cause is lack of bounds validation combined with public `Player::id` field allowing arbitrary player construction
- Impact is HIGH due to validator crash potential during consensus-critical epoch transitions

### Citations

**File:** crates/aptos-dkg/src/pvss/insecure_field/transcript.rs (L129-137)
```rust
    fn decrypt_own_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player: &Player,
        _dk: &Self::DecryptPrivKey,
        _pp: &Self::PublicParameters,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        (self.C[player.id], self.get_public_key_share(sc, player))
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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-424)
```rust
    fn check_sizes(&self, sc: &WeightedConfigBlstrs) -> anyhow::Result<()> {
        let W = sc.get_total_weight();

        if self.V.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V.len()
            );
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

**File:** consensus/src/epoch_manager.rs (L1043-1046)
```rust
        if dkg_session.metadata.dealer_epoch + 1 != new_epoch_state.epoch {
            return Err(NoRandomnessReason::CompletedSessionTooOld);
        }
        let dkg_pub_params = DefaultDKG::new_public_params(&dkg_session.metadata);
```

**File:** consensus/src/epoch_manager.rs (L1056-1063)
```rust
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_session.transcript.as_slice(),
        )
        .map_err(NoRandomnessReason::TranscriptDeserializationError)?;

        let vuf_pp = WvufPP::from(&dkg_pub_params.pvss_config.pp);

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

**File:** crates/aptos-crypto/src/player.rs (L21-28)
```rust
pub struct Player {
    /// A number from 0 to n-1.
    pub id: usize,
}

/// The point of Player is to provide type-safety: ensure nobody creates out-of-range player IDs.
/// So there is no `new()` method; only the SecretSharingConfig trait is allowed to create them.
// TODO: AFAIK the only way to really enforce this is to put both traits inside the same module (or use unsafe Rust)
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```
