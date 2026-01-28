# Audit Report

## Title
Missing Bounds Validation in DKG Transcript Decryption Causes Validator Node Crashes

## Summary
The DKG PVSS protocol's `decrypt_own_share()` and `get_public_key_share()` functions perform unchecked array indexing using `player.id`, which can cause validator nodes to panic and crash during epoch transitions if validator set size mismatches occur between DKG transcript creation and epoch start. The code lacks defensive bounds validation and explicitly bypasses transcript verification.

## Finding Description

The DKG (Distributed Key Generation) protocol contains multiple unchecked array accesses that can cause out-of-bounds panics during epoch transitions.

**In the unweighted protocol, direct array access occurs without bounds checking:** [1](#0-0) [2](#0-1) 

**The weighted protocol (used in production) has the same vulnerability:** [3](#0-2) 

**The underlying `get_share_index()` function accesses arrays without bounds validation:** [4](#0-3) 

When `player.id >= self.weights.len()`, the array access `self.weights[i]` will panic.

**The vulnerability is triggered in the consensus epoch manager during randomness configuration:** [5](#0-4) 

This code iterates over `new_epoch_state.verifier.len()` validators and directly constructs `Player { id }` without validation, bypassing the Player struct's intended type safety.

**The Player struct's type safety is explicitly acknowledged as broken:** [6](#0-5) 

**Transcript verification is explicitly skipped:** [7](#0-6) 

**The `check_sizes()` verification function exists but is not called:** [8](#0-7) 

**Critical validation gap:** [9](#0-8) 

This only checks epoch number, NOT validator set sizes. There is no validation that `new_epoch_state.verifier.len()` equals the DKG transcript's target validator set size.

**Attack Path:**
1. DKG session completes with `target_validator_set` of size X
2. Validator set size becomes Y (where Y > X) at epoch start due to edge cases in reconfiguration
3. Code iterates `(0..Y)` and calls `get_public_key_share()` with `Player { id: i }` where `i >= X`
4. Array access panics when accessing transcript arrays sized for X validators
5. Validator node crashes in consensus critical path

## Impact Explanation

**High Severity** per Aptos bug bounty criteria - "Validator node crashes" and "API crashes" (up to $50,000).

**Concrete Impact:**
- Validator nodes crash during epoch transitions, disrupting consensus participation
- Affects randomness generation infrastructure critical to on-chain randomness
- Crashes occur in the consensus path (`epoch_manager.rs`), not peripheral services
- Potential for partial network unavailability if multiple validators crash simultaneously
- Violates deterministic execution invariant as crashing nodes cannot process the epoch transition

This constitutes High severity because:
1. Causes validator node crashes (explicit bounty category)
2. Occurs in consensus-critical code path
3. Affects multiple validators simultaneously
4. Disrupts essential randomness infrastructure

## Likelihood Explanation

**Likelihood: Medium**

**Required Conditions:**
- Validator set size at epoch N+1 start must exceed the DKG transcript's target validator set size created during epoch N

**Mitigating Factors:**
- Protocol is designed to lock validator sets during reconfiguration
- Transcripts are created for specific target validator sets
- Normal operations maintain validator set consistency

**Aggravating Factors:**
- ZERO defensive bounds checking despite known type safety issues
- NO validation that validator set sizes match between DKG transcript and epoch state
- Explicit skipping of transcript verification ("No need to verify the transcript")
- Acknowledged broken Player type safety with TODO comment
- Loop iterates over CURRENT validator count, not transcript's validator count

**Key Issue:** This is a **defensive programming failure**. Even if the protocol is designed to prevent mismatches, the code should validate its assumptions rather than assuming correctness. The explicit TODO comment about broken type safety and the skipped verification indicate awareness of potential issues without adding defensive checks.

While rare under normal operations, edge cases in governance actions, emergency validator additions, or reconfiguration race conditions could trigger this. The lack of ANY bounds checking means edge cases cause immediate crashes rather than graceful error handling.

## Recommendation

Add defensive bounds validation before array access:

```rust
// In epoch_manager.rs around line 1080
let num_validators = new_epoch_state.verifier.len();
let transcript_validator_count = dkg_pub_params.pvss_config.wconfig.get_total_num_players();

if num_validators != transcript_validator_count {
    return Err(NoRandomnessReason::ValidatorSetSizeMismatch {
        expected: transcript_validator_count,
        actual: num_validators,
    });
}

let pk_shares = (0..num_validators)
    .map(|id| {
        transcript
            .main
            .get_public_key_share(&dkg_pub_params.pvss_config.wconfig, &Player { id })
    })
    .collect::<Vec<_>>();
```

Additionally:
1. Enable transcript verification instead of skipping it
2. Add bounds checking in `get_share_index()` with proper error handling
3. Fix Player type safety as noted in TODO comment

## Proof of Concept

The vulnerability can be demonstrated by examining the execution path during epoch transition when validator set sizes mismatch. Since this requires specific epoch transition conditions, a full PoC would need to:

1. Simulate epoch N with X validators completing DKG
2. Trigger epoch N+1 with Y > X validators
3. Observe the panic when `get_share_index()` is called with `player.id >= X`

The panic trace would be:
```
thread panicked at 'index out of bounds: the len is X but the index is Y'
  at weighted_config.rs:200 in get_share_index()
  called from weighted_protocol.rs:206 in get_public_key_share()
  called from epoch_manager.rs:1084 in try_get_rand_config_for_new_epoch()
```

## Notes

This vulnerability represents a failure of defensive programming principles. While the protocol is designed to prevent validator set mismatches, the code makes no effort to validate this assumption. The explicit TODO comment about broken Player type safety and the deliberately skipped transcript verification demonstrate awareness of potential issues without implementing proper safeguards. This gap creates risk under edge case conditions that could cause validator crashes in the consensus critical path.

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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-455)
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

        if self.V_hat.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V_hat.len()
            );
        }

        if self.R.len() != W {
            bail!(
                "Expected {} G_1 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R.len()
            );
        }

        if self.R_hat.len() != W {
            bail!(
                "Expected {} G_2 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R_hat.len()
            );
        }

        if self.C.len() != W {
            bail!("Expected C of length {}, but got {}", W, self.C.len());
        }

        Ok(())
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
