# Audit Report

## Title
Out-of-Bounds Index Panic in Randomness Key Decryption During Epoch Transition

## Summary
The `try_get_rand_config_for_new_epoch()` function fails to validate that a validator's index in the new epoch is within bounds for the DKG transcript's target validator set before using it for secret share decryption. This causes validator node panics during epoch transitions when validator set changes occur between DKG completion and epoch start.

## Finding Description

During epoch transitions, validators attempt to decrypt their randomness keys from the completed DKG session. The vulnerable path begins when `try_get_rand_config_for_new_epoch()` obtains the validator's index from the new epoch state without validating it against the DKG transcript's target validator set size: [1](#0-0) 

This index is then passed directly to `decrypt_secret_share_from_transcript()` for key decryption: [2](#0-1) 

The decryption call flows through the RealDKG implementation: [3](#0-2) 

Which invokes `decrypt_own_share()` on the PVSS transcript: [4](#0-3) 

This calls `get_player_weight()` which performs an **unchecked array access**: [5](#0-4) 

Additionally, accessing ciphertext arrays is also unchecked and will panic if the index exceeds the DKG target set size.

The only validation performed is an epoch number check, with **no verification of validator set compatibility**: [6](#0-5) 

**Attack Scenario:**
The DKG target validator set is determined when DKG starts, sourced from `stake::next_validator_consensus_infos()`: [7](#0-6) 

If governance adds validators or reorders the validator set after DKG completes but before the epoch actually transitions, validators with indices >= the DKG target set size will attempt to access out-of-bounds array elements, causing immediate panics.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:

This vulnerability causes **Validator Node Crashes** (HIGH - up to $50,000), specifically meeting the "API crashes" and "Validator node slowdowns" categories:

- **Critical Phase Failure**: Crashes occur during epoch transitions when validator participation is most critical
- **Randomness Participation Loss**: Affected validators cannot contribute to on-chain randomness generation  
- **Cascading Impact**: Multiple validators may crash simultaneously if validator set changes affect multiple indices
- **Manual Recovery Required**: Node operators must manually restart crashed validators
- **Consensus Degradation**: Reduced active validator count decreases network resilience

While not causing total network halt, this represents a significant protocol reliability violation during the most sensitive operational phase.

## Likelihood Explanation

**Medium Likelihood** assessment:

**Mitigating Factors (Lower Likelihood):**
- Normal operation: DKG target validator set should match actual new epoch validator set
- Validator sets are generally stable between epochs
- System designed for consistency between DKG and epoch transition

**Risk Factors (Increases Likelihood):**
- **No Defensive Validation**: Complete absence of bounds checking means ANY mismatch causes immediate crash
- **Governance Changes**: Validator set modifications through governance can occur between DKG completion and epoch start
- **Edge Cases**: Emergency validator set updates, implementation bugs in validator set management
- **Race Conditions**: Timing windows during epoch transitions

Even if rare in practice, the **complete lack of defensive validation** violates production system best practices. Critical systems should validate assumptions rather than panic on unexpected state transitions.

## Recommendation

Add bounds validation before array accesses:

```rust
// In try_get_rand_config_for_new_epoch()
let my_index = new_epoch_state
    .verifier
    .address_to_validator_index()
    .get(&self.author)
    .copied()
    .ok_or_else(|| NoRandomnessReason::NotInValidatorSet)?;

// ADD VALIDATION HERE:
let target_validator_count = dkg_pub_params.pvss_config.wconfig.get_total_num_players();
if my_index >= target_validator_count as usize {
    return Err(NoRandomnessReason::ValidatorIndexOutOfBounds);
}
```

Additionally, validate the entire validator set compatibility:
```rust
if new_epoch_state.verifier.len() != target_validator_count {
    return Err(NoRandomnessReason::ValidatorSetSizeMismatch);
}
```

## Proof of Concept

While a full PoC requires complex test infrastructure, the vulnerability path is demonstrable through code inspection:

1. The DKG session completes with `target_validator_set` of size N
2. Governance updates the validator set to size M where M > N  
3. Epoch transition occurs
4. Validator at index i (where i >= N) calls `try_get_rand_config_for_new_epoch()`
5. Line 164 in `weighted_config.rs` executes: `self.weights[i]` where i >= weights.len()
6. Rust panics with index out of bounds error
7. Validator node crashes

The unchecked array accesses at the cited locations guarantee this panic behavior when the preconditions are met.

**Notes:**
This is a legitimate reliability vulnerability caused by missing defensive validation. While the normal operational path should work correctly, the absence of bounds checking creates fragility to validator set state changes. Production consensus systems should validate critical assumptions during state transitions rather than assuming consistency.

### Citations

**File:** consensus/src/epoch_manager.rs (L1043-1045)
```rust
        if dkg_session.metadata.dealer_epoch + 1 != new_epoch_state.epoch {
            return Err(NoRandomnessReason::CompletedSessionTooOld);
        }
```

**File:** consensus/src/epoch_manager.rs (L1047-1052)
```rust
        let my_index = new_epoch_state
            .verifier
            .address_to_validator_index()
            .get(&self.author)
            .copied()
            .ok_or_else(|| NoRandomnessReason::NotInValidatorSet)?;
```

**File:** consensus/src/epoch_manager.rs (L1066-1072)
```rust
        let (sk, pk) = DefaultDKG::decrypt_secret_share_from_transcript(
            &dkg_pub_params,
            &transcript,
            my_index as u64,
            &dkg_decrypt_key,
        )
        .map_err(NoRandomnessReason::SecretShareDecryptionFailed)?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L428-435)
```rust
        let (sk, pk) = trx.main.decrypt_own_share(
            &pub_params.pvss_config.wconfig,
            &Player {
                id: player_idx as usize,
            },
            dk,
            &pub_params.pvss_config.pp,
        );
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L318-327)
```rust
    fn decrypt_own_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player: &Player,
        dk: &Self::DecryptPrivKey,
        pp: &Self::PublicParameters,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let weight = sc.get_player_weight(player);

        let Cs = &self.Cs[player.id];
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L163-165)
```rust
    pub fn get_player_weight(&self, player: &Player) -> usize {
        self.weights[player.id]
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L34-39)
```text
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
```
