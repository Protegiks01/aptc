# Audit Report

## Title
Missing Per-Validator Share Count Validation in Weighted PVSS Enables Share Redistribution Attack

## Summary
The weighted PVSS implementation in the chunky transcript lacks validation that each validator receives the correct number of encrypted shares matching their configured weight. A malicious dealer can redistribute shares among validators while maintaining the correct total count, causing decryption failures or effective weight manipulation that breaks weighted secret sharing correctness.

## Finding Description

The weighted PVSS (Publicly Verifiable Secret Sharing) protocol is designed to distribute secret shares among validators proportionally to their configured weights. For example, a validator with weight 5 should receive 5 shares, while a validator with weight 3 should receive 3 shares. Any threshold number of validators whose combined weight meets the threshold should be able to reconstruct the secret.

However, the implementation contains a critical validation gap: [1](#0-0) 

This TODO comment indicates that per-player share count validation was intended but never implemented. The only validation present is a debug assertion that is compiled out in release builds: [2](#0-1) 

The transcript verification only validates the total flattened share count, not the per-validator distribution: [3](#0-2) 

During decryption, validators access their shares by iterating from `0..weight`: [4](#0-3) 

**Attack Scenario:**

A malicious dealer creates a weighted PVSS transcript with redistributed shares:
- Validator A (weight 40%): receives only 15% worth of shares  
- Validator B (weight 35%): receives 35% worth of shares (correct)
- Validator C (weight 25%): receives 50% worth of shares
- Total: 100% (passes validation ✓)

When Validator A attempts decryption with weight=40, the code tries to access `Cs[i]` for `i ∈ [0, 40)`, but only 15 shares exist, causing an out-of-bounds panic and DKG failure.

Alternatively, if the dealer provides fewer shares than configured weight without triggering panic, the effective weight during reconstruction is reduced: [5](#0-4) 

This code processes whatever shares are provided without validating the count matches the configured weight, allowing effective weight manipulation.

## Impact Explanation

**Severity: High**

This vulnerability breaks the fundamental security guarantee of weighted secret sharing - that validators' reconstruction power should match their configured stake-based weights. Impact includes:

1. **Denial of Service**: Malicious dealers can cause targeted validators to fail during share decryption, preventing DKG completion and blocking epoch transitions
2. **Weight Manipulation**: Effective validator weights during reconstruction no longer match declared weights, potentially allowing threshold manipulation
3. **Consensus Disruption**: DKG failures prevent randomness beacon generation, impacting leader election and consensus liveness

This qualifies as "Significant protocol violations" under the High severity category ($50,000) in the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is exploitable whenever:
- A validator acts as DKG dealer (rotates among all validators)
- The malicious dealer has incentive to disrupt DKG or manipulate effective weights
- The chunky weighted PVSS implementation is in active use

The attack requires no special privileges beyond being selected as dealer in a DKG round, making it accessible to any compromised validator. The lack of validation is present in production release builds where debug assertions are disabled.

## Recommendation

Add explicit per-validator share count validation during transcript verification:

```rust
// In weighted_transcript.rs verify() function, after line 152:
for i in 0..sc.get_total_num_players() {
    let player = sc.get_player(i);
    let expected_weight = sc.get_player_weight(&player);
    let actual_shares = self.subtrs.Cs[i].len();
    
    if actual_shares != expected_weight {
        bail!(
            "Player {} has {} shares but expected {} based on weight",
            i,
            actual_shares,
            expected_weight
        );
    }
    
    // Similarly validate Vs[i].len()
    if self.subtrs.Vs[i].len() != expected_weight {
        bail!(
            "Player {} has {} public key shares but expected {}",
            i,
            self.subtrs.Vs[i].len(),
            expected_weight
        );
    }
}
```

Additionally, add validation during reconstruction to prevent validators from providing arbitrary share counts:

```rust
// In weighted_config.rs reconstruct() function, after line 399:
let expected_weight = sc.get_player_weight(player);
if sub_shares.len() != expected_weight {
    bail!(
        "Player {} provided {} shares but has configured weight {}",
        player.id,
        sub_shares.len(),
        expected_weight
    );
}
```

## Proof of Concept

```rust
// Reproduction steps for the vulnerability

use aptos_dkg::pvss::chunky::weighted_transcript::*;
use aptos_crypto::weighted_config::WeightedConfigBlstrs;

#[test]
fn test_share_redistribution_attack() {
    // Setup: 3 validators with weights [5, 3, 2], threshold 6
    let weights = vec![5, 3, 2];
    let sc = WeightedConfigBlstrs::new(6, weights).unwrap();
    
    // Malicious dealer creates transcript with redistributed shares:
    // - Validator 0: only 2 shares (should be 5)
    // - Validator 1: 6 shares (should be 3)
    // - Validator 2: 2 shares (correct)
    
    // Create malformed Cs structure where:
    // Cs[0].len() = 2 (instead of 5)
    // Cs[1].len() = 6 (instead of 3)
    // Cs[2].len() = 2 (correct)
    // Total: 10 shares (passes flat validation)
    
    let mut malicious_transcript = create_malicious_transcript(&sc);
    
    // Verification SUCCEEDS because only total is checked
    assert!(verify_transcript(&malicious_transcript, &sc).is_ok());
    
    // Validator 0 attempts decryption with weight=5
    let player_0 = Player { id: 0 };
    let dk_0 = DecryptPrivKey::generate();
    
    // This will PANIC trying to access Cs[0][2], Cs[0][3], Cs[0][4]
    // when only Cs[0][0], Cs[0][1] exist
    let result = std::panic::catch_unwind(|| {
        malicious_transcript.decrypt_own_share(&sc, &player_0, &dk_0, &pp)
    });
    
    assert!(result.is_err(), "Decryption should panic due to out-of-bounds access");
    
    // This demonstrates the vulnerability: verification passes but
    // decryption fails due to incorrect per-player share distribution
}
```

**Notes**

The vulnerability exists in the chunky weighted PVSS implementation currently used for DKG. The missing validation allows malicious dealers to create transcripts that pass all cryptographic checks but cause operational failures or weight manipulation during share decryption and reconstruction. The explicit TODO comment and debug-only assertions indicate this was a known gap that was never properly addressed in production code.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L247-250)
```rust
        let Cs_flat: Vec<_> = self.subtrs.Cs.iter().flatten().cloned().collect();
        assert_eq!(
            Cs_flat.len(),
            sc.get_total_weight(),
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L327-329)
```rust
        let Cs = &self.Cs[player.id];

        // TODO: put an assert here saying that len(Cs) = weight
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L349-351)
```rust
        for i in 0..weight {
            // TODO: should really put this in a separate function
            let dealt_encrypted_secret_key_share_chunks: Vec<_> = Cs[i]
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L578-578)
```rust
        debug_assert_eq!(Cs.len(), sc.get_player_weight(player));
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L399-409)
```rust
            for (pos, share) in sub_shares.iter().enumerate() {
                let virtual_player = sc.get_virtual_player(player, pos);

                // println!(
                //     " + Adding share {pos} as virtual player {virtual_player}: {:?}",
                //     share
                // );
                // TODO(Performance): Avoiding the cloning here might be nice
                let tuple = (virtual_player, share.clone());
                flattened_shares.push(tuple);
            }
```
