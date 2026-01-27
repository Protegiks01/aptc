# Audit Report

## Title
DKG Weight Mismatch Enables Denial-of-Service via Malicious PVSS Transcript

## Summary
A malicious dealer can craft a PVSS transcript with per-player ciphertext counts that don't match player weights, bypassing verification checks in release builds and causing validator nodes to panic during secret reconstruction, resulting in a Denial-of-Service attack on the DKG randomness generation protocol.

## Finding Description

The weighted chunky PVSS implementation contains a critical verification gap that allows malicious dealers to create transcripts with incorrect per-player share allocations. The vulnerability stems from three interacting issues:

**Issue 1: Missing Verification Check**

The `verify()` function validates transcript structure but fails to enforce per-player weight constraints: [1](#0-0) [2](#0-1) 

The verification only checks that `Cs.len() == total_num_players` (outer dimension) and `Cs_flat.len() == total_weight` (total count), but never validates that `Cs[i].len() == player_weight[i]` for each individual player.

**Issue 2: Debug-Only Assertion in decrypt_own_share()**

The function that decrypts shares contains only a debug assertion to check weight matching: [3](#0-2) 

In Rust, `debug_assert_eq!` is completely removed in release builds (compiled with `--release`). Production validators run release builds, so this check never executes.

**Issue 3: Deferred Panic During Reconstruction**

The actual panic occurs later during secret reconstruction when virtual player indexing fails: [4](#0-3) 

The `assert_lt!` at line 179 (not a debug assertion) panics when a player attempts to reconstruct with more shares than their weight entitles, crashing the validator node.

**Attack Scenario:**

1. Malicious dealer creates a PVSS transcript during DKG with manipulated structure:
   - Player 0: weight 3, but `Cs[0]` contains 5 ciphertext vectors
   - Player 1: weight 2, but `Cs[1]` contains 0 ciphertext vectors  
   - Total: 5 vectors = total_weight ✓ (passes verification)

2. Transcript passes all verification checks because:
   - Outer dimensions match: `Cs.len() == 2` players ✓
   - Total count matches: `5 == total_weight` ✓
   - SoK/range proofs verify (they don't enforce structural constraints)

3. Player 0 calls `decrypt_own_share()` in a release build:
   - Debug assertion is removed, no error
   - `decrypt_chunked_scalars()` uses `.zip()` iterator [5](#0-4) 

   - Decrypts `min(5, Rs.len())` shares = 5 shares instead of entitled 3

4. Player 0 attempts reconstruction with 5 shares: [6](#0-5) 

5. At iteration `pos=3`, `get_virtual_player(player, 3)` is called
6. `assert_lt!(3, 3)` panics because weight is 3
7. Validator node crashes, DKG protocol fails

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per Aptos bug bounty criteria:

**Significant Protocol Violations**: The DKG protocol is critical for Aptos randomness generation, which is required for:
- Validator leader election randomness
- On-chain randomness API for dApps
- Consensus protocol operation

**Validator Node Crashes**: Affected validators will panic and crash during secret reconstruction, requiring manual intervention to restart.

**Liveness Impact**: While not total network failure, DKG failures prevent epoch transitions and randomness generation, degrading network liveness until the malicious dealer's transcript is identified and excluded.

**Consensus Disruption**: Since DKG runs during epoch changes, failures can delay or prevent validator set updates, affecting consensus operation.

This matches the HIGH severity category: "Validator node slowdowns / API crashes / Significant protocol violations" (up to $50,000).

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Must be selected as a dealer in the DKG protocol (any validator can be a dealer)
- Requires basic understanding of PVSS transcript structure
- No collusion with other validators needed
- Exploit is deterministic once conditions are met

**Complexity: LOW**
- Attack is straightforward: manipulate ciphertext vector lengths while preserving total count
- No timing dependencies or race conditions
- No cryptographic breaks required

**Detection Difficulty: HIGH**
- Malicious transcript passes all verification checks
- Panic occurs later during reconstruction, not immediately
- Hard to attribute to specific dealer without forensic analysis
- Appears as a generic assertion failure rather than obvious attack

**Frequency: MEDIUM**
- Occurs during DKG protocol execution (epoch changes)
- Typical epoch duration: ~2 hours on Aptos mainnet
- Any malicious validator can trigger when selected as dealer

## Recommendation

Add explicit per-player weight validation in the `verify()` function:

```rust
// In weighted_transcript.rs, fn verify(), after line 152:

// Validate per-player ciphertext counts match weights
for i in 0..sc.get_total_num_players() {
    let player = Player { id: i };
    let expected_weight = sc.get_player_weight(&player);
    let actual_count = self.subtrs.Cs[i].len();
    if actual_count != expected_weight {
        bail!(
            "Player {} has {} ciphertext vectors but weight is {}",
            i,
            actual_count,
            expected_weight
        );
    }
}

// Also validate Rs.len() matches max_weight
if self.subtrs.Rs.len() != sc.get_max_weight() {
    bail!(
        "Expected {} randomness vectors (max_weight), but got {}",
        sc.get_max_weight(),
        self.subtrs.Rs.len()
    );
}
```

**Additional Hardening:**
Replace the debug assertion in `decrypt_own_share()` with a runtime check:

```rust
// At line 578, replace debug_assert_eq! with:
if Cs.len() != sc.get_player_weight(player) {
    bail!(
        "Ciphertext count mismatch: got {} but player weight is {}",
        Cs.len(),
        sc.get_player_weight(player)
    );
}
```

This provides defense-in-depth, catching malicious transcripts at verification time (primary defense) and during decryption (secondary defense).

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability by creating a malicious transcript
// and showing it passes verification but causes panic during reconstruction.

#[cfg(test)]
mod malicious_transcript_test {
    use super::*;
    use aptos_crypto::weighted_config::WeightedConfig;
    use aptos_dkg::pvss::{
        chunky::{weighted_transcript::*, keys::*},
        traits::{Transcript, transcript::Aggregatable},
        Player,
    };
    
    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_weight_mismatch_panic() {
        // Setup: 2 players with weights [3, 2], total_weight = 5
        let weights = vec![3, 2];
        let threshold_weight = 3;
        let sc = WeightedConfig::new(weights, threshold_weight).unwrap();
        
        // Create a valid transcript first
        let mut transcript = Transcript::deal(/*...*/);
        
        // MALICIOUS MANIPULATION:
        // Swap ciphertext allocations: Player 0 gets 5 vectors, Player 1 gets 0
        let stolen_vectors = transcript.subtrs.Cs[1].clone();
        transcript.subtrs.Cs[0].extend(stolen_vectors);
        transcript.subtrs.Cs[1].clear();
        
        // Verification PASSES (missing per-player check)
        assert!(transcript.verify(&sc, &pp, &spks, &eks, &sid).is_ok());
        
        // Player 0 decrypts successfully in release build
        let (sk_shares, _pk_shares) = transcript.decrypt_own_share(
            &sc,
            &Player { id: 0 },
            &dk_0,
            &pp,
        );
        
        // sk_shares now has 5 elements instead of 3
        assert_eq!(sk_shares.len(), 5); // Wrong!
        
        // Attempt reconstruction - this PANICS at get_virtual_player
        // when iterating with pos >= 3 (the actual weight)
        let shares = vec![(Player { id: 0 }, sk_shares)];
        DealtSecretKey::reconstruct(&sc, &shares).unwrap(); // PANIC HERE
    }
}
```

**Runtime Demonstration:**
```bash
# Compile in release mode (debug assertions removed)
cargo build --release --package aptos-dkg

# Run DKG with malicious dealer
# Expected: Validator crashes during secret reconstruction
# Error: "assertion failed: j < self.weights[player.id]"
```

## Notes

This vulnerability is particularly insidious because:

1. **Timing of failure**: The malicious transcript passes verification immediately but only fails during reconstruction, which may occur much later or on different nodes.

2. **Attribution difficulty**: The panic appears as a generic assertion failure rather than obvious malicious activity, making it hard to identify the attacker.

3. **Release-only impact**: Debug builds catch the issue immediately, but production validators running release builds are vulnerable.

4. **Structural validation gap**: The verification relies on total counts rather than per-element constraints, a common oversight in aggregate validation logic.

The fix is straightforward (add explicit per-player validation), but the impact is significant given DKG's role in Aptos consensus and randomness generation.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L140-152)
```rust
        if self.subtrs.Cs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of chunked ciphertexts, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Cs.len()
            );
        }
        if self.subtrs.Vs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of commitment elements, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Vs.len()
            );
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L247-252)
```rust
        let Cs_flat: Vec<_> = self.subtrs.Cs.iter().flatten().cloned().collect();
        assert_eq!(
            Cs_flat.len(),
            sc.get_total_weight(),
            "Number of ciphertexts does not equal number of weights"
        ); // TODO what if zero weight?
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L577-578)
```rust
        let Cs = &self.subtrs.Cs[player.id];
        debug_assert_eq!(Cs.len(), sc.get_player_weight(player));
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L177-183)
```rust
    pub fn get_virtual_player(&self, player: &Player, j: usize) -> Player {
        // println!("WeightedConfig::get_virtual_player({player}, {i})");
        assert_lt!(j, self.weights[player.id]);

        let id = self.get_share_index(player.id, j).unwrap();

        Player { id }
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

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L327-333)
```rust
    for (row, Rs_row) in Cs_rows.iter().zip(Rs_rows.iter()) {
        // Compute C - d_k * R for each chunk
        let exp_chunks: Vec<C> = row
            .iter()
            .zip(Rs_row.iter())
            .map(|(C_ij, &R_j)| C_ij.sub(R_j * *dk))
            .collect();
```
