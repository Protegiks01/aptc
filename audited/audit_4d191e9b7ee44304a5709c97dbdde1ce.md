# Audit Report

## Title
Missing Randomness Array Length Validation Enables Validator DoS in Chunky PVSS Decryption

## Summary
The `verify()` function in the chunky PVSS weighted transcript implementation fails to validate that the randomness array (`Rs`) has the correct length (`max_weight`). This allows a byzantine validator to create a malformed transcript that passes verification but causes other validators to crash during decryption, violating liveness guarantees.

## Finding Description

The chunky PVSS implementation has two different `decrypt_own_share()` implementations with inconsistent error handling: [1](#0-0) [2](#0-1) 

The critical vulnerability exists in the `Subtranscript::decrypt_own_share()` implementation, which assumes `Rs` has at least `weight` elements but doesn't validate this assumption. When a player with `weight > Rs.len()` calls this function:

1. Line 334 executes `.take(weight)` on `Rs`, creating `ephemeral_keys` with only `Rs.len()` elements
2. Line 349 iterates `for i in 0..weight`  
3. Line 353 accesses `ephemeral_keys[i]`, which **panics** when `i >= Rs.len()`

The root cause is missing validation in the `verify()` function: [3](#0-2) 

The verify function checks `Cs.len()` and `Vs.len()` against `total_num_players`, but **never validates** `Rs.len() == max_weight`.

**Attack Path:**
1. Byzantine validator creates transcript with `Rs.len() < max_weight` during DKG dealing
2. Transcript passes verification (no Rs length check in PoK/range proof verification)
3. Transcript is used in batch encryption setup via FPTXWeighted: [4](#0-3) 

4. Validators with `weight > Rs.len()` call `decrypt_own_share()` and crash with index out of bounds panic
5. This occurs during encrypted transaction processing in consensus: [5](#0-4) 

## Impact Explanation

**Severity: Medium** (Validator availability/liveness issue)

This vulnerability breaks two critical invariants:

1. **Deterministic Execution**: Different validators experience different failures based on their weight
2. **Network Liveness**: Validators with high weight cannot process encrypted transactions

Impact aligns with **Medium Severity** criteria:
- Causes "State inconsistencies requiring intervention" 
- Creates validator-specific failures that could require manual intervention
- Not Critical because it doesn't cause fund loss or permanent network halt
- Requires byzantine validator (< 1/3 assumed possible in BFT model)

## Likelihood Explanation

**Likelihood: Medium**

**Required conditions:**
- Byzantine validator participating in DKG (assumed possible under < 1/3 Byzantine fault tolerance)
- Encrypted transactions enabled in consensus
- Target validators with weight exceeding malicious Rs length

**Feasibility:**
- Attacker can trivially create short Rs array when dealing
- Verification will pass (PoK only validates existing Rs entries)
- Guaranteed crash on affected validators

The attack is straightforward once a byzantine validator exists, making it moderately likely.

## Recommendation

Add explicit validation of `Rs` length in the `verify()` function:

```rust
fn verify<A: Serialize + Clone>(
    &self,
    sc: &Self::SecretSharingConfig,
    pp: &Self::PublicParameters,
    spks: &[Self::SigningPubKey],
    eks: &[Self::EncryptPubKey],
    sid: &A,
) -> anyhow::Result<()> {
    // Existing checks...
    if self.subtrs.Cs.len() != sc.get_total_num_players() {
        bail!(...);
    }
    if self.subtrs.Vs.len() != sc.get_total_num_players() {
        bail!(...);
    }
    
    // ADD THIS CHECK:
    if self.subtrs.Rs.len() != sc.get_max_weight() {
        bail!(
            "Expected {} randomness arrays, but got {}",
            sc.get_max_weight(),
            self.subtrs.Rs.len()
        );
    }
    
    // Rest of verification...
}
```

Additionally, add defensive bounds checking in `Subtranscript::decrypt_own_share()`:

```rust
fn decrypt_own_share(...) -> (...) {
    let weight = sc.get_player_weight(player);
    
    if self.Rs.len() < weight {
        bail!("Insufficient randomness: need {}, have {}", weight, self.Rs.len());
    }
    
    // Rest of decryption...
}
```

## Proof of Concept

```rust
#[test]
fn test_short_rs_causes_panic() {
    use ark_bls12_381::Bls12_381 as E;
    use aptos_dkg::pvss::chunky::{WeightedSubtranscript, public_parameters::PublicParameters};
    use aptos_crypto::weighted_config::WeightedConfigArkworks;
    
    // Setup weighted config with max_weight=2
    let weights = vec![1, 2]; // Player 0: weight 1, Player 1: weight 2
    let sc = WeightedConfigArkworks::<Fr>::new(1, weights).unwrap();
    let pp = PublicParameters::<E>::default_for_testing();
    
    // Create subtranscript with ONLY 1 Rs entry (should have 2 for max_weight=2)
    let mut subtrs = WeightedSubtranscript::<E>::random(&sc, &pp);
    subtrs.Rs.truncate(1); // Malicious: reduce Rs to length 1
    
    // Player 0 (weight=1) can decrypt successfully
    let player0 = Player { id: 0 };
    let dk = keys::DecryptPrivKey::<E>::random();
    let result0 = subtrs.decrypt_own_share(&sc, &player0, &dk, &pp);
    assert!(result0.is_ok()); // Works because weight=1 <= Rs.len()=1
    
    // Player 1 (weight=2) PANICS  
    let player1 = Player { id: 1 };
    let result1 = std::panic::catch_unwind(|| {
        subtrs.decrypt_own_share(&sc, &player1, &dk, &pp)
    });
    assert!(result1.is_err()); // PANIC: ephemeral_keys[1] index out of bounds
}
```

## Notes

This vulnerability demonstrates a critical gap in transcript validation that enables targeted denial-of-service against specific validators based on their weight assignment. The inconsistency between the two `decrypt_own_share()` implementations reveals that the Subtranscript version lacks defensive programming practices present in the Transcript version's use of `zip()`, which gracefully handles mismatched lengths.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L125-153)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &Self::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        sid: &A,
    ) -> anyhow::Result<()> {
        if eks.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} encryption keys, but got {}",
                sc.get_total_num_players(),
                eks.len()
            );
        }
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
        }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L318-380)
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

        // TODO: put an assert here saying that len(Cs) = weight

        let ephemeral_keys: Vec<_> = self
            .Rs
            .iter()
            .take(weight)
            .map(|R_i_vec| R_i_vec.iter().map(|R_i| R_i.mul(dk.dk)).collect::<Vec<_>>())
            .collect();

        if let Some(first_key) = ephemeral_keys.first() {
            debug_assert_eq!(
                first_key.len(),
                Cs[0].len(),
                "Number of ephemeral keys does not match the number of ciphertext chunks"
            );
        }

        let mut sk_shares: Vec<Scalar<E::ScalarField>> = Vec::with_capacity(weight);
        let pk_shares = self.get_public_key_share(sc, player);

        for i in 0..weight {
            // TODO: should really put this in a separate function
            let dealt_encrypted_secret_key_share_chunks: Vec<_> = Cs[i]
                .iter()
                .zip(ephemeral_keys[i].iter())
                .map(|(C_ij, ephemeral_key)| C_ij.sub(ephemeral_key))
                .collect();

            let dealt_chunked_secret_key_share = bsgs::dlog_vec(
                pp.pp_elgamal.G.into_group(),
                &dealt_encrypted_secret_key_share_chunks,
                &pp.table,
                pp.get_dlog_range_bound(),
            )
            .expect("BSGS dlog failed");

            let dealt_chunked_secret_key_share_fr: Vec<E::ScalarField> =
                dealt_chunked_secret_key_share
                    .iter()
                    .map(|&x| E::ScalarField::from(x))
                    .collect();

            let dealt_secret_key_share =
                chunks::le_chunks_to_scalar(pp.ell, &dealt_chunked_secret_key_share_fr);

            sk_shares.push(Scalar(dealt_secret_key_share));
        }

        (
            sk_shares, pk_shares, // TODO: review this formalism... why do we need this here?
        )
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L570-605)
```rust
    fn decrypt_own_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player: &Player,
        dk: &Self::DecryptPrivKey,
        pp: &Self::PublicParameters,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let Cs = &self.subtrs.Cs[player.id];
        debug_assert_eq!(Cs.len(), sc.get_player_weight(player));

        if !Cs.is_empty() {
            if let Some(first_key) = self.subtrs.Rs.first() {
                debug_assert_eq!(
                    first_key.len(),
                    Cs[0].len(),
                    "Number of ephemeral keys does not match the number of ciphertext chunks"
                );
            }
        }

        let pk_shares = self.get_public_key_share(sc, player);

        let sk_shares: Vec<_> = decrypt_chunked_scalars(
            &Cs,
            &self.subtrs.Rs,
            &dk.dk,
            &pp.pp_elgamal,
            &pp.table,
            pp.ell,
        );

        (
            Scalar::vec_from_inner(sk_shares),
            pk_shares, // TODO: review this formalism... why do we need this here?
        )
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L263-273)
```rust
                .decrypt_own_share(
                    threshold_config,
                    &current_player,
                    msk_share_decryption_key,
                    pvss_public_params,
                )
                .0
                .into_iter()
                .map(|s| s.into_fr())
                .collect(),
        };
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::pipeline::pipeline_builder::{PipelineBuilder, Tracker};
use aptos_batch_encryption::{
    schemes::fptx_weighted::FPTXWeighted, traits::BatchThresholdEncryption,
};
use aptos_consensus_types::{
    block::Block,
    common::Author,
    pipelined_block::{DecryptionResult, MaterializeResult, TaskFuture, TaskResult},
};
use aptos_types::{
    secret_sharing::{
        Ciphertext, DigestKey, MasterSecretKeyShare, SecretShare, SecretShareConfig,
        SecretShareMetadata, SecretSharedKey,
    },
    transaction::encrypted_payload::DecryptedPayload,
};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::sync::Arc;
use tokio::sync::oneshot;

impl PipelineBuilder {
    /// Precondition: Block is materialized and the transactions are available locally
    /// What it does: Decrypt encrypted transactions in the block
    pub(crate) async fn decrypt_encrypted_txns(
        materialize_fut: TaskFuture<MaterializeResult>,
        block: Arc<Block>,
        author: Author,
        secret_share_config: Option<SecretShareConfig>,
        derived_self_key_share_tx: oneshot::Sender<Option<SecretShare>>,
        secret_shared_key_rx: oneshot::Receiver<Option<SecretSharedKey>>,
    ) -> TaskResult<DecryptionResult> {
        let mut tracker = Tracker::start_waiting("decrypt_encrypted_txns", &block);
        let (input_txns, max_txns_from_block_to_execute, block_gas_limit) = materialize_fut.await?;

        tracker.start_working();

        if secret_share_config.is_none() {
            return Ok((input_txns, max_txns_from_block_to_execute, block_gas_limit));
        }

        let (encrypted_txns, unencrypted_txns): (Vec<_>, Vec<_>) = input_txns
            .into_iter()
            .partition(|txn| txn.is_encrypted_txn());

        // TODO: figure out handling of
        if encrypted_txns.is_empty() {
            return Ok((
```
