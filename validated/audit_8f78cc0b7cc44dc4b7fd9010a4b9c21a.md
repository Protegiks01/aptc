# Audit Report

## Title
Player ID Validation Bypass in FPTXWeighted Decryption Key Share Verification Enables Reconstruction Denial of Service

## Summary
The `verify_decryption_key_share()` function in the FPTXWeighted batch encryption scheme fails to validate that the player ID embedded in decryption key shares matches the expected validator identity. While verification checks cryptographic validity using BLS signatures, it completely ignores the player ID field that is later used for Shamir secret sharing reconstruction. This allows a malicious validator to submit cryptographically valid shares with incorrect player IDs, causing decryption key reconstruction to fail and disrupting the secret sharing protocol.

## Finding Description

The vulnerability exists in the decryption key share verification flow implemented in the consensus secret sharing system.

When `SecretShare::verify()` is called, it uses the `author` field to look up the verification key by index [1](#0-0) , then calls `verify_decryption_key_share()` on that verification key.

However, the `WeightedBIBEVerificationKey::verify_decryption_key_share()` implementation ignores the player ID from the incoming share. It explicitly replaces the share's player ID with `self.weighted_player` during verification [2](#0-1) . The verification key's own `weighted_player` is used instead of the player ID embedded in `dk_share.0`, meaning **the player ID in the submitted share is never validated against the expected validator identity**.

During reconstruction, the player ID from the share is critical. The weighted reconstruction implementation uses the player ID from each share to compute virtual players and Lagrange coefficients [3](#0-2) . The reconstruction iterates over shares using the player ID from each share tuple and calls `get_virtual_player()` using that player ID, which is then used in Lagrange interpolation to reconstruct the decryption key.

**Attack Path:**
1. A malicious validator modifies the `weighted_player` field in their `WeightedBIBEMasterSecretKeyShare` to an arbitrary value (the struct has public fields [4](#0-3) )
2. They derive a decryption key share using `derive_decryption_key_share()`, which creates a share containing the malicious player ID [5](#0-4) 
3. They submit a `SecretShare` with their correct `author` address but the malicious player ID embedded in the share [6](#0-5) 
4. Verification passes because it only checks BLS signature validity using the verification key indexed by author, and replaces the player ID during verification
5. The malicious share is added to the `SecretShareStore` after verification [7](#0-6) 
6. When `SecretShare::aggregate()` is called for reconstruction [8](#0-7) , the malicious player ID is used to compute incorrect virtual players
7. This produces wrong Lagrange coefficients, causing decryption key reconstruction to fail or produce an incorrect key

This breaks the **Liveness** guarantee, as validators cannot decrypt and process batched transactions, potentially halting block execution for rounds where the malicious share is included.

## Impact Explanation

**Severity: High** (Significant Protocol Disruption)

This vulnerability enables a single malicious validator to cause denial of service in the secret sharing protocol:

- **Liveness Impact**: Prevents validators from successfully reconstructing decryption keys needed to process encrypted transactions, potentially halting consensus progress for affected rounds
- **Non-Deterministic Behavior**: Different validators may get different reconstruction results depending on which shares they use, leading to consensus divergence
- **Beyond Standard BFT Tolerance**: While BFT consensus tolerates up to 1/3 Byzantine validators, this vulnerability allows a single malicious validator to disrupt decryption if their share is included in the threshold set used for reconstruction

The impact is High rather than Critical because:
- It does not directly cause permanent fund loss
- It does not create an unrecoverable network partition  
- Recovery may be possible by retrying with different share combinations excluding the malicious validator
- The impact is limited to rounds where encrypted transactions are present and the malicious share is selected

However, it represents a significant protocol violation as it allows a single Byzantine validator to cause consensus disruption beyond what the BFT security model should tolerate.

## Likelihood Explanation

**Likelihood: Medium-to-High**

- **Attacker Requirements**: Requires validator access, which is within the BFT threat model (up to 1/3 Byzantine validators are assumed)
- **Complexity**: Low - attacker only needs to modify the `weighted_player` field in their master secret key share before deriving decryption key shares
- **Detection**: Difficult - the malicious share passes all cryptographic verification checks and appears valid
- **Exploitation Trigger**: Occurs whenever the malicious share is included in the threshold set during reconstruction, which happens probabilistically when validators collect shares

The likelihood is elevated because:
1. The aggregation takes the first threshold number of shares collected, and a malicious validator can ensure their share is among the early ones
2. There is no validation or filtering mechanism to detect and exclude shares with incorrect player IDs
3. The vulnerability is silent until reconstruction fails, making it difficult to diagnose
4. A TODO comment indicates awareness of validation gaps [9](#0-8) 

## Recommendation

Add validation in `WeightedBIBEVerificationKey::verify_decryption_key_share()` to ensure the player ID in the incoming share matches the expected player ID:

```rust
pub fn verify_decryption_key_share(
    &self,
    digest: &Digest,
    dk_share: &WeightedBIBEDecryptionKeyShare,
) -> Result<()> {
    // Validate player ID matches expected value
    if dk_share.0 != self.weighted_player {
        return Err(BatchEncryptionError::PlayerIDMismatchError.into());
    }
    
    (self.vks_g2.len() == dk_share.1.len())
        .then_some(())
        .ok_or(BatchEncryptionError::DecryptionKeyVerifyError)?;
    // ... rest of verification
}
```

Alternatively, modify the reconstruction flow to use the author field to determine the player ID instead of trusting the player ID embedded in the share.

## Proof of Concept

The attack can be demonstrated by:
1. Setting up a weighted threshold encryption scheme with multiple validators
2. Modifying a validator's `WeightedBIBEMasterSecretKeyShare.weighted_player` field to an incorrect value
3. Deriving a decryption key share from the modified master secret key share
4. Submitting the share through the normal consensus flow
5. Observing that verification passes but reconstruction fails when the threshold is met

The vulnerability is confirmed by code inspection showing that player ID validation is missing between the verification and reconstruction phases.

### Citations

**File:** types/src/secret_sharing.rs (L75-82)
```rust
    pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
        let index = config.get_id(self.author());
        let decryption_key_share = self.share().clone();
        // TODO(ibalajiarun): Check index out of bounds
        config.verification_keys[index]
            .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
        Ok(())
    }
```

**File:** types/src/secret_sharing.rs (L84-99)
```rust
    pub fn aggregate<'a>(
        dec_shares: impl Iterator<Item = &'a SecretShare>,
        config: &SecretShareConfig,
    ) -> anyhow::Result<DecryptionKey> {
        let threshold = config.threshold();
        let shares: Vec<SecretKeyShare> = dec_shares
            .map(|dec_share| dec_share.share.clone())
            .take(threshold as usize)
            .collect();
        let decryption_key =
            <FPTXWeighted as BatchThresholdEncryption>::reconstruct_decryption_key(
                &shares,
                &config.config,
            )?;
        Ok(decryption_key)
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L46-53)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeightedBIBEMasterSecretKeyShare {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) mpk_g2: G2Affine,
    pub(crate) weighted_player: Player,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) shamir_share_evals: Vec<Fr>,
}
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L85-113)
```rust
    pub fn derive_decryption_key_share(
        &self,
        digest: &Digest,
    ) -> Result<WeightedBIBEDecryptionKeyShare> {
        let evals_raw: Vec<G1Affine> = self
            .shamir_share_evals
            .iter()
            .map(|eval| {
                Ok(BIBEMasterSecretKeyShare {
                    mpk_g2: self.mpk_g2,
                    player: self.weighted_player, // arbitrary
                    shamir_share_eval: *eval,
                }
                .derive_decryption_key_share(digest)?
                .1
                .signature_share_eval)
            })
            .collect::<Result<Vec<G1Affine>>>()?;

        Ok((
            self.weighted_player,
            evals_raw
                .into_iter()
                .map(|eval| BIBEDecryptionKeyShareValue {
                    signature_share_eval: eval,
                })
                .collect(),
        ))
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L149-169)
```rust
    pub fn verify_decryption_key_share(
        &self,
        digest: &Digest,
        dk_share: &WeightedBIBEDecryptionKeyShare,
    ) -> Result<()> {
        (self.vks_g2.len() == dk_share.1.len())
            .then_some(())
            .ok_or(BatchEncryptionError::DecryptionKeyVerifyError)?;

        self.vks_g2
            .iter()
            .map(|vk_g2| BIBEVerificationKey {
                mpk_g2: self.mpk_g2,
                vk_g2: *vk_g2,
                player: self.weighted_player, // arbitrary
            })
            .zip(&dk_share.1)
            .try_for_each(|(vk, dk_share)| {
                vk.verify_decryption_key_share(digest, &(self.weighted_player, dk_share.clone()))
            })
    }
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L423-450)
```rust
    fn reconstruct(
        sc: &WeightedConfigArkworks<F>,
        shares: &[ShamirShare<Self::ShareValue>],
    ) -> anyhow::Result<Self> {
        let mut flattened_shares = Vec::with_capacity(sc.get_total_weight());

        // println!();
        for (player, sub_shares) in shares {
            // println!(
            //     "Flattening {} share(s) for player {player}",
            //     sub_shares.len()
            // );
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
        }
        flattened_shares.truncate(sc.get_threshold_weight());

        SK::reconstruct(sc.get_threshold_config(), &flattened_shares)
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L103-109)
```rust
        let derived_key_share = FPTXWeighted::derive_decryption_key_share(&msk_share, &digest)?;
        derived_self_key_share_tx
            .send(Some(SecretShare::new(
                author,
                metadata.clone(),
                derived_key_share,
            )))
```

**File:** consensus/src/rand/secret_sharing/reliable_broadcast_state.rs (L44-59)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.secret_share_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.secret_share_metadata,
            share.metadata()
        );
        share.verify(&self.secret_share_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveSecretShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.secret_share_store.lock();
        let aggregated = store.add_share(share)?.then_some(());
        Ok(aggregated)
```
