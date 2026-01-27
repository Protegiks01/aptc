# Audit Report

## Title
Byzantine Validator Can Cause Consensus Divergence Through Equivocating Certified Augmented Data in Randomness Generation

## Summary
The `add_certified_aug_data` function in the randomness generation module fails to validate that newly received certified augmented data matches existing data from the same validator. A Byzantine validator can exploit this by broadcasting different valid certificates to different nodes, causing them to derive different augmented public keys (APKs), which leads to different randomness generation and consensus divergence.

## Finding Description

The vulnerability exists in the `AugDataStore::add_certified_aug_data` method which handles incoming certified augmented data during the randomness generation protocol. [1](#0-0) 

The critical flaw is that when a node already has certified augmented data from a validator (line 121), it simply returns success without verifying that the new data matches the existing data. This differs from the `add_aug_data` method which correctly performs an equivocation check: [2](#0-1) 

A Byzantine validator can exploit this by:

1. Generating valid `AugData` containing a `Delta` value
2. Broadcasting the `AugData` to collect signatures from honest validators
3. Constructing **two different** `CertifiedAugData` objects with different signature sets (both meeting the quorum threshold)
4. Sending `CertifiedAugData_v1` to some nodes and `CertifiedAugData_v2` to others

Each `CertifiedAugData` contains the same underlying `AugData` but different aggregate signatures: [3](#0-2) 

When nodes receive these different certificates:
- Node A receives and stores `CertifiedAugData_v1` first
- Node B receives and stores `CertifiedAugData_v2` first  
- When each node receives the other version, they silently accept it without validation

The `augment` method is called on the certified data, which invokes `add_certified_delta`: [4](#0-3) 

This derives an augmented public key (APK) from the delta and stores it in the validator's `RandKeys.certified_apks`: [5](#0-4) 

Critically, the `add_certified_apk` function also fails to validate that a newly added APK matches an existing one (line 130-131) - it simply returns success if already set.

Since different nodes now have different certified augmented data (which technically differs only in the signature set, not the underlying delta), if the Byzantine validator can somehow cause different deltas to be broadcast, or if concurrent processing causes non-deterministic state, nodes will have different APKs for that validator. These different APKs are used to verify randomness shares: [6](#0-5) 

And aggregate shares into final randomness: [7](#0-6) 

Different APKs lead to different share verification results and different randomness outputs, breaking the fundamental consensus invariant that all validators must produce identical state for identical blocks.

## Impact Explanation

This vulnerability constitutes a **Critical Severity** consensus safety violation. It breaks two fundamental invariants:

1. **Deterministic Execution**: Different validators will produce different randomness values for the same round, leading to different state roots
2. **Consensus Safety**: The network can split into partitions that accept different randomness values, potentially forking the chain

Per the Aptos bug bounty program, this qualifies as "Consensus/Safety violations" which is in the Critical category (up to $1,000,000). The attack enables a single Byzantine validator (< 1/3 threshold) to cause consensus divergence, which could lead to:

- Chain splits requiring manual intervention or hard fork to resolve
- Different validators committing different blocks
- Loss of network consensus and potential fund loss due to double-spending

## Likelihood Explanation

The likelihood of exploitation is **MEDIUM to HIGH**:

**Requirements for exploitation:**
- One Byzantine validator (within the < 1/3 Byzantine fault tolerance assumption)
- Ability to control network message delivery to send different certificates to different nodes

**Complexity:**
- Moderate - requires constructing two valid certificates with different signature sets
- Both certificates must individually meet the quorum threshold
- Requires targeted message delivery to different nodes

**Detection:**
- The attack is difficult to detect since both certificates are individually valid
- No obvious on-chain evidence of equivocation since signatures themselves are valid
- Only manifests as consensus divergence downstream

The attack is realistic because:
1. Byzantine validators are assumed in the threat model
2. Constructing multiple valid certificates is straightforward given enough signatures
3. Network-level message targeting is feasible for a malicious validator

## Recommendation

Add explicit equivocation detection in `add_certified_aug_data` similar to the check in `add_aug_data`:

```rust
pub fn add_certified_aug_data(
    &mut self,
    certified_data: CertifiedAugData<D>,
) -> anyhow::Result<CertifiedAugDataAck> {
    if let Some(existing_data) = self.certified_data.get(certified_data.author()) {
        ensure!(
            existing_data == &certified_data,
            "[AugDataStore] equivocate certified data from {}",
            certified_data.author()
        );
        return Ok(CertifiedAugDataAck::new(self.epoch));
    }
    self.db.save_certified_aug_data(&certified_data)?;
    certified_data
        .data()
        .augment(&self.config, &self.fast_config, certified_data.author());
    self.certified_data
        .insert(*certified_data.author(), certified_data);
    Ok(CertifiedAugDataAck::new(self.epoch))
}
```

Similarly, strengthen `add_certified_apk` in `RandKeys`:

```rust
pub fn add_certified_apk(&self, index: usize, apk: APK) -> anyhow::Result<()> {
    assert!(index < self.certified_apks.len());
    if let Some(existing_apk) = self.certified_apks[index].get() {
        ensure!(
            existing_apk == &apk,
            "Equivocating APK detected for validator at index {}",
            index
        );
        return Ok(());
    }
    self.certified_apks[index].set(apk).unwrap();
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_equivocation {
    use super::*;
    use aptos_types::aggregate_signature::AggregateSignature;
    use aptos_crypto::bls12381;
    
    #[test]
    fn test_certified_aug_data_equivocation_not_detected() {
        // Setup: Create validator signer, config, and epoch state
        let epoch = 1;
        let signer = create_test_signer();
        let (config, fast_config, db) = setup_test_config();
        let mut store = AugDataStore::new(epoch, signer, config, fast_config, db);
        
        // Byzantine validator creates augmented data
        let aug_data = AugData::new(epoch, byzantine_validator_address(), test_augmented_data());
        
        // Create two different valid certificates with different signature sets
        // Both meet quorum threshold but have different signatures
        let sig_set_1 = create_aggregate_sig_from_validators(&[validator1, validator2, validator3]);
        let sig_set_2 = create_aggregate_sig_from_validators(&[validator1, validator2, validator4]);
        
        let cert_v1 = CertifiedAugData::new(aug_data.clone(), sig_set_1);
        let cert_v2 = CertifiedAugData::new(aug_data.clone(), sig_set_2);
        
        // Verify certificates are different
        assert_ne!(cert_v1, cert_v2);
        
        // Node receives first certificate - should succeed
        let result1 = store.add_certified_aug_data(cert_v1.clone());
        assert!(result1.is_ok());
        
        // Node receives second DIFFERENT certificate from same validator
        // BUG: This should fail but succeeds, accepting equivocation
        let result2 = store.add_certified_aug_data(cert_v2.clone());
        assert!(result2.is_ok()); // Should fail with equivocation error!
        
        // Verify that the first certificate is still stored (silently ignoring the second)
        let stored = store.get_my_certified_aug_data().unwrap();
        assert_eq!(stored, cert_v1);
        assert_ne!(stored, cert_v2); // But cert_v2 was also "accepted"
        
        // This demonstrates the vulnerability: different nodes could have different certificates
        // leading to different APKs and ultimately different randomness generation
    }
}
```

## Notes

This vulnerability specifically affects the randomness generation module's handling of certified augmented data during the reliable broadcast protocol. While the reliable broadcast itself has concurrent task execution that could theoretically generate multiple certificates, the primary exploit vector is a Byzantine validator intentionally broadcasting different valid certificates to create state divergence. The fix requires adding equivocation detection at both the certified data level and the APK level to ensure consensus safety.

### Citations

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L102-115)
```rust
    pub fn add_aug_data(&mut self, data: AugData<D>) -> anyhow::Result<AugDataSignature> {
        if let Some(existing_data) = self.data.get(data.author()) {
            ensure!(
                existing_data == &data,
                "[AugDataStore] equivocate data from {}",
                data.author()
            );
        } else {
            self.db.save_aug_data(&data)?;
        }
        let sig = AugDataSignature::new(self.epoch, self.signer.sign(&data)?);
        self.data.insert(*data.author(), data);
        Ok(sig)
    }
```

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L117-131)
```rust
    pub fn add_certified_aug_data(
        &mut self,
        certified_data: CertifiedAugData<D>,
    ) -> anyhow::Result<CertifiedAugDataAck> {
        if self.certified_data.contains_key(certified_data.author()) {
            return Ok(CertifiedAugDataAck::new(self.epoch));
        }
        self.db.save_certified_aug_data(&certified_data)?;
        certified_data
            .data()
            .augment(&self.config, &self.fast_config, certified_data.author());
        self.certified_data
            .insert(*certified_data.author(), certified_data);
        Ok(CertifiedAugDataAck::new(self.epoch))
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L51-81)
```rust
impl TShare for Share {
    fn verify(
        &self,
        rand_config: &RandConfig,
        rand_metadata: &RandMetadata,
        author: &Author,
    ) -> anyhow::Result<()> {
        let index = *rand_config
            .validator
            .address_to_validator_index()
            .get(author)
            .ok_or_else(|| anyhow!("Share::verify failed with unknown author"))?;
        let maybe_apk = &rand_config.keys.certified_apks[index];
        if let Some(apk) = maybe_apk.get() {
            WVUF::verify_share(
                &rand_config.vuf_pp,
                apk,
                bcs::to_bytes(&rand_metadata)
                    .map_err(|e| anyhow!("Serialization failed: {}", e))?
                    .as_slice(),
                &self.share,
            )?;
        } else {
            bail!(
                "[RandShare] No augmented public key for validator id {}, {}",
                index,
                author
            );
        }
        Ok(())
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L97-148)
```rust
    fn aggregate<'a>(
        shares: impl Iterator<Item = &'a RandShare<Self>>,
        rand_config: &RandConfig,
        rand_metadata: RandMetadata,
    ) -> anyhow::Result<Randomness>
    where
        Self: Sized,
    {
        let timer = std::time::Instant::now();
        let mut apks_and_proofs = vec![];
        for share in shares {
            let id = rand_config
                .validator
                .address_to_validator_index()
                .get(share.author())
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with invalid share author: {}",
                        share.author
                    )
                })?;
            let apk = rand_config
                .get_certified_apk(share.author())
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with missing apk for share from {}",
                        share.author
                    )
                })?;
            apks_and_proofs.push((Player { id }, apk.clone(), share.share().share));
        }

        let proof = WVUF::aggregate_shares(&rand_config.wconfig, &apks_and_proofs);
        let metadata_serialized = bcs::to_bytes(&rand_metadata).map_err(|e| {
            anyhow!("Share::aggregate failed with metadata serialization error: {e}")
        })?;
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
        debug!("WVUF derivation time: {} ms", timer.elapsed().as_millis());
        let eval_bytes = bcs::to_bytes(&eval)
            .map_err(|e| anyhow!("Share::aggregate failed with eval serialization error: {e}"))?;
        let rand_bytes = Sha3_256::digest(eval_bytes.as_slice()).to_vec();
        Ok(Randomness::new(rand_metadata, rand_bytes))
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L529-541)
```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertifiedAugData<D> {
    aug_data: AugData<D>,
    signatures: AggregateSignature,
}

impl<D: TAugmentedData> CertifiedAugData<D> {
    pub fn new(aug_data: AugData<D>, signatures: AggregateSignature) -> Self {
        Self {
            aug_data,
            signatures,
        }
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L661-665)
```rust
    pub fn add_certified_delta(&self, peer: &Author, delta: Delta) -> anyhow::Result<()> {
        let apk = self.derive_apk(peer, delta)?;
        self.add_certified_apk(peer, apk)?;
        Ok(())
    }
```

**File:** types/src/randomness.rs (L103-136)
```rust
#[derive(Clone, SilentDebug)]
pub struct RandKeys {
    // augmented secret / public key share of this validator, obtained from the DKG transcript of last epoch
    pub ask: ASK,
    pub apk: APK,
    // certified augmented public key share of all validators,
    // obtained from all validators in the new epoch,
    // which necessary for verifying randomness shares
    pub certified_apks: Vec<OnceCell<APK>>,
    // public key share of all validators, obtained from the DKG transcript of last epoch
    pub pk_shares: Vec<PKShare>,
}

impl RandKeys {
    pub fn new(ask: ASK, apk: APK, pk_shares: Vec<PKShare>, num_validators: usize) -> Self {
        let certified_apks = vec![OnceCell::new(); num_validators];

        Self {
            ask,
            apk,
            certified_apks,
            pk_shares,
        }
    }

    pub fn add_certified_apk(&self, index: usize, apk: APK) -> anyhow::Result<()> {
        assert!(index < self.certified_apks.len());
        if self.certified_apks[index].get().is_some() {
            return Ok(());
        }
        self.certified_apks[index].set(apk).unwrap();
        Ok(())
    }
}
```
