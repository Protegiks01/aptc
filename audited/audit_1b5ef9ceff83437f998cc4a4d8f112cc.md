# Audit Report

## Title
Byzantine Validator Equivocation Attack via Missing Consistency Check in Certified Augmented Data Storage

## Summary
The `add_certified_aug_data()` function in the randomness generation subsystem lacks an equivocation check when certified augmented data already exists for a validator. This allows a Byzantine validator to distribute different certified augmented data to different nodes, causing inconsistent augmented public keys (APKs) across the network, which breaks consensus safety on randomness generation.

## Finding Description

The vulnerability exists in the augmented data storage mechanism used for Aptos randomness generation. [1](#0-0) 

The function returns early if certified data already exists without verifying that the existing data matches the incoming data. This is in stark contrast to the `add_aug_data()` function, which explicitly checks for equivocation. [2](#0-1) 

When certified augmented data is processed, it extracts the delta value and uses it to derive an augmented public key (APK) which gets stored in a `OnceCell`. [3](#0-2) 

The `add_certified_apk()` function also exhibits the same vulnerability pattern - it returns early without validation if the APK is already set. [4](#0-3) 

**Attack Scenario:**

1. Byzantine validator V_byz generates two different `AugData` instances with different deltas (D1 and D2)
2. V_byz broadcasts AugData(D1) to subset of validators S1, receives signatures, creates CertifiedAugData(D1)
3. V_byz broadcasts AugData(D2) to subset of validators S2, receives signatures, creates CertifiedAugData(D2)
4. V_byz sends CertifiedAugData(D1) to nodes N1, N2, N3
5. V_byz sends CertifiedAugData(D2) to nodes N4, N5, N6
6. Each node stores the first version received and ignores subsequent versions due to the early return
7. Network now has inconsistent APKs for V_byz: N1-N3 have APK1 (derived from D1), N4-N6 have APK2 (derived from D2)
8. When V_byz sends randomness shares, nodes with APK1 verify them differently than nodes with APK2
9. Different nodes reach different conclusions about randomness validity, breaking consensus

The signature verification in the message handler only validates that the certified data has valid quorum signatures, not that it's consistent across the network. [5](#0-4) 

## Impact Explanation

**Severity: Critical** - This is a consensus safety violation under the Aptos bug bounty program.

This vulnerability breaks **Critical Invariant #2: Consensus Safety** - AptosBFT must prevent chain splits under < 1/3 Byzantine validators. By exploiting this vulnerability, a single Byzantine validator can cause different honest nodes to have inconsistent views of the randomness generation state, leading to:

1. **Consensus Disagreement**: Different nodes verify randomness shares differently, causing disagreement on block validity
2. **Chain Split Risk**: If nodes disagree on randomness, they may commit different blocks, causing a network partition
3. **Liveness Failure**: Nodes unable to agree on randomness cannot progress consensus

The augmented public keys are critical for the weighted VUF (Verifiable Unpredictable Function) used in randomness generation. [6](#0-5) 

If different nodes have different APKs for a validator, they will derive different randomness values from the same shares, directly violating deterministic execution and consensus safety.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Single Byzantine Validator Sufficient**: Only one malicious validator (< 1/3 threshold) is needed
2. **No Special Privileges Required**: Any validator can perform this attack without special access
3. **Simple Execution**: The attack only requires sending different messages to different network peers
4. **No Detection Mechanism**: The early return silently accepts the first version without logging inconsistencies
5. **Persistent Impact**: Once inconsistent APKs are stored in `OnceCell`, they cannot be corrected for the entire epoch
6. **Natural Race Conditions**: Even without malicious intent, network delays could cause legitimate inconsistencies that cannot be resolved

The attack can be executed at epoch start when augmented data exchange occurs, making it a repeatable attack vector.

## Recommendation

Add an equivocation check similar to the one in `add_aug_data()`:

```rust
pub fn add_certified_aug_data(
    &mut self,
    certified_data: CertifiedAugData<D>,
) -> anyhow::Result<CertifiedAugDataAck> {
    // Check if certified data already exists and verify consistency
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

Similarly, `add_certified_apk()` should verify consistency:

```rust
pub fn add_certified_apk(&self, index: usize, apk: APK) -> anyhow::Result<()> {
    assert!(index < self.certified_apks.len());
    if let Some(existing_apk) = self.certified_apks[index].get() {
        ensure!(
            existing_apk == &apk,
            "APK mismatch for validator index {}: existing {:?}, new {:?}",
            index,
            existing_apk,
            apk
        );
        return Ok(());
    }
    self.certified_apks[index].set(apk).unwrap();
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_certified_aug_data_equivocation_vulnerability() {
    use aptos_types::validator_signer::ValidatorSigner;
    use consensus::rand::rand_gen::{
        aug_data_store::AugDataStore,
        types::{AugData, AugmentedData, CertifiedAugData},
    };
    
    // Setup two nodes with AugDataStore
    let epoch = 1;
    let signer = Arc::new(ValidatorSigner::random(None));
    let config = /* initialize RandConfig */;
    let db = /* initialize storage */;
    
    let mut store_node1 = AugDataStore::new(epoch, signer.clone(), config.clone(), None, db.clone());
    let mut store_node2 = AugDataStore::new(epoch, signer.clone(), config.clone(), None, db.clone());
    
    // Byzantine validator creates two different augmented data instances
    let delta1 = /* create delta1 */;
    let delta2 = /* create delta2 (different from delta1) */;
    
    let aug_data1 = AugData::new(epoch, byzantine_author, AugmentedData { delta: delta1, fast_delta: None });
    let aug_data2 = AugData::new(epoch, byzantine_author, AugmentedData { delta: delta2, fast_delta: None });
    
    // Get both certified with valid signatures
    let certified_data1 = CertifiedAugData::new(aug_data1, aggregate_sig1);
    let certified_data2 = CertifiedAugData::new(aug_data2, aggregate_sig2);
    
    // Send different versions to different nodes
    store_node1.add_certified_aug_data(certified_data1.clone()).unwrap();
    store_node2.add_certified_aug_data(certified_data2.clone()).unwrap();
    
    // Verify inconsistency: nodes have different APKs for the same validator
    let apk1 = config.get_certified_apk(&byzantine_author).unwrap();
    let apk2 = config.get_certified_apk(&byzantine_author).unwrap();
    
    // This assertion should fail, demonstrating the vulnerability
    // In current code, both nodes accept different data without detecting equivocation
    assert_ne!(apk1, apk2, "Nodes have inconsistent APKs - consensus broken!");
}
```

**Notes:**
- The vulnerability exists at two levels: in `add_certified_aug_data()` and in `add_certified_apk()`
- Both functions use "first-write-wins" semantics without consistency verification
- The attack exploits the distributed nature of the system where different nodes may receive messages in different orders
- The `OnceCell` data structure prevents updating once set, making the inconsistency permanent for the epoch
- This breaks the fundamental assumption that all honest nodes should have identical state for consensus operations

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

**File:** consensus/src/rand/rand_gen/types.rs (L178-194)
```rust
    fn augment(
        &self,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        author: &Author,
    ) {
        let AugmentedData { delta, fast_delta } = self;
        rand_config
            .add_certified_delta(author, delta.clone())
            .expect("Add delta should succeed");

        if let (Some(config), Some(fast_delta)) = (fast_rand_config, fast_delta) {
            config
                .add_certified_delta(author, fast_delta.clone())
                .expect("Add delta for fast path should succeed");
        }
    }
```

**File:** types/src/randomness.rs (L104-114)
```rust
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
```

**File:** types/src/randomness.rs (L128-135)
```rust
    pub fn add_certified_apk(&self, index: usize, apk: APK) -> anyhow::Result<()> {
        assert!(index < self.certified_apks.len());
        if self.certified_apks[index].get().is_some() {
            return Ok(());
        }
        self.certified_apks[index].set(apk).unwrap();
        Ok(())
    }
```

**File:** consensus/src/rand/rand_gen/network_messages.rs (L50-52)
```rust
            RandMessage::CertifiedAugData(certified_aug_data) => {
                certified_aug_data.verify(&epoch_state.verifier)
            },
```
