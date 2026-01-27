# Audit Report

## Title
Permanent RandConfig Corruption via Unchecked Delta Validation in Certified Augmented Data

## Summary
The `add_certified_aug_data()` function in `aug_data_store.rs` contains a critical vulnerability where it returns early if certified data already exists for an author, preventing re-augmentation. Combined with insufficient content verification of `CertifiedAugData` messages and lack of delta correctness validation in `AugmentedData::verify()`, Byzantine validators can permanently corrupt the `RandConfig` by injecting incorrect delta values that pass cryptographic validation but are not the legitimate deltas for their validator identity. This corrupts the consensus randomness generation process.

## Finding Description

The vulnerability exists across multiple components:

**1. Insufficient Delta Verification:** [1](#0-0) 

The `AugmentedData::verify()` function only checks if a provided delta can derive *some* valid APK via `derive_apk()`, but does not verify that the delta matches the validator's legitimate delta obtained from `get_my_delta()`. A Byzantine validator can provide any cryptographically valid delta (not their actual one), and it will pass this verification check.

**2. Missing Content Verification for CertifiedAugData:** [2](#0-1) [3](#0-2) 

When `CertifiedAugData` messages are received, only the signatures are verified via `verify_multi_signatures()`. The actual content (the delta values) is not re-verified against cryptographic constraints. This differs from `AugData` messages where content verification occurs before signing.

**3. Permanent Write via Early Return:** [4](#0-3) 

The `add_certified_aug_data()` function returns early if data for an author already exists, preventing any correction. The `augment()` call only happens on first write, permanently modifying the `RandConfig` with potentially incorrect certified APKs.

**4. Immutable Storage in OnceCell:** [5](#0-4) 

The `add_certified_apk()` function stores APKs in `OnceCell` structures and returns early if already set, making the corruption permanent at the storage level.

**Attack Path:**

1. Byzantine validator generates `AugData` with an incorrect but cryptographically valid delta (not from `get_my_delta()`)
2. The delta passes `AugmentedData::verify()` because it can derive *a* valid APK (though not the correct one)
3. Honest validators verify and sign this data during the initial reliable broadcast phase
4. Byzantine validator collects 2f+1 signatures and creates `CertifiedAugData`
5. Byzantine validator broadcasts `CertifiedAugData` to all nodes
6. Receiving nodes only verify signatures (not content) and call `add_certified_aug_data()`
7. `augment()` is called, which invokes `add_certified_delta()` with the incorrect delta [6](#0-5) 
8. This derives a wrong APK and stores it permanently in `RandConfig.certified_apks`
9. Due to early returns in both `add_certified_aug_data()` and `add_certified_apk()`, this corruption cannot be corrected
10. All subsequent randomness share verifications use the wrong certified APK, corrupting consensus randomness [7](#0-6) 

## Impact Explanation

**Severity: Critical**

This vulnerability meets the Critical severity criteria per the Aptos bug bounty program:

1. **Consensus Safety Violation**: The corrupted certified APKs cause randomness share verification failures or incorrect randomness derivation, breaking the deterministic consensus requirement that all validators must agree on the same randomness for each round.

2. **Permanent Network Impact**: Once the wrong certified APKs are stored via `OnceCell`, they cannot be corrected without restarting nodes or performing a hard fork. This represents a "non-recoverable network partition" requiring manual intervention.

3. **Byzantine Fault Tolerance Compromise**: The attack succeeds with even a single Byzantine validator (< 1/3 threshold), as they can broadcast their own incorrect data and get it certified. This breaks the < 1/3 Byzantine tolerance invariant.

4. **Randomness Corruption**: Since randomness is used for leader selection and other consensus mechanisms, corrupted randomness directly impacts consensus safety and liveness.

## Likelihood Explanation

**Likelihood: High**

1. **Low Attack Complexity**: The Byzantine validator only needs to modify their own delta value when generating `AugData`, which is straightforward.

2. **No Collusion Required**: A single Byzantine validator can execute this attack without requiring coordination with other malicious actors.

3. **Verification Gap**: The legitimate verification path (during `AugData` signing) has the same flaw as the `CertifiedAugData` path - neither checks delta correctness, only cryptographic validity.

4. **Race Condition Exploitation**: If a Byzantine validator acts quickly during epoch initialization, they can ensure their corrupt data is first to be stored.

5. **Persistent Impact**: Once executed, the corruption persists for the entire epoch and affects all randomness generation.

## Recommendation

Implement strict delta validation to ensure provided deltas match the expected deltas:

**Fix for `AugmentedData::verify()`:**
```rust
fn verify(
    &self,
    rand_config: &RandConfig,
    fast_rand_config: &Option<RandConfig>,
    author: &Author,
) -> anyhow::Result<()> {
    // Derive the APK from the provided delta
    let derived_apk = rand_config.derive_apk(author, self.delta.clone())?;
    
    // NEW: Get the expected APK by deriving from the author's pk_share and their legitimate delta
    let expected_delta = WVUF::get_public_delta(&rand_config.get_pk_share(author));
    let expected_apk = rand_config.derive_apk(author, expected_delta.clone())?;
    
    // NEW: Verify the derived APK matches the expected APK
    ensure!(
        derived_apk == expected_apk,
        "Delta verification failed: provided delta does not match expected delta for author {}",
        author
    );

    // Verify fast path delta if present
    ensure!(
        self.fast_delta.is_some() == fast_rand_config.is_some(),
        "Fast path delta should be present iff fast_rand_config is present."
    );
    if let (Some(config), Some(fast_delta)) = (fast_rand_config, self.fast_delta.as_ref()) {
        let derived_fast_apk = config.derive_apk(author, fast_delta.clone())?;
        let expected_fast_delta = WVUF::get_public_delta(&config.get_pk_share(author));
        let expected_fast_apk = config.derive_apk(author, expected_fast_delta.clone())?;
        ensure!(
            derived_fast_apk == expected_fast_apk,
            "Fast path delta verification failed for author {}",
            author
        );
    }
    Ok(())
}
```

**Additional Fix: Re-verify content in CertifiedAugData:** [8](#0-7) 

Modify `CertifiedAugData::verify()` to also verify the data content:
```rust
pub fn verify(
    &self,
    verifier: &ValidatorVerifier,
    rand_config: &RandConfig,
    fast_rand_config: &Option<RandConfig>,
) -> anyhow::Result<()> {
    verifier.verify_multi_signatures(&self.aug_data, &self.signatures)?;
    // NEW: Also verify the content
    self.aug_data.data.verify(rand_config, fast_rand_config, self.author())?;
    Ok(())
}
```

Update the call sites to pass the required parameters.

## Proof of Concept

```rust
// This is a conceptual PoC demonstrating the vulnerability
// In a real test environment:

#[test]
fn test_delta_corruption_vulnerability() {
    // Setup: Create epoch with Byzantine validator
    let (byzantine_validator, honest_validators) = setup_validators();
    let rand_config = create_rand_config(&all_validators);
    
    // Step 1: Byzantine validator generates AugData with WRONG delta
    let legitimate_delta = WVUF::get_public_delta(&byzantine_validator.keys.apk);
    let malicious_delta = create_different_but_valid_delta(); // Different from legitimate
    
    let malicious_aug_data = AugData::new(
        epoch,
        byzantine_validator.author(),
        AugmentedData {
            delta: malicious_delta.clone(),
            fast_delta: None,
        }
    );
    
    // Step 2: Verify the malicious data PASSES verification
    // This should fail but currently succeeds!
    assert!(malicious_aug_data.verify(&rand_config, &None, byzantine_validator.author()).is_ok());
    
    // Step 3: Honest validators sign it (because verification passed)
    let signatures = collect_signatures_from_honest_validators(malicious_aug_data);
    
    // Step 4: Create CertifiedAugData
    let certified_malicious = CertifiedAugData::new(malicious_aug_data, signatures);
    
    // Step 5: All nodes receive and process it
    for node in &honest_validators {
        node.aug_data_store.add_certified_aug_data(certified_malicious.clone()).unwrap();
    }
    
    // Step 6: Verify the RandConfig is now corrupted
    let stored_apk = rand_config.get_certified_apk(&byzantine_validator.author()).unwrap();
    let expected_apk = derive_apk_from_delta(&byzantine_validator, &legitimate_delta);
    let malicious_apk = derive_apk_from_delta(&byzantine_validator, &malicious_delta);
    
    // The stored APK is the malicious one, not the legitimate one!
    assert_eq!(stored_apk, malicious_apk);
    assert_ne!(stored_apk, expected_apk);
    
    // Step 7: Demonstrate that randomness verification now fails or produces wrong results
    let share = create_valid_randomness_share(&byzantine_validator, legitimate_keys);
    // This verification will fail because it uses the wrong certified APK
    assert!(share.verify(&rand_config).is_err());
}
```

## Notes

This vulnerability demonstrates a critical gap in the augmented data validation logic where cryptographic validity is checked but semantic correctness is not. The early return pattern, while useful for preventing equivocation, creates permanent state corruption when combined with insufficient validation. The fix requires both strengthening the delta verification and ensuring content re-verification when receiving certified data.

### Citations

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

**File:** consensus/src/rand/rand_gen/types.rs (L196-215)
```rust
    fn verify(
        &self,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        author: &Author,
    ) -> anyhow::Result<()> {
        rand_config
            .derive_apk(author, self.delta.clone())
            .map(|_| ())?;

        ensure!(
            self.fast_delta.is_some() == fast_rand_config.is_some(),
            "Fast path delta should be present iff fast_rand_config is present."
        );
        if let (Some(config), Some(fast_delta)) = (fast_rand_config, self.fast_delta.as_ref()) {
            config.derive_apk(author, fast_delta.clone()).map(|_| ())
        } else {
            Ok(())
        }
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L555-563)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        verifier.verify_multi_signatures(&self.aug_data, &self.signatures)?;
        Ok(())
    }

    pub fn data(&self) -> &D {
        &self.aug_data.data
    }
}
```

**File:** consensus/src/rand/rand_gen/network_messages.rs (L50-52)
```rust
            RandMessage::CertifiedAugData(certified_aug_data) => {
                certified_aug_data.verify(&epoch_state.verifier)
            },
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
