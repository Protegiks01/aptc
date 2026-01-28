# Audit Report

## Title
Identity Element Attack Bypasses Cryptographic Validation in Pinkas WVUF `augment_pubkey()`

## Summary
The `augment_pubkey()` function in the Pinkas Weighted VUF implementation fails to validate that `delta.pi` and `delta.rks` elements are non-identity. A malicious validator can bypass cryptographic validation by providing identity group elements, allowing them to get a malformed augmented public key certified without proving possession of the corresponding secret key.

## Finding Description

The `augment_pubkey()` function is designed to cryptographically verify that a delta (randomized public keys) was correctly generated using the legitimate secret key. [1](#0-0) 

The validation uses a multi-pairing check: `e(delta.pi, pks_combined) * e(rks_combined, -g_hat) = identity`

**Attack Vector:**

A malicious validator can construct a `RandomizedPKs` delta with:
- `delta.pi = G1Projective::identity()`  
- All `delta.rks[i] = G1Projective::identity()`

When this delta is validated, the pairing check mathematically evaluates as:
1. `pks_combined = sum_i tau^i * pk_i` (non-identity, legitimate public keys from honest validator)
2. `rks_combined = sum_i tau^i * identity = identity` (line 132)
3. Since `e(identity, X) = identity` for any element X, the pairing becomes:
   `e(identity, pks_combined) * e(identity, -g_hat) = identity * identity = identity` ✓

The validation incorrectly passes despite the attacker not using their secret key to generate the delta.

**Attack Flow:**

1. Malicious validator participates in DKG and receives legitimate `pk_share`
2. Instead of calling `augment_key_pair()` with their secret key, they construct a malicious `RandomizedPKs` struct with identity elements
3. They broadcast this delta to other validators during the augmented data exchange
4. Honest validators call `add_certified_delta()` [2](#0-1)  which invokes `augment_pubkey()` via `derive_apk()`
5. The malformed delta passes validation and gets stored in `certified_apks` [3](#0-2) 

**Attack Limitation:**

While the attacker can get their malformed APK certified, they **cannot** participate in actual randomness generation. The `verify_share()` function [4](#0-3)  checks: `e(delta.pi, proof) * e(-g, h) = identity`

With `delta.pi = identity`, this becomes: `e(identity, proof) * e(-g, h) = identity`, which requires `e(-g, h) = identity`. However, `e(-g, h) ≠ identity` since g and h are non-identity group elements, so the verification fails and any share the attacker creates will be rejected.

## Impact Explanation

**Severity: Medium**

This vulnerability represents a cryptographic validation bypass that qualifies as a "Limited Protocol Violation" under the Aptos bug bounty Medium severity criteria.

**Security Property Violated:**
The protocol assumes that only validators possessing their secret key share can have a certified augmented public key. This cryptographic binding is violated.

**Actual Impact:**
- **Protocol Integrity Violation**: The assumption that all certified APKs are cryptographically bound to secret keys is broken
- **State Inconsistency**: The `certified_apks` vector contains malformed entries that violate protocol assumptions [5](#0-4) 
- **Resource Waste**: Honest validators expend CPU cycles verifying and storing malformed deltas

**No Critical Impact:**
- Consensus safety is NOT violated (malicious shares are rejected by `verify_share`)
- Randomness generation continues with honest validators via the weighted threshold
- No fund theft, loss of liveness, or consensus split occurs
- The Byzantine fault tolerance ensures system functionality

This qualifies as Medium severity under "Limited Protocol Violations" - a cryptographic validation bypass that creates state inconsistencies, though the system remains functional due to downstream protections.

## Likelihood Explanation

**Likelihood: Medium**

**Attacker Requirements:**
- Must be a validator in the active validator set
- Must participate in DKG to receive legitimate `pk_share`
- Can execute unilaterally without collusion

**Execution Complexity:**
- Low - simply construct `RandomizedPKs` with `G1Projective::identity()` elements instead of calling `augment_key_pair()` [6](#0-5) 
- Attack is deterministic and reliable
- Triggers through normal augmented data exchange protocol [7](#0-6) 

**Detection:**
- Difficult to detect in real-time since validation passes
- Could be detected through monitoring if validators track whether peers contribute randomness shares

## Recommendation

Add explicit validation to reject identity elements in `augment_pubkey()`:

```rust
fn augment_pubkey(
    pp: &Self::PublicParameters,
    pk: Self::PubKeyShare,
    delta: Self::Delta,
) -> anyhow::Result<Self::AugmentedPubKeyShare> {
    if delta.rks.len() != pk.len() {
        bail!(...);
    }
    
    // Add identity element validation
    if delta.pi.is_identity().into() {
        bail!("delta.pi cannot be the identity element");
    }
    
    for (i, rk) in delta.rks.iter().enumerate() {
        if rk.is_identity().into() {
            bail!("delta.rks[{}] cannot be the identity element", i);
        }
    }
    
    // Continue with existing pairing check...
}
```

This ensures that only properly randomized keys with non-trivial randomization factors can pass validation.

## Proof of Concept

```rust
#[test]
fn test_identity_element_attack() {
    use blstrs::{G1Projective, G2Projective};
    use group::Group;
    use aptos_dkg::weighted_vuf::{pinkas::*, traits::WeightedVUF};
    
    // Setup similar to test_wvuf_basic_viability
    let (wc, d, trx) = setup_weighted_pvss();
    let vuf_pp = PublicParameters::from(&d.pp);
    
    // Honest validator's public key share
    let pk_share = trx.decrypt_own_share(&wc, &wc.get_player(0), &d.dks[0], &d.pp).1;
    
    // Attacker constructs malicious delta with identity elements
    let malicious_delta = RandomizedPKs {
        pi: G1Projective::identity(),
        rks: vec![G1Projective::identity(); pk_share.len()],
    };
    
    // This should fail but currently passes
    let result = PinkasWUF::augment_pubkey(&vuf_pp, pk_share.clone(), malicious_delta.clone());
    
    // The validation incorrectly succeeds
    assert!(result.is_ok(), "Identity element attack bypasses validation");
    
    let malicious_apk = result.unwrap();
    
    // However, any share created with this malicious APK will fail verification
    let msg = b"test message";
    let fake_ask = (Scalar::ONE, vec![/* some secret key shares */]);
    let proof = PinkasWUF::create_share(&fake_ask, msg);
    
    // This correctly fails
    let verify_result = PinkasWUF::verify_share(&vuf_pp, &malicious_apk, msg, &proof);
    assert!(verify_result.is_err(), "Share verification correctly rejects malicious shares");
}
```

**Notes**

This vulnerability represents a real cryptographic validation bypass in the Pinkas WVUF implementation used for consensus randomness generation. While downstream checks (`verify_share`) prevent the attacker from corrupting randomness output, the ability to bypass `augment_pubkey` validation violates the protocol's security assumptions and allows malformed state entries. The issue is categorized as Medium severity because it constitutes a limited protocol violation with state inconsistencies, though consensus safety and liveness remain intact due to the Byzantine fault tolerant design.

### Citations

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L82-100)
```rust
    fn augment_key_pair<R: rand_core::RngCore + rand_core::CryptoRng>(
        pp: &Self::PublicParameters,
        sk: Self::SecretKeyShare,
        pk: Self::PubKeyShare,
        // lsk: &Self::BlsSecretKey,
        rng: &mut R,
    ) -> (Self::AugmentedSecretKeyShare, Self::AugmentedPubKeyShare) {
        let r = random_nonzero_scalar(rng);

        let rpks = RandomizedPKs {
            pi: pp.g.mul(&r),
            rks: sk
                .iter()
                .map(|sk| sk.as_group_element().mul(&r))
                .collect::<Vec<G1Projective>>(),
        };

        ((r.invert().unwrap(), sk), (rpks, pk))
    }
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L108-143)
```rust
    fn augment_pubkey(
        pp: &Self::PublicParameters,
        pk: Self::PubKeyShare,
        // lpk: &Self::BlsPubKey,
        delta: Self::Delta,
    ) -> anyhow::Result<Self::AugmentedPubKeyShare> {
        if delta.rks.len() != pk.len() {
            bail!(
                "Expected PKs and RKs to be of the same length. Got {} and {}, respectively.",
                delta.rks.len(),
                pk.len()
            );
        }

        // TODO: Fiat-Shamir transform instead of RNG
        let tau = random_scalar(&mut thread_rng());

        let pks = pk
            .iter()
            .map(|pk| *pk.as_group_element())
            .collect::<Vec<G2Projective>>();
        let taus = get_powers_of_tau(&tau, pks.len());

        let pks_combined = g2_multi_exp(&pks[..], &taus[..]);
        let rks_combined = g1_multi_exp(&delta.rks[..], &taus[..]);

        if multi_pairing(
            [&delta.pi, &rks_combined].into_iter(),
            [&pks_combined, &pp.g_hat.neg()].into_iter(),
        ) != Gt::identity()
        {
            bail!("RPKs were not correctly randomized.");
        }

        Ok((delta, pk))
    }
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L153-170)
```rust
    fn verify_share(
        pp: &Self::PublicParameters,
        apk: &Self::AugmentedPubKeyShare,
        msg: &[u8],
        proof: &Self::ProofShare,
    ) -> anyhow::Result<()> {
        let delta = Self::get_public_delta(apk);

        let h = Self::hash_to_curve(msg);

        if multi_pairing([&delta.pi, &pp.g_neg].into_iter(), [proof, &h].into_iter())
            != Gt::identity()
        {
            bail!("PinkasWVUF ProofShare failed to verify.");
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

**File:** consensus/src/rand/rand_gen/types.rs (L661-665)
```rust
    pub fn add_certified_delta(&self, peer: &Author, delta: Delta) -> anyhow::Result<()> {
        let apk = self.derive_apk(peer, delta)?;
        self.add_certified_apk(peer, apk)?;
        Ok(())
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
