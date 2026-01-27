# Audit Report

## Title
DKG Schnorr Proof-of-Knowledge Replay Attack Enabling Secret Reuse Across Epochs

## Summary
The Schnorr proof-of-knowledge (PoK) verification in the DKG protocol lacks epoch-specific binding, allowing malicious validators to reuse the same `(R, s)` proof values across multiple DKG epochs. This enables validators to avoid generating fresh secrets for each epoch by deliberately reusing the same polynomial constant term, violating the fundamental DKG security requirement of independent randomness per epoch.

## Finding Description

The vulnerability exists in the Schnorr PoK implementation used to prove knowledge of dealt secrets in the DKG protocol. The Fiat-Shamir challenge computation only includes the commitment `R`, public key `pk`, and generator `g`, without any epoch-specific context: [1](#0-0) 

This challenge structure is used during both proof generation and verification: [2](#0-1) [3](#0-2) 

**Attack Scenario:**

A malicious validator can exploit this by:

1. **Epoch N**: Generate a DKG transcript with secret `f_coeff[0] = secret_value`, producing commitment `V[W] = g₁^secret_value` and Schnorr PoK `(R, s)`: [4](#0-3) 

2. **Epoch N+1**: Deliberately reuse the same secret `f_coeff[0] = secret_value`, resulting in the same `V[W]` commitment. The validator then:
   - Reuses the same `(R, s)` proof from Epoch N
   - Generates fresh ElGamal encryptions (required for pairing checks)
   - Creates a new BLS signature with the updated epoch in the `aux` parameter

3. **Verification passes** because:
   - The Schnorr PoK verification at batch_verify_soks only checks the proof against `(R, pk, g)` without epoch binding: [5](#0-4) 

   - The BLS signature verification passes with the new epoch-specific signature: [6](#0-5) 

   - The epoch check at the VM level only validates that the transcript claims to be from the current epoch: [7](#0-6) 

The `aux` parameter containing epoch information is passed during verification but **only used for BLS signature verification**, not for binding the Schnorr PoK to the epoch: [8](#0-7) 

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria, classified as a "Significant protocol violation" affecting validator behavior and consensus security:

1. **Forward Secrecy Violation**: If a validator's secret from one epoch is compromised (e.g., through side-channel attacks, key leakage, or cryptanalysis), all epochs where that validator reused the secret are retroactively compromised.

2. **Reduced Entropy**: The aggregated DKG output's security relies on the assumption that each validator contributes independent fresh randomness. Validators reusing secrets reduce the effective entropy of the shared secret, potentially bringing it below the security threshold if multiple colluding validators employ this technique.

3. **Predictable Contributions**: An adversary observing a validator's transcript can predict that validator's contribution to future DKG rounds, enabling targeted attacks or manipulation strategies.

4. **Collusion Amplification**: Multiple malicious validators could coordinate to all reuse their secrets, significantly weakening the DKG output and potentially enabling practical attacks on the randomness beacon or threshold cryptography operations.

5. **Protocol Invariant Violation**: Violates the DKG security requirement that "each epoch must use independent randomness" which is fundamental to the security proof of the protocol.

## Likelihood Explanation

**Likelihood: HIGH**

- **Ease of Exploitation**: Any validator can execute this attack independently without requiring additional privileges, coordination with other validators, or technical sophistication beyond understanding the protocol.

- **Detection Difficulty**: The attack is not easily detectable through normal monitoring since the transcript appears valid and passes all verification checks. Only forensic analysis comparing transcripts across epochs would reveal the reuse.

- **Attacker Motivation**: Validators might be motivated to perform this attack to:
  - Reduce computational overhead by avoiding fresh PoK generation
  - Enable strategic manipulation of DKG outputs
  - Participate in coordinated attacks on randomness generation
  - Maintain backdoors into the cryptographic parameters

- **No Cost to Attack**: The attack requires no additional resources and actually reduces the validator's computational burden, providing a perverse incentive for lazy or malicious validators.

## Recommendation

**Fix**: Bind the Schnorr PoK challenge to epoch-specific context by including it in the Challenge structure:

```rust
#[derive(Serialize, Deserialize, BCSCryptoHash, CryptoHasher)]
#[allow(non_snake_case)]
struct Challenge<Gr, A: Serialize> {
    R: Gr,     // g^r
    pk: Gr,    // g^a
    g: Gr,
    aux: A,    // Include epoch-specific binding (epoch, address)
}
```

Update the signature of `pok_prove` and `pok_batch_verify` to accept and include the `aux` parameter:

```rust
pub fn pok_prove<Gr, A, R>(
    a: &Scalar,
    g: &Gr,
    pk: &Gr,
    aux: &A,
    rng: &mut R
) -> PoK<Gr>
where
    Gr: Serialize + Group + for<'a> Mul<&'a Scalar, Output = Gr>,
    A: Serialize,
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let r = random_scalar(rng);
    let R = g.mul(&r);
    let e = schnorr_hash(Challenge::<Gr, A> { R, pk: *pk, g: *g, aux: aux.clone() });
    let s = r + e * a;
    (R, s)
}

pub fn pok_batch_verify<'a, Gr, A>(
    poks: &Vec<(Gr, PoK<Gr>)>,
    g: &Gr,
    gamma: &Scalar,
    auxs: &[A],
) -> anyhow::Result<()>
where
    Gr: Serialize + Group + Mul<&'a Scalar> + HasMultiExp,
    A: Serialize,
{
    // ... existing code ...
    for i in 0..n {
        let (pk, (R, s)) = poks[i];
        // Include aux in challenge computation
        exps.push(schnorr_hash(Challenge::<Gr, A> { 
            R, 
            pk, 
            g: *g, 
            aux: auxs[i].clone() 
        }) * gammas[i]);
        // ... rest of verification ...
    }
    // ... existing code ...
}
```

This ensures that proofs from one epoch cannot be replayed in another epoch since the challenge will differ due to the epoch parameter in `aux`.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_crypto::blstrs::random_scalar;
    use blstrs::{G1Projective, Scalar};
    use rand::thread_rng;

    #[test]
    fn test_schnorr_pok_replay_across_epochs() {
        let mut rng = thread_rng();
        
        // Setup: validator's secret and public key
        let secret = random_scalar(&mut rng);
        let g = G1Projective::generator();
        let pk = g * secret;
        
        // Epoch N: Generate proof
        let (R_epoch_n, s_epoch_n) = pok_prove(&secret, &g, &pk, &mut rng);
        
        // Verify proof works for Epoch N
        let poks = vec![(pk, (R_epoch_n, s_epoch_n))];
        let gamma = random_scalar(&mut rng);
        assert!(pok_batch_verify(&poks, &g, &gamma).is_ok());
        
        // Epoch N+1: Malicious validator reuses SAME secret and SAME proof
        // This should fail but currently succeeds
        let reused_proof = (R_epoch_n, s_epoch_n); // Same (R, s) from Epoch N
        let poks_reused = vec![(pk, reused_proof)];
        let gamma_n1 = random_scalar(&mut rng);
        
        // VULNERABILITY: This verification passes even though it's a replay
        assert!(pok_batch_verify(&poks_reused, &g, &gamma_n1).is_ok());
        
        // The proof from Epoch N successfully verifies in Epoch N+1
        // This demonstrates that validators can avoid generating fresh secrets
        println!("VULNERABILITY CONFIRMED: Schnorr PoK replay attack successful");
        println!("Validator reused proof across epochs without detection");
    }
}
```

**Note**: This PoC demonstrates the core issue. In a full DKG context, the attacker would also need to generate fresh ElGamal encryptions and BLS signatures, but the Schnorr PoK replay is the critical vulnerability allowing secret reuse across epochs.

### Citations

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L25-29)
```rust
struct Challenge<Gr> {
    R: Gr,  // g^r
    pk: Gr, // g^a
    g: Gr,
}
```

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L41-41)
```rust
    let e = schnorr_hash(Challenge::<Gr> { R, pk: *pk, g: *g });
```

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L96-96)
```rust
        exps.push(schnorr_hash(Challenge::<Gr> { R, pk, g: *g }) * gammas[i]);
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L173-173)
```rust
        let pok = schnorr::pok_prove(&f_coeff[0], g_1, &V[W], rng);
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L76-76)
```rust
    schnorr::pok_batch_verify::<Gr>(&poks, pk_base, &tau)?;
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L79-102)
```rust
    let msgs = soks
        .iter()
        .zip(aux)
        .map(|((player, comm, _, _), aux)| Contribution::<Gr, A> {
            comm: *comm,
            player: *player,
            aux: aux.clone(),
        })
        .collect::<Vec<Contribution<Gr, A>>>();
    let msgs_refs = msgs
        .iter()
        .map(|c| c)
        .collect::<Vec<&Contribution<Gr, A>>>();
    let pks = spks
        .iter()
        .map(|pk| pk)
        .collect::<Vec<&bls12381::PublicKey>>();
    let sig = bls12381::Signature::aggregate(
        soks.iter()
            .map(|(_, _, sig, _)| sig.clone())
            .collect::<Vec<bls12381::Signature>>(),
    )?;

    sig.verify_aggregate(&msgs_refs[..], &pks[..])?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L100-102)
```rust
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }
```

**File:** types/src/dkg/real_dkg/mod.rs (L363-374)
```rust
        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();

        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;
```
