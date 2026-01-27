# Audit Report

## Title
Integer Underflow DoS in DKG Schnorr Proof Batch Verification with Empty Input

## Summary
The `pok_batch_verify` function in the DKG PVSS implementation contains an integer underflow vulnerability when processing empty proof arrays, which can cause validator nodes to crash (debug mode) or hang indefinitely (release mode). [1](#0-0) 

## Finding Description
The `pok_batch_verify` function computes powers of a challenge scalar `gamma` for batch verification of Schnorr proofs. When `n = poks.len()` is 0 (empty input), line 84 attempts to iterate `0..(n-1)`, which triggers integer underflow since `n` is a `usize`.

**Attack Flow:**
1. Attacker (with validator privileges) crafts a DKG transcript with empty `soks` array and `V[W] = identity`
2. The `get_dealers()` method returns an empty dealer list from empty soks [2](#0-1) 
3. Verification constructs empty `spks` and `auxs` arrays from empty dealers [3](#0-2) 
4. `check_sizes()` validation passes (doesn't validate `soks.len()`) [4](#0-3) 
5. `batch_verify_soks` is called with all arrays empty, passing length checks [5](#0-4) 
6. Commitment sum check passes: `sum([]) = identity = V[W]` [6](#0-5) 
7. `pok_batch_verify` called with `n=0`, triggering underflow on line 84
8. **Debug mode**: Immediate panic crashes validator
9. **Release mode**: Wraps to `usize::MAX`, loops ~18 quintillion times, causing validator hang/OOM

The vulnerability bypasses the multi-exp length checks because the node crashes before reaching that code path.

## Impact Explanation
**High Severity** - Validator node crash/hang leading to availability impact. While this requires validator privileges to submit a malicious DKG transcript, a single malicious or compromised validator could disrupt the DKG ceremony and prevent the network from progressing through epoch transitions. This aligns with "Validator node slowdowns" and "API crashes" under High Severity ($50,000) in the bug bounty program.

This breaks the **Cryptographic Correctness** invariant (#10) by failing to handle edge cases in cryptographic verification, and potentially impacts **Total loss of liveness** if exploited during critical DKG phases.

## Likelihood Explanation
**Medium-High**. While the attack requires validator access, the code path is deterministic and the underflow is guaranteed with empty input. DKG transcript submission occurs during epoch transitions, and a malicious validator could submit this malformed transcript. The lack of explicit empty-input validation makes this exploitable.

## Recommendation
Add explicit validation for empty inputs in both `pok_batch_verify` and `batch_verify_soks`:

```rust
pub fn pok_batch_verify<'a, Gr>(
    poks: &Vec<(Gr, PoK<Gr>)>,
    g: &Gr,
    gamma: &Scalar,
) -> anyhow::Result<()>
where
    Gr: Serialize + Group + Mul<&'a Scalar> + HasMultiExp,
{
    let n = poks.len();
    
    // Add validation for empty input
    if n == 0 {
        bail!("Cannot batch verify empty proof set");
    }
    
    let mut exps = Vec::with_capacity(2 * n + 1);
    // ... rest of function
}
```

Similarly, add validation in `batch_verify_soks`:
```rust
pub fn batch_verify_soks<Gr, A>(...) -> anyhow::Result<()> {
    if soks.is_empty() {
        bail!("Cannot verify empty SoK set");
    }
    // ... existing checks
}
```

Additionally, `check_sizes()` should validate that `soks` is non-empty and contains the expected number of dealers.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to subtract with overflow")]
fn test_pok_batch_verify_empty_underflow() {
    use blstrs::{G1Projective, Scalar};
    use aptos_dkg::pvss::schnorr::pok_batch_verify;
    
    let empty_poks: Vec<(G1Projective, (G1Projective, Scalar))> = vec![];
    let g = G1Projective::generator();
    let gamma = Scalar::ONE;
    
    // This will panic in debug mode due to integer underflow at line 84
    // In release mode, it will hang attempting to loop usize::MAX times
    let _ = pok_batch_verify(&empty_poks, &g, &gamma);
}
```

**Notes**:
- This vulnerability requires validator privileges to exploit, as DKG transcripts are submitted via validator transactions [7](#0-6) 
- The underlying `g1_multi_exp`/`g2_multi_exp` length checks are effective at preventing blstrs bugs when reached, but this vulnerability prevents that code from executing
- The documented blstrs "heisenbugs" with length mismatches are properly protected by the wrapper functions in normal operation [8](#0-7) 
- Test file documents known blstrs issues that these wrappers prevent [9](#0-8)

### Citations

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L77-86)
```rust
    let n = poks.len();
    let mut exps = Vec::with_capacity(2 * n + 1);
    let mut bases = Vec::with_capacity(2 * n + 1);

    // Compute \gamma_i = \gamma^i, for all i \in [0, n]
    let mut gammas = Vec::with_capacity(n);
    gammas.push(Scalar::ONE);
    for _ in 0..(n - 1) {
        gammas.push(gammas.last().unwrap().mul(gamma));
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L190-195)
```rust
    fn get_dealers(&self) -> Vec<Player> {
        self.soks
            .iter()
            .map(|(p, _, _, _)| *p)
            .collect::<Vec<Player>>()
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-454)
```rust
    fn check_sizes(&self, sc: &WeightedConfigBlstrs) -> anyhow::Result<()> {
        let W = sc.get_total_weight();

        if self.V.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V.len()
            );
        }

        if self.V_hat.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V_hat.len()
            );
        }

        if self.R.len() != W {
            bail!(
                "Expected {} G_1 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R.len()
            );
        }

        if self.R_hat.len() != W {
            bail!(
                "Expected {} G_2 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R_hat.len()
            );
        }

        if self.C.len() != W {
            bail!("Expected C of length {}, but got {}", W, self.C.len());
        }

        Ok(())
```

**File:** types/src/dkg/real_dkg/mod.rs (L358-366)
```rust
        let spks = dealers_addresses
            .iter()
            .filter_map(|author| params.verifier.get_public_key(author))
            .collect::<Vec<_>>();

        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L40-54)
```rust
    if soks.len() != spks.len() {
        bail!(
            "Expected {} signing PKs, but got {}",
            soks.len(),
            spks.len()
        );
    }

    if soks.len() != aux.len() {
        bail!(
            "Expected {} auxiliary infos, but got {}",
            soks.len(),
            aux.len()
        );
    }
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L57-68)
```rust
    let mut c = Gr::identity();
    for (_, c_i, _, _) in soks {
        c.add_assign(c_i)
    }

    if c.ne(pk) {
        bail!(
            "The PoK does not correspond to the dealt secret. Expected {} but got {}",
            pk,
            c
        );
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L104-112)
```rust
        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** crates/aptos-dkg/src/utils/mod.rs (L58-88)
```rust
pub fn g1_multi_exp(bases: &[G1Projective], scalars: &[blstrs::Scalar]) -> G1Projective {
    if bases.len() != scalars.len() {
        panic!(
            "blstrs's multiexp has heisenbugs when the # of bases != # of scalars ({} != {})",
            bases.len(),
            scalars.len()
        );
    }

    match bases.len() {
        0 => G1Projective::identity(),
        1 => bases[0].mul(scalars[0]),
        _ => G1Projective::multi_exp(bases, scalars),
    }
}

/// Works around the `blst_hell` bug (see README.md).
pub fn g2_multi_exp(bases: &[G2Projective], scalars: &[blstrs::Scalar]) -> G2Projective {
    if bases.len() != scalars.len() {
        panic!(
            "blstrs's multiexp has heisenbugs when the # of bases != # of scalars ({} != {})",
            bases.len(),
            scalars.len()
        );
    }
    match bases.len() {
        0 => G2Projective::identity(),
        1 => bases[0].mul(scalars[0]),
        _ => G2Projective::multi_exp(bases, scalars),
    }
}
```

**File:** crates/aptos-dkg/tests/crypto.rs (L22-91)
```rust
/// TODO(Security): This shouldn't fail, but it does.
#[test]
#[should_panic]
#[ignore]
fn test_crypto_g1_multiexp_more_points() {
    let bases = vec![G1Projective::identity(), G1Projective::identity()];
    let scalars = vec![Scalar::ONE];

    let result = G1Projective::multi_exp(&bases, &scalars);

    assert_eq!(result, bases[0]);
}

/// TODO(Security): This failed once out of the blue. Can never call G1Projective::multi_exp directly
///  because of this.
///
/// Last reproduced on Dec. 5th, 2023 with blstrs 0.7.1:
///  ```
///  failures:
///
///  ---- test_multiexp_less_points stdout ----
///  thread 'test_multiexp_less_points' panicked at 'assertion failed: `(left == right)`
///  left: `G1Projective { x: Fp(0x015216375988dea7b8f1642e6667482a0fe06709923f24e629468da4cf265ea6f03f593188d3557d5cf20a50ff28f870), y: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), z: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001) }`,
///  right: `G1Projective { x: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), y: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), z: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000) }`', crates/aptos-dkg/tests/crypto.rs:32:5
///  ```
#[test]
#[ignore]
fn test_crypto_g1_multiexp_less_points() {
    let bases = vec![G1Projective::identity()];
    let scalars = vec![Scalar::ONE, Scalar::ONE];

    let result = G1Projective::multi_exp(&bases, &scalars);

    assert_eq!(result, bases[0]);
}

/// At some point I suspected that size-1 multiexps where the scalar is set to 1 had a bug in them.
/// But they seem fine.
#[test]
fn test_crypto_size_1_multiexp_random_base() {
    let mut rng = thread_rng();

    let bases = vec![random_g2_point(&mut rng)];
    let scalars = vec![Scalar::ONE];

    let result = G2Projective::multi_exp(&bases, &scalars);

    assert_eq!(result, bases[0]);
}

/// TODO(Security): Size-1 G2 multiexps on the generator where the scalar is set to one WILL
///  sometimes fail. Can never call G2Projective::multi_exp directly because of this.
///
/// Last reproduced on Dec. 5th, 2023 with blstrs 0.7.0:
/// ```
///  ---- test_size_1_g2_multiexp_generator_base stdout ----
///  thread 'test_size_1_g2_multiexp_generator_base' panicked at 'assertion failed: `(left == right)`
///    left: `G2Projective { x: Fp2 { c0: Fp(0x0eebd388297e6ad4aa4abe2dd6d2b65061c8a38ce9ac87718432dbdf9843c3a60bbc9706251cb8fa74bc9f5a8572a531), c1: Fp(0x18e7670f7afe6f13acd673491d6d835719c40e5ee1786865ea411262ccafa75c6aef2b28ff973b4532cc4b80e5be4936) }, y: Fp2 { c0: Fp(0x0a4548b4e05e80f16df8a1209b68de65252a7a6f8d8a133bc673ac1505ea59eb30a537e1c1b4e64394d8b2f3aa1f0f14), c1: Fp(0x00b47b3a434ab44b045f5009bcf93b6c47710ffd17c90f35b6ae39864af8d4994003fb223e29a209d609b092042cebbd) }, z: Fp2 { c0: Fp(0x06df5e339dc55dc159f0a845f3f792ea1dee8a0933dc0ed950ed588b21cb553cd6b616f49b73ea3e44ab7618125c9875), c1: Fp(0x0e9d03aee09a7603dc069da045848488f10a51bc5655baffd31f4a7b0e3746cdf93fb3345950f70617730e440f71a8e2) } }`,
///   right: `G2Projective { x: Fp2 { c0: Fp(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8), c1: Fp(0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e) }, y: Fp2 { c0: Fp(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801), c1: Fp(0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be) }, z: Fp2 { c0: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001), c1: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000) } }`', crates/aptos-dkg/tests/crypto.rs:67:5
/// ```
#[test]
#[ignore]
fn test_crypto_g_2_to_zero_multiexp() {
    let bases = vec![G2Projective::generator()];
    let scalars = vec![Scalar::ONE];

    let result = G2Projective::multi_exp(&bases, &scalars);

    assert_eq!(result, bases[0]);
}
```
