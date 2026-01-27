# Audit Report

## Title
DKG Liveness Failure Risk Due to Panic-Based Error Handling in Cryptographic Utility Functions

## Summary
The DKG (Distributed Key Generation) utility functions in `crates/aptos-dkg/src/utils/mod.rs` use `panic!` for error handling instead of returning `Result<>`. These functions are called during transcript verification in the critical DKG phase of epoch transitions. While current validation logic prevents normal triggering of these panics, any future bugs or edge cases that bypass size checks would cause validator crashes, potentially preventing DKG completion and halting epoch transitions.

## Finding Description

The functions `g1_multi_exp()`, `g2_multi_exp()`, and `hash_to_scalar()` use `panic!` to handle error conditions during DKG transcript verification. [1](#0-0) [2](#0-1) [3](#0-2) 

These functions are called during the verification phase of DKG transcripts received from network peers: [4](#0-3) [5](#0-4) 

The panic conditions are defensive checks for known bugs in the underlying `blstrs` cryptographic library: [6](#0-5) 

When transcript verification is performed, it's called through the DKG aggregation state: [7](#0-6) 

**The Security Issue:**

If any condition causes mismatched array lengths to reach `g1_multi_exp` or `g2_multi_exp`:
1. The validator process crashes via `panic!`
2. The crashed validator cannot complete DKG
3. If multiple validators encounter the same condition, DKG may fail to reach quorum
4. Failed DKG prevents epoch transition, causing network liveness failure

While current code has size validation, the fragility lies in the error handling strategy itself - any future bug, unexpected edge case, or memory corruption that bypasses validation would cause catastrophic failure rather than graceful degradation.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:
- This creates a **state inconsistency requiring intervention** during epoch transitions
- DKG failure prevents the network from transitioning to the next epoch, requiring manual validator coordination or extended downtime
- Does not directly enable fund theft or consensus safety violations
- The system is designed to recover from individual validator crashes, but simultaneous crashes affecting quorum would be problematic [8](#0-7) 

The test shows recovery is possible for individual crashes, but not for widespread simultaneous failures.

## Likelihood Explanation

**Medium Likelihood:**
- Current validation logic provides protection against normal operation
- However, DKG runs during every epoch transition (critical, frequently-executed code path)
- The defensive panics acknowledge known fragility in the underlying cryptographic library
- Future code changes, compiler updates, or unforeseen edge cases could create paths to trigger the panic
- The complexity of PVSS transcript verification with multiple array slicing operations increases risk of logic errors

## Recommendation

Replace `panic!` with `Result<>` returns in all DKG utility functions:

```rust
pub fn g1_multi_exp(bases: &[G1Projective], scalars: &[blstrs::Scalar]) -> Result<G1Projective, anyhow::Error> {
    if bases.len() != scalars.len() {
        bail!(
            "blstrs multiexp size mismatch: {} bases != {} scalars",
            bases.len(),
            scalars.len()
        );
    }

    match bases.len() {
        0 => Ok(G1Projective::identity()),
        1 => Ok(bases[0].mul(scalars[0])),
        _ => Ok(G1Projective::multi_exp(bases, scalars)),
    }
}

pub fn g2_multi_exp(bases: &[G2Projective], scalars: &[blstrs::Scalar]) -> Result<G2Projective, anyhow::Error> {
    if bases.len() != scalars.len() {
        bail!(
            "blstrs multiexp size mismatch: {} bases != {} scalars",
            bases.len(),
            scalars.len()
        );
    }
    
    match bases.len() {
        0 => Ok(G2Projective::identity()),
        1 => Ok(bases[0].mul(scalars[0])),
        _ => Ok(G2Projective::multi_exp(bases, scalars)),
    }
}

pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<blstrs::Scalar, anyhow::Error> {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst);
    let binding = hasher.finalize();
    let dst_hash = binding.as_slice();

    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst_hash);
    hasher.update(msg);
    let binding = hasher.finalize();
    let bytes = binding.as_slice();

    ensure!(bytes.len() == 64, "SHA3-512 hash size mismatch: expected 64 bytes, got {}", bytes.len());

    let chunk: [u8; 64] = bytes.try_into()
        .map_err(|_| anyhow!("Failed to convert hash bytes to fixed array"))?;
    Ok(random_scalar_from_uniform_bytes(chunk))
}
```

Propagate these `Result<>` types through the call chain in PVSS verification functions. This allows validators to:
- Log detailed error information for debugging
- Reject problematic transcripts without crashing
- Continue processing other valid transcripts
- Maintain availability during DKG

## Proof of Concept

The vulnerability manifests in operational fragility rather than a directly exploitable bug. A PoC would require:

1. Creating a scenario that bypasses size validation (requires finding a separate logic bug)
2. Demonstrating validator crash during DKG
3. Showing DKG failure due to insufficient participating validators

Since no current attack path exists to trigger the panic through malicious input (the validation checks are effective), a realistic PoC cannot be constructed without first discovering a bug in the validation logic itself.

However, the systemic risk can be demonstrated through fault injection:

```rust
// Hypothetical test showing fragility (would require fault injection framework)
#[tokio::test]
async fn test_dkg_panic_causes_liveness_failure() {
    // Setup: 4 validator network with DKG enabled
    // Inject: fault that causes size mismatch in 3 validators during verification
    // Expected: DKG fails, epoch transition blocked
    // With Result<>: Validators log error, reject transcript, DKG continues with other transcripts
}
```

The lack of a concrete exploit path, combined with the design-level nature of this issue, places this at the boundary of the "EXTREMELY high bar" for validation.

## Notes

This finding identifies a **defensive programming weakness** that increases fragility during critical operations rather than a directly exploitable vulnerability. The current code's validation logic appears sound, making actual exploitation require discovery of a separate bug. The recommendation to use `Result<>` is a **hardening measure** that would improve robustness against future bugs, edge cases, and unexpected conditions during the critical DKG phase.

### Citations

**File:** crates/aptos-dkg/src/utils/mod.rs (L35-55)
```rust
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> blstrs::Scalar {
    // First, hash the DST as `dst_hash = H(dst)`
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst);
    let binding = hasher.finalize();
    let dst_hash = binding.as_slice();

    // Second, hash the msg as `H(dst_hash, msg)`
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst_hash);
    hasher.update(msg);
    let binding = hasher.finalize();
    let bytes = binding.as_slice();

    assert_eq!(bytes.len(), 64);

    match bytes.try_into() {
        Ok(chunk) => random_scalar_from_uniform_bytes(chunk),
        Err(_) => panic!("Expected a 64-byte SHA3-512 hash, but got a different size"),
    }
}
```

**File:** crates/aptos-dkg/src/utils/mod.rs (L58-72)
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
```

**File:** crates/aptos-dkg/src/utils/mod.rs (L75-88)
```rust
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

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L280-310)
```rust
        //

        // TODO(Performance): Change the Fiat-Shamir transform to use 128-bit random exponents.
        // r_i = \tau^i, \forall i \in [n]
        // TODO: benchmark this
        let taus = get_nonzero_powers_of_tau(&extra[1], sc.n);

        // Compute the multiexps from above.
        let v = g2_multi_exp(&self.V[..self.V.len() - 1], taus.as_slice());
        let ek = g1_multi_exp(
            eks.iter()
                .map(|ek| Into::<G1Projective>::into(ek))
                .collect::<Vec<G1Projective>>()
                .as_slice(),
            taus.as_slice(),
        );
        let c = g1_multi_exp(self.C.as_slice(), taus.as_slice());

        // Fetch some public parameters
        let h_1 = *pp.get_encryption_public_params().message_base();
        let g_1_inverse = pp.get_encryption_public_params().pubkey_base().neg();

        // The vector of left-hand-side ($\mathbb{G}_1$) inputs to each pairing in the multi-pairing.
        let lhs = vec![h_1, ek.add(g_1_inverse), self.C_0.add(c.neg())];
        // The vector of right-hand-side ($\mathbb{G}_2$) inputs to each pairing in the multi-pairing.
        let rhs = vec![v, self.hat_w, g_2];

        let res = multi_pairing(lhs.iter(), rhs.iter());
        if res != Gt::identity() {
            bail!("Expected zero, but got {} during multi-pairing check", res);
        }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L342-350)
```rust
        for i in 0..n {
            let p = sc.get_player(i);
            let weight = sc.get_player_weight(&p);
            let s_i = sc.get_player_starting_index(&p);

            lc_R_hat.push(g2_multi_exp(
                &self.R_hat[s_i..s_i + weight],
                &gammas[s_i..s_i + weight],
            ));
```

**File:** crates/aptos-dkg/README.md (L28-46)
```markdown

### Size-1 multiexps

`blstrs 0.7.0` had a bug (originally from `blst`) where size-1 multiexps (sometimes) don't output the correct result: see [this issue](https://github.com/filecoin-project/blstrs/issues/57) opened by Sourav Das.

As a result, some of our 1 out of 1 weighted PVSS tests which did a secret reconstruction via a size-1 multiexp in G2 failed intermittently. (This test was called `weighted_fail` at commit `5cd69cba8908b6676cf4481457aae93850b6245e`; it runs in a loop until it fails; sometimes it doesn't fail; most of the times it does though.)

We patched this by clumsily checking for the input size before calling `blstrs`'s multiexp wrapper.

### $g_1^0$ and $g_2^0$ multiexps can fail
test_crypto_g1_multiexp_less_points
See `test_crypto_g_2_to_zero_multiexp` and `test_crypto_g_1_to_zero_multiexp`.

### Multiexps with more exponents than bases fail. 

See `test_crypto_g1_multiexp_less_points`.

Instead, they should truncate the exponents to be the size of the bases.

```

**File:** dkg/src/transcript_aggregation/mod.rs (L65-101)
```rust
    fn add(
        &self,
        sender: Author,
        dkg_transcript: DKGTranscript,
    ) -> anyhow::Result<Option<Self::Aggregated>> {
        let DKGTranscript {
            metadata,
            transcript_bytes,
        } = dkg_transcript;
        ensure!(
            metadata.epoch == self.epoch_state.epoch,
            "[DKG] adding peer transcript failed with invalid node epoch",
        );

        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** testsuite/smoke-test/src/randomness/validator_restart_during_dkg.rs (L16-42)
```rust
#[tokio::test]
async fn validator_restart_during_dkg() {
    let epoch_duration_secs = 30;
    let estimated_dkg_latency_secs = 30;
    let time_limit_secs = epoch_duration_secs + estimated_dkg_latency_secs;
    let num_validators = 4;
    let num_validators_to_restart = 3;
    let mut swarm = SwarmBuilder::new_local(num_validators)
        .with_num_fullnodes(1)
        .with_aptos()
        .with_init_config(Arc::new(|_, conf, _| {
            conf.api.failpoints_enabled = true;
        }))
        .with_init_genesis_config(Arc::new(|conf| {
            conf.epoch_duration_secs = 30;

            // Ensure randomness is enabled.
            conf.consensus_config.enable_validator_txns();
            conf.randomness_config_override = Some(OnChainRandomnessConfig::default_enabled());
        }))
        .build()
        .await;

    swarm
        .wait_for_all_nodes_to_catchup_to_epoch(2, Duration::from_secs(epoch_duration_secs * 10))
        .await
        .unwrap();
```
