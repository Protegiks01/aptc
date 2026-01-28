# Audit Report

## Title
Integer Underflow in DKG Schnorr Proof Batch Verification Causes Validator Denial of Service

## Summary
A critical integer underflow vulnerability exists in the `pok_batch_verify()` function that allows a single Byzantine validator to crash or indefinitely hang all other validator nodes by sending a malicious DKG transcript with an empty proof-of-knowledge vector. This affects the DKG (Distributed Key Generation) protocol essential for randomness generation in Aptos, violating Byzantine fault tolerance guarantees.

## Finding Description

The vulnerability exists in the `pok_batch_verify()` function where it computes powers of gamma for batch verification. [1](#0-0) 

When `poks.len()` equals 0, the variable `n` becomes 0. At line 84, the expression `n - 1` in the range `0..(n - 1)` causes unsigned integer underflow since `usize` cannot represent negative values:
- **Debug mode**: Panics immediately with "attempt to subtract with overflow", crashing the validator process
- **Release mode**: Wraps to `usize::MAX` (approximately 2^64-1 or 18,446,744,073,709,551,615), creating a loop that iterates for an effectively infinite duration, causing the validator to hang indefinitely

**Attack Propagation Path:**

1. A Byzantine validator crafts a malicious DKG `Transcript` with `soks: vec![]` (empty vector). The codebase even provides a `dummy()` function demonstrating this is possible. [2](#0-1) 

2. The malicious validator serializes the transcript using BCS and sends it to other validators via the DKG message protocol.

3. Honest validators receive the transcript in `TranscriptAggregationState::add()`, which validates that the sender is a validator with voting power. [3](#0-2) 

4. The transcript is deserialized and verification begins. [4](#0-3) 

5. The `check_sizes()` validation does NOT check `soks` length - it only validates V, V_hat, R, R_hat, and C vector lengths. [5](#0-4) 

6. The `verify_transcript_extra()` function extracts dealers from `get_dealers()` which returns an empty vector when `soks` is empty. An empty dealer set passes validation when `checks_voting_power` is false (as it is during transcript aggregation). [6](#0-5) 

7. Verification proceeds to `verify()` which calls `batch_verify_soks()` with empty `soks`, `spks`, and `aux` vectors. [7](#0-6) 

8. The `batch_verify_soks()` function validates that vector lengths match but allows all vectors to be empty (0 == 0). [8](#0-7) 

9. Finally, `pok_batch_verify()` is called with an empty `poks` vector. [9](#0-8) 

10. The integer underflow triggers, causing the receiving honest validator to crash or hang.

**Broken Invariants:**
- **Byzantine Fault Tolerance**: A single Byzantine validator (<1/3 stake) can crash all honest validators, violating the core BFT guarantee that the system should tolerate up to 1/3 Byzantine actors
- **Resource Limits**: The infinite/near-infinite loop violates computational resource limits
- **Availability**: Honest validators become unavailable, breaking network liveness
- **Deterministic Execution**: Different build modes produce different behaviors (crash vs hang)

## Impact Explanation

**Critical Severity** per Aptos Bug Bounty criteria - **Total Loss of Liveness/Network Availability**:

- Any honest validator receiving the malicious transcript will crash (debug builds) or hang indefinitely (release builds), preventing DKG completion and randomness generation
- A single Byzantine validator can target all honest validators simultaneously by broadcasting the malicious transcript during DKG
- This prevents epoch transitions that require successful DKG execution, halting the network
- The vulnerability violates fundamental Byzantine fault tolerance assumptions - the system should tolerate up to 1/3 Byzantine validators without honest validators crashing

This qualifies as Critical severity because it causes complete validator unavailability due to a protocol bug, meeting the "Network halts due to protocol bug" criterion.

## Likelihood Explanation

**High Likelihood:**

- **Attacker requirements**: Any single Byzantine validator (< 1/3 stake) can execute the attack - the system is designed to tolerate such actors but fails to do so
- **Trivial exploit complexity**: Attacker only needs to construct a `Transcript` struct with an empty `soks` vector and serialize it using BCS
- **No additional defenses**: There are no checks preventing empty `soks` vectors throughout the entire verification pipeline
- **Deterministic outcome**: The attack reliably crashes or hangs every validator that attempts to verify the malicious transcript
- **Affects all validators**: Every validator running the vulnerable code will be affected when they receive and attempt to verify the malicious transcript

The attack is practical, deterministic, and requires minimal resources to execute. The only requirement is being a validator in the current validator set, which is an expected threat model component in Byzantine fault tolerance systems.

## Recommendation

Add validation to ensure `poks` vector is non-empty before computing gamma powers:

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
    
    // Add validation for empty vector
    if n == 0 {
        bail!("Cannot batch verify empty PoK vector");
    }
    
    let mut exps = Vec::with_capacity(2 * n + 1);
    let mut bases = Vec::with_capacity(2 * n + 1);
    // ... rest of function
}
```

Additionally, add validation in `check_sizes()` to ensure `soks` is non-empty:

```rust
fn check_sizes(&self, sc: &WeightedConfigBlstrs) -> anyhow::Result<()> {
    let W = sc.get_total_weight();
    
    if self.soks.is_empty() {
        bail!("Transcript must contain at least one signature of knowledge");
    }
    
    // ... rest of validation
}
```

## Proof of Concept

```rust
#[test]
fn test_integer_underflow_empty_poks() {
    use crate::pvss::schnorr::pok_batch_verify;
    use blstrs::{G1Projective, Scalar};
    
    // Create empty poks vector
    let empty_poks: Vec<(G1Projective, (G1Projective, Scalar))> = vec![];
    let g = G1Projective::generator();
    let gamma = Scalar::from(42u64);
    
    // This will panic in debug mode or hang indefinitely in release mode
    let result = pok_batch_verify(&empty_poks, &g, &gamma);
    
    // Test will never reach here in release mode due to infinite loop
    // In debug mode, it will panic before reaching this assertion
    assert!(result.is_err());
}
```

## Notes

This vulnerability demonstrates a critical failure in Byzantine fault tolerance. While the system is designed to tolerate up to 1/3 Byzantine validators, a single malicious validator can crash or hang all honest validators through this exploit. The root cause is the lack of input validation for empty vectors combined with an arithmetic operation that assumes non-empty input. The vulnerability affects the DKG protocol which is essential for randomness generation in Aptos, making this a network-critical issue.

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

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L302-309)
```rust
        batch_verify_soks::<G1Projective, A>(
            self.soks.as_slice(),
            g_1,
            &self.V[W],
            spks,
            auxs,
            sok_vrfy_challenge,
        )?;
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-455)
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
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L552-562)
```rust
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn dummy() -> Self {
        Self {
            soks: vec![],
            R: vec![],
            R_hat: vec![],
            V: vec![],
            V_hat: vec![],
            C: vec![],
        }
    }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L79-83)
```rust
        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
```

**File:** dkg/src/transcript_aggregation/mod.rs (L88-101)
```rust
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

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L70-76)
```rust
    let poks = soks
        .iter()
        .map(|(_, c, _, pok)| (*c, *pok))
        .collect::<Vec<(Gr, schnorr::PoK<Gr>)>>();

    // TODO(Performance): 128-bit exponents instead of powers of tau
    schnorr::pok_batch_verify::<Gr>(&poks, pk_base, &tau)?;
```
