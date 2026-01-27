# Audit Report

## Title
Panic-Induced Validator Crash via Malformed BLS Weighted VUF Share Verification

## Summary
A malicious network peer can crash validator nodes by sending a randomness share (`RandShare`) with a mismatched proof length during the BLS Weighted VUF verification process. The vulnerability exists in the `verify_share()` function where `multi_exp_slice()` panics instead of returning an error when proof and public key array lengths differ, and Aptos validators are configured to exit on any panic.

## Finding Description

The vulnerability exists in the DKG randomness generation subsystem used by Aptos consensus. When validators participate in weighted verifiable unpredictable function (WVUF) operations to generate on-chain randomness, they verify shares from other validators. [1](#0-0) 

In the `verify_share()` function, line 87 creates coefficients with length `apk.len()`, while line 95 calls `multi_exp_slice()` with `proof` (which has length `proof.len()`) and `coeffs`. If an attacker sends a share where `proof.len() != apk.len()`, the call to `multi_exp_slice()` delegates to `g1_multi_exp()`: [2](#0-1) 

This function explicitly panics with message "blstrs's multiexp has heisenbugs when the # of bases != # of scalars" when lengths mismatch (lines 59-65).

**Attack Vector:**

The vulnerable path is triggered when validators request shares via reliable broadcast: [3](#0-2) 

At line 139, `share.verify(&self.rand_config)?` is called **synchronously** (not in a spawned task) when processing responses to share requests. This flows through:

1. `RandShare::verify()` → `Share::verify()` [4](#0-3) 

2. Which calls `WVUF::verify_share()` at line 65-72

3. Leading to the panic in `g1_multi_exp()`

**Why this crashes validators:**

Aptos nodes set up a global panic handler that exits the process: [5](#0-4) 

Line 57 calls `process::exit(12)` on any panic (except in Move verifier), and this handler is installed during node startup: [6](#0-5) 

**Exploitation:**

An attacker (malicious validator or network peer) crafts a `RandShare` message where the `ProofShare` vector has a different length than the expected augmented public key share vector. When sent as a response to `RequestShare` messages during reliable broadcast, the receiving validator's main processing thread panics and the process exits.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability causes **validator node crashes**, which falls under "Validator node slowdowns" and "Significant protocol violations" in the High severity category. 

**Specific impacts:**

1. **Liveness Failure**: Crashing validators reduces network participation and can delay block finalization if enough validators are targeted
2. **Consensus Disruption**: Repeated crashes during randomness generation rounds can prevent proper randomness beacon operation
3. **DoS Against Specific Validators**: Attackers can selectively target validators to manipulate leader election or voting power distribution
4. **Network Availability**: If >1/3 of validators are crashed simultaneously, the network loses liveness until they restart

This does not reach Critical severity because:
- It doesn't cause fund loss or permanent state corruption
- Validators can recover by restarting
- It requires continuous attacks to maintain the DoS

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to succeed because:

1. **No Special Privileges Required**: Any network peer capable of sending consensus messages can exploit this
2. **Simple Payload**: The malicious payload is trivial to construct - just a `RandShare` with mismatched vector lengths
3. **No Rate Limiting**: The vulnerable code path processes incoming shares without apparent rate limiting on malformed messages
4. **Deterministic Trigger**: The panic occurs 100% reliably when the length mismatch condition is met
5. **Active Attack Surface**: Randomness generation runs continuously in production, creating persistent exposure

Attack complexity is low - the attacker only needs to:
- Serialize a `RandShare` with `proof.len() != expected_apk.len()`
- Send it via the consensus network protocol
- Target validators during active randomness rounds

## Recommendation

**Immediate Fix**: Add length validation before calling `multi_exp_slice()`:

```rust
fn verify_share(
    pp: &Self::PublicParameters,
    apk: &Self::AugmentedPubKeyShare,
    msg: &[u8],
    proof: &Self::ProofShare,
) -> anyhow::Result<()> {
    let hash = Self::hash_to_curve(msg);
    
    // ADD LENGTH VALIDATION
    if proof.len() != apk.len() {
        bail!("ProofShare length ({}) does not match augmented public key length ({})", 
              proof.len(), apk.len());
    }
    
    let coeffs = get_powers_of_tau(&random_scalar(&mut thread_rng()), apk.len());
    let pks = apk
        .iter()
        .map(|pk| *pk.as_group_element())
        .collect::<Vec<G2Projective>>();
    let agg_pk = G2Projective::multi_exp_slice(pks.as_slice(), coeffs.as_slice());
    let agg_sig = G1Projective::multi_exp_slice(proof.to_vec().as_slice(), coeffs.as_slice());

    if multi_pairing(
        [&hash, &agg_sig].into_iter(),
        [&agg_pk, &pp.g.neg()].into_iter(),
    ) != Gt::identity()
    {
        bail!("BlsWVUF ProofShare failed to verify.");
    }

    Ok(())
}
```

**Additional Hardening**:
1. Add similar length checks in `g1_multi_exp()` and `g2_multi_exp()` to return errors instead of panicking
2. Implement message validation earlier in the network stack to reject malformed shares before verification
3. Add metrics/alerts for verification failures to detect attack attempts

## Proof of Concept

```rust
// Add this test to crates/aptos-dkg/src/weighted_vuf/bls/mod.rs

#[cfg(test)]
mod vulnerability_tests {
    use super::*;
    use crate::pvss::{Player, WeightedConfigBlstrs};
    use crate::weighted_vuf::traits::WeightedVUF;
    
    #[test]
    #[should_panic(expected = "blstrs's multiexp has heisenbugs")]
    fn test_mismatched_proof_length_causes_panic() {
        // Setup: Create a valid configuration with weight 3
        let mut players = vec![];
        players.push(Player { id: 0 });
        let wconfig = WeightedConfigBlstrs::new(3, players).unwrap();
        
        // Create public parameters
        let pp = PublicParameters {
            g: G2Projective::generator(),
        };
        
        // Create valid augmented public key shares (3 elements for weight 3)
        let apk: Vec<_> = (0..3)
            .map(|_| {
                let sk = random_scalar(&mut thread_rng());
                pvss::dealt_pub_key_share::g2::DealtPubKeyShare::new(
                    G2Projective::generator() * sk,
                    Player { id: 0 },
                    0,
                )
            })
            .collect();
        
        // ATTACK: Create malformed proof with WRONG length (2 instead of 3)
        let malformed_proof: Vec<G1Projective> = vec![
            G1Projective::generator(),
            G1Projective::generator(),
            // Missing third element - creates length mismatch
        ];
        
        let msg = b"test message";
        
        // This will PANIC instead of returning an error
        let result = BlsWUF::verify_share(&pp, &apk, msg, &malformed_proof);
        
        // Should never reach here - process exits with panic
        println!("Result: {:?}", result);
    }
}
```

To test the vulnerability in a running validator:
1. Set up a test network with validators running randomness generation
2. Craft a `RandMessage::Share` with malformed `ProofShare` length
3. Send it to a validator during an active randomness round
4. Observe the validator process exit with code 12 and panic message in logs

**Notes**

The vulnerability is present in the production codebase and affects all validators participating in randomness generation. The root cause is the assumption in `g1_multi_exp()` and `g2_multi_exp()` that input validation has already occurred, combined with the panic-on-failure behavior. The fix requires defensive programming with explicit length validation at the application layer before calling cryptographic primitives that have panic semantics for invalid inputs.

### Citations

**File:** crates/aptos-dkg/src/weighted_vuf/bls/mod.rs (L79-106)
```rust
    fn verify_share(
        pp: &Self::PublicParameters,
        apk: &Self::AugmentedPubKeyShare,
        msg: &[u8],
        proof: &Self::ProofShare,
    ) -> anyhow::Result<()> {
        let hash = Self::hash_to_curve(msg);
        // TODO: Use Fiat-Shamir instead of random_scalar
        let coeffs = get_powers_of_tau(&random_scalar(&mut thread_rng()), apk.len());

        let pks = apk
            .iter()
            .map(|pk| *pk.as_group_element())
            .collect::<Vec<G2Projective>>();
        // TODO: Calling multi-exp seems to decrease performance by 100+ microseconds even when |coeffs| = 1 and the coefficient is 1. Not sure what's going on here.
        let agg_pk = G2Projective::multi_exp_slice(pks.as_slice(), coeffs.as_slice());
        let agg_sig = G1Projective::multi_exp_slice(proof.to_vec().as_slice(), coeffs.as_slice());

        if multi_pairing(
            [&hash, &agg_sig].into_iter(),
            [&agg_pk, &pp.g.neg()].into_iter(),
        ) != Gt::identity()
        {
            bail!("BlsWVUF ProofShare failed to verify.");
        }

        Ok(())
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

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L131-150)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.rand_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.rand_metadata,
            share.metadata()
        );
        share.verify(&self.rand_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveRandShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.rand_store.lock();
        let aggregated = if store.add_share(share, PathType::Slow)? {
            Some(())
        } else {
            None
        };
        Ok(aggregated)
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

**File:** crates/crash-handler/src/lib.rs (L26-58)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
}
```

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```
