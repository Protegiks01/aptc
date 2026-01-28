# Audit Report

## Title
DKG Transcript Panic on Empty Commitment Vectors Leading to Validator Denial of Service

## Summary
The DKG (Distributed Key Generation) weighted transcript implementation contains a panic vulnerability when processing malformed transcripts with empty commitment vectors. A Byzantine validator can craft a malformed transcript to crash other validators when the fast path feature is enabled, disrupting DKG execution and potentially preventing epoch transitions.

## Finding Description

The `Transcript` struct in the weighted DAS protocol contains commitment vectors `V_hat` representing cryptographic commitments to polynomial evaluations. The `get_dealt_public_key()` function unsafely accesses the last element using `.last().unwrap()` without checking if the vector is empty. [1](#0-0) 

When a DKG transcript is received from a peer validator, it follows this execution path:

1. **Deserialization without validation**: Transcripts are deserialized using BCS without validating vector sizes. [2](#0-1) 

2. **Early verification call**: The transcript aggregation logic calls `verify_transcript_extra()` before `verify_transcript()`. [3](#0-2) 

3. **Panic before size validation**: When fast path is enabled, `verify_transcript_extra()` calls `get_dealt_public_key()` to compare dealt public keys, which panics if `V_hat` is empty. [4](#0-3) 

4. **Size validation occurs too late**: The proper size validation in `check_sizes()` validates that `V_hat.len() == W + 1`, but this check only occurs within the `verify()` call inside `verify_transcript()`, which executes after the panic has already occurred. [5](#0-4) 

**Attack scenario**: A Byzantine validator crafts a `Transcripts` struct where `main.V_hat` is an empty vector. The transcript is serialized and broadcast to other validators. When honest validators with fast path enabled process this transcript, they panic at line 216 during the public key comparison check in `verify_transcript_extra()`, crashing before proper validation occurs.

The vulnerability exists because:
- BCS deserialization accepts empty vectors without validation [6](#0-5) 
- Input validation is performed in the wrong order (extra checks before size checks)
- The sender must be a validator with voting power, which is checked but does not prevent the attack [7](#0-6) 

## Impact Explanation

**Severity: High**

This vulnerability enables a Byzantine validator to crash other validators during DKG execution, breaking the liveness invariant. According to the Aptos bug bounty criteria, this qualifies as:
- **High Severity ($50,000)**: "Validator node slowdowns, API crashes, Significant protocol violations"

A panic crash is equivalent to or more severe than a slowdown, representing a significant availability issue. The impact is conditional on the fast path feature being enabled (controlled by on-chain configuration). When enabled, a single malformed transcript can cause all receiving validators to panic, disrupting the DKG protocol and potentially preventing epoch transitions.

This affects validator availability and DKG liveness, which are critical for epoch transitions and validator set updates in Aptos.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
1. Attacker must be a validator in the current validator set (verified by voting power checks)
2. Fast path must be enabled in on-chain configuration
3. Attacker must craft a malformed transcript with empty `V_hat` vector
4. Attack must occur during DKG phase

The technical barrier is low - crafting the malformed transcript requires only serializing a `Transcript` struct with empty vectors using BCS. The main limiting factor is that fast path is an optional feature that may not always be enabled.

Validators are expected to follow the < 1/3 Byzantine fault tolerance model, making this a realistic attack vector within the protocol's threat model.

## Recommendation

Perform size validation immediately after deserialization and before any access to vector elements. The fix should add an early size check in `verify_transcript_extra()` or modify `get_dealt_public_key()` to return a `Result`:

**Option 1**: Add early validation in `verify_transcript_extra()`:
```rust
fn verify_transcript_extra(
    trx: &Self::Transcript,
    verifier: &ValidatorVerifier,
    checks_voting_power: bool,
    ensures_single_dealer: Option<AccountAddress>,
) -> anyhow::Result<()> {
    // Add early size validation
    if trx.main.V_hat.is_empty() {
        bail!("Invalid transcript: V_hat is empty");
    }
    if let Some(fast_trx) = &trx.fast {
        if fast_trx.V_hat.is_empty() {
            bail!("Invalid transcript: fast V_hat is empty");
        }
    }
    // ... rest of function
}
```

**Option 2**: Make `get_dealt_public_key()` return a `Result`:
```rust
fn get_dealt_public_key(&self) -> anyhow::Result<Self::DealtPubKey> {
    self.V_hat.last()
        .map(|pk| Self::DealtPubKey::new(*pk))
        .ok_or_else(|| anyhow!("V_hat is empty"))
}
```

**Option 3**: Call `check_sizes()` before accessing vector elements in `verify_transcript_extra()`.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
    fn test_empty_v_hat_panic() {
        // Create a transcript with empty V_hat
        let malicious_transcript = Transcript {
            soks: vec![],
            R: vec![],
            R_hat: vec![],
            V: vec![],
            V_hat: vec![], // Empty vector
            C: vec![],
        };
        
        // This will panic
        let _ = malicious_transcript.get_dealt_public_key();
    }
}
```

To trigger the vulnerability in a real scenario, a Byzantine validator would:
1. Construct a `Transcripts` struct with `main.V_hat = vec![]`
2. Serialize it using BCS
3. Broadcast it during the DKG phase
4. All validators with fast path enabled will panic when processing this transcript

## Notes

This vulnerability is a classic input validation ordering issue where untrusted input is accessed before proper validation occurs. The fix should ensure that all size validations happen before any vector element access, following the principle of "validate early, fail fast."

The vulnerability is only exploitable when the fast path feature is enabled, as evidenced by the conditional check at line 324 of `types/src/dkg/real_dkg/mod.rs`. If fast path is disabled, the vulnerable code path is not executed and validators are protected by the size validation in `verify_transcript()`.

### Citations

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L82-90)
```rust
impl TryFrom<&[u8]> for Transcript {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: The `serde` implementation in `blstrs` already performs the necessary point validation
        // by ultimately calling `GroupEncoding::from_bytes`.
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
    }
}
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L215-217)
```rust
    fn get_dealt_public_key(&self) -> Self::DealtPubKey {
        Self::DealtPubKey::new(*self.V_hat.last().unwrap())
    }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L426-431)
```rust
        if self.V_hat.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V_hat.len()
            );
```

**File:** dkg/src/transcript_aggregation/mod.rs (L79-87)
```rust
        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );
```

**File:** dkg/src/transcript_aggregation/mod.rs (L88-90)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
```

**File:** dkg/src/transcript_aggregation/mod.rs (L96-101)
```rust
        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L324-327)
```rust
        if let Some(fast_trx) = &trx.fast {
            ensure!(fast_trx.get_dealers() == main_trx_dealers);
            ensure!(trx.main.get_dealt_public_key() == fast_trx.get_dealt_public_key());
        }
```
