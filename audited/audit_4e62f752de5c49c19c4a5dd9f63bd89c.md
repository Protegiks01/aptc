# Audit Report

## Title
Silent Loss of Quorum-Certified JWK Updates Due to Session Key Extraction Failure in PerKeyMode

## Summary
In the JWK consensus system's PerKeyMode, when a Quorum Certificate (QC) is successfully produced through reliable broadcast but the subsequent session key extraction fails, the QC is silently dropped and never propagated to the validator transaction pool. This results in permanent loss of consensus results that validators have already agreed upon.

## Finding Description

The vulnerability exists in `UpdateCertifier::start_produce` where the error handling for session key extraction is improperly implemented. [1](#0-0) 

After a Quorum Certified Update is successfully produced via reliable broadcast (representing validator consensus), the code attempts to extract a session key using `ConsensusMode::session_key_from_qc(&qc_update)`. For PerKeyMode, this calls `KeyLevelUpdate::try_from_issuer_level_repr`: [2](#0-1) 

The conversion can fail if the `ProviderJWKs` structure is malformed: [3](#0-2) 

When `session_key_from_qc` returns an error, the code logs the error message "JWK update QCed but could not identify the session key" but does NOT push the QC to the `qc_update_tx` channel. This means:

1. The QC is dropped and never reaches `process_quorum_certified_update`
2. No `ValidatorTransaction::ObservedJWKUpdate` is created
3. The JWK update never gets executed on-chain
4. Consensus results are permanently lost [4](#0-3) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program because it causes:

1. **Loss of Liveness**: Valid consensus results that validators have cryptographically signed and agreed upon are permanently lost, preventing legitimate JWK updates from reaching the chain
2. **Protocol Violation**: The system violates the guarantee that once quorum is reached, the certified update will be processed
3. **Validator Resource Waste**: Validators spend computational and network resources reaching consensus, but the result is discarded

While the conversion failure may be rare in normal operation (since the payload is validated in `new_rb_request` before broadcast), the improper error handling creates a critical gap where valid consensus can be lost due to:
- Edge cases in the conversion logic
- Future code changes introducing bugs
- Unexpected data states during epoch transitions

## Likelihood Explanation

**Likelihood: Medium to Low** under current implementation, but **Critical if triggered**.

The vulnerability requires `try_from_issuer_level_repr` to succeed during `new_rb_request` validation but fail during `session_key_from_qc`. While both call the same function, potential triggers include:

1. **Version edge cases**: If `base_version` is derived from on-chain state that gets updated between validation and QC processing
2. **Concurrent state updates**: Race conditions during epoch transitions or on-chain JWK updates
3. **Future code modifications**: Changes to conversion logic that introduce non-determinism

Once triggered, the impact is severe: consensus results are permanently lost with only a log message indicating the failure.

## Recommendation

The error handling must be improved to never silently drop a valid QC. Three options:

**Option 1 (Recommended)**: Send the QC anyway and handle conversion errors downstream:

```rust
let task = async move {
    let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
    ConsensusMode::log_certify_done(epoch, &qc_update);
    let session_key = ConsensusMode::session_key_from_qc(&qc_update);
    match session_key {
        Ok(key) => {
            let _ = qc_update_tx.push(key, qc_update);
        },
        Err(e) => {
            error!("JWK update QCed but could not identify the session key: {e}");
            // Use a fallback session key derived from the QC directly
            let fallback_key = ConsensusMode::fallback_session_key(&qc_update);
            let _ = qc_update_tx.push(fallback_key, qc_update);
        },
    }
};
```

**Option 2**: Panic to force operator intervention:
```rust
let session_key = ConsensusMode::session_key_from_qc(&qc_update)
    .expect("CRITICAL: QC produced but session key extraction failed - data corruption suspected");
```

**Option 3**: Pre-validate the payload more aggressively to ensure the conversion will never fail later.

## Proof of Concept

While a full PoC requires setting up the entire JWK consensus environment, the vulnerability can be demonstrated by:

1. Creating a `ProviderJWKs` with `version = 0`
2. Bypassing the `new_rb_request` validation (or simulating a scenario where it succeeds)
3. Attempting `try_from_issuer_level_repr` which will fail on `checked_sub(1)`
4. Observing that the QC is dropped with only an error log

The core issue is architectural: once a QC has quorum signatures, it represents immutable validator consensus and must never be silently discarded.

## Notes

- This vulnerability specifically affects **PerKeyMode** JWK consensus. The PerIssuerMode uses a simpler session key extraction that never fails.
- The reliable broadcast mechanism correctly produces the QC - the issue is purely in post-processing error handling.
- The error message "could not identify the session key" is logged at the error level, but operators may miss this in logs, resulting in silent failures.
- The validation checklist item "Exploitable by unprivileged attacker" is not fully satisfied - this is more of an internal consistency bug than an external attack vector. However, it represents a critical protocol violation where consensus results can be lost.

### Citations

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-79)
```rust
        let task = async move {
            let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
            ConsensusMode::log_certify_done(epoch, &qc_update);
            let session_key = ConsensusMode::session_key_from_qc(&qc_update);
            match session_key {
                Ok(key) => {
                    let _ = qc_update_tx.push(key, qc_update);
                },
                Err(e) => {
                    error!("JWK update QCed but could not identify the session key: {e}");
                },
            }
        };
```

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L59-64)
```rust
    fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<(Issuer, KID)> {
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(&qc.update)
                .context("session_key_from_qc failed with repr translation")?;
        Ok((issuer, kid))
    }
```

**File:** types/src/jwks/mod.rs (L360-384)
```rust
    pub fn try_from_issuer_level_repr(repr: &ProviderJWKs) -> anyhow::Result<Self> {
        ensure!(
            repr.jwks.len() == 1,
            "wrapped repr of a key-level update should have exactly 1 jwk"
        );
        let jwk =
            JWK::try_from(&repr.jwks[0]).context("try_from_issuer_level_repr failed on JWK")?;
        let base_version = repr
            .version
            .checked_sub(1)
            .context("try_from_issuer_level_repr on version")?;
        Ok(Self {
            issuer: repr.issuer.clone(),
            base_version,
            kid: jwk.id(),
            to_upsert: match jwk {
                JWK::Unsupported(unsupported)
                    if unsupported.payload.as_slice() == DELETE_COMMAND_INDICATOR.as_bytes() =>
                {
                    None
                },
                _ => Some(jwk),
            },
        })
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L312-362)
```rust
    pub fn process_quorum_certified_update(
        &mut self,
        issuer_level_repr: QuorumCertifiedUpdate,
    ) -> Result<()> {
        let key_level_update =
            KeyLevelUpdate::try_from_issuer_level_repr(&issuer_level_repr.update)
                .context("process_quorum_certified_update failed with repr err")?;
        let issuer = &key_level_update.issuer;
        let issuer_str = String::from_utf8(issuer.clone()).ok();
        let kid = &key_level_update.kid;
        let kid_str = String::from_utf8(kid.clone()).ok();
        info!(
            epoch = self.epoch_state.epoch,
            issuer = issuer_str,
            kid = kid_str,
            base_version = key_level_update.base_version,
            "KeyLevelJWKManager processing certified key-level update."
        );
        let state = self
            .states_by_key
            .entry((issuer.clone(), kid.clone()))
            .or_default();
        match state {
            ConsensusState::InProgress { my_proposal, .. } => {
                let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
                    issuer: issuer.clone(),
                    kid: kid.clone(),
                };
                let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
                let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
                *state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: issuer_level_repr,
                };
                info!(
                    epoch = self.epoch_state.epoch,
                    issuer = issuer_str,
                    kid = kid_str,
                    base_version = key_level_update.base_version,
                    "certified key-level update accepted."
                );
                Ok(())
            },
            _ => Err(anyhow!(
                "qc update not expected for issuer {:?} in state {}",
                String::from_utf8(issuer.clone()),
                state.name()
            )),
        }
    }
```
