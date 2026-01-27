# Audit Report

## Title
Lack of JWK Validation Before Consensus Enables Deterministic Execution Failures in Validator Transactions

## Summary
The `log_certify_start()` function in the JWK consensus module does not validate JWKMoveStruct entries before they are logged, signed, and propagated through consensus. Malformed JWK entries can pass through all consensus stages undetected and only fail during Move VM execution, causing validator transactions to abort. While this doesn't cause consensus divergence (failures are deterministic), it can prevent JWK updates from being applied on-chain.

## Finding Description
The JWK consensus system lacks input validation at critical checkpoints. When a validator observes JWK updates from OIDC providers, the data flows through the following path:

1. **Observation**: JWKs are fetched and converted to `JWKMoveStruct` via infallible conversions [1](#0-0) 

2. **Logging without validation**: `log_certify_start()` logs the payload without any semantic validation of the JWK entries [2](#0-1) 

3. **Consensus**: The `ProviderJWKs` is signed and propagated through reliable broadcast [3](#0-2) 

4. **Execution**: Only when the Move function `upsert_into_observed_jwks` is called does validation occur via `get_jwk_id()` [4](#0-3) 

If a JWKMoveStruct has a malformed `variant` field with an unrecognized type name or corrupted BCS data, the Move function will abort [5](#0-4) . This causes the `copyable_any::unpack` operation to fail, resulting in an unexpected Move abort that propagates as an error [6](#0-5) .

## Impact Explanation
This issue qualifies as **Medium severity** under the Aptos bug bounty criteria for the following reasons:

- **State Inconsistencies**: Failed JWK updates prevent the on-chain `ObservedJWKs` resource from being updated, causing a divergence between observed off-chain JWKs and on-chain state
- **Keyless Authentication Availability**: Stale JWKs can affect keyless authentication functionality, as the system relies on up-to-date JWKs for signature verification
- **Deterministic Failure**: All validators experience the same failure, so there's no consensus divergence, but the validator transaction is discarded
- **No Consensus Safety Violation**: The deterministic nature prevents chain splits or double-spending

The impact is limited because:
- No fund loss occurs
- Consensus safety is maintained (all nodes fail identically)
- The issue requires a code bug, version mismatch, or operational anomaly to manifest

## Likelihood Explanation
**Low likelihood** - The vulnerability requires one of these scenarios:

1. **Code bugs in JWK conversion**: A bug in the `From<JWK>` implementation for `JWKMoveStruct` that creates invalid `MoveAny` wrappers
2. **Version mismatch**: Rust and Move struct definitions getting out of sync during framework upgrades
3. **Memory corruption**: Unlikely in safe Rust code
4. **Malicious validator with insider access**: Could theoretically craft malformed JWKs, but other validators would reject due to view mismatch [7](#0-6) 

Normal OIDC provider responses are parsed infallibly into either `RSA_JWK` or `UnsupportedJWK` variants [8](#0-7) , making legitimate JWK observation safe.

## Recommendation
Add defensive validation before consensus to fail fast:

```rust
// In crates/aptos-jwk-consensus/src/mode/per_issuer.rs
fn log_certify_start(epoch: u64, payload: &ProviderJWKs) {
    // Add validation here
    if let Err(e) = validate_jwks(payload) {
        error!(
            epoch = epoch,
            issuer = String::from_utf8(payload.issuer.clone()).ok(),
            error = ?e,
            "Invalid JWKs detected before consensus"
        );
        return;
    }
    
    info!(
        epoch = epoch,
        issuer = String::from_utf8(payload.issuer.clone()).ok(),
        version = payload.version,
        "Start certifying update."
    );
}

fn validate_jwks(payload: &ProviderJWKs) -> anyhow::Result<()> {
    // Attempt to convert each JWKMoveStruct to JWK
    for jwk_move in payload.jwks.iter() {
        JWK::try_from(jwk_move)
            .context("JWK validation failed")?;
    }
    Ok(())
}
```

This validation leverages the existing `TryFrom<&JWKMoveStruct> for JWK` implementation [9](#0-8)  to catch malformed entries before they enter consensus.

## Proof of Concept
This vulnerability cannot be easily demonstrated with a standard PoC because it requires artificially creating malformed `JWKMoveStruct` entries, which the normal code paths prevent. A theoretical test would need to:

1. Manually construct a `JWKMoveStruct` with an invalid `MoveAny` variant
2. Serialize it into a `ProviderJWKs`
3. Process it through the consensus flow
4. Observe the Move VM abort during execution

However, such a test would require bypassing Rust's type safety and deliberately corrupting data structures, which represents a code bug rather than an exploitable attack vector.

## Notes
After thorough analysis, while the lack of validation is a defensive programming weakness, this issue does **not meet the strict criteria for an exploitable vulnerability** because:

- There is no realistic attack path for an unprivileged attacker to inject malformed JWKs
- The only failure scenarios involve code bugs or operational issues, not deliberate exploits
- Normal operation through OIDC provider observation creates valid JWKs
- Malicious validators cannot inject arbitrary malformed data due to view matching requirements

This represents a **code quality and defensive programming issue** rather than a security vulnerability exploitable by external attackers. The recommendation to add validation is still valid for operational robustness and fail-fast behavior during upgrades or edge cases.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L151-151)
```rust
                    let jwks = jwks.into_iter().map(JWKMoveStruct::from).collect();
```

**File:** crates/aptos-jwk-consensus/src/mode/per_issuer.rs (L14-21)
```rust
    fn log_certify_start(epoch: u64, payload: &ProviderJWKs) {
        info!(
            epoch = epoch,
            issuer = String::from_utf8(payload.issuer.clone()).ok(),
            version = payload.version,
            "Start certifying update."
        );
    }
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L58-66)
```rust
        ConsensusMode::log_certify_start(epoch_state.epoch, &payload);
        let rb = self.reliable_broadcast.clone();
        let epoch = epoch_state.epoch;
        let req = ConsensusMode::new_rb_request(epoch, &payload)
            .context("UpdateCertifier::start_produce failed at rb request construction")?;
        let agg_state = Arc::new(ObservationAggregationState::<ConsensusMode>::new(
            epoch_state,
            payload,
        ));
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L562-573)
```text
    fun get_jwk_id(jwk: &JWK): vector<u8> {
        let variant_type_name = *string::bytes(copyable_any::type_name(&jwk.variant));
        if (variant_type_name == b"0x1::jwks::RSA_JWK") {
            let rsa = copyable_any::unpack<RSA_JWK>(jwk.variant);
            *string::bytes(&rsa.kid)
        } else if (variant_type_name == b"0x1::jwks::UnsupportedJWK") {
            let unsupported = copyable_any::unpack<UnsupportedJWK>(jwk.variant);
            unsupported.id
        } else {
            abort(error::invalid_argument(EUNKNOWN_JWK_VARIANT))
        }
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L90-96)
```rust
            Err(Unexpected(vm_status)) => {
                debug!(
                    "Processing jwk transaction unexpected failure: {:?}",
                    vm_status
                );
                Err(vm_status)
            },
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L82-84)
```rust
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** crates/jwk-utils/src/lib.rs (L35-36)
```rust
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
```

**File:** types/src/jwks/jwk/mod.rs (L102-122)
```rust
impl TryFrom<&JWKMoveStruct> for JWK {
    type Error = anyhow::Error;

    fn try_from(value: &JWKMoveStruct) -> Result<Self, Self::Error> {
        match value.variant.type_name.as_str() {
            RSA_JWK::MOVE_TYPE_NAME => {
                let rsa_jwk =
                    MoveAny::unpack(RSA_JWK::MOVE_TYPE_NAME, value.variant.clone()).map_err(|e|anyhow!("converting from jwk move struct to jwk failed with move any to rsa unpacking error: {e}"))?;
                Ok(Self::RSA(rsa_jwk))
            },
            UnsupportedJWK::MOVE_TYPE_NAME => {
                let unsupported_jwk =
                    MoveAny::unpack(UnsupportedJWK::MOVE_TYPE_NAME, value.variant.clone()).map_err(|e|anyhow!("converting from jwk move struct to jwk failed with move any to unsupported unpacking error: {e}"))?;
                Ok(Self::Unsupported(unsupported_jwk))
            },
            _ => Err(anyhow!(
                "converting from jwk move struct to jwk failed with unknown variant"
            )),
        }
    }
}
```
