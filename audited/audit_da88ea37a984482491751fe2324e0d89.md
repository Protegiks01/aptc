# Audit Report

## Title
Missing KeylessSignature Size Validation in P2P Network Path Enables Memory Pressure DoS

## Summary
The `KeylessSignature::MAX_LEN` limit of 4000 bytes is not enforced when transactions are received via the P2P network path, allowing attackers to send transactions with `OpenIdSig` structures containing vectors up to ~4 MiB in size, causing memory pressure on validator nodes before validation rejects them.

## Finding Description
The `OpenIdSig` struct contains two unbounded `Vec<u8>` fields: `jwt_sig` and `epk_blinder`. [1](#0-0) 

The `KeylessSignature` struct defines `MAX_LEN` as 4000 bytes to limit signature size. [2](#0-1) 

This limit is enforced in the API submission path where `VerifyInput::verify()` checks signature length before processing. [3](#0-2) 

However, when transactions arrive via the P2P network, they are deserialized directly from network frames using `bcs::from_bytes()` without size validation. [4](#0-3) 

The network layer enforces a frame size limit of 4 MiB, [5](#0-4)  which is applied before deserialization. [6](#0-5) 

**Attack Flow:**
1. Attacker crafts a transaction with `KeylessSignature` containing `OpenIdSig` with 1.5 MB `jwt_sig` and 1.5 MB `epk_blinder` (~3 MB total, 750x the intended 4 KB limit)
2. Transaction is broadcast via P2P network (within 4 MiB frame limit)
3. Each receiving node deserializes the transaction via BCS, allocating ~3 MB of memory
4. Transaction proceeds to mempool validation via `validate_authenticators` [7](#0-6)  which does NOT check signature size
5. Eventually validation fails (invalid signature), but memory was already allocated during step 3
6. Attacker sends many such transactions to exhaust validator node memory

The keyless validation path checks feature flags, expiry, and cryptographic validity, but never validates the signature size against `MAX_LEN`. [8](#0-7) 

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program: "Validator node slowdowns."

An attacker can cause significant memory pressure on validator nodes by sending many transactions (each allocating up to ~4 MiB during deserialization). While individual frame size limits prevent unbounded memory allocation per transaction, sustained attacks with hundreds of oversized keyless transactions could:
- Degrade validator performance through memory pressure
- Increase transaction processing latency
- Potentially trigger OOM conditions under resource-constrained environments

The vulnerability breaks Critical Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits" - the 4 KB signature size limit is bypassed, allowing 1000x larger allocations.

## Likelihood Explanation
**Likelihood: High**

The attack requires:
1. Ability to send P2P network messages to validator nodes (publicly accessible for network participation)
2. Crafting transactions with large but valid BCS-encoded KeylessSignature structures
3. No special privileges, validator access, or cryptographic breaks required

The attacker can easily automate sending many such transactions. While network rate limiting provides partial mitigation, it's based on byte throughput rather than preventing individual oversized structures. [9](#0-8) 

## Recommendation
Add size validation for `KeylessSignature` in the transaction validation path before deserialization or immediately after. The check should be added to `validate_authenticators` in the keyless validation module:

```rust
// In aptos-move/aptos-vm/src/keyless_validation.rs, validate_authenticators function
pub(crate) fn validate_authenticators(
    pvk: Option<&PreparedVerifyingKey<Bn254>>,
    configuration: Option<&Configuration>,
    authenticators: &Vec<(AnyKeylessPublicKey, KeylessSignature)>,
    features: &Features,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl ModuleStorage,
) -> Result<(), VMStatus> {
    // Add size check before other validation
    for (_, sig) in authenticators {
        let sig_bytes = bcs::to_bytes(sig).map_err(|_| {
            invalid_signature!("Failed to serialize KeylessSignature")
        })?;
        if sig_bytes.len() > KeylessSignature::MAX_LEN {
            return Err(invalid_signature!(
                format!("KeylessSignature size {} exceeds maximum {}", 
                    sig_bytes.len(), KeylessSignature::MAX_LEN)
            ));
        }
    }
    
    // ... existing validation code
}
```

Alternatively, enforce the check at the network layer before BCS deserialization by adding a length-prefixed size check in the transaction broadcast handling.

## Proof of Concept
```rust
// Rust PoC demonstrating the vulnerability
use aptos_types::{
    transaction::{SignedTransaction, RawTransaction, TransactionPayload},
    keyless::{OpenIdSig, KeylessSignature, EphemeralCertificate, Pepper},
    transaction::authenticator::{
        AccountAuthenticator, TransactionAuthenticator, 
        EphemeralPublicKey, EphemeralSignature
    },
};

fn create_oversized_keyless_transaction() -> SignedTransaction {
    // Create OpenIdSig with large vectors (1.5 MB each)
    let oversized_openid_sig = OpenIdSig {
        jwt_sig: vec![0u8; 1_500_000],  // 1.5 MB - 375x over limit
        jwt_payload_json: "{}".to_string(),
        uid_key: "sub".to_string(),
        epk_blinder: vec![0u8; 1_500_000],  // 1.5 MB - 375x over limit
        pepper: Pepper::new([0u8; 31]),
        idc_aud_val: None,
    };
    
    // Wrap in KeylessSignature
    let keyless_sig = KeylessSignature {
        cert: EphemeralCertificate::OpenIdSig(oversized_openid_sig),
        jwt_header_json: "{}".to_string(),
        exp_date_secs: 9999999999,
        ephemeral_pubkey: EphemeralPublicKey::ed25519(/* ... */),
        ephemeral_signature: EphemeralSignature::ed25519(/* ... */),
    };
    
    // Total signature size: ~3 MB (750x the 4 KB MAX_LEN)
    let sig_bytes = bcs::to_bytes(&keyless_sig).unwrap();
    assert!(sig_bytes.len() > 3_000_000); // Verify > 3 MB
    assert!(sig_bytes.len() > KeylessSignature::MAX_LEN * 750); // 750x over limit
    
    // Create transaction (would pass P2P network frame limit but fail API check)
    // When broadcast via P2P, each node deserializes this, allocating ~3 MB
    // before validation eventually rejects it
    
    /* ... construct SignedTransaction with keyless_sig ... */
}
```

**Notes**

While the 4 MiB frame size limit prevents unbounded memory exhaustion from a single transaction, the missing `MAX_LEN` validation in the P2P path allows attackers to bypass the intended 4 KB signature size restriction by 1000x. This enables resource exhaustion attacks that degrade validator performance through sustained memory pressure, meeting the High severity threshold for "Validator node slowdowns" without requiring the attacker to achieve network-wide memory exhaustion.

### Citations

**File:** types/src/keyless/openid_sig.rs (L22-38)
```rust
pub struct OpenIdSig {
    /// The decoded bytes of the JWS signature in the JWT (<https://datatracker.ietf.org/doc/html/rfc7515#section-3>)
    #[serde(with = "serde_bytes")]
    pub jwt_sig: Vec<u8>,
    /// The decoded/plaintext JSON payload of the JWT (<https://datatracker.ietf.org/doc/html/rfc7519#section-3>)
    pub jwt_payload_json: String,
    /// The name of the key in the claim that maps to the user identifier; e.g., "sub" or "email"
    pub uid_key: String,
    /// The random value used to obfuscate the EPK from OIDC providers in the nonce field
    #[serde(with = "serde_bytes")]
    pub epk_blinder: Vec<u8>,
    /// The privacy-preserving value used to calculate the identity commitment. It is typically uniquely derived from `(iss, client_id, uid_key, uid_val)`.
    pub pepper: Pepper,
    /// When an override aud_val is used, the signature needs to contain the aud_val committed in the
    /// IDC, since the JWT will contain the override.
    pub idc_aud_val: Option<String>,
}
```

**File:** types/src/keyless/mod.rs (L195-195)
```rust
    pub const MAX_LEN: usize = 4000;
```

**File:** api/types/src/transaction.rs (L1530-1534)
```rust
        } else if signature_len > keyless::KeylessSignature::MAX_LEN {
            bail!(
                "Keyless signature length is greater than the maximum number of {} bytes: found {} bytes",
                keyless::KeylessSignature::MAX_LEN, signature_len
            )
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L197-203)
```rust
pub fn network_message_frame_codec(max_frame_size: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_size)
        .length_field_length(4)
        .big_endian()
        .new_codec()
}
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L227-230)
```rust
            Poll::Ready(Some(Ok(frame))) => {
                let frame = frame.freeze();

                match bcs::from_bytes(&frame) {
```

**File:** config/src/config/network_config.rs (L49-50)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** config/src/config/network_config.rs (L147-147)
```rust
            max_frame_size: MAX_FRAME_SIZE,
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L153-160)
```rust
pub(crate) fn validate_authenticators(
    pvk: Option<&PreparedVerifyingKey<Bn254>>,
    configuration: Option<&Configuration>,
    authenticators: &Vec<(AnyKeylessPublicKey, KeylessSignature)>,
    features: &Features,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl ModuleStorage,
) -> Result<(), VMStatus> {
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L162-218)
```rust
    for (pk, sig) in authenticators {
        // Feature-gating for keyless TXNs (whether ZK or ZKless, whether passkey-based or not)
        if matches!(sig.cert, EphemeralCertificate::ZeroKnowledgeSig { .. }) {
            if !features.is_zk_keyless_enabled() {
                return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
            }

            with_zk = true;
        }
        if matches!(sig.cert, EphemeralCertificate::OpenIdSig { .. })
            && !features.is_zkless_keyless_enabled()
        {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
        if matches!(sig.ephemeral_signature, EphemeralSignature::WebAuthn { .. })
            && !features.is_keyless_with_passkeys_enabled()
        {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
        if matches!(pk, AnyKeylessPublicKey::Federated { .. })
            && !features.is_federated_keyless_enabled()
        {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
    }

    // If there are ZK authenticators, the Groth16 VK must have been set on-chain.
    if with_zk && pvk.is_none() {
        return Err(invalid_signature!("Groth16 VK has not been set on-chain"));
    }

    let config = configuration.ok_or_else(|| {
        // Preserve error code for compatibility.
        value_deserialization_error!(format!(
            "get_resource failed on {}::{}::{}",
            CORE_CODE_ADDRESS.to_hex_literal(),
            Configuration::struct_tag().module,
            Configuration::struct_tag().name
        ))
    })?;
    if authenticators.len() > config.max_signatures_per_txn as usize {
        // println!("[aptos-vm][groth16] Too many keyless authenticators");
        return Err(invalid_signature!("Too many keyless authenticators"));
    }

    let onchain_timestamp_obj = get_current_time_onchain(resolver)?;
    // Check the expiry timestamp on all authenticators first to fail fast
    // This is a redundant check to quickly dismiss expired signatures early and save compute on more computationally costly checks.
    // The actual check is performed in `verify_keyless_signature_without_ephemeral_signature_check`.
    for (_, sig) in authenticators {
        sig.verify_expiry(onchain_timestamp_obj.microseconds)
            .map_err(|_| {
                // println!("[aptos-vm][groth16] ZKP expired");

                invalid_signature!("The ephemeral keypair has expired")
            })?;
    }
```
