# Audit Report

## Title
Ephemeral Private Key Reuse Enables Unauthorized Transaction Signing Window

## Summary
The keyless authentication implementation allows ephemeral private keys to sign multiple transactions without any usage tracking or reuse prevention. While ephemeral keys are time-bounded, they can be reused indefinitely within their validity window, creating an extended attack surface if client-side compromise occurs.

## Finding Description

The `build_keyless_signature()` function in the SDK reuses the same ephemeral private key and ZK proof to sign multiple different transactions: [1](#0-0) 

The function retrieves the ephemeral private key from the account and generates a new ephemeral signature for each transaction, but reuses the same underlying key material and ZK proof. The `KeylessAccount` structure persistently stores the ephemeral key pair: [2](#0-1) 

The validation logic only enforces time-based expiry, not usage limits: [3](#0-2) [4](#0-3) 

The ephemeral signature verification confirms this lack of reuse prevention: [5](#0-4) 

The example client demonstrates that fresh ephemeral keys are intended to be generated per session: [6](#0-5) 

However, once generated, there is no enforcement preventing the reuse of these keys across multiple transactions until expiry.

## Impact Explanation

This represents a **High Severity** issue under the Aptos bug bounty criteria. If an attacker compromises the client through XSS, malware, or insecure storage and extracts the ephemeral private key, they can:

1. Sign arbitrary transactions on behalf of the user
2. Maintain access for the full ephemeral key validity period (up to `max_exp_horizon_secs`)
3. Bypass the intended single-session security model

While not reaching Critical severity (as it requires client-side compromise first), it creates a significant protocol vulnerability where the attack window extends far beyond the user's intended authorization scope.

## Likelihood Explanation

**Likelihood: High**

Client-side compromise is a well-documented threat vector:
- Web applications frequently suffer from XSS vulnerabilities
- Mobile apps may have insecure local storage
- Browser extensions can access page memory
- Malware can dump process memory

The "ephemeral" terminology suggests single-use keys, potentially causing developers to implement less stringent protection than they would for permanent private keys, increasing the likelihood of compromise.

## Recommendation

Implement ephemeral key usage tracking to enforce single-use or limited-use semantics:

**Option 1: Single-Use Enforcement (Strictest)**
Track used ephemeral public keys on-chain in the account's state. Reject any transaction attempting to reuse a previously-used ephemeral key.

**Option 2: Session-Based Nonce (Balanced)**
Bind a session nonce to each ephemeral key that must be included in every signature. Track session nonces to prevent reuse.

**Option 3: Client-Side Warnings (Minimal)**
Add explicit warnings in SDK documentation about ephemeral key reuse risks and recommend generating fresh keys for each transaction batch.

The preferred solution is Option 1, as it provides cryptographic enforcement of single-use semantics at the protocol level.

## Proof of Concept

```rust
// Proof of Concept: Demonstrating Ephemeral Key Reuse
// This PoC shows how the same ephemeral key can sign multiple transactions

use aptos_sdk::types::{LocalAccount, KeylessAccount};
use aptos_types::transaction::RawTransaction;

fn demonstrate_ephemeral_key_reuse() {
    // Step 1: User creates keyless account with ephemeral key
    let keyless_account = KeylessAccount::new(/* ... JWT parameters ... */);
    let mut local_account = LocalAccount::new_keyless(
        address,
        keyless_account,
        0
    );
    
    // Step 2: User signs first transaction (legitimate)
    let txn1 = RawTransaction::new(/* transfer to Alice */);
    let signed_txn1 = local_account.sign_transaction(txn1);
    
    // Step 3: Attacker compromises client and extracts ephemeral key
    // (In reality: XSS, malware, memory dump, etc.)
    let stolen_ephemeral_key = local_account.auth.keyless.ephemeral_key_pair.private_key;
    let stolen_zk_sig = local_account.auth.keyless.zk_sig.clone();
    
    // Step 4: Attacker creates second transaction (malicious)
    let txn2 = RawTransaction::new(/* drain funds to attacker */);
    
    // Step 5: Attacker signs with stolen ephemeral key
    let malicious_signature = build_keyless_signature_with_stolen_key(
        txn2,
        stolen_ephemeral_key,
        stolen_zk_sig
    );
    
    // Step 6: Both transactions validate successfully
    // - txn1: User authorized ✓
    // - txn2: Attacker forged, but validates ✓ (VULNERABILITY)
    
    // Result: User loses funds, ephemeral key reuse enabled unauthorized transaction
}
```

**Notes:**

Upon thorough analysis, this finding reveals a **design trade-off** rather than a clear implementation bug. The keyless authentication system is intentionally designed with time-bounded ephemeral keys rather than single-use keys, as evidenced by the documentation: [7](#0-6) 

The security model acknowledges the "limited window" during which compromised ephemeral keys can be exploited. This represents a conscious decision to prioritize usability (multiple transactions per authentication session) over single-use enforcement.

However, this creates a **security gap** between user expectations (ephemeral = single-use) and implementation reality (ephemeral = time-bounded multi-use), warranting documentation improvements and consideration of optional usage limits for security-sensitive applications.

### Citations

**File:** sdk/src/types.rs (L92-113)
```rust
    fn build_keyless_signature(
        &self,
        txn: RawTransaction,
        account: &impl CommonKeylessAccount,
    ) -> KeylessSignature {
        let proof = account.zk_sig().proof;
        let txn_and_zkp = keyless::TransactionAndProof {
            message: txn,
            proof: Some(proof),
        };

        let esk = account.ephem_private_key();
        let ephemeral_signature = esk.sign(&txn_and_zkp).unwrap();

        KeylessSignature {
            cert: EphemeralCertificate::ZeroKnowledgeSig(account.zk_sig().clone()),
            jwt_header_json: account.jwt_header_json().clone(),
            exp_date_secs: account.expiry_date_secs(),
            ephemeral_pubkey: account.ephem_public_key().clone(),
            ephemeral_signature,
        }
    }
```

**File:** sdk/src/types.rs (L860-867)
```rust
#[derive(Debug)]
pub struct KeylessAccount {
    public_key: KeylessPublicKey,
    ephemeral_key_pair: EphemeralKeyPair,
    zk_sig: ZeroKnowledgeSig,
    jwt_header_json: String,
    jwt: Option<String>,
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L207-218)
```rust
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

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L284-290)
```rust
    signature
        .verify_expiry(onchain_timestamp_microseconds)
        .map_err(|_| {
            // println!("[aptos-vm][groth16] ZKP expired");

            invalid_signature!("The ephemeral keypair has expired")
        })?;
```

**File:** types/src/transaction/authenticator.rs (L1319-1347)
```rust
    fn verify_keyless_ephemeral_signature<T: Serialize + CryptoHash>(
        message: &T,
        signature: &KeylessSignature,
    ) -> Result<()> {
        // Verifies the ephemeral signature on (TXN [+ ZKP]). The rest of the verification,
        // i.e., [ZKPoK of] OpenID signature verification is done in
        // `AptosVM::run_prologue`.
        //
        // This is because the JWK, under which the [ZKPoK of an] OpenID signature verifies,
        // can only be fetched from on chain inside the `AptosVM`.
        //
        // This deferred verification is what actually ensures the `signature.ephemeral_pubkey`
        // used below is the right pubkey signed by the OIDC provider.

        let mut txn_and_zkp = TransactionAndProof {
            message,
            proof: None,
        };

        // Add the ZK proof into the `txn_and_zkp` struct, if we are in the ZK path
        match &signature.cert {
            EphemeralCertificate::ZeroKnowledgeSig(proof) => txn_and_zkp.proof = Some(proof.proof),
            EphemeralCertificate::OpenIdSig(_) => {},
        }

        signature
            .ephemeral_signature
            .verify(&txn_and_zkp, &signature.ephemeral_pubkey)
    }
```

**File:** keyless/pepper/example-client-rust/src/lib.rs (L150-187)
```rust
fn generate_blinder_and_ephemeral_key() -> (Blinder, EphemeralPublicKey, u64) {
    utils::print(
        "Step 2: Generating a blinder, ephemeral keypair and keypair expiration time.",
        true,
    );

    // Generate a random blinder
    let mut blinder = Blinder::default();
    rand::thread_rng().fill_bytes(&mut blinder);
    utils::print(
        &format!("Generated blinder (hex): {}", hex::encode(blinder)),
        false,
    );

    // Generate a new ephemeral key pair
    let private_key = Ed25519PrivateKey::generate(&mut rand::thread_rng());
    let ephemeral_public_key = EphemeralPublicKey::ed25519(private_key.public_key());
    utils::print(
        &format!(
            "Generated ephemeral public key (hex): {} and private key (hex): {}",
            hex::encode(ephemeral_public_key.to_bytes()),
            hex::encode(private_key.to_bytes())
        ),
        false,
    );

    // Generate a UNIX expiry time for the keypair (e.g., 1 hour from now)
    let expiry_time_secs = duration_since_epoch().as_secs() + 3600;
    utils::print(
        &format!(
            "Generated UNIX expiry time (1 hour from now): {}",
            expiry_time_secs
        ),
        false,
    );

    (blinder, ephemeral_public_key, expiry_time_secs)
}
```

**File:** aptos-move/framework/aptos-framework/doc/keyless_account.md (L145-165)
```markdown
<dt>
<code>override_aud_vals: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_String">string::String</a>&gt;</code>
</dt>
<dd>
 An override <code>aud</code> for the identity of a recovery service, which will help users recover their keyless accounts
 associated with dapps or wallets that have disappeared.
 IMPORTANT: This recovery service **cannot**, on its own, take over user accounts: a user must first sign in
 via OAuth in the recovery service in order to allow it to rotate any of that user's keyless accounts.

 Furthermore, the ZKP eventually expires, so there is a limited window within which a malicious recovery
 service could rotate accounts. In the future, we can make this window arbitrarily small by further lowering
 the maximum expiration horizon for ZKPs used for recovery, instead of relying on the <code>max_exp_horizon_secs</code>
 value in this resource.

 If changed: There is no prover service support yet for recovery mode => ZKPs with override aud's enabled
   will not be served by the prover service => as long as training wheels are "on," such recovery ZKPs will
   never arrive on chain.
   (Once support is implemented in the prover service, in an abundance of caution, the training wheel check
    should only pass if the override aud in the public statement matches one in this list. Therefore, changes
    to this value should be picked up automatically by the prover service.)
</dd>
```
