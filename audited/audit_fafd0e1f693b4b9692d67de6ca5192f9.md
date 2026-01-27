# Audit Report

## Title
Invalid Ed25519 Public Keys Allow Creation of Permanently Unspendable Accounts

## Summary
The `create_user_account()` function in the SDK and `AuthenticationKey::ed25519()` do not validate that Ed25519 public keys are cryptographically valid before deriving account addresses. This allows attackers to create accounts from small subgroup points (e.g., the identity element), resulting in addresses that can receive funds but can never spend them, causing permanent fund loss.

## Finding Description

The vulnerability exists across multiple layers of the account creation flow:

**1. Rust Crypto Layer - No Small Subgroup Validation:** [1](#0-0) 

The `Ed25519PublicKey::try_from()` implementation only validates that bytes form a valid curve point but explicitly does NOT check for small subgroup membership. The comment states: "This method will NOT check for key validity, which means the returned public key could be in a small subgroup."

**2. AuthenticationKey Derivation - No Validation:** [2](#0-1) 

The `AuthenticationKey::ed25519()` function directly hashes the public key bytes without any cryptographic validation: [3](#0-2) 

**3. SDK Account Creation - Uses Unvalidated Keys:** [4](#0-3) 

**4. Signature Verification DOES Validate - Creating Unspendable Accounts:** [5](#0-4) 

The signature verification (line 137) calls `verify_strict` which checks both the signature's R-component and the public key are NOT in a small subgroup. This means accounts created with invalid keys can never sign valid transactions.

**5. Native Validation Confirms Small Subgroup Rejection:** [6](#0-5) 

The native validation explicitly rejects small order points at line 80: `!point.is_small_order()`.

**6. Test Case Confirms Identity Element is Invalid:** [7](#0-6) 

**Attack Scenario:**
1. Attacker creates an `Ed25519PublicKey` from a small subgroup point (e.g., `0x0100...00` - the identity element)
2. Attacker calls `create_user_account(invalid_pubkey)` which derives an address via `AuthenticationKey::ed25519()`
3. An account is successfully created on-chain at this address
4. Users or contracts send funds to this address
5. **No one can ever spend from this account** because signature verification will always fail the small subgroup check
6. Funds are permanently locked with no recovery mechanism

The vulnerability breaks the **Cryptographic Correctness** invariant: authentication keys should only be derivable from cryptographically valid public keys that can actually sign transactions.

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria - "Limited funds loss or manipulation"

- Any funds sent to addresses derived from invalid public keys are **permanently and irreversibly lost**
- No recovery mechanism exists - key rotation requires signing with the current (invalid) key: [8](#0-7) 

- Attackers can create malicious addresses and trick users into sending funds through phishing or social engineering
- The impact is limited to explicitly crafted addresses, not a systemic vulnerability affecting all accounts
- Requires user interaction (sending funds to the malicious address)

## Likelihood Explanation

**Medium-High Likelihood:**

- **Easy to execute**: Creating an invalid public key requires only calling `Ed25519PublicKey::try_from()` with specific byte sequences
- **Low attacker requirements**: No privileged access needed, any SDK user can exploit this
- **Requires social engineering**: Attacker must trick users into sending funds to crafted addresses
- **Not immediately obvious**: Addresses derived from invalid keys appear valid (32-byte addresses)
- **Could target high-value scenarios**: Phishing attacks, malicious wallet integrations, or compromised address lists

## Recommendation

Add public key validation before deriving authentication keys. Implement validation at the SDK level:

**Option 1: Validate in AuthenticationKey::ed25519()** (Recommended)
Add validation directly in the authentication key derivation:
- Call the Move native `public_key_validate_internal` functionality
- Reject small subgroup points before deriving addresses
- Return a Result type to propagate validation errors

**Option 2: Validate in TransactionFactory::create_user_account()**
Add validation in the SDK transaction builder:
- Check public key validity before creating the transaction
- Provide clear error messages to SDK users

**Option 3: Add a validated Ed25519PublicKey type**
Create a `ValidatedEd25519PublicKey` type that enforces validation at construction time, similar to the Move `ValidatedPublicKey` struct: [9](#0-8) 

Use this type in all account creation APIs to enforce validation by construction.

## Proof of Concept

```rust
use aptos_crypto::ed25519::Ed25519PublicKey;
use aptos_types::transaction::authenticator::AuthenticationKey;

fn main() {
    // Create an Ed25519PublicKey from the identity element (small subgroup point)
    let identity_element = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    
    // This succeeds - no validation performed!
    let invalid_pubkey = Ed25519PublicKey::try_from(&identity_element[..]).unwrap();
    
    // Derive authentication key and address - also succeeds without validation
    let auth_key = AuthenticationKey::ed25519(&invalid_pubkey);
    let address = auth_key.account_address();
    
    println!("Created unspendable account at address: {}", address);
    println!("Any funds sent to this address are permanently locked!");
    
    // Attempting to sign a transaction with this key would fail:
    // - Ed25519PrivateKey for identity element doesn't exist
    // - Even if it did, signature verification would reject small subgroup keys
}
```

**Move Test Validation:**
The existing test already demonstrates that small order points fail validation: [7](#0-6) 

This confirms that `0x0100...00` is correctly identified as invalid by the validation function, but this validation is never called during account creation via the SDK.

### Citations

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L295-305)
```rust
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Ed25519PublicKey. This method will NOT check for key validity, which means
    /// the returned public key could be in a small subgroup. Nonetheless, our signature
    /// verification implicitly checks if the public key lies in a small subgroup, so canonical
    /// uses of this library will not be susceptible to small subgroup attacks.
    fn try_from(bytes: &[u8]) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        Ed25519PublicKey::from_bytes_unchecked(bytes)
    }
}
```

**File:** types/src/transaction/authenticator.rs (L884-887)
```rust
    pub fn from_preimage(mut public_key_bytes: Vec<u8>, scheme: Scheme) -> AuthenticationKey {
        public_key_bytes.push(scheme as u8);
        AuthenticationKey::new(*HashValue::sha3_256_of(&public_key_bytes).as_ref())
    }
```

**File:** types/src/transaction/authenticator.rs (L913-916)
```rust
    /// Create an authentication key from an Ed25519 public key
    pub fn ed25519(public_key: &Ed25519PublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes().to_vec(), Scheme::Ed25519)
    }
```

**File:** sdk/src/transaction_builder.rs (L217-221)
```rust
    pub fn create_user_account(&self, public_key: &Ed25519PublicKey) -> TransactionBuilder {
        self.payload(aptos_stdlib::aptos_account_create_account(
            AuthenticationKey::ed25519(public_key).account_address(),
        ))
    }
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_sigs.rs (L126-140)
```rust
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Result<()> {
        // NOTE: ed25519::PublicKey::verify_strict already checks that the s-component of the signature
        // is not mauled, but does so via an optimistic path which fails into a slower path. By doing
        // our own (much faster) checking here, we can ensure dalek's optimistic path always succeeds
        // and the slow path is never triggered.
        Ed25519Signature::check_s_malleability(&self.to_bytes())?;

        // NOTE: ed25519::PublicKey::verify_strict checks that the signature's R-component and
        // the public key are *not* in a small subgroup.
        public_key
            .0
            .verify_strict(message, &self.0)
            .map_err(|e| anyhow!("{}", e))
            .and(Ok(()))
    }
```

**File:** aptos-move/framework/src/natives/cryptography/ed25519.rs (L67-83)
```rust
    // This deserialization only performs point-on-curve checks, so we check for small subgroup below
    // NOTE(Gas): O(1) cost: some arithmetic for converting to (X, Y, Z, T) coordinates
    let point = match CompressedEdwardsY(key_bytes_slice).decompress() {
        Some(point) => point,
        None => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };

    // Check if the point lies on a small subgroup. This is required when using curves with a
    // small cofactor (e.g., in Ed25519, cofactor = 8).
    // NOTE(Gas): O(1) cost: multiplies the point by the cofactor
    context.charge(ED25519_PER_PUBKEY_SMALL_ORDER_CHECK * NumArgs::one())?;
    let valid = !point.is_small_order();

    Ok(smallvec![Value::bool(valid)])
}
```

**File:** testsuite/fuzzer/data/0x1/ed25519/public_key_validate_internal/sources/call_native.move (L30-32)
```text
        let small_order_pk_bytes = x"0100000000000000000000000000000000000000000000000000000000000000";
        let result_fail_small_order = ed25519::new_validated_public_key_from_bytes(small_order_pk_bytes);
        assert!(option::is_none(&result_fail_small_order), 6);
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L604-658)
```text
    public entry fun rotate_authentication_key(
        account: &signer,
        from_scheme: u8,
        from_public_key_bytes: vector<u8>,
        to_scheme: u8,
        to_public_key_bytes: vector<u8>,
        cap_rotate_key: vector<u8>,
        cap_update_table: vector<u8>,
    ) acquires Account, OriginatingAddress {
        let addr = signer::address_of(account);
        ensure_resource_exists(addr);
        check_rotation_permission(account);
        let account_resource = &mut Account[addr];
        let old_auth_key = account_resource.authentication_key;
        // Verify the given `from_public_key_bytes` matches this account's current authentication key.
        if (from_scheme == ED25519_SCHEME) {
            let from_pk = ed25519::new_unvalidated_public_key_from_bytes(from_public_key_bytes);
            let from_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&from_pk);
            assert!(
                account_resource.authentication_key == from_auth_key,
                error::unauthenticated(EWRONG_CURRENT_PUBLIC_KEY)
            );
        } else if (from_scheme == MULTI_ED25519_SCHEME) {
            let from_pk = multi_ed25519::new_unvalidated_public_key_from_bytes(from_public_key_bytes);
            let from_auth_key = multi_ed25519::unvalidated_public_key_to_authentication_key(&from_pk);
            assert!(
                account_resource.authentication_key == from_auth_key,
                error::unauthenticated(EWRONG_CURRENT_PUBLIC_KEY)
            );
        } else {
            abort error::invalid_argument(EINVALID_SCHEME)
        };

        // Construct a valid `RotationProofChallenge` that `cap_rotate_key` and `cap_update_table` will validate against.
        let curr_auth_key_as_address = from_bcs::to_address(account_resource.authentication_key);
        let challenge = RotationProofChallenge {
            sequence_number: account_resource.sequence_number,
            originator: addr,
            current_auth_key: curr_auth_key_as_address,
            new_public_key: to_public_key_bytes,
        };

        // Assert the challenges signed by the current and new keys are valid
        assert_valid_rotation_proof_signature_and_get_auth_key(
            from_scheme,
            from_public_key_bytes,
            cap_rotate_key,
            &challenge
        );
        let new_auth_key = assert_valid_rotation_proof_signature_and_get_auth_key(
            to_scheme,
            to_public_key_bytes,
            cap_update_table,
            &challenge
        );
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/ed25519.move (L55-61)
```text
    /// A *validated* Ed25519 public key: not necessarily a prime-order point, could be mixed-order, but will never be
    /// a small-order point.
    ///
    /// For now, this struct is not used in any verification functions, but it might be in the future.
    struct ValidatedPublicKey has copy, drop, store {
        bytes: vector<u8>
    }
```
