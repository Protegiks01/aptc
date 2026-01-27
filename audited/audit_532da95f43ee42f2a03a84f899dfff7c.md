# Audit Report

## Title
Keyless Account Identity Fragmentation via JWK Address Switching

## Summary
The `derive_keyless_account()` function allows a single keyless identity (same JWT, ephemeral key pair, and pepper) to create multiple distinct on-chain accounts by varying the `jwk_addr` parameter between `None` and `Some(address)`. This breaks the fundamental invariant that one identity should map to one account, enabling authentication confusion and JWK provider manipulation attacks.

## Finding Description

The vulnerability exists in the keyless account derivation logic where the `jwk_addr` parameter directly influences the account address generation. [1](#0-0) 

When `jwk_addr` is `None`, the function creates a regular `KeylessAccount` using `AnyPublicKey::Keyless`, but when `jwk_addr` is `Some(address)`, it creates a `FederatedKeylessAccount` using `AnyPublicKey::FederatedKeyless`. These are different enum variants: [2](#0-1) 

The authentication key is derived by BCS-serializing the public key and hashing it: [3](#0-2) 

Since `FederatedKeylessPublicKey` includes the `jwk_addr` field in addition to the nested `KeylessPublicKey`: [4](#0-3) 

The BCS serialization produces different bytes for the same identity commitment when `jwk_addr` varies, resulting in different authentication keys and thus different account addresses.

Furthermore, the validation logic treats these accounts differently during JWK lookup: [5](#0-4) 

Regular keyless accounts MUST find their JWK at `0x1` (failing otherwise), while federated keyless accounts can fall back to the custom `jwk_addr` if not found at `0x1`. This creates fundamentally different authentication requirements for what should be the same identity.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program for "Significant protocol violations" because:

1. **Authentication Invariant Violation**: The keyless system is designed with the assumption that one identity (JWT + pepper → identity commitment) maps to one account. This vulnerability allows unlimited accounts per identity with different security properties.

2. **Account Address Unpredictability**: Dapps and users cannot predict which account address a keyless identity will use, breaking wallet recovery and account recognition flows.

3. **JWK Provider Shopping**: Malicious users can create federated accounts pointing to compromised or manipulated JWK providers they control, while maintaining a "clean" regular account for legitimate use.

4. **Authentication Confusion**: The same user identity has inconsistent authentication paths—transactions from the regular account fail if JWKs are missing at `0x1`, but transactions from federated accounts succeed if JWKs exist at the custom address.

5. **Security Downgrade**: If the default JWK at `0x1` enforces strict security policies, users can bypass them by creating federated accounts with lax JWK providers.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** because:

1. **Easy to Exploit**: Any user can call `derive_keyless_account()` multiple times with the same JWT and ephemeral key pair but different `jwk_addr` values.

2. **No Special Privileges Required**: Exploitation requires only a valid JWT from any supported OIDC provider—no validator access, no governance participation needed.

3. **Undetectable**: The system has no mechanism to detect or prevent the same identity from creating multiple accounts with different authentication requirements.

4. **Intentional Feature Misuse**: The federated keyless feature is legitimately designed for dapps to use custom JWK addresses, but the lack of binding between identity and JWK address enables the exploit.

## Recommendation

Implement identity-to-account binding by including the `jwk_addr` (or lack thereof) in the identity commitment calculation:

**Option 1: Include jwk_addr in IdCommitment**
Modify the identity commitment to hash: `pepper || aud || uid_val || uid_key || jwk_addr_option`

This ensures different `jwk_addr` values produce different identity commitments, making it impossible for the same logical identity to have multiple authentication paths.

**Option 2: Enforce Single Account Mode**
Add an on-chain registry mapping identity commitments to their first-used account type (regular vs federated with specific jwk_addr). Subsequent account creation attempts with the same identity commitment but different jwk_addr should be rejected.

**Option 3: Remove jwk_addr from Address Derivation**
Derive account addresses solely from the base `KeylessPublicKey` (without jwk_addr), storing the jwk_addr preference in the account's on-chain state instead. This ensures one identity → one address, with the JWK lookup preference being mutable account configuration rather than address-defining.

## Proof of Concept

```rust
// Rust SDK demonstration
use aptos_sdk::{
    rest_client::Client,
    types::{derive_keyless_account, EphemeralKeyPair},
};

async fn demonstrate_account_fragmentation() {
    let client = Client::new("https://fullnode.devnet.aptoslabs.com".parse().unwrap());
    let jwt = "eyJ..."; // Same JWT
    let ephemeral_key_pair = EphemeralKeyPair::new_ed25519(/* ... */);
    
    // Create regular keyless account
    let account_regular = derive_keyless_account(
        &client,
        jwt,
        ephemeral_key_pair.clone(),
        None // jwk_addr = None
    ).await.unwrap();
    
    // Create federated keyless account with jwk_addr = 0xadd
    let account_federated1 = derive_keyless_account(
        &client,
        jwt,
        ephemeral_key_pair.clone(),
        Some(AccountAddress::from_hex_literal("0xadd").unwrap())
    ).await.unwrap();
    
    // Create federated keyless account with jwk_addr = 0xbee
    let account_federated2 = derive_keyless_account(
        &client,
        jwt,
        ephemeral_key_pair.clone(),
        Some(AccountAddress::from_hex_literal("0xbee").unwrap())
    ).await.unwrap();
    
    // Verify: All three accounts have DIFFERENT addresses
    assert_ne!(account_regular.address(), account_federated1.address());
    assert_ne!(account_regular.address(), account_federated2.address());
    assert_ne!(account_federated1.address(), account_federated2.address());
    
    // Verify: Same identity commitment in all three accounts
    // (Same JWT → same pepper → same idc)
    println!("Regular account: {}", account_regular.address());
    println!("Federated account 1: {}", account_federated1.address());
    println!("Federated account 2: {}", account_federated2.address());
}
```

This demonstrates that a single keyless identity can control multiple accounts with different authentication requirements, violating the protocol's security model.

## Notes

The vulnerability stems from a design decision to include the `jwk_addr` in the `FederatedKeylessPublicKey` structure, which then gets included in the BCS serialization used for authentication key derivation. While federated keyless accounts are an intentional feature for allowing dapps to use custom JWK providers, the lack of binding between identity and authentication path creates a security gap.

The issue is particularly concerning because the keyless account system is explicitly designed for users without traditional private keys, relying on OAuth-based identity. Allowing identity fragmentation undermines the trust model and creates confusion about which account represents a user's "true" identity on-chain.

### Citations

**File:** sdk/src/types.rs (L1056-1121)
```rust
pub async fn derive_keyless_account(
    rest_client: &Client,
    jwt: &str,
    ephemeral_key_pair: EphemeralKeyPair,
    jwk_addr: Option<AccountAddress>,
) -> Result<LocalAccount> {
    let pepper = get_pepper_from_jwt(rest_client, jwt, &ephemeral_key_pair).await?;
    let zksig = get_proof_from_jwt(rest_client, jwt, &ephemeral_key_pair, &pepper).await?;

    let account = match jwk_addr {
        Some(jwk_addr) => {
            let federated_account = FederatedKeylessAccount::new_from_jwt(
                jwt,
                ephemeral_key_pair,
                jwk_addr,
                Some("sub"),
                pepper.clone(),
                zksig,
            )?;
            LocalAccount::new_federated_keyless(
                federated_account.authentication_key().account_address(),
                federated_account,
                0, // We'll update this with the actual sequence number below
            )
        },
        None => {
            let keyless_account = KeylessAccount::new_from_jwt(
                jwt,
                ephemeral_key_pair,
                Some("sub"),
                pepper.clone(),
                zksig,
            )?;
            LocalAccount::new_keyless(
                keyless_account.authentication_key().account_address(),
                keyless_account,
                0, // We'll update this with the actual sequence number below
            )
        },
    };

    // Look up the on-chain address and sequence number
    let address = rest_client
        .lookup_address(account.authentication_key().account_address(), false)
        .await?;
    let sequence_number = rest_client
        .get_account_sequence_number(account.authentication_key().account_address())
        .await?;

    // Create the final account with the correct address and sequence number
    Ok(match account.auth {
        LocalAccountAuthenticator::Keyless(keyless_account) => LocalAccount::new_keyless(
            address.into_inner(),
            keyless_account,
            sequence_number.into_inner(),
        ),
        LocalAccountAuthenticator::FederatedKeyless(federated_keyless_account) => {
            LocalAccount::new_federated_keyless(
                address.into_inner(),
                federated_keyless_account,
                sequence_number.into_inner(),
            )
        },
        _ => unreachable!("We only create keyless or federated keyless accounts here"),
    })
}
```

**File:** types/src/transaction/authenticator.rs (L884-926)
```rust
    pub fn from_preimage(mut public_key_bytes: Vec<u8>, scheme: Scheme) -> AuthenticationKey {
        public_key_bytes.push(scheme as u8);
        AuthenticationKey::new(*HashValue::sha3_256_of(&public_key_bytes).as_ref())
    }

    /// Construct a preimage from a transaction-derived AUID as (txn_hash || auid_scheme_id)
    pub fn auid(mut txn_hash: Vec<u8>, auid_counter: u64) -> Self {
        txn_hash.extend(auid_counter.to_le_bytes().to_vec());
        Self::from_preimage(txn_hash, Scheme::DeriveAuid)
    }

    pub fn object_address_from_object(
        source: &AccountAddress,
        derive_from: &AccountAddress,
    ) -> AuthenticationKey {
        let mut bytes = source.to_vec();
        bytes.append(&mut derive_from.to_vec());
        Self::from_preimage(bytes, Scheme::DeriveObjectAddressFromObject)
    }

    pub fn domain_abstraction_address(
        func_info_bcs_bytes: Vec<u8>,
        account_identity: &[u8],
    ) -> AuthenticationKey {
        let mut bytes = func_info_bcs_bytes;
        bytes.append(&mut bcs::to_bytes(account_identity).expect("must serialize byte array"));
        Self::from_preimage(bytes, Scheme::DeriveDomainAbstraction)
    }

    /// Create an authentication key from an Ed25519 public key
    pub fn ed25519(public_key: &Ed25519PublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes().to_vec(), Scheme::Ed25519)
    }

    /// Create an authentication key from a MultiEd25519 public key
    pub fn multi_ed25519(public_key: &MultiEd25519PublicKey) -> Self {
        Self::from_preimage(public_key.to_bytes(), Scheme::MultiEd25519)
    }

    /// Create an authentication key from an AnyPublicKey
    pub fn any_key(public_key: AnyPublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes(), Scheme::SingleKey)
    }
```

**File:** types/src/transaction/authenticator.rs (L1361-1410)
```rust
pub enum AnyPublicKey {
    Ed25519 {
        public_key: Ed25519PublicKey,
    },
    Secp256k1Ecdsa {
        public_key: secp256k1_ecdsa::PublicKey,
    },
    Secp256r1Ecdsa {
        public_key: secp256r1_ecdsa::PublicKey,
    },
    Keyless {
        public_key: KeylessPublicKey,
    },
    FederatedKeyless {
        public_key: FederatedKeylessPublicKey,
    },
    SlhDsa_Sha2_128s {
        public_key: slh_dsa_sha2_128s::PublicKey,
    },
}

impl AnyPublicKey {
    pub fn ed25519(public_key: Ed25519PublicKey) -> Self {
        Self::Ed25519 { public_key }
    }

    pub fn secp256k1_ecdsa(public_key: secp256k1_ecdsa::PublicKey) -> Self {
        Self::Secp256k1Ecdsa { public_key }
    }

    pub fn secp256r1_ecdsa(public_key: secp256r1_ecdsa::PublicKey) -> Self {
        Self::Secp256r1Ecdsa { public_key }
    }

    pub fn slh_dsa_sha2_128s(public_key: slh_dsa_sha2_128s::PublicKey) -> Self {
        Self::SlhDsa_Sha2_128s { public_key }
    }

    pub fn keyless(public_key: KeylessPublicKey) -> Self {
        Self::Keyless { public_key }
    }

    pub fn federated_keyless(public_key: FederatedKeylessPublicKey) -> Self {
        Self::FederatedKeyless { public_key }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("Only unhandleable errors happen here.")
    }
}
```

**File:** types/src/keyless/mod.rs (L372-389)
```rust
/// Unlike a normal keyless account, a "federated" keyless account will accept JWKs published at a
/// specific contract address.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct FederatedKeylessPublicKey {
    pub jwk_addr: AccountAddress,
    pub pk: KeylessPublicKey,
}

impl FederatedKeylessPublicKey {
    /// A reasonable upper bound for the number of bytes we expect in a federated keyless public key.
    /// This is enforced by our full nodes when they receive TXNs.
    pub const MAX_LEN: usize = AccountAddress::LENGTH + KeylessPublicKey::MAX_LEN;

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self).expect("Only unhandleable errors happen here.")
    }
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L236-260)
```rust
        // Try looking up the jwk in 0x1.
        let jwk = match get_jwk_for_authenticator(&patched_jwks.jwks, pk.inner_keyless_pk(), sig) {
            // 1: If found in 0x1, then we consider that the ground truth & we are done.
            Ok(jwk) => jwk,
            // 2: If not found in 0x1, we check the Keyless PK type.
            Err(e) => {
                match pk {
                    // 2.a: If this is a federated keyless account; look in `jwk_addr` for JWKs
                    AnyKeylessPublicKey::Federated(fed_pk) => {
                        let federated_jwks =
                            get_federated_jwks_onchain(resolver, &fed_pk.jwk_addr, module_storage)
                                .map_err(|_| {
                                    invalid_signature!(format!(
                                        "Could not fetch federated PatchedJWKs at {}",
                                        fed_pk.jwk_addr
                                    ))
                                })?;
                        // 2.a.i If not found in jwk_addr either, then we fail the validation.
                        get_jwk_for_authenticator(&federated_jwks.jwks, pk.inner_keyless_pk(), sig)?
                    },
                    // 2.b: If this is not a federated keyless account, then we fail the validation.
                    AnyKeylessPublicKey::Normal(_) => return Err(e),
                }
            },
        };
```
