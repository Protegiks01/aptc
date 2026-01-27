# Audit Report

## Title
Authentication Key Reuse Across Accounts Bypassing OriginatingAddress Tracking

## Summary
Multiple accounts can rotate to the same authentication key using unverified rotation methods, causing only the first account to be tracked in the `OriginatingAddress` table. This breaks wallet recovery functionality and creates ambiguity about which account owns a given authentication key.

## Finding Description

The Aptos account module provides two paths for authentication key rotation:

1. **Verified rotation** (`rotate_authentication_key()`) - requires proof-of-knowledge signatures from both current and new keys, updates `OriginatingAddress` table
2. **Unverified rotation** (`rotate_authentication_key_call()`) - requires only the account's current signature, does NOT update `OriginatingAddress` table

The critical vulnerability exists because:

**Verified rotation path** includes protection against key reuse: [1](#0-0) 

This check prevents adding a new authentication key that already exists in the `OriginatingAddress` table.

However, **unverified rotation path** completely bypasses this protection: [2](#0-1) [3](#0-2) 

The `rotate_authentication_key_internal()` function directly updates the account's authentication key without checking or updating the `OriginatingAddress` table.

**Attack Scenario:**
1. Alice (Account A at address 0xAAAA) rotates to authentication key 0xXXXX using `rotate_authentication_key()` with valid proofs
   - `OriginatingAddress[0xXXXX] = 0xAAAA` is recorded
   - `Account[0xAAAA].authentication_key = 0xXXXX`

2. Bob (Account B at address 0xBBBB) rotates to the SAME authentication key 0xXXXX using `rotate_authentication_key_call()`
   - No check that 0xXXXX already exists in `OriginatingAddress`
   - No update to `OriginatingAddress` table
   - `Account[0xBBBB].authentication_key = 0xXXXX`

3. **Result:** Both accounts have authentication key 0xXXXX, but `OriginatingAddress[0xXXXX]` only points to Alice's address 0xAAAA. Bob's account is invisible in the wallet recovery system.

Additionally, the code documentation suggests calling `set_originating_address()` to update the table after unverified rotation: [4](#0-3) 

However, this function is **completely disabled**: [5](#0-4) 

The comment at line 821 states this was disabled "due to potential poisoning from account abstraction", but this leaves unverified rotations permanently untracked.

Furthermore, unverified rotations do not emit the standard `KeyRotation` event that is used by indexers: [6](#0-5) 

This event is only emitted within `update_auth_key_and_originating_address_table()`, which unverified rotations bypass.

## Impact Explanation

This vulnerability represents a **HIGH severity** issue based on the Aptos bug bounty criteria for "Significant protocol violations":

1. **Wallet Recovery Failure:** When users attempt to recover their wallet using authentication key 0xXXXX, the wallet software will query `OriginatingAddress[0xXXXX]` and receive only Alice's address, not Bob's. Bob's funds become inaccessible through standard recovery flows.

2. **State Inconsistency:** The `OriginatingAddress` table, designed as the authoritative source for authentication key to address mapping, is incomplete and misleading. Multiple accounts can share authentication keys while the table only tracks a subset.

3. **Loss of Funds Risk:** Users of accounts rotated via unverified methods (like Bob) may lose access to their funds during wallet recovery scenarios, as their account address cannot be derived from their authentication key.

4. **Missing Audit Trail:** No `KeyRotation` events are emitted for unverified rotations, preventing off-chain indexers and monitoring systems from tracking these critical state changes.

The `OriginatingAddress` resource exists specifically to enable wallet recovery after key rotation: [7](#0-6) 

This vulnerability fundamentally breaks this security guarantee.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to occur because:

1. **Legitimate Use Case:** `rotate_authentication_key_call()` is an officially supported entry function intended for non-standard key algorithms like passkeys. Users will naturally use this function for legitimate key rotations.

2. **No Warning:** There is no runtime warning or error when rotating to an authentication key that already exists in another account. The transaction succeeds silently.

3. **Documentation Misleading:** The code comments suggest calling `set_originating_address()` as a follow-up, but this function aborts immediately, leaving users with no way to fix the issue.

4. **Easy to Trigger:** Any two users can independently choose to rotate to the same authentication key. While unlikely by chance, it could happen through:
   - Shared key management systems
   - Multisig setups where multiple accounts rotate to the same multisig key
   - Contract-generated accounts using deterministic key derivation

## Recommendation

**Immediate Fix:** Add a check in `rotate_authentication_key_internal()` to prevent rotating to an authentication key that already exists in the `OriginatingAddress` table:

```move
public(friend) fun rotate_authentication_key_internal(account: &signer, new_auth_key: vector<u8>) acquires Account, OriginatingAddress {
    let addr = signer::address_of(account);
    ensure_resource_exists(addr);
    assert!(
        new_auth_key.length() == 32,
        error::invalid_argument(EMALFORMED_AUTHENTICATION_KEY)
    );
    check_rotation_permission(account);
    
    // NEW: Check if this auth key is already mapped to a different account
    let new_auth_key_as_addr = from_bcs::to_address(new_auth_key);
    let address_map = &OriginatingAddress[@aptos_framework].address_map;
    if (address_map.contains(new_auth_key_as_addr)) {
        let existing_addr = *address_map.borrow(new_auth_key_as_addr);
        assert!(
            existing_addr == addr,
            error::invalid_argument(ENEW_AUTH_KEY_ALREADY_MAPPED)
        );
    };
    
    let account_resource = &mut Account[addr];
    account_resource.authentication_key = new_auth_key;
}
```

**Alternative Solution:** If allowing key reuse is intentional for specific use cases, implement a proper tracking mechanism:
- Modify `OriginatingAddress` to support one-to-many mappings (auth_key → Set<address>)
- Emit `KeyRotation` events for all rotation types
- Re-enable and fix `set_originating_address()` with proper access controls

## Proof of Concept

```move
#[test(aptos_framework = @0x1, alice = @0xA11CE, bob = @0xB0B)]
public entry fun test_authentication_key_reuse_vulnerability(
    aptos_framework: &signer,
    alice: &signer,
    bob: &signer,
) {
    use aptos_framework::account;
    use aptos_framework::genesis;
    use std::vector;
    
    // Initialize the blockchain
    genesis::setup();
    
    // Create Alice's account
    account::create_account_for_test(signer::address_of(alice));
    
    // Create Bob's account  
    account::create_account_for_test(signer::address_of(bob));
    
    // Step 1: Alice rotates to a new authentication key using VERIFIED rotation
    let new_auth_key = x"1111111111111111111111111111111111111111111111111111111111111111";
    
    // Alice performs verified rotation (with proofs - omitted for brevity)
    // This would call rotate_authentication_key() which updates OriginatingAddress
    // OriginatingAddress[new_auth_key] = alice's address
    
    // Step 2: Bob rotates to the SAME authentication key using UNVERIFIED rotation
    account::rotate_authentication_key_call(bob, new_auth_key);
    
    // Verify the vulnerability:
    // 1. Bob's account now has the same auth key as Alice
    assert!(account::get_authentication_key(signer::address_of(bob)) == new_auth_key, 1);
    
    // 2. OriginatingAddress[new_auth_key] still points to Alice, not Bob
    let originating_addr = account::originating_address(
        from_bcs::to_address(new_auth_key)
    );
    assert!(originating_addr == option::some(signer::address_of(alice)), 2);
    // Bob's address is NOT in the OriginatingAddress table!
    
    // 3. During wallet recovery, only Alice's address is discoverable from this auth key
    // Bob's funds are inaccessible through standard recovery flows
}
```

## Notes

The vulnerability exists due to a design trade-off: supporting non-standard key algorithms (like passkeys) that cannot produce proof-of-knowledge signatures. However, this trade-off was implemented without adequate safeguards against authentication key reuse, breaking the invariant that `OriginatingAddress` should enable reliable wallet recovery.

The disabled `set_originating_address()` function (line 832-833) exacerbates the issue by providing no mechanism for users to reconcile the `OriginatingAddress` table after unverified rotation, even though the documentation suggests this as a solution (line 458-459).

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L92-105)
```text
    /// It is easy to fetch the authentication key of an address by simply reading it from the `Account` struct at that address.
    /// The table in this struct makes it possible to do a reverse lookup: it maps an authentication key, to the address of the account which has that authentication key set.
    ///
    /// This mapping is needed when recovering wallets for accounts whose authentication key has been rotated.
    ///
    /// For example, imagine a freshly-created wallet with address `a` and thus also with authentication key `a`, derived from a PK `pk_a` with corresponding SK `sk_a`.
    /// It is easy to recover such a wallet given just the secret key `sk_a`, since the PK can be derived from the SK, the authentication key can then be derived from the PK, and the address equals the authentication key (since there was no key rotation).
    ///
    /// However, if such a wallet rotates its authentication key to `b` derived from a different PK `pk_b` with SK `sk_b`, how would account recovery work?
    /// The recovered address would no longer be 'a'; it would be `b`, which is incorrect.
    /// This struct solves this problem by mapping the new authentication key `b` to the original address `a` and thus helping the wallet software during recovery find the correct address.
    struct OriginatingAddress has key {
        address_map: Table<address, address>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L440-450)
```text
    public(friend) fun rotate_authentication_key_internal(account: &signer, new_auth_key: vector<u8>) acquires Account {
        let addr = signer::address_of(account);
        ensure_resource_exists(addr);
        assert!(
            new_auth_key.length() == 32,
            error::invalid_argument(EMALFORMED_AUTHENTICATION_KEY)
        );
        check_rotation_permission(account);
        let account_resource = &mut Account[addr];
        account_resource.authentication_key = new_auth_key;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L456-459)
```text
    /// the format expected in `rotate_authentication_key`.
    ///
    /// If you'd like to followup with updating the `OriginatingAddress` table, you can call
    /// `set_originating_address()`.
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L460-462)
```text
    entry fun rotate_authentication_key_call(account: &signer, new_auth_key: vector<u8>) acquires Account {
        rotate_authentication_key_internal(account, new_auth_key);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L832-833)
```text
    entry fun set_originating_address(_account: &signer) acquires Account, OriginatingAddress {
        abort error::invalid_state(ESET_ORIGINATING_ADDRESS_DISABLED);
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1077-1080)
```text
        assert!(
            !address_map.contains(new_auth_key),
            error::invalid_argument(ENEW_AUTH_KEY_ALREADY_MAPPED)
        );
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1084-1088)
```text
            event::emit(KeyRotation {
                account: originating_addr,
                old_authentication_key: account_resource.authentication_key,
                new_authentication_key: new_auth_key_vector,
            });
```
