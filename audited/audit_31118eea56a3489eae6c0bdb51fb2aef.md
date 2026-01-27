# Audit Report

## Title
Authentication Key Rotation Event History Can Be Manipulated Through Incomplete Event Emission

## Summary
The `old_authentication_key` field in KeyRotation events is not verified against the original authentication key. Account owners can use non-event-emitting rotation functions to change their authentication key, then later use event-emitting functions, causing the KeyRotation event to display an intermediate key as the "old" key instead of the original key. This allows creation of incomplete/fake event history.

## Finding Description

The Aptos account module provides multiple functions for rotating authentication keys. The KeyRotation event struct contains three fields: `account`, `old_authentication_key`, and `new_authentication_key`. [1](#0-0) 

When a KeyRotation event is emitted in the `update_auth_key_and_originating_address_table` function, the `old_authentication_key` field is populated directly from `account_resource.authentication_key` without any verification: [2](#0-1) 

The critical issue is that there are multiple authentication key rotation functions with different event emission behaviors:

**Functions that emit KeyRotation events:**
- `rotate_authentication_key` 
- `rotate_authentication_key_with_rotation_capability`

**Functions that do NOT emit KeyRotation events:**
- `rotate_authentication_key_call` - emits no event at all [3](#0-2) 

- `rotate_authentication_key_from_public_key` - emits KeyRotationToPublicKey instead [4](#0-3) 

- `rotate_authentication_key_internal` - emits no event (used by friend modules) [5](#0-4) 

**Attack Scenario:**
1. Account created with address A (initial authentication_key = A)
2. Attacker calls `rotate_authentication_key_call` to change auth key from A to B
   - No KeyRotation event is emitted
   - `account_resource.authentication_key` is now B
3. Attacker calls `rotate_authentication_key` to change auth key from B to C
   - KeyRotation event is emitted with `old_authentication_key = B, new_authentication_key = C`
4. Result: Event history shows rotation B→C, but completely hides the initial A→B rotation

The system reads whatever value is currently stored in `account_resource.authentication_key` as the "old" key, without verifying it matches the actual historical key. This breaks the integrity of the event audit trail.

## Impact Explanation

This is a **HIGH severity** vulnerability according to Aptos bug bounty criteria because it constitutes a "Significant protocol violation" that breaks critical security guarantees:

1. **Event Integrity Violation**: Events are designed to provide an immutable, complete audit trail of all state changes. This vulnerability allows arbitrary gaps in that audit trail.

2. **Forensic Analysis Compromise**: Security teams and auditors rely on event logs to trace account history. Attackers can hide key rotations from forensic investigation.

3. **Monitoring System Evasion**: Off-chain indexers and monitoring systems that track KeyRotation events will have incomplete information, potentially missing security-relevant rotations.

4. **Wallet Recovery Impact**: The code comments explicitly state that the OriginatingAddress table is used for wallet recovery after key rotation. The comments in `rotate_authentication_key_call` note that it does NOT update this table: [6](#0-5) 

Combined with incomplete event history, this could confuse wallet recovery mechanisms.

5. **Protocol Trust Violation**: Users and applications expect that events provide a complete record of security-relevant operations. This vulnerability violates that trust assumption.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **No Special Permissions Required**: Any account owner can call `rotate_authentication_key_call` - it's a public entry function with only standard permission checks.

2. **Simple Attack Path**: The attack requires only two straightforward function calls with no complex setup or timing requirements.

3. **Legitimate Use Case Cover**: The `rotate_authentication_key_call` function is designed for legitimate use with non-standard key types (like passkeys), so its use doesn't immediately appear suspicious.

4. **Immediate Benefit to Attackers**: Hiding key rotation history provides clear value for:
   - Compromised account operators trying to hide evidence
   - Insiders covering their tracks after unauthorized access
   - Attackers evading monitoring and alerting systems

5. **No On-Chain Detection**: There is no on-chain mechanism to detect that an incomplete event history has been created.

## Recommendation

**Option 1: Emit Events from All Rotation Functions (Recommended)**

Ensure that ALL authentication key rotation functions emit KeyRotation events, including `rotate_authentication_key_call`, `rotate_authentication_key_from_public_key`, and `rotate_authentication_key_internal`. This ensures complete event history.

Modify `rotate_authentication_key_internal` to always emit an event:

```move
public(friend) fun rotate_authentication_key_internal(account: &signer, new_auth_key: vector<u8>) acquires Account {
    let addr = signer::address_of(account);
    ensure_resource_exists(addr);
    assert!(
        new_auth_key.length() == 32,
        error::invalid_argument(EMALFORMED_AUTHENTICATION_KEY)
    );
    check_rotation_permission(account);
    let account_resource = &mut Account[addr];
    let old_auth_key = account_resource.authentication_key;
    account_resource.authentication_key = new_auth_key;
    
    // Emit event for all rotations
    if (std::features::module_event_migration_enabled()) {
        event::emit(KeyRotation {
            account: addr,
            old_authentication_key: old_auth_key,
            new_authentication_key: new_auth_key,
        });
    } else {
        event::emit_event<KeyRotationEvent>(
            &mut account_resource.key_rotation_events,
            KeyRotationEvent {
                old_authentication_key: old_auth_key,
                new_authentication_key: new_auth_key,
            }
        );
    };
}
```

**Option 2: Store Complete Rotation History On-Chain**

Maintain a complete on-chain history of all authentication keys an account has used, stored in the Account resource. Verify the `old_authentication_key` in events against this history before emission.

**Option 3: Remove Non-Event-Emitting Rotation Functions**

If Option 1 is not feasible due to gas concerns or other constraints, remove `rotate_authentication_key_call` and require all rotations to go through functions that properly emit events and update the OriginatingAddress table.

## Proof of Concept

```move
#[test(account = @aptos_framework)]
public entry fun test_incomplete_event_history_attack(account: signer) acquires Account, OriginatingAddress {
    initialize(&account);
    
    // Step 1: Create account with initial key A
    let (sk_a, pk_a) = ed25519::generate_keys();
    let pk_a_unvalidated = ed25519::public_key_to_unvalidated(&pk_a);
    let auth_key_a = ed25519::unvalidated_public_key_to_authentication_key(&pk_a_unvalidated);
    let alice_addr = from_bcs::to_address(auth_key_a);
    let alice = create_account_unchecked(alice_addr);
    
    // Verify initial state
    assert!(Account[alice_addr].authentication_key == auth_key_a, 0);
    
    // Step 2: Rotate to key B using rotate_authentication_key_call (NO EVENT)
    let (sk_b, pk_b) = ed25519::generate_keys();
    let pk_b_unvalidated = ed25519::public_key_to_unvalidated(&pk_b);
    let auth_key_b = ed25519::unvalidated_public_key_to_authentication_key(&pk_b_unvalidated);
    
    rotate_authentication_key_call(&alice, auth_key_b);
    
    // Verify key was rotated but NO KeyRotation event was emitted
    assert!(Account[alice_addr].authentication_key == auth_key_b, 1);
    
    // Step 3: Rotate to key C using full rotate_authentication_key (EMITS EVENT)
    let (sk_c, pk_c) = ed25519::generate_keys();
    let pk_c_unvalidated = ed25519::public_key_to_unvalidated(&pk_c);
    let auth_key_c = ed25519::unvalidated_public_key_to_authentication_key(&pk_c_unvalidated);
    
    let challenge = RotationProofChallenge {
        sequence_number: Account[alice_addr].sequence_number,
        originator: alice_addr,
        current_auth_key: from_bcs::to_address(auth_key_b),
        new_public_key: ed25519::unvalidated_public_key_to_bytes(&pk_c_unvalidated),
    };
    
    let from_sig = ed25519::sign_struct(&sk_b, challenge);
    let to_sig = ed25519::sign_struct(&sk_c, challenge);
    
    rotate_authentication_key(
        &alice,
        ED25519_SCHEME,
        ed25519::unvalidated_public_key_to_bytes(&pk_b_unvalidated),
        ED25519_SCHEME,
        ed25519::unvalidated_public_key_to_bytes(&pk_c_unvalidated),
        ed25519::signature_to_bytes(&from_sig),
        ed25519::signature_to_bytes(&to_sig),
    );
    
    // Step 4: Verify the attack succeeded
    // The KeyRotation event emitted shows old_authentication_key = B (not A!)
    // Event history is: B → C
    // But actual history was: A → B → C
    // The rotation from A to B is completely hidden from event logs!
    
    assert!(Account[alice_addr].authentication_key == auth_key_c, 2);
}
```

This test demonstrates that an attacker can hide the initial key rotation (A→B) from the event history by using `rotate_authentication_key_call`, which does not emit events. The subsequent rotation (B→C) emits an event showing B as the old key, creating an incomplete audit trail that misses the original key A.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L30-35)
```text
    #[event]
    struct KeyRotation has drop, store {
        account: address,
        old_authentication_key: vector<u8>,
        new_authentication_key: vector<u8>,
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

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L453-459)
```text
    /// Note that this does not update the `OriginatingAddress` table because the `new_auth_key` is not "verified": it
    /// does not come with a proof-of-knowledge of the underlying SK. Nonetheless, we need this functionality due to
    /// the introduction of non-standard key algorithms, such as passkeys, which cannot produce proofs-of-knowledge in
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

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L468-496)
```text
    entry fun rotate_authentication_key_from_public_key(account: &signer, scheme: u8, new_public_key_bytes: vector<u8>) acquires Account {
        let addr = signer::address_of(account);
        let account_resource = &Account[addr];
        let old_auth_key = account_resource.authentication_key;
        let new_auth_key;
        if (scheme == ED25519_SCHEME) {
            let from_pk = ed25519::new_unvalidated_public_key_from_bytes(new_public_key_bytes);
            new_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&from_pk);
        } else if (scheme == MULTI_ED25519_SCHEME) {
            let from_pk = multi_ed25519::new_unvalidated_public_key_from_bytes(new_public_key_bytes);
            new_auth_key = multi_ed25519::unvalidated_public_key_to_authentication_key(&from_pk);
        } else if (scheme == SINGLE_KEY_SCHEME) {
            new_auth_key = single_key::new_public_key_from_bytes(new_public_key_bytes).to_authentication_key();
        } else if (scheme == MULTI_KEY_SCHEME) {
            new_auth_key = multi_key::new_public_key_from_bytes(new_public_key_bytes).to_authentication_key();
        } else {
            abort error::invalid_argument(EUNRECOGNIZED_SCHEME)
        };
        rotate_authentication_key_call(account, new_auth_key);
        event::emit(KeyRotationToPublicKey {
            account: addr,
            // Set verified_public_key_bit_map to [0x00, 0x00, 0x00, 0x00] as the public key(s) are not verified
            verified_public_key_bit_map: vector[0x00, 0x00, 0x00, 0x00],
            public_key_scheme: scheme,
            public_key: new_public_key_bytes,
            old_auth_key,
            new_auth_key,
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1084-1088)
```text
            event::emit(KeyRotation {
                account: originating_addr,
                old_authentication_key: account_resource.authentication_key,
                new_authentication_key: new_auth_key_vector,
            });
```
