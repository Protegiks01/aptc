# Audit Report

## Title
Cross-Chain Replay Attack on Authentication Key Rotation via Missing chain_id in RotationProofChallenge

## Summary
The `RotationProofChallenge` structure used for authentication key rotation lacks a `chain_id` field, enabling cross-chain replay attacks where key rotation signatures created for testnet can be replayed on mainnet (or vice versa) if specific account state conditions align. This vulnerability exists despite the codebase containing V2 challenge structures that explicitly include `chain_id` for replay protection.

## Finding Description

The authentication key rotation mechanism in Aptos uses a `RotationProofChallenge` structure that users must sign to prove ownership of both their current and new keys. This challenge structure contains only four fields: `sequence_number`, `originator`, `current_auth_key`, and `new_public_key`. [1](#0-0) 

Critically, this structure lacks a `chain_id` field, meaning signatures are not bound to a specific blockchain network. The signature verification function validates signatures only against this challenge structure without any chain-specific binding. [2](#0-1) 

The codebase demonstrates awareness of this cross-chain replay vulnerability through the existence of V2 challenge structures. The `RotationCapabilityOfferProofChallengeV2` explicitly includes a `chain_id` field with a comment stating: "This V2 struct adds the `chain_id` and `source_address` to the challenge message, which prevents replaying the challenge message." [3](#0-2) 

However, the primary `RotationProofChallenge` used in the `rotate_authentication_key` entry function was never upgraded to include this protection, creating an inconsistency in the security model.

**Attack Scenario:**

1. **Victim Action**: A user with address `0xABCD` tests key rotation on testnet, rotating from key A to key B at sequence number 5
2. **Attacker Observation**: The attacker monitors testnet transactions and extracts the rotation proof signatures (`cap_rotate_key` and `cap_update_table`) from the transaction
3. **Prerequisite Conditions**: The same address `0xABCD` exists on mainnet with:
   - Sequence number also at 5 (achievable if the user performs similar transactions on both chains)
   - Current authentication key matching key A
4. **Replay Attack**: The attacker submits a transaction on mainnet calling `rotate_authentication_key` with the extracted signatures
5. **Result**: The mainnet account's key is rotated to key B, potentially before the user intended or was ready

The CLI implementation confirms this vulnerability, constructing the `RotationProofChallenge` without any chain_id field. [4](#0-3) 

This breaks the **cross-chain isolation invariant**: operations intended for one network (testnet) should never affect another network (mainnet).

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria for the following reasons:

**Impact Category**: State inconsistencies requiring intervention

While this attack does not result in direct fund theft or consensus violations, it enables:

1. **Forced Premature Key Rotation**: An attacker can force a mainnet key rotation before the user is ready, potentially disrupting operational procedures or invalidating prepared transactions
2. **Security Procedure Disruption**: If a user is testing key rotation as part of a security incident response (e.g., suspected key compromise), replaying this on mainnet could interfere with their security procedures
3. **Account State Manipulation**: Forces unwanted changes to account authentication state, requiring manual intervention to revert or adjust

**Limitations on Impact**:
- The victim retains control of the new key (they created and signed the rotation)
- No direct fund loss occurs
- The attack requires specific preconditions (matching sequence numbers, authentication keys)
- Users can still access their accounts with the new key

This does not reach Critical or High severity because:
- No funds are stolen or locked permanently
- No consensus or safety violations occur
- The account remains accessible to its legitimate owner
- No validator node operations are affected

## Likelihood Explanation

**Likelihood: Medium**

The attack is realistic because:

1. **Common User Patterns**: Users frequently test operations on testnet before executing on mainnet, often using the same keypairs and deterministic addresses for convenience
2. **Public Transaction Visibility**: All testnet transactions are publicly observable, giving attackers full visibility into rotation signatures
3. **Sequence Number Synchronization**: Users performing similar transaction sequences on both networks will naturally have aligned sequence numbers
4. **No Technical Barriers**: The attack requires no special privileges, consensus manipulation, or validator access—only the ability to observe testnet and submit transactions

**Attack Prerequisites**:
- Same account address exists on both testnet and mainnet (common due to deterministic address derivation)
- Matching sequence numbers (achievable within a narrow window)
- Matching current authentication key (likely during testing phases)
- Attacker monitors testnet activity

**Constraining Factors**:
- The attack window is narrow: only viable when sequence numbers align
- The victim must have tested rotation on testnet first
- Both accounts must have identical current authentication keys
- The rotation must be to the same new public key

## Recommendation

Add a `chain_id` field to the `RotationProofChallenge` structure, following the pattern already established in V2 challenge structures:

```move
struct RotationProofChallenge has copy, drop {
    chain_id: u8,
    sequence_number: u64,
    originator: address,
    current_auth_key: address,
    new_public_key: vector<u8>,
}
```

Update the challenge construction in `rotate_authentication_key` to include the chain_id:

```move
let challenge = RotationProofChallenge {
    chain_id: chain_id::get(),
    sequence_number: account_resource.sequence_number,
    originator: addr,
    current_auth_key: curr_auth_key_as_address,
    new_public_key: to_public_key_bytes,
};
```

This change must be coordinated with:
1. The Rust type definition [5](#0-4) 
2. CLI implementation [4](#0-3) 
3. All test files constructing `RotationProofChallenge`

**Migration Strategy**: This is a breaking change requiring a coordinated upgrade. Consider introducing `RotationProofChallengeV2` with chain_id while maintaining backward compatibility during a transition period, similar to how capability offer challenges were upgraded.

## Proof of Concept

```move
#[test_only]
module test_addr::cross_chain_replay_test {
    use std::signer;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_std::ed25519;
    
    #[test(framework = @0x1, testnet_user = @0xABCD, mainnet_user = @0xABCD)]
    fun test_cross_chain_key_rotation_replay(
        framework: &signer,
        testnet_user: &signer,
        mainnet_user: &signer,
    ) {
        // Step 1: Setup testnet (chain_id = 2)
        chain_id::initialize(framework, 2);
        account::create_account_for_test(signer::address_of(testnet_user));
        
        // Step 2: User creates rotation signatures for testnet
        let old_privkey = /* generate key A */;
        let new_privkey = /* generate key B */;
        
        // Construct RotationProofChallenge (no chain_id!)
        let challenge = RotationProofChallenge {
            sequence_number: 0,
            originator: signer::address_of(testnet_user),
            current_auth_key: /* auth key A */,
            new_public_key: /* pubkey B */,
        };
        
        let cap_rotate_key = old_privkey.sign(challenge);
        let cap_update_table = new_privkey.sign(challenge);
        
        // Step 3: User rotates key on testnet
        account::rotate_authentication_key(
            testnet_user,
            0, // ED25519_SCHEME
            old_pubkey,
            0,
            new_pubkey,
            cap_rotate_key,
            cap_update_table,
        );
        
        // Step 4: Simulate mainnet (chain_id = 1)
        // Reset chain_id to mainnet value
        chain_id::initialize(framework, 1);
        account::create_account_for_test(signer::address_of(mainnet_user));
        
        // Step 5: Attacker replays the SAME signatures on mainnet
        // This succeeds because signatures don't include chain_id!
        account::rotate_authentication_key(
            mainnet_user,
            0,
            old_pubkey,
            0,
            new_pubkey,
            cap_rotate_key,  // Same signature from testnet!
            cap_update_table, // Same signature from testnet!
        );
        
        // Both testnet and mainnet accounts now have rotated keys
        // despite user only intending to rotate on testnet
    }
}
```

**Notes**:
- The KeyRotationEvent itself is just an event emitted after successful rotation; it does not directly cause the vulnerability but reflects it [6](#0-5) 
- The root cause is the missing chain_id in the signed challenge structure
- Transaction-level chain_id validation prevents transaction replay but does not prevent signature replay within valid transactions [7](#0-6)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L112-121)
```text
    struct RotationProofChallenge has copy, drop {
        sequence_number: u64,
        // the sequence number of the account whose key is being rotated
        originator: address,
        // the address of the account whose key is being rotated
        current_auth_key: address,
        // the current authentication key of the account whose key is being rotated
        new_public_key: vector<u8>,
        // the new public key that the account owner wants to rotate to
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L135-143)
```text
    /// This struct stores the challenge message that should be signed by the source account, when the source account
    /// is delegating its rotation capability to the `recipient_address`.
    /// This V2 struct adds the `chain_id` and `source_address` to the challenge message, which prevents replaying the challenge message.
    struct RotationCapabilityOfferProofChallengeV2 has drop {
        chain_id: u8,
        sequence_number: u64,
        source_address: address,
        recipient_address: address,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1015-1040)
```text
    fun assert_valid_rotation_proof_signature_and_get_auth_key(
        scheme: u8,
        public_key_bytes: vector<u8>,
        signature: vector<u8>,
        challenge: &RotationProofChallenge
    ): vector<u8> {
        if (scheme == ED25519_SCHEME) {
            let pk = ed25519::new_unvalidated_public_key_from_bytes(public_key_bytes);
            let sig = ed25519::new_signature_from_bytes(signature);
            assert!(
                ed25519::signature_verify_strict_t(&sig, &pk, *challenge),
                std::error::invalid_argument(EINVALID_PROOF_OF_KNOWLEDGE)
            );
            ed25519::unvalidated_public_key_to_authentication_key(&pk)
        } else if (scheme == MULTI_ED25519_SCHEME) {
            let pk = multi_ed25519::new_unvalidated_public_key_from_bytes(public_key_bytes);
            let sig = multi_ed25519::new_signature_from_bytes(signature);
            assert!(
                multi_ed25519::signature_verify_strict_t(&sig, &pk, *challenge),
                std::error::invalid_argument(EINVALID_PROOF_OF_KNOWLEDGE)
            );
            multi_ed25519::unvalidated_public_key_to_authentication_key(&pk)
        } else {
            abort error::invalid_argument(EINVALID_SCHEME)
        }
    }
```

**File:** crates/aptos/src/account/key_rotation.rs (L193-202)
```rust
        let rotation_proof = RotationProofChallenge {
            account_address: CORE_CODE_ADDRESS,
            module_name: "account".to_string(),
            struct_name: "RotationProofChallenge".to_string(),
            sequence_number,
            originator: current_address,
            current_auth_key: AccountAddress::from_bytes(auth_key)
                .map_err(|err| CliError::UnableToParse("auth_key", err.to_string()))?,
            new_public_key: new_public_key.to_bytes().to_vec(),
        };
```

**File:** types/src/account_config/resources/challenge.rs (L13-24)
```rust
pub struct RotationProofChallenge {
    // Should be `CORE_CODE_ADDRESS`
    pub account_address: AccountAddress,
    // Should be `account`
    pub module_name: String,
    // Should be `RotationProofChallenge`
    pub struct_name: String,
    pub sequence_number: u64,
    pub originator: AccountAddress,
    pub current_auth_key: AccountAddress,
    pub new_public_key: Vec<u8>,
}
```

**File:** types/src/account_config/events/key_rotation_event.rs (L15-19)
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    old_authentication_key: Vec<u8>,
    new_authentication_key: Vec<u8>,
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L143-143)
```text
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));
```
