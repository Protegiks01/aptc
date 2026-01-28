# Audit Report

## Title
Cross-Chain Signature Replay Attack via Missing Chain ID in SignerCapabilityOfferProofChallengeV2

## Summary
The `SignerCapabilityOfferProofChallengeV2` structure used for delegating signer capabilities lacks a `chain_id` field, enabling signature replay attacks across different Aptos networks (mainnet, testnet, devnet). An attacker can observe a signer capability offer signature on one chain and replay it on another chain where the victim uses the same private key, granting unauthorized signer capability without the victim's consent.

## Finding Description

The vulnerability exists in the account capability delegation system within the Aptos Framework. A critical inconsistency in chain ID protection has been identified between two similar capability delegation mechanisms.

**RotationCapabilityOfferProofChallengeV2** correctly includes `chain_id` field for cross-chain replay protection: [1](#0-0) 

The code comment explicitly acknowledges this protection mechanism: [2](#0-1) 

However, **SignerCapabilityOfferProofChallengeV2** is missing the `chain_id` field entirely: [3](#0-2) 

The `offer_rotation_capability` function properly binds to chain_id using `chain_id::get()`: [4](#0-3) 

But the `offer_signer_capability` function constructs the proof challenge without any chain binding: [5](#0-4) 

The signature verification mechanism uses `signature_verify_strict_t`, which wraps messages in a `SignedMessage` structure: [6](#0-5) 

This provides only type-based domain separation via `TypeInfo`, without any chain context: [7](#0-6) 

**Attack Execution Path:**

1. Alice creates a transaction on MAINNET calling `offer_signer_capability` with signature S signed over `SignerCapabilityOfferProofChallengeV2{sequence_number: N, source_address: A, recipient_address: B}`
2. The transaction executes successfully, signature S is recorded on-chain as a transaction parameter
3. Attacker observes the transaction and extracts signature bytes S
4. If Alice uses the same private key on TESTNET with sequence number N, the attacker creates a NEW transaction on TESTNET
5. The attacker calls `offer_signer_capability` on TESTNET using the SAME signature S
6. The `SignerCapabilityOfferProofChallengeV2` struct on TESTNET is identical (same sequence_number, source_address, recipient_address)
7. Signature verification passes because the struct has no chain_id differentiation
8. Bob receives unauthorized signer capability over Alice's TESTNET account

The chain_id mechanism exists and is available via the `chain_id` module: [8](#0-7) 

## Impact Explanation

**Critical Severity - Loss of Funds**

This vulnerability meets the Critical severity criteria for "Loss of Funds (theft)" as defined in the Aptos bug bounty program.

Signer capability is the most powerful capability in the Aptos Framework, granting complete control over an account. An attacker who gains unauthorized signer capability through this cross-chain replay attack can:

- **Direct theft**: Transfer all APT tokens and other assets from the victim's account
- **Arbitrary execution**: Execute any transaction on behalf of the victim
- **State manipulation**: Modify account resources and module states
- **Permanent lockout**: Rotate authentication keys to prevent legitimate owner access
- **Governance abuse**: If the account has voting power or staking positions, manipulate those

The attack enables complete account takeover on the target chain without requiring any compromise of the victim's private key or any social engineering. The vulnerability is particularly severe because:

1. Signer capability offers are legitimate operations visible on-chain
2. Developers commonly use the same keys across testnet and mainnet for testing
3. The attack requires only passive observation and transaction replay
4. No cryptographic breaks or complex exploitation is needed

## Likelihood Explanation

**Medium to High Likelihood**

The vulnerability has medium to high likelihood of exploitation due to several factors:

1. **Common Development Practice**: Developers routinely use identical private keys across testnet, devnet, and mainnet during development and testing phases. This is standard practice in blockchain development.

2. **Public Observability**: All `offer_signer_capability` transactions are publicly visible on-chain, with signature bytes included as transaction parameters. An attacker can trivially monitor and extract these signatures.

3. **Multiple Production Networks**: Aptos operates multiple distinct networks (mainnet, testnet, devnet) as evidenced by the chain_id infrastructure, increasing attack surface.

4. **Sequence Number Feasibility**: While sequence numbers must align for the attack to succeed, this is more feasible than it initially appears:
   - Accounts often have similar transaction patterns across chains during testing
   - Attackers can wait for natural sequence number alignment
   - For high-value targets, attackers could front-run transactions to manipulate sequence numbers

5. **No Additional Barriers**: Unlike other vulnerabilities requiring precise timing or complex setups, this attack requires only:
   - Observing a single transaction on one chain
   - Submitting a single transaction on another chain
   - No special privileges or validator access

The only friction is sequence number alignment, which prevents this from being "guaranteed" but doesn't significantly reduce practical exploitability.

## Recommendation

Add a `chain_id` field to `SignerCapabilityOfferProofChallengeV2` struct, matching the fix already applied to `RotationCapabilityOfferProofChallengeV2`:

```move
struct SignerCapabilityOfferProofChallengeV2 has copy, drop {
    chain_id: u8,  // ADD THIS FIELD
    sequence_number: u64,
    source_address: address,
    recipient_address: address,
}
```

Update the `offer_signer_capability` function to include chain_id when constructing the proof challenge:

```move
let proof_challenge = SignerCapabilityOfferProofChallengeV2 {
    chain_id: chain_id::get(),  // ADD THIS LINE
    sequence_number: get_sequence_number(source_address),
    source_address,
    recipient_address,
};
```

This fix follows the exact pattern used for `RotationCapabilityOfferProofChallengeV2` and prevents cross-chain signature replay attacks by binding each signature to a specific chain.

## Proof of Concept

The vulnerability can be demonstrated with the following scenario:

1. Deploy test accounts on both a local testnet (chain_id=4) and a second test network (chain_id=5)
2. Create account Alice with the same private key on both chains
3. Ensure Alice has sequence_number=10 on both chains
4. On chain 4: Alice calls `offer_signer_capability(signature_bytes, scheme, pubkey, Bob)` where signature is signed over `SignerCapabilityOfferProofChallengeV2{10, Alice, Bob}`
5. Extract the signature_bytes from the chain 4 transaction
6. On chain 5: Attacker submits transaction calling `offer_signer_capability` with the SAME signature_bytes
7. The transaction succeeds on chain 5 because the proof challenge is identical
8. Bob now has signer capability over Alice's account on chain 5 without Alice's consent on that chain

The vulnerability is confirmed by the code structure showing that while `RotationCapabilityOfferProofChallengeV2` includes chain_id protection, `SignerCapabilityOfferProofChallengeV2` does not, creating an inconsistent security posture in the capability delegation system.

## Notes

This vulnerability represents a design inconsistency where the Aptos team correctly identified and fixed the cross-chain replay issue for rotation capabilities but failed to apply the same fix to signer capabilities. The comment at line 137 of account.move explicitly acknowledges that chain_id "prevents replaying the challenge message," yet this protection was not extended to the arguably more powerful signer capability delegation mechanism.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L135-137)
```text
    /// This struct stores the challenge message that should be signed by the source account, when the source account
    /// is delegating its rotation capability to the `recipient_address`.
    /// This V2 struct adds the `chain_id` and `source_address` to the challenge message, which prevents replaying the challenge message.
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L138-143)
```text
    struct RotationCapabilityOfferProofChallengeV2 has drop {
        chain_id: u8,
        sequence_number: u64,
        source_address: address,
        recipient_address: address,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L145-149)
```text
    struct SignerCapabilityOfferProofChallengeV2 has copy, drop {
        sequence_number: u64,
        source_address: address,
        recipient_address: address,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L777-782)
```text
        let proof_challenge = RotationCapabilityOfferProofChallengeV2 {
            chain_id: chain_id::get(),
            sequence_number: account_resource.sequence_number,
            source_address: addr,
            recipient_address,
        };
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L922-926)
```text
        let proof_challenge = SignerCapabilityOfferProofChallengeV2 {
            sequence_number: get_sequence_number(source_address),
            source_address,
            recipient_address,
        };
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/ed25519.move (L45-48)
```text
    struct SignedMessage<MessageType> has drop {
        type_info: TypeInfo,
        inner: MessageType,
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/ed25519.move (L142-149)
```text
    public fun signature_verify_strict_t<T: drop>(signature: &Signature, public_key: &UnvalidatedPublicKey, data: T): bool {
        let encoded = SignedMessage {
            type_info: type_info::type_of<T>(),
            inner: data,
        };

        signature_verify_strict_internal(signature.bytes, public_key.bytes, bcs::to_bytes(&encoded))
    }
```

**File:** aptos-move/framework/aptos-framework/sources/chain_id.move (L20-24)
```text
    #[view]
    /// Return the chain ID of this instance.
    public fun get(): u8 acquires ChainId {
        borrow_global<ChainId>(@aptos_framework).id
    }
```
