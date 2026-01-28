# Audit Report

## Title
Missing BCS Stream Validation Allows Padding Injection in Derivable Account Abstract Public Keys

## Summary
The `ethereum_derivable_account.move` and `solana_derivable_account.move` modules fail to validate that all bytes are consumed during BCS deserialization of `abstract_public_key`, allowing attackers to inject arbitrary padding that affects address derivation but is ignored during authentication, breaking the 1:1 mapping between external identities and Aptos addresses.

## Finding Description

The derivable account abstraction system derives Aptos addresses by hashing the BCS-serialized `abstract_public_key`. The address derivation function includes the entire raw byte vector in the hash computation: [1](#0-0) 

However, the Ethereum implementation deserializes `abstract_public_key` without validating that all bytes were consumed from the BCS stream: [2](#0-1) 

The Solana implementation has the same vulnerability: [3](#0-2) 

In contrast, the Sui implementation correctly validates that all bytes were consumed, preventing this attack: [4](#0-3) 

The `bcs_stream` module provides the `has_remaining()` function specifically for this validation: [5](#0-4) 

This pattern is consistently used across other Aptos cryptographic modules. For example, `single_key.move`: [6](#0-5) 

And `multi_key.move`: [7](#0-6) 

The Sui module also includes explicit tests demonstrating this vulnerability is a known attack pattern: [8](#0-7) 

**Attack Scenario:**

1. Attacker creates `pk_padded = BCS(ethereum_address, domain) || [0xDE, 0xAD, 0xBE, 0xEF]`
2. Address derivation includes the entire byte vector (with padding) when computing the hash, producing address_A
3. During authentication, deserialization only reads `ethereum_address` and `domain`, leaving padding bytes unconsumed
4. Attacker can also derive address_B using unpadded version with same Ethereum credentials
5. Both addresses authenticate with the same Ethereum signature but are different Aptos addresses

This breaks the invariant that one external identity deterministically maps to exactly one Aptos address.

## Impact Explanation

This is a **MEDIUM severity** vulnerability per Aptos bug bounty criteria, specifically categorized as "Limited Protocol Violations":

1. **Protocol Invariant Violation**: Breaks the fundamental assumption that derivable account abstraction provides deterministic 1:1 mapping between external identities and Aptos addresses.

2. **Account Squatting/Griefing**: Attackers can pre-register multiple addresses derived from their external identity, creating namespace confusion and preventing legitimate users from claiming their canonical address.

3. **Application-Level Exploits**: Smart contracts and dApps assuming address uniqueness per identity could be exploited for:
   - Airdrop gaming (claiming multiple allocations)
   - Voting system manipulation (multiple votes from one identity)
   - Access control bypasses (creating shadow accounts)

4. **State Consistency**: While deterministic execution is maintained across validators (no consensus split), the protocol semantics are violated at the application layer.

The vulnerability does NOT cause: direct fund theft from the protocol, consensus splits, network partitions, or loss of liveness. Therefore, it appropriately falls into the **MEDIUM severity** category.

## Likelihood Explanation

**Likelihood: HIGH**

- **Ease of Exploitation**: Trivial - attacker only needs to append arbitrary bytes to a valid BCS-serialized `abstract_public_key`
- **Attacker Requirements**: None - any user can submit transactions with padded keys through normal transaction submission
- **Detection Difficulty**: Low - the malformed keys are silently accepted without error
- **Affected Scope**: All users of Ethereum and Solana derivable account abstractions
- **Preconditions**: Only requires derivable account abstraction features to be enabled

## Recommendation

Add validation to ensure all bytes are consumed during BCS deserialization, matching the pattern used in Sui and other Aptos cryptographic modules:

For `ethereum_derivable_account.move`:
```move
fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): SIWEAbstractPublicKey {
    let stream = bcs_stream::new(*abstract_public_key);
    let ethereum_address = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
    let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
    assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA);  // ADD THIS LINE
    SIWEAbstractPublicKey { ethereum_address, domain }
}
```

Apply the same fix to `deserialize_abstract_signature()` in both Ethereum and Solana modules. Add corresponding error constants and tests for trailing bytes, following the Sui implementation pattern.

## Proof of Concept

The Sui implementation already includes explicit tests demonstrating this vulnerability: [9](#0-8) 

A similar test can be added to the Ethereum module by appending padding bytes to a valid `abstract_public_key`, which would currently succeed but should fail with proper validation.

## Notes

This vulnerability represents a systematic gap in input validation between the Ethereum/Solana implementations and the Sui implementation. The existence of `has_remaining()` validation in Sui, `single_key`, `multi_key`, and other modules demonstrates this is a known security pattern in the Aptos codebase that was inadvertently omitted from the Ethereum and Solana derivable account implementations.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/account_abstraction.move (L114-117)
```text
        let bytes = bcs::to_bytes(&derivable_func_info);
        bytes.append(bcs::to_bytes(abstract_public_key));
        bytes.push_back(DERIVABLE_ABSTRACTION_DERIVED_SCHEME);
        from_bcs::to_address(hash::sha3_256(bytes))
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/ethereum_derivable_account.move (L75-80)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): SIWEAbstractPublicKey {
        let stream = bcs_stream::new(*abstract_public_key);
        let ethereum_address = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        SIWEAbstractPublicKey { ethereum_address, domain }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/solana_derivable_account.move (L60-66)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>):
    (vector<u8>, vector<u8>) {
        let stream = bcs_stream::new(*abstract_public_key);
        let base58_public_key = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        (base58_public_key, domain)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L113-119)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): SuiAbstractPublicKey {
        let stream = bcs_stream::new(*abstract_public_key);
        let sui_account_address = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA);
        SuiAbstractPublicKey { sui_account_address, domain }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L410-421)
```text
    #[expected_failure(abort_code = EMALFORMED_DATA)]
    fun test_deserialize_abstract_signature_with_trailing_bytes() {
        let signature_bytes = vector[0, 151, 47, 171, 144, 115, 16, 129, 17, 202, 212, 180, 155, 213, 223, 249, 203, 195, 0, 84, 142, 121, 167, 29, 113, 159, 33, 177, 108, 137, 113, 160, 118, 41, 246, 199, 202, 79, 151, 27, 86, 235, 219, 123, 168, 152, 38, 124, 147, 146, 118, 101, 37, 187, 223, 206, 120, 101, 148, 33, 141, 80, 60, 155, 13, 25, 200, 235, 92, 139, 72, 175, 189, 40, 0, 65, 76, 215, 148, 94, 194, 78, 134, 60, 189, 212, 116, 40, 134, 179, 104, 31, 249, 222, 84, 104, 202];
        let abstract_signature = create_raw_signature(signature_bytes);
        // Append trailing bytes to simulate griefing attack
        abstract_signature.push_back(0xDE);
        abstract_signature.push_back(0xAD);
        abstract_signature.push_back(0xBE);
        abstract_signature.push_back(0xEF);
        // This should fail with EMALFORMED_DATA due to trailing bytes
        deserialize_abstract_signature(&abstract_signature);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L423-436)
```text
    #[test]
    #[expected_failure(abort_code = EMALFORMED_DATA)]
    fun test_deserialize_abstract_public_key_with_trailing_bytes() {
        let sui_account_address = b"0x8d6ce7a3c13617b29aaf7ec58bee5a611606a89c62c5efbea32e06d8d167bd49";
        let domain = b"localhost:3001";
        let abstract_public_key = create_abstract_public_key(sui_account_address, domain);
        // Append trailing bytes to simulate griefing attack
        abstract_public_key.push_back(0xDE);
        abstract_public_key.push_back(0xAD);
        abstract_public_key.push_back(0xBE);
        abstract_public_key.push_back(0xEF);
        // This should fail with EMALFORMED_DATA due to trailing bytes
        deserialize_abstract_public_key(&abstract_public_key);
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/bcs_stream.move (L39-41)
```text
    public fun has_remaining(stream: &mut BCSStream): bool {
        stream.cur < stream.data.length()
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/single_key.move (L66-71)
```text
    public fun new_public_key_from_bytes(bytes: vector<u8>): AnyPublicKey {
        let stream = bcs_stream::new(bytes);
        let pk = deserialize_any_public_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_SINGLE_KEY_EXTRA_BYTES));
        pk
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_key.move (L51-56)
```text
    public fun new_public_key_from_bytes(bytes: vector<u8>): MultiKey {
        let stream = bcs_stream::new(bytes);
        let pk = deserialize_multi_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_MULTI_KEY_EXTRA_BYTES));
        pk
    }
```
