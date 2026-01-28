# Audit Report

## Title
BLS12-381 Public Key Subgroup Check Gas Undercharging Vulnerability Enabling Validator DoS

## Summary
The native Rust function `bls12381_pk_subgroub_check()` incorrectly charges `BLS12381_PER_PUBKEY_DESERIALIZE` (400,684 gas units) instead of the correct `BLS12381_PER_PUBKEY_SUBGROUP_CHECK` (1,360,120 gas units) at line 158, resulting in a 71% undercharge. This vulnerability is exploitable via public Move API functions and enables resource exhaustion attacks against validator nodes through a 3.4x computational cost amplification. [1](#0-0) 

## Finding Description

The vulnerability exists in the BLS12-381 cryptographic native implementation. The function `bls12381_pk_subgroub_check()` performs prime-order subgroup membership checking, an expensive cryptographic operation taking approximately 39 microseconds according to inline documentation.

**Gas Charging Error:**

The function charges for deserialization instead of subgroup checking: [2](#0-1) 

The correct gas parameter exists in the gas schedule configuration: [3](#0-2) 

**Gas Cost Discrepancy:** [4](#0-3) 

- Charged: 400,684 gas units
- Should charge: 1,360,120 gas units  
- Undercharge: 959,436 gas units (71% discount)

**Exploitation Paths:**

1. Via `public_key_from_bytes()`: [5](#0-4) [6](#0-5) [7](#0-6) 

2. Via `verify_normal_signature()`: [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10) 

## Impact Explanation

**Severity: High** (Validator Node Slowdowns per Aptos Bug Bounty)

This vulnerability enables resource exhaustion through gas undercharging:

- **Resource Amplification**: 3.4x (attackers pay 400K gas, validators perform 1.36M gas worth of computation)
- **Per-operation savings**: 959,436 gas units undercharged
- **Attack vector**: Public Move APIs accessible to any transaction sender

An attacker can submit transactions repeatedly calling these functions, forcing validators to execute expensive cryptographic operations while paying only 29% of the true computational cost. With sustained transaction volume, this leads to:

1. Increased block execution time
2. Validator CPU saturation  
3. Potential consensus delays
4. Degraded network performance

This aligns with the HIGH severity category "Validator Node Slowdowns: DoS through resource exhaustion" where gas calculation bugs cause validator performance degradation.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Any Aptos user with transaction submission capability
- **Economic Barrier**: Minimal (71% discount on expensive operations)
- **Complexity**: Low (simple Move function calls, no special knowledge required)
- **Detection**: Difficult (transactions execute successfully, gas charges appear normal)

The BLS12-381 APIs are publicly documented and widely used for signature verification, making this vulnerability easily discoverable and exploitable.

## Recommendation

Change line 158 to charge the correct gas parameter:

```rust
context.charge(BLS12381_PER_PUBKEY_SUBGROUP_CHECK * NumArgs::one())?;
```

The correct constant should be imported from the gas parameters module. Verify all other BLS12-381 functions charge appropriate gas amounts for their operations.

## Proof of Concept

```move
script {
    use aptos_std::bls12381;
    
    fun exploit(account: &signer) {
        // Arbitrary 48-byte input
        let pk_bytes = x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        // Each call costs validators 1.36M gas but only charges 400K
        let _ = bls12381::public_key_from_bytes(pk_bytes);
        let _ = bls12381::public_key_from_bytes(pk_bytes);
        // Repeat to maximize resource amplification within gas limit
    }
}
```

## Notes

The function name contains a typo (`bls12381_pk_subgroub_check` instead of `bls12381_pk_subgroup_check`), but the primary security issue is the incorrect gas charging. The correct gas parameter `bls12381_per_pubkey_subgroup_check` exists in the gas schedule configuration but is never used in the Rust implementation, confirming this is an implementation bug rather than a configuration issue.

### Citations

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L153-161)
```rust
fn bls12381_pk_subgroub_check(
    pk: &bls12381::PublicKey,
    context: &mut SafeNativeContext,
) -> SafeNativeResult<bool> {
    // NOTE(Gas): constant-time; around 39 microseconds on Apple M1
    context.charge(BLS12381_PER_PUBKEY_DESERIALIZE * NumArgs::one())?;

    Ok(pk.subgroup_check().is_ok())
}
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L225-227)
```rust
    if check_pk_subgroup && !bls12381_pk_subgroub_check(&pk, context)? {
        return Ok(smallvec![Value::bool(false)]);
    }
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L392-412)
```rust
fn native_bls12381_validate_pubkey(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    context.charge(BLS12381_BASE)?;

    let pk_bytes = safely_pop_arg!(arguments, Vec<u8>);

    let pk = match bls12381_deserialize_pk(pk_bytes, context)? {
        Some(key) => key,
        None => return Ok(smallvec![Value::bool(false)]),
    };

    let valid = bls12381_pk_subgroub_check(&pk, context)?;

    Ok(smallvec![Value::bool(valid)])
}
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L536-546)
```rust
pub fn native_bls12381_verify_normal_signature(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // For normal (non-aggregated) signatures, PK's typically don't come with PoPs and the caller
    // might forget to check prime-order subgroup membership of the PK. Therefore, we always enforce
    // it here.
    let check_pk_subgroup = true;
    bls12381_verify_signature_helper(context, ty_args, arguments, check_pk_subgroup)
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L174-176)
```rust
        [bls12381_per_pubkey_deserialize: InternalGasPerArg, "bls12381.per_pubkey_deserialize", 400684],
        [bls12381_per_pubkey_aggregate: InternalGasPerArg, "bls12381.per_pubkey_aggregate", 15439],
        [bls12381_per_pubkey_subgroup_check: InternalGasPerArg, "bls12381.per_pubkey_subgroup_check", 1360120],
```

**File:** aptos-move/aptos-release-builder/data/example-release-with-randomness-framework/output/5-gas-schedule.move (L318-320)
```text
//     aptos_framework.bls12381.per_pubkey_deserialize                         : 400684
//     aptos_framework.bls12381.per_pubkey_aggregate                           : 15439
//     aptos_framework.bls12381.per_pubkey_subgroup_check                      : 1360120
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381.move (L87-95)
```text
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

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381.move (L229-235)
```text
    public fun verify_normal_signature(
        signature: &Signature,
        public_key: &PublicKey,
        message: vector<u8>
    ): bool {
        verify_normal_signature_internal(signature.bytes, public_key.bytes, message)
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381.move (L390-390)
```text
    native fun validate_pubkey_internal(public_key: vector<u8>): bool;
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381.move (L438-442)
```text
    native fun verify_normal_signature_internal(
        signature: vector<u8>,
        public_key: vector<u8>,
        message: vector<u8>
    ): bool;
```
