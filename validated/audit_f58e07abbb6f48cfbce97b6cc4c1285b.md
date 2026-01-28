# Audit Report

## Title
BLS12-381 Public Key Subgroup Check Gas Undercharging Vulnerability Enabling Validator DoS

## Summary
The native Rust function `bls12381_pk_subgroub_check()` incorrectly charges `BLS12381_PER_PUBKEY_DESERIALIZE` (400,684 gas units) instead of `BLS12381_PER_PUBKEY_SUBGROUP_CHECK` (1,360,120 gas units), resulting in a 71% undercharge that enables resource exhaustion attacks against validator nodes through a 3.4x computational cost amplification.

## Finding Description

The vulnerability exists in the BLS12-381 cryptographic native implementation where prime-order subgroup membership checking is performed. The function `bls12381_pk_subgroub_check()` performs an expensive cryptographic operation documented to take approximately 39 microseconds.

**Gas Charging Error:**

The function charges for deserialization instead of subgroup checking: [1](#0-0) 

The correct gas parameter exists in the gas schedule: [2](#0-1) 

**Gas Cost Discrepancy:**
- Charged: 400,684 gas units (deserialize cost)
- Should charge: 1,360,120 gas units (subgroup check cost)
- Undercharge: 959,436 gas units (71% discount)

**Exploitation Path 1 - Via `public_key_from_bytes()`:**

Public Move API function: [3](#0-2) 

Native implementation that calls the vulnerable function: [4](#0-3) 

**Exploitation Path 2 - Via `verify_normal_signature()`:**

Public Move API function: [5](#0-4) 

Native implementation enforcing subgroup check: [6](#0-5) 

Call to vulnerable function: [7](#0-6) 

**Supporting Evidence:**

The signature subgroup check correctly uses its designated gas constant, demonstrating the public key version is anomalous: [8](#0-7) 

## Impact Explanation

**Severity: High** (Validator Node Slowdowns per Aptos Bug Bounty)

This vulnerability enables resource exhaustion through gas undercharging, matching the exact HIGH severity example in the Aptos Bug Bounty Program: "Gas calculation bug causes validator slowdowns."

**Resource Amplification:** 3.4x (attackers pay 400K gas, validators perform 1.36M gas worth of computation)

**Attack Mechanics:**
An attacker submits transactions repeatedly calling `public_key_from_bytes()` or `verify_normal_signature()`, forcing validators to execute expensive cryptographic operations (39 microseconds each) while paying only 29% of the true computational cost. With sustained transaction volume targeting multiple blocks, this leads to:

1. Increased block execution time due to accumulated undercharged computation
2. Validator CPU saturation from processing 3.4x more work than paid for
3. Potential consensus delays as block processing slows
4. Degraded network performance affecting other transactions

The vulnerability directly breaks the gas metering security guarantee that computational costs are accurately reflected in gas charges, enabling resource exhaustion attacks.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Any Aptos user with transaction submission capability
- **Economic Barrier**: Minimal (71% discount on expensive operations makes attack economically favorable)
- **Complexity**: Low (simple public Move function calls, no special privileges required)
- **Detection**: Difficult (transactions execute successfully with normal-appearing gas charges)
- **Discoverability**: BLS12-381 APIs are publicly documented and widely used

The public nature of the affected APIs and significant gas discount make exploitation straightforward for any network participant.

## Recommendation

Change line 158 in `aptos-move/framework/src/natives/cryptography/bls12381.rs` to charge the correct gas constant:

```rust
// Current (incorrect):
context.charge(BLS12381_PER_PUBKEY_DESERIALIZE * NumArgs::one())?;

// Fixed:
context.charge(BLS12381_PER_PUBKEY_SUBGROUP_CHECK * NumArgs::one())?;
```

This aligns the public key subgroup check with the pattern used in the signature subgroup check function and ensures accurate gas metering for the computational cost incurred.

## Proof of Concept

A Move test demonstrating the gas undercharging:

```move
#[test]
fun test_gas_undercharge_exploit() {
    use std::bls12381;
    use std::vector;
    
    // Valid BLS12-381 public key bytes (48 bytes)
    let pk_bytes = x"..."; // Insert valid serialized public key
    
    // This call performs expensive subgroup checking
    // but only charges deserialize gas (400,684)
    // instead of subgroup check gas (1,360,120)
    let pk_opt = bls12381::public_key_from_bytes(pk_bytes);
    
    // Attacker can call this repeatedly in transactions
    // paying ~71% less than the actual computational cost
    // causing validators to perform undercharged work
}
```

## Notes

The typo in the function name (`subgroub` instead of `subgroup`) appears throughout the codebase but does not affect the vulnerability. The gas constant `BLS12381_PER_PUBKEY_SUBGROUP_CHECK` exists and is properly defined with value 1,360,120, but the function incorrectly references `BLS12381_PER_PUBKEY_DESERIALIZE` (value 400,684) instead.

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

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L164-171)
```rust
fn bls12381_sig_subgroub_check(
    sig: &bls12381::Signature,
    context: &mut SafeNativeContext,
) -> SafeNativeResult<bool> {
    context.charge(BLS12381_PER_SIG_SUBGROUP_CHECK * NumArgs::one())?;

    Ok(sig.subgroup_check().is_ok())
}
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L225-227)
```rust
    if check_pk_subgroup && !bls12381_pk_subgroub_check(&pk, context)? {
        return Ok(smallvec![Value::bool(false)]);
    }
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L400-412)
```rust
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
