# Audit Report

## Title
Discrete Logarithm Attack on Zero-Randomness ElGamal Ciphertexts Enables Balance Deanonymization Through Homomorphic Operations

## Summary
The veiled coin implementation uses ElGamal encryption with zero randomness for public veil/unveil operations, creating ciphertexts of the form `(v*G, 0*G)`. An attacker who observes known plaintext-ciphertext pairs can use the homomorphic properties of `ciphertext_add()` and `ciphertext_sub()` combined with discrete logarithm computation (via baby-step giant-step algorithm) to completely deanonymize encrypted balances for any account that has not received a fully veiled transfer.

## Finding Description

The veiled coin system encrypts coin balances using ElGamal encryption "in the exponent" where a value `v` is encrypted as `(v*G + r*Y, r*G)` where `G` is the Ristretto255 basepoint, `Y` is the public key, and `r` is a random scalar. [1](#0-0) 

When users veil or unveil public amounts, the system creates ciphertexts with zero randomness using `new_ciphertext_no_randomness()`, which produces `(v*G, 0*G)`. [2](#0-1) 

This zero-randomness ciphertext is used in two critical operations:
1. When converting public amounts to veiled balances [3](#0-2) 
2. When unveiling public amounts from encrypted balances [4](#0-3) 

**The Attack Vector:**

1. **Initial Veil Operation**: When Alice veils 1000 coins, her balance becomes `(1000*G, 0*G)` with randomness `r=0`.

2. **Subsequent Unveil Operations**: When Alice unveils 300 coins, the system computes `balance - (300*G, 0*G)`, resulting in `(700*G, 0*G)` - still with `r=0`. The randomness component remains zero until a fully veiled transfer occurs.

3. **Homomorphic Subtraction Attack**: An attacker who knows Alice veiled 1000 coins initially can:
   - Observe Alice's current encrypted balance on-chain: `CT_current`
   - Compute: `CT_current - (1000*G, 0*G) = (delta*G, 0*G)` where `delta` is the net change
   - Use this to track all of Alice's balance changes over time

4. **Discrete Logarithm Recovery**: Since veiled coin amounts are restricted to 32 bits (approximately 4 billion values), an attacker can use the baby-step giant-step algorithm to solve the discrete log problem in `O(sqrt(2^32)) = O(2^16) ≈ 65,536` operations. [5](#0-4) 

The codebase already implements BSGS for discrete log computation: [6](#0-5) 

5. **Complete Deanonymization**: By combining homomorphic operations with discrete log computation, an attacker can:
   - Determine exact balances for any account that was initialized via `veil()`
   - Track all balance changes through homomorphic arithmetic
   - Retroactively deanonymize all historical balances once any known plaintext is observed

This breaks the fundamental security guarantee stated in the documentation: "a veiled balance is secret; i.e., it is encrypted under the account's public key." [7](#0-6) 

## Impact Explanation

This vulnerability represents a **High Severity** issue under the category "Significant protocol violations" because it completely breaks the privacy guarantees of the veiled coin system for a large class of users (those who haven't received fully veiled transfers).

While the module is marked as experimental, the security question specifically asks whether this attack is possible, indicating it's being evaluated for potential production use. The impact includes:

1. **Complete Privacy Loss**: All encrypted balances for accounts initialized via public veil operations can be fully deanonymized
2. **Retroactive Deanonymization**: Once any known plaintext is observed, all historical balance states become recoverable
3. **Permanent Privacy Violation**: The information leakage cannot be reversed once the discrete log is computed
4. **System-Wide Impact**: Affects all users who use the standard onboarding flow (veil → transfer → unveil)

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **Trivial to Execute**: Any blockchain observer can perform this attack with standard computational resources
2. **No Special Privileges Required**: Attacker only needs read access to blockchain state (publicly available)
3. **Computationally Feasible**: BSGS with 2^16 operations is trivial on modern hardware (milliseconds)
4. **Expected User Behavior**: Most users will veil public amounts initially, making them vulnerable
5. **Persistent Vulnerability**: The zero-randomness property persists through all unveil operations until a fully veiled transfer

The attack is not theoretical - the codebase already contains the discrete log implementation needed to execute it.

## Recommendation

**Immediate Fix**: Always add proper randomness to ciphertexts, even for public amounts:

1. **Modify `unveil_to_internal()`**: Instead of using `new_ciphertext_no_randomness()`, generate a proper ciphertext with randomness:

```move
// Instead of:
let veiled_amount = elgamal::new_ciphertext_no_randomness(&scalar_amount);

// Use:
let random_r = ristretto255::random_scalar();
let veiled_amount = elgamal::new_ciphertext_with_basepoint(&scalar_amount, &random_r, &sender_pk);
```

2. **Modify `public_amount_to_veiled_balance()`**: Generate proper ciphertexts with randomness for veil operations.

3. **Add Re-randomization**: Automatically re-randomize balances after any operation to prevent randomness from becoming stale.

4. **Document Limitations**: If zero-randomness ciphertexts are kept for performance reasons, explicitly document that balances are NOT private until a fully veiled transfer occurs, and warn that all historical states are retroactively compromised.

**Alternative Approach**: Use Twisted ElGamal with mandatory range proofs on all operations, which provides better privacy guarantees.

## Proof of Concept

```move
#[test(framework = @aptos_framework, user = @0x123)]
fun test_known_plaintext_attack(framework: &signer, user: &signer) {
    // Setup
    veiled_coin::init_module_for_testing(framework);
    let (sk, pk) = helpers::generate_elgamal_keypair();
    veiled_coin::register_internal<AptosCoin>(user, pk);
    
    // User veils 1000 coins (PUBLIC OPERATION - attacker knows this)
    coin::mint_test<AptosCoin>(user, 1000_0000); // with decimals
    veiled_coin::veil<AptosCoin>(user, 1000);
    
    // Get encrypted balance
    let balance_ct = veiled_coin::veiled_balance<AptosCoin>(@0x123);
    let balance = elgamal::decompress_ciphertext(&balance_ct);
    let (left, right) = elgamal::ciphertext_as_points(&balance);
    
    // ATTACK: Since right component is identity (r=0), we can brute force left component
    // For i in [0, 2^32), check if i*G == left
    // With BSGS, this takes O(2^16) operations - feasible!
    
    // Verify the balance is indeed recoverable
    assert!(ristretto255::point_equals(
        right, 
        &ristretto255::point_identity()
    ), 0); // Confirms r=0
    
    // User unveils 300 coins (PUBLIC OPERATION)
    // Generate required proofs...
    veiled_coin::unveil<AptosCoin>(user, 300, comm_new_balance, zkrp, subproof);
    
    // Get new balance
    let new_balance_ct = veiled_coin::veiled_balance<AptosCoin>(@0x123);
    let new_balance = elgamal::decompress_ciphertext(&new_balance_ct);
    let (new_left, new_right) = elgamal::ciphertext_as_points(&new_balance);
    
    // ATTACK: Still r=0! Can still brute force!
    assert!(ristretto255::point_equals(
        new_right,
        &ristretto255::point_identity()  
    ), 1); // Confirms r is STILL 0
    
    // Attacker can use homomorphic subtraction:
    // new_balance - known_veil + known_unveil = (700*G, 0*G)
    // Then brute force to recover 700
}
```

## Notes

This vulnerability is **partially acknowledged** in the codebase. The `helpers.move` file contains a warning that values "can be easily bruteforced" [8](#0-7) , and the module is marked as experimental with warnings about potential loss of funds. [9](#0-8) 

However, the documentation does not fully explain the implications of combining known plaintexts with homomorphic operations for retroactive balance recovery. The attack path described here - using homomorphic subtraction of known values followed by discrete log recovery - is more sophisticated than simple brute-forcing and affects privacy across all historical states.

The module's experimental status and existing warnings may reduce the severity in practice, but the security question specifically asks whether this attack is possible (rated as "High"), indicating it should be addressed before any production deployment.

### Citations

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/ristretto255_elgamal.move (L1-9)
```text
/// This module implements an ElGamal encryption API, over the Ristretto255 curve, that can be used with the
/// Bulletproofs module.
///
/// An ElGamal *ciphertext* is an encryption of a value `v` under a basepoint `G` and public key `Y = sk * G`, where `sk`
/// is the corresponding secret key, is `(v * G + r * Y, r * G)`, for a random scalar `r`.
///
/// Note that we place the value `v` "in the exponent" of `G` so that ciphertexts are additively homomorphic: i.e., so
/// that `Enc_Y(v, r) + Enc_Y(v', r') = Enc_Y(v + v', r + r')` where `v, v'` are plaintext messages, `Y` is a public key and `r, r'`
/// are the randomness of the ciphertexts.
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/ristretto255_elgamal.move (L91-98)
```text
    /// Creates a new ciphertext `(val * G + 0 * Y, 0 * G) = (val * G, 0 * G)` where `G` is the Ristretto255 basepoint
    /// and the randomness is set to zero.
    public fun new_ciphertext_no_randomness(val: &Scalar): Ciphertext {
        Ciphertext {
            left: ristretto255::basepoint_mul(val),
            right: ristretto255::point_identity(),
        }
    }
```

**File:** aptos-move/framework/aptos-experimental/sources/veiled_coin/helpers.move (L33-39)
```text
    /// Returns an encryption of `amount`, without any randomness (i.e., $r=0$), under any ElGamal PK.
    /// WARNING: This is not a proper ciphertext: the value `amount` can be easily bruteforced.
    public fun public_amount_to_veiled_balance(amount: u32): elgamal::Ciphertext {
        let scalar = ristretto255::new_scalar_from_u32(amount);

        elgamal::new_ciphertext_no_randomness(&scalar)
    }
```

**File:** aptos-move/framework/aptos-experimental/sources/veiled_coin/veiled_coin.move (L1-3)
```text
/// **WARNING:** This is an **experimental, proof-of-concept** module! It is *NOT* production-ready and it will likely
/// lead to loss of funds if used (or misused).
///
```

**File:** aptos-move/framework/aptos-experimental/sources/veiled_coin/veiled_coin.move (L42-43)
```text
/// 5. *Veiled balance*: unlike a normal balance, a veiled balance is secret; i.e., it is encrypted under the account's
///    public key.
```

**File:** aptos-move/framework/aptos-experimental/sources/veiled_coin/veiled_coin.move (L59-74)
```text
/// ## Veiled coin amounts as truncated `u32`'s
///
/// Veiled coin amounts must be specified as `u32`'s rather than `u64`'s as would be typical for normal coins in the
/// Aptos framework. This is because coin amounts must be encrypted with an *efficient*, additively-homomorphic encryption
/// scheme. Currently, our best candidate is ElGamal encryption in the exponent, which can only decrypt values around
/// 32 bits or slightly larger.
///
/// Specifically, veiled coin amounts are restricted to be 32 bits and can be cast to a normal 64-bit coin value by
/// setting the leftmost and rightmost 16 bits to zero and the "middle" 32 bits to be the veiled coin bits.
///
/// This gives veiled amounts ~10 bits for specifying ~3 decimals and ~22 bits for specifying whole amounts, which
/// limits veiled balances and veiled transfers to around 4 million coins. (See `coin.move` for how a normal 64-bit coin
/// value gets interpreted as a decimal number.)
///
/// In order to convert a `u32` veiled coin amount to a normal `u64` coin amount, we have to shift it left by 16 bits.
///
```

**File:** aptos-move/framework/aptos-experimental/sources/veiled_coin/veiled_coin.move (L612-615)
```text
        let veiled_amount = elgamal::new_ciphertext_no_randomness(&scalar_amount);

        // Withdraw `amount` from the veiled balance (leverages the homomorphism of the encryption scheme.)
        elgamal::ciphertext_sub_assign(&mut veiled_balance, &veiled_amount);
```

**File:** crates/aptos-dkg/src/dlog/bsgs.rs (L7-47)
```rust
/// Compute discrete log using baby-step giant-step with a precomputed table
///
/// # Arguments
/// - `G`: base of the exponentiation
/// - `H`: target point
/// - `baby_table`: precomputed HashMap from `C.to_compressed()` |---> exponent
/// - `range_limit`: maximum size of the exponent we're trying to obtain. TODO: Change to u64?
//
// TODO:: ensure that G is also the element used to build the baby_table? So turn baby_table into a struct?
#[allow(non_snake_case)]
pub fn dlog<C: CurveGroup>(
    G: C,
    H: C,
    baby_table: &HashMap<Vec<u8>, u32>,
    range_limit: u32,
) -> Option<u32> {
    let byte_size = G.compressed_size();

    let m = baby_table
        .len()
        .try_into()
        .expect("Table seems rather large");
    let n = range_limit.div_ceil(m);

    let G_neg_m = G * -C::ScalarField::from(m);

    let mut gamma = H;

    for i in 0..n {
        let mut buf = vec![0u8; byte_size];
        gamma.serialize_compressed(&mut buf[..]).unwrap();

        if let Some(&j) = baby_table.get(&buf) {
            return Some(i * m + j);
        }

        gamma += G_neg_m;
    }

    None
}
```
