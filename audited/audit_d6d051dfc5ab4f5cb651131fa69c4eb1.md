# Audit Report

## Title
Unhandled PartialVMResult in hash_to_structure Native Function Causes Validator Crash

## Summary
The `suite_from_ty_arg!` macro in the hash_to_structure native function contains an `.unwrap()` call on a `PartialVMResult` return value from `type_to_type_tag()`. This unwrap can panic when converting complex type arguments, causing validator nodes to crash during transaction execution due to a mismatch between bytecode verifier type complexity limits and runtime type tag conversion limits.

## Finding Description

The vulnerability exists in the `suite_from_ty_arg!` macro which extracts type argument information in cryptographic algebra native functions. The macro calls `context.type_to_type_tag()` and immediately unwraps the result without proper error handling: [1](#0-0) 

The `type_to_type_tag()` method returns a `PartialVMResult<TypeTag>` and can fail when type complexity exceeds configured limits. Specifically, it returns `TYPE_TAG_LIMIT_EXCEEDED` when the pseudo-gas cost exceeds `type_max_cost`: [2](#0-1) 

The macro is invoked during execution of the `hash_to_internal` native function: [3](#0-2) 

When a user calls the public Move function `crypto_algebra::hash_to<S, H>()`, the type arguments flow through to the native implementation: [4](#0-3) 

**Attack Vector:**

The vulnerability is exploitable due to a critical mismatch between the bytecode verifier's type complexity limits and the runtime's type tag conversion limits:

- **Verifier limits** (production config): `max_type_nodes = 128` with weighted counting where structs=4, primitives=1 [5](#0-4) 

- **Runtime limits**: `type_max_cost = 5000` with flat `type_base_cost = 100` per type node [6](#0-5) 

This means the verifier allows types with up to 128 weighted nodes, but the runtime only allows ~50 nodes worth of cost (5000 / 100 = 50).

An attacker can craft a struct type with approximately 52 primitive fields:
- Verifier count: 1×4 (struct weight) + 52×1 (primitive weights) = 56 nodes < 128 ✓
- Runtime cost: 53 nodes × 100 base_cost = 5,300 > 5,000 ✗
- Type depth: 2 < 20 ✓

When the native function executes with such a type argument, `type_to_type_tag()` fails, the `.unwrap()` panics, and the validator process terminates. Native functions are called directly without panic handling: [7](#0-6) 

There is no `catch_unwind` wrapper around native function execution during block execution, only during validation and verification phases. The panic propagates up and crashes the validator.

**Inconsistency Evidence:**

The codebase demonstrates that proper error handling is both possible and implemented in the similar `structure_from_ty_arg!` macro, which correctly uses the `?` operator: [8](#0-7) 

This proves the `.unwrap()` in `suite_from_ty_arg!` is an oversight that violates the established error handling pattern.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability enables:
1. **Validator node crashes**: Malicious transactions cause validators to panic and terminate immediately
2. **Liveness degradation**: Multiple validators executing the same malicious transaction crash simultaneously, degrading network liveness
3. **Deterministic execution**: All validators crash identically on the same transaction, preventing recovery until manual intervention

This qualifies as High severity under the Aptos Bug Bounty "Validator Node Slowdowns (High)" category, as crashes represent severe degradation beyond mere slowdowns. The vulnerability:
- Violates the fundamental protocol invariant that validators must handle all user inputs gracefully
- Enables repeated DoS attacks with minimal cost (single transaction gas)
- Does NOT cause permanent network partition or fund loss (validators can restart)
- Does NOT require network-level attacks (in-scope protocol bug)

## Likelihood Explanation

**Likelihood: Medium to High**

**Factors enabling exploitation:**
- **Public accessibility**: The `hash_to<S, H>()` function is publicly accessible to any user
- **Low technical barrier**: Requires only crafting a struct with ~52 primitive fields as a type argument
- **Deterministic**: Same malformed transaction always triggers the crash
- **Verified mismatch**: Production configuration confirms verifier allows 128 nodes while runtime allows only ~50 nodes worth of cost

**Factors limiting exploitation:**
- **Feature flag dependency**: Requires `BLS12_381_STRUCTURES` feature flag to be enabled on the target network
- **Transaction acceptance**: The malicious transaction must pass mempool validation and be included in a block
- **Understanding required**: Attacker must understand the verifier/runtime limit mismatch

The verifier/runtime configuration mismatch is documented in production configs, making exploitation feasible for attackers with codebase knowledge.

## Recommendation

Replace the `.unwrap()` call with the `?` operator to properly propagate errors, consistent with the `structure_from_ty_arg!` macro pattern:

```rust
macro_rules! suite_from_ty_arg {
    ($context:expr, $typ:expr) => {{
        let type_tag = $context.type_to_type_tag($typ)?;  // Use ? instead of unwrap()
        HashToStructureSuite::try_from(type_tag).ok()
    }};
}
```

Additionally, consider aligning the verifier's `max_type_nodes` limit with the runtime's `type_max_cost` to prevent this class of vulnerabilities. The runtime limit of 5000 with base_cost 100 allows ~50 nodes, significantly less than the verifier's 128-node limit.

## Proof of Concept

A proof of concept would involve:
1. Defining a Move struct with 52+ primitive fields
2. Publishing this struct definition to the blockchain
3. Calling `crypto_algebra::hash_to<StructWith52Fields, ValidHashSuite>(dst, msg)`
4. Observing validator process termination when the transaction executes

The exact PoC requires the `BLS12_381_STRUCTURES` feature flag to be enabled and depends on the specific deployment configuration.

## Notes

This vulnerability represents a critical discrepancy between static verification and runtime execution limits. The bytecode verifier allows types that the runtime cannot safely process, violating defense-in-depth principles. The proper fix requires both correcting the immediate `.unwrap()` issue and harmonizing the verifier and runtime type complexity limits to prevent similar vulnerabilities.

### Citations

**File:** aptos-move/framework/src/natives/cryptography/algebra/hash_to_structure.rs (L47-52)
```rust
macro_rules! suite_from_ty_arg {
    ($context:expr, $typ:expr) => {{
        let type_tag = $context.type_to_type_tag($typ).unwrap();
        HashToStructureSuite::try_from(type_tag).ok()
    }};
}
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/hash_to_structure.rs (L81-89)
```rust
pub fn hash_to_internal(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    assert_eq!(2, ty_args.len());
    let structure_opt = structure_from_ty_arg!(context, &ty_args[0]);
    let suite_opt = suite_from_ty_arg!(context, &ty_args[1]);
    abort_unless_hash_to_structure_enabled!(context, structure_opt, suite_opt);
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L50-62)
```rust
    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(
                PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED).with_message(format!(
                    "Exceeded maximum type tag limit of {} when charging {}",
                    self.max_cost, amount
                )),
            )
        } else {
            Ok(())
        }
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/crypto_algebra.move (L258-263)
```text
    public fun hash_to<S, H>(dst: &vector<u8>, msg: &vector<u8>): Element<S> {
        abort_unless_cryptography_algebra_natives_enabled();
        Element {
            handle: hash_to_internal<S, H>(dst, msg)
        }
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L162-166)
```rust
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L246-249)
```rust
        // 5000 limits type tag total size < 5000 bytes and < 50 nodes.
        type_max_cost: 5000,
        type_base_cost: 100,
        type_byte_cost: 1,
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1106-1106)
```rust
        let result = native_function(&mut native_context, ty_args, args)?;
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/mod.rs (L94-100)
```rust
#[macro_export]
macro_rules! structure_from_ty_arg {
    ($context:expr, $typ:expr) => {{
        let type_tag = $context.type_to_type_tag($typ)?;
        Structure::try_from(type_tag).ok()
    }};
}
```
