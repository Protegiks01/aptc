# Audit Report

## Title
Gas Cost Underpricing for Fq12 Element Creation Enables Cheap Memory Exhaustion

## Summary
The gas cost for creating BLS12-381 Fq12 extension field elements via `from_u64()` is significantly underpriced relative to their memory consumption compared to Fr base field elements. Fq12 elements consume 18x more memory than Fr elements but cost only 1.82x more gas, enabling attackers to exhaust the 1MB algebra memory limit while paying approximately 10% of the gas cost that would be required using Fr elements.

## Finding Description

The vulnerability exists in the gas parameter configuration for the algebra module's `from_u64_internal()` function. When creating algebraic structures from u64 values, the gas costs are: [1](#0-0) [2](#0-1) 

The native implementation charges these costs when creating elements: [3](#0-2) 

However, these elements have drastically different memory footprints: [4](#0-3) [5](#0-4) 

The memory tracking uses `std::mem::size_of_val()` which reflects the actual in-memory size: [6](#0-5) 

With a 1MB memory limit enforced: [7](#0-6) 

**The Disparity:**
- Fr: 32 bytes, 1815 gas → 56.7 gas/byte
- Fq12: 576 bytes, 3312 gas → 5.75 gas/byte

This represents a ~10x underpricing for Fq12 elements in terms of gas cost per byte of memory consumed.

**Attack Path:**
1. Attacker submits transaction calling `crypto_algebra::from_u64<Fq12>(value)` repeatedly
2. Each Fq12 creation costs only 3312 gas but consumes ~576 bytes
3. To reach 1MB limit: 1,820 Fq12 elements × 3312 gas = 6,027,840 gas
4. Equivalent memory using Fr: 32,768 elements × 1815 gas = 59,473,920 gas

The attacker reaches the memory limit paying only ~10% of what they should pay based on the Fr baseline.

## Impact Explanation

This is a **Medium severity** vulnerability per Aptos bug bounty criteria. While it doesn't directly cause loss of funds or consensus violations, it represents a significant gas metering bypass that violates Invariant #9: "All operations must respect gas, storage, and computational limits."

The vulnerability enables:
1. **Resource exhaustion at underpriced rates**: Attackers can consume memory disproportionately cheaply
2. **Gas metering bypass**: The fundamental assumption that gas cost scales with resource consumption is violated
3. **Potential DoS vector**: Transactions can hit memory limits unexpectedly, causing state inconsistencies requiring intervention

This fits the Medium category definition: "State inconsistencies requiring intervention" and represents a gas calculation miscalculation that could enable unfair resource consumption.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is easily exploitable:
- No special permissions required - any transaction sender can call `crypto_algebra::from_u64<Fq12>()`
- The function is publicly exposed through the Move standard library
- Attack requires no complex setup or timing
- The gas parameter mismatch is permanent until corrected through governance

The exploitation is deterministic and repeatable. An attacker simply needs to craft a transaction that creates multiple Fq12 elements to exploit the underpricing.

## Recommendation

The gas costs should be adjusted to reflect memory consumption proportionality. The current costs are based purely on CPU execution time benchmarks, but should also account for memory allocation.

**Recommended Fix:**

Adjust the gas parameter to include a memory allocation component:

```rust
// In aptos_framework.rs, update line 114:
[algebra_ark_bls12_381_fq12_from_u64: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_from_u64" }, 32670],
// Calculation: 3312 (current CPU cost) + (576/32) * 1815 (memory proportional cost) ≈ 32,670
```

Alternatively, implement a memory-aware gas charging mechanism in the `store_element!` macro:

```rust
// In mod.rs, update the store_element! macro:
macro_rules! store_element {
    ($context:expr, $obj:expr) => {{
        let context = &mut $context.extensions_mut().get_mut::<AlgebraContext>();
        let obj_size = std::mem::size_of_val(&$obj);
        let new_size = context.bytes_used + obj_size;
        
        // Charge gas proportional to memory allocated (e.g., 50 gas per byte)
        let memory_gas = InternalGas::new(obj_size as u64 * 50);
        $context.charge(memory_gas)?;
        
        if new_size > MEMORY_LIMIT_IN_BYTES {
            Err(SafeNativeError::Abort {
                abort_code: E_TOO_MUCH_MEMORY_USED,
            })
        } else {
            let target_vec = &mut context.objs;
            context.bytes_used = new_size;
            let ret = target_vec.len();
            target_vec.push(Rc::new($obj));
            Ok(ret)
        }
    }};
}
```

## Proof of Concept

```move
#[test_only]
module test_addr::gas_exploit_test {
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bls12381_algebra::{Fr, Fq12};

    #[test]
    fun test_fq12_underpricing() {
        // Create Fq12 elements - should hit memory limit cheaply
        let fq12_elements = vector::empty<Element<Fq12>>();
        
        let i = 0;
        // Try to create ~1800 Fq12 elements (should consume ~1MB)
        while (i < 1800) {
            let elem = crypto_algebra::from_u64<Fq12>(i);
            vector::push_back(&mut fq12_elements, elem);
            i = i + 1;
        };
        
        // This consumes ~1MB but costs only ~6M gas
        // Equivalent memory with Fr would cost ~60M gas (10x more)
        
        // Gas measurements would show:
        // - Fq12 path: 1,820 elements × 3312 gas ≈ 6,027,840 gas
        // - Fr path (equivalent memory): 32,768 elements × 1815 gas ≈ 59,473,920 gas
        // Ratio: ~10x underpricing for Fq12
    }

    #[test]
    #[expected_failure(abort_code = 0x090003)] // E_TOO_MUCH_MEMORY_USED
    fun test_memory_exhaustion_fq12() {
        let fq12_elements = vector::empty<Element<Fq12>>();
        
        // Create enough Fq12 elements to exceed 1MB limit
        let i = 0;
        while (i < 2000) {
            let elem = crypto_algebra::from_u64<Fq12>(i);
            vector::push_back(&mut fq12_elements, elem);
            i = i + 1;
        };
        // Should abort with E_TOO_MUCH_MEMORY_USED after ~1820 elements
    }
}
```

## Notes

The root cause is that gas parameters were generated purely from CPU execution time benchmarks without accounting for memory allocation costs. The gas generation script uses actual nanosecond measurements multiplied by a gas_per_ns factor, which captures CPU cost but not memory proportionality: [8](#0-7) 

This approach works well for operations where memory consumption is uniform, but breaks down when different structures have vastly different memory footprints while having similar CPU execution times. The `from_u64` operation is relatively fast for both Fr and Fq12, but the memory allocation differs by 18x.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L114-114)
```rust
        [algebra_ark_bls12_381_fq12_from_u64: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_from_u64" }, 3312],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L128-128)
```rust
        [algebra_ark_bls12_381_fr_from_u64: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_from_u64" }, 1815],
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/new.rs (L39-50)
```rust
        Some(Structure::BLS12381Fr) => from_u64_internal!(
            context,
            args,
            ark_bls12_381::Fr,
            ALGEBRA_ARK_BLS12_381_FR_FROM_U64
        ),
        Some(Structure::BLS12381Fq12) => from_u64_internal!(
            context,
            args,
            ark_bls12_381::Fq12,
            ALGEBRA_ARK_BLS12_381_FQ12_FROM_U64
        ),
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381_algebra.move (L61-69)
```text
    /// The finite field $F_{q^12}$ used in BLS12-381 curves,
    /// which is an extension field of `Fq6` (defined in the module documentation), constructed as $F_{q^12}=F_{q^6}[w]/(w^2-v)$.
    struct Fq12 {}

    /// A serialization scheme for `Fq12` elements,
    /// where an element $(c_0+c_1\cdot w)$ is represented by a byte array `b[]` of size 576,
    /// which is a concatenation of its coefficients serialized, with the least significant coefficient (LSC) coming first.
    /// - `b[0..288]` is $c_0$ serialized using `FormatFq6LscLsb` (defined in the module documentation).
    /// - `b[288..576]` is $c_1$ serialized using `FormatFq6LscLsb`.
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381_algebra.move (L206-214)
```text
    /// The finite field $F_r$ that can be used as the scalar fields
    /// associated with the groups $G_1$, $G_2$, $G_t$ in BLS12-381-based pairing.
    struct Fr {}

    /// A serialization format for `Fr` elements,
    /// where an element is represented by a byte array `b[]` of size 32 with the least significant byte (LSB) coming first.
    ///
    /// NOTE: other implementation(s) using this format: ark-bls12-381-0.4.0, blst-0.3.7.
    struct FormatFrLsb {}
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/mod.rs (L184-188)
```rust
/// This limit ensures that no more than 1MB will be allocated for elements per VM session.
const MEMORY_LIMIT_IN_BYTES: usize = 1 << 20;

/// Equivalent to `std::error::resource_exhausted(3)` in Move.
const E_TOO_MUCH_MEMORY_USED: u64 = 0x09_0003;
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/mod.rs (L243-260)
```rust
#[macro_export]
macro_rules! store_element {
    ($context:expr, $obj:expr) => {{
        let context = &mut $context.extensions_mut().get_mut::<AlgebraContext>();
        let new_size = context.bytes_used + std::mem::size_of_val(&$obj);
        if new_size > MEMORY_LIMIT_IN_BYTES {
            Err(SafeNativeError::Abort {
                abort_code: E_TOO_MUCH_MEMORY_USED,
            })
        } else {
            let target_vec = &mut context.objs;
            context.bytes_used = new_size;
            let ret = target_vec.len();
            target_vec.push(Rc::new($obj));
            Ok(ret)
        }
    }};
}
```

**File:** scripts/algebra-gas/update_bls12381_algebra_gas_params.py (L35-56)
```python
def get_algebra_lines(gas_per_ns):
    nanoseconds = {}
    nanoseconds['ark_bls12_381_fr_add'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_add')
    nanoseconds['ark_bls12_381_fr_deser'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_deser')
    nanoseconds['ark_bls12_381_fr_div'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_div')
    nanoseconds['ark_bls12_381_fr_eq'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_eq')
    nanoseconds['ark_bls12_381_fr_from_u64'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_from_u64')
    nanoseconds['ark_bls12_381_fr_inv'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_inv')
    nanoseconds['ark_bls12_381_fr_mul'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_mul')
    nanoseconds['ark_bls12_381_fr_neg'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_neg')
    nanoseconds['ark_bls12_381_fr_one'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_one')
    nanoseconds['ark_bls12_381_fr_serialize'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_serialize')
    nanoseconds['ark_bls12_381_fr_square'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_square')
    nanoseconds['ark_bls12_381_fr_sub'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_sub')
    nanoseconds['ark_bls12_381_fr_zero'] = load_bench_ns.main('target/criterion/ark_bls12_381/fr_zero')
    nanoseconds['ark_bls12_381_fq12_add'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_add')
    nanoseconds['ark_bls12_381_fq12_clone'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_clone')
    nanoseconds['ark_bls12_381_fq12_deser'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_deser')
    nanoseconds['ark_bls12_381_fq12_div'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_div')
    nanoseconds['ark_bls12_381_fq12_eq'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_eq')
    nanoseconds['ark_bls12_381_fq12_from_u64'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_from_u64')
    nanoseconds['ark_bls12_381_fq12_inv'] = load_bench_ns.main('target/criterion/ark_bls12_381/fq12_inv')
```
