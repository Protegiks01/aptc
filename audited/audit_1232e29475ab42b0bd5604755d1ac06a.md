# Audit Report

## Title
Missing Maximum Size Enforcement for Multi-Scalar Multiplication Operations Creates Potential DoS Vector

## Summary
The MSM (Multi-Scalar Multiplication) native functions exposed to Move smart contracts lack explicit size limits beyond gas charging. While benchmarks validate gas costs only up to 257 elements, production code allows operations with ~1000 elements within gas limits. If the gas cost model underestimates actual CPU consumption at these larger scales, validators could experience CPU exhaustion while attackers pay insufficient gas.

## Finding Description
The vulnerability exists in the native function implementation that exposes MSM operations to Move smart contracts: [1](#0-0) 

The benchmark test cases only validate MSM operations up to 257 elements, yet the production implementation accepts vectors of arbitrary length with no explicit upper bound: [2](#0-1) 

The function only validates that input vector lengths match but does not enforce maximum size limits: [3](#0-2) 

Gas is charged using the `ark_msm_bigint_wnaf_cost!` macro, which calculates cost based on number of elements: [4](#0-3) 

The maximum execution gas limit allows operations with approximately 1000 elements: [5](#0-4) 

With gas parameters for BN254 operations: [6](#0-5) 

An attacker can submit transactions calling `multi_scalar_mul_internal` with vectors containing ~1000 elements, which is approximately 4x larger than the maximum benchmarked size. If the gas cost formula (derived from benchmarks ≤257 elements) underestimates actual CPU cost at these larger scales due to cache effects, memory pressure, or non-linear scaling, validators will spend disproportionate CPU time relative to gas charged.

**Attack Path:**
1. Attacker creates a Move smart contract that calls `crypto_algebra::multi_scalar_mul()` with large vectors
2. Vectors contain ~800-1000 elements, staying within gas limits
3. Gas formula charges based on the `ark_msm_bigint_wnaf_cost!` calculation
4. If actual CPU time grows faster than the formula predicts, validators experience CPU exhaustion
5. Multiple such transactions can amplify the DoS effect

## Impact Explanation
This qualifies as **High Severity** per Aptos bug bounty criteria ("Validator node slowdowns"). If the gas cost model is inaccurate at scales beyond benchmarked ranges, attackers can cause validator CPU exhaustion while paying gas costs that don't reflect true computational burden. This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

The impact is limited to validator performance degradation rather than consensus breaks, justifying High rather than Critical severity.

## Likelihood Explanation
**Likelihood: Medium to High**

The attack is feasible because:
- No validator privileges required
- Attack can be launched via regular transactions
- MSM operations are explicitly exposed to Move contracts
- Gas limits demonstrably allow ~1000 element operations

However, exploitability depends on whether the gas formula actually undercharges at scale, which requires empirical validation. The gap between benchmarked range (≤257) and allowed range (~1000) is significant enough to warrant concern about cost model accuracy.

## Recommendation
Implement explicit maximum size limits for MSM operations based on empirically validated ranges:

```rust
// In multi_scalar_mul_internal function
const MAX_MSM_ELEMENTS: usize = 256; // Or 512 after extended benchmarking

let num_elements = element_handles.len();
let num_scalars = scalar_handles.len();

// Add size limit check
if num_elements > MAX_MSM_ELEMENTS {
    return Err(SafeNativeError::Abort {
        abort_code: MOVE_ABORT_CODE_INPUT_VECTOR_TOO_LARGE,
    });
}

if num_elements != num_scalars {
    return Err(SafeNativeError::Abort {
        abort_code: MOVE_ABORT_CODE_INPUT_VECTOR_SIZES_NOT_MATCHING,
    });
}
```

Additionally:
1. Extend benchmarks to cover the full range allowed by gas limits (up to ~1000 elements)
2. Empirically validate that gas costs accurately reflect CPU time at these scales
3. If gas costs are found to be inaccurate, either adjust the formula or reduce the allowed maximum size

## Proof of Concept
The following Move test demonstrates that MSM operations with 1000 elements can be invoked within gas limits:

```move
#[test(fx = @std)]
fun test_large_msm_dos(fx: signer) {
    use aptos_std::crypto_algebra;
    use aptos_std::bn254_algebra::{G1, Fr};
    use std::vector;
    
    crypto_algebra::enable_cryptography_algebra_natives(&fx);
    
    // Create 1000 G1 elements
    let elements: vector<crypto_algebra::Element<G1>> = vector[];
    let scalars: vector<crypto_algebra::Element<Fr>> = vector[];
    
    let i = 0;
    while (i < 1000) {
        vector::push_back(&mut elements, crypto_algebra::one<G1>());
        vector::push_back(&mut scalars, crypto_algebra::from_u64<Fr>(1));
        i = i + 1;
    };
    
    // This succeeds if within gas limits but may cause
    // disproportionate CPU load on validators
    let _result = crypto_algebra::multi_scalar_mul<G1, Fr>(&elements, &scalars);
}
```

This PoC demonstrates the technical feasibility of invoking MSM with 1000 elements. To prove actual DoS impact, benchmark the CPU time consumed versus gas charged to demonstrate undercharging.

### Citations

**File:** crates/aptos-crypto/benches/ark_bn254.rs (L25-33)
```rust
fn msm_all_bench_cases() -> Vec<usize> {
    let series_until_65 = (1..65).step_by(2);
    let series_until_129 = (64..129).step_by(4);
    let series_until_257 = (129..257).step_by(8);
    series_until_65
        .chain(series_until_129)
        .chain(series_until_257)
        .collect::<Vec<_>>()
}
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/arithmetics/scalar_mul.rs (L80-89)
```rust
macro_rules! ark_msm_bigint_wnaf_cost {
    ($cost_add:expr, $cost_double:expr, $num_entries:expr $(,)?) => {{
        let num_entries: usize = $num_entries;
        let window_size = ark_msm_window_size(num_entries);
        let num_windows = 255_usize.div_ceil(window_size);
        let num_buckets = 1_usize << window_size;
        $cost_add * NumArgs::from(((num_entries + num_buckets + 1) * num_windows) as u64)
            + $cost_double * NumArgs::from((num_buckets * num_windows) as u64)
    }};
}
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/arithmetics/scalar_mul.rs (L197-205)
```rust
        let scalar_handles = safely_pop_arg!($args, Vec<u64>);
        let element_handles = safely_pop_arg!($args, Vec<u64>);
        let num_elements = element_handles.len();
        let num_scalars = scalar_handles.len();
        if num_elements != num_scalars {
            return Err(SafeNativeError::Abort {
                abort_code: MOVE_ABORT_CODE_INPUT_VECTOR_SIZES_NOT_MATCHING,
            });
        }
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/arithmetics/scalar_mul.rs (L223-229)
```rust
        $context.charge(ark_msm_bigint_wnaf_cost!(
            $proj_add_cost,
            $proj_double_cost,
            num_elements,
        ))?;
        let new_element: $element_typ =
            ark_ec::VariableBaseMSM::msm(bases.as_slice(), scalars.as_slice()).unwrap();
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L211-214)
```rust
            max_execution_gas: InternalGas,
            { 7.. => "max_execution_gas" },
            920_000_000, // 92ms of execution at 10k gas per ms
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L80-81)
```rust
        [algebra_ark_bn254_g1_proj_add: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_add" }, 19574],
        [algebra_ark_bn254_g1_proj_double: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_double" }, 11704],
```
