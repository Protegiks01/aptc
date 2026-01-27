# Audit Report

## Title
Consensus Fork via Version Rollback Attack on Gas Parameter Version Gates

## Summary
Validators running older software versions will compute different gas limits for governance transactions due to version-gated gas parameters, causing non-deterministic transaction execution outcomes and consensus failures.

## Finding Description

The gas parameter system uses version gates to introduce new parameters across releases. When validators run software compiled with older version constants, they fail to recognize newer gas parameters and default them to zero or use outdated limits. [1](#0-0) 

The macro system uses compile-time pattern matching against version constants: [2](#0-1) 

**Critical Issue: Governance Gas Limits**

In RELEASE_V1_13, higher gas limits were introduced specifically for approved governance scripts: [3](#0-2) 

The gas algebra implementation checks both the governance script flag AND the gas feature version to select limits: [4](#0-3) 

**Attack Scenario:**

1. On-chain `gas_feature_version` = 45 (RELEASE_V1_41)
2. Most validators run current software (V41)
3. Malicious validator intentionally rolls back to software from before RELEASE_V1_13 (e.g., V12)
4. Governance transaction is proposed requiring 2 billion execution gas units

**Execution Divergence:**

- **New validators (V41)**: 
  - Check `gas_feature_version >= RELEASE_V1_13` → true
  - Use `max_execution_gas_gov = 4,000,000,000`
  - Transaction **SUCCEEDS**

- **Old validator (V12)**:
  - Doesn't have `RELEASE_V1_13` constant or governance limit code
  - Uses `max_execution_gas = 920,000,000`
  - Transaction **FAILS** with `EXECUTION_LIMIT_REACHED` [5](#0-4) 

Different execution results produce different state checkpoint hashes, breaking consensus: [6](#0-5) 

## Impact Explanation

**Critical Severity** - This violates the fundamental consensus invariant: "All validators must produce identical state roots for identical blocks."

When validators compute different transaction outcomes:
- Transaction success/failure differs between validators
- State roots diverge after block execution  
- Validators cannot agree on `executed_state_id` for voting
- Network experiences consensus failure and potential fork
- Requires hard fork or emergency validator coordination to recover

This meets the Critical severity criteria: **Consensus/Safety violations** and **Non-recoverable network partition (requires hardfork)**.

## Likelihood Explanation

**Likelihood: Medium-High**

- Validators have operational control over software versions
- No on-chain enforcement prevents validators from running old software
- The blockchain version check only prevents downgrade of on-chain version, not validator software versions [7](#0-6) 

- Gas schedule updates are routine through governance
- Governance transactions legitimately use higher gas limits
- Attack requires only one validator to maintain network disruption

## Recommendation

**Immediate Mitigations:**

1. **Validator Software Version Enforcement**: Add on-chain minimum software version checks during block validation:

```rust
// In block execution/validation
if validator_software_version < minimum_required_version {
    return Err(ValidationError::OutdatedSoftware);
}
```

2. **Gas Parameter Validation**: When loading gas parameters, validate that all expected parameters for the current feature version exist:

```rust
// After from_on_chain_gas_schedule
fn validate_gas_params_completeness(
    params: &AptosGasParameters, 
    feature_version: u64
) -> Result<(), String> {
    // Ensure governance-specific params exist for v13+
    if feature_version >= RELEASE_V1_13 {
        if params.vm.txn.max_execution_gas_gov == 0.into() 
            || params.vm.txn.max_io_gas_gov == 0.into() {
            return Err("Missing governance gas limits for v13+".into());
        }
    }
    Ok(())
}
```

3. **Consensus Version Signaling**: Include software version in consensus messages and reject proposals from validators running incompatible versions.

## Proof of Concept

```rust
// Reproduction steps (conceptual - requires multi-node setup):

// Setup:
// 1. Deploy network with gas_feature_version = 45
// 2. Validator A runs software v41
// 3. Validator B runs software v12 (pre-RELEASE_V1_13)

// Create governance transaction requiring 2B execution gas
let governance_txn = create_approved_governance_script(
    execution_gas_needed: 2_000_000_000,
);

// Execute on both validators:
// Validator A (v41):
let gas_meter_a = make_prod_gas_meter(
    45,  // gas_feature_version
    vm_gas_params_a,
    storage_gas_params,
    true, // is_approved_gov_script
    Gas::new(2_000_000_000),
    kill_switch,
);
// Sets max_execution_gas = 4B
// Result: SUCCESS, state_root = 0xAAA...

// Validator B (v12):
let gas_meter_b = make_prod_gas_meter(
    45,  // same feature_version from chain
    vm_gas_params_b,  // but compiled with old constants
    storage_gas_params,
    false, // doesn't recognize governance scripts
    Gas::new(2_000_000_000),
    kill_switch,
);
// Sets max_execution_gas = 920M (lacks governance limits)
// Result: EXECUTION_LIMIT_REACHED, state_root = 0xBBB...

// Consensus fails: 0xAAA != 0xBBB
```

## Notes

This vulnerability exists because:
1. Gas parameter version gates use **compile-time** constants but **runtime** feature versions
2. No enforcement exists requiring validators to run minimum software versions
3. The on-chain gas schedule version can advance without forcing validator upgrades

The issue affects any version-gated parameter where old software would compute different values, but governance gas limits present the clearest consensus violation scenario.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L18-365)
```rust
crate::gas_schedule::macros::define_gas_parameters!(
    AptosFrameworkGasParameters,
    "aptos_framework",
    NativeGasParameters => .aptos_framework,
    [
        [account_create_address_base: InternalGas, "account.create_address.base", 1102],
        [account_create_signer_base: InternalGas, "account.create_signer.base", 1102],

        // Permissioned signer gas parameters
        [permission_address_base: InternalGas, { RELEASE_V1_26 => "permissioned_signer.permission_address.base"}, 1102],
        [is_permissioned_signer_base: InternalGas, { RELEASE_V1_26 => "permissioned_signer.is_permissioned_signer.base"}, 1102],
        [signer_from_permissioned_handle_base: InternalGas, { RELEASE_V1_26 => "permissioned_signer.signer_from_permissioned_handle.base"}, 1102],

        // BN254 algebra gas parameters begin.
        // Generated at time 1701559125.5498126 by `scripts/algebra-gas/update_bn254_algebra_gas_params.py` with gas_per_ns=209.10511688369482.
        [algebra_ark_bn254_fq12_add: InternalGas, { 12.. => "algebra.ark_bn254_fq12_add" }, 809],
        [algebra_ark_bn254_fq12_clone: InternalGas, { 12.. => "algebra.ark_bn254_fq12_clone" }, 807],
        [algebra_ark_bn254_fq12_deser: InternalGas, { 12.. => "algebra.ark_bn254_fq12_deser" }, 23721],
        [algebra_ark_bn254_fq12_div: InternalGas, { 12.. => "algebra.ark_bn254_fq12_div" }, 517140],
        [algebra_ark_bn254_fq12_eq: InternalGas, { 12.. => "algebra.ark_bn254_fq12_eq" }, 2231],
        [algebra_ark_bn254_fq12_from_u64: InternalGas, { 12.. => "algebra.ark_bn254_fq12_from_u64" }, 2658],
        [algebra_ark_bn254_fq12_inv: InternalGas, { 12.. => "algebra.ark_bn254_fq12_inv" }, 398555],
        [algebra_ark_bn254_fq12_mul: InternalGas, { 12.. => "algebra.ark_bn254_fq12_mul" }, 118351],
        [algebra_ark_bn254_fq12_neg: InternalGas, { 12.. => "algebra.ark_bn254_fq12_neg" }, 2446],
        [algebra_ark_bn254_fq12_one: InternalGas, { 12.. => "algebra.ark_bn254_fq12_one" }, 38],
        [algebra_ark_bn254_fq12_pow_u256: InternalGas, { 12.. => "algebra.ark_bn254_fq12_pow_u256" }, 35449826],
        [algebra_ark_bn254_fq12_serialize: InternalGas, { 12.. => "algebra.ark_bn254_fq12_serialize" }, 21566],
        [algebra_ark_bn254_fq12_square: InternalGas, { 12.. => "algebra.ark_bn254_fq12_square" }, 86193],
        [algebra_ark_bn254_fq12_sub: InternalGas, { 12.. => "algebra.ark_bn254_fq12_sub" }, 5605],
        [algebra_ark_bn254_fq12_zero: InternalGas, { 12.. => "algebra.ark_bn254_fq12_zero" }, 38],
        [algebra_ark_bn254_fq_add: InternalGas, { 12.. => "algebra.ark_bn254_fq_add" }, 803],
        [algebra_ark_bn254_fq_clone: InternalGas, { 12.. => "algebra.ark_bn254_fq_clone" }, 792],
        [algebra_ark_bn254_fq_deser: InternalGas, { 12.. => "algebra.ark_bn254_fq_deser" }, 3232],
        [algebra_ark_bn254_fq_div: InternalGas, { 12.. => "algebra.ark_bn254_fq_div" }, 209631],
        [algebra_ark_bn254_fq_eq: InternalGas, { 12.. => "algebra.ark_bn254_fq_eq" }, 803],
        [algebra_ark_bn254_fq_from_u64: InternalGas, { 12.. => "algebra.ark_bn254_fq_from_u64" }, 2598],
        [algebra_ark_bn254_fq_inv: InternalGas, { 12.. => "algebra.ark_bn254_fq_inv" }, 208902],
        [algebra_ark_bn254_fq_mul: InternalGas, { 12.. => "algebra.ark_bn254_fq_mul" }, 1847],
        [algebra_ark_bn254_fq_neg: InternalGas, { 12.. => "algebra.ark_bn254_fq_neg" }, 792],
        [algebra_ark_bn254_fq_one: InternalGas, { 12.. => "algebra.ark_bn254_fq_one" }, 38],
        [algebra_ark_bn254_fq_pow_u256: InternalGas, { 12.. => "algebra.ark_bn254_fq_pow_u256" }, 382570],
        [algebra_ark_bn254_fq_serialize: InternalGas, { 12.. => "algebra.ark_bn254_fq_serialize" }, 4767],
        [algebra_ark_bn254_fq_square: InternalGas, { 12.. => "algebra.ark_bn254_fq_square" }, 792],
        [algebra_ark_bn254_fq_sub: InternalGas, { 12.. => "algebra.ark_bn254_fq_sub" }, 1130],
        [algebra_ark_bn254_fq_zero: InternalGas, { 12.. => "algebra.ark_bn254_fq_zero" }, 38],
        [algebra_ark_bn254_fr_add: InternalGas, { 12.. => "algebra.ark_bn254_fr_add" }, 804],
        [algebra_ark_bn254_fr_deser: InternalGas, { 12.. => "algebra.ark_bn254_fr_deser" }, 3073],
        [algebra_ark_bn254_fr_div: InternalGas, { 12.. => "algebra.ark_bn254_fr_div" }, 223857],
        [algebra_ark_bn254_fr_eq: InternalGas, { 12.. => "algebra.ark_bn254_fr_eq" }, 807],
        [algebra_ark_bn254_fr_from_u64: InternalGas, { 12.. => "algebra.ark_bn254_fr_from_u64" }, 2478],
        [algebra_ark_bn254_fr_inv: InternalGas, { 12.. => "algebra.ark_bn254_fr_inv" }, 222216],
        [algebra_ark_bn254_fr_mul: InternalGas, { 12.. => "algebra.ark_bn254_fr_mul" }, 1813],
        [algebra_ark_bn254_fr_neg: InternalGas, { 12.. => "algebra.ark_bn254_fr_neg" }, 792],
        [algebra_ark_bn254_fr_one: InternalGas, { 12.. => "algebra.ark_bn254_fr_one" }, 0],
        [algebra_ark_bn254_fr_serialize: InternalGas, { 12.. => "algebra.ark_bn254_fr_serialize" }, 4732],
        [algebra_ark_bn254_fr_square: InternalGas, { 12.. => "algebra.ark_bn254_fr_square" }, 792],
        [algebra_ark_bn254_fr_sub: InternalGas, { 12.. => "algebra.ark_bn254_fr_sub" }, 1906],
        [algebra_ark_bn254_fr_zero: InternalGas, { 12.. => "algebra.ark_bn254_fr_zero" }, 38],
        [algebra_ark_bn254_g1_affine_deser_comp: InternalGas, { 12.. => "algebra.ark_bn254_g1_affine_deser_comp" }, 4318809],
        [algebra_ark_bn254_g1_affine_deser_uncomp: InternalGas, { 12.. => "algebra.ark_bn254_g1_affine_deser_uncomp" }, 3956976],
        [algebra_ark_bn254_g1_affine_serialize_comp: InternalGas, { 12.. => "algebra.ark_bn254_g1_affine_serialize_comp" }, 8257],
        [algebra_ark_bn254_g1_affine_serialize_uncomp: InternalGas, { 12.. => "algebra.ark_bn254_g1_affine_serialize_uncomp" }, 10811],
        [algebra_ark_bn254_g1_proj_add: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_add" }, 19574],
        [algebra_ark_bn254_g1_proj_double: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_double" }, 11704],
        [algebra_ark_bn254_g1_proj_eq: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_eq" }, 9745],
        [algebra_ark_bn254_g1_proj_generator: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_generator" }, 38],
        [algebra_ark_bn254_g1_proj_infinity: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_infinity" }, 38],
        [algebra_ark_bn254_g1_proj_neg: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_neg" }, 38],
        [algebra_ark_bn254_g1_proj_scalar_mul: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_scalar_mul" }, 4862683],
        [algebra_ark_bn254_g1_proj_sub: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_sub" }, 19648],
        [algebra_ark_bn254_g1_proj_to_affine: InternalGas, { 12.. => "algebra.ark_bn254_g1_proj_to_affine" }, 1165],
        [algebra_ark_bn254_g2_affine_deser_comp: InternalGas, { 12.. => "algebra.ark_bn254_g2_affine_deser_comp" }, 12445138],
        [algebra_ark_bn254_g2_affine_deser_uncomp: InternalGas, { 12.. => "algebra.ark_bn254_g2_affine_deser_uncomp" }, 11152541],
        [algebra_ark_bn254_g2_affine_serialize_comp: InternalGas, { 12.. => "algebra.ark_bn254_g2_affine_serialize_comp" }, 12721],
        [algebra_ark_bn254_g2_affine_serialize_uncomp: InternalGas, { 12.. => "algebra.ark_bn254_g2_affine_serialize_uncomp" }, 18105],
        [algebra_ark_bn254_g2_proj_add: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_add" }, 58491],
        [algebra_ark_bn254_g2_proj_double: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_double" }, 29201],
        [algebra_ark_bn254_g2_proj_eq: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_eq" }, 25981],
        [algebra_ark_bn254_g2_proj_generator: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_generator" }, 38],
        [algebra_ark_bn254_g2_proj_infinity: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_infinity" }, 38],
        [algebra_ark_bn254_g2_proj_neg: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_neg" }, 38],
        [algebra_ark_bn254_g2_proj_scalar_mul: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_scalar_mul" }, 14041548],
        [algebra_ark_bn254_g2_proj_sub: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_sub" }, 59133],
        [algebra_ark_bn254_g2_proj_to_affine: InternalGas, { 12.. => "algebra.ark_bn254_g2_proj_to_affine" }, 230100],
        [algebra_ark_bn254_multi_pairing_base: InternalGas, { 12.. => "algebra.ark_bn254_multi_pairing_base" }, 23488646],
        [algebra_ark_bn254_multi_pairing_per_pair: InternalGasPerArg, { 12.. => "algebra.ark_bn254_multi_pairing_per_pair" }, 12429399],
        [algebra_ark_bn254_pairing: InternalGas, { 12.. => "algebra.ark_bn254_pairing" }, 38543565],
        // BN254 algebra gas parameters end.

        // BLS12-381 algebra gas parameters begin.
        // Generated at time 1680606720.0709136 by `scripts/algebra-gas/update_algebra_gas_params.py` with gas_per_ns=204.6.
        [algebra_ark_bls12_381_fq12_add: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_add" }, 6686],
        [algebra_ark_bls12_381_fq12_clone: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_clone" }, 775],
        [algebra_ark_bls12_381_fq12_deser: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_deser" }, 41097],
        [algebra_ark_bls12_381_fq12_div: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_div" }, 921988],
        [algebra_ark_bls12_381_fq12_eq: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_eq" }, 2668],
        [algebra_ark_bls12_381_fq12_from_u64: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_from_u64" }, 3312],
        [algebra_ark_bls12_381_fq12_inv: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_inv" }, 737122],
        [algebra_ark_bls12_381_fq12_mul: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_mul" }, 183380],
        [algebra_ark_bls12_381_fq12_neg: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_neg" }, 4341],
        [algebra_ark_bls12_381_fq12_one: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_one" }, 40],
        [algebra_ark_bls12_381_fq12_pow_u256: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_pow_u256" }, 53905624],
        [algebra_ark_bls12_381_fq12_serialize: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_serialize" }, 29694],
        [algebra_ark_bls12_381_fq12_square: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_square" }, 129193],
        [algebra_ark_bls12_381_fq12_sub: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_sub" }, 6462],
        [algebra_ark_bls12_381_fq12_zero: InternalGas, { 8.. => "algebra.ark_bls12_381_fq12_zero" }, 775],
        [algebra_ark_bls12_381_fr_add: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_add" }, 775],
        [algebra_ark_bls12_381_fr_deser: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_deser" }, 2764],
        [algebra_ark_bls12_381_fr_div: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_div" }, 218501],
        [algebra_ark_bls12_381_fr_eq: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_eq" }, 779],
        [algebra_ark_bls12_381_fr_from_u64: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_from_u64" }, 1815],
        [algebra_ark_bls12_381_fr_inv: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_inv" }, 215450],
        [algebra_ark_bls12_381_fr_mul: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_mul" }, 1845],
        [algebra_ark_bls12_381_fr_neg: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_neg" }, 782],
        [algebra_ark_bls12_381_fr_one: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_one" }, 775],
        [algebra_ark_bls12_381_fr_serialize: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_serialize" }, 4054],
        [algebra_ark_bls12_381_fr_square: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_square" }, 1746],
        [algebra_ark_bls12_381_fr_sub: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_sub" }, 1066],
        [algebra_ark_bls12_381_fr_zero: InternalGas, { 8.. => "algebra.ark_bls12_381_fr_zero" }, 775],
        [algebra_ark_bls12_381_g1_affine_deser_comp: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_affine_deser_comp" }, 3784805],
        [algebra_ark_bls12_381_g1_affine_deser_uncomp: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_affine_deser_uncomp" }, 2649065],
        [algebra_ark_bls12_381_g1_affine_serialize_comp: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_affine_serialize_comp" }, 7403],
        [algebra_ark_bls12_381_g1_affine_serialize_uncomp: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_affine_serialize_uncomp" }, 8943],
        [algebra_ark_bls12_381_g1_proj_add: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_add" }, 39722],
        [algebra_ark_bls12_381_g1_proj_double: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_double" }, 19350],
        [algebra_ark_bls12_381_g1_proj_eq: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_eq" }, 18508],
        [algebra_ark_bls12_381_g1_proj_generator: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_generator" }, 40],
        [algebra_ark_bls12_381_g1_proj_infinity: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_infinity" }, 40],
        [algebra_ark_bls12_381_g1_proj_neg: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_neg" }, 40],
        [algebra_ark_bls12_381_g1_proj_scalar_mul: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_scalar_mul" }, 9276463],
        [algebra_ark_bls12_381_g1_proj_sub: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_sub" }, 40976],
        [algebra_ark_bls12_381_g1_proj_to_affine: InternalGas, { 8.. => "algebra.ark_bls12_381_g1_proj_to_affine" }, 444924],
        [algebra_ark_bls12_381_g2_affine_deser_comp: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_affine_deser_comp" }, 7572809],
        [algebra_ark_bls12_381_g2_affine_deser_uncomp: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_affine_deser_uncomp" }, 3742090],
        [algebra_ark_bls12_381_g2_affine_serialize_comp: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_affine_serialize_comp" }, 12417],
        [algebra_ark_bls12_381_g2_affine_serialize_uncomp: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_affine_serialize_uncomp" }, 15501],
        [algebra_ark_bls12_381_g2_proj_add: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_add" }, 119106],
        [algebra_ark_bls12_381_g2_proj_double: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_double" }, 54548],
        [algebra_ark_bls12_381_g2_proj_eq: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_eq" }, 55709],
        [algebra_ark_bls12_381_g2_proj_generator: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_generator" }, 40],
        [algebra_ark_bls12_381_g2_proj_infinity: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_infinity" }, 40],
        [algebra_ark_bls12_381_g2_proj_neg: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_neg" }, 40],
        [algebra_ark_bls12_381_g2_proj_scalar_mul: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_scalar_mul" }, 27667443],
        [algebra_ark_bls12_381_g2_proj_sub: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_sub" }, 120826],
        [algebra_ark_bls12_381_g2_proj_to_affine: InternalGas, { 8.. => "algebra.ark_bls12_381_g2_proj_to_affine" }, 473678],
        [algebra_ark_bls12_381_multi_pairing_base: InternalGas, { 8.. => "algebra.ark_bls12_381_multi_pairing_base" }, 33079033],
        [algebra_ark_bls12_381_multi_pairing_per_pair: InternalGasPerArg, { 8.. => "algebra.ark_bls12_381_multi_pairing_per_pair" }, 16919311],
        [algebra_ark_bls12_381_pairing: InternalGas, { 8.. => "algebra.ark_bls12_381_pairing" }, 54523240],
        [algebra_ark_h2c_bls12381g1_xmd_sha256_sswu_base: InternalGas, { 8.. => "algebra.ark_h2c_bls12381g1_xmd_sha256_sswu_base" }, 11954142],
        [algebra_ark_h2c_bls12381g1_xmd_sha256_sswu_per_msg_byte: InternalGasPerByte, { 8.. => "algebra.ark_h2c_bls12381g1_xmd_sha256_sswu_per_msg_byte" }, 176],
        [algebra_ark_h2c_bls12381g2_xmd_sha256_sswu_base: InternalGas, { 8.. => "algebra.ark_h2c_bls12381g2_xmd_sha256_sswu_base" }, 24897555],
        [algebra_ark_h2c_bls12381g2_xmd_sha256_sswu_per_msg_byte: InternalGasPerByte, { 8.. => "algebra.ark_h2c_bls12381g2_xmd_sha256_sswu_per_msg_byte" }, 176],
        // BLS12-381 algebra gas parameters end.

        [bls12381_base: InternalGas, "bls12381.base", 551],

        [bls12381_per_pubkey_deserialize: InternalGasPerArg, "bls12381.per_pubkey_deserialize", 400684],
        [bls12381_per_pubkey_aggregate: InternalGasPerArg, "bls12381.per_pubkey_aggregate", 15439],
        [bls12381_per_pubkey_subgroup_check: InternalGasPerArg, "bls12381.per_pubkey_subgroup_check", 1360120],

        [bls12381_per_sig_deserialize: InternalGasPerArg, "bls12381.per_sig_deserialize", 816072],
        [bls12381_per_sig_aggregate: InternalGasPerArg, "bls12381.per_sig_aggregate", 42825],
        [bls12381_per_sig_subgroup_check: InternalGasPerArg, "bls12381.per_sig_subgroup_check", 1692798],

        [bls12381_per_sig_verify: InternalGasPerArg, "bls12381.per_sig_verify", 31190860],
        [bls12381_per_pop_verify: InternalGasPerArg, "bls12381.per_pop_verify", 37862800],

        [bls12381_per_pairing: InternalGasPerArg, "bls12381.per_pairing", 14751788],

        [bls12381_per_msg_hashing: InternalGasPerArg, "bls12381.per_msg_hashing", 5661040],
        [bls12381_per_byte_hashing: InternalGasPerByte, "bls12381.per_byte_hashing", 183],

        [ed25519_base: InternalGas, "signature.base", 551],
        [ed25519_per_pubkey_deserialize: InternalGasPerArg, "signature.per_pubkey_deserialize", 139688],
        [ed25519_per_pubkey_small_order_check: InternalGasPerArg, "signature.per_pubkey_small_order_check", 23342],
        [ed25519_per_sig_deserialize: InternalGasPerArg, "signature.per_sig_deserialize", 1378],
        [ed25519_per_sig_strict_verify: InternalGasPerArg, "signature.per_sig_strict_verify", 981492],
        [ed25519_per_msg_hashing_base: InternalGasPerArg, "signature.per_msg_hashing_base", 11910],
        [ed25519_per_msg_byte_hashing: InternalGasPerByte, "signature.per_msg_byte_hashing", 220],

        [secp256k1_base: InternalGas, "secp256k1.base", 551],
        [secp256k1_ecdsa_recover: InternalGasPerArg, "secp256k1.ecdsa_recover", 5918360],

        [ristretto255_basepoint_mul: InternalGasPerArg, "ristretto255.basepoint_mul", 470528],
        [ristretto255_basepoint_double_mul: InternalGasPerArg, "ristretto255.basepoint_double_mul", 1617440],

        [ristretto255_point_add: InternalGasPerArg, "ristretto255.point_add", 7848],
        [ristretto255_point_clone: InternalGasPerArg, { 11.. => "ristretto255.point_clone" }, 551],
        [ristretto255_point_compress: InternalGasPerArg, "ristretto255.point_compress", 147040],
        [ristretto255_point_decompress: InternalGasPerArg, "ristretto255.point_decompress", 148878],
        [ristretto255_point_equals: InternalGasPerArg, "ristretto255.point_equals", 8454],
        [ristretto255_point_from_64_uniform_bytes: InternalGasPerArg, "ristretto255.point_from_64_uniform_bytes", 299594],
        [ristretto255_point_identity: InternalGasPerArg, "ristretto255.point_identity", 551],
        [ristretto255_point_mul: InternalGasPerArg, "ristretto255.point_mul", 1731396],
        [ristretto255_point_double_mul: InternalGasPerArg, { 11.. => "ristretto255.point_double_mul" }, 1869907],
        [ristretto255_point_neg: InternalGasPerArg, "ristretto255.point_neg", 1323],
        [ristretto255_point_sub: InternalGasPerArg, "ristretto255.point_sub", 7829],
        [ristretto255_point_parse_arg: InternalGasPerArg, "ristretto255.point_parse_arg", 551],


        // TODO(Alin): These SHA512 gas costs could be unified with the costs in our future SHA512 module
        // (assuming same implementation complexity, which might not be the case
        [ristretto255_sha512_per_byte: InternalGasPerByte, "ristretto255.scalar_sha512_per_byte", 220],
        [ristretto255_sha512_per_hash: InternalGasPerArg, "ristretto255.scalar_sha512_per_hash", 11910],

        [ristretto255_scalar_add: InternalGasPerArg, "ristretto255.scalar_add", 2830],
        [ristretto255_scalar_reduced_from_32_bytes: InternalGasPerArg, "ristretto255.scalar_reduced_from_32_bytes", 2609],
        [ristretto255_scalar_uniform_from_64_bytes: InternalGasPerArg, "ristretto255.scalar_uniform_from_64_bytes", 4576],
        [ristretto255_scalar_from_u128: InternalGasPerArg, "ristretto255.scalar_from_u128", 643],
        [ristretto255_scalar_from_u64: InternalGasPerArg, "ristretto255.scalar_from_u64", 643],
        [ristretto255_scalar_invert: InternalGasPerArg, "ristretto255.scalar_invert", 404360],
        [ristretto255_scalar_is_canonical: InternalGasPerArg, "ristretto255.scalar_is_canonical", 4227],
        [ristretto255_scalar_mul: InternalGasPerArg, "ristretto255.scalar_mul", 3914],
        [ristretto255_scalar_neg: InternalGasPerArg, "ristretto255.scalar_neg", 2665],
        [ristretto255_scalar_sub: InternalGasPerArg, "ristretto255.scalar_sub", 3896],
        [ristretto255_scalar_parse_arg: InternalGasPerArg, "ristretto255.scalar_parse_arg", 551],

        [hash_sip_hash_base: InternalGas, "hash.sip_hash.base", 3676],
        [hash_sip_hash_per_byte: InternalGasPerByte, "hash.sip_hash.per_byte", 73],

        [hash_keccak256_base: InternalGas, { 1.. => "hash.keccak256.base" }, 14704],
        [hash_keccak256_per_byte: InternalGasPerByte, { 1.. => "hash.keccak256.per_byte" }, 165],

        // Bulletproofs gas parameters begin.
        // Generated at time 1683148919.0628748 by `scripts/algebra-gas/update_bulletproofs_gas_params.py` with gas_per_ns=10.0.
        [bulletproofs_base: InternalGas, { 11.. => "bulletproofs.base" }, 11794651],
        [bulletproofs_per_bit_rangeproof_verify: InternalGasPerArg, { 11.. => "bulletproofs.per_bit_rangeproof_verify" }, 1004253],
        [bulletproofs_per_byte_rangeproof_deserialize: InternalGasPerByte, { 11.. => "bulletproofs.per_byte_rangeproof_deserialize" }, 121],
        // Bulletproofs gas parameters end.

        // Bulletproofs batch verify gas parameters begin.
        // Generated at time 1738897425.2325199 by `scripts/algebra-gas/update_bulletproofs_batch_verify_gas_params.py` with gas_per_ns=37.59.
        [bulletproofs_verify_base_batch_1_bits_8: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_1_bits_8" }, 17_099_501],
        [bulletproofs_verify_base_batch_1_bits_16: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_1_bits_16" }, 25_027_962],
        [bulletproofs_verify_base_batch_1_bits_32: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_1_bits_32" }, 39_739_929],
        [bulletproofs_verify_base_batch_1_bits_64: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_1_bits_64" }, 67_748_218],
        [bulletproofs_verify_base_batch_2_bits_8: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_2_bits_8" }, 25_645_449],
        [bulletproofs_verify_base_batch_2_bits_16: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_2_bits_16" }, 40_207_383],
        [bulletproofs_verify_base_batch_2_bits_32: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_2_bits_32" }, 68_498_984],
        [bulletproofs_verify_base_batch_2_bits_64: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_2_bits_64" }, 118_069_899],
        [bulletproofs_verify_base_batch_4_bits_8: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_4_bits_8" }, 41_471_127],
        [bulletproofs_verify_base_batch_4_bits_16: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_4_bits_16" }, 69_359_728],
        [bulletproofs_verify_base_batch_4_bits_32: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_4_bits_32" }, 118_697_464],
        [bulletproofs_verify_base_batch_4_bits_64: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_4_bits_64" }, 196_689_638],
        [bulletproofs_verify_base_batch_8_bits_8: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_8_bits_8" }, 71_932_907],
        [bulletproofs_verify_base_batch_8_bits_16: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_8_bits_16" }, 120_974_478],
        [bulletproofs_verify_base_batch_8_bits_32: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_8_bits_32" }, 198_670_838],
        [bulletproofs_verify_base_batch_8_bits_64: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_8_bits_64" }, 339_391_615],
        [bulletproofs_verify_base_batch_16_bits_8: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_16_bits_8" }, 124_950_279],
        [bulletproofs_verify_base_batch_16_bits_16: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_16_bits_16" }, 202_393_357],
        [bulletproofs_verify_base_batch_16_bits_32: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_16_bits_32" }, 344_222_644],
        [bulletproofs_verify_base_batch_16_bits_64: InternalGas, { RELEASE_V1_28.. => "bulletproofs.verify.base_batch_16_bits_64" }, 603_952_779],
        // Bulletproofs batch verify gas parameters end.

        [type_info_type_of_base: InternalGas, "type_info.type_of.base", 1102],
        // TODO(Gas): the on-chain name is wrong...
        [type_info_type_of_per_byte_in_str: InternalGasPerByte, "type_info.type_of.per_abstract_memory_unit", 18],
        [type_info_type_name_base: InternalGas, "type_info.type_name.base", 1102],
        // TODO(Gas): the on-chain name is wrong...
        [type_info_type_name_per_byte_in_str: InternalGasPerByte, "type_info.type_name.per_abstract_memory_unit", 18],
        [type_info_chain_id_base: InternalGas, { 4.. => "type_info.chain_id.base" }, 551],

        // TODO(Gas): Fix my cost
        [function_info_check_is_identifier_base: InternalGas, { RELEASE_V1_13.. => "function_info.is_identifier.base" }, 551],
        [function_info_check_is_identifier_per_byte: InternalGasPerByte, { RELEASE_V1_13.. => "function_info.is_identifier.per_byte" }, 3],
        [function_info_check_dispatch_type_compatibility_impl_base: InternalGas, { RELEASE_V1_13.. => "function_info.check_dispatch_type_compatibility_impl.base" }, 1002],
        [function_info_load_function_base: InternalGas, { RELEASE_V1_13.. => "function_info.load_function.base" }, 551],
        [dispatchable_fungible_asset_dispatch_base: InternalGas, { RELEASE_V1_13.. => "dispatchable_fungible_asset.dispatch.base" }, 551],
        [dispatchable_authenticate_dispatch_base: InternalGas, { RELEASE_V1_26.. => "dispatchable_authenticate.dispatch.base" }, 551],

        // Reusing SHA2-512's cost from Ristretto
        [hash_sha2_512_base: InternalGas, { 4.. => "hash.sha2_512.base" }, 11910],  // 3_240 * 20
        [hash_sha2_512_per_byte: InternalGasPerByte, { 4.. => "hash.sha2_512.per_byte" }, 220], // 60 * 20
        // Back-of-the-envelope approximation from SHA3-256's costs (4000 base, 45 per-byte)
        [hash_sha3_512_base: InternalGas, { 4.. => "hash.sha3_512.base" }, 16542], // 4_500 * 20
        [hash_sha3_512_per_byte: InternalGasPerByte, { 4.. => "hash.sha3_512.per_byte" }, 183], // 50 * 20
        // Using SHA2-256's cost
        [hash_ripemd160_base: InternalGas, { 4.. => "hash.ripemd160.base" }, 11028], // 3000 * 20
        [hash_ripemd160_per_byte: InternalGasPerByte, { 4.. => "hash.ripemd160.per_byte" }, 183], // 50 * 20
        [hash_blake2b_256_base: InternalGas, { 6.. => "hash.blake2b_256.base" }, 6433], // 1750 * 20
        [hash_blake2b_256_per_byte: InternalGasPerByte, { 6.. => "hash.blake2b_256.per_byte" }, 55], // 15 * 20

        [util_from_bytes_base: InternalGas, "util.from_bytes.base", 1102],
        [util_from_bytes_per_byte: InternalGasPerByte, "util.from_bytes.per_byte", 18],

        [transaction_context_get_txn_hash_base: InternalGas, { 10.. => "transaction_context.get_txn_hash.base" }, 735],
        [transaction_context_get_script_hash_base: InternalGas, "transaction_context.get_script_hash.base", 735],
        // Based on SHA3-256's cost
        [transaction_context_generate_unique_address_base: InternalGas, { 10.. => "transaction_context.generate_unique_address.base" }, 14704],
        [transaction_context_monotonically_increasing_counter_base: InternalGas, {RELEASE_V1_36.. => "transaction_context.monotonically_increasing_counter.base"}, 735],
        [transaction_context_sender_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.sender.base"}, 735],
        [transaction_context_secondary_signers_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.secondary_signers.base"}, 735],
        [transaction_context_secondary_signers_per_signer: InternalGasPerArg, {RELEASE_V1_12.. => "transaction_context.secondary_signers.per_signer"}, 576], // 18 * 32
        [transaction_context_fee_payer_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.fee_payer.base"}, 735],
        [transaction_context_max_gas_amount_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.max_gas_amount.base"}, 735],
        [transaction_context_gas_unit_price_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.gas_unit_price.base"}, 735],
        [transaction_context_chain_id_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.chain_id.base"}, 735],
        [transaction_context_entry_function_payload_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.entry_function_payload.base"}, 735],
        [transaction_context_entry_function_payload_per_byte_in_str: InternalGasPerByte, {RELEASE_V1_12.. => "transaction_context.entry_function_payload.per_abstract_memory_unit"}, 18],
        [transaction_context_multisig_payload_base: InternalGas, {RELEASE_V1_12.. => "transaction_context.multisig_payload.base"}, 735],
        [transaction_context_multisig_payload_per_byte_in_str: InternalGasPerByte, {RELEASE_V1_12.. => "transaction_context.multisig_payload.per_abstract_memory_unit"}, 18],

        [code_request_publish_base: InternalGas, "code.request_publish.base", 1838],
        [code_request_publish_per_byte: InternalGasPerByte, "code.request_publish.per_byte", 7],

        [event_write_to_event_store_base: InternalGas, "event.write_to_event_store.base", 20006],
        // TODO(Gas): the on-chain name is wrong...
        [event_write_to_event_store_per_abstract_value_unit: InternalGasPerAbstractValueUnit, "event.write_to_event_store.per_abstract_memory_unit", 61],

        [state_storage_get_usage_base_cost: InternalGas, "state_storage.get_usage.base", 1838],

        [aggregator_add_base: InternalGas, "aggregator.add.base", 1102],
        [aggregator_read_base: InternalGas, "aggregator.read.base", 1102],
        [aggregator_sub_base: InternalGas, "aggregator.sub.base", 1102],
        [aggregator_destroy_base: InternalGas, "aggregator.destroy.base", 1838],
        [aggregator_factory_new_aggregator_base: InternalGas, "aggregator_factory.new_aggregator.base", 1838],

        [aggregator_v2_create_aggregator_base: InternalGas, {RELEASE_V1_9_SKIPPED.. => "aggregator_v2.create_aggregator.base"}, 1838],
        [aggregator_v2_try_add_base: InternalGas, {RELEASE_V1_9_SKIPPED.. => "aggregator_v2.try_add.base"}, 1102],
        [aggregator_v2_try_sub_base: InternalGas, {RELEASE_V1_9_SKIPPED.. => "aggregator_v2.try_sub.base"}, 1102],
        [aggregator_v2_is_at_least_base: InternalGas, {RELEASE_V1_14.. => "aggregator_v2.is_at_least.base"}, 500],

        [aggregator_v2_read_base: InternalGas, {RELEASE_V1_9_SKIPPED.. => "aggregator_v2.read.base"}, 2205],
        [aggregator_v2_snapshot_base: InternalGas, {RELEASE_V1_9_SKIPPED.. => "aggregator_v2.snapshot.base"}, 1102],

        [aggregator_v2_create_snapshot_base: InternalGas, {RELEASE_V1_8.. => "aggregator_v2.create_snapshot.base"}, 1102],
        [aggregator_v2_create_snapshot_per_byte: InternalGasPerByte, { RELEASE_V1_9_SKIPPED.. =>"aggregator_v2.create_snapshot.per_byte" }, 3],
        [aggregator_v2_copy_snapshot_base: InternalGas, {RELEASE_V1_8.. => "aggregator_v2.copy_snapshot.base"}, 1102],
        [aggregator_v2_read_snapshot_base: InternalGas, {RELEASE_V1_8.. => "aggregator_v2.read_snapshot.base"}, 2205],
        [aggregator_v2_string_concat_base: InternalGas, {RELEASE_V1_8.. => "aggregator_v2.string_concat.base"}, 1102],
        [aggregator_v2_string_concat_per_byte: InternalGasPerByte, { RELEASE_V1_9_SKIPPED.. =>"aggregator_v2.string_concat.per_byte" }, 3],

        [object_exists_at_base: InternalGas, { 7.. => "object.exists_at.base" }, 919],
        // Based on SHA3-256's cost
        [object_user_derived_address_base: InternalGas, { RELEASE_V1_12.. => "object.user_derived_address.base" }, 14704],

        // These are dummy value, they copied from storage gas in aptos-core/aptos-vm/src/aptos_vm_impl.rs
        [object_exists_at_per_byte_loaded: InternalGasPerByte, { 7.. => "object.exists_at.per_byte_loaded" }, 183],
        [object_exists_at_per_item_loaded: InternalGas, { 7.. => "object.exists_at.per_item_loaded" }, 1470],
        [string_utils_base: InternalGas, { 8.. => "string_utils.format.base" }, 1102],
        [string_utils_per_byte: InternalGasPerByte, { 8.. =>"string_utils.format.per_byte" }, 3],

        [randomness_fetch_and_inc_counter: InternalGas, { RELEASE_V1_23.. => "randomness.fetch_and_inc_counter" }, 1],

        // Reflection
        [reflect_resolve_base: InternalGas, { RELEASE_V1_39.. => "reflect.resolve_base" }, 4096],
    ]
);
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L4-46)
```rust
macro_rules! define_gas_parameters_extract_key_at_version {
    ($key: literal, $cur_ver: expr) => {
        Some($key)
    };

    ({ $($ver: pat => $key: literal),+ }, $cur_ver: expr) => {
        match $cur_ver {
            $($ver => Some($key)),+,
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

macro_rules! define_gas_parameters {
    (
        $params_name: ident,
        $prefix: literal,
        $env: ty => $(.$field: ident)*,
        [$(
            [$name: ident: $ty: ident, $key_bindings: tt, $initial: expr $(, $tn: ident)? $(,)?]
        ),* $(,)?]
    ) => {
        #[derive(Debug, Clone)]
        pub struct $params_name {
            $(pub $name : $ty),*
        }

        impl $crate::traits::FromOnChainGasSchedule for $params_name {
            #[allow(unused)]
            fn from_on_chain_gas_schedule(gas_schedule: &std::collections::BTreeMap<String, u64>, feature_version: u64) -> Result<Self, String> {
                let mut params = $params_name::zeros();

                $(
                    if let Some(key) = $crate::gas_schedule::macros::define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
                        let name = format!("{}.{}", $prefix, key);
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
                    }
                )*

                Ok(params)
            }
        }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L216-229)
```rust
            max_execution_gas_gov: InternalGas,
            { RELEASE_V1_13.. => "max_execution_gas.gov" },
            4_000_000_000,
        ],
        [
            max_io_gas: InternalGas,
            { 7.. => "max_io_gas" },
            1_000_000_000, // 100ms of IO at 10k gas per ms
        ],
        [
            max_io_gas_gov: InternalGas,
            { RELEASE_V1_13.. => "max_io_gas.gov" },
            2_000_000_000,
        ],
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L63-87)
```rust
    pub fn new(
        gas_feature_version: u64,
        vm_gas_params: VMGasParameters,
        storage_gas_params: StorageGasParameters,
        is_approved_gov_script: bool,
        balance: impl Into<Gas>,
        block_synchronization_kill_switch: &'a T,
    ) -> Self {
        let balance = balance.into().to_unit_with_params(&vm_gas_params.txn);

        let (max_execution_gas, max_io_gas, max_storage_fee) = if is_approved_gov_script
            && gas_feature_version >= gas_feature_versions::RELEASE_V1_13
        {
            (
                vm_gas_params.txn.max_execution_gas_gov,
                vm_gas_params.txn.max_io_gas_gov,
                vm_gas_params.txn.max_storage_fee_gov,
            )
        } else {
            (
                vm_gas_params.txn.max_execution_gas,
                vm_gas_params.txn.max_io_gas,
                vm_gas_params.txn.max_storage_fee,
            )
        };
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L204-208)
```rust
        if self.feature_version >= 7 && self.execution_gas_used > self.max_execution_gas {
            Err(PartialVMError::new(StatusCode::EXECUTION_LIMIT_REACHED))
        } else {
            Ok(())
        }
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L15-19)
```rust
pub fn get_gas_feature_version(state_view: &impl StateView) -> u64 {
    GasScheduleV2::fetch_config(state_view)
        .map(|gas_schedule| gas_schedule.feature_version)
        .unwrap_or(0)
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-103)
```text
    public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        config_buffer::upsert(new_gas_schedule);
    }
```
