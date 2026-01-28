# Audit Report

## Title
Consensus Failure Due to Inconsistent max_aa_gas Parameter During Rolling Validator Upgrades

## Summary
The `max_aa_gas` parameter creates a consensus vulnerability during rolling validator upgrades when the on-chain gas feature version is below 30 (RELEASE_V1_26). Validators running updated node software initialize `max_aa_gas` to 0 due to version gating, causing all Account Abstraction transactions to fail with OUT_OF_GAS errors. Meanwhile, validators running older node software without this parameter process the same transactions successfully, breaking consensus determinism and creating potential network partition.

## Finding Description

The vulnerability stems from a critical mismatch between code-level functionality (when node software is upgraded) and on-chain gas feature version gating (when governance upgrades the gas schedule).

The `max_aa_gas` parameter is version-gated in the gas schedule definition: [1](#0-0) 

The version gating macro implementation ensures that when `feature_version < RELEASE_V1_26` (30), the parameter is not loaded from on-chain storage and the macro returns `None`: [2](#0-1) 

When version gating skips a parameter, it remains at its zero-initialized value: [3](#0-2) 

However, the code that **uses** `max_aa_gas` contains NO version gating - it only checks if account abstraction features are enabled: [4](#0-3) 

When `max_aa_gas = 0`, the calculation `initial_balance = min(0, txn.max_gas_amount())` results in a gas meter initialized with zero balance. This causes immediate OUT_OF_GAS failures during transaction validation, which the `unwrap_or_discard!` macro converts to early return with failure status: [5](#0-4) 

**Attack Scenario:**

1. Network operates with `GasScheduleV2.feature_version < 30`: [6](#0-5) 

2. Account Abstraction features are enabled by default: [7](#0-6) 

3. Some validators upgrade their node software containing the `max_aa_gas` code
4. Updated validators load gas parameters from on-chain `GasScheduleV2`, but `max_aa_gas` remains 0 due to version gating
5. An AA transaction is submitted
6. **Updated validators**: Execute with `initial_balance = 0`, transaction fails with OUT_OF_GAS
7. **Old validators**: Execute without `max_aa_gas` limiting logic, transaction succeeds with full gas allowance
8. **Result**: Different execution outcomes → consensus divergence → network partition

The same divergent behavior occurs in the validation path: [8](#0-7) 

## Impact Explanation

This is a **Critical** severity vulnerability per Aptos bug bounty criteria, specifically qualifying as a **Consensus/Safety Violation**. It breaks the fundamental blockchain invariant that "All validators must produce identical state roots for identical blocks."

During a rolling upgrade period where validators gradually update their node software before the on-chain gas schedule is upgraded via governance, the network will experience:

- **Consensus failures**: Different validators produce different state roots for any block containing AA transactions
- **Network partition risk**: The blockchain may fork as validators disagree on block validity, potentially requiring hardfork intervention
- **Transaction execution non-determinism**: Identical AA transactions yield different results on different validators based solely on software version
- **Liveness degradation**: Network may fail to reach consensus quorum on blocks with AA transactions

This matches the Critical severity criteria: "Different validators commit different blocks" and "Chain splits without hardfork requirement" with no requirement for Byzantine behavior (< 1/3 Byzantine validators).

## Likelihood Explanation

**High likelihood** of occurrence due to multiple factors:

1. **Default feature flag enabled**: Account Abstraction is enabled by default in the feature set, making the vulnerable code path active on all networks
2. **Standard operational procedure**: Rolling upgrades are the standard practice for validator software updates to maintain network availability
3. **Temporal gap by design**: There is inherently a time window between validator software releases and governance-approved on-chain gas schedule upgrades
4. **No runtime safeguards**: The code lacks any runtime version checks in the usage path to prevent using `max_aa_gas` when uninitialized
5. **Silent failure mode**: Manifests as consensus divergence rather than explicit errors, making it difficult to detect before production deployment

The vulnerability triggers automatically whenever:
- Validators run mixed node software versions (old vs. new)
- On-chain gas `feature_version < 30`
- AA feature flags are enabled (default state)
- Any user submits an AA transaction

No attacker is required - this is an unintentional consensus bug that occurs during normal network operations.

## Recommendation

Implement version gating checks in the usage code to align with the parameter definition:

```rust
let initial_balance = if (self.features().is_account_abstraction_enabled()
    || self.features().is_derivable_account_abstraction_enabled())
    && self.gas_feature_version() >= RELEASE_V1_26
{
    vm_params.txn.max_aa_gas.min(txn.max_gas_amount().into())
} else {
    txn.max_gas_amount().into()
};
```

This ensures that `max_aa_gas` limiting is only applied when the on-chain gas schedule has actually been upgraded to include this parameter, preventing consensus divergence during rolling upgrades.

Additionally, consider adding explicit validation that version-gated parameters are not used when their corresponding version threshold hasn't been met, or ensuring all version-gated parameters have default values that maintain backward compatibility.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a network with `GasScheduleV2.feature_version = 29` (< RELEASE_V1_26)
2. Ensuring AA features are enabled (default configuration)
3. Running validators with mixed software versions (some with `max_aa_gas` code, some without)
4. Submitting an AA transaction with `dispatchable_authenticate`
5. Observing that updated validators reject the transaction with OUT_OF_GAS while old validators accept it
6. Verifying different state roots produced by different validator sets

The execution divergence is deterministic and reproducible given the version mismatch scenario described.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L276-278)
```rust
            max_aa_gas: Gas,
            { RELEASE_V1_26.. => "max_aa_gas" },
            60,
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L38-41)
```rust
                    if let Some(key) = $crate::gas_schedule::macros::define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
                        let name = format!("{}.{}", $prefix, key);
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
                    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L64-68)
```rust
            pub fn zeros() -> Self {
                Self {
                    $($name: 0.into()),*
                }
            }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L176-188)
```rust
macro_rules! unwrap_or_discard {
    ($res:expr) => {
        match $res {
            Ok(s) => s,
            Err(e) => {
                // covers both VMStatus itself and VMError which can convert to VMStatus
                let s: VMStatus = e.into();

                let o = discarded_output(s.status_code());
                return (s, o);
            },
        }
    };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2149-2155)
```rust
        let initial_balance = if self.features().is_account_abstraction_enabled()
            || self.features().is_derivable_account_abstraction_enabled()
        {
            vm_params.txn.max_aa_gas.min(txn.max_gas_amount().into())
        } else {
            txn.max_gas_amount().into()
        };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3263-3269)
```rust
        let initial_balance = if self.features().is_account_abstraction_enabled()
            || self.features().is_derivable_account_abstraction_enabled()
        {
            vm_params.txn.max_aa_gas.min(txn_data.max_gas_amount())
        } else {
            txn_data.max_gas_amount()
        };
```

**File:** types/src/on_chain_config/gas_schedule.rs (L14-17)
```rust
pub struct GasScheduleV2 {
    pub feature_version: u64,
    pub entries: Vec<(String, u64)>,
}
```

**File:** types/src/on_chain_config/aptos_features.rs (L254-254)
```rust
            FeatureFlag::ACCOUNT_ABSTRACTION,
```
