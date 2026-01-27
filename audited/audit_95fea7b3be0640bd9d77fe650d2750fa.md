# Audit Report

## Title
Consensus Failure Due to Inconsistent max_aa_gas Parameter During Rolling Validator Upgrades

## Summary
The `max_aa_gas` parameter, introduced in RELEASE_V1_26 (gas feature version 30), creates a consensus vulnerability during rolling validator upgrades. Validators running updated node software but connecting to a network with gas feature version < 30 will initialize `max_aa_gas` to 0, causing all Account Abstraction (AA) transactions to fail with OUT_OF_GAS errors. Meanwhile, validators running older node software without the `max_aa_gas` limiting logic will process the same AA transactions successfully, breaking consensus determinism.

## Finding Description

The vulnerability occurs due to a mismatch between code-level version gating (when node software is upgraded) and on-chain gas feature version gating (when the gas schedule is upgraded via governance).

The `max_aa_gas` parameter is defined with version gating in the gas schedule: [1](#0-0) 

The version gating macro implementation shows that when `feature_version < RELEASE_V1_26` (30), the parameter is skipped during loading and remains at its zero-initialized value: [2](#0-1) [3](#0-2) 

However, the code that **uses** `max_aa_gas` has NO version gating - it only checks if account abstraction features are enabled: [4](#0-3) 

When `max_aa_gas = 0`, the initial gas balance becomes `min(0, txn.max_gas_amount()) = 0`. The prologue execution then fails immediately: [5](#0-4) 

The `unwrap_or_discard!` macro catches the OUT_OF_GAS error and returns early with a failure status: [6](#0-5) 

**Attack Scenario:**

1. Network operates with gas feature version < 30 (before RELEASE_V1_26)
2. Account Abstraction features are enabled by default: [7](#0-6) 

3. Some validators upgrade their node software to a version that includes the `max_aa_gas` code
4. These updated validators load gas parameters from on-chain GasScheduleV2: [8](#0-7) 

5. Since `feature_version < 30`, the `max_aa_gas` parameter is not loaded and remains 0
6. An AA transaction is submitted to the network
7. **Updated validators**: Execute with `initial_balance = 0`, transaction fails with OUT_OF_GAS
8. **Old validators**: Execute without `max_aa_gas` limiting, transaction processes normally with full gas allowance
9. **Result**: Different execution outcomes → consensus divergence → network partition

## Impact Explanation

This is a **Critical** severity vulnerability per Aptos bug bounty criteria because it causes **Consensus/Safety violations** - specifically, it breaks the fundamental invariant that "All validators must produce identical state roots for identical blocks."

During a rolling upgrade where validators gradually update their node software before the on-chain gas schedule is upgraded, the network will experience:

- **Consensus failures**: Different validators produce different state roots for blocks containing AA transactions
- **Network partition risk**: The blockchain may fork as validators disagree on block validity
- **Transaction execution non-determinism**: Same transaction yields different results on different validators
- **Potential hardfork requirement**: Recovery may require coordinated intervention to restore consensus

The vulnerability affects all AA transactions during the upgrade window, which could be a significant portion of network traffic depending on AA adoption.

## Likelihood Explanation

**High likelihood** of occurrence:

1. **Default feature flag enabled**: Account Abstraction is enabled by default in the feature set, so the vulnerable code path is active
2. **Common upgrade pattern**: Rolling upgrades are the standard practice for validator software updates to maintain network availability
3. **Governance coordination gap**: There is typically a time window between validator software releases and governance-approved gas schedule upgrades
4. **No safeguards**: The code lacks runtime version checks to prevent using `max_aa_gas` when it's uninitialized
5. **Silent failure mode**: The issue manifests as consensus divergence rather than explicit errors, making it hard to detect before deployment

The vulnerability will trigger automatically whenever:
- Validators run mixed node software versions (old vs. new)
- Gas feature version < 30
- AA feature flags are enabled
- Any user submits an AA transaction

## Recommendation

Add runtime version gating in the code that uses `max_aa_gas` to ensure it's only applied when the gas feature version supports it:

```rust
let initial_balance = if (self.features().is_account_abstraction_enabled()
    || self.features().is_derivable_account_abstraction_enabled())
    && self.gas_feature_version() >= gas_feature_versions::RELEASE_V1_26
{
    vm_params.txn.max_aa_gas.min(txn.max_gas_amount().into())
} else {
    txn.max_gas_amount().into()
};
```

Similarly, add version gating to the post-prologue gas injection logic:

```rust
if (self.features().is_account_abstraction_enabled()
    || self.features().is_derivable_account_abstraction_enabled())
    && self.gas_feature_version() >= gas_feature_versions::RELEASE_V1_26
{
    let max_aa_gas = unwrap_or_discard!(self.gas_params(log_context))
        .vm
        .txn
        .max_aa_gas;
    if max_aa_gas < txn_data.max_gas_amount() {
        unwrap_or_discard!(gas_meter
            .inject_balance(txn_data.max_gas_amount().checked_sub(max_aa_gas).unwrap()));
    }
} else {
    assert_eq!(initial_gas, gas_meter.balance());
}
```

**Additional safeguards:**
1. Enforce minimum value validation for `max_aa_gas` to prevent zero values from being used
2. Document upgrade coordination requirements between node software and gas schedule updates
3. Add integration tests that simulate mixed-version validator scenarios
4. Implement monitoring to detect consensus divergence during upgrades

## Proof of Concept

**Setup:**
1. Deploy a local testnet with gas feature version 29 (< RELEASE_V1_26)
2. Enable ACCOUNT_ABSTRACTION feature flag (already enabled by default)
3. Run two validators: one with old node software, one with updated software containing `max_aa_gas` code

**Execution:**
```rust
// Validator A (old software): No max_aa_gas code
// Validator B (new software): Has max_aa_gas code, but feature_version = 29 < 30
// Both validators: ACCOUNT_ABSTRACTION enabled

// Submit AA transaction with max_gas_amount = 1000
let txn = create_aa_transaction(max_gas: 1000);

// Validator A execution:
// - No max_aa_gas limiting logic
// - initial_balance = 1000
// - Prologue executes successfully
// - Transaction result: SUCCESS

// Validator B execution:
// - max_aa_gas loaded as 0 (feature_version < 30)
// - initial_balance = min(0, 1000) = 0
// - Prologue fails immediately with OUT_OF_GAS
// - Transaction result: OUT_OF_GAS

// Consensus check:
// - Validator A state root: X (includes AA transaction effects)
// - Validator B state root: Y (different, transaction failed)
// - Consensus failure: validators cannot agree on block validity
```

**Demonstration script:**
1. Modify gas feature version in genesis to 29
2. Deploy mixed validator set (simulate rolling upgrade)
3. Submit AA transaction
4. Observe consensus divergence in block proposals
5. Verify state roots differ between validators

## Notes

This vulnerability exemplifies a broader pattern in version-gated systems: code-level feature gates must be synchronized with runtime configuration gates. The `max_aa_gas` parameter has proper on-chain version gating (through GasScheduleV2 feature_version), but the code consuming it lacks corresponding runtime checks, creating a dangerous intermediate state during upgrades.

The issue is particularly insidious because:
- It doesn't affect non-AA transactions
- Both feature flags and gas parameters appear correctly configured from each validator's perspective
- The failure mode (consensus divergence) only manifests when the network has mixed software versions
- Standard pre-deployment testing with homogeneous validator versions would not detect this issue

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L276-279)
```rust
            max_aa_gas: Gas,
            { RELEASE_V1_26.. => "max_aa_gas" },
            60,
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L34-45)
```rust
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2001-2012)
```rust
        let serialized_signers = unwrap_or_discard!(prologue_session.execute(|session| {
            self.validate_signed_transaction(
                session,
                code_storage,
                txn,
                &txn_data,
                log_context,
                is_approved_gov_script,
                &mut traversal_context,
                gas_meter,
            )
        }));
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

**File:** types/src/on_chain_config/aptos_features.rs (L254-256)
```rust
            FeatureFlag::ACCOUNT_ABSTRACTION,
            FeatureFlag::BULLETPROOFS_BATCH_NATIVES,
            FeatureFlag::DERIVABLE_ACCOUNT_ABSTRACTION,
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L27-35)
```rust
    match GasScheduleV2::fetch_config_and_bytes(state_view) {
        Some((gas_schedule, bytes)) => {
            sha3_256.update(&bytes);
            let feature_version = gas_schedule.feature_version;
            let map = gas_schedule.into_btree_map();
            (
                AptosGasParameters::from_on_chain_gas_schedule(&map, feature_version),
                feature_version,
            )
```
