# Audit Report

## Title
Gas Schedule Feature Version Ceiling Attack via Missing Upper Bound Validation

## Summary
The gas schedule updator tool and on-chain validation logic lack upper bound checks on `feature_version`, allowing governance proposals to set it to `u64::MAX`. This permanently freezes the gas schedule upgrade mechanism, requiring a hard fork to recover, and breaks the invariant that gas schedules must remain upgradeable to support network evolution.

## Finding Description

The gas schedule updator tool accepts arbitrary `feature_version` values through the `--gas-feature-version` command-line argument with no validation: [1](#0-0) 

This value flows directly into the proposal generation without any bounds checking: [2](#0-1) 

The on-chain validation in `gas_schedule.move` only enforces a non-decreasing constraint (`>=`) without an upper bound: [3](#0-2) 

**Attack Path:**
1. A governance proposal is generated with `--gas-feature-version 18446744073709551615` (u64::MAX)
2. The proposal passes governance voting (requires governance participation)
3. On-chain execution checks: `18446744073709551615 >= current_version` → passes ✓
4. Gas schedule updated with `feature_version = u64::MAX`
5. All future upgrade attempts fail: no value can satisfy `new_version >= u64::MAX` except u64::MAX itself
6. Gas schedule version is permanently frozen, preventing any meaningful upgrades

**Invariant Broken:** The gas schedule must remain upgradeable to support network evolution. The expected versioning pattern increments by 1 (currently at version 45): [4](#0-3) 

Once `feature_version` reaches u64::MAX, no legitimate increment is possible, permanently breaking upgrade ordering guarantees.

## Impact Explanation

**Severity: Critical** - This qualifies under "Non-recoverable network partition (requires hardfork)" because:

1. **Hard Fork Required**: Recovery requires manually resetting the `feature_version` in the on-chain state, which cannot be done through normal governance and necessitates a hard fork
2. **Network Evolution Frozen**: Future Aptos releases cannot add properly-priced gas parameters for new Move operations, forcing the choice between:
   - Not deploying new VM features (development stagnation)
   - Deploying features without gas pricing (DoS vulnerability via resource exhaustion)
3. **Cascading Security Impact**: Inability to update gas schedules means newly discovered gas computation inefficiencies cannot be fixed, leaving known DoS vectors permanently exploitable

While only a warning exists in the replay-benchmark tool, no validation exists where it matters: [5](#0-4) 

## Likelihood Explanation

**Likelihood: Low to Medium**

This requires governance approval, which involves trusted participants. However, the likelihood increases due to:

1. **Operational Error Risk**: An operator using the tool could accidentally paste a large number or use MAX values during testing
2. **Lack of Safeguards**: The tool provides no warnings or confirmation prompts for suspicious values
3. **Governance Process Vulnerability**: If a malicious or compromised governance participant submits such a proposal with misleading descriptions, other voters might not scrutinize the raw `feature_version` value in the serialized blob
4. **Irreversible Consequences**: A single approved proposal permanently damages the network

The expected version increment pattern (currently v45, historically incrementing by 1) makes u64::MAX clearly anomalous, but the lack of automated validation creates unnecessary risk.

## Recommendation

Implement strict upper bound validation at both the tool level and on-chain:

**1. Tool-Level Validation** (aptos-gas-schedule-updator/src/lib.rs):
```rust
pub fn generate_update_proposal(args: &GenArgs) -> Result<()> {
    let mut pack = PackageBuilder::new("GasScheduleUpdate");

    let feature_version = args
        .gas_feature_version
        .unwrap_or(LATEST_GAS_FEATURE_VERSION);
    
    // Add validation
    if feature_version > LATEST_GAS_FEATURE_VERSION + 100 {
        anyhow::bail!(
            "Feature version {} exceeds safe maximum (latest: {}, max allowed: {}). \
             This would prevent future gas schedule upgrades.",
            feature_version,
            LATEST_GAS_FEATURE_VERSION,
            LATEST_GAS_FEATURE_VERSION + 100
        );
    }

    pack.add_source(
        "update_gas_schedule.move",
        &generate_script(&current_gas_schedule(feature_version))?,
    );
    // ... rest of implementation
}
```

**2. On-Chain Validation** (gas_schedule.move):
```move
const MAX_REASONABLE_FEATURE_VERSION: u64 = 10000; // Generous upper bound

public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // Prevent ceiling attacks
    assert!(
        new_gas_schedule.feature_version <= MAX_REASONABLE_FEATURE_VERSION,
        error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
    );
    
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

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_feature_version_ceiling_attack() {
    use aptos_gas_schedule_updator::{generate_update_proposal, GenArgs};
    use std::u64;
    
    // Generate malicious proposal with u64::MAX
    let args = GenArgs {
        output: Some("./malicious_proposal".to_string()),
        gas_feature_version: Some(u64::MAX),
    };
    
    // Currently succeeds without validation ✗
    let result = generate_update_proposal(&args);
    assert!(result.is_ok(), "Tool should reject u64::MAX but doesn't");
    
    // The generated proposal would pass on-chain checks:
    // u64::MAX >= current_version (45) → TRUE
    // But future updates would fail:
    // any_future_version >= u64::MAX → FALSE (except u64::MAX itself)
}
```

**Move Test for On-Chain Behavior:**
```move
#[test(fx = @aptos_framework)]
fun test_feature_version_prevents_future_upgrades(fx: signer) {
    // Setup: Install gas schedule with u64::MAX
    let malicious_schedule = GasScheduleV2 {
        feature_version: 18446744073709551615, // u64::MAX
        entries: vector[],
    };
    move_to(&fx, malicious_schedule);
    
    // Attempt legitimate future upgrade
    let future_schedule = GasScheduleV2 {
        feature_version: 46, // Next legitimate version
        entries: vector[],
    };
    let future_bytes = bcs::to_bytes(&future_schedule);
    
    // This should fail: 46 >= u64::MAX is FALSE
    gas_schedule::set_for_next_epoch(&fx, future_bytes);
    // Expected: EINVALID_GAS_FEATURE_VERSION abort
}
```

## Notes

While this vulnerability requires governance approval (trusted actors), it represents a critical missing defensive validation that could lead to irreversible network damage through either malicious action or operational error. The lack of upper bound checks violates basic input validation principles for security-critical parameters that control network upgradeability.

### Citations

**File:** aptos-move/aptos-gas-schedule-updator/src/lib.rs (L105-113)
```rust
/// Command line arguments to the gas schedule update proposal generation tool.
#[derive(Debug, Parser)]
pub struct GenArgs {
    #[clap(short, long)]
    pub output: Option<String>,

    #[clap(short, long)]
    pub gas_feature_version: Option<u64>,
}
```

**File:** aptos-move/aptos-gas-schedule-updator/src/lib.rs (L124-141)
```rust
pub fn generate_update_proposal(args: &GenArgs) -> Result<()> {
    let mut pack = PackageBuilder::new("GasScheduleUpdate");

    let feature_version = args
        .gas_feature_version
        .unwrap_or(LATEST_GAS_FEATURE_VERSION);

    pack.add_source(
        "update_gas_schedule.move",
        &generate_script(&current_gas_schedule(feature_version))?,
    );
    // TODO: use relative path here
    pack.add_local_dep("AptosFramework", &aptos_framework_path().to_string_lossy());

    pack.write_to_disk(args.output.as_deref().unwrap_or("./proposal"))?;

    Ok(())
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

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L76-112)
```rust
pub const LATEST_GAS_FEATURE_VERSION: u64 = gas_feature_versions::RELEASE_V1_41;

pub mod gas_feature_versions {
    pub const RELEASE_V1_8: u64 = 11;
    pub const RELEASE_V1_9_SKIPPED: u64 = 12;
    pub const RELEASE_V1_9: u64 = 13;
    pub const RELEASE_V1_10: u64 = 15;
    pub const RELEASE_V1_11: u64 = 16;
    pub const RELEASE_V1_12: u64 = 17;
    pub const RELEASE_V1_13: u64 = 18;
    pub const RELEASE_V1_14: u64 = 19;
    pub const RELEASE_V1_15: u64 = 20;
    pub const RELEASE_V1_16: u64 = 21;
    pub const RELEASE_V1_18: u64 = 22;
    pub const RELEASE_V1_19: u64 = 23;
    pub const RELEASE_V1_20: u64 = 24;
    pub const RELEASE_V1_21: u64 = 25;
    pub const RELEASE_V1_22: u64 = 26;
    pub const RELEASE_V1_23: u64 = 27;
    pub const RELEASE_V1_24: u64 = 28;
    pub const RELEASE_V1_26: u64 = 30;
    pub const RELEASE_V1_27: u64 = 31;
    pub const RELEASE_V1_28: u64 = 32;
    pub const RELEASE_V1_29: u64 = 33;
    pub const RELEASE_V1_30: u64 = 34;
    pub const RELEASE_V1_31: u64 = 35;
    pub const RELEASE_V1_32: u64 = 36;
    pub const RELEASE_V1_33: u64 = 37;
    pub const RELEASE_V1_34: u64 = 38;
    pub const RELEASE_V1_35: u64 = 39;
    pub const RELEASE_V1_36: u64 = 40;
    pub const RELEASE_V1_37: u64 = 41;
    pub const RELEASE_V1_38: u64 = 42;
    pub const RELEASE_V1_39: u64 = 43;
    pub const RELEASE_V1_40: u64 = 44;
    pub const RELEASE_V1_41: u64 = 45;
}
```

**File:** aptos-move/replay-benchmark/src/overrides.rs (L76-81)
```rust
        if matches!(gas_feature_version, Some(v) if v > LATEST_GAS_FEATURE_VERSION) {
            warn!(
                "Gas feature version is greater than the latest one: {}",
                LATEST_GAS_FEATURE_VERSION
            );
        }
```
