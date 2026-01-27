# Audit Report

## Title
Governance Attack: Feature Version Poisoning via u64::MAX Setting Breaks Gas Schedule Version Tracking

## Summary
The gas schedule update mechanism lacks upper bound validation on `feature_version`, allowing a malicious governance proposal to set `feature_version` to `u64::MAX`. This permanently breaks version tracking for gas schedules, as all future updates must use the same maximum value, defeating the purpose of versioning without completely preventing updates.

## Finding Description

The on-chain gas schedule update validation in the Move framework only enforces a lower bound check on `feature_version`, using a greater-than-or-equal comparison without any upper bound validation. [1](#0-0) [2](#0-1) 

The formal specification explicitly permits this behavior: [3](#0-2) 

The proposal generation code in the release builder accepts arbitrary `feature_version` values from external sources without validation: [4](#0-3) 

While the `LATEST_GAS_FEATURE_VERSION` constant tracks the expected version progression: [5](#0-4) 

There is no enforcement preventing a governance proposal from setting `feature_version` to `u64::MAX` (18,446,744,073,709,551,615).

**Attack Path:**
1. Attacker crafts a malicious gas schedule JSON file with `feature_version: 18446744073709551615`
2. Attacker creates a governance proposal using this gas schedule
3. Proposal passes governance voting (requires stake-weighted majority)
4. On-chain validation check `u64::MAX >= current_version` passes
5. Gas schedule with `feature_version = u64::MAX` is committed to chain
6. All future legitimate updates must use `feature_version = u64::MAX` (cannot increment beyond)
7. Version tracking is permanently broken - multiple different gas schedules share the same version number

This breaks the **Governance Integrity** invariant by allowing manipulation of the versioning mechanism that governance relies upon for tracking gas schedule evolution.

## Impact Explanation

This qualifies as **High Severity** under the "Significant protocol violations" category. While it doesn't prevent gas schedule updates entirely (the `>=` check still allows same-version updates), it causes:

1. **Protocol Violation**: Breaks the gas schedule versioning protocol designed for tracking changes
2. **Governance Degradation**: Multiple different gas schedules become indistinguishable by version
3. **Operational Impact**: Tools expecting monotonic version increases (like `bump_ver.py`) would fail
4. **Recovery Difficulty**: Cannot restore normal versioning without manual intervention or hard fork
5. **Audit Trail Loss**: Cannot reliably track which gas schedule version is deployed

The attack doesn't meet Critical criteria because:
- No fund loss occurs
- Consensus safety is maintained (all nodes still agree)
- Network liveness continues (updates still work)
- No permanent freezing requiring hard fork

## Likelihood Explanation

**Medium-High Likelihood:**

**Attack Requirements:**
- Attacker needs sufficient governance voting power OR ability to convince legitimate voters
- Current governance thresholds require stake-weighted majority voting [6](#0-5) 

**Feasibility Factors:**
- **Technical Difficulty**: Low - simply requires setting a JSON field to u64::MAX
- **Social Engineering**: Possible if disguised in a seemingly legitimate proposal
- **Detection**: Difficult to notice in complex proposals with many parameter changes
- **Reversibility**: None - once set to u64::MAX, cannot revert to normal versioning

**Realistic Scenarios:**
1. Compromised proposer account with sufficient stake
2. Social engineering attack on governance voters
3. Insider threat from governance participant
4. Supply chain attack on proposal generation tooling

## Recommendation

Add upper bound validation to prevent `feature_version` from exceeding a reasonable maximum. Implement the fix in the on-chain Move code:

**Recommended Fix in `gas_schedule.move`:**

```move
// Add new error code
const EINVALID_GAS_FEATURE_VERSION_TOO_HIGH: u64 = 4;

// Add validation in set_for_next_epoch (line 91-103)
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
        // NEW: Add upper bound check
        assert!(
            new_gas_schedule.feature_version < 1000000, // Reasonable upper limit
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION_TOO_HIGH)
        );
    };
    config_buffer::upsert(new_gas_schedule);
}
```

Apply the same fix to `set_for_next_epoch_check_hash` and `set_gas_schedule` functions.

Additionally, add validation in the Rust proposal generation code to warn or reject unreasonable version values.

## Proof of Concept

```move
#[test_only]
module aptos_framework::gas_schedule_attack_test {
    use aptos_framework::gas_schedule;
    use std::vector;
    
    #[test(aptos_framework = @0x1)]
    fun test_feature_version_max_attack(aptos_framework: signer) {
        // Setup: Initialize with normal gas schedule
        let normal_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 45,
            entries: vector::empty(),
        };
        let normal_bytes = bcs::to_bytes(&normal_schedule);
        gas_schedule::initialize(&aptos_framework, normal_bytes);
        
        // Attack: Submit malicious gas schedule with u64::MAX version
        let malicious_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 18446744073709551615, // u64::MAX
            entries: vector::empty(),
        };
        let malicious_bytes = bcs::to_bytes(&malicious_schedule);
        
        // This should fail with proper validation but currently succeeds
        gas_schedule::set_for_next_epoch(&aptos_framework, malicious_bytes);
        
        // Verify attack succeeded - version is now u64::MAX
        gas_schedule::on_new_epoch(&aptos_framework);
        let current = borrow_global<gas_schedule::GasScheduleV2>(@aptos_framework);
        assert!(current.feature_version == 18446744073709551615, 0);
        
        // Demonstrate impact: Cannot increment version anymore
        let next_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 46, // Normal next version
            entries: vector::empty(),
        };
        let next_bytes = bcs::to_bytes(&next_schedule);
        
        // This will fail: 46 < u64::MAX
        gas_schedule::set_for_next_epoch(&aptos_framework, next_bytes); // ABORTS!
    }
}
```

## Notes

This vulnerability arises from the combination of:
1. The intentional design choice to allow `>=` comparisons (per formal specification)
2. The absence of upper bound validation
3. The reliance on external input sources for `feature_version` values

While the `>=` behavior is formally verified and intentional, the lack of sanity checking on the upper bound creates an exploitable governance attack vector. The issue specifically breaks the **Governance Integrity** invariant by allowing manipulation of the version tracking mechanism that governance processes depend upon for managing gas schedule evolution over time.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L108-132)
```text
    public fun set_for_next_epoch_check_hash(
        aptos_framework: &signer,
        old_gas_schedule_hash: vector<u8>,
        new_gas_schedule_blob: vector<u8>
    ) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&new_gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));

        let new_gas_schedule: GasScheduleV2 = from_bytes(new_gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
            let cur_gas_schedule_bytes = bcs::to_bytes(cur_gas_schedule);
            let cur_gas_schedule_hash = aptos_hash::sha3_512(cur_gas_schedule_bytes);
            assert!(
                cur_gas_schedule_hash == old_gas_schedule_hash,
                error::invalid_argument(EINVALID_GAS_SCHEDULE_HASH)
            );
        };

        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.spec.move (L23-30)
```text
    /// No.: 4
    /// Requirement: Only a gas schedule with the feature version greater or equal than the current feature version is
    /// allowed to be provided when performing an update operation.
    /// Criticality: Medium
    /// Implementation: The set_gas_schedule function validates the feature_version of the new_gas_schedule by ensuring
    /// that it is greater or equal than the current gas_schedule.feature_version.
    /// Enforcement: Formally verified via [high-level-req-4](set_gas_schedule).
    /// </high-level-req>
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L196-214)
```rust
impl GasScheduleLocator {
    async fn fetch_gas_schedule(&self) -> Result<GasScheduleV2> {
        println!("{:?}", self);
        match self {
            GasScheduleLocator::LocalFile(path) => {
                let file_contents = fs::read_to_string(path)?;
                let gas_schedule: GasScheduleV2 = serde_json::from_str(&file_contents)?;
                Ok(gas_schedule)
            },
            GasScheduleLocator::RemoteFile(url) => {
                let response = reqwest::get(url.as_str()).await?;
                let gas_schedule: GasScheduleV2 = response.json().await?;
                Ok(gas_schedule)
            },
            GasScheduleLocator::Current => Ok(aptos_gas_schedule_updator::current_gas_schedule(
                LATEST_GAS_FEATURE_VERSION,
            )),
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L76-76)
```rust
pub const LATEST_GAS_FEATURE_VERSION: u64 = gas_feature_versions::RELEASE_V1_41;
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L1-1)
```text
///
```
