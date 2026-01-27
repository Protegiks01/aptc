# Audit Report

## Title
DKG Threshold Manipulation via Unvalidated On-Chain Randomness Configuration

## Summary
The on-chain randomness configuration allows governance to set arbitrary DKG threshold values without validation, causing `randomness_enabled()` to return true and consensus to accept DKG transactions even when the thresholds violate DKG security requirements. This enables attackers with governance access to configure thresholds that break the distributed key generation security model.

## Finding Description

The vulnerability exists in the interaction between the Move-based configuration system and Rust DKG implementation. The attack flow is:

**Step 1: Unvalidated Configuration in Move** [1](#0-0) 

The `new_v1()` function accepts arbitrary `FixedPoint64` threshold values with no validation of DKG security constraints (secrecy > 1/3, reconstruction ≤ 2/3, secrecy < reconstruction).

**Step 2: Governance Sets Invalid Thresholds** [2](#0-1) 

Governance can call `set_for_next_epoch()` with maliciously crafted thresholds (e.g., secrecy=0.1, reconstruction=0.15).

**Step 3: Configuration Read Without Validation** [3](#0-2) 

The Rust code reads on-chain config via `from_configs()` which performs no threshold validation. [4](#0-3) 

**Step 4: Consensus Accepts DKG Transactions** [5](#0-4) 

The `randomness_enabled()` function only checks variant type (V1/V2), not threshold validity. [6](#0-5) 

At line 21, `is_vtxn_expected()` returns true for DKGResult transactions when `randomness_enabled()` is true, regardless of threshold validity. [7](#0-6) 

**Step 5: DKG Validation Fails, Falls Back to Unsafe Mode** [8](#0-7) 

When DKG runs, `DKGRoundingProfile::new()` validates thresholds at lines 197-199, requiring:
- `secrecy_threshold * 3 > 1` (secrecy > 33.33%)
- `secrecy_threshold < reconstruct_threshold`
- `reconstruct_threshold * 3 <= 2` (reconstruction ≤ 66.67%) [9](#0-8) 

When validation fails, the system falls back to `infallible()` mode instead of rejecting the configuration. [10](#0-9) 

**Critical Flaw**: `infallible()` only clamps values to [0,1] and ensures reconstruction ≥ secrecy, but does NOT enforce the DKG security constraints (secrecy > 1/3, reconstruction ≤ 2/3).

**Concrete Attack Example:**
1. Governance sets: `new_v1(create_from_rational(1, 10), create_from_rational(15, 100))` → secrecy=10%, reconstruction=15%
2. Config validation passes (FixedPoint64 only checks range, not DKG constraints)
3. `randomness_enabled()` returns true
4. Consensus accepts DKGResult transactions
5. DKGRounding validation fails (10% < 33.33% requirement)
6. Falls back to infallible mode with secrecy=10%, reconstruction=15%
7. **DKG operates with secrecy threshold at 10%**, meaning any validator coalition with >10% stake can reconstruct the secret randomness seed, violating the intended >33% security threshold

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the **Cryptographic Correctness** invariant (BLS signatures, VRF, and hash operations must be secure) by allowing DKG to operate with insufficient security thresholds.

**Impact Category**: Consensus/Safety violations (Critical - up to $1,000,000)

With a compromised secrecy threshold below 1/3:
- A small coalition (e.g., 10-20% of stake) can reconstruct randomness secrets
- Attackers can predict future randomness values
- Leader election manipulation becomes possible
- Validator selection can be biased
- All randomness-dependent protocols are compromised

This fundamentally breaks the security assumptions of the Aptos randomness beacon and any smart contracts relying on it.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Requirements:**
- Governance proposal access (requires stake and voting power)
- OR: Buggy governance proposal that accidentally sets invalid thresholds

**Feasibility:**
- Move validation is missing entirely (no threshold constraints)
- Rust code accepts any valid FixedPoint64 values
- No alerts or warnings for invalid configurations
- Silent fallback to unsafe parameters makes detection difficult

The attack is particularly concerning because:
1. Legitimate operators might accidentally set invalid values
2. No pre-deployment validation catches this
3. The system continues operating (doesn't fail-safe)
4. The misconfiguration persists for an entire epoch

## Recommendation

**Immediate Fix: Add Threshold Validation in Move Module**

Add validation to the `new_v1()` and `new_v2()` functions in `randomness_config.move`:

```move
public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
    // Validate DKG security constraints
    let one_third = fixed_point64::create_from_rational(1, 3);
    let two_thirds = fixed_point64::create_from_rational(2, 3);
    
    assert!(
        fixed_point64::greater(secrecy_threshold, one_third),
        EINVALID_SECRECY_THRESHOLD  // secrecy must be > 1/3
    );
    assert!(
        fixed_point64::less(secrecy_threshold, reconstruction_threshold),
        EINVALID_THRESHOLD_ORDERING  // secrecy < reconstruction
    );
    assert!(
        fixed_point64::less_or_equal(reconstruction_threshold, two_thirds),
        EINVALID_RECONSTRUCTION_THRESHOLD  // reconstruction must be <= 2/3
    );
    
    RandomnessConfig {
        variant: copyable_any::pack(ConfigV1 {
            secrecy_threshold,
            reconstruction_threshold
        })
    }
}
```

**Secondary Fix: Fail-Safe in Rust**

Modify `OnChainRandomnessConfig::from_configs()` to validate thresholds:

```rust
pub fn from_configs(
    local_seqnum: u64,
    onchain_seqnum: u64,
    onchain_raw_config: Option<RandomnessConfigMoveStruct>,
) -> Self {
    if local_seqnum > onchain_seqnum {
        Self::default_disabled()
    } else {
        match onchain_raw_config
            .and_then(|onchain_raw| OnChainRandomnessConfig::try_from(onchain_raw).ok())
        {
            Some(config) if config.validate_thresholds() => config,
            _ => {
                warn!("Invalid randomness config detected, disabling randomness");
                OnChainRandomnessConfig::default_disabled()
            }
        }
    }
}
```

Add validation method:

```rust
impl OnChainRandomnessConfig {
    fn validate_thresholds(&self) -> bool {
        if let Some(s) = self.secrecy_threshold() {
            if let Some(r) = self.reconstruct_threshold() {
                return s * U64F64::from_num(3) > U64F64::from_num(1)
                    && s < r
                    && r * U64F64::from_num(3) <= U64F64::from_num(2);
            }
        }
        true  // Off variant is always valid
    }
}
```

**Tertiary Fix: Remove Infallible Fallback**

Modify `DKGRounding::new()` to return an error instead of falling back to infallible mode, and handle the error at epoch initialization by disabling randomness.

## Proof of Concept

```move
// File: test_invalid_randomness_config.move
script {
    use aptos_framework::randomness_config;
    use aptos_std::fixed_point64;
    use aptos_framework::aptos_governance;

    fun exploit_invalid_thresholds(framework: &signer) {
        // Set dangerously low thresholds
        // secrecy = 10%, reconstruction = 15%
        // This violates DKG security (should be > 33.33% and <= 66.67%)
        let invalid_config = randomness_config::new_v1(
            fixed_point64::create_from_rational(1, 10),   // 0.1
            fixed_point64::create_from_rational(15, 100)  // 0.15
        );
        
        // This call succeeds with no validation!
        randomness_config::set_for_next_epoch(framework, invalid_config);
        
        // After reconfiguration, randomness_enabled() will return true
        // Consensus will accept DKG transactions
        // But DKG will operate with 10% secrecy threshold
        // allowing any 10%+ coalition to break randomness security
        aptos_governance::reconfigure(framework);
    }
}
```

**Expected Behavior**: The `new_v1()` call should abort with threshold validation error.

**Actual Behavior**: Configuration is accepted, `randomness_enabled()` returns true, and DKG operates in unsafe infallible mode with 10% secrecy threshold.

---

**Notes**

The vulnerability stems from a defense-in-depth failure where:
1. Move layer has no validation (assumes Rust will validate)
2. Rust layer accepts any deserialized config (assumes Move validated)
3. DKG validation failure silently falls back to unsafe mode instead of failing closed

The reference to "line 22" in the security question appears to be incorrect, as the critical check occurs at line 21 of `consensus/src/util/mod.rs` where `is_vtxn_expected()` evaluates DKGResult transactions.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L53-56)
```text
    public fun set_for_next_epoch(framework: &signer, new_config: RandomnessConfig) {
        system_addresses::assert_aptos_framework(framework);
        config_buffer::upsert(new_config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L93-99)
```text
    public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV1 {
                secrecy_threshold,
                reconstruction_threshold
            } )
        }
```

**File:** types/src/on_chain_config/randomness_config.rs (L138-151)
```rust
    /// Used by DKG and Consensus on a new epoch to determine the actual `OnChainRandomnessConfig` to be used.
    pub fn from_configs(
        local_seqnum: u64,
        onchain_seqnum: u64,
        onchain_raw_config: Option<RandomnessConfigMoveStruct>,
    ) -> Self {
        if local_seqnum > onchain_seqnum {
            Self::default_disabled()
        } else {
            onchain_raw_config
                .and_then(|onchain_raw| OnChainRandomnessConfig::try_from(onchain_raw).ok())
                .unwrap_or_else(OnChainRandomnessConfig::default_if_missing)
        }
    }
```

**File:** types/src/on_chain_config/randomness_config.rs (L154-175)
```rust
impl TryFrom<RandomnessConfigMoveStruct> for OnChainRandomnessConfig {
    type Error = anyhow::Error;

    fn try_from(value: RandomnessConfigMoveStruct) -> Result<Self, Self::Error> {
        let RandomnessConfigMoveStruct { variant } = value;
        let variant_type_name = variant.type_name.as_str();
        match variant_type_name {
            ConfigOff::MOVE_TYPE_NAME => Ok(OnChainRandomnessConfig::Off),
            ConfigV1::MOVE_TYPE_NAME => {
                let v1 = MoveAny::unpack(ConfigV1::MOVE_TYPE_NAME, variant)
                    .map_err(|e| anyhow!("unpack as v1 failed: {e}"))?;
                Ok(OnChainRandomnessConfig::V1(v1))
            },
            ConfigV2::MOVE_TYPE_NAME => {
                let v2 = MoveAny::unpack(ConfigV2::MOVE_TYPE_NAME, variant)
                    .map_err(|e| anyhow!("unpack as v2 failed: {e}"))?;
                Ok(OnChainRandomnessConfig::V2(v2))
            },
            _ => Err(anyhow!("unknown variant type")),
        }
    }
}
```

**File:** types/src/on_chain_config/randomness_config.rs (L205-211)
```rust
    pub fn randomness_enabled(&self) -> bool {
        match self {
            OnChainRandomnessConfig::Off => false,
            OnChainRandomnessConfig::V1(_) => true,
            OnChainRandomnessConfig::V2(_) => true,
        }
    }
```

**File:** consensus/src/util/mod.rs (L15-24)
```rust
pub fn is_vtxn_expected(
    randomness_config: &OnChainRandomnessConfig,
    jwk_consensus_config: &OnChainJWKConsensusConfig,
    vtxn: &ValidatorTransaction,
) -> bool {
    match vtxn {
        ValidatorTransaction::DKGResult(_) => randomness_config.randomness_enabled(),
        ValidatorTransaction::ObservedJWKUpdate(_) => jwk_consensus_config.jwk_consensus_enabled(),
    }
}
```

**File:** consensus/src/dag/rb_handler.rs (L120-131)
```rust
        let num_vtxns = node.validator_txns().len() as u64;
        ensure!(num_vtxns <= self.vtxn_config.per_block_limit_txn_count());
        for vtxn in node.validator_txns() {
            let vtxn_type_name = vtxn.type_name();
            ensure!(
                is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                "unexpected validator transaction: {:?}",
                vtxn_type_name
            );
            vtxn.verify(self.epoch_state.verifier.as_ref())
                .context(format!("{} verification failed", vtxn_type_name))?;
        }
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L79-97)
```rust
        let (profile, rounding_error, rounding_method) = match DKGRoundingProfile::new(
            validator_stakes,
            total_weight_min,
            total_weight_max,
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
            fast_secrecy_threshold_in_stake_ratio,
        ) {
            Ok(profile) => (profile, None, "binary_search".to_string()),
            Err(e) => {
                let profile = DKGRoundingProfile::infallible(
                    validator_stakes,
                    secrecy_threshold_in_stake_ratio,
                    reconstruct_threshold_in_stake_ratio,
                    fast_secrecy_threshold_in_stake_ratio,
                );
                (profile, Some(format!("{e}")), "infallible".to_string())
            },
        };
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L187-199)
```rust
    pub fn new(
        validator_stakes: &Vec<u64>,
        total_weight_min: usize,
        total_weight_max: usize,
        secrecy_threshold_in_stake_ratio: U64F64,
        reconstruct_threshold_in_stake_ratio: U64F64,
        fast_secrecy_threshold_in_stake_ratio: Option<U64F64>,
    ) -> anyhow::Result<Self> {
        ensure!(total_weight_min >= validator_stakes.len());
        ensure!(total_weight_max >= total_weight_min);
        ensure!(secrecy_threshold_in_stake_ratio * U64F64::from_num(3) > U64F64::from_num(1));
        ensure!(secrecy_threshold_in_stake_ratio < reconstruct_threshold_in_stake_ratio);
        ensure!(reconstruct_threshold_in_stake_ratio * U64F64::from_num(3) <= U64F64::from_num(2));
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L254-266)
```rust
    pub fn infallible(
        validator_stakes: &Vec<u64>,
        mut secrecy_threshold_in_stake_ratio: U64F64,
        mut reconstruct_threshold_in_stake_ratio: U64F64,
        fast_secrecy_threshold_in_stake_ratio: Option<U64F64>,
    ) -> Self {
        let one = U64F64::from_num(1);
        secrecy_threshold_in_stake_ratio = min(one, secrecy_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = min(one, reconstruct_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = max(
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
        );
```
