# Audit Report

## Title
Consensus-Breaking Version Skew in RandomnessConfig During Rolling Upgrades

## Summary
During rolling upgrades where the on-chain `RandomnessConfig` is upgraded to V2, validators running old code (compiled without ConfigV2 support) will silently fall back to treating randomness as disabled, while validators running new code will treat it as enabled. This configuration divergence causes validators to reject each other's blocks, leading to a permanent network partition requiring coordinated intervention to resolve.

## Finding Description

The vulnerability exists in the `OnChainRandomnessConfig::from_configs()` function, which determines the effective randomness configuration for each epoch. [1](#0-0) 

The deserialization logic uses pattern matching on variant type names to parse the on-chain configuration into one of three variants: `Off`, `V1`, or `V2`. [2](#0-1) 

**The Critical Flaw**: During rolling upgrades:

1. **On-chain state** contains `ConfigV2` with type name `"0x1::randomness_config::ConfigV2"` [3](#0-2) 

2. **Old validators** running binaries compiled before V2 was added have a match statement that only handles `ConfigOff` and `ConfigV1`. When they encounter V2, it hits the wildcard `_` case returning `Err(anyhow!("unknown variant type"))` [4](#0-3) 

3. In `from_configs()`, this error is silently converted to `None` via `.ok()`, then `unwrap_or_else()` applies the fallback [5](#0-4) 

4. The fallback `default_if_missing()` returns `OnChainRandomnessConfig::Off` [6](#0-5) 

This creates **configuration divergence**:
- **New validators**: `randomness_enabled() = true` (ConfigV2 parsed successfully) [7](#0-6) 
- **Old validators**: `randomness_enabled() = false` (fallback to Off)

The divergence breaks consensus during block proposal validation. When a validator receives a block proposal containing validator transactions, it validates each transaction type using `is_vtxn_expected()` [8](#0-7) 

The `is_vtxn_expected()` function checks whether `DKGResult` transactions are allowed based on `randomness_enabled()` [9](#0-8) 

**Consensus Failure Mechanism**:
1. New validators create proposals with `ValidatorTransaction::DKGResult` (randomness enabled)
2. Old validators receive these proposals and execute validation at line 1130
3. For old validators, `is_vtxn_expected()` returns `false` causing the `ensure!` to fail
4. Old validators reject the block with error: `"unexpected validator txn: DKGResult"`
5. If old validators represent >1/3 of voting power, consensus cannot progress when new validators are leaders

This breaks **Consensus Safety** (validators must agree on valid blocks given identical on-chain state) and **Deterministic Execution** (same on-chain state produces different validator behavior due to binary version differences).

Both consensus and DKG subsystems use `from_configs()` during epoch transitions, amplifying the impact. [10](#0-9) 

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for maximum severity under multiple Aptos bug bounty categories:

1. **Consensus/Safety Violations**: Validators reading identical on-chain state disagree on block validity, violating the fundamental AptosBFT safety property that < 1/3 Byzantine validators should maintain consensus.

2. **Non-recoverable Network Partition**: Once triggered, the network enters a permanent split state where validators cannot achieve consensus on blocks containing randomness transactions. The partition persists until ALL validators upgrade their binaries or on-chain configuration is rolled back, likely requiring a coordinated hardfork.

3. **Total Loss of Liveness/Network Availability**: If >1/3 of validators are running old code, the network cannot make progress when new validators are elected as leaders, resulting in complete loss of liveness for the blockchain.

The vulnerability affects core consensus infrastructure and is triggered automatically by normal operational procedures, not adversarial action.

## Likelihood Explanation

**VERY HIGH** - This vulnerability will **automatically trigger** during any on-chain governance upgrade to RandomnessConfig V2 if validators have not all synchronized their binary upgrades beforehand.

The likelihood is near-certain because:

1. **Rolling upgrades are standard practice**: Aptos explicitly tests and supports validators running different binary versions during upgrade windows. [11](#0-10) 

2. **On-chain governance operates independently**: Governance proposals can upgrade on-chain configurations without requiring coordinated validator binary upgrades.

3. **Silent failure mode**: The error is converted to a default value with no logging. The only warning occurs when *reading* the config fails, not when *parsing* fails. [12](#0-11) 

4. **No validation prevents this scenario**: There is no version checking or coordination mechanism between binary versions and on-chain config schema versions.

5. **Requires no attacker action**: This is triggered by legitimate upgrade procedures.

The vulnerability is amplified by being an invisible failure—validators don't detect that configuration parsing failed; they silently use the default `Off` configuration, appearing to function normally until consensus breaks.

## Recommendation

Implement explicit version coordination between binary releases and on-chain configuration schema upgrades:

1. **Add error logging**: Log when variant parsing fails (not just reading failures), making the issue visible to operators.

2. **Version gating**: Add on-chain version checks that prevent ConfigV2 from being activated until the minimum binary version supports it (similar to how feature flags work with `AptosVersion`).

3. **Graceful degradation warning**: If parsing fails, emit a critical warning and potentially halt the validator rather than silently falling back to a different configuration.

4. **Upgrade coordination**: Document that RandomnessConfig schema upgrades require coordinated binary upgrades across all validators before on-chain activation.

Example fix for adding error logging:

```rust
let onchain_randomness_config = match onchain_raw_config {
    Some(raw) => match OnChainRandomnessConfig::try_from(raw) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to parse RandomnessConfig variant: {}. Falling back to Off.", e);
            OnChainRandomnessConfig::default_if_missing()
        }
    },
    None => OnChainRandomnessConfig::default_if_missing(),
};
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a validator network with version N (without ConfigV2 support compiled in)
2. Upgrading some validators to version N+1 (with ConfigV2 support)
3. Submitting a governance proposal to upgrade on-chain RandomnessConfig to V2
4. Observing that:
   - Version N validators silently parse the config as `Off`
   - Version N+1 validators parse it as `V2` (enabled)
   - When version N+1 validators propose blocks with DKGResult, version N validators reject them
   - Consensus fails if version N validators represent >1/3 voting power

The compatibility test framework already demonstrates that version skew scenarios are expected and tested in Aptos, confirming this is a realistic operational scenario.

### Citations

**File:** types/src/on_chain_config/randomness_config.rs (L68-70)
```rust
impl AsMoveAny for ConfigV2 {
    const MOVE_TYPE_NAME: &'static str = "0x1::randomness_config::ConfigV2";
}
```

**File:** types/src/on_chain_config/randomness_config.rs (L139-151)
```rust
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

**File:** types/src/on_chain_config/randomness_config.rs (L154-174)
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
```

**File:** types/src/on_chain_config/randomness_config.rs (L197-199)
```rust
    pub fn default_if_missing() -> Self {
        OnChainRandomnessConfig::Off
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

**File:** consensus/src/round_manager.rs (L1126-1136)
```rust
        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
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

**File:** consensus/src/epoch_manager.rs (L1195-1196)
```rust
        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
```

**File:** consensus/src/epoch_manager.rs (L1217-1221)
```rust
        let onchain_randomness_config = OnChainRandomnessConfig::from_configs(
            self.randomness_override_seq_num,
            onchain_randomness_config_seq_num.seq_num,
            randomness_config_move_struct.ok(),
        );
```

**File:** testsuite/testcases/src/compatibility_test.rs (L12-100)
```rust
pub struct SimpleValidatorUpgrade;

impl SimpleValidatorUpgrade {
    pub const EPOCH_DURATION_SECS: u64 = 30;
}

impl Test for SimpleValidatorUpgrade {
    fn name(&self) -> &'static str {
        "compatibility::simple-validator-upgrade"
    }
}

#[async_trait]
impl NetworkTest for SimpleValidatorUpgrade {
    async fn run<'a>(&self, ctxa: NetworkContextSynchronizer<'a>) -> Result<()> {
        let upgrade_wait_for_healthy = true;
        let upgrade_node_delay = Duration::from_secs(20);
        let upgrade_max_wait = Duration::from_secs(40);

        let epoch_duration = Duration::from_secs(Self::EPOCH_DURATION_SECS);

        // Get the different versions we're testing with
        let (old_version, new_version) = {
            let mut versions = ctxa
                .ctx
                .lock()
                .await
                .swarm
                .read()
                .await
                .versions()
                .collect::<Vec<_>>();
            versions.sort();
            if versions.len() != 2 {
                bail!("exactly two different versions needed to run compat test");
            }

            (versions[0].clone(), versions[1].clone())
        };

        let msg = format!(
            "Compatibility test results for {} ==> {} (PR)",
            old_version, new_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;

        // Split the swarm into 2 parts
        if ctxa
            .ctx
            .lock()
            .await
            .swarm
            .read()
            .await
            .validators()
            .count()
            < 4
        {
            bail!("compat test requires >= 4 validators");
        }
        let all_validators = ctxa
            .ctx
            .lock()
            .await
            .swarm
            .read()
            .await
            .validators()
            .map(|v| v.peer_id())
            .collect::<Vec<_>>();
        let mut first_batch = all_validators.clone();
        let second_batch = first_batch.split_off(first_batch.len() / 2);
        let first_node = first_batch.pop().unwrap();
        let duration = Duration::from_secs(30);

        let msg = format!(
            "1. Check liveness of validators at old version: {}",
            old_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;

        // Generate some traffic
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();
            let txn_stat_prior = generate_traffic(ctx, &all_validators, duration).await?;
            ctx.report
```
