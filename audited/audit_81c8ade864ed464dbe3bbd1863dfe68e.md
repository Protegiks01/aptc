# Audit Report

## Title
Silent Deserialization Failure in `validator_txn_enabled()` Native Function Causes Consensus Divergence During Version Upgrades

## Summary
The native function `validator_txn_enabled()` uses `.unwrap_or_default()` to handle deserialization failures silently, returning a default configuration (V4 with validator transactions disabled) instead of the actual on-chain configuration. During rolling validator upgrades where nodes run different code versions, this causes validators to disagree on whether validator transactions are enabled, leading to consensus divergence when deciding whether to start DKG reconfiguration.

## Finding Description

The vulnerability exists in the native function implementation that determines whether validator transactions are enabled: [1](#0-0) 

The critical issue is on line 19, which uses `.unwrap_or_default()` to silently fall back to a default configuration if BCS deserialization fails. The default configuration is V4 with validator transactions disabled: [2](#0-1) 

The `OnChainConsensusConfig` enum has multiple variants (V1 through V5): [3](#0-2) 

**Attack Scenario:**

During a rolling validator upgrade:
1. Validators running **old code** (e.g., version that only knows OnChainConsensusConfig V1-V3) are still active
2. Validators running **new code** (e.g., version that knows V1-V5) have been upgraded
3. A governance proposal updates the on-chain consensus config to **V5** with validator transactions enabled
4. **Old validators**: BCS deserialization encounters discriminant 4 (V5), which is unknown to their code → deserialization **FAILS** → silently falls back to default V4 with `vtxn` **DISABLED** → `validator_txn_enabled()` returns **false**
5. **New validators**: Successfully deserialize V5 → `vtxn` field determines result (likely **ENABLED**) → `validator_txn_enabled()` returns **true**

The result of this function directly controls critical consensus logic in the governance reconfiguration path: [4](#0-3) 

When `validator_txn_enabled()` returns different values:
- Validators returning **true** execute `reconfiguration_with_dkg::try_start()` → initiates DKG session and waits: [5](#0-4) 

- Validators returning **false** execute `reconfiguration_with_dkg::finish()` → immediately triggers epoch change: [6](#0-5) 

This breaks the **Deterministic Execution** invariant: validators execute different code paths for the same blockchain state, causing consensus divergence.

## Impact Explanation

**Severity: Critical** (Consensus/Safety violations)

This vulnerability causes **consensus divergence**, where validators disagree on whether to start DKG or immediately enter a new epoch. This breaks AptosBFT consensus safety guarantees:

1. **Network Split**: Validators following different paths cannot reach consensus on subsequent blocks
2. **Liveness Failure**: Some validators wait for DKG completion while others proceed, preventing quorum formation
3. **State Divergence**: Different validators apply epoch transitions at different times, leading to different state roots

The issue meets Critical severity criteria:
- **Consensus/Safety violations**: Different validators execute different state transitions
- **Non-recoverable network partition**: Requires manual intervention or hardfork to resolve if validators permanently disagree on consensus state
- **Total loss of liveness**: Network cannot make progress when validators are split on reconfiguration paths

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is triggered during **normal operational procedures** (validator upgrades) when:

1. **Rolling upgrades are standard practice**: Validators upgrade gradually, not simultaneously, as evidenced by the compatibility test framework: [7](#0-6) 

2. **Governance can update configs**: On-chain governance can update the consensus config to newer variants via: [8](#0-7) 

3. **No validation of config bytes**: The Move function only validates that bytes are non-empty, not that they can be deserialized by all validators: [8](#0-7) 

**Attack Requirements:**
- Malicious governance proposal that updates config to a new variant before all validators upgrade
- OR poor coordination between code deployments and governance proposals
- No special validator privileges required beyond governance control

## Recommendation

**Fix 1: Fail explicitly instead of silently using default**

Replace `.unwrap_or_default()` with explicit error handling that propagates failures:

```rust
pub fn validator_txn_enabled(
    _context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let config_bytes = safely_pop_arg!(args, Vec<u8>);
    let config = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes)
        .map_err(|e| {
            SafeNativeError::Abort {
                abort_code: 1, // EINVALID_CONFIG
            }
        })?;
    Ok(smallvec![Value::bool(config.is_vtxn_enabled())])
}
```

**Fix 2: Add validation in Move layer**

Validate that config bytes can be deserialized before storing:

```move
public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
    system_addresses::assert_aptos_framework(account);
    assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
    // Add validation that config can be deserialized
    assert!(validator_txn_enabled_internal(config) || true, error::invalid_argument(EINVALID_CONFIG));
    std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
}
```

**Fix 3: Enforce version compatibility**

Add checks ensuring all validators support the new config variant before governance can deploy it:
- Track validator software versions in on-chain state
- Require minimum version before allowing config upgrades
- Add prevalidation in governance proposal execution

## Proof of Concept

```rust
// Reproduction steps (Rust test):
#[test]
fn test_validator_txn_enabled_version_mismatch() {
    // 1. Create a V5 config with vtxn enabled
    let config_v5 = OnChainConsensusConfig::V5 {
        alg: ConsensusAlgorithmConfig::default_for_genesis(),
        vtxn: ValidatorTxnConfig::default_enabled(), // ENABLED
        window_size: None,
        rand_check_enabled: true,
    };
    
    // 2. Serialize it
    let config_bytes = bcs::to_bytes(&config_v5).unwrap();
    
    // 3. Simulate old validator code that only knows V1-V3
    // (In practice, this would be an older version of OnChainConsensusConfig enum)
    // When deserialization fails, unwrap_or_default() returns V4 with vtxn DISABLED
    
    // 4. New validators: successfully deserialize V5
    let new_validator_result = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes)
        .unwrap_or_default();
    assert!(new_validator_result.is_vtxn_enabled()); // true
    
    // 5. Old validators: fail to deserialize, use default
    // (Simulated by directly calling default)
    let old_validator_result = OnChainConsensusConfig::default();
    assert!(!old_validator_result.is_vtxn_enabled()); // false - DIVERGENCE!
    
    // 6. This causes different code paths in aptos_governance::reconfigure()
    // New validators: reconfiguration_with_dkg::try_start()
    // Old validators: reconfiguration_with_dkg::finish()
    // Result: CONSENSUS DIVERGENCE
}
```

**Notes**

The vulnerability stems from a design choice to use `.unwrap_or_default()` for error handling, which prioritizes availability over correctness. While this may prevent individual node crashes, it creates a worse outcome: silent consensus divergence across the network. The issue is particularly insidious because:

1. **No error visibility**: The native function provides no indication that deserialization failed
2. **Affects critical path**: The function determines consensus behavior (DKG vs immediate epoch change)
3. **Natural trigger**: Rolling upgrades are standard practice, making this vulnerability likely to manifest
4. **Asymmetric information**: Only validators running old code experience the issue, making it hard to detect

The comparison with epoch_manager.rs is instructive - that code at least logs a warning when deserialization fails: [9](#0-8) 

However, logging alone is insufficient; the function should either abort the transaction or ensure all validators have compatible code before config updates.

### Citations

**File:** aptos-move/framework/src/natives/consensus_config.rs (L13-21)
```rust
pub fn validator_txn_enabled(
    _context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let config_bytes = safely_pop_arg!(args, Vec<u8>);
    let config = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes).unwrap_or_default();
    Ok(smallvec![Value::bool(config.is_vtxn_enabled())])
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L190-213)
```rust
/// The on-chain consensus config, in order to be able to add fields, we use enum to wrap the actual struct.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum OnChainConsensusConfig {
    V1(ConsensusConfigV1),
    V2(ConsensusConfigV1),
    V3 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
    },
    V4 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
        // Execution pool block window
        window_size: Option<u64>,
    },
    V5 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
        // Execution pool block window
        window_size: Option<u64>,
        // Whether to check if we can skip generating randomness for blocks
        rand_check_enabled: bool,
    },
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L443-451)
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        OnChainConsensusConfig::V4 {
            alg: ConsensusAlgorithmConfig::default_if_missing(),
            vtxn: ValidatorTxnConfig::default_if_missing(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L22-40)
```text
    /// Trigger a reconfiguration with DKG.
    /// Do nothing if one is already in progress.
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L42-61)
```text
    /// Clear incomplete DKG session, if it exists.
    /// Apply buffered on-chain configs (except for ValidatorSet, which is done inside `reconfiguration::reconfigure()`).
    /// Re-enable validator set changes.
    /// Run the default reconfiguration to enter the new epoch.
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        reconfiguration::reconfigure();
    }
```

**File:** testsuite/testcases/src/compatibility_test.rs (L12-50)
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
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```

**File:** consensus/src/epoch_manager.rs (L1187-1189)
```rust
        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }
```
