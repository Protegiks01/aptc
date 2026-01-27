# Audit Report

## Title
Consensus Split During Epoch Transitions Due to Divergent Randomness Configuration Override States

## Summary
During epoch transitions, validators with inconsistent `randomness_override_seq_num` node configurations will derive different `OnChainRandomnessConfig` states, causing some validators to accept `DKGResult` validator transactions while others reject them, resulting in consensus failure and chain halt.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Configuration Loading** - Each validator independently loads `randomness_override_seq_num` from its node configuration file. [1](#0-0) 

2. **Config Resolution** - During epoch transitions, `OnChainRandomnessConfig::from_configs()` is called to determine the effective randomness configuration. When `local_seqnum > onchain_seqnum`, it returns `Off` (disabled), otherwise it parses the on-chain config. [2](#0-1) 

3. **Validator Transaction Validation** - When processing proposals, `is_vtxn_expected()` checks if randomness is enabled to determine if `DKGResult` transactions should be accepted. [3](#0-2) 

**Attack Scenario:**

During a randomness stall recovery operation or due to misconfiguration:
- Validator A has `randomness_override_seq_num = 0` (default)
- Validator B has `randomness_override_seq_num = 101` (set for recovery)
- On-chain `RandomnessConfigSeqNum = 100` with randomness enabled

When the epoch starts: [4](#0-3) 

- Validator A: `from_configs(0, 100, config)` → Returns enabled `V1/V2` config
- Validator B: `from_configs(101, 100, config)` → Returns `Off` config

This divergent state is stored in `RoundManager`: [5](#0-4) 

When a proposal containing `DKGResult` is received: [6](#0-5) 

- Validator A: `is_vtxn_expected(&V1/V2, ..., DKGResult)` returns `true` → Accepts proposal
- Validator B: `is_vtxn_expected(&Off, ..., DKGResult)` returns `false` → Rejects proposal with error "unexpected validator txn: DKGResult"

This breaks the fundamental invariant: **"All validators must produce identical state roots for identical blocks"**. Validators cannot reach 2/3+ consensus on the proposal, causing chain halt.

## Impact Explanation

**Critical Severity** per Aptos bug bounty criteria:
- **Consensus/Safety violations**: Validators disagree on proposal validity, breaking AptosBFT safety guarantees
- **Non-recoverable network partition**: If sufficient validators (>1/3) have divergent configs, consensus cannot be reached, requiring hard fork recovery
- **Total loss of liveness**: Chain halts completely as no proposals can achieve quorum

This violates Critical Invariant #1 (Deterministic Execution) and #2 (Consensus Safety).

## Likelihood Explanation

**Medium-to-High Likelihood:**

1. **Recovery Operations**: The documented recovery procedure for randomness stalls explicitly uses `randomness_override_seq_num`: [7](#0-6) 

During rolling updates where validators restart sequentially, there's a window where some have the override and others don't.

2. **Operator Error**: Validators are operated by different entities who may apply configuration changes at different times or make mistakes.

3. **No Code-Level Protection**: There's no validation to ensure all validators have consistent override values before processing DKG transactions.

## Recommendation

Implement a **consensus-level validation** to detect configuration divergence before accepting validator transactions:

```rust
// In RoundManager or EpochManager
fn validate_vtxn_config_consistency(
    &self,
    vtxn: &ValidatorTransaction,
    epoch_state: &EpochState,
) -> anyhow::Result<()> {
    // If this validator would reject a DKGResult, but we receive one
    // that's signed by sufficient validators, log a warning about
    // potential configuration divergence
    if matches!(vtxn, ValidatorTransaction::DKGResult(_)) {
        if !self.randomness_config.randomness_enabled() {
            warn!(
                "Received DKGResult with randomness disabled locally. \
                 This may indicate configuration divergence. \
                 randomness_override_seq_num may need adjustment."
            );
        }
    }
    Ok(())
}
```

**Better solution**: Add on-chain validation during epoch transition to reject DKG transactions if randomness is disabled, preventing proposals from being created in the first place:

```rust
// In ProposalGenerator or similar
fn should_include_dkg_result(&self) -> bool {
    self.randomness_config.randomness_enabled()
}
```

Alternatively, make `randomness_override_seq_num` a network-wide parameter coordinated through governance rather than a per-node configuration.

## Proof of Concept

The existing smoke test demonstrates correct usage but can be modified to trigger the bug:

```rust
#[tokio::test]
async fn test_divergent_randomness_config() {
    let (mut swarm, _cli, _faucet) = SwarmBuilder::new_local(4)
        .with_aptos()
        .with_init_genesis_config(Arc::new(|conf| {
            conf.randomness_config_override = Some(OnChainRandomnessConfig::default_enabled());
        }))
        .build_with_cli(0)
        .await;

    // Wait for epoch 2
    swarm.wait_for_all_nodes_to_catchup_to_epoch(2, Duration::from_secs(60)).await.unwrap();

    // Only update SOME validators with override (not all)
    for (idx, validator) in swarm.validators_mut().take(2).enumerate() {
        validator.stop();
        let config_path = validator.config_path();
        let mut config = OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        config.override_config_mut().randomness_override_seq_num = 1;
        config.save_config(config_path).unwrap();
        validator.start().unwrap();
    }
    // validators 2 and 3 still have randomness_override_seq_num = 0

    // Force epoch change
    // ...governance transaction to trigger epoch change...

    // Expected: Consensus fails because validators disagree on DKGResult validity
    let liveness_result = swarm
        .liveness_check(Instant::now().add(Duration::from_secs(30)))
        .await;
    
    // Chain should halt due to consensus split
    assert!(liveness_result.is_err(), "Chain should halt due to config divergence");
}
```

**Notes**

This vulnerability stems from a distributed systems design flaw where per-node configuration (`randomness_override_seq_num`) affects consensus-critical decisions without cross-validator validation. While intended as a recovery mechanism, it creates a consensus split risk when validators have divergent configurations during epoch transitions. The issue is most likely to manifest during operational procedures like stall recovery or when operators apply configuration changes non-atomically across the validator set.

### Citations

**File:** config/src/config/node_config.rs (L78-81)
```rust
    /// In a randomness stall, set this to be on-chain `RandomnessConfigSeqNum` + 1.
    /// Once enough nodes restarted with the new value, the chain should unblock with randomness disabled.
    #[serde(default)]
    pub randomness_override_seq_num: u64,
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

**File:** consensus/src/epoch_manager.rs (L1217-1221)
```rust
        let onchain_randomness_config = OnChainRandomnessConfig::from_configs(
            self.randomness_override_seq_num,
            onchain_randomness_config_seq_num.seq_num,
            randomness_config_move_struct.ok(),
        );
```

**File:** consensus/src/round_manager.rs (L317-317)
```rust
    randomness_config: OnChainRandomnessConfig,
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

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L64-84)
```rust
    info!("Hot-fixing all validators.");
    for (idx, validator) in swarm.validators_mut().enumerate() {
        info!("Stopping validator {}.", idx);
        validator.stop();
        let config_path = validator.config_path();
        let mut validator_override_config =
            OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        validator_override_config
            .override_config_mut()
            .randomness_override_seq_num = 1;
        validator_override_config
            .override_config_mut()
            .consensus
            .sync_only = false;
        info!("Updating validator {} config.", idx);
        validator_override_config.save_config(config_path).unwrap();
        info!("Restarting validator {}.", idx);
        validator.start().unwrap();
        info!("Let validator {} bake for 5 secs.", idx);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
```
