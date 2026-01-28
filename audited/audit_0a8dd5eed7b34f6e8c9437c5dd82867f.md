# Audit Report

## Title
Consensus Split During Epoch Transitions Due to Divergent Randomness Configuration Override States

## Summary
During epoch transitions, validators with inconsistent `randomness_override_seq_num` node configurations derive different `OnChainRandomnessConfig` states, causing consensus divergence when processing `DKGResult` validator transactions. This leads to chain halt as validators cannot reach quorum on proposal validity.

## Finding Description

The vulnerability exists in the interaction between three consensus components:

**1. Configuration Loading**
Each validator independently loads `randomness_override_seq_num` from its node configuration file. [1](#0-0) 

**2. Config Resolution During Epoch Transitions**
When a new epoch starts, `OnChainRandomnessConfig::from_configs()` determines the effective randomness configuration by comparing the local override sequence number against the on-chain value. When `local_seqnum > onchain_seqnum`, it returns `Self::default_disabled()` (randomness Off); otherwise it parses the on-chain config. [2](#0-1) 

This resolution happens in the consensus epoch manager: [3](#0-2) 

**3. Validator Transaction Validation**
The resolved `OnChainRandomnessConfig` is stored in the `RoundManager`: [4](#0-3) 

When processing block proposals containing validator transactions, `is_vtxn_expected()` checks if randomness is enabled to determine whether `DKGResult` transactions should be accepted: [5](#0-4) 

This validation occurs during proposal processing: [6](#0-5) 

**Attack Scenario:**

Consider validators with divergent configurations during a recovery operation:
- Validator A: `randomness_override_seq_num = 0` (default)
- Validator B: `randomness_override_seq_num = 101` (set for recovery)
- On-chain: `RandomnessConfigSeqNum = 100` with randomness enabled

When the epoch starts:
- Validator A: `from_configs(0, 100, config)` → Returns enabled `V1` or `V2` config → `randomness_enabled()` returns `true`
- Validator B: `from_configs(101, 100, config)` → Returns `Off` → `randomness_enabled()` returns `false`

When a block proposal containing `DKGResult` arrives:
- Validator A validates with `is_vtxn_expected(&V1, ..., DKGResult)` → returns `true` → accepts proposal
- Validator B validates with `is_vtxn_expected(&Off, ..., DKGResult)` → returns `false` → rejects proposal with error "unexpected validator txn: DKGResult"

This creates a consensus split where validators fundamentally disagree on proposal validity, preventing quorum formation.

## Impact Explanation

**Critical Severity** - This qualifies as "Consensus/Safety Violations" under Aptos bug bounty criteria:

1. **Consensus Divergence**: Validators with different configurations cannot agree on block validity, violating the fundamental consensus invariant that all validators must produce identical decisions for identical blocks.

2. **Total Loss of Liveness**: If >1/3 of validators have divergent configurations, consensus cannot be reached. No proposals can achieve the required 2f+1 votes, causing complete chain halt.

3. **Non-recoverable Without Coordination**: Recovery requires all validators to align their configurations, which may require coordinated restarts or emergency governance actions.

The randomness feature test demonstrates the expected behavior when configurations align: [7](#0-6) 

## Likelihood Explanation

**Medium Likelihood:**

1. **Recovery Operations**: The documented randomness stall recovery procedure explicitly uses this mechanism. During rolling restarts where validators are updated sequentially, timing windows exist where configurations diverge. [8](#0-7) 

The recovery test shows validators are restarted sequentially with delays between them: [9](#0-8) 

2. **No Protocol-Level Validation**: There is no mechanism to detect or prevent divergent override values across validators. The protocol assumes operational coordination but provides no safeguards.

3. **Configuration Drift**: Validators operated by different entities may have configuration drift from previous recovery operations or apply updates at different times.

While the documented procedure includes halting the chain first, deviations from this procedure (whether intentional or accidental) would trigger the vulnerability.

## Recommendation

Implement one or more of the following mitigations:

1. **Consensus-Level Validation**: Add a check during epoch transitions to ensure all validators report compatible randomness configs. If divergence is detected, log warnings and potentially delay epoch progression.

2. **Override Expiration**: Make `randomness_override_seq_num` automatically reset after N epochs to prevent stale configurations.

3. **Strict Equality Check**: During DKG operations, verify that all validators agree on the randomness config state before processing DKG transactions.

4. **Enhanced Logging**: Add telemetry to track when validators use overrides, making divergence visible to operators.

## Proof of Concept

A proof of concept would require modifying the existing recovery test to NOT halt the chain before applying divergent override values:

```rust
// In testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs
// Remove the sync_only halt (lines 52-62)
// Apply different override values to different validators
// Observe consensus failure when DKGResult is proposed
```

The existing test infrastructure at [10](#0-9)  demonstrates the validation behavior and could be extended to test divergent configurations across multiple validators.

## Notes

This vulnerability represents a gap between operational procedures and protocol-level safeguards. While the documented recovery procedure mitigates the risk by halting the chain first, the protocol itself does not enforce this coordination, leaving validators vulnerable to configuration timing issues or operator errors during critical recovery operations.

### Citations

**File:** config/src/config/node_config.rs (L78-81)
```rust
    /// In a randomness stall, set this to be on-chain `RandomnessConfigSeqNum` + 1.
    /// Once enough nodes restarted with the new value, the chain should unblock with randomness disabled.
    #[serde(default)]
    pub randomness_override_seq_num: u64,
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

**File:** consensus/src/round_manager.rs (L1126-1137)
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

**File:** consensus/src/round_manager_tests/vtxn_on_proposal_test.rs (L95-115)
```rust
fn no_vote_on_proposal_with_unexpected_vtxns() {
    let vtxns = vec![ValidatorTransaction::ObservedJWKUpdate(
        QuorumCertifiedUpdate::dummy(),
    )];

    assert_process_proposal_result(
        None,
        None,
        Some(OnChainJWKConsensusConfig::default_disabled()),
        vtxns.clone(),
        false,
    );

    assert_process_proposal_result(
        None,
        None,
        Some(OnChainJWKConsensusConfig::default_enabled()),
        vtxns,
        true,
    );
}
```

**File:** consensus/src/round_manager_tests/vtxn_on_proposal_test.rs (L215-266)
```rust
/// Setup a node with default configs and an optional `Features` override.
/// Create a block, fill it with the given vtxns, and process it with the `RoundManager` from the setup.
/// Assert the processing result.
fn assert_process_proposal_result(
    validator_set: Option<(Vec<ValidatorSigner>, ValidatorVerifier)>,
    randomness_config: Option<OnChainRandomnessConfig>,
    jwk_consensus_config: Option<OnChainJWKConsensusConfig>,
    vtxns: Vec<ValidatorTransaction>,
    expected_result: bool,
) {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes_with_validator_set(
        &mut playground,
        runtime.handle().clone(),
        1,
        None,
        Some(OnChainConsensusConfig::default_for_genesis()),
        None,
        None,
        randomness_config,
        jwk_consensus_config,
        validator_set,
        false,
    );

    let node = &mut nodes[0];
    let genesis_qc = certificate_for_genesis();
    let block = Block::new_proposal_ext(
        vtxns,
        Payload::empty(false, true),
        1,
        1,
        genesis_qc.clone(),
        &node.signer,
        Vec::new(),
    )
    .unwrap();

    timed_block_on(&runtime, async {
        // clear the message queue
        node.next_proposal().await;

        assert_eq!(
            expected_result,
            node.round_manager
                .process_proposal(block.clone())
                .await
                .is_ok()
        );
    });
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config_seqnum.move (L1-9)
```text
/// Randomness stall recovery utils.
///
/// When randomness generation is stuck due to a bug, the chain is also stuck. Below is the recovery procedure.
/// 1. Ensure more than 2/3 stakes are stuck at the same version.
/// 1. Every validator restarts with `randomness_override_seq_num` set to `X+1` in the node config file,
///    where `X` is the current `RandomnessConfigSeqNum` on chain.
/// 1. The chain should then be unblocked.
/// 1. Once the bug is fixed and the binary + framework have been patched,
///    a governance proposal is needed to set `RandomnessConfigSeqNum` to be `X+2`.
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
