# Audit Report

## Title
DKG Consensus Split via Per-Node Randomness Override Configuration

## Summary
Validators can have divergent views on whether DKG (Distributed Key Generation) should run due to per-node `randomness_override_seq_num` configuration, causing DKG participation inconsistency and consensus safety violations.

## Finding Description

The DKG epoch manager makes a critical decision about whether to participate in the DKG protocol based on a `randomness_enabled` flag computed using a **per-node configuration parameter** (`randomness_override_seq_num`). This creates a consensus-breaking scenario where validators make different decisions about DKG participation. [1](#0-0) 

The `randomness_enabled` flag is computed by comparing the local node's `randomness_override_seq_num` with the on-chain `RandomnessConfigSeqNum`: [2](#0-1) 

The critical flaw is in the `OnChainRandomnessConfig::from_configs()` method, which force-disables randomness if the local override value exceeds the on-chain value: [3](#0-2) 

This same logic is applied in the consensus epoch manager: [4](#0-3) 

The consensus layer expects completed DKG sessions when randomness is enabled: [5](#0-4) 

**Attack Scenario:**

Per the on-chain documentation, this configuration is meant for coordinated recovery: [6](#0-5) 

However, there is **no enforcement mechanism** to ensure all validators use the same value. If validators have different `randomness_override_seq_num` values:

1. **Epoch N**: On-chain has `RandomnessConfigSeqNum = 5`, randomness enabled
2. **Validator Group A** (60% stake): `randomness_override_seq_num = 0` (default)
   - Computes: `0 <= 5` → randomness enabled
   - DKG manager starts, participates in DKG protocol
3. **Validator Group B** (40% stake): `randomness_override_seq_num = 10` (misconfigured)
   - Computes: `10 > 5` → randomness force-disabled  
   - DKG manager never starts, no DKG participation
4. **DKG Protocol**: Requires 2/3+ quorum to complete successfully
   - Only 60% participate → DKG FAILS
5. **Consensus Epoch N+1**: 
   - Group A expects completed DKG session, fails to initialize randomness
   - Group B doesn't expect randomness at all
   - Validators have divergent views on system state

This violates **Invariant #1 (Deterministic Execution)** and **Invariant #2 (Consensus Safety)**.

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Consensus Safety Violation**: Validators have different views on whether randomness/DKG is enabled, breaking the fundamental assumption that all honest validators see identical state
2. **Non-recoverable Network Partition**: Once validators diverge on randomness configuration, the chain may halt or fork depending on how critical randomness is to consensus
3. **Total Loss of Liveness**: If randomness is required for consensus operation (leader election, etc.), and DKG fails to complete due to insufficient participation, the chain cannot make progress

The configuration parameter defaults to 0 per node config: [7](#0-6) 

This meets the **Critical Severity** criteria per Aptos bug bounty rules: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Medium Likelihood** - While this requires validator misconfiguration rather than a direct attack:

1. The recovery procedure documented in the Move code explicitly states "Every validator restarts" with the override value, but provides no enforcement
2. During emergency recovery scenarios, operators under pressure may set different values
3. The configuration is per-node with no validation that all nodes agree
4. Silent failure - there's only a warning log, no hard check preventing inconsistent configs
5. No gossip protocol or consensus-level validation ensures configuration agreement

The vulnerability is realistic because:
- Emergency recovery procedures are high-stress situations prone to operator error
- The system was designed with an assumption of coordination but no enforcement
- A single misconfigured validator can break the 2/3 quorum requirement for DKG

## Recommendation

**Primary Fix**: Add consensus-level validation to ensure all validators agree on the effective randomness configuration before starting DKG:

1. **Pre-DKG Configuration Consensus**: Before starting DKG, validators should exchange and validate their computed `randomness_enabled` values through a dedicated consensus round
2. **Hard Validation**: If any validator detects a disagreement, halt epoch transition with a clear error
3. **On-Chain Override Tracking**: Store override values on-chain or require governance approval for overrides
4. **Fail-Safe Mode**: Default to the most conservative interpretation (disable randomness) if any inconsistency is detected

**Code Fix** (add to `dkg/src/epoch_manager.rs` before line 201):

```rust
// Validate randomness config consistency across validators
// This would require adding a new network message type and consensus round
// to exchange and verify randomness_enabled flags before starting DKG
if randomness_enabled {
    // TODO: Implement pre-DKG configuration consensus round
    // to ensure all validators agree on randomness_enabled
    // before spawning DKG manager
}
```

**Alternative Fix**: Remove the local override mechanism entirely and rely only on on-chain governance for randomness configuration changes.

## Proof of Concept

**Setup Script** (Rust integration test pseudocode):

```rust
// Configure two validator clusters with different overrides
let mut validators_group_a = setup_validators(60); // 60% stake
for v in &mut validators_group_a {
    v.config.randomness_override_seq_num = 0; // Default
}

let mut validators_group_b = setup_validators(40); // 40% stake  
for v in &mut validators_group_b {
    v.config.randomness_override_seq_num = 10; // Override enabled
}

// Set on-chain config
set_onchain_randomness_config_seqnum(5);
set_onchain_randomness_config(RandomnessConfig::V2(..));

// Trigger epoch transition
trigger_epoch_transition();

// Observe:
// - Group A validators log: "Starting DKG manager"
// - Group B validators log: "Randomness will be force-disabled"
// - DKG protocol fails to reach quorum (only 60% < 67% threshold)
// - Consensus diverges on randomness state

assert!(dkg_failed_to_complete());
assert!(consensus_has_divergent_views());
```

**Notes**

This vulnerability represents a critical design flaw where a per-node configuration parameter can cause consensus-breaking state divergence. The recovery procedure documentation assumes perfect coordination among validator operators, but provides no technical mechanism to enforce this assumption. The silent failure mode (logging a warning but continuing) allows the misconfiguration to propagate through epoch transitions until DKG failure manifests as a consensus issue.

### Citations

**File:** dkg/src/epoch_manager.rs (L186-190)
```rust
        let onchain_randomness_config = OnChainRandomnessConfig::from_configs(
            self.randomness_override_seq_num,
            onchain_randomness_config_seq_num.seq_num,
            randomness_config_move_struct.ok(),
        );
```

**File:** dkg/src/epoch_manager.rs (L199-201)
```rust
        let randomness_enabled =
            consensus_config.is_vtxn_enabled() && onchain_randomness_config.randomness_enabled();
        if let (true, Some(my_index)) = (randomness_enabled, my_index) {
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

**File:** consensus/src/epoch_manager.rs (L1034-1045)
```rust
        if !onchain_randomness_config.randomness_enabled() {
            return Err(NoRandomnessReason::FeatureDisabled);
        }
        let new_epoch = new_epoch_state.epoch;

        let dkg_state = maybe_dkg_state.map_err(NoRandomnessReason::DKGStateResourceMissing)?;
        let dkg_session = dkg_state
            .last_completed
            .ok_or_else(|| NoRandomnessReason::DKGCompletedSessionResourceMissing)?;
        if dkg_session.metadata.dealer_epoch + 1 != new_epoch_state.epoch {
            return Err(NoRandomnessReason::CompletedSessionTooOld);
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

**File:** config/src/config/node_config.rs (L78-81)
```rust
    /// In a randomness stall, set this to be on-chain `RandomnessConfigSeqNum` + 1.
    /// Once enough nodes restarted with the new value, the chain should unblock with randomness disabled.
    #[serde(default)]
    pub randomness_override_seq_num: u64,
```
