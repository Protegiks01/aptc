# Audit Report

## Title
Non-Deterministic Validator Transaction Acceptance Due to Local Randomness Config Override

## Summary
A consensus safety violation exists where validators with different local `randomness_override_seq_num` configurations will non-deterministically accept or reject the same validator transaction (DKGResult), breaking consensus determinism during epoch transitions.

## Finding Description

The vulnerability exists in how `OnChainRandomnessConfig` is constructed during epoch initialization. The system allows operators to set a local `randomness_override_seq_num` parameter in their node configuration for emergency recovery scenarios. [1](#0-0) 

When starting a new epoch, this local override is used to determine the actual randomness configuration via `OnChainRandomnessConfig::from_configs()`. [2](#0-1) 

The critical flaw is at line 144: if `local_seqnum > onchain_seqnum`, the function returns `Self::default_disabled()` (randomness OFF), completely ignoring the on-chain configuration that may have randomness enabled. [3](#0-2) 

During epoch initialization, each validator constructs their `OnChainRandomnessConfig` using their own local override value. [4](#0-3) 

This config is then stored in the RoundManager and used to validate validator transactions. [5](#0-4) 

When processing proposals, the `is_vtxn_expected()` function checks if a DKGResult validator transaction should be accepted based on `randomness_config.randomness_enabled()`. [6](#0-5) 

**Attack Scenario:**
1. Network enters epoch N+1 with on-chain randomness enabled (ConfigV1, seq_num=5)
2. Most validators have default config: `randomness_override_seq_num = 0`
3. One or more validators have emergency override: `randomness_override_seq_num = 6`
4. Byzantine validator submits proposal with DKGResult validator transaction
5. Normal validators: `from_configs(0, 5, Some(ConfigV1))` → returns V1 → `randomness_enabled() = true` → **ACCEPTS**
6. Override validators: `from_configs(6, 5, Some(ConfigV1))` → returns Off → `randomness_enabled() = false` → **REJECTS** [7](#0-6) 

The validation happens at line 1130, where the `ensure!` macro causes override validators to reject the proposal with error "unexpected validator txn", while normal validators accept it.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos bug bounty program as it constitutes a **Consensus/Safety violation**. 

Different validators will diverge on which proposals are valid for the same epoch, breaking the fundamental consensus invariant that all honest validators must agree on the same block sequence. This can lead to:

1. **Chain splits**: Validators fork into separate chains based on their local configuration
2. **Liveness failures**: Inability to form quorums if validators disagree on proposal validity
3. **Network partition**: Requires manual intervention or hard fork to recover

The vulnerability breaks Critical Invariants #1 (Deterministic Execution) and #2 (Consensus Safety). While the emergency override mechanism is intended for recovery scenarios, it creates a consensus hazard when different validators use different values during normal operation.

## Likelihood Explanation

**Medium to High Likelihood** depending on operational practices:

- The vulnerability requires validators to have different `randomness_override_seq_num` values, which could occur through:
  1. **Misconfiguration**: Operators forgetting to revert emergency overrides after recovery
  2. **Staged rollouts**: Some validators updating configs while others haven't
  3. **Testing/debugging**: Operators using different configs in production by mistake
  4. **Intentional emergency state**: During actual randomness stall recovery where this is by design

- Once the network is in this mixed state, any Byzantine validator can trivially exploit it by submitting a validator transaction
- The vulnerability persists for the entire epoch duration
- Detection is difficult as validators may not realize others have different configs until a failure occurs

## Recommendation

**Solution 1: Consensus-based override (Recommended)**
The local override mechanism should be replaced with an on-chain consensus mechanism where validators vote to disable randomness, ensuring all validators observe the same configuration.

**Solution 2: Reject mismatched configurations**
During epoch initialization, validators should gossip their intended randomness configuration and reject starting the epoch if there's disagreement. Add a check in `start_new_epoch()`: [4](#0-3) 

Before line 1217, add validation:
```rust
// Verify all validators will use the same randomness config
// by checking if local override would differ from on-chain
if self.randomness_override_seq_num > onchain_randomness_config_seq_num.seq_num {
    error!("Local randomness override would cause non-deterministic validator transaction acceptance");
    // Either: panic to prevent starting epoch with mismatched config
    // Or: broadcast override intent and coordinate with other validators
}
```

**Solution 3: Make validator transactions config-agnostic**
Modify `is_vtxn_expected()` to check a consensus-wide flag rather than per-node configuration, ensuring all nodes in the same epoch use identical validation logic.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[test]
fn test_non_deterministic_vtxn_acceptance() {
    // Setup two validators with same epoch but different randomness_override_seq_num
    let epoch = 10;
    let onchain_seqnum = 5;
    let onchain_config = Some(RandomnessConfigMoveStruct::from(
        OnChainRandomnessConfig::new_v1(50, 67)
    ));
    
    // Validator A: Normal configuration (no override)
    let config_a = OnChainRandomnessConfig::from_configs(
        0,  // local_seqnum = 0 (default)
        onchain_seqnum,
        onchain_config.clone()
    );
    
    // Validator B: Emergency override configuration
    let config_b = OnChainRandomnessConfig::from_configs(
        6,  // local_seqnum = 6 (override)
        onchain_seqnum,
        onchain_config
    );
    
    // Create a DKGResult validator transaction
    let dkg_result = ValidatorTransaction::DKGResult(
        DKGTranscript::new(/* ... */)
    );
    
    // Validator A accepts it
    assert!(is_vtxn_expected(
        &config_a,
        &OnChainJWKConsensusConfig::default_disabled(),
        &dkg_result
    ));
    
    // Validator B rejects it - CONSENSUS VIOLATION!
    assert!(!is_vtxn_expected(
        &config_b,
        &OnChainJWKConsensusConfig::default_disabled(),
        &dkg_result
    ));
    
    // Same epoch, same transaction, different acceptance = broken consensus
}
```

## Notes

The vulnerability is rooted in the emergency recovery design that allows local node configuration to override on-chain consensus state. While this mechanism serves a legitimate purpose (recovering from randomness stalls), it violates consensus determinism when different validators use different overrides.

The issue specifically affects `OnChainRandomnessConfig` through the `randomness_override_seq_num` parameter. The similar `OnChainJWKConsensusConfig` does not have this vulnerability as it lacks a local override mechanism. [8](#0-7)

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

**File:** consensus/src/round_manager.rs (L317-318)
```rust
    randomness_config: OnChainRandomnessConfig,
    jwk_consensus_config: OnChainJWKConsensusConfig,
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

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L69-74)
```rust
    pub fn jwk_consensus_enabled(&self) -> bool {
        match self {
            OnChainJWKConsensusConfig::Off => false,
            OnChainJWKConsensusConfig::V1 { .. } => true,
        }
    }
```
