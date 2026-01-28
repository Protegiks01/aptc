# Audit Report

## Title
Consensus Safety Violation: Fast Path Configuration Divergence Enables Randomness Fork

## Summary
Validators with different `randomness_override_seq_num` local configurations will produce divergent randomness values for identical blocks, violating consensus safety and potentially causing a chain split. The vulnerability stems from the protocol's failure to enforce consistent fast path randomness configuration across validators, combined with strict augmented data verification that prevents cross-configuration cryptographic material exchange.

## Finding Description

The vulnerability occurs through a multi-stage mechanism that breaks consensus safety:

**Root Cause - Local Configuration Parameter**: The `randomness_override_seq_num` is a local node configuration parameter that can differ across validators. [1](#0-0) 

**Configuration Divergence**: During epoch transitions, validators use this local parameter to determine the effective randomness configuration. When `local_seqnum > onchain_seqnum`, the configuration is forced to disabled (returns `Off`), otherwise it uses the on-chain configuration. [2](#0-1) 

**Fast Path Enablement Divergence**: The `fast_randomness_enabled()` method returns `true` only for `ConfigV2`, causing validators with different configurations to have different fast path enablement states. [3](#0-2) 

**Fast Config Initialization**: Validators check `fast_randomness_enabled()` to determine whether to create `fast_rand_config`. Those with fast path enabled get `Some(RandConfig)`, while others get `None`. [4](#0-3) [5](#0-4) 

**Augmented Data Structure Mismatch**: Validators generate `AugmentedData` with optional `fast_delta` based on their configuration. [6](#0-5) 

**Strict Verification Causing Cross-Rejection**: The augmented data verification enforces exact matching with the strict check `ensure!(self.fast_delta.is_some() == fast_rand_config.is_some())`, causing validators with mismatched configurations to reject each other's augmented data. [7](#0-6) 

**APK Divergence**: Due to augmented data rejection, validators build different sets of certified augmented public keys (APKs). The `augment()` method adds APKs only for accepted data. [8](#0-7) 

**Randomness Divergence via Different APK Sets**: During share aggregation, `Share::aggregate()` calls `WVUF::derive_eval()` using `get_all_certified_apk()` as input. [9](#0-8) [10](#0-9)  Different APK sets produce different randomness outputs, as each validator independently computes randomness. [11](#0-10) 

**State Root Divergence**: Different randomness values are included in block metadata transactions, causing different execution outcomes and different state roots. [12](#0-11) [13](#0-12)  This breaks consensus safety as validators vote on different state roots for the same block.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability breaks the fundamental consensus safety invariant: "All validators must produce identical state roots for identical blocks." The impact qualifies as **Consensus/Safety Violations (Critical)** under the Aptos bug bounty program because it enables:

1. **Consensus Safety Violation**: Validators processing the same block compute different randomness values, leading to different execution outcomes
2. **Chain Split Risk**: If network partitions occur with different configuration groups each achieving quorum, the network forks permanently
3. **State Root Divergence**: Different randomness leads to different transaction execution and state transitions
4. **Non-recoverable Network Partition**: Once validators commit different randomness values to their local state, manual intervention or hard fork is required for recovery

The vulnerability affects ALL validators when configuration mismatches occur, making it a network-wide critical issue that can halt the blockchain or cause permanent divergence.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability can be triggered through realistic operational scenarios:

1. **Emergency Recovery Procedure**: The Move framework documentation explicitly describes a recovery procedure where validators set `randomness_override_seq_num` to unblock a stalled chain. [14](#0-13)  The documentation states "Every validator" must set the same value, but the protocol does not enforce this requirement.

2. **Gradual Rollout**: If validator operators update their configurations in phases (common during incident response), early updaters and late updaters will have mismatched configurations.

3. **Operational Error**: During troubleshooting or incident response, operators may independently adjust `randomness_override_seq_num` without coordinating across all validators.

The likelihood is elevated because:
- The parameter is designed for manual intervention during incidents when stress is high
- No protocol-level validation enforces consistency across validators  
- The consequence is non-obvious to operators (they may not realize local configuration affects consensus)
- The failure mode is silent until randomness is actually used in block execution
- Configuration divergence is a realistic scenario during emergency procedures

## Recommendation

Implement protocol-level validation to prevent configuration divergence:

1. **Consensus-Level Override Validation**: Include `randomness_override_seq_num` in epoch state or validate it during epoch transitions. Reject epoch changes if validators have inconsistent override values.

2. **Augmented Data Compatibility Check**: Modify the verification logic to handle mixed configurations gracefully during transition periods, or enforce that all validators must have identical fast path configurations.

3. **Explicit Configuration Broadcast**: Require validators to broadcast their effective randomness configuration during epoch start and verify consistency before proceeding with randomness generation.

4. **Safe Recovery Procedure**: Implement a governance-controlled emergency procedure that coordinates the override value across all validators atomically through on-chain state.

## Proof of Concept

To demonstrate this vulnerability:

1. Deploy a test network with validators split between two configurations:
   - Group A: `randomness_override_seq_num = 0` (uses on-chain config V2 with fast path)
   - Group B: `randomness_override_seq_num = X+1` where X is the on-chain `RandomnessConfigSeqNum` (forced to Off)

2. Start a new epoch and observe:
   - Group A generates and broadcasts `AugmentedData` with `fast_delta = Some(...)`
   - Group B generates and broadcasts `AugmentedData` with `fast_delta = None`
   - Cross-rejection occurs at verification

3. When randomness is needed for a block:
   - Group A computes randomness using APKs only from Group A validators
   - Group B computes randomness using APKs only from Group B validators
   - Different randomness values are produced

4. Block execution diverges:
   - Group A executes with randomness_A
   - Group B executes with randomness_B
   - Different state roots result, causing consensus split

**Note**: A complete implementation PoC would require a multi-validator testnet setup with controlled configuration divergence during epoch transitions.

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

**File:** types/src/on_chain_config/randomness_config.rs (L213-219)
```rust
    pub fn fast_randomness_enabled(&self) -> bool {
        match self {
            OnChainRandomnessConfig::Off => false,
            OnChainRandomnessConfig::V1(_) => false,
            OnChainRandomnessConfig::V2(_) => true,
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1074-1078)
```rust
        let fast_randomness_is_enabled = onchain_randomness_config.fast_randomness_enabled()
            && sk.fast.is_some()
            && pk.fast.is_some()
            && transcript.fast.is_some()
            && dkg_pub_params.pvss_config.fast_wconfig.is_some();
```

**File:** consensus/src/epoch_manager.rs (L1137-1159)
```rust
        let fast_rand_config = if let (Some((ask, apk)), Some(trx), Some(wconfig)) = (
            fast_augmented_key_pair,
            transcript.fast.as_ref(),
            dkg_pub_params.pvss_config.fast_wconfig.as_ref(),
        ) {
            let pk_shares = (0..new_epoch_state.verifier.len())
                .map(|id| trx.get_public_key_share(wconfig, &Player { id }))
                .collect::<Vec<_>>();

            let fast_keys = RandKeys::new(ask, apk, pk_shares, new_epoch_state.verifier.len());
            let fast_wconfig = wconfig.clone();

            Some(RandConfig::new(
                self.author,
                new_epoch,
                new_epoch_state.verifier.clone(),
                vuf_pp,
                fast_keys,
                fast_wconfig,
            ))
        } else {
            None
        };
```

**File:** consensus/src/rand/rand_gen/types.rs (L46-49)
```rust
pub struct AugmentedData {
    delta: Delta,
    fast_delta: Option<Delta>,
}
```

**File:** consensus/src/rand/rand_gen/types.rs (L134-142)
```rust
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
```

**File:** consensus/src/rand/rand_gen/types.rs (L184-193)
```rust
        let AugmentedData { delta, fast_delta } = self;
        rand_config
            .add_certified_delta(author, delta.clone())
            .expect("Add delta should succeed");

        if let (Some(config), Some(fast_delta)) = (fast_rand_config, fast_delta) {
            config
                .add_certified_delta(author, fast_delta.clone())
                .expect("Add delta for fast path should succeed");
        }
```

**File:** consensus/src/rand/rand_gen/types.rs (L206-209)
```rust
        ensure!(
            self.fast_delta.is_some() == fast_rand_config.is_some(),
            "Fast path delta should be present iff fast_rand_config is present."
        );
```

**File:** consensus/src/rand/rand_gen/types.rs (L643-649)
```rust
    pub fn get_all_certified_apk(&self) -> Vec<Option<APK>> {
        self.keys
            .certified_apks
            .iter()
            .map(|cell| cell.get().cloned())
            .collect()
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L69-78)
```rust
        tokio::task::spawn_blocking(move || {
            let maybe_randomness = S::aggregate(
                self.shares.values(),
                &rand_config,
                rand_metadata.metadata.clone(),
            );
            match maybe_randomness {
                Ok(randomness) => {
                    let _ = decision_tx.unbounded_send(randomness);
                },
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L806-811)
```rust
        // if randomness is disabled, the metadata skips DKG and triggers immediate reconfiguration
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** execution/executor-types/src/state_compute_result.rs (L87-89)
```rust
    pub fn root_hash(&self) -> HashValue {
        self.ledger_update_output.transaction_accumulator.root_hash
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
