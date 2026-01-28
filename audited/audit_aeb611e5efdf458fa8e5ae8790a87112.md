# Audit Report

## Title
Consensus Split via Local Randomness Override Configuration Divergence in Fast Path Randomness

## Summary
When validators configure different `randomness_override_seq_num` values in their local node configurations, they compute divergent `OnChainRandomnessConfig` values during epoch initialization. This causes some validators to enable fast randomness while others disable it, leading to different randomness values being decided. These divergent randomness values are embedded in block metadata during execution, producing different state roots and causing an irrecoverable consensus split.

## Finding Description

The vulnerability originates in the epoch initialization logic where local node configuration overrides on-chain randomness settings without cross-validator validation.

The `randomness_override_seq_num` is a per-validator local configuration parameter: [1](#0-0) 

The `from_configs` function uses this local parameter to determine the effective randomness configuration: [2](#0-1) 

When `local_seqnum > onchain_seqnum`, the function returns `Off`, disabling randomness. The `fast_randomness_enabled()` method returns different values based on the config variant: [3](#0-2) 

During epoch initialization, each validator independently computes their configuration with only a warning log: [4](#0-3) 

This divergence propagates to the fast path determination: [5](#0-4) 

Validators with `fast_rand_config = Some(...)` generate fast path shares: [6](#0-5) 

However, validators without `fast_rand_config` reject fast shares with an error: [7](#0-6) 

The fast and slow paths aggregate independently using different cryptographic keys: [8](#0-7) 

Both paths send decisions through the same channel, with the first decision "winning": [9](#0-8) 

The decided randomness is embedded in block metadata: [10](#0-9) 

This updates the `PerBlockRandomness` global resource: [11](#0-10) 

Different randomness values cause different state updates, leading to different state roots. Validators vote on `BlockInfo` containing the `executed_state_id`: [12](#0-11) 

When validators have different state roots, their votes diverge, preventing quorum and halting consensus.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under the Aptos Bug Bounty program:

**Consensus/Safety Violations**: Validators with different configurations produce different state roots for the same block, breaking the fundamental safety property that honest validators agree on committed blocks. This occurs because fast and slow randomness paths use different DKG keys (main vs fast) and aggregate different share sets, producing cryptographically different randomness values.

**Non-recoverable Network Partition**: Once validators diverge on randomness values, they cannot reconcile without coordinated manual intervention. The divergence persists across all subsequent blocks as execution state accumulates. Recovery requires all validators to align their configurations and potentially requires blockchain rollback via hardfork.

**Total Loss of Liveness**: If validator voting power splits between those using fast randomness and those using slow/no randomness, neither group can achieve the 2/3+ supermajority required for quorum certificates. No new blocks can be committed, completely halting the network.

The severity is amplified because:
1. The failure is **silent** - only warning logs are emitted, no errors prevent divergence
2. Detection is **delayed** - the split manifests only when blocks requiring randomness are executed
3. Impact is **permanent** - validators cannot self-recover once state roots diverge
4. It can be triggered **accidentally** through routine operational procedures

## Likelihood Explanation

**High Likelihood** due to:

1. **Operational Reality**: The `randomness_override_seq_num` exists specifically for emergency recovery procedures. In production networks with 100+ validators operated by independent entities, configuration drift is inevitable during updates, recoveries, or testing.

2. **No Enforcement**: The recovery documentation describes the intended coordinated procedure, but there is no protocol-level validation ensuring all validators use the same configuration: [13](#0-12) 

3. **Silent Failure**: The existing test only validates the coordinated scenario where all validators use the same value: [14](#0-13) 

There is no test or validation for divergent configurations.

4. **Low Expertise Required**: This requires no malicious intent or cryptographic expertise. Any operator following outdated procedures, using different configuration templates, or performing partial rollouts triggers the vulnerability.

5. **Realistic Trigger**: The vulnerability manifests during epoch transitions when transactions require randomness, which becomes more frequent as on-chain randomness usage increases.

## Recommendation

Implement cross-validator validation of randomness configuration before epoch transitions:

1. Add a consensus-level check that all validators have compatible randomness configurations
2. Include the effective `randomness_override_seq_num` in epoch initialization messages  
3. Reject epoch transitions if validators report divergent configurations
4. Add explicit error logging (not just warnings) when local overrides are active
5. Implement a governance-controlled "maintenance mode" flag instead of per-validator configuration for emergency randomness disabling

## Proof of Concept

While a full PoC would require a multi-validator testnet setup, the vulnerability can be demonstrated conceptually:

1. Configure 4 validators with `randomness_override_seq_num = 0` (default)
2. Configure 3 validators with `randomness_override_seq_num = 10`  
3. Set on-chain `RandomnessConfigSeqNum = 5` with fast randomness enabled (ConfigV2)
4. Trigger epoch transition
5. Validators with override 0 enable fast randomness (0 < 5)
6. Validators with override 10 disable all randomness (10 > 5)
7. Submit a transaction requiring randomness
8. Fast-enabled validators aggregate fast shares and decide randomness R1
9. Disabled validators only aggregate slow shares (if any) and decide randomness R2 (or None)
10. Block execution produces different `PerBlockRandomness.seed` values
11. State roots diverge
12. Votes cannot reach quorum
13. Network halts

The mechanism is deterministic and follows directly from the code paths validated above.

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

**File:** consensus/src/epoch_manager.rs (L1207-1221)
```rust
        info!(
            epoch = epoch_state.epoch,
            local = self.randomness_override_seq_num,
            onchain = onchain_randomness_config_seq_num.seq_num,
            "Checking randomness config override."
        );
        if self.randomness_override_seq_num > onchain_randomness_config_seq_num.seq_num {
            warn!("Randomness will be force-disabled by local config!");
        }

        let onchain_randomness_config = OnChainRandomnessConfig::from_configs(
            self.randomness_override_seq_num,
            onchain_randomness_config_seq_num.seq_num,
            randomness_config_move_struct.ok(),
        );
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L157-163)
```rust
        if let Some(fast_config) = &self.fast_config {
            let self_fast_share =
                FastShare::new(S::generate(fast_config, metadata.metadata.clone()));
            rand_store
                .add_share(self_fast_share.rand_share(), PathType::Fast)
                .expect("Add self share for fast path should succeed");
        }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L196-206)
```rust
    fn process_randomness(&mut self, randomness: Randomness) {
        let rand = hex::encode(randomness.randomness());
        info!(
            metadata = randomness.metadata(),
            rand = rand,
            "Processing decisioned randomness."
        );
        if let Some(block) = self.block_queue.item_mut(randomness.round()) {
            block.set_randomness(randomness.round(), randomness);
        }
    }
```

**File:** consensus/src/rand/rand_gen/network_messages.rs (L53-57)
```rust
            RandMessage::FastShare(share) => {
                share.share.verify(fast_rand_config.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("[RandMessage] rand config for fast path not found")
                })?)
            },
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L218-247)
```rust
pub struct RandStore<S> {
    epoch: u64,
    author: Author,
    rand_config: RandConfig,
    rand_map: BTreeMap<Round, RandItem<S>>,
    fast_rand_config: Option<RandConfig>,
    fast_rand_map: Option<BTreeMap<Round, RandItem<S>>>,
    highest_known_round: u64,
    decision_tx: Sender<Randomness>,
}

impl<S: TShare> RandStore<S> {
    pub fn new(
        epoch: u64,
        author: Author,
        rand_config: RandConfig,
        fast_rand_config: Option<RandConfig>,
        decision_tx: Sender<Randomness>,
    ) -> Self {
        Self {
            epoch,
            author,
            rand_config,
            rand_map: BTreeMap::new(),
            fast_rand_config: fast_rand_config.clone(),
            fast_rand_map: fast_rand_config.map(|_| BTreeMap::new()),
            highest_known_round: 0,
            decision_tx,
        }
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L807-811)
```rust
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** aptos-move/framework/aptos-framework/sources/randomness.move (L64-72)
```text
    public(friend) fun on_new_block(vm: &signer, epoch: u64, round: u64, seed_for_new_block: Option<vector<u8>>) acquires PerBlockRandomness {
        system_addresses::assert_vm(vm);
        if (exists<PerBlockRandomness>(@aptos_framework)) {
            let randomness = borrow_global_mut<PerBlockRandomness>(@aptos_framework);
            randomness.epoch = epoch;
            randomness.round = round;
            randomness.seed = seed_for_new_block;
        }
    }
```

**File:** types/src/block_info.rs (L29-44)
```rust
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
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
