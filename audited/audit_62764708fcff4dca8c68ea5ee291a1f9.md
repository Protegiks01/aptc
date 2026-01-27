# Audit Report

## Title
State Divergence via randomness_override_seq_num Causes Network Halt with <1/3 Compromised Validators

## Summary
The `randomness_override_seq_num` configuration field, designed for emergency randomness recovery, creates a critical vulnerability where an attacker who compromises fewer than 1/3 of validators can cause permanent network halt by inducing state root divergence across all validators. This violates the fundamental BFT liveness guarantee that the network should tolerate up to 1/3 Byzantine validators.

## Finding Description
The vulnerability stems from a design flaw in how randomness configuration is determined at the node level. Each validator independently decides whether to enable randomness by comparing its local `randomness_override_seq_num` value against the on-chain `RandomnessConfigSeqNum`: [1](#0-0) 

When a validator's local override value exceeds the on-chain sequence number, randomness is force-disabled. This creates two execution paths:

1. **Validators with override > on-chain value**: Execute blocks WITHOUT randomness
2. **Validators with override ≤ on-chain value**: Execute blocks WITH randomness

This divergence occurs during block execution in the pipeline: [2](#0-1) 

The critical issue is that randomness is NOT part of the block ID (which is computed from BlockData only): [3](#0-2) 

Instead, randomness is added AFTER consensus during execution: [4](#0-3) 

This means validators can agree on the SAME block via consensus, but execute it with DIFFERENT randomness values, producing different state roots. The state root is embedded in the LedgerInfo that validators must sign to commit: [5](#0-4) 

**Attack Scenario:**
1. Attacker compromises <1/3 validators (e.g., 3 out of 10)
2. On-chain `RandomnessConfigSeqNum` = 5
3. Attacker sets compromised validators' `randomness_override_seq_num` to 6, 7, 8 (any value > 5)
4. Honest validators (>2/3) have default override = 0

**Execution Flow:**
- Compromised validators: override > 5 → randomness disabled → State Root A
- Honest validators: override = 0 ≤ 5 → randomness enabled → State Root B
- Different state roots in BlockInfo → Different LedgerInfo hashes
- Cannot gather 2f+1 signatures on ANY LedgerInfo → **Network Halts**

The execution phase determines randomness configuration: [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program category "Non-recoverable network partition (requires hardfork)" because:

1. **Total Network Halt**: All validators are unable to commit blocks due to state root divergence, regardless of whether they are honest or compromised
2. **Violates BFT Liveness**: A fundamental property of Byzantine Fault Tolerant systems is that they remain live (make progress) with <1/3 Byzantine validators. This attack breaks that guarantee
3. **Difficult Recovery**: The designed recovery mechanism requires ALL validators to restart with the same override value: [7](#0-6) 

However, if compromised validators refuse to cooperate or continuously change their override values, recovery becomes impossible without:
- Out-of-band social consensus among all validator operators
- Coordinated manual intervention across all nodes
- Potential hardfork to exclude compromised validators

4. **Permanent Randomness Denial**: Even if network is recovered, attackers can repeat the attack indefinitely as long as they maintain access to <1/3 validators

## Likelihood Explanation
**Attack Requirements:**
- Compromise <1/3 of validators (significantly lower threshold than typical BFT attacks)
- Modify node configuration files (requires infrastructure access)
- No special cryptographic knowledge or complex exploit chains needed

**Likelihood: MEDIUM-HIGH** because:
- Only requires compromising a minority of validators (not 1/3+ needed for typical BFT attacks)
- Configuration modification is simple (single field change)
- Attack is repeatable and persistent
- No on-chain detection mechanism exists

The attack is easier than traditional BFT attacks because it leverages a design flaw rather than requiring Byzantine behavior during consensus protocol execution.

## Recommendation

**Immediate Fix:**
Remove or significantly restrict the `randomness_override_seq_num` mechanism. The field creates a per-node configuration that affects global consensus state without any validation that nodes agree.

**Proper Design:**
If emergency randomness override is needed, it should be:

1. **On-chain only**: Controlled via governance proposals that all validators observe
2. **Validated**: Checked during epoch transition that all validators agree on the configuration
3. **Consensus-aware**: Override should be part of the on-chain config that gets voted on through normal consensus mechanisms

**Code Fix Suggestion:**
```rust
// In config/src/config/node_config.rs
// REMOVE or deprecate:
pub randomness_override_seq_num: u64,

// In types/src/on_chain_config/randomness_config.rs
// Modify from_configs to ignore local override:
pub fn from_configs(
    onchain_seqnum: u64,  // Remove local_seqnum parameter
    onchain_raw_config: Option<RandomnessConfigMoveStruct>,
) -> Self {
    // Always use on-chain config, never local override
    onchain_raw_config
        .and_then(|onchain_raw| OnChainRandomnessConfig::try_from(onchain_raw).ok())
        .unwrap_or_else(OnChainRandomnessConfig::default_if_missing)
}
```

**Alternative Mitigation:**
If the override must be kept for operational reasons, add epoch-start validation:
```rust
// During epoch transition, verify all validators have the same override value
// Refuse to start epoch if divergence detected
// This prevents state divergence by ensuring configuration consistency
```

## Proof of Concept

```rust
// Simulation of the attack scenario
// This would be run as a Rust test in the consensus module

#[tokio::test]
async fn test_randomness_override_causes_state_divergence() {
    // Setup: 4 validators, on-chain RandomnessConfigSeqNum = 5
    let num_validators = 4;
    let byzantine_count = 1; // < 1/3
    
    // Create validator swarm
    let mut swarm = create_test_swarm(num_validators).await;
    
    // Set on-chain RandomnessConfigSeqNum to 5
    set_onchain_randomness_seqnum(&mut swarm, 5).await;
    
    // Compromise 1 validator (< 1/3)
    let byzantine_validator = swarm.validators_mut().nth(0).unwrap();
    byzantine_validator.stop();
    
    // Set override to 6 (> on-chain value of 5)
    let config_path = byzantine_validator.config_path();
    let mut config = OverrideNodeConfig::load_config(config_path.clone()).unwrap();
    config.override_config_mut().randomness_override_seq_num = 6;
    config.save_config(config_path).unwrap();
    
    byzantine_validator.start().unwrap();
    
    // Wait for epoch transition
    tokio::time::sleep(Duration::from_secs(30)).await;
    
    // Attempt to commit a block
    let commit_result = swarm.wait_for_all_nodes_to_commit(
        Duration::from_secs(60)
    ).await;
    
    // EXPECTED: Network should halt due to state divergence
    assert!(commit_result.is_err(), "Network should have halted");
    
    // Verify: Check that validators have different state roots
    let state_roots: Vec<_> = swarm.validators()
        .map(|v| v.get_latest_state_root())
        .collect();
    
    // Byzantine validator has different state root than honest validators
    assert_ne!(state_roots[0], state_roots[1]);
    assert_ne!(state_roots[0], state_roots[2]);
    assert_ne!(state_roots[0], state_roots[3]);
    
    // Honest validators agree with each other
    assert_eq!(state_roots[1], state_roots[2]);
    assert_eq!(state_roots[2], state_roots[3]);
    
    // But cannot form 2f+1 quorum on either state root
    // Therefore network is halted
}
```

**Notes:**
- This vulnerability violates **Invariant #1 (Deterministic Execution)**: Validators produce different state roots for the same blocks
- This vulnerability violates **Invariant #2 (Consensus Safety)**: Network halts with <1/3 Byzantine validators, breaking BFT liveness
- The attack requires validator infrastructure access, making it an insider threat scenario, but the impact affects all users of the blockchain

### Citations

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

**File:** consensus/src/pipeline/pipeline_builder.rs (L685-702)
```rust
    async fn rand_check(
        prepare_fut: TaskFuture<PrepareResult>,
        parent_block_execute_fut: TaskFuture<ExecuteResult>,
        rand_rx: oneshot::Receiver<Option<Randomness>>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
        is_randomness_enabled: bool,
        rand_check_enabled: bool,
        module_cache: Arc<Mutex<Option<CachedModuleView<CachedStateView>>>>,
    ) -> TaskResult<RandResult> {
        let mut tracker = Tracker::start_waiting("rand_check", &block);
        parent_block_execute_fut.await?;
        let (user_txns, _) = prepare_fut.await?;

        tracker.start_working();
        if !is_randomness_enabled {
            return Ok((None, false));
        }
```

**File:** consensus/consensus-types/src/block_data.rs (L105-120)
```rust
impl CryptoHash for BlockData {
    type Hasher = BlockDataHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        if self.is_opt_block() {
            #[derive(Serialize)]
            struct OptBlockDataForHash<'a> {
                epoch: u64,
                round: Round,
                timestamp_usecs: u64,
                quorum_cert_vote_data: &'a VoteData,
                block_type: &'a BlockType,
            }

            let opt_block_data_for_hash = OptBlockDataForHash {
```

**File:** consensus/consensus-types/src/block.rs (L597-616)
```rust
    pub fn new_metadata_with_randomness(
        &self,
        validators: &[AccountAddress],
        randomness: Option<Randomness>,
    ) -> BlockMetadataExt {
        BlockMetadataExt::new_v1(
            self.id(),
            self.epoch(),
            self.round(),
            self.author().unwrap_or(AccountAddress::ZERO),
            self.previous_bitvec().into(),
            // For nil block, we use 0x0 which is convention for nil address in move.
            self.block_data()
                .failed_authors()
                .map_or(vec![], |failed_authors| {
                    Self::failed_authors_to_indices(validators, failed_authors)
                }),
            self.timestamp_usecs(),
            randomness,
        )
```

**File:** types/src/block_info.rs (L24-44)
```rust
/// This structure contains all the information needed for tracking a block
/// without having access to the block or its execution output state. It
/// assumes that the block is the last block executed within the ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
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

**File:** consensus/src/pipeline/execution_client.rs (L566-577)
```rust
        let randomness_enabled = onchain_consensus_config.is_vtxn_enabled()
            && onchain_randomness_config.randomness_enabled();

        let aux_version = onchain_execution_config.persisted_auxiliary_info_version();

        self.execution_proxy.new_epoch(
            &epoch_state,
            payload_manager,
            transaction_shuffler,
            block_executor_onchain_config,
            transaction_deduper,
            randomness_enabled,
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
