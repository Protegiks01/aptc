# Audit Report

## Title
Consensus Split Vulnerability Due to Silent Fallback in Randomness Config Variant Parsing

## Summary
When the on-chain `randomness_config` Move module is upgraded to add a new variant (e.g., ConfigV3), validators running older Rust binaries fail to parse the unknown variant and silently fall back to `OnChainRandomnessConfig::Off`. This causes validators with different binary versions to have divergent views on whether randomness is enabled, leading to creation of different block metadata transaction types (`BlockMetadata` vs `BlockMetadataExt`), resulting in a consensus safety violation and network partition requiring a hard fork.

## Finding Description

The vulnerability exists in the randomness configuration parsing logic. The `TryFrom` implementation for `RandomnessConfigMoveStruct` only recognizes three variant types: `ConfigOff`, `ConfigV1`, and `ConfigV2`. When an unknown variant is encountered, it returns an error. [1](#0-0) 

The error handling in `from_configs()` uses `.ok()` which swallows the parsing error, then `unwrap_or_else()` defaults to `default_if_missing()`, which returns `OnChainRandomnessConfig::Off`. [2](#0-1) 

The `default_if_missing()` method explicitly returns the `Off` variant. [3](#0-2) 

**Attack Scenario:**

1. A governance proposal upgrades the framework to add `ConfigV3` with new randomness features
2. Some validators upgrade their binaries early; others haven't upgraded yet
3. The proposal executes, setting the on-chain config to use `ConfigV3`
4. At epoch transition in `start_new_epoch`, validators call `OnChainRandomnessConfig::from_configs()`. [4](#0-3) 
5. OLD validators: Parse fails on unknown variant, error is logged as warning, but execution continues with `Off`. [5](#0-4) 
6. The `randomness_enabled()` method returns `false` for `Off` but `true` for V1/V2 variants. [6](#0-5) 
7. This boolean flows through the execution pipeline: the `randomness_enabled` flag is computed and stored. [7](#0-6) [8](#0-7) 
8. The flag is used by `PipelineBuilder` during block execution. [9](#0-8) [10](#0-9) 
9. In the `execute()` phase, the flag determines which metadata transaction type to create:
   - If randomness disabled: creates `BlockMetadata` via `new_block_metadata().into()`
   - If randomness enabled: creates `BlockMetadataExt::V1` via `new_metadata_with_randomness()` [11](#0-10) 
10. These convert to different `Transaction` enum variants:
    - `BlockMetadataExt::V0` → `Transaction::BlockMetadata`
    - `BlockMetadataExt::V1` → `Transaction::BlockMetadataExt` [12](#0-11) 
11. These are **different transaction types** that serialize and hash differently, resulting in:
    - Different transaction lists in blocks
    - Different execution results
    - **Different state roots**
    - **Consensus split** - validators cannot agree on the canonical chain

This breaks the **Deterministic Execution** invariant: all validators must produce identical state roots for identical blocks.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability qualifies as Critical severity under multiple Aptos bug bounty categories:

1. **Consensus/Safety Violations**: Different validators compute different state roots for the same block height, violating Byzantine Fault Tolerance guarantees. This is a fundamental consensus safety violation.

2. **Non-recoverable Network Partition (requires hardfork)**: The network splits into two incompatible partitions (old vs new binary validators). Neither partition can validate blocks from the other because they're creating fundamentally different transaction types. Recovery requires a coordinated hard fork where all validators upgrade and the chain is rolled back or manually reconciled.

3. **Total Loss of Liveness/Network Availability**: If neither partition maintains >2/3 stake, the entire chain halts as no partition can reach consensus quorum. Even if one partition has >2/3 stake, the minority partition is permanently forked.

The consensus split affects **all network participants** - users cannot submit transactions, funds become inaccessible, and the blockchain's core security guarantee (consensus on a single canonical chain) is violated. This is not theoretical - it's a latent design flaw that will manifest during any framework upgrade that adds new randomness config variants.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This vulnerability is highly likely to occur because:

1. **Framework upgrades are routine**: Aptos regularly upgrades the framework through governance proposals for feature additions and improvements.

2. **ConfigV2 was recently added**: The progression from `ConfigOff` to `ConfigV1` to `ConfigV2` demonstrates that the randomness configuration actively evolves, making `ConfigV3` a realistic future addition. [13](#0-12) 

3. **Imperfect upgrade coordination**: Validator operators upgrade their binaries at different times based on their operational schedules. This creates a window (potentially hours to days) where validators run mixed versions during the upgrade rollout.

4. **Silent failure**: The parsing error is only logged as a warning, and execution continues with incorrect assumptions about the randomness state. [5](#0-4) 

5. **No runtime version enforcement**: Unlike Move module compatibility which has strict bytecode version checks, there's no mechanism preventing validators from running incompatible Rust binary versions during randomness config transitions. The `AptosVersion` only tracks major protocol versions, not binary compatibility. [14](#0-13) 

6. **Legitimate use case**: This scenario doesn't require malicious intent - it naturally occurs during standard upgrade procedures when governance votes to enable new randomness features.

The vulnerability could be triggered **accidentally** during legitimate upgrades or **intentionally** by a malicious governance participant who times the proposal to maximize network disruption during a known validator upgrade window.

## Recommendation

Implement strict variant validation that prevents unknown variants from silently defaulting to a different configuration state:

1. **Fail-safe parsing**: Instead of defaulting to `Off` on parse failure, the validator should halt or refuse to participate in consensus until the binary is upgraded:

```rust
pub fn from_configs(
    local_seqnum: u64,
    onchain_seqnum: u64,
    onchain_raw_config: Option<RandomnessConfigMoveStruct>,
) -> Result<Self, anyhow::Error> {
    if local_seqnum > onchain_seqnum {
        return Ok(Self::default_disabled());
    }
    
    match onchain_raw_config {
        Some(config) => {
            // Explicitly fail instead of defaulting - forces validator to upgrade
            OnChainRandomnessConfig::try_from(config)
                .map_err(|e| anyhow!("Incompatible randomness config - binary upgrade required: {}", e))
        },
        None => Ok(OnChainRandomnessConfig::default_if_missing()),
    }
}
```

2. **Binary compatibility checking**: Add a version field to randomness configs that validators can check before parsing variants, similar to Move bytecode versioning.

3. **Graceful degradation**: If maintaining backward compatibility is required, add an explicit `UnknownVariant` enum case that causes validators to log errors prominently and refuse to produce blocks until upgraded, rather than silently assuming `Off`.

4. **Governance coordination**: For config upgrades that add new variants, require a two-phase rollout: (1) First upgrade all validator binaries, (2) Then activate the new config variant via governance after confirming all validators upgraded.

## Proof of Concept

The vulnerability can be demonstrated by simulating the epoch transition with mixed validator versions:

**Scenario Setup:**
1. Deploy a modified `RandomnessConfig` Move module with a `ConfigV3` variant
2. Run two validator nodes: one with old binary (recognizes only V1/V2), one with new binary (recognizes V3)
3. Submit a governance proposal to set config to `ConfigV3`
4. Observe epoch transition behavior

**Expected Behavior:**
- Old validator: Parses config, fails with "unknown variant type", defaults to `Off`, creates `Transaction::BlockMetadata`
- New validator: Parses config successfully, sets `randomness_enabled = true`, creates `Transaction::BlockMetadataExt`
- Block at epoch boundary: Old and new validators propose different transaction lists
- Consensus fails: Validators cannot agree on block hash due to different transaction types
- Network splits: Two incompatible chains emerge

The consensus split can be verified by checking that blocks produced by old vs new validators have different state roots despite processing the same user transactions, with the only difference being the block metadata transaction type.

**Notes**

This is a **latent vulnerability** that exists in the current codebase but hasn't been triggered yet because no ConfigV3 has been deployed. However, the design pattern guarantees this will occur on the next randomness config variant addition unless the parsing logic is hardened. The vulnerability is in the fundamental design of the error handling, not in any specific variant implementation.

The root cause is the violation of the fail-safe principle: when a validator encounters data it cannot parse, it should refuse to proceed rather than silently falling back to a default state that may be inconsistent with other validators' interpretations.

### Citations

**File:** types/src/on_chain_config/randomness_config.rs (L15-70)
```rust
#[derive(Deserialize, Serialize)]
pub struct ConfigOff {}

impl AsMoveAny for ConfigOff {
    const MOVE_TYPE_NAME: &'static str = "0x1::randomness_config::ConfigOff";
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConfigV1 {
    pub secrecy_threshold: FixedPoint64MoveStruct,
    pub reconstruction_threshold: FixedPoint64MoveStruct,
}

impl Default for ConfigV1 {
    fn default() -> Self {
        Self {
            secrecy_threshold: FixedPoint64MoveStruct::from_u64f64(
                U64F64::from_num(1) / U64F64::from_num(2),
            ),
            reconstruction_threshold: FixedPoint64MoveStruct::from_u64f64(
                U64F64::from_num(2) / U64F64::from_num(3),
            ),
        }
    }
}

impl AsMoveAny for ConfigV1 {
    const MOVE_TYPE_NAME: &'static str = "0x1::randomness_config::ConfigV1";
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConfigV2 {
    pub secrecy_threshold: FixedPoint64MoveStruct,
    pub reconstruction_threshold: FixedPoint64MoveStruct,
    pub fast_path_secrecy_threshold: FixedPoint64MoveStruct,
}

impl Default for ConfigV2 {
    fn default() -> Self {
        Self {
            secrecy_threshold: FixedPoint64MoveStruct::from_u64f64(
                U64F64::from_num(1) / U64F64::from_num(2),
            ),
            reconstruction_threshold: FixedPoint64MoveStruct::from_u64f64(
                U64F64::from_num(2) / U64F64::from_num(3),
            ),
            fast_path_secrecy_threshold: FixedPoint64MoveStruct::from_u64f64(
                U64F64::from_num(2) / U64F64::from_num(3),
            ),
        }
    }
}

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

**File:** consensus/src/pipeline/execution_client.rs (L566-567)
```rust
        let randomness_enabled = onchain_consensus_config.is_vtxn_enabled()
            && onchain_randomness_config.randomness_enabled();
```

**File:** consensus/src/state_computer.rs (L86-126)
```rust
    pub fn pipeline_builder(&self, commit_signer: Arc<ValidatorSigner>) -> PipelineBuilder {
        let MutableState {
            validators,
            payload_manager,
            transaction_shuffler,
            block_executor_onchain_config,
            transaction_deduper,
            is_randomness_enabled,
            consensus_onchain_config,
            persisted_auxiliary_info_version,
            network_sender,
        } = self
            .state
            .read()
            .as_ref()
            .cloned()
            .expect("must be set within an epoch");

        let block_preparer = Arc::new(BlockPreparer::new(
            payload_manager.clone(),
            self.txn_filter_config.clone(),
            transaction_deduper.clone(),
            transaction_shuffler.clone(),
        ));
        PipelineBuilder::new(
            block_preparer,
            self.executor.clone(),
            validators,
            block_executor_onchain_config,
            is_randomness_enabled,
            commit_signer,
            self.state_sync_notifier.clone(),
            payload_manager,
            self.txn_notifier.clone(),
            self.enable_pre_commit,
            &consensus_onchain_config,
            persisted_auxiliary_info_version,
            network_sender,
            self.secret_share_config.clone(),
        )
    }
```

**File:** consensus/src/state_computer.rs (L242-257)
```rust
        randomness_enabled: bool,
        consensus_onchain_config: OnChainConsensusConfig,
        persisted_auxiliary_info_version: u8,
        network_sender: Arc<NetworkSender>,
    ) {
        *self.state.write() = Some(MutableState {
            validators: epoch_state
                .verifier
                .get_ordered_account_addresses_iter()
                .collect::<Vec<_>>()
                .into(),
            payload_manager,
            transaction_shuffler,
            block_executor_onchain_config,
            transaction_deduper,
            is_randomness_enabled: randomness_enabled,
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L125-142)
```rust
pub struct PipelineBuilder {
    block_preparer: Arc<BlockPreparer>,
    executor: Arc<dyn BlockExecutorTrait>,
    validators: Arc<[AccountAddress]>,
    block_executor_onchain_config: BlockExecutorConfigFromOnchain,
    is_randomness_enabled: bool,
    signer: Arc<ValidatorSigner>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    payload_manager: Arc<dyn TPayloadManager>,
    txn_notifier: Arc<dyn TxnNotifier>,
    pre_commit_status: Arc<Mutex<PreCommitStatus>>,
    order_vote_enabled: bool,
    persisted_auxiliary_info_version: u8,
    rand_check_enabled: bool,
    module_cache: Arc<Mutex<Option<CachedModuleView<CachedStateView>>>>,
    network_sender: Arc<NetworkSender>,
    secret_share_config: Option<SecretShareConfig>,
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

**File:** types/src/transaction/mod.rs (L2946-2986)
```rust
pub enum Transaction {
    /// Transaction submitted by the user. e.g: P2P payment transaction, publishing module
    /// transaction, etc.
    /// TODO: We need to rename SignedTransaction to SignedUserTransaction, as well as all the other
    ///       transaction types we had in our codebase.
    UserTransaction(SignedTransaction),

    /// Transaction that applies a WriteSet to the current storage, it's applied manually via aptos-db-bootstrapper.
    GenesisTransaction(WriteSetPayload),

    /// Transaction to update the block metadata resource at the beginning of a block,
    /// when on-chain randomness is disabled.
    BlockMetadata(BlockMetadata),

    /// Transaction to let the executor update the global state tree and record the root hash
    /// in the TransactionInfo
    /// The hash value inside is unique block id which can generate unique hash of state checkpoint transaction
    StateCheckpoint(HashValue),

    /// Transaction that only proposed by a validator mainly to update on-chain configs.
    ValidatorTransaction(ValidatorTransaction),

    /// Transaction to update the block metadata resource at the beginning of a block,
    /// when on-chain randomness is enabled.
    BlockMetadataExt(BlockMetadataExt),

    /// Transaction to let the executor update the global state tree and record the root hash
    /// in the TransactionInfo
    /// The hash value inside is unique block id which can generate unique hash of state checkpoint transaction
    /// Replaces StateCheckpoint, with optionally having more data.
    BlockEpilogue(BlockEpiloguePayload),
}

impl From<BlockMetadataExt> for Transaction {
    fn from(metadata: BlockMetadataExt) -> Self {
        match metadata {
            BlockMetadataExt::V0(v0) => Transaction::BlockMetadata(v0),
            vx => Transaction::BlockMetadataExt(vx),
        }
    }
}
```

**File:** types/src/on_chain_config/aptos_version.rs (L7-34)
```rust
/// Defines the version of Aptos Validator software.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct AptosVersion {
    pub major: u64,
}

impl OnChainConfig for AptosVersion {
    const MODULE_IDENTIFIER: &'static str = "version";
    const TYPE_IDENTIFIER: &'static str = "Version";
}

// NOTE: version number for release 1.2 Aptos
// Items gated by this version number include:
//  - the EntryFunction payload type
pub const APTOS_VERSION_2: AptosVersion = AptosVersion { major: 2 };

// NOTE: version number for release 1.3 of Aptos
// Items gated by this version number include:
//  - Multi-agent transactions
pub const APTOS_VERSION_3: AptosVersion = AptosVersion { major: 3 };

// NOTE: version number for release 1.4 of Aptos
// Items gated by this version number include:
//  - Conflict-Resistant Sequence Numbers
pub const APTOS_VERSION_4: AptosVersion = AptosVersion { major: 4 };

// Maximum current known version
pub const APTOS_MAX_KNOWN_VERSION: AptosVersion = APTOS_VERSION_4;
```
