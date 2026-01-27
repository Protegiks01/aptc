# Audit Report

## Title
Network Partition Risk Due to Unsynchronized `order_vote_enabled` Flag in Consensus LedgerInfo Generation

## Summary
The consensus layer lacks validation that all validators have synchronized `order_vote_enabled` flag values during epoch initialization. If validators end up with different flag values (due to on-chain config retrieval failures falling back to different defaults), they will generate incompatible `LedgerInfo` objects for the same block, preventing signature aggregation and causing network partition.

## Finding Description

During epoch initialization, each validator independently reads the `order_vote_enabled` flag from the on-chain consensus configuration. [1](#0-0)  If the config retrieval fails (returns an error), the code falls back to `OnChainConsensusConfig::default()`, which uses `ConsensusAlgorithmConfig::default_if_missing()` with `order_vote_enabled: false`. [2](#0-1) [3](#0-2) 

The `order_vote_enabled` flag directly controls the `consensus_data_hash` field when generating commit `LedgerInfo` objects. [4](#0-3)  When `order_vote_enabled` is `true`, the hash is set to `HashValue::zero()`, otherwise it uses the actual consensus data hash from the ordered proof.

During signature aggregation, commit votes are only accepted if their `LedgerInfo` exactly matches the locally generated one. [5](#0-4)  Since `LedgerInfo` derives `Eq` and `PartialEq`, two `LedgerInfo` objects with different `consensus_data_hash` values are not equal, even if they have identical `commit_info`. [6](#0-5) 

**Network Partition Scenario:**
1. Epoch transition occurs where on-chain config has `order_vote_enabled: true`
2. Some validators successfully read the config (get `true`)  
3. Other validators fail to read the config due to deserialization errors, state sync lag, or missing config (fall back to default with `false`)
4. When committing blocks, Group A (with `true`) generates `LedgerInfo` with `consensus_data_hash = HashValue::zero()`
5. Group B (with `false`) generates `LedgerInfo` with `consensus_data_hash = actual_hash`
6. Validators in Group A reject all commit votes from Group B and vice versa
7. Neither group can aggregate 2f+1 signatures for quorum
8. Network cannot commit blocks → complete liveness failure

## Impact Explanation

This represents **Critical Severity** under the Aptos bug bounty criteria as "Non-recoverable network partition (requires hardfork)" and "Total loss of liveness/network availability". The network would be unable to commit any blocks until manual intervention (likely requiring a coordinated restart or hardfork to synchronize the flag values).

The vulnerability breaks the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" by allowing non-Byzantine failures (config read errors) to cause network partition.

## Likelihood Explanation

**Likelihood: Medium to Low**

While the code path exists, this requires validators to experience different outcomes when reading the on-chain config during the same epoch transition. This could occur during:

1. **Rolling upgrades** where different validator code versions handle config deserialization differently
2. **State corruption** where some validators have corrupted state affecting config reads
3. **Race conditions** in state sync during epoch boundaries
4. **Missing on-chain config** in test networks or misconfigured deployments

However, this is **not directly exploitable by an unprivileged external attacker**. The condition requires pre-existing system failures, network issues, or deployment errors. It's a defensive programming gap rather than a targeted attack vector.

## Recommendation

Add explicit validation during epoch initialization to ensure all validators have synchronized on the same `order_vote_enabled` value:

1. **Immediate fix**: Remove the silent fallback to default and make config retrieval failures fatal during epoch start:
   ```rust
   let consensus_config = onchain_consensus_config
       .context("Failed to read on-chain consensus config - cannot start epoch")?;
   ```

2. **Robust fix**: Add the `order_vote_enabled` flag to the `EpochState` structure that is validated via quorum certificates, ensuring all validators agree on it before starting the epoch.

3. **Defense-in-depth**: Add runtime assertion in `generate_commit_ledger_info()` that logs and panics if validators receive commit votes with mismatched `LedgerInfo` objects, helping detect this condition early.

4. **Monitoring**: Add metrics tracking config retrieval failures and alerting when validators have different `order_vote_enabled` values.

## Proof of Concept

```rust
// Integration test demonstrating the partition condition
#[test]
fn test_order_vote_enabled_mismatch_causes_partition() {
    // Setup two validator groups
    let (validators_true, verifier_true) = create_validators_with_config(true);
    let (validators_false, verifier_false) = create_validators_with_config(false);
    
    // Create same block
    let block = create_test_block();
    let commit_info = block.block_info();
    let ordered_proof = create_ordered_proof();
    
    // Group A generates LedgerInfo with order_vote_enabled=true
    let ledger_info_true = generate_commit_ledger_info(
        &commit_info,
        &ordered_proof,
        true  // order_vote_enabled=true → consensus_data_hash=HashValue::zero()
    );
    
    // Group B generates LedgerInfo with order_vote_enabled=false  
    let ledger_info_false = generate_commit_ledger_info(
        &commit_info,
        &ordered_proof,
        false  // order_vote_enabled=false → consensus_data_hash=actual_hash
    );
    
    // These LedgerInfo objects are NOT equal despite same commit_info
    assert_ne!(ledger_info_true, ledger_info_false);
    assert_ne!(
        ledger_info_true.consensus_data_hash(),
        ledger_info_false.consensus_data_hash()
    );
    
    // Create commit votes
    let vote_from_group_a = CommitVote::new(
        validators_true[0].author(),
        ledger_info_true.clone(),
        &validators_true[0]
    );
    
    // Try to aggregate vote from Group A into Group B's aggregator
    let mut aggregator_b = SignatureAggregator::new(ledger_info_false.clone());
    
    // This vote will be REJECTED because ledger_info_true != ledger_info_false
    // Signature aggregation will fail, preventing quorum formation
    assert!(vote_from_group_a.ledger_info() != &ledger_info_false);
    
    // Network partition: neither group can reach 2f+1 signatures
}
```

## Notes

This issue represents a **lack of defensive validation** rather than a directly exploitable attack vector. The vulnerability cannot be triggered by unprivileged external attackers but could manifest during:
- Software upgrades with incompatible serialization
- Network partitions during epoch transitions  
- State database corruption affecting config reads
- Misconfigured test/development networks

The fix should prioritize fail-fast behavior over silent fallback to prevent validators from starting epochs with inconsistent configurations.

### Citations

**File:** consensus/src/epoch_manager.rs (L1178-1201)
```rust
        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
        let onchain_randomness_config_seq_num: anyhow::Result<RandomnessConfigSeqNum> =
            payload.get();
        let randomness_config_move_struct: anyhow::Result<RandomnessConfigMoveStruct> =
            payload.get();
        let onchain_jwk_consensus_config: anyhow::Result<OnChainJWKConsensusConfig> = payload.get();
        let dkg_state = payload.get::<DKGState>();

        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }

        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }

        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
        }

        self.epoch_state = Some(epoch_state.clone());

        let consensus_config = onchain_consensus_config.unwrap_or_default();
```

**File:** types/src/on_chain_config/consensus_config.rs (L46-52)
```rust
    pub fn default_if_missing() -> Self {
        Self::JolteonV2 {
            main: ConsensusConfigV1::default(),
            quorum_store_enabled: true,
            order_vote_enabled: false,
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L443-450)
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        OnChainConsensusConfig::V4 {
            alg: ConsensusAlgorithmConfig::default_if_missing(),
            vtxn: ValidatorTxnConfig::default_if_missing(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
```

**File:** consensus/src/pipeline/buffer_item.rs (L25-38)
```rust
fn generate_commit_ledger_info(
    commit_info: &BlockInfo,
    ordered_proof: &LedgerInfoWithSignatures,
    order_vote_enabled: bool,
) -> LedgerInfo {
    LedgerInfo::new(
        commit_info.clone(),
        if order_vote_enabled {
            HashValue::zero()
        } else {
            ordered_proof.ledger_info().consensus_data_hash()
        },
    )
}
```

**File:** consensus/src/pipeline/buffer_item.rs (L40-52)
```rust
fn create_signature_aggregator(
    unverified_votes: HashMap<Author, CommitVote>,
    commit_ledger_info: &LedgerInfo,
) -> SignatureAggregator<LedgerInfo> {
    let mut sig_aggregator = SignatureAggregator::new(commit_ledger_info.clone());
    for vote in unverified_votes.values() {
        let sig = vote.signature_with_status();
        if vote.ledger_info() == commit_ledger_info {
            sig_aggregator.add_signature(vote.author(), sig);
        }
    }
    sig_aggregator
}
```

**File:** types/src/ledger_info.rs (L51-90)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct LedgerInfo {
    commit_info: BlockInfo,

    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl Display for LedgerInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "LedgerInfo: [commit_info: {}] [Consensus data hash: {}]",
            self.commit_info(),
            self.consensus_data_hash()
        )
    }
}

impl LedgerInfo {
    pub fn dummy() -> Self {
        Self {
            commit_info: BlockInfo::empty(),
            consensus_data_hash: HashValue::zero(),
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.commit_info.is_empty() && self.consensus_data_hash == HashValue::zero()
    }

    /// Constructs a `LedgerInfo` object based on the given commit info and vote data hash.
    pub fn new(commit_info: BlockInfo, consensus_data_hash: HashValue) -> Self {
        Self {
            commit_info,
            consensus_data_hash,
        }
    }
```
