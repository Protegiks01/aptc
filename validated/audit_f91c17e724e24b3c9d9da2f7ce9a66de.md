# Audit Report

## Title
Consensus Configuration Loading Error Suppression Enables Validators to Operate Under Divergent Consensus Rules

## Summary
During epoch transitions, when `OnChainConsensusConfig` deserialization fails, validators silently fall back to default configuration with fundamentally different consensus parameters (`order_vote_enabled: false`) instead of halting. This design flaw creates a fail-open vulnerability where validators could operate under incompatible consensus protocols if configuration loading failures occur non-uniformly.

## Finding Description

The `EpochManager::start_new_epoch()` function exhibits a critical inconsistency in how it handles configuration loading failures during epoch transitions.

**ValidatorSet** (critical consensus component) properly halts on failure using `.expect()` which panics immediately: [1](#0-0) 

**OnChainConsensusConfig** (equally critical) silently continues with defaults using `.unwrap_or_default()`: [2](#0-1) 

The default configuration returned on deserialization failure uses `order_vote_enabled: false`: [3](#0-2) [4](#0-3) 

While genesis and typical on-chain configurations use `order_vote_enabled: true`: [5](#0-4) 

The `order_vote_enabled` parameter controls fundamental consensus protocol behavior, with explicit checks preventing cross-compatibility. The `into_quorum_cert()` function explicitly errors when `order_vote_enabled` is true: [6](#0-5) 

Similarly, `certified_block()` errors when order votes are enabled: [7](#0-6) 

Different code paths are executed in the sync manager based on this parameter: [8](#0-7) 

Order vote processing is gated by this flag in the round manager: [9](#0-8) [10](#0-9) 

Configuration deserialization involves double BCS deserialization which can fail if the payload is missing or bytes are malformed: [11](#0-10) [12](#0-11) 

The system explicitly acknowledges that on-chain configs may not exist: [13](#0-12) 

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violations category)

This vulnerability represents a fail-open design flaw in a critical consensus component. The inconsistent error handling creates a potential consensus safety violation:

1. **Protocol Incompatibility**: The explicit error checks in `into_quorum_cert()` and `certified_block()` prove that validators with different `order_vote_enabled` settings operate incompatible consensus protocols.

2. **Fail-Open vs Fail-Safe**: ValidatorSet correctly implements fail-safe behavior (panic on error), ensuring validators cannot participate with invalid configuration. OnChainConsensusConfig implements fail-open behavior (continue with defaults), allowing validators to participate with potentially incorrect consensus parameters.

3. **Consensus Divergence Risk**: If triggered non-uniformly, validators would follow different sync logic, vote processing paths, and certificate validation rules, potentially leading to consensus inconsistencies.

This is a logic vulnerability in the design of critical consensus configuration handling, meeting the "Consensus/Safety violations" criterion where different validators could follow different consensus rules.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

While the inconsistent error handling is objectively present, triggering this non-uniformly across validators is challenging because:

- All validators read epoch configurations from the same committed blockchain state
- Configuration payload comes from deterministic on-chain state, not network messages
- Uniform failures (affecting all validators) would not cause divergence

However, non-uniform failures remain possible through:
- Local storage corruption on specific validators
- State sync implementation bugs affecting subset of nodes
- Software version differences during upgrades
- Edge cases in double BCS deserialization logic

The explicit acknowledgment in the codebase that "configs may not exist on-chain" suggests this scenario was anticipated, making the inconsistent handling between ValidatorSet and OnChainConsensusConfig a design oversight rather than impossible scenario.

## Recommendation

Implement consistent fail-safe behavior for all critical consensus configuration components:

```rust
let consensus_config = onchain_consensus_config
    .expect("failed to get OnChainConsensusConfig from payload");
```

Alternatively, if fallback behavior is required, implement explicit validation ensuring the default configuration is compatible with the expected network state, or add explicit checks during consensus operation that all validators are using compatible `order_vote_enabled` settings.

## Proof of Concept

This is a logic vulnerability in error handling design. A proof of concept would require artificially triggering deserialization failure on specific validators during epoch transitions, which would need infrastructure-level testing beyond typical unit tests. The vulnerability is proven by the code structure itself showing inconsistent error handling between equally critical consensus components.

## Notes

This represents a **defense-in-depth violation** where the fail-safe principle is not consistently applied across critical consensus components. While practical exploitation requires specific failure conditions, the design flaw is objectively present and creates unnecessary risk in consensus safety guarantees. The explicit incompatibility checks throughout the codebase prove that `order_vote_enabled` is a protocol-level parameter that must be consistent across all validators.

### Citations

**File:** consensus/src/epoch_manager.rs (L1165-1167)
```rust
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
```

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

**File:** types/src/on_chain_config/consensus_config.rs (L30-36)
```rust
    pub fn default_for_genesis() -> Self {
        Self::JolteonV2 {
            main: ConsensusConfigV1::default(),
            quorum_store_enabled: true,
            order_vote_enabled: true,
        }
    }
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

**File:** types/src/on_chain_config/consensus_config.rs (L464-468)
```rust
    fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
        let raw_bytes: Vec<u8> = bcs::from_bytes(bytes)?;
        bcs::from_bytes(&raw_bytes)
            .map_err(|e| format_err!("[on-chain config] Failed to deserialize into config: {}", e))
    }
```

**File:** consensus/consensus-types/src/wrapped_ledger_info.rs (L64-68)
```rust
    pub fn certified_block(&self, order_vote_enabled: bool) -> anyhow::Result<&BlockInfo> {
        ensure!(
            !order_vote_enabled,
            "wrapped_ledger_info.certified_block should not be called when order votes are enabled"
        );
```

**File:** consensus/consensus-types/src/wrapped_ledger_info.rs (L125-129)
```rust
    pub fn into_quorum_cert(self, order_vote_enabled: bool) -> anyhow::Result<QuorumCert> {
        ensure!(
            !order_vote_enabled,
            "wrapped_ledger_info.into_quorum_cert should not be called when order votes are enabled"
        );
```

**File:** consensus/src/block_storage/sync_manager.rs (L150-167)
```rust
        if self.order_vote_enabled {
            self.insert_ordered_cert(&sync_info.highest_ordered_cert())
                .await?;
        } else {
            // When order votes are disabled, the highest_ordered_cert().certified_block().id() need not be
            // one of the ancestors of highest_quorum_cert.certified_block().id() due to forks. So, we call
            // insert_quorum_cert instead of insert_ordered_cert as in the above case. This will ensure that
            // highest_ordered_cert().certified_block().id() is inserted the block store.
            self.insert_quorum_cert(
                &self
                    .highest_ordered_cert()
                    .as_ref()
                    .clone()
                    .into_quorum_cert(self.order_vote_enabled)?,
                &mut retriever,
            )
            .await?;
        }
```

**File:** consensus/src/round_manager.rs (L1546-1560)
```rust
    async fn process_order_vote_msg(&mut self, order_vote_msg: OrderVoteMsg) -> anyhow::Result<()> {
        if self.onchain_config.order_vote_enabled() {
            fail_point!("consensus::process_order_vote_msg", |_| {
                Err(anyhow::anyhow!("Injected error in process_order_vote_msg"))
            });

            let order_vote = order_vote_msg.order_vote();
            trace!(
                self.new_log(LogEvent::ReceiveOrderVote)
                    .remote_peer(order_vote.author()),
                epoch = order_vote.ledger_info().epoch(),
                round = order_vote.ledger_info().round(),
                id = order_vote.ledger_info().consensus_block_id(),
            );

```

**File:** consensus/src/round_manager.rs (L1795-1815)
```rust
                if self.onchain_config.order_vote_enabled() {
                    // This check is already done in safety rules. As printing the "failed to broadcast order vote"
                    // in humio logs could sometimes look scary, we are doing the same check again here.
                    if let Some(last_sent_vote) = self.round_state.vote_sent() {
                        if let Some((two_chain_timeout, _)) = last_sent_vote.two_chain_timeout() {
                            if round <= two_chain_timeout.round() {
                                return Ok(());
                            }
                        }
                    }
                    // Broadcast order vote if the QC is successfully aggregated
                    // Even if broadcast order vote fails, the function will return Ok
                    if let Err(e) = self.broadcast_order_vote(vote, qc.clone()).await {
                        warn!(
                            "Failed to broadcast order vote for QC {:?}. Error: {:?}",
                            qc, e
                        );
                    } else {
                        self.broadcast_fast_shares(qc.certified_block()).await;
                    }
                }
```

**File:** types/src/on_chain_config/mod.rs (L106-112)
```rust
    fn get<T: OnChainConfig>(&self) -> Result<T> {
        let bytes = self
            .configs
            .get(&T::CONFIG_ID)
            .ok_or_else(|| format_err!("[on-chain cfg] config not in payload"))?;
        T::deserialize_into_config(bytes)
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L277-280)
```rust
    /// Fetches the configs on-chain at the specified version.
    /// Note: We cannot assume that all configs will exist on-chain. As such, we
    /// must fetch each resource one at a time. Reconfig subscribers must be able
    /// to handle on-chain configs not existing in a reconfiguration notification.
```
