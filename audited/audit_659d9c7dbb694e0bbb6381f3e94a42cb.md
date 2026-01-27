# Audit Report

## Title
Insecure Default Health Backpressure Configuration in DAG Consensus Allows Consensus Instability During Network Degradation

## Summary
The `DagHealthConfig` struct uses empty vectors as defaults for critical health backpressure mechanisms (`chain_backoff_config` and `pipeline_backpressure_config`), which disables adaptive block size reduction during network stress. When validators deploy with minimal or default configuration, they continue proposing full-size blocks during network degradation, potentially causing consensus liveness issues and chain instability.

## Finding Description

The DAG consensus configuration in Aptos Core contains a critical misconfiguration vulnerability where insecure defaults disable health-based backpressure mechanisms. [1](#0-0) 

The `DagHealthConfig::default()` implementation sets both `chain_backoff_config` and `pipeline_backpressure_config` to empty vectors. These fields control critical adaptive mechanisms that reduce block sizes and add delays when:
- Validator voting power participation drops (chain health)
- Execution pipeline latency increases (pipeline backpressure) [2](#0-1) 

When `chain_backoff_config` is empty, `ChainHealthBackoffConfig::get_backoff()` returns `None`, causing no chain health backpressure to be applied. [3](#0-2) 

Similarly, when `pipeline_backpressure_config` is empty, `PipelineBackpressureConfig::get_backoff()` returns `None`, disabling pipeline backpressure. [4](#0-3) 

In `HealthBackoff::calculate_payload_limits()`, when these return `None`, they default to `u64::MAX`, effectively removing all adaptive limits. The misconfigured validator will continue proposing blocks with full payload limits (10,000 transactions, 10MB) regardless of network conditions. [5](#0-4) 

The configuration sanitizer only validates payload size limits, not the presence of health backpressure configuration, allowing this insecure default to pass validation.

In contrast, the standard `ConsensusConfig` has comprehensive defaults with 6-7 backpressure levels: [6](#0-5) [7](#0-6) 

**Attack Scenario:**
While validator operators are trusted, this represents a **systemic deployment risk** where:
1. Operators deploy DAG consensus validators with minimal configuration
2. Due to `#[serde(default)]`, missing health config fields use empty defaults
3. During network stress (partition, slow execution, low participation), properly configured validators reduce block sizes
4. Misconfigured validators continue proposing full blocks, worsening congestion
5. This can cause consensus degradation, increased latency, and potential liveness failures

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Misconfigured validators can cause prolonged consensus degradation requiring manual intervention
- The issue affects consensus resilience during adverse network conditions
- While not causing immediate consensus safety violations, it degrades the liveness guarantee under stress
- Multiple misconfigured validators could amplify the impact, potentially requiring emergency configuration updates

## Likelihood Explanation

**Likelihood: High**
- Validators deploying with minimal configuration is a common operational practice
- No warning or validation alerts operators about the insecure default
- Sample configuration files don't include DAG health config examples
- The on-chain `DagConsensusConfigV1` doesn't enforce these settings
- Operators may not realize health backpressure is disabled by default [8](#0-7) 

## Recommendation

**Immediate Fix:**
Change `DagHealthConfig::default()` to include safe, production-ready backpressure configurations matching the standard consensus defaults:

```rust
impl Default for DagHealthConfig {
    fn default() -> Self {
        Self {
            chain_backoff_config: vec![
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 80,
                    max_sending_block_txns_after_filtering_override: 10000,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backoff_proposal_delay_ms: 150,
                },
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 78,
                    max_sending_block_txns_after_filtering_override: 2000,
                    max_sending_block_bytes_override: 1024 * 1024 + 512,
                    backoff_proposal_delay_ms: 300,
                },
                // Additional levels...
            ],
            voter_pipeline_latency_limit_ms: 30_000,
            pipeline_backpressure_config: vec![
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1200,
                    max_sending_block_txns_after_filtering_override: 10000,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 50,
                },
                // Additional levels...
            ],
        }
    }
}
```

**Additional Safeguards:**
1. Add sanitizer validation to warn when health configs are empty:
```rust
impl ConfigSanitizer for DagConsensusConfig {
    fn sanitize(...) -> Result<(), Error> {
        DagPayloadConfig::sanitize(node_config, node_type, chain_id)?;
        
        if node_config.dag_consensus.health_config.chain_backoff_config.is_empty() {
            warn!("DAG consensus chain_backoff_config is empty - health backpressure disabled");
        }
        
        if node_config.dag_consensus.health_config.pipeline_backpressure_config.is_empty() {
            warn!("DAG consensus pipeline_backpressure_config is empty - pipeline backpressure disabled");
        }
        
        Ok(())
    }
}
```

2. Update sample configurations to include health backpressure examples
3. Add documentation explaining the importance of these settings

## Proof of Concept

**Reproduction Steps:**

1. Create a minimal DAG consensus configuration file (`minimal_dag_config.yaml`):
```yaml
base:
    data_dir: "/opt/aptos/data"
    role: "validator"

# No dag_consensus section - will use all defaults
```

2. Load and inspect the configuration:
```rust
use aptos_config::config::NodeConfig;

fn main() {
    let config = NodeConfig::load_from_path("minimal_dag_config.yaml").unwrap();
    
    // These will be empty vectors due to defaults
    assert!(config.dag_consensus.health_config.chain_backoff_config.is_empty());
    assert!(config.dag_consensus.health_config.pipeline_backpressure_config.is_empty());
    
    println!("Health backpressure is DISABLED - validator will not adapt to network stress");
}
```

3. During DAG consensus operation with degraded network (simulated):
```rust
// In HealthBackoff::calculate_payload_limits
let chain_backoff = self.chain_health
    .get_round_payload_limits(round)
    .unwrap_or((u64::MAX, u64::MAX));  // Returns MAX due to empty config
    
let pipeline_backoff = self.pipeline_health
    .get_payload_limits()
    .unwrap_or((u64::MAX, u64::MAX));  // Returns MAX due to empty config

// Result: Full payload limits even during network stress
// max_txns = min(10000, u64::MAX, u64::MAX) = 10000
// max_bytes = min(10*1024*1024, u64::MAX, u64::MAX) = 10MB
```

**Expected Behavior (with proper defaults):**
When voting power drops to 76%, limits should reduce to 500 txns and 1MB, not remain at 10,000 txns and 10MB.

## Notes

This vulnerability represents a **configuration security anti-pattern** where insecure defaults can cause system-wide degradation. While validator operators are trusted to configure their nodes correctly, the system should provide secure defaults that don't require expert knowledge to avoid consensus instability.

### Citations

**File:** config/src/config/dag_consensus_config.rs (L140-155)
```rust
#[serde(default, deny_unknown_fields)]
pub struct DagHealthConfig {
    pub chain_backoff_config: Vec<ChainHealthBackoffValues>,
    pub voter_pipeline_latency_limit_ms: u64,
    pub pipeline_backpressure_config: Vec<PipelineBackpressureValues>,
}

impl Default for DagHealthConfig {
    fn default() -> Self {
        Self {
            chain_backoff_config: Vec::new(),
            voter_pipeline_latency_limit_ms: 30_000,
            pipeline_backpressure_config: Vec::new(),
        }
    }
}
```

**File:** config/src/config/dag_consensus_config.rs (L169-179)
```rust
impl ConfigSanitizer for DagConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        DagPayloadConfig::sanitize(node_config, node_type, chain_id)?;

        Ok(())
    }
}
```

**File:** consensus/src/liveness/proposal_generator.rs (L75-103)
```rust
    pub fn get_backoff(&self, voting_power_ratio: f64) -> Option<&ChainHealthBackoffValues> {
        if self.backoffs.is_empty() {
            return None;
        }

        if voting_power_ratio < 2.0 / 3.0 {
            error!("Voting power ratio {} is below 2f + 1", voting_power_ratio);
        }
        let voting_power_percentage = (voting_power_ratio * 100.0).floor() as usize;
        if voting_power_percentage > 100 {
            error!(
                "Voting power participation percentatge {} is > 100, before rounding {}",
                voting_power_percentage, voting_power_ratio
            );
        }
        self.backoffs
            .range(voting_power_percentage..)
            .next()
            .map(|(_, v)| {
                sample!(
                    SampleRate::Duration(Duration::from_secs(10)),
                    warn!(
                        "Using chain health backoff config for {} voting power percentage: {:?}",
                        voting_power_percentage, v
                    )
                );
                v
            })
    }
```

**File:** consensus/src/liveness/proposal_generator.rs (L137-143)
```rust
    pub fn get_backoff(
        &self,
        pipeline_pending_latency: Duration,
    ) -> Option<&PipelineBackpressureValues> {
        if self.backoffs.is_empty() {
            return None;
        }
```

**File:** consensus/src/dag/health/backoff.rs (L30-72)
```rust
    pub fn calculate_payload_limits(
        &self,
        round: Round,
        payload_config: &DagPayloadConfig,
    ) -> (u64, u64) {
        let chain_backoff = self
            .chain_health
            .get_round_payload_limits(round)
            .unwrap_or((u64::MAX, u64::MAX));
        let pipeline_backoff = self
            .pipeline_health
            .get_payload_limits()
            .unwrap_or((u64::MAX, u64::MAX));
        let voting_power_ratio = self.chain_health.voting_power_ratio(round);

        let max_txns_per_round = [
            payload_config.max_sending_txns_per_round,
            chain_backoff.0,
            pipeline_backoff.0,
        ]
        .into_iter()
        .min()
        .expect("must not be empty");

        let max_size_per_round_bytes = [
            payload_config.max_sending_size_per_round_bytes,
            chain_backoff.1,
            pipeline_backoff.1,
        ]
        .into_iter()
        .min()
        .expect("must not be empty");

        // TODO: figure out receiver side checks
        let max_txns = max_txns_per_round.saturating_div(
            (self.epoch_state.verifier.len() as f64 * voting_power_ratio).ceil() as u64,
        );
        let max_txn_size_bytes = max_size_per_round_bytes.saturating_div(
            (self.epoch_state.verifier.len() as f64 * voting_power_ratio).ceil() as u64,
        );

        (max_txns, max_txn_size_bytes)
    }
```

**File:** config/src/config/consensus_config.rs (L263-319)
```rust
            pipeline_backpressure: vec![
                PipelineBackpressureValues {
                    // pipeline_latency looks how long has the oldest block still in pipeline
                    // been in the pipeline.
                    // Block enters the pipeline after consensus orders it, and leaves the
                    // pipeline once quorum on execution result among validators has been reached
                    // (so-(badly)-called "commit certificate"), meaning 2f+1 validators have finished execution.
                    back_pressure_pipeline_latency_limit_ms: 1200,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 50,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1500,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 100,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1900,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 200,
                },
                // with execution backpressure, only later start reducing block size
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 2500,
                    max_sending_block_txns_after_filtering_override: 1000,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 3500,
                    max_sending_block_txns_after_filtering_override: 200,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 4500,
                    max_sending_block_txns_after_filtering_override: 30,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 6000,
                    // in practice, latencies and delay make it such that ~2 blocks/s is max,
                    // meaning that most aggressively we limit to ~10 TPS
                    // For transactions that are more expensive than that, we should
                    // instead rely on max gas per block to limit latency.
                    max_sending_block_txns_after_filtering_override: 5,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
            ],
```

**File:** config/src/config/consensus_config.rs (L321-360)
```rust
            chain_health_backoff: vec![
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 80,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backoff_proposal_delay_ms: 150,
                },
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 78,
                    max_sending_block_txns_after_filtering_override: 2000,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backoff_proposal_delay_ms: 300,
                },
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 76,
                    max_sending_block_txns_after_filtering_override: 500,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backoff_proposal_delay_ms: 300,
                },
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 74,
                    max_sending_block_txns_after_filtering_override: 100,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backoff_proposal_delay_ms: 300,
                },
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 72,
                    max_sending_block_txns_after_filtering_override: 25,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backoff_proposal_delay_ms: 300,
                },
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 70,
                    // in practice, latencies and delay make it such that ~2 blocks/s is max,
                    // meaning that most aggressively we limit to ~10 TPS
                    // For transactions that are more expensive than that, we should
                    // instead rely on max gas per block to limit latency.
                    max_sending_block_txns_after_filtering_override: 5,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
```

**File:** types/src/on_chain_config/consensus_config.rs (L584-608)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DagConsensusConfigV1 {
    pub dag_ordering_causal_history_window: usize,
    pub anchor_election_mode: AnchorElectionMode,
}

impl Default for DagConsensusConfigV1 {
    /// It is primarily used as `default_if_missing()`.
    fn default() -> Self {
        Self {
            dag_ordering_causal_history_window: 10,
            anchor_election_mode: AnchorElectionMode::LeaderReputation(
                LeaderReputationType::ProposerAndVoterV2(ProposerAndVoterConfig {
                    active_weight: 1000,
                    inactive_weight: 10,
                    failed_weight: 1,
                    failure_threshold_percent: 10,
                    proposer_window_num_validators_multiplier: 10,
                    voter_window_num_validators_multiplier: 1,
                    weight_by_voting_power: true,
                    use_history_from_previous_epoch_max_count: 5,
                }),
            ),
        }
    }
```
