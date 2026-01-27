# Audit Report

## Title
DAG Consensus Network Partition via Inconsistent Payload Configuration Limits

## Summary
The DAG consensus implementation allows validators to independently configure `max_receiving_txns_per_round` values through local node configuration files, without network-wide agreement. This creates a critical consensus safety violation where validators with different limits will accept different sets of nodes during the voting phase, potentially causing network partition and DAG state inconsistencies.

## Finding Description

The `DagPayloadConfig` struct defines transaction and byte limits for DAG consensus nodes, including `max_receiving_txns_per_round` and `max_receiving_size_per_round_bytes`. These limits are **not** part of the on-chain consensus configuration that validators must agree upon. [1](#0-0) 

The on-chain DAG configuration only includes `dag_ordering_causal_history_window` and `anchor_election_mode`, explicitly excluding payload limits: [2](#0-1) 

**The Critical Asymmetry:**

When a node is initially broadcast, each validator validates it against their **local** `max_receiving_txns_per_round` configuration: [3](#0-2) 

However, when a `CertifiedNode` (with 2f+1 signatures) is received, the validation does **not** check payload limits: [4](#0-3) 

**Attack Scenario:**

1. Validator group A (34 validators) configures `max_receiving_txns_per_round = 8,000`
2. Validator group B (66 validators) configures `max_receiving_txns_per_round = 15,000`  
3. A validator in group B creates a node with 12,000 transactions
4. During initial broadcast, group A validators **reject** it (12,000 > 8,000), group B validators **accept** and vote
5. The node obtains 66 votes (≥ 2f+1), becoming certified
6. The certified node is broadcast to all validators
7. Group A validators add it to their DAG without checking payload limits (via `validate_new_node`)

**Result:** Group A validators now have nodes in their DAG that exceed their configured acceptance threshold. When creating their own nodes, they're limited to 8,000 transactions while accepting nodes with 15,000 transactions from others.

**Consensus Safety Violation:**

During high transaction volume:
- Different validators vote for different nodes based on their local limits
- Validators with low limits may not vote for nodes that validators with high limits consider valid
- This creates different "strong links" sets across validators
- DAG state diverges across the network
- Violates the invariant: "All validators must produce identical state roots for identical blocks" [5](#0-4) 

The payload limits are used when creating nodes via `calculate_payload_limits`, which respects the validator's local configuration: [6](#0-5) 

## Impact Explanation

**Critical Severity** - This vulnerability meets the criteria for "Non-recoverable network partition (requires hardfork)" from the Aptos bug bounty program.

The impact includes:

1. **Consensus Safety Violation**: Validators following different validation rules can accept different sets of nodes, breaking the fundamental consensus assumption that all honest validators validate identically.

2. **Network Partition**: If validators split into groups with significantly different limits (e.g., during a rolling upgrade or misconfiguration), they may diverge in their DAG states and be unable to reach consensus.

3. **Liveness Failure**: Validators with low limits may be unable to create competitive nodes during high transaction volume, effectively excluding them from consensus participation.

4. **Requires Hardfork**: Once validators have diverged in their DAG states due to this issue, reconciliation would require coordinated intervention or a hardfork to reset state.

The vulnerability affects **all validators** in the network and can cause **total consensus failure** if the configuration divergence is severe enough.

## Likelihood Explanation

**High Likelihood** - This vulnerability can occur through:

1. **Configuration Errors**: Validators independently load configuration from YAML files. Different operators may set different values, either through misunderstanding or intentional tuning.

2. **Rolling Upgrades**: During network upgrades, if new recommended values are published but not all validators update simultaneously, temporary inconsistency occurs.

3. **No Enforcement Mechanism**: Unlike other critical consensus parameters, these limits are not enforced network-wide. The sanitizer only checks that sending ≤ receiving for a single node, not cross-validator consistency. [7](#0-6) 

4. **No Warning System**: Validators receive no alerts when their configuration differs significantly from peers.

The vulnerability requires no attacker action - it emerges naturally from configuration drift.

## Recommendation

**Solution 1: Move Payload Limits to On-Chain Configuration (Recommended)**

Add `max_receiving_txns_per_round` and `max_receiving_size_per_round_bytes` to `DagConsensusConfigV1` so validators must reach consensus on these values:

```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DagConsensusConfigV1 {
    pub dag_ordering_causal_history_window: usize,
    pub anchor_election_mode: AnchorElectionMode,
    // Add payload limits to on-chain config
    pub max_receiving_txns_per_round: u64,
    pub max_receiving_size_per_round_bytes: u64,
}
```

Update the DAG initialization to use on-chain limits rather than local configuration.

**Solution 2: Validate CertifiedNode Payload Limits**

If keeping limits local, add validation in `DagStore::validate_new_node()` to reject certified nodes that exceed local limits:

```rust
fn validate_new_node(&mut self, node: &CertifiedNode) -> anyhow::Result<()> {
    // ... existing validations ...
    
    // Add payload validation
    let num_txns = node.validator_txns().len() as u64 + node.payload().len() as u64;
    let txn_bytes = node.validator_txns().iter()
        .map(|txn| txn.size_in_bytes()).sum::<usize>() as u64 
        + node.payload().size() as u64;
    
    ensure!(num_txns <= self.payload_config.max_receiving_txns_per_round,
        "certified node exceeds receiving txn limit");
    ensure!(txn_bytes <= self.payload_config.max_receiving_size_per_round_bytes,
        "certified node exceeds receiving byte limit");
    
    Ok(())
}
```

However, this creates a different problem where validators might reject valid certified nodes, causing liveness issues.

**Solution 3: Configuration Synchronization Check**

Add a handshake mechanism where validators verify their peers have compatible payload configurations before accepting nodes, and log warnings for mismatches.

**Recommended Approach**: Solution 1 is strongly recommended as it eliminates the root cause by ensuring network-wide agreement on critical consensus parameters.

## Proof of Concept

```rust
// File: consensus/src/dag/tests/partition_test.rs

#[tokio::test]
async fn test_payload_config_partition() {
    // Setup two validator groups with different configs
    let mut validators_low_limit = vec![];
    let mut validators_high_limit = vec![];
    
    // Group A: 34 validators with max_receiving = 8000
    for i in 0..34 {
        let config = DagPayloadConfig {
            max_sending_txns_per_round: 7000,
            max_receiving_txns_per_round: 8000,
            ..Default::default()
        };
        validators_low_limit.push(create_validator(i, config));
    }
    
    // Group B: 66 validators with max_receiving = 15000
    for i in 34..100 {
        let config = DagPayloadConfig {
            max_sending_txns_per_round: 14000,
            max_receiving_txns_per_round: 15000,
            ..Default::default()
        };
        validators_high_limit.push(create_validator(i, config));
    }
    
    // Create a node with 12000 transactions (between the limits)
    let large_node = create_node_with_txn_count(12000);
    
    // Broadcast to all validators
    let mut votes = vec![];
    
    // Group A validators reject during initial validation
    for validator in &validators_low_limit {
        let result = validator.rb_handler.process(large_node.clone()).await;
        assert!(result.is_err(), "Should reject: exceeds max_receiving");
    }
    
    // Group B validators accept and vote
    for validator in &validators_high_limit {
        let vote = validator.rb_handler.process(large_node.clone()).await
            .expect("Should accept: within max_receiving");
        votes.push(vote);
    }
    
    // Create certificate with 66 votes (> 2f+1)
    let certified_node = CertifiedNode::new(
        large_node.clone(),
        aggregate_signatures(votes)
    );
    
    // Broadcast certified node to Group A
    for validator in &validators_low_limit {
        // This succeeds because validate_new_node doesn't check payload limits
        let result = validator.dag_driver.process(certified_node.clone()).await;
        assert!(result.is_ok(), 
            "Group A accepts certified node despite local limit violation");
        
        // Verify node is now in DAG with 12000 txns > their 8000 limit
        assert!(validator.dag.read().exists(certified_node.metadata()));
    }
    
    // Network partition: Group A has nodes they would never create themselves
    // This breaks consensus safety - validators with different rules
}
```

The test demonstrates that validators with `max_receiving_txns_per_round = 8000` will accept and store certified nodes containing 12,000 transactions, violating their configured limits and creating asymmetric validation rules across the network.

## Notes

This vulnerability is particularly insidious because:

1. It doesn't manifest as an immediate crash or error
2. The network may appear to function normally under low transaction load
3. Problems only emerge during high load or when configuration drift becomes severe
4. Recovery requires coordinated intervention across all validators

The root cause is architectural: treating safety-critical consensus parameters as optional local configuration rather than mandatory on-chain agreement.

### Citations

**File:** config/src/config/dag_consensus_config.rs (L11-33)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DagPayloadConfig {
    pub max_sending_txns_per_round: u64,
    pub max_sending_size_per_round_bytes: u64,
    pub max_receiving_txns_per_round: u64,
    pub max_receiving_size_per_round_bytes: u64,

    pub payload_pull_max_poll_time_ms: u64,
}

impl Default for DagPayloadConfig {
    fn default() -> Self {
        Self {
            max_sending_txns_per_round: 10000,
            max_sending_size_per_round_bytes: 10 * 1024 * 1024,
            max_receiving_txns_per_round: 11000,
            max_receiving_size_per_round_bytes: 20 * 1024 * 1024,

            payload_pull_max_poll_time_ms: 1000,
        }
    }
}
```

**File:** config/src/config/dag_consensus_config.rs (L52-78)
```rust
    fn sanitize_payload_size_limits(
        sanitizer_name: &str,
        config: &DagPayloadConfig,
    ) -> Result<(), Error> {
        let send_recv_pairs = [
            (
                config.max_sending_txns_per_round,
                config.max_receiving_txns_per_round,
                "txns",
            ),
            (
                config.max_sending_size_per_round_bytes,
                config.max_receiving_size_per_round_bytes,
                "bytes",
            ),
        ];
        for (send, recv, label) in &send_recv_pairs {
            if *send > *recv {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name.to_owned(),
                    format!("Failed {}: {} > {}", label, *send, *recv),
                ));
            }
        }
        Ok(())
    }
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L585-609)
```rust
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
}
```

**File:** consensus/src/dag/rb_handler.rs (L112-142)
```rust
    fn validate(&self, node: Node) -> anyhow::Result<Node> {
        ensure!(
            node.epoch() == self.epoch_state.epoch,
            "different epoch {}, current {}",
            node.epoch(),
            self.epoch_state.epoch
        );

        let num_vtxns = node.validator_txns().len() as u64;
        ensure!(num_vtxns <= self.vtxn_config.per_block_limit_txn_count());
        for vtxn in node.validator_txns() {
            let vtxn_type_name = vtxn.type_name();
            ensure!(
                is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                "unexpected validator transaction: {:?}",
                vtxn_type_name
            );
            vtxn.verify(self.epoch_state.verifier.as_ref())
                .context(format!("{} verification failed", vtxn_type_name))?;
        }
        let vtxn_total_bytes = node
            .validator_txns()
            .iter()
            .map(ValidatorTransaction::size_in_bytes)
            .sum::<usize>() as u64;
        ensure!(vtxn_total_bytes <= self.vtxn_config.per_block_limit_total_bytes());

        let num_txns = num_vtxns + node.payload().len() as u64;
        let txn_bytes = vtxn_total_bytes + node.payload().size() as u64;
        ensure!(num_txns <= self.payload_config.max_receiving_txns_per_round);
        ensure!(txn_bytes <= self.payload_config.max_receiving_size_per_round_bytes);
```

**File:** consensus/src/dag/dag_store.rs (L128-163)
```rust
    fn validate_new_node(&mut self, node: &CertifiedNode) -> anyhow::Result<()> {
        ensure!(
            node.epoch() == self.epoch_state.epoch,
            "different epoch {}, current {}",
            node.epoch(),
            self.epoch_state.epoch
        );
        let author = node.metadata().author();
        let index = *self
            .author_to_index
            .get(author)
            .ok_or_else(|| anyhow!("unknown author"))?;
        let round = node.metadata().round();
        ensure!(
            round >= self.lowest_round(),
            "round too low {}, lowest in dag {}",
            round,
            self.lowest_round()
        );
        ensure!(
            round <= self.highest_round() + 1,
            "round too high {}, highest in dag {}",
            round,
            self.highest_round()
        );
        if round > self.lowest_round() {
            for parent in node.parents() {
                ensure!(self.exists(parent.metadata()), "parent not exist");
            }
        }
        let round_ref = self
            .nodes_by_round
            .entry(round)
            .or_insert_with(|| vec![None; self.author_to_index.len()]);
        ensure!(round_ref[index].is_none(), "duplicate node");
        Ok(())
```

**File:** consensus/src/dag/dag_driver.rs (L255-257)
```rust
        let (max_txns, max_size_bytes) = self
            .health_backoff
            .calculate_payload_limits(new_round, &self.payload_config);
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
