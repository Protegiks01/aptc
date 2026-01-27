# Audit Report

## Title
Transaction Filter Configuration Bypass Allows Consensus Disagreement Between Validators

## Summary
The `NodeConfig::sanitize()` function fails to validate the `transaction_filters` field, allowing validators to configure different consensus transaction filters. This enables validators to disagree on which block proposals to vote for, violating consensus determinism and potentially causing liveness failures or network partitions.

## Finding Description

The node configuration sanitizer at line 144 of `node_config_loader.rs` calls `NodeConfig::sanitize()` to validate security-critical configuration fields before a node starts. [1](#0-0) 

However, the `NodeConfig::sanitize()` implementation does not sanitize the `transaction_filters` field, which contains a `consensus_filter` that directly affects consensus voting behavior: [2](#0-1) 

The `NodeConfig` struct contains a `transaction_filters: TransactionFiltersConfig` field that includes multiple filters, most critically the `consensus_filter`: [3](#0-2) [4](#0-3) 

During consensus, validators use this `consensus_filter` to validate block proposals. When a validator receives a proposal containing inline transactions, the `RoundManager` checks if any transactions are denied by the filter and **refuses to vote** if denied transactions are found: [5](#0-4) 

The actual filtering logic confirms that validators drop proposals containing denied inline transactions: [6](#0-5) 

**Attack Scenario:**

1. Validator A configures their node with `consensus_filter` that denies transactions from address X
2. Validator B runs with the default configuration (no filter, allows all transactions)
3. A block proposer creates a proposal containing an inline transaction from address X
4. Validator B votes for the proposal (transaction is allowed)
5. Validator A refuses to vote (transaction is denied by their filter)
6. The validators disagree on proposal validity, violating consensus determinism

Since there is no sanitization enforcing uniform consensus filters across validators, this configuration divergence can occur through:
- Accidental misconfiguration during node setup
- Intentional configuration by a malicious validator operator
- Different node configuration templates being deployed

## Impact Explanation

This vulnerability has **High Severity** impact based on the Aptos bug bounty criteria for "Significant protocol violations":

1. **Consensus Determinism Violation**: The fundamental invariant that all validators must agree on proposal validity is broken. Validators with different filters will vote differently on the same proposals.

2. **Liveness Failures**: If enough validators have different filter configurations, the network may be unable to reach quorum on certain proposals, causing the blockchain to stall.

3. **Network Partition Risk**: Different validator subsets could effectively split into groups that vote on different sets of proposals, creating partitioned views of consensus.

Unlike other sanitized fields (e.g., ExecutionConfig requiring paranoid verification on mainnet, or ConsensusConfig preventing test-only features), there is no enforcement ensuring consensus-critical transaction filters are uniformly configured across validators: [7](#0-6) [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium to High**

While the default configuration has all transaction filters disabled (preventing immediate exploitation), the likelihood is significant because:

1. **No Protection Mechanism**: There is zero validation preventing validators from configuring different consensus filters on mainnet
2. **Configuration Flexibility**: Validators have full control over their node configurations and may legitimately configure filters for operational reasons without realizing the consensus impact
3. **No Documentation Warning**: There are no warnings in the configuration system about consensus filters needing to be identical across validators
4. **Test Evidence**: The codebase includes explicit tests demonstrating that validators will not vote on proposals with denied transactions: [9](#0-8) 

## Recommendation

Implement a `ConfigSanitizer` for `TransactionFiltersConfig` that enforces mainnet security requirements. The sanitizer should ensure consensus-critical filters are either disabled or uniformly configured.

**Recommended Fix:**

Add sanitization for TransactionFiltersConfig in `config/src/config/transaction_filters_config.rs`:

```rust
impl ConfigSanitizer for TransactionFiltersConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let transaction_filters = &node_config.transaction_filters;
        
        // For mainnet, consensus filters must be disabled to ensure
        // all validators vote on the same proposals
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if transaction_filters.consensus_filter.is_enabled() {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "consensus_filter must be disabled on mainnet nodes to ensure consensus determinism!".into(),
                    ));
                }
                
                if transaction_filters.execution_filter.is_enabled() {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "execution_filter must be disabled on mainnet nodes to ensure execution determinism!".into(),
                    ));
                }
            }
        }
        
        Ok(())
    }
}
```

Then add the sanitizer call to `NodeConfig::sanitize()` in `config/src/config/config_sanitizer.rs`:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // ... existing sanitizers ...
        StorageConfig::sanitize(node_config, node_type, chain_id)?;
        InternalIndexerDBConfig::sanitize(node_config, node_type, chain_id)?;
        TransactionFiltersConfig::sanitize(node_config, node_type, chain_id)?; // ADD THIS
        sanitize_validator_network_config(node_config, node_type, chain_id)?;
        
        Ok(())
    }
}
```

## Proof of Concept

**Scenario**: Two validators with different consensus filter configurations fail to reach agreement.

**Setup Configuration for Validator A** (`node_config_validator_a.yaml`):
```yaml
transaction_filters:
  consensus_filter:
    filter_enabled: true
    block_transaction_filter:
      rules:
        - matchers:
            - Transaction:
                Sender: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
          allow: false
        - matchers: []
          allow: true
```

**Setup Configuration for Validator B** (`node_config_validator_b.yaml`):
```yaml
transaction_filters:
  consensus_filter:
    filter_enabled: false
```

**Exploitation Steps**:

1. Deploy Validator A with the filter configuration that denies transactions from address `0x1234...`
2. Deploy Validator B with the default configuration (no filtering)
3. Wait for a block proposer to create a proposal containing an inline transaction from the denied address
4. Observe that Validator A refuses to vote (logs: "Proposal contains denied inline transactions")
5. Observe that Validator B votes on the proposal normally
6. If enough validators have divergent configurations, consensus cannot reach quorum

**Expected Result**: The network experiences liveness degradation or complete stalling when proposals contain transactions that are filtered differently by validators.

**Current State**: No sanitization prevents this configuration divergence, allowing the vulnerability to manifest in production.

## Notes

Additional unsanitized fields identified during this investigation that may warrant separate security review:

- `consensus_observer: ConsensusObserverConfig` - Not sanitized, though appears less consensus-critical
- `dkg: DKGConfig` - Not sanitized, simple buffer size configuration
- `indexer: IndexerConfig` - Not sanitized, indexer-specific settings
- `indexer_table_info: IndexerTableInfoConfig` - Not sanitized
- `jwk_consensus: JWKConsensusConfig` - Not sanitized, another buffer size
- `node_startup: NodeStartupConfig` - Not sanitized, but contains the skip_config_sanitizer flag itself
- `peer_monitoring_service: PeerMonitoringServiceConfig` - Not sanitized
- `randomness_override_seq_num: u64` - Not sanitized, used to force-disable randomness

The most critical finding is the `transaction_filters.consensus_filter` as it directly impacts consensus voting behavior, creating an immediate path to consensus disagreement.

### Citations

**File:** config/src/config/node_config_loader.rs (L127-145)
```rust
fn optimize_and_sanitize_node_config(
    node_config: &mut NodeConfig,
    local_config_yaml: Value,
) -> Result<(), Error> {
    // Extract the node type and chain ID from the node config
    let (node_type, chain_id) = extract_node_type_and_chain_id(node_config);

    // Print the extracted node type and chain ID
    println!(
        "Identified node type ({:?}) and chain ID ({:?}) from node config!",
        node_type, chain_id
    );

    // Optimize the node config
    NodeConfig::optimize(node_config, &local_config_yaml, node_type, chain_id)?;

    // Sanitize the node config
    NodeConfig::sanitize(node_config, node_type, chain_id)
}
```

**File:** config/src/config/config_sanitizer.rs (L39-71)
```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }

        // Sanitize all of the sub-configs
        AdminServiceConfig::sanitize(node_config, node_type, chain_id)?;
        ApiConfig::sanitize(node_config, node_type, chain_id)?;
        BaseConfig::sanitize(node_config, node_type, chain_id)?;
        ConsensusConfig::sanitize(node_config, node_type, chain_id)?;
        DagConsensusConfig::sanitize(node_config, node_type, chain_id)?;
        ExecutionConfig::sanitize(node_config, node_type, chain_id)?;
        sanitize_failpoints_config(node_config, node_type, chain_id)?;
        sanitize_fullnode_network_configs(node_config, node_type, chain_id)?;
        IndexerGrpcConfig::sanitize(node_config, node_type, chain_id)?;
        InspectionServiceConfig::sanitize(node_config, node_type, chain_id)?;
        LoggerConfig::sanitize(node_config, node_type, chain_id)?;
        MempoolConfig::sanitize(node_config, node_type, chain_id)?;
        NetbenchConfig::sanitize(node_config, node_type, chain_id)?;
        StateSyncConfig::sanitize(node_config, node_type, chain_id)?;
        StorageConfig::sanitize(node_config, node_type, chain_id)?;
        InternalIndexerDBConfig::sanitize(node_config, node_type, chain_id)?;
        sanitize_validator_network_config(node_config, node_type, chain_id)?;

        Ok(()) // All configs passed validation
    }
}
```

**File:** config/src/config/node_config.rs (L35-92)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default)]
    pub admin_service: AdminServiceConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub base: BaseConfig,
    #[serde(default)]
    pub consensus: ConsensusConfig,
    #[serde(default)]
    pub consensus_observer: ConsensusObserverConfig,
    #[serde(default)]
    pub dag_consensus: DagConsensusConfig,
    #[serde(default)]
    pub dkg: DKGConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub failpoints: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_node_networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub indexer: IndexerConfig,
    #[serde(default)]
    pub indexer_grpc: IndexerGrpcConfig,
    #[serde(default)]
    pub indexer_table_info: IndexerTableInfoConfig,
    #[serde(default)]
    pub inspection_service: InspectionServiceConfig,
    #[serde(default)]
    pub jwk_consensus: JWKConsensusConfig,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub mempool: MempoolConfig,
    #[serde(default)]
    pub netbench: Option<NetbenchConfig>,
    #[serde(default)]
    pub node_startup: NodeStartupConfig,
    #[serde(default)]
    pub peer_monitoring_service: PeerMonitoringServiceConfig,
    /// In a randomness stall, set this to be on-chain `RandomnessConfigSeqNum` + 1.
    /// Once enough nodes restarted with the new value, the chain should unblock with randomness disabled.
    #[serde(default)]
    pub randomness_override_seq_num: u64,
    #[serde(default)]
    pub state_sync: StateSyncConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub transaction_filters: TransactionFiltersConfig,
    #[serde(default)]
    pub validator_network: Option<NetworkConfig>,
    #[serde(default)]
    pub indexer_db_config: InternalIndexerDBConfig,
}
```

**File:** config/src/config/transaction_filters_config.rs (L10-18)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFiltersConfig {
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
}
```

**File:** consensus/src/round_manager.rs (L1202-1214)
```rust
        // If the proposal contains any inline transactions that need to be denied
        // (e.g., due to filtering) drop the message and do not vote for the block.
        if let Err(error) = self
            .block_store
            .check_denied_inline_transactions(&proposal, &self.block_txn_filter_config)
        {
            counters::REJECTED_PROPOSAL_DENY_TXN_COUNT.inc();
            bail!(
                "[RoundManager] Proposal for block {} contains denied inline transactions: {}. Dropping proposal!",
                proposal.id(),
                error
            );
        }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L308-347)
```rust
    fn check_denied_inline_transactions(
        &self,
        block: &Block,
        block_txn_filter_config: &BlockTransactionFilterConfig,
    ) -> anyhow::Result<()> {
        // If the filter is disabled, return early
        if !block_txn_filter_config.is_enabled() {
            return Ok(());
        }

        // Get the inline transactions for the block proposal
        let inline_transactions = get_inline_transactions(block);
        if inline_transactions.is_empty() {
            return Ok(());
        }

        // Fetch the block metadata
        let block_id = block.id();
        let block_author = block.author();
        let block_epoch = block.epoch();
        let block_timestamp = block.timestamp_usecs();

        // Identify any denied inline transactions
        let block_transaction_filter = block_txn_filter_config.block_transaction_filter();
        let denied_inline_transactions = block_transaction_filter.get_denied_block_transactions(
            block_id,
            block_author,
            block_epoch,
            block_timestamp,
            inline_transactions,
        );
        if !denied_inline_transactions.is_empty() {
            return Err(anyhow::anyhow!(
                "Inline transactions for QuorumStorePayload denied by block transaction filter: {:?}",
                denied_inline_transactions
            ));
        }

        Ok(()) // No transactions were denied
    }
```

**File:** config/src/config/execution_config.rs (L157-187)
```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}
```

**File:** config/src/config/consensus_config.rs (L503-533)
```rust
impl ConfigSanitizer for ConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // Verify that the safety rules and quorum store configs are valid
        SafetyRulesConfig::sanitize(node_config, node_type, chain_id)?;
        QuorumStoreConfig::sanitize(node_config, node_type, chain_id)?;

        // Verify that the consensus-only feature is not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && is_consensus_only_perf_test_enabled() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "consensus-only-perf-test should not be enabled in mainnet!".to_string(),
                ));
            }
        }

        // Sender block limits must be <= receiver block limits
        Self::sanitize_send_recv_block_limits(&sanitizer_name, &node_config.consensus)?;

        // Quorum store batches must be <= consensus blocks
        Self::sanitize_batch_block_limits(&sanitizer_name, &node_config.consensus)?;

        Ok(())
    }
}
```

**File:** consensus/src/round_manager_tests/txn_filter_proposal_test.rs (L31-90)
```rust
// Verify that the round manager will not vote if a block
// proposal contains any denied inline transactions.
#[test]
fn test_no_vote_on_denied_inline_transactions() {
    // Test both direct mempool and quorum store payloads
    for use_quorum_store_payloads in [false, true] {
        // Create test transactions
        let transactions = create_test_transactions();

        // Create a block filter config that denies the first transaction sender
        let block_txn_filter = BlockTransactionFilter::empty()
            .add_multiple_matchers_filter(false, vec![BlockTransactionMatcher::Transaction(
                TransactionMatcher::Sender(transactions[0].sender()),
            )])
            .add_all_filter(true);
        let block_txn_filter_config = BlockTransactionFilterConfig::new(true, block_txn_filter);

        // Create a new network playground
        let runtime = consensus_runtime();
        let mut playground = NetworkPlayground::new(runtime.handle().clone());

        // Create a new consensus node. Note: To observe the votes we're
        // going to check proposal processing on the non-proposer node
        // (which will send the votes to the proposer).
        let mut nodes = NodeSetup::create_nodes(
            &mut playground,
            runtime.handle().clone(),
            1,
            None,
            None,
            Some(block_txn_filter_config),
            None,
            None,
            None,
            use_quorum_store_payloads,
        );
        let node = &mut nodes[0];

        // Create a block proposal with inline transactions that will be denied
        let payload = create_payload(transactions, use_quorum_store_payloads);
        let denied_block = Block::new_proposal(
            payload,
            1,
            1,
            certificate_for_genesis(),
            &node.signer,
            Vec::new(),
        )
        .unwrap();

        // Verify that the node does not vote on a block with denied inline transactions
        timed_block_on(&runtime, async {
            assert!(node
                .round_manager
                .process_proposal(denied_block)
                .await
                .is_err());
        });
    }
}
```
