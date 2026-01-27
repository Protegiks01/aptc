# Audit Report

## Title
Zero Timeout Configuration Causes Complete Transaction Processing Denial of Service in DirectMempoolQuorumStore

## Summary
Setting `mempool_txn_pull_timeout_ms=0` in the consensus configuration causes all mempool transaction pull requests to timeout instantly, resulting in empty blocks being proposed continuously. This creates a complete denial of service for user transaction processing while consensus appears to function normally.

## Finding Description

The `DirectMempoolQuorumStore` uses the `mempool_txn_pull_timeout_ms` configuration parameter to set a timeout when pulling transactions from the mempool. When this value is set to 0, `Duration::from_millis(0)` creates a zero-duration timeout. [1](#0-0) 

With `tokio::time::timeout`, a zero-duration timeout expires immediately on the first poll. Since the mempool pull operation is asynchronous (using a oneshot channel callback), it cannot complete synchronously on the first poll, causing the timeout to fire every time.

When the timeout fires, an error is returned and caught in `handle_block_request`, which then returns an empty transaction vector: [2](#0-1) 

This empty payload is then sent to consensus, resulting in blocks that contain zero user transactions despite the mempool potentially having transactions available.

**Critical Issue**: The configuration has NO validation to prevent this dangerous value: [3](#0-2) 

The default value is 1000ms, but there are no sanitization checks in the `ConfigSanitizer` implementation to ensure this value is greater than zero: [4](#0-3) 

## Impact Explanation

This constitutes **High Severity** according to Aptos bug bounty criteria:

- **Validator node slowdowns**: Nodes with this misconfiguration will continuously propose empty blocks, severely degrading network transaction throughput
- **Significant protocol violations**: The network appears healthy (blocks are produced and committed) but is functionally unusable for processing user transactions

If multiple validators have this misconfiguration, the network experiences severe transaction processing degradation. While consensus safety is not violated (blocks are still valid and properly ordered), the network fails to fulfill its primary purpose of processing transactions.

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - the system should gracefully handle mempool operations within reasonable timeouts, not degrade to zero throughput.

## Likelihood Explanation

**Likelihood: Medium-Low**

This requires a configuration change by a validator operator, which could occur through:
- Accidental misconfiguration during node setup
- Copy-paste errors in configuration files
- Misunderstanding of the timeout parameter (thinking 0 means "no timeout" rather than "instant timeout")
- Malicious insider action (though validator operators are generally trusted)

The lack of validation makes this easier to trigger accidentally than it should be.

## Recommendation

Add configuration validation in `ConsensusConfig::sanitize()` to ensure `mempool_txn_pull_timeout_ms` has a reasonable minimum value:

```rust
fn sanitize_mempool_timeouts(
    sanitizer_name: &str,
    config: &ConsensusConfig,
) -> Result<(), Error> {
    const MIN_MEMPOOL_PULL_TIMEOUT_MS: u64 = 100;
    
    if config.mempool_txn_pull_timeout_ms < MIN_MEMPOOL_PULL_TIMEOUT_MS {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name.to_owned(),
            format!(
                "mempool_txn_pull_timeout_ms must be at least {}ms, got {}ms",
                MIN_MEMPOOL_PULL_TIMEOUT_MS,
                config.mempool_txn_pull_timeout_ms
            ),
        ));
    }
    
    if config.mempool_executed_txn_timeout_ms == 0 {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name.to_owned(),
            "mempool_executed_txn_timeout_ms cannot be zero".to_owned(),
        ));
    }
    
    Ok(())
}
```

Then call this validation method in `ConsensusConfig::sanitize()` after the existing checks.

## Proof of Concept

**Configuration-based PoC:**

1. Create a node configuration file with `mempool_txn_pull_timeout_ms: 0` in the consensus section:

```yaml
consensus:
  mempool_txn_pull_timeout_ms: 0
  # ... other config
```

2. Start the validator node with this configuration
3. Observe that the node continuously logs "GetBatch failed" errors
4. Monitor block proposals - all blocks will have empty payloads
5. Submit user transactions to mempool - they will never be included in blocks
6. Network continues producing blocks but processes zero user transactions

**Observable behavior:**
- Counter `REQUEST_FAIL_LABEL` increments for every pull attempt
- Counter `REQUEST_SUCCESS_LABEL` never increments
- All proposed blocks contain `Payload::DirectMempool(vec![])` (empty)
- Mempool may contain transactions, but they're never pulled
- Transaction throughput drops to zero while block production continues

---

**Notes:**

While this vulnerability requires validator operator access to trigger (through configuration), it represents a critical oversight in configuration validation that could lead to accidental denial of service. The system should fail-fast during configuration validation rather than allowing a dangerous zero-timeout value that renders the node unable to include transactions in blocks.

### Citations

**File:** consensus/src/quorum_store/direct_mempool_quorum_store.rs (L69-86)
```rust
        match monitor!(
            "pull_txn",
            timeout(
                Duration::from_millis(self.mempool_txn_pull_timeout_ms),
                callback_rcv
            )
            .await
        ) {
            Err(_) => Err(anyhow::anyhow!(
                "[direct_mempool_quorum_store] did not receive GetBatchResponse on time"
            )),
            Ok(resp) => match resp.map_err(anyhow::Error::from)?? {
                QuorumStoreResponse::GetBatchResponse(txns) => Ok(txns),
                _ => Err(anyhow::anyhow!(
                    "[direct_mempool_quorum_store] did not receive expected GetBatchResponse"
                )),
            },
        }
```

**File:** consensus/src/quorum_store/direct_mempool_quorum_store.rs (L106-115)
```rust
        let (txns, result) = match self
            .pull_internal(max_txns, max_bytes, return_non_full, exclude_txns)
            .await
        {
            Err(_) => {
                error!("GetBatch failed");
                (vec![], counters::REQUEST_FAIL_LABEL)
            },
            Ok(txns) => (txns, counters::REQUEST_SUCCESS_LABEL),
        };
```

**File:** config/src/config/consensus_config.rs (L220-234)
```rust
impl Default for ConsensusConfig {
    fn default() -> ConsensusConfig {
        ConsensusConfig {
            max_network_channel_size: 1024,
            max_sending_block_txns: MAX_SENDING_BLOCK_TXNS,
            max_sending_block_txns_after_filtering: MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
            max_sending_opt_block_txns_after_filtering: MAX_SENDING_OPT_BLOCK_TXNS_AFTER_FILTERING,
            max_sending_block_bytes: 3 * 1024 * 1024, // 3MB
            max_receiving_block_txns: *MAX_RECEIVING_BLOCK_TXNS,
            max_sending_inline_txns: 100,
            max_sending_inline_bytes: 200 * 1024,       // 200 KB
            max_receiving_block_bytes: 6 * 1024 * 1024, // 6MB
            max_pruned_blocks_in_mem: 100,
            mempool_executed_txn_timeout_ms: 1000,
            mempool_txn_pull_timeout_ms: 1000,
```

**File:** config/src/config/consensus_config.rs (L503-532)
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
```
