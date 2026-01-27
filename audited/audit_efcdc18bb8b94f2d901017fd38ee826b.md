# Audit Report

## Title
Missing Network Capacity Validation for max_txns_after_filtering Leading to Silent Proposal Broadcast Failures

## Summary
The `max_txns_after_filtering` parameter in consensus configuration is not validated against network message size limits (MAX_MESSAGE_SIZE of 64 MiB). When misconfigured with excessively high values alongside high `max_sending_block_bytes`, the resulting serialized ProposalMsg can exceed network propagation capacity, causing silent broadcast failures and transaction loss.

## Finding Description
The `max_txns_after_filtering` field limits the count of unique transactions in a block after deduplication. [1](#0-0) 

When a validator creates a proposal, this parameter is used without validation against the actual network capacity to propagate the resulting message. [2](#0-1) 

The network layer enforces a MAX_MESSAGE_SIZE limit of 64 MiB during message streaming. [3](#0-2) 

When this limit is exceeded, the stream fails with an error. [4](#0-3) 

However, the broadcast failure is silently ignored (only logged as a warning) in the consensus layer. [5](#0-4) 

The proposal never reaches other validators, and the error is not surfaced to the proposal generator. [6](#0-5) 

The ConsensusConfig sanitizer validates that sender limits are less than receiver limits, but does NOT validate against network message size limits. [7](#0-6) 

**Attack Scenario:**
1. Operator misconfigures: `max_txns_after_filtering = 100,000` and `max_sending_block_bytes = 55 MB`
2. Validator creates proposal with 100,000 small transactions fitting within 55 MB
3. ProposalMsg serialization includes Block + SyncInfo + signatures + BCS overhead, exceeding 64 MiB
4. Network layer rejects message during streaming
5. Broadcast silently fails with only warning log
6. Other validators never receive proposal
7. All 100,000 transactions are lost for that round

## Impact Explanation
This constitutes **Medium severity** as it causes transaction loss requiring operator intervention. Per the Aptos bug bounty criteria, "Limited funds loss or manipulation" and "State inconsistencies requiring intervention" qualify as Medium severity.

While the misconfigured node can recover by reducing limits, transactions are lost during the affected rounds, and the issue is not detected through normal error propagation—only through manual log inspection.

## Likelihood Explanation
**Likelihood: Low-Medium**

This requires operator misconfiguration of consensus parameters beyond safe defaults. However:
- Default values (1,800 transactions, 3 MB) are safe
- No automated validation prevents dangerous configurations
- Operators tuning for high throughput may inadvertently exceed limits
- The silent failure mode makes detection difficult

The issue is less likely in production with default configurations but becomes probable in custom deployments optimizing for high transaction throughput.

## Recommendation
Add comprehensive validation in the ConsensusConfig sanitizer:

```rust
// In consensus_config.rs, add to sanitize():
fn validate_against_network_limits(
    sanitizer_name: &str,
    config: &ConsensusConfig,
) -> Result<(), Error> {
    // Import MAX_APPLICATION_MESSAGE_SIZE from network_config
    const MAX_SAFE_BLOCK_SIZE: u64 = MAX_APPLICATION_MESSAGE_SIZE as u64;
    
    // Account for ProposalMsg overhead (Block + SyncInfo + signatures)
    const PROPOSAL_OVERHEAD_ESTIMATE: u64 = 10 * 1024 * 1024; // 10 MB
    
    if config.max_sending_block_bytes + PROPOSAL_OVERHEAD_ESTIMATE > MAX_SAFE_BLOCK_SIZE {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name.to_owned(),
            format!(
                "max_sending_block_bytes {} may exceed network capacity with overhead",
                config.max_sending_block_bytes
            ),
        ));
    }
    
    Ok(())
}
```

Additionally, improve error handling in proposal broadcasting to surface failures to the proposer rather than silently logging.

## Proof of Concept

```rust
#[test]
fn test_oversized_proposal_broadcast_failure() {
    // Configuration that could cause network limit violation
    let config = ConsensusConfig {
        max_sending_block_txns: 100_000,
        max_sending_block_txns_after_filtering: 100_000,
        max_sending_block_bytes: 55 * 1024 * 1024, // 55 MB
        ..Default::default()
    };
    
    // Create proposal with many transactions
    // When serialized with Block + SyncInfo + overhead,
    // total message size would exceed 64 MiB MAX_MESSAGE_SIZE
    
    // Expected: Config sanitizer should reject this configuration
    // Actual: Configuration is accepted, proposal broadcast fails silently
    
    assert!(ConsensusConfig::sanitize(
        &create_node_config_with(config),
        NodeType::Validator,
        Some(ChainId::testnet())
    ).is_err(), "Should reject configuration exceeding network capacity");
}
```

**Notes**

This vulnerability represents a validation gap where configuration values can be set that exceed network propagation capacity. While it requires operator misconfiguration rather than direct exploitation by an unprivileged attacker, it violates the principle of defense-in-depth by not preventing invalid configurations at the sanitization layer. The silent failure mode exacerbates the issue by making detection difficult without detailed log analysis.

### Citations

**File:** consensus/consensus-types/src/payload_pull_params.rs (L19-19)
```rust
    pub max_txns_after_filtering: u64,
```

**File:** consensus/src/liveness/proposal_generator.rs (L654-668)
```rust
            .pull_payload(
                PayloadPullParameters {
                    max_poll_time: self.quorum_store_poll_time.saturating_sub(proposal_delay),
                    max_txns: max_block_txns,
                    max_txns_after_filtering: max_block_txns_after_filtering,
                    soft_max_txns_after_filtering: max_txns_from_block_to_execute
                        .unwrap_or(max_block_txns_after_filtering),
                    max_inline_txns: self.max_inline_txns,
                    maybe_optqs_payload_pull_params,
                    user_txn_filter: payload_filter,
                    pending_ordering,
                    pending_uncommitted_blocks: pending_blocks.len(),
                    recent_max_fill_fraction: max_fill_fraction,
                    block_timestamp: timestamp,
                },
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/protocols/stream/mod.rs (L267-273)
```rust
        let message_data_len = message.data_len();
        ensure!(
            message_data_len <= self.max_message_size,
            "Message length {} exceeds max message size {}!",
            message_data_len,
            self.max_message_size,
        );
```

**File:** consensus/src/network.rs (L402-408)
```rust
        if let Err(err) = self
            .consensus_network_client
            .send_to_many(other_validators, msg)
        {
            warn!(error = ?err, "Error broadcasting message");
        }
    }
```

**File:** consensus/src/round_manager.rs (L546-546)
```rust
        network.broadcast_proposal(proposal_msg).await;
```

**File:** config/src/config/consensus_config.rs (L525-529)
```rust
        // Sender block limits must be <= receiver block limits
        Self::sanitize_send_recv_block_limits(&sanitizer_name, &node_config.consensus)?;

        // Quorum store batches must be <= consensus blocks
        Self::sanitize_batch_block_limits(&sanitizer_name, &node_config.consensus)?;
```
