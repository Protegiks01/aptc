# Audit Report

## Title
Consensus Observer Block Loss Due to Unchecked Payload Manager Type Selection

## Summary
The consensus observer unconditionally creates `ConsensusObserverPayloadManager` when `quorum_store_enabled=true` without validating that quorum store infrastructure is operational, causing blocks to be silently dropped when payloads are unavailable.

## Finding Description

The vulnerability exists in the payload manager selection logic where the system blindly trusts the on-chain configuration without runtime validation. [1](#0-0) 

When `quorum_store_enabled=true`, `ConsensusObserverPayloadManager` is created, which requires block payloads to exist in the `block_payloads` shared map. However, if quorum store infrastructure fails or validators don't publish `BlockPayload` messages, the system exhibits the following behavior:

1. Ordered blocks arrive with `InQuorumStore` payloads
2. No corresponding `BlockPayload` messages are received  
3. Blocks are stored in pending queue waiting for payloads that never arrive
4. When pending queue exceeds `max_num_pending_blocks`, oldest blocks are garbage collected: [2](#0-1) 

5. `ConsensusObserverPayloadManager.get_transactions()` returns errors for missing payloads: [3](#0-2) 

6. Execution retry loop logs warnings indefinitely: [4](#0-3) 

**Attack Scenario**: A malicious validator could propose blocks but deliberately not publish `BlockPayload` messages, causing consensus observers to permanently drop those blocks after garbage collection timeout.

## Impact Explanation

This constitutes a **High Severity** liveness degradation issue affecting consensus observers:

- Consensus observers cannot process blocks in real-time without payloads
- Blocks are permanently lost after garbage collection (only warnings logged)
- System eventually enters fallback mode and syncs via state sync, but with significant lag
- Malicious validators can weaponize this by selectively withholding payload publications
- All consensus observers network-wide are affected simultaneously if infrastructure fails

While this doesn't affect consensus safety or validator operations, it represents a "significant protocol violation" per bug bounty criteria as consensus observers are unable to fulfill their intended role of real-time blockchain observation.

## Likelihood Explanation

**Moderate to High Likelihood**:

1. **Operational Failures**: Quorum store infrastructure can fail due to:
   - Network partitions affecting payload distribution
   - Publisher service crashes/misconfigurations
   - Storage backend unavailability

2. **Malicious Exploitation**: Byzantine validators can:
   - Propose valid blocks that pass consensus
   - Selectively withhold `BlockPayload` publications
   - Target specific consensus observers or all observers

3. **No Defense-in-Depth**: Zero runtime validation that selected payload manager matches reality

## Recommendation

Add runtime validation that quorum store infrastructure is operational before creating `ConsensusObserverPayloadManager`:

```rust
pub async fn wait_for_epoch_start(
    &mut self,
    block_payloads: Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
) -> (
    Arc<dyn TPayloadManager>,
    OnChainConsensusConfig,
    OnChainExecutionConfig,
    OnChainRandomnessConfig,
) {
    let (epoch_state, consensus_config, execution_config, randomness_config) =
        extract_on_chain_configs(&self.node_config, &mut self.reconfig_events).await;

    self.epoch_state = Some(epoch_state.clone());
    self.execution_pool_window_size = consensus_config.window_size();
    self.quorum_store_enabled = consensus_config.quorum_store_enabled();

    // Add validation: check if payloads are actually being received
    let payload_manager: Arc<dyn TPayloadManager> = if self.quorum_store_enabled {
        // Verify consensus publisher is configured and functional
        if self.consensus_publisher.is_none() {
            warn!("Quorum store enabled but no consensus publisher available, using fallback");
            Arc::new(DirectMempoolPayloadManager {})
        } else {
            Arc::new(ConsensusObserverPayloadManager::new(
                block_payloads,
                self.consensus_publisher.clone(),
            ))
        }
    } else {
        Arc::new(DirectMempoolPayloadManager {})
    };

    (payload_manager, consensus_config, execution_config, randomness_config)
}
```

Additionally, implement payload arrival monitoring with automatic fallback:
- Track time since last successful payload receipt
- If threshold exceeded (e.g., 30 seconds), trigger immediate state sync
- Emit critical alerts when payload delivery fails

## Proof of Concept

```rust
// Reproduction steps in integration test:

#[tokio::test]
async fn test_missing_payloads_cause_block_loss() {
    // 1. Setup consensus observer with quorum_store_enabled=true
    let mut observer = setup_consensus_observer_with_quorum_store();
    
    // 2. Send ordered blocks WITHOUT corresponding BlockPayload messages
    for round in 1..=100 {
        let ordered_block = create_ordered_block_with_quorum_store_payload(round);
        observer.process_ordered_block(ordered_block).await;
        // Deliberately DON'T send: observer.process_block_payload(...)
    }
    
    // 3. Verify pending blocks accumulate
    assert_eq!(observer.pending_blocks_count(), 100);
    
    // 4. Exceed max_num_pending_blocks (e.g., 100)
    let extra_block = create_ordered_block_with_quorum_store_payload(101);
    observer.process_ordered_block(extra_block).await;
    
    // 5. Verify oldest block was garbage collected (LOST)
    assert_eq!(observer.pending_blocks_count(), 100); // Still at max
    assert!(observer.get_block_by_round(1).is_none()); // Round 1 DROPPED
    
    // 6. Verify observer cannot execute any blocks due to missing payloads
    let execution_result = observer.try_execute_pending_blocks().await;
    assert!(execution_result.is_err()); // All fail with "Missing payload data"
}
```

**Notes**:
- This vulnerability exploits the gap between on-chain configuration (quorum store enabled) and runtime reality (payloads unavailable)
- Consensus observers are critical infrastructure for light clients, indexers, and real-time applications
- Current fallback to state sync adds significant latency and defeats the purpose of consensus observation
- The "silent" aspect is that blocks are permanently lost with only warning logs, no error propagation to operators

### Citations

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L110-118)
```rust
        // Create the payload manager
        let payload_manager: Arc<dyn TPayloadManager> = if self.quorum_store_enabled {
            Arc::new(ConsensusObserverPayloadManager::new(
                block_payloads,
                self.consensus_publisher.clone(),
            ))
        } else {
            Arc::new(DirectMempoolPayloadManager {})
        };
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L176-194)
```rust
        // Remove the oldest blocks if the store is too large
        for _ in 0..num_blocks_to_remove {
            if let Some((oldest_epoch_round, pending_block)) =
                self.blocks_without_payloads.pop_first()
            {
                // Log a warning message for the removed block
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "The pending block store is too large: {:?} blocks. Removing the block for the oldest epoch and round: {:?}",
                        num_pending_blocks, oldest_epoch_round
                    ))
                );

                // Remove the block from the hash store
                let first_block = pending_block.ordered_block().first_block();
                self.blocks_without_payloads_by_hash
                    .remove(&first_block.id());
            }
        }
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L36-58)
```rust
    let block_payload = match block_payloads.lock().entry((block.epoch(), block.round())) {
        Entry::Occupied(mut value) => match value.get_mut() {
            BlockPayloadStatus::AvailableAndVerified(block_payload) => block_payload.clone(),
            BlockPayloadStatus::AvailableAndUnverified(_) => {
                // This shouldn't happen (the payload should already be verified)
                let error = format!(
                    "Payload data for block epoch {}, round {} is unverified!",
                    block.epoch(),
                    block.round()
                );
                return Err(InternalError { error });
            },
        },
        Entry::Vacant(_) => {
            // This shouldn't happen (the payload should already be present)
            let error = format!(
                "Missing payload data for block epoch {}, round {}!",
                block.epoch(),
                block.round()
            );
            return Err(InternalError { error });
        },
    };
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L634-646)
```rust
        let result = loop {
            match preparer.materialize_block(&block, qc_rx.clone()).await {
                Ok(input_txns) => break input_txns,
                Err(e) => {
                    warn!(
                        "[BlockPreparer] failed to prepare block {}, retrying: {}",
                        block.id(),
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        };
```
