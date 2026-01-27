# Audit Report

## Title
Validator Crash Due to Unreachable Panic on Configuration State Mismatch in ProofManager

## Summary
The `ProofManager::handle_proposal_request()` function contains an `unreachable!()` macro at line 109 that triggers when receiving `PayloadFilter::DirectMempool`. If this code path is executed due to system state inconsistency during quorum store configuration transitions, it will panic and crash the validator's consensus component, causing that validator to become unavailable for block proposals. [1](#0-0) 

## Finding Description

The vulnerability stems from the interaction between payload type filtering and the quorum store configuration state. The system has two payload handling modes:

1. **DirectMempool mode** (quorum_store_enabled=false): Uses `DirectMempoolQuorumStore` 
2. **QuorumStore mode** (quorum_store_enabled=true): Uses `ProofManager`

The `PayloadFilter` enum has three variants: `Empty`, `DirectMempool`, and `InQuorumStore`. When generating block proposals, the filter is created from ancestor blocks in the BlockStore: [2](#0-1) 

The critical issue is in the `From<&Vec<&Payload>>` implementation for `PayloadFilter`, which checks if ANY payload in the exclusion set is DirectMempool: [3](#0-2) 

If any ancestor block contains a `DirectMempool` payload, the entire filter becomes `PayloadFilter::DirectMempool` variant, which is then sent to `ProofManager`, triggering the panic.

**Attack Scenario:**

While normal verification should prevent mismatched payload types: [4](#0-3) 

A problematic scenario can occur during epoch transitions when the `quorum_store_enabled` configuration changes:

1. System operates with `quorum_store_enabled=false` (DirectMempool mode)
2. Blocks are committed with `DirectMempool` payloads
3. Governance proposal changes `quorum_store_enabled=true`
4. Epoch transition occurs, `ProofManager` starts
5. New `BlockStore` is created from recovery data including old blocks: [5](#0-4) 

6. Validator becomes leader and generates proposal
7. Ancestor blocks include old `DirectMempool` payloads  
8. `PayloadFilter::DirectMempool` is created and sent to `ProofManager`
9. `unreachable!()` panics, crashing the validator

## Impact Explanation

This is a **High Severity** issue according to Aptos bug bounty criteria:
- **Validator node crashes**: The panic causes the `ProofManager` task to abort
- **Loss of proposal capability**: The affected validator cannot generate new blocks
- **Partial network availability impact**: While consensus continues with other validators, network capacity is reduced

The impact is limited to the specific validator experiencing the panic, not network-wide consensus failure, which is why it's High rather than Critical.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires specific conditions:
1. A quorum store configuration transition from disabled to enabled
2. Block generation during the transition period where old blocks are still in the ancestor chain
3. The affected validator being selected as leader

However, configuration changes through governance are legitimate operational events. The `failpoint` mechanism at line 1524 in `epoch_manager.rs` suggests the developers test quorum store enable/disable scenarios: [6](#0-5) 

This indicates the transition is a real concern and could occur in production.

## Recommendation

Replace the `unreachable!()` panic with graceful error handling that logs the issue and returns an appropriate error or empty payload:

```rust
pub(crate) fn handle_proposal_request(&mut self, msg: GetPayloadCommand) {
    let GetPayloadCommand::GetPayloadRequest(request) = msg;

    let excluded_batches: HashSet<_> = match request.filter {
        PayloadFilter::Empty => HashSet::new(),
        PayloadFilter::DirectMempool(_) => {
            error!(
                "Received DirectMempool filter in ProofManager, this indicates a configuration mismatch. \
                Returning empty payload to maintain liveness."
            );
            // Return empty response rather than panicking
            let response = Payload::empty(true, self.allow_batches_without_pos_in_proposal);
            let res = GetPayloadResponse::GetPayloadResponse(response);
            let _ = request.callback.send(Ok(res));
            return;
        },
        PayloadFilter::InQuorumStore(batches) => batches,
    };
    
    // ... rest of function
}
```

Additionally, add validation during epoch transitions to ensure payload type consistency:

```rust
// In epoch_manager.rs during BlockStore initialization
fn validate_payload_consistency(blocks: &[Block], quorum_store_enabled: bool) -> Result<()> {
    for block in blocks {
        if let Some(payload) = block.payload() {
            let is_direct = payload.is_direct();
            if quorum_store_enabled && is_direct {
                warn!("Found DirectMempool payload in block {} during QuorumStore mode initialization", 
                      block.id());
            }
        }
    }
    Ok(())
}
```

## Proof of Concept

Due to the complexity of simulating epoch transitions and configuration changes, a full PoC would require:

```rust
// Pseudo-code demonstrating the vulnerability path
#[test]
fn test_payload_filter_mismatch_panic() {
    // 1. Create BlockStore with DirectMempool payload blocks
    let direct_payload = Payload::DirectMempool(vec![]);
    let blocks = create_test_blocks_with_payload(direct_payload);
    
    // 2. Initialize ProofManager (simulating quorum_store_enabled=true)
    let proof_manager = ProofManager::new(
        /* params */
        allow_batches_without_pos_in_proposal: true,
        enable_payload_v2: false,
    );
    
    // 3. Create PayloadFilter from DirectMempool blocks
    let exclude_payload: Vec<_> = blocks.iter()
        .flat_map(|block| block.payload())
        .collect();
    let filter = PayloadFilter::from(&exclude_payload);
    
    // 4. Send request to ProofManager
    // This will panic at the unreachable!() line
    let request = GetPayloadRequest {
        filter: filter, // This is PayloadFilter::DirectMempool
        // ... other fields
    };
    
    // Expected: panic!("internal error: entered unreachable code")
    proof_manager.handle_proposal_request(GetPayloadCommand::GetPayloadRequest(request));
}
```

The test would demonstrate that `ProofManager` panics when receiving a `DirectMempool` filter, confirming the vulnerability.

## Notes

The symmetric issue exists in `DirectMempoolQuorumStore` which also has an `unreachable!()` for the opposite case: [7](#0-6) 

Both locations should be fixed with proper error handling to ensure system resilience during configuration transitions.

### Citations

**File:** consensus/src/quorum_store/proof_manager.rs (L106-112)
```rust
        let excluded_batches: HashSet<_> = match request.filter {
            PayloadFilter::Empty => HashSet::new(),
            PayloadFilter::DirectMempool(_) => {
                unreachable!()
            },
            PayloadFilter::InQuorumStore(batches) => batches,
        };
```

**File:** consensus/src/liveness/proposal_generator.rs (L585-589)
```rust
        let exclude_payload: Vec<_> = pending_blocks
            .iter()
            .flat_map(|block| block.payload())
            .collect();
        let payload_filter = PayloadFilter::from(&exclude_payload);
```

**File:** consensus/consensus-types/src/common.rs (L580-631)
```rust
        match (quorum_store_enabled, self) {
            (false, Payload::DirectMempool(_)) => Ok(()),
            (true, Payload::InQuorumStore(proof_with_status)) => {
                Self::verify_with_cache(&proof_with_status.proofs, verifier, proof_cache)
            },
            (true, Payload::InQuorumStoreWithLimit(proof_with_status)) => Self::verify_with_cache(
                &proof_with_status.proof_with_data.proofs,
                verifier,
                proof_cache,
            ),
            (true, Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _))
            | (true, Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _)) => {
                Self::verify_with_cache(&proof_with_data.proofs, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    inline_batches.iter().map(|(info, txns)| (info, txns)),
                )?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V1(p))) => {
                let proof_with_data = p.proof_with_data();
                Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    p.inline_batches()
                        .iter()
                        .map(|batch| (batch.info(), batch.transactions())),
                )?;
                Self::verify_opt_batches(verifier, p.opt_batches())?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V2(p))) => {
                if true {
                    bail!("OptQuorumStorePayload::V2 cannot be accepted yet");
                }
                #[allow(unreachable_code)]
                {
                    let proof_with_data = p.proof_with_data();
                    Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                    Self::verify_inline_batches(
                        p.inline_batches()
                            .iter()
                            .map(|batch| (batch.info(), batch.transactions())),
                    )?;
                    Self::verify_opt_batches(verifier, p.opt_batches())?;
                    Ok(())
                }
            },
            (_, _) => Err(anyhow::anyhow!(
                "Wrong payload type. Expected Payload::InQuorumStore {} got {} ",
                quorum_store_enabled,
                self
            )),
        }
```

**File:** consensus/consensus-types/src/common.rs (L772-787)
```rust
        let direct_mode = exclude_payloads.iter().any(|payload| payload.is_direct());

        if direct_mode {
            let mut exclude_txns = Vec::new();
            for payload in exclude_payloads {
                if let Payload::DirectMempool(txns) = payload {
                    for txn in txns {
                        exclude_txns.push(TransactionSummary {
                            sender: txn.sender(),
                            replay_protector: txn.replay_protector(),
                            hash: txn.committed_hash(),
                        });
                    }
                }
            }
            PayloadFilter::DirectMempool(exclude_txns)
```

**File:** consensus/src/epoch_manager.rs (L887-899)
```rust
        let block_store = Arc::new(BlockStore::new(
            Arc::clone(&self.storage),
            recovery_data,
            self.execution_client.clone(),
            self.config.max_pruned_blocks_in_mem,
            Arc::clone(&self.time_service),
            self.config.vote_back_pressure_limit,
            payload_manager,
            onchain_consensus_config.order_vote_enabled(),
            onchain_consensus_config.window_size(),
            self.pending_blocks.clone(),
            Some(pipeline_builder),
        ));
```

**File:** consensus/src/epoch_manager.rs (L1523-1526)
```rust
    fn enable_quorum_store(&mut self, onchain_config: &OnChainConsensusConfig) -> bool {
        fail_point!("consensus::start_new_epoch::disable_qs", |_| false);
        onchain_config.quorum_store_enabled()
    }
```

**File:** consensus/src/quorum_store/direct_mempool_quorum_store.rs (L98-104)
```rust
        let exclude_txns = match payload_filter {
            PayloadFilter::DirectMempool(exclude_txns) => exclude_txns,
            PayloadFilter::InQuorumStore(_) => {
                unreachable!("Unknown payload_filter: {}", payload_filter)
            },
            PayloadFilter::Empty => Vec::new(),
        };
```
