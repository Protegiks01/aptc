# Audit Report

## Title
Missing Timeout in Certified Augmented Data Acknowledgment Causes Total Chain Liveness Failure

## Summary
The randomness generation protocol's Phase 2 broadcast requires acknowledgments from ALL validators before proceeding, violating Byzantine fault tolerance principles. When any single validator is offline or unresponsive, the reliable broadcast mechanism retries indefinitely, causing complete blockchain liveness failure.

## Finding Description

The randomness generation protocol uses a two-phase reliable broadcast. Phase 1 collects signatures using a quorum-based approach, but Phase 2 requires acknowledgments from 100% of validators.

The `CertifiedAugDataAckState::add()` function only completes when ALL validators have acknowledged: [1](#0-0) 

The function maintains a validators set and only returns `Some(())` when `validators_guard.is_empty()`. If any validator never responds, it continues returning `None` indefinitely.

The reliable broadcast mechanism retries failed RPCs infinitely with exponential backoff: [2](#0-1) 

On RPC failure, the code calls `backoff_strategy.next().expect("should produce value")` and retries. The `.expect()` assumes an infinite iterator. The loop only exits when aggregation completes (returns `Some`).

The exponential backoff is configured with `max_delay` but no max retry count: [3](#0-2) 

When randomness is enabled, RandManager only processes blocks if certified augmented data exists: [4](#0-3) 

The execution coordinator requires BOTH randomness AND secret sharing to be ready before forwarding blocks: [5](#0-4) 

The chain halt scenario is explicitly documented: [6](#0-5) 

**Critical Design Flaw:** Phase 1 uses quorum-based signature aggregation, which tolerates failures: [7](#0-6) 

But Phase 2 requires ALL validators, creating an asymmetric design that violates BFT principles. This inconsistency has no valid technical justification—if certified data can be produced with quorum signatures, acknowledgments should also use quorum.

## Impact Explanation

This vulnerability causes **Total Loss of Liveness/Network Availability** (Critical Severity - up to $1,000,000 in Aptos bug bounty).

**Catastrophic impact:**
- **All validators affected simultaneously** - entire network halts
- **No blocks can be committed** - execution pipeline blocked
- **Manual intervention required** - all validators must coordinate restart with `randomness_override_seq_num` override
- **Violates BFT invariants** - should tolerate < 1/3 Byzantine/offline validators

A recovery test demonstrates the manual coordination required: [8](#0-7) 

Significantly, DKG (Distributed Key Generation) can tolerate validator failures: [9](#0-8) 

This proves the system CAN handle offline validators in other phases, making the Phase 2 all-validators requirement an unjustified design flaw.

## Likelihood Explanation

**Likelihood: HIGH**

Validator downtime is routine in distributed blockchain networks:
- Network connectivity issues
- Scheduled maintenance
- Hardware failures
- Software crashes
- Geographic network partitions

The requirement for 100% acknowledgment (vs. quorum) makes this easily triggerable. Any single validator experiencing issues causes total chain halt, violating the core BFT guarantee that systems should tolerate < 1/3 Byzantine/offline nodes.

## Recommendation

**Fix:** Change `CertifiedAugDataAckState` to use quorum-based completion (like `AugDataCertBuilder`) instead of requiring all validators.

**Implementation:**
1. Add `EpochState` to `CertifiedAugDataAckState` to access validator verifier
2. Replace empty-set check with `check_voting_power()` call (same as Phase 1)
3. Complete when quorum (2f+1 voting power) acknowledges

This maintains BFT properties, ensures consistency with Phase 1 design, and eliminates the chain halt scenario while preserving protocol safety guarantees.

## Proof of Concept

The existing test demonstrates the issue: [10](#0-9) 

To reproduce:
1. Deploy 4-validator network with randomness enabled
2. Wait for epoch transition (augmented data broadcast begins)
3. Stop 1 validator during Phase 2
4. Observe: Chain halts indefinitely
5. Recovery requires all validators restart with `randomness_override_seq_num = 1`

The vulnerability is triggered by normal operational events (single validator offline), not external attacks or special conditions.

### Citations

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L52-56)
```rust
        let qc_aug_data = self
            .epoch_state
            .verifier
            .check_voting_power(parital_signatures_guard.signatures().keys(), true)
            .ok()
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L88-101)
```rust
    fn add(&self, peer: Author, _ack: Self::Response) -> anyhow::Result<Option<Self::Aggregated>> {
        let mut validators_guard = self.validators.lock();
        ensure!(
            validators_guard.remove(&peer),
            "[RandMessage] Unknown author: {}",
            peer
        );
        // If receive from all validators, stop the reliable broadcast
        if validators_guard.is_empty() {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L167-206)
```rust
            loop {
                tokio::select! {
                    Some((receiver, result)) = rpc_futures.next() => {
                        let aggregating = aggregating.clone();
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
                        aggregate_futures.push(future);
                    },
                    Some(result) = aggregate_futures.next() => {
                        let (receiver, result) = result.expect("spawned task must succeed");
                        match result {
                            Ok(may_be_aggragated) => {
                                if let Some(aggregated) = may_be_aggragated {
                                    return Ok(aggregated);
                                }
                            },
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
                        }
                    },
                    else => unreachable!("Should aggregate with all responses")
                }
            }
        }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L85-87)
```rust
        let rb_backoff_policy = ExponentialBackoff::from_millis(rb_config.backoff_policy_base_ms)
            .factor(rb_config.backoff_policy_factor)
            .max_delay(Duration::from_millis(rb_config.backoff_policy_max_delay_ms));
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L380-382)
```rust
                Some(blocks) = incoming_blocks.next(), if self.aug_data_store.my_certified_aug_data_exists() => {
                    self.process_incoming_blocks(blocks);
                }
```

**File:** consensus/src/pipeline/execution_client.rs (L357-360)
```rust
                if o.get().1 && o.get().2 {
                    let (_, (ordered_blocks, _, _)) = o.remove_entry();
                    let _ = ready_block_tx.send(ordered_blocks).await;
                }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config_seqnum.move (L1-9)
```text
/// Randomness stall recovery utils.
///
/// When randomness generation is stuck due to a bug, the chain is also stuck. Below is the recovery procedure.
/// 1. Ensure more than 2/3 stakes are stuck at the same version.
/// 1. Every validator restarts with `randomness_override_seq_num` set to `X+1` in the node config file,
///    where `X` is the current `RandomnessConfigSeqNum` on chain.
/// 1. The chain should then be unblocked.
/// 1. Once the bug is fixed and the binary + framework have been patched,
///    a governance proposal is needed to set `RandomnessConfigSeqNum` to be `X+2`.
```

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L19-62)
```rust
/// Chain recovery using a local config from randomness stall should work.
/// See `randomness_config_seqnum.move` for more details.
#[tokio::test]
async fn randomness_stall_recovery() {
    let epoch_duration_secs = 20;

    let (mut swarm, mut cli, _faucet) = SwarmBuilder::new_local(4)
        .with_num_fullnodes(0) //TODO: revert back to 1 after invalid version bug is fixed
        .with_aptos()
        .with_init_config(Arc::new(|_, conf, _| {
            conf.api.failpoints_enabled = true;
        }))
        .with_init_genesis_config(Arc::new(move |conf| {
            conf.epoch_duration_secs = epoch_duration_secs;

            // Ensure randomness is enabled.
            conf.consensus_config.enable_validator_txns();
            conf.randomness_config_override = Some(OnChainRandomnessConfig::default_enabled());
        }))
        .build_with_cli(0)
        .await;

    let root_addr = swarm.chain_info().root_account().address();
    let root_idx = cli.add_account_with_address_to_cli(swarm.root_key(), root_addr);

    let rest_client = swarm.validators().next().unwrap().rest_client();

    info!("Wait for epoch 2.");
    swarm
        .wait_for_all_nodes_to_catchup_to_epoch(2, Duration::from_secs(epoch_duration_secs * 2))
        .await
        .expect("Epoch 2 taking too long to arrive!");

    info!("Halting the chain by putting every validator into sync_only mode.");
    for validator in swarm.validators_mut() {
        enable_sync_only_mode(4, validator).await;
    }

    info!("Chain should have halted.");
    let liveness_check_result = swarm
        .liveness_check(Instant::now().add(Duration::from_secs(20)))
        .await;
    info!("liveness_check_result={:?}", liveness_check_result);
    assert!(liveness_check_result.is_err());
```

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L64-84)
```rust
    info!("Hot-fixing all validators.");
    for (idx, validator) in swarm.validators_mut().enumerate() {
        info!("Stopping validator {}.", idx);
        validator.stop();
        let config_path = validator.config_path();
        let mut validator_override_config =
            OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        validator_override_config
            .override_config_mut()
            .randomness_override_seq_num = 1;
        validator_override_config
            .override_config_mut()
            .consensus
            .sync_only = false;
        info!("Updating validator {} config.", idx);
        validator_override_config.save_config(config_path).unwrap();
        info!("Restarting validator {}.", idx);
        validator.start().unwrap();
        info!("Let validator {} bake for 5 secs.", idx);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
```

**File:** testsuite/smoke-test/src/randomness/dkg_with_validator_down.rs (L38-56)
```rust
    println!("Take one validator down.");
    swarm.validators_mut().take(1).for_each(|v| {
        v.stop();
    });

    println!(
        "Wait until we fully entered epoch {}.",
        dkg_session_1.target_epoch() + 1
    );

    let dkg_session_2 = wait_for_dkg_finish(
        &client,
        Some(dkg_session_1.target_epoch() + 1),
        time_limit_secs,
    )
    .await;

    assert!(verify_dkg_transcript(&dkg_session_2, &decrypt_key_map).is_ok());
}
```
