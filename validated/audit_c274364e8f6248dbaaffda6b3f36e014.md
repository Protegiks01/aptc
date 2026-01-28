# Audit Report

## Title
Byzantine Validators Can Halt Blockchain via Threshold Starvation in Secret Sharing Randomness Generation

## Summary
Byzantine validators (up to 1/3 of the validator set) can cause a complete blockchain halt by strategically withholding their secret shares. The reconstruction threshold for randomness generation is calculated based on the secrecy threshold (50%) rather than the BFT quorum requirement (67%), creating insufficient buffer against network delays and allowing Byzantine validators to prevent consensus progress indefinitely.

## Finding Description

The Aptos consensus protocol uses distributed secret sharing for randomness generation. The vulnerability exists in how the reconstruction threshold is calculated in the DKG rounding algorithm.

The threshold formula uses the **secrecy threshold** (50%) to set the minimum shares required for reconstruction: [1](#0-0) 

This calculation bases the threshold on `secrecy_threshold_in_stake_ratio` rather than the BFT-aligned `reconstruct_threshold_in_stake_ratio` (67%).

For validator sets with equal weights, this produces a threshold of `ceil(n * 0.5) + 1`, as confirmed in the test implementation: [2](#0-1) 

The default thresholds are explicitly defined as: [3](#0-2) 

Mainnet configuration demonstrates the vulnerability in practice. With 129 validators and total weight 414, the reconstruction threshold is only 228 weights (~55% of total), with an actual reconstruction threshold in stake ratio of ~60.5%: [4](#0-3) 

The aggregation logic strictly enforces this threshold with no exceptions: [5](#0-4) 

Blocks cannot proceed without randomness and remain in the queue indefinitely: [6](#0-5) 

There is **no automatic timeout mechanism**. Recovery requires manual intervention via configuration override: [7](#0-6) 

**Attack Scenario:**
- Network has 100 validators with equal weight
- Reconstruction threshold = 51 shares (51%)
- Byzantine validators (33) withhold shares
- Honest validators: 67 available
- If 17+ honest validators experience network delays: only 50 shares collected
- 50 < 51 → threshold never met → blocks stuck indefinitely → chain halts

For mainnet: With threshold at 228/414 (~55%), Byzantine validators controlling 33% can block progress if just 12% of total stake experiences delays.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program, specifically matching the "Total Loss of Liveness/Network Availability" category. The standard BFT consensus quorum requires 2/3 + 1 voting power: [8](#0-7) 

However, the randomness threshold is set at only ~55-60%, creating a dangerous gap. Byzantine validators can:

1. **Permanently halt all block production** - Blocks cannot proceed without randomness
2. **Freeze all transactions** - No new transactions can be processed during the halt
3. **Require coordinated manual intervention** - Every validator must restart with configuration overrides
4. **Hold the network hostage** - Attack can persist until manual recovery is performed

The vulnerability breaks the liveness guarantee of BFT consensus by setting the threshold below the 2/3 quorum requirement, making the system vulnerable to the combination of Byzantine behavior (≤1/3 validators) and normal network variance.

## Likelihood Explanation

**HIGH Likelihood** - This attack is practical and realistic:

1. **Attacker Capability**: Requires only 1/3 Byzantine validators, which is the standard BFT threat model assumption. No additional privileges needed.

2. **Attack Complexity**: LOW - Byzantine validators simply withhold shares (passive attack, no complex protocol manipulation required).

3. **Network Conditions**: Normal network delays naturally occur in distributed systems. The 12% buffer on mainnet (or 17% for equal-weight scenarios) can easily be exceeded during periods of network congestion or latency spikes.

4. **Detection Difficulty**: Hard to distinguish malicious withholding from legitimate network delays or validator issues, making the attack stealthy.

5. **Recovery Cost**: HIGH - Requires manual configuration changes and coordinated validator restarts across the entire network, causing extended downtime.

The gap between the reconstruction threshold (~55-60%) and the BFT honest validator guarantee (≥67%) is only 7-12% of the validator set, which represents normal network variance in real-world deployments.

## Recommendation

**Fix the threshold calculation to align with BFT requirements:**

1. Modify the reconstruction threshold calculation to use `reconstruct_threshold_in_stake_ratio` (67%) instead of `secrecy_threshold_in_stake_ratio` (50%) in the primary formula, ensuring adequate buffer for Byzantine behavior combined with network delays.

2. Implement an automatic timeout mechanism for randomness generation to prevent indefinite blocking. After a timeout period, the system should either:
   - Retry with backoff
   - Automatically trigger a recovery procedure
   - Escalate to governance-based intervention

3. Add monitoring and alerting for share aggregation metrics to detect potential threshold starvation attacks early.

The threshold should be set such that any subset of honest validators (≥67%) can reliably meet it even with Byzantine validators withholding shares and reasonable network delays.

## Proof of Concept

The vulnerability can be demonstrated using the existing test infrastructure. The mainnet test already shows the problematic configuration:

```rust
// From types/src/dkg/real_dkg/rounding/tests.rs
// Mainnet has 129 validators, total weight 414
// Reconstruction threshold: 228 (~55% of total weight)
// Actual reconstruction threshold in stake ratio: 0.60478... (~60.5%)

// Attack scenario:
// - Byzantine validators: ~33% withhold shares (~138 weight)
// - Honest validators: ~67% available (~276 weight)  
// - Threshold required: 228 weight (~55%)
// - Buffer: only 48 weight (~12%)
// - If 12% of stake experiences delays → threshold not met → chain halts
```

The equal-weight test case demonstrates the formula directly calculates threshold as `ceil(n * 0.5) + 1`, confirming the use of secrecy threshold rather than reconstruction threshold for determining the minimum shares needed.

## Notes

This vulnerability represents a fundamental mismatch between the cryptographic threshold parameters (50% secrecy) and the BFT liveness requirements (67% quorum). While the secrecy property ensures subsets ≤50% cannot reconstruct, and the mathematical validation confirms subsets >67% can reconstruct, the practical threshold (~55-60%) leaves insufficient buffer for real-world network conditions when Byzantine validators actively withhold shares.

The absence of an automatic timeout mechanism exacerbates the issue, converting what could be a temporary delay into a permanent chain halt requiring manual intervention across all validators.

### Citations

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L324-327)
```rust
    let reconstruct_threshold_in_weights_fixed =
        (secrecy_threshold_in_stake_ratio * stake_sum_fixed / stake_per_weight + delta_up_fixed)
            .ceil()
            + one;
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L366-370)
```rust
pub static DEFAULT_SECRECY_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(1) / U64F64::from_num(2));

pub static DEFAULT_RECONSTRUCT_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(2) / U64F64::from_num(3));
```

**File:** types/src/dkg/real_dkg/rounding/tests.rs (L24-26)
```rust
    println!("mainnet rounding profile: {:?}", dkg_rounding.profile);
    // Result:
    // mainnet rounding profile: total_weight: 414, secrecy_threshold_in_stake_ratio: 0.5, reconstruct_threshold_in_stake_ratio: 0.60478401144595166257, reconstruct_threshold_in_weights: 228, fast_reconstruct_threshold_in_stake_ratio: Some(0.7714506781126183292), fast_reconstruct_threshold_in_weights: Some(335), validator_weights: [7, 5, 6, 6, 5, 1, 6, 6, 1, 5, 6, 5, 1, 7, 1, 6, 6, 1, 2, 1, 6, 3, 2, 1, 1, 4, 3, 2, 5, 5, 5, 1, 1, 4, 1, 1, 1, 7, 5, 1, 1, 2, 6, 1, 6, 1, 3, 5, 5, 1, 5, 5, 3, 2, 5, 1, 6, 3, 6, 1, 1, 3, 1, 5, 1, 9, 1, 1, 1, 6, 1, 5, 7, 4, 6, 1, 5, 6, 5, 5, 3, 1, 6, 7, 6, 1, 3, 1, 1, 1, 1, 1, 1, 7, 2, 1, 6, 7, 1, 1, 1, 1, 5, 3, 1, 2, 3, 1, 1, 1, 1, 4, 1, 1, 1, 2, 1, 6, 7, 5, 1, 5, 1, 6, 1, 2, 3, 2, 2]
```

**File:** types/src/dkg/real_dkg/rounding/tests.rs (L70-78)
```rust
        let wconfig = WeightedConfigBlstrs::new(
            (U64F64::from_num(validator_num) * *DEFAULT_SECRECY_THRESHOLD.deref())
                .ceil()
                .to_num::<usize>()
                + 1,
            vec![1; validator_num],
        )
        .unwrap();
        assert_eq!(dkg_rounding.wconfig, wconfig);
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L47-49)
```rust
        if self.total_weight < rand_config.threshold() {
            return Either::Left(self);
        }
```

**File:** consensus/src/rand/rand_gen/block_queue.rs (L115-136)
```rust
    /// Dequeue all ordered blocks prefix that have randomness
    /// Unwrap is safe because the queue is not empty
    #[allow(clippy::unwrap_used)]
    pub fn dequeue_rand_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut rand_ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.num_undecided() == 0 {
                let (_, item) = self.queue.pop_first().unwrap();
                for block in item.blocks() {
                    observe_block(block.timestamp_usecs(), BlockStage::RAND_READY);
                }
                let QueueItem { ordered_blocks, .. } = item;
                debug_assert!(ordered_blocks
                    .ordered_blocks
                    .iter()
                    .all(|block| block.has_randomness()));
                rand_ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        rand_ready_prefix
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config_seqnum.move (L2-7)
```text
///
/// When randomness generation is stuck due to a bug, the chain is also stuck. Below is the recovery procedure.
/// 1. Ensure more than 2/3 stakes are stuck at the same version.
/// 1. Every validator restarts with `randomness_override_seq_num` set to `X+1` in the node config file,
///    where `X` is the current `RandomnessConfigSeqNum` on chain.
/// 1. The chain should then be unblocked.
```

**File:** types/src/validator_verifier.rs (L207-214)
```rust
        let total_voting_power = sum_voting_power(&validator_infos);
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
        Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
    }
```
