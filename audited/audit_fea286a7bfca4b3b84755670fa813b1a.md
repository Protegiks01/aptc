# Audit Report

## Title
Consensus Divergence via Silent Fallback to Default window_size Configuration

## Summary
When validators fail to read the on-chain consensus configuration during epoch initialization, they silently fall back to default values instead of halting. This creates a scenario where some validators operate with `window_size = None` while others use the actual on-chain value (e.g., `window_size = Some(10)`), causing them to select different `window_root_blocks` and diverge on block tree state, violating consensus safety.

## Finding Description

The vulnerability exists in the epoch initialization flow where validators read the on-chain consensus configuration. When a validator starts a new epoch, it attempts to read the `OnChainConsensusConfig` from the blockchain state: [1](#0-0) 

The critical flaw is the error handling: [2](#0-1) 

If `payload.get()` fails (returns `Err`), the validator logs a warning but continues with the default configuration: [3](#0-2) 

The default `window_size` is `None`: [4](#0-3) 

This `window_size` value is then used during recovery to determine the `window_root_block`: [5](#0-4) 

The `find_root` function branches based on whether `window_size` is `None` or `Some(value)`: [6](#0-5) 

**Divergence Mechanism:**

When `window_size = None`, the validator uses `find_root_without_window`, which sets `window_root_block = None`: [7](#0-6) 

When `window_size = Some(value)`, the validator uses `find_root_with_window`, which calculates a specific window start round and sets `window_root_block = Some(...)`: [8](#0-7) 

The different `window_root_block` values lead to different `root_id` selections for pruning: [9](#0-8) 

**Example Scenario:**
- On-chain config has `window_size = Some(10)` for epoch N
- Commit block is at round 100
- Validator A successfully reads config: calculates `window_start_round = 91`, uses block at round 91 as root
- Validator B fails to read config (database error, deserialization failure): uses default `window_size = None`, uses block at round 100 as root
- Validator A keeps blocks from round 91+, Validator B keeps blocks from round 100+
- They prune different blocks and cannot agree on the valid block tree
- **Consensus safety is broken**

## Impact Explanation

**Severity: Critical** (Consensus Safety Violation)

This vulnerability breaks the fundamental safety guarantee of Byzantine Fault Tolerant consensus: that fewer than 1/3 Byzantine validators cannot cause a chain split. Even with all honest validators, a transient configuration read failure can cause permanent consensus divergence.

**Impact:**
- **Consensus Fork**: Validators with different `window_root_blocks` cannot agree on valid blocks
- **Network Partition**: The network effectively splits into groups based on their `window_size` configuration
- **Non-Recoverable**: Once validators have pruned different blocks, they cannot re-synchronize without manual intervention
- **Hard Fork Required**: Recovery would require coordinating a network-wide restart with corrected state

This qualifies as **Critical Severity** under Aptos Bug Bounty criteria: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Medium to High**

While direct attacker exploitation requires causing configuration read failures, this can occur through:

1. **Natural Failures** (High likelihood):
   - Database I/O errors during epoch transitions
   - Deserialization bugs in `OnChainConsensusConfig` that only affect certain code paths
   - Race conditions where some validators read stale blockchain state during reconfiguration
   - Disk corruption or hardware failures

2. **Induced Failures** (Medium likelihood):
   - Malformed on-chain configs published through governance (if validation is insufficient)
   - Resource exhaustion attacks causing database read failures
   - Exploiting other vulnerabilities to corrupt the on-chain config storage

3. **Version Skew** (Medium likelihood):
   - Different validator software versions with different deserialization behavior
   - Incompatible config format changes during upgrades

The vulnerability is particularly dangerous because:
- It fails silently (only a warning log)
- The validator continues participating in consensus with incorrect configuration
- The divergence is not immediately detected
- Multiple validators could fail independently, creating multiple factions

## Recommendation

**Immediate Fix**: Validators MUST halt when they cannot read critical on-chain configuration, rather than falling back to defaults.

Replace the silent fallback with explicit failure:

```rust
// In consensus/src/epoch_manager.rs, around line 1201:
let consensus_config = onchain_consensus_config
    .expect("CRITICAL: Failed to read on-chain consensus config. Validator cannot participate safely. Halting.");
```

**Additional Safeguards**:

1. **Pre-validation**: Add checks during config update to ensure it's deserializable
2. **Checksum verification**: Store config checksums that validators verify before using
3. **Quorum agreement**: Validators could exchange config hashes before epoch start to detect mismatches
4. **Explicit defaults**: If defaults are needed for backward compatibility, make them explicit and logged prominently

**Long-term Fix**: Implement a config agreement protocol where validators must agree on the exact configuration before starting an epoch.

## Proof of Concept

```rust
// Rust test demonstrating the divergence
#[tokio::test]
async fn test_window_size_mismatch_causes_divergence() {
    // Setup: Two validators with same committed state
    let mut blocks = create_test_blocks(100); // Blocks up to round 100
    let mut qcs = create_test_quorum_certs(&blocks);
    let ledger_info = create_ledger_info(blocks[99].id()); // Committed to round 100
    
    let ledger_recovery = LedgerRecoveryData::new(ledger_info);
    
    // Validator A: Reads actual on-chain config (window_size = Some(10))
    let root_a = ledger_recovery.find_root(
        &mut blocks.clone(),
        &mut qcs.clone(),
        true,
        Some(10) // Successfully read on-chain config
    ).unwrap();
    
    // Validator B: Fails to read config, uses default (window_size = None)
    let root_b = ledger_recovery.find_root(
        &mut blocks.clone(),
        &mut qcs.clone(),
        true,
        None // Failed to read config, using default
    ).unwrap();
    
    // Assert: They selected different window_root_blocks
    assert!(root_a.window_root_block.is_some());
    assert!(root_b.window_root_block.is_none());
    
    // Assert: They will use different roots for pruning
    let root_id_a = root_a.window_root_block.unwrap().id();
    let root_id_b = root_b.commit_root_block.id();
    assert_ne!(root_id_a, root_id_b);
    
    // Consequence: Different blocks will be pruned
    // Validator A keeps blocks from round 91+
    // Validator B keeps blocks from round 100+
    // They cannot agree on valid blocks referencing rounds 91-99
}
```

**Notes**

This vulnerability demonstrates a critical failure in defensive programming for distributed consensus systems. The principle of "fail-safe" requires that when critical configuration cannot be read, the system must halt rather than guess. The silent fallback to defaults creates a Byzantine fault scenario where honest validators diverge due to configuration mismatch, which is indistinguishable from malicious behavior and cannot be resolved without manual intervention.

The window_size parameter is particularly sensitive because it directly affects the block pruning logic, which determines what historical blocks each validator retains. Different pruning decisions lead to incompatible block trees, making recovery impossible without coordinated state reset.

### Citations

**File:** consensus/src/epoch_manager.rs (L1178-1189)
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
```

**File:** consensus/src/epoch_manager.rs (L1201-1201)
```rust
        let consensus_config = onchain_consensus_config.unwrap_or_default();
```

**File:** consensus/src/epoch_manager.rs (L1383-1386)
```rust
        match self.storage.start(
            consensus_config.order_vote_enabled(),
            consensus_config.window_size(),
        ) {
```

**File:** types/src/on_chain_config/consensus_config.rs (L12-12)
```rust
pub const DEFAULT_WINDOW_SIZE: Option<u64> = None;
```

**File:** types/src/on_chain_config/consensus_config.rs (L443-451)
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        OnChainConsensusConfig::V4 {
            alg: ConsensusAlgorithmConfig::default_if_missing(),
            vtxn: ValidatorTxnConfig::default_if_missing(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
}
```

**File:** consensus/src/persistent_liveness_storage.rs (L165-196)
```rust
        let window_start_round = calculate_window_start_round(commit_block.round(), window_size);
        let mut id_to_blocks = HashMap::new();
        blocks.iter().for_each(|block| {
            id_to_blocks.insert(block.id(), block);
        });

        let mut current_block = &commit_block;
        while !current_block.is_genesis_block()
            && current_block.quorum_cert().certified_block().round() >= window_start_round
        {
            if let Some(parent_block) = id_to_blocks.get(&current_block.parent_id()) {
                current_block = *parent_block;
            } else {
                bail!("Parent block not found for block {}", current_block.id());
            }
        }
        let window_start_id = current_block.id();

        let window_start_idx = blocks
            .iter()
            .position(|block| block.id() == window_start_id)
            .ok_or_else(|| format_err!("unable to find window root: {}", window_start_id))?;
        let window_start_block = blocks.remove(window_start_idx);

        info!(
            "Commit block is {}, window block is {}",
            commit_block, window_start_block
        );

        Ok(RootInfo {
            commit_root_block: Box::new(commit_block),
            window_root_block: Some(Box::new(window_start_block)),
```

**File:** consensus/src/persistent_liveness_storage.rs (L265-267)
```rust
        Ok(RootInfo {
            commit_root_block: Box::new(root_block),
            window_root_block: None,
```

**File:** consensus/src/persistent_liveness_storage.rs (L290-295)
```rust
        match window_size {
            None => self.find_root_without_window(blocks, quorum_certs, order_vote_enabled),
            Some(window_size) => {
                self.find_root_with_window(blocks, quorum_certs, order_vote_enabled, window_size)
            },
        }
```

**File:** consensus/src/persistent_liveness_storage.rs (L386-402)
```rust
        let (root_id, epoch) = match &root.window_root_block {
            None => {
                let commit_root_id = root.commit_root_block.id();
                let epoch = root.commit_root_block.epoch();
                (commit_root_id, epoch)
            },
            Some(window_root_block) => {
                let window_start_id = window_root_block.id();
                let epoch = window_root_block.epoch();
                (window_start_id, epoch)
            },
        };
        let blocks_to_prune = Some(Self::find_blocks_to_prune(
            root_id,
            &mut blocks,
            &mut quorum_certs,
        ));
```
