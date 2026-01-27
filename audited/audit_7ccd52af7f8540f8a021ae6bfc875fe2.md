# Audit Report

## Title
Consensus Split During OnChainConsensusConfig V4→V5 Migration Due to BCS Deserialization Incompatibility

## Summary
During migration from OnChainConsensusConfig V4 to V5, validators running pre-V5 code fail to deserialize the new config format and silently fall back to a default configuration with validator transactions disabled, while V5-aware validators correctly deserialize and see validator transactions as enabled. This creates divergent block validation rules that cause consensus safety violations.

## Finding Description

The vulnerability exists in the handling of `OnChainConsensusConfig` version upgrades, specifically when the on-chain config is updated from V4 to V5. The V5 variant adds a `rand_check_enabled: bool` field that V4-only code cannot deserialize.

**Critical Code Paths:**

1. **Native Function Path** - The `validator_txn_enabled()` native function uses `unwrap_or_default()` when BCS deserialization fails: [1](#0-0) 

2. **Consensus Epoch Manager** - During epoch initialization, failed deserialization falls back to default config: [2](#0-1) 

3. **Default Implementation** - The default config returns V4 with validator transactions DISABLED: [3](#0-2) 

4. **ValidatorTxnConfig Default** - Returns V0 (disabled) when config is missing: [4](#0-3) 

5. **Block Validation** - RoundManager rejects ProposalExt blocks when vtxn is disabled: [5](#0-4) 

6. **Governance Reconfiguration** - Uses validator_txn_enabled() to determine reconfiguration path: [6](#0-5) 

**Attack Scenario:**

BCS enum deserialization is NOT forward-compatible - when code expecting V4 (enum indices 0-3) receives V5 data (enum index 4), deserialization fails. This creates the following sequence:

1. Network has validators running mixed versions during rolling upgrade
2. Governance proposal updates consensus config from V4 to V5 with `vtxn: ValidatorTxnConfig::V1 {...}` (enabled)
3. **V5-aware validators**: Successfully deserialize, see `vtxn_enabled() = true`
4. **V4-only validators**: Deserialization fails, fall back to `default()` which has `vtxn: ValidatorTxnConfig::V0` (disabled)
5. When a block with `BlockType::ProposalExt` is proposed:
   - V5 validators: Accept the block (vtxn enabled)
   - V4 validators: **Reject with error** "ProposalExt unexpected while the vtxn feature is disabled"
6. **Consensus split occurs** - validators disagree on block validity, violating consensus safety

This breaks the critical invariant that all validators must produce identical validation results for identical blocks.

## Impact Explanation

This is a **CRITICAL** severity issue under Aptos bug bounty criteria:

- **Consensus/Safety Violation**: Validators reach different conclusions about block validity, directly violating the AptosBFT safety guarantee that < 1/3 Byzantine validators cannot cause chain splits
- **Non-recoverable Network Partition**: Once validators diverge on block validation, the network cannot achieve consensus without manual intervention or emergency hardfork
- **Breaks Deterministic Execution Invariant**: Different validators execute governance reconfiguration logic differently based on their view of `validator_txn_enabled()`

The impact affects:
- All validators during config migration period
- Governance operations that depend on `validator_txn_enabled()` 
- DKG (Distributed Key Generation) reconfiguration logic
- Network liveness and safety properties

## Likelihood Explanation

**High Likelihood** - This vulnerability will trigger automatically during routine network upgrades:

1. **No attacker required**: The issue manifests naturally during any V4→V5 config migration while validators run mixed software versions
2. **Standard upgrade procedure**: Rolling validator upgrades are the recommended deployment model for network stability
3. **No special permissions needed**: The vulnerability is triggered by normal governance proposals
4. **Silent failure**: The `unwrap_or_default()` pattern suppresses errors, preventing early detection
5. **Observable in production**: Any network attempting V5 config deployment before 100% validator upgrade completion will experience this

The only mitigation currently is perfect coordination requiring ALL validators to upgrade before config change, which contradicts standard rolling upgrade practices.

## Recommendation

Implement strict version compatibility enforcement:

**Option 1: Add Version Validation**
```rust
// In consensus/src/epoch_manager.rs
let consensus_config = match onchain_consensus_config {
    Ok(config) => config,
    Err(error) => {
        error!("CRITICAL: Failed to deserialize consensus config: {}", error);
        // Halt consensus rather than silently using wrong config
        panic!("Cannot proceed with incompatible consensus config version");
    }
};
```

**Option 2: Add Compatibility Check in Native Function**
```rust
// In aptos-move/framework/src/natives/consensus_config.rs
pub fn validator_txn_enabled(
    _context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let config_bytes = safely_pop_arg!(args, Vec<u8>);
    let config = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes)
        .expect("CRITICAL: Failed to deserialize consensus config - version incompatibility");
    Ok(smallvec![Value::bool(config.is_vtxn_enabled())])
}
```

**Option 3: Require Version Feature Flag** (Recommended)
Before allowing V5 config deployment, require a feature flag that gates the config version: [7](#0-6) 

Add validation in the governance proposal generator to ensure minimum validator version is met before allowing V5 configs.

## Proof of Concept

**Reproduction Steps:**

1. Deploy network with validators running V4-compatible code
2. Submit governance proposal to upgrade consensus config to V5:
```rust
let v5_config = OnChainConsensusConfig::V5 {
    alg: ConsensusAlgorithmConfig::default_for_genesis(),
    vtxn: ValidatorTxnConfig::V1 {
        per_block_limit_txn_count: 2,
        per_block_limit_total_bytes: 2097152,
    },
    window_size: None,
    rand_check_enabled: true,
};
```

3. Observe that V4-only validators log warning:
   "Failed to read on-chain consensus config"

4. Check validator vtxn_config state - V4 validators will have `ValidatorTxnConfig::V0` while V5 validators have `ValidatorTxnConfig::V1`

5. Propose a block with `BlockType::ProposalExt` containing validator transactions

6. Observe consensus split:
   - V5 validators vote for the block
   - V4 validators reject with counter increment at `UNEXPECTED_PROPOSAL_EXT_COUNT`

7. Network fails to achieve quorum, entering liveness failure

**Verification:**
Monitor metrics at the cited rejection point to confirm divergent behavior across validator versions during config migration.

### Citations

**File:** aptos-move/framework/src/natives/consensus_config.rs (L13-21)
```rust
pub fn validator_txn_enabled(
    _context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let config_bytes = safely_pop_arg!(args, Vec<u8>);
    let config = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes).unwrap_or_default();
    Ok(smallvec![Value::bool(config.is_vtxn_enabled())])
}
```

**File:** consensus/src/epoch_manager.rs (L1178-1201)
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

        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }

        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
        }

        self.epoch_state = Some(epoch_state.clone());

        let consensus_config = onchain_consensus_config.unwrap_or_default();
```

**File:** types/src/on_chain_config/consensus_config.rs (L147-149)
```rust
    pub fn default_if_missing() -> Self {
        Self::V0
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L443-450)
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        OnChainConsensusConfig::V4 {
            alg: ConsensusAlgorithmConfig::default_if_missing(),
            vtxn: ValidatorTxnConfig::default_if_missing(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
```

**File:** consensus/src/round_manager.rs (L1116-1124)
```rust
        if !self.vtxn_config.enabled()
            && matches!(
                proposal.block_data().block_type(),
                BlockType::ProposalExt(_)
            )
        {
            counters::UNEXPECTED_PROPOSAL_EXT_COUNT.inc();
            bail!("ProposalExt unexpected while the vtxn feature is disabled.");
        }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/aptos-release-builder/src/components/consensus_config.rs (L11-51)
```rust
pub fn generate_consensus_upgrade_proposal(
    consensus_config: &OnChainConsensusConfig,
    is_testnet: bool,
    next_execution_hash: Option<HashValue>,
    is_multi_step: bool,
) -> Result<Vec<(String, String)>> {
    let signer_arg = get_signer_arg(is_testnet, &next_execution_hash);
    let mut result = vec![];

    let writer = CodeWriter::new(Loc::default());

    emitln!(writer, "// Consensus config upgrade proposal\n");
    let config_comment = format!("// config: {:#?}", consensus_config).replace('\n', "\n// ");
    emitln!(writer, "{}\n", config_comment);

    let proposal = generate_governance_proposal(
        &writer,
        is_testnet,
        next_execution_hash,
        is_multi_step,
        &["aptos_framework::consensus_config"],
        |writer| {
            let consensus_config_blob = bcs::to_bytes(consensus_config).unwrap();
            assert!(consensus_config_blob.len() < 65536);

            emit!(writer, "let consensus_blob: vector<u8> = ");
            generate_blob_as_hex_string(writer, &consensus_config_blob);
            emitln!(writer, ";\n");

            emitln!(
                writer,
                "consensus_config::set_for_next_epoch({}, consensus_blob);",
                signer_arg
            );
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
        },
    );

    result.push(("consensus-config".to_string(), proposal));
    Ok(result)
}
```
