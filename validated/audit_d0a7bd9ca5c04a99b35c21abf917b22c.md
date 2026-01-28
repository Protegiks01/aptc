# Audit Report

## Title
Consensus Configuration Inconsistency Due to Missing Version Compatibility Enforcement in OnChain Config Deserialization

## Summary
During rolling upgrades, validators running different software versions can operate with inconsistent consensus configurations when a governance proposal updates `OnChainConsensusConfig` to a newer variant (e.g., V5) that older validators cannot deserialize. This creates a critical liveness failure where validators sign different `LedgerInfo` hashes, preventing quorum formation and halting the network.

## Finding Description

The vulnerability stems from the interaction between BCS enum deserialization, fallback behavior, and the `order_vote_enabled` flag's impact on commit ledger info generation.

**Execution Flow:**

1. **Config Deserialization Phase**: At epoch transition, validators fetch `OnChainConsensusConfig` from on-chain state via `payload.get::<OnChainConsensusConfig>()`. [1](#0-0) 

2. **Deserialization Failure**: Validators running older software (knowing only V1-V4) fail to deserialize V5 configs via BCS, as BCS cannot handle unknown enum variants. The code logs a warning but continues execution. [2](#0-1) 

3. **Fallback to Default**: Failed deserialization triggers `unwrap_or_default()`, which returns `OnChainConsensusConfig::V4` with the default algorithm config. [3](#0-2) 

The default implementation returns V4 with `ConsensusAlgorithmConfig::default_if_missing()`: [4](#0-3) 

This default_if_missing() sets `order_vote_enabled: false`: [5](#0-4) 

4. **Config Divergence**: Newer validators successfully deserialize V5 (potentially with `order_vote_enabled: true`), while older validators use V4 default (with `order_vote_enabled: false`).

5. **Critical Impact - Different LedgerInfo Construction**: The `generate_commit_ledger_info` function creates fundamentally different `LedgerInfo` objects based on `order_vote_enabled`: [6](#0-5) 

In the signing pipeline, when `order_vote_enabled` is true, the consensus_data_hash is forced to `HashValue::zero()`: [7](#0-6) 

This hash is then used to create the LedgerInfo that validators sign: [8](#0-7) 

6. **Quorum Formation Failure**: Validators sign different `LedgerInfo` hashes, making signature aggregation impossible. The network cannot form a commit quorum.

7. **No Version Enforcement**: The Move framework's `set_for_next_epoch` only validates that config bytes are non-empty, with no check that all validators can deserialize the new variant: [9](#0-8) 

## Impact Explanation

**Critical Severity - Total Loss of Liveness/Network Availability**

This vulnerability meets the Aptos bug bounty's **Critical** criteria for "Total Loss of Liveness/Network Availability: Network halts due to protocol bug, all validators unable to progress."

The impact is severe because:

1. **Complete Network Halt**: Validators cannot aggregate signatures on commit decisions, preventing any blocks from being committed
2. **Silent Failure**: Validators continue operating but cannot reach consensus, making the issue difficult to diagnose
3. **Requires Manual Intervention**: Recovery requires coordinated validator upgrades or governance action to roll back the config
4. **Breaks Consensus Invariant**: Violates the requirement that all honest validators produce identical behavior for identical inputs

The vulnerability specifically causes different `consensus_data_hash` values in `LedgerInfo` objects that validators must sign, fundamentally breaking the ability to form a quorum certificate.

## Likelihood Explanation

**Medium Likelihood** during operational windows:

**Triggering Conditions:**
- Rolling upgrade in progress with mixed validator versions (standard practice)
- Governance proposal updates `OnChainConsensusConfig` to newer variant (V5)
- No coordination between upgrade completion and config update timing

**Realistic Scenario:**
1. Validators begin rolling upgrade from version supporting V1-V4 to version supporting V1-V5
2. During upgrade window (50% upgraded, 50% not), governance proposal passes updating config to V5
3. At next epoch boundary, divergence occurs silently

**No Code-Level Protection:**
- Framework validation only checks non-empty bytes
- No minimum version requirements enforced
- No validator capability checks before applying configs
- Relies entirely on operational coordination (not enforced in code)

**Mitigating Factors:**
- Requires operational timing error (config update during incomplete upgrade)
- Aptos governance reviews proposals, but no technical enforcement
- Compatibility tests exist but don't validate config version mismatches during rolling upgrades

## Recommendation

Implement version compatibility enforcement at multiple levels:

1. **Move Framework Validation**: Add deserialization validation in `set_for_next_epoch` to ensure the config can be deserialized before storing it in the config buffer.

2. **Validator Version Tracking**: Introduce a mechanism to track minimum validator software versions and reject config updates that require versions not yet deployed to sufficient validators.

3. **Graceful Degradation**: Instead of silently falling back to default, validators should halt or enter a safe mode when encountering undeserializable configs, making the issue immediately visible.

4. **Config Compatibility Metadata**: Include version compatibility metadata in governance proposals to validate against current validator capabilities before application.

## Proof of Concept

While a full PoC would require setting up a multi-validator testnet with mixed software versions, the vulnerability can be demonstrated through the following logic:

1. Deploy validators with old code supporting OnChainConsensusConfig V1-V4
2. Deploy validators with new code supporting OnChainConsensusConfig V1-V5
3. Submit governance proposal updating config to V5 with `order_vote_enabled: true`
4. At epoch transition, observe:
   - Old validators fail to deserialize V5, fall back to V4 default with `order_vote_enabled: false`
   - New validators deserialize V5 successfully with `order_vote_enabled: true`
   - Old validators sign LedgerInfo with `consensus_data_hash` from order proof
   - New validators sign LedgerInfo with `consensus_data_hash = HashValue::zero()`
   - Signature aggregation fails, network halts

The critical code paths have been verified and cited above, demonstrating the technical feasibility of this attack vector.

## Notes

This vulnerability represents a systemic issue in the consensus configuration upgrade process. The lack of version compatibility enforcement creates a window of vulnerability during every rolling upgrade where configuration changes could inadvertently halt the network. The issue is particularly insidious because it manifests as a silent consensus failure rather than an obvious error, making diagnosis difficult in production environments.

### Citations

**File:** consensus/src/epoch_manager.rs (L1178-1178)
```rust
        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
```

**File:** consensus/src/epoch_manager.rs (L1187-1189)
```rust
        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }
```

**File:** consensus/src/epoch_manager.rs (L1201-1201)
```rust
        let consensus_config = onchain_consensus_config.unwrap_or_default();
```

**File:** types/src/on_chain_config/consensus_config.rs (L46-52)
```rust
    pub fn default_if_missing() -> Self {
        Self::JolteonV2 {
            main: ConsensusConfigV1::default(),
            quorum_store_enabled: true,
            order_vote_enabled: false,
        }
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

**File:** consensus/src/pipeline/buffer_item.rs (L25-38)
```rust
fn generate_commit_ledger_info(
    commit_info: &BlockInfo,
    ordered_proof: &LedgerInfoWithSignatures,
    order_vote_enabled: bool,
) -> LedgerInfo {
    LedgerInfo::new(
        commit_info.clone(),
        if order_vote_enabled {
            HashValue::zero()
        } else {
            ordered_proof.ledger_info().consensus_data_hash()
        },
    )
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1004-1006)
```rust
        if order_vote_enabled {
            consensus_data_hash = HashValue::zero();
        }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1022-1024)
```rust
        let ledger_info = LedgerInfo::new(block_info, consensus_data_hash);
        info!("[Pipeline] Signed ledger info {ledger_info}");
        let signature = signer.sign(&ledger_info).expect("Signing should succeed");
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```
