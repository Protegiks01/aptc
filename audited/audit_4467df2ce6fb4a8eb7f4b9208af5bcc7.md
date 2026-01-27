# Audit Report

## Title
Unvalidated persisted_auxiliary_info_version in On-Chain Governance Causes Network-Wide Consensus Halt

## Summary
Setting `persisted_auxiliary_info_version` to any value greater than 1 through on-chain governance proposals causes all validator nodes to panic with `unimplemented!()` during block execution, resulting in complete network halt and requiring a hard fork to recover.

## Finding Description

The `persisted_auxiliary_info_version` field is a u8 configuration parameter exposed through on-chain governance that controls which version of `PersistedAuxiliaryInfo` to create during transaction execution. [1](#0-0) 

The governance mechanism allows updating this configuration through the Move framework without validation: [2](#0-1) 

The Move contract only validates that config bytes are non-empty, not their semantic content. The release builder's validation logic also fails to check version bounds: [3](#0-2) 

**The Critical Flaw:** When executing blocks, the consensus pipeline uses this version to determine auxiliary info format: [4](#0-3) 

This code explicitly panics with `unimplemented!()` for any version > 1. When a governance proposal sets `persisted_auxiliary_info_version = 2` (or any value > 1), the configuration is accepted without validation and applied at the next epoch boundary. When validators attempt to execute the first block of the new epoch, ALL validators simultaneously crash at this panic point, causing complete network halt.

**Attack Path:**
1. Attacker (or mistaken operator) submits governance proposal setting `ExecutionConfigV7` with `persisted_auxiliary_info_version: 2`
2. Proposal passes governance vote (or is mistakenly approved)
3. Configuration is buffered and applied at epoch change
4. First block execution triggers panic on ALL validators
5. Network halts completely - no blocks can be produced
6. Recovery requires coordinated hard fork with code changes

## Impact Explanation

**CRITICAL Severity** - This vulnerability meets multiple Critical severity criteria per Aptos Bug Bounty:

1. **Total loss of liveness/network availability**: All validators crash simultaneously, no blocks can be produced
2. **Non-recoverable network partition (requires hardfork)**: The network cannot self-recover. Validators will continue to crash on restart unless the code is patched or the on-chain config is manually reverted at the database level
3. **Consensus Safety Violation**: The deterministic execution invariant is broken as the network cannot progress

The impact affects:
- All validator nodes (100% of network)
- All users (cannot submit transactions)
- All DApps (complete service disruption)
- Requires emergency hard fork coordination

## Likelihood Explanation

**Medium-High Likelihood:**

**Factors increasing likelihood:**
- No validation exists at any layer (Move, Rust, release builder)
- The field is legitimately exposed to governance as a configuration parameter
- Value `2` appears to be a logical "next version" that someone might set thinking they're enabling new functionality
- Testing in devnet/testnet with version 1 works fine, hiding the issue
- No runtime warnings or errors appear until actual execution

**Factors that could trigger:**
- Malicious governance proposal
- Mistaken "upgrade" attempt by thinking version 2 is supported
- Testing new features with incorrect version numbers
- Copy-paste errors in configuration

The barrier to exploitation is only the governance voting process, which is the standard mechanism for configuration changes. An attacker with sufficient stake or social engineering could trigger this, or it could occur accidentally.

## Recommendation

**Immediate Fix:** Add validation at multiple layers:

1. **Runtime validation in consensus** (defensive programming):
```rust
let persisted_auxiliary_info = match persisted_auxiliary_info_version {
    0 => PersistedAuxiliaryInfo::None,
    1 => PersistedAuxiliaryInfo::V1 {
        transaction_index: txn_index as u32,
    },
    v => {
        error!("Unsupported persisted_auxiliary_info_version: {}, falling back to version 1", v);
        PersistedAuxiliaryInfo::V1 {
            transaction_index: txn_index as u32,
        }
    }
};
```

2. **Validation in Move governance contract**:
```move
const EMAX_PERSISTED_AUX_VERSION: u64 = 2;

public fun validate_execution_config(config_bytes: &vector<u8>) {
    // Deserialize and validate persisted_auxiliary_info_version <= MAX_SUPPORTED
}
```

3. **Validation in release builder**:
```rust
// In validate_upgrade for Execution config
if let OnChainExecutionConfig::V7(config) = execution_config {
    assert!(
        config.persisted_auxiliary_info_version <= 1,
        "persisted_auxiliary_info_version must be 0 or 1"
    );
}
```

## Proof of Concept

**Rust unit test demonstrating the panic:**

```rust
#[test]
#[should_panic(expected = "Unsupported persisted auxiliary info version")]
fn test_unsupported_aux_version_panics() {
    let persisted_auxiliary_info_version: u8 = 2; // Invalid version
    let txn_index = 0;
    
    let persisted_auxiliary_info = match persisted_auxiliary_info_version {
        0 => PersistedAuxiliaryInfo::None,
        1 => PersistedAuxiliaryInfo::V1 {
            transaction_index: txn_index as u32,
        },
        _ => unimplemented!("Unsupported persisted auxiliary info version"),
    };
}
```

**Governance proposal simulation:**
```move
script {
    use aptos_framework::execution_config;
    use aptos_framework::aptos_governance;
    
    fun trigger_network_halt(framework_signer: &signer) {
        // Create ExecutionConfigV7 with version = 2
        let malicious_config = create_config_with_version_2();
        execution_config::set_for_next_epoch(framework_signer, malicious_config);
        aptos_governance::reconfigure(framework_signer);
        // Network will halt at next epoch boundary
    }
}
```

**Notes**

This vulnerability demonstrates a critical gap in defense-in-depth for on-chain governance parameters. While governance is trusted, configuration values must still be validated to prevent catastrophic failures from mistakes or social engineering attacks. The lack of validation at the consensus execution layer, combined with the use of `unimplemented!()` (which panics rather than returning an error), creates a single point of failure that can bring down the entire network through a standard governance mechanism.

The issue is particularly severe because:
- It bypasses all normal consensus safety mechanisms
- It affects all validators simultaneously (no gradual degradation)
- Recovery cannot be automated and requires manual intervention
- The panic happens in the critical path of block execution

### Citations

**File:** types/src/on_chain_config/execution_config.rs (L86-97)
```rust
    pub fn persisted_auxiliary_info_version(&self) -> u8 {
        match self {
            OnChainExecutionConfig::Missing
            | OnChainExecutionConfig::V1(_)
            | OnChainExecutionConfig::V2(_)
            | OnChainExecutionConfig::V3(_)
            | OnChainExecutionConfig::V4(_)
            | OnChainExecutionConfig::V5(_)
            | OnChainExecutionConfig::V6(_) => 0,
            OnChainExecutionConfig::V7(config) => config.persisted_auxiliary_info_version,
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L48-52)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L504-508)
```rust
            ReleaseEntry::Execution(execution_config) => {
                if !wait_until_equals(client_opt, execution_config, *MAX_ASYNC_RECONFIG_TIME) {
                    bail!("Consensus config mismatch: Expected {:?}", execution_config);
                }
            },
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L835-841)
```rust
                let persisted_auxiliary_info = match persisted_auxiliary_info_version {
                    0 => PersistedAuxiliaryInfo::None,
                    1 => PersistedAuxiliaryInfo::V1 {
                        transaction_index: txn_index as u32,
                    },
                    _ => unimplemented!("Unsupported persisted auxiliary info version"),
                };
```
