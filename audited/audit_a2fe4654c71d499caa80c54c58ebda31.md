# Audit Report

## Title
Critical Network Halt via Deprecated TransactionShufflerType in Execution Config Governance Proposals

## Summary
A governance proposal can set an execution config with deprecated `TransactionShufflerType` variants (`SenderAwareV2` or `DeprecatedFairness`) that cause all validators to panic and crash simultaneously at the next epoch boundary, resulting in total network unavailability requiring an emergency hardfork to recover.

## Finding Description

The `OnChainExecutionConfig` enum allows configuration of transaction shuffling behavior through the `TransactionShufflerType` field. [1](#0-0) 

The governance system allows setting execution config for the next epoch through the `set_for_next_epoch` function, which only validates that the config vector is non-empty but performs no semantic validation of the config contents. [2](#0-1) 

During epoch initialization, the consensus layer calls `create_transaction_shuffler` with the configured shuffler type. [3](#0-2) 

However, the `create_transaction_shuffler` function treats two shuffler variants as unreachable, causing immediate panic if encountered. [4](#0-3) 

The `start_epoch` method has no error handling mechanism as it returns void, making validator crashes unrecoverable. [5](#0-4) 

**Attack Path:**
1. Attacker submits governance proposal containing `OnChainExecutionConfig::V7` (or any version) with `transaction_shuffler_type: TransactionShufflerType::SenderAwareV2(32)`
2. Proposal undergoes normal governance voting and passes
3. Config is serialized via BCS and stored on-chain successfully (all enum variants are valid for serialization)
4. At next epoch boundary, all validators load the new config
5. Each validator calls `create_transaction_shuffler(SenderAwareV2(32))`
6. Function hits `unreachable!()` macro at line 79, causing panic
7. All validators crash simultaneously
8. Network halts completely with no automatic recovery
9. Emergency hardfork required to remove malicious config from state

This breaks the **Consensus Safety** and **Deterministic Execution** invariants by causing total network unavailability.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple criteria for critical impact:

1. **Total loss of liveness/network availability**: All validators crash simultaneously when attempting to initialize the new epoch, completely halting the network. No blocks can be proposed, voted on, or committed.

2. **Non-recoverable network partition (requires hardfork)**: The malicious config is stored in on-chain state and will be loaded at every epoch boundary. Validators cannot skip or ignore the config. Recovery requires an emergency hardfork to manually patch the state and remove the invalid configuration.

3. **Network-wide synchronized failure**: Unlike gradual failures or single-node issues, this causes instantaneous crash across all validators at the exact same point (epoch boundary), making the attack highly effective.

Per Aptos Bug Bounty criteria, this qualifies for Critical Severity (up to $1,000,000) as it causes "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Medium-to-High Likelihood** for the following reasons:

**Enabling Factors:**
- Governance proposals are accessible to any participant with sufficient voting power or social engineering capability
- The attack could occur accidentally if developers test deprecated configs on mainnet
- No validation prevents setting deprecated shuffler types
- BCS serialization accepts all enum variants as valid
- The failure mode is deterministic and guaranteed

**Mitigating Factors:**
- Requires passing a governance vote (needs community support or stake majority)
- Would likely be caught during proposal review by vigilant community members
- Testnet environments would catch this before mainnet if properly tested

However, the severity of impact outweighs the governance requirement. The vulnerability is particularly dangerous because:
1. It's not obvious from the Move code that certain enum variants are dangerous
2. Developers might unknowingly include deprecated types in proposals
3. A malicious actor with governance influence could exploit this deliberately

## Recommendation

**Immediate Fix - Add Runtime Validation:**

Replace `unreachable!()` with graceful fallback in `create_transaction_shuffler`: [6](#0-5) 

Replace lines 78-82 with:
```rust
SenderAwareV2(_) => {
    warn!("SenderAwareV2 shuffler is deprecated, falling back to NoOpShuffler");
    Arc::new(NoOpShuffler {})
},
DeprecatedFairness => {
    warn!("DeprecatedFairness shuffler is deprecated, falling back to NoOpShuffler");
    Arc::new(NoOpShuffler {})
},
```

**Long-term Fix - Add Move-Level Validation:**

Add validation in `set_for_next_epoch` to check for deprecated shuffler types: [2](#0-1) 

Add native function or on-chain validation that deserializes the config and checks that `transaction_shuffler_type` is not a deprecated variant. Reject the proposal if deprecated types are detected.

**Additional Hardening:**
1. Add integration tests that verify epoch transitions with all possible config variants
2. Document which TransactionShufflerType variants are deprecated and unsafe
3. Consider removing deprecated variants entirely from the enum (breaking change requiring migration)
4. Add circuit breaker mechanism for validator crashes during epoch transitions

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_deprecated_shuffler_causes_panic() {
    use aptos_types::on_chain_config::{OnChainExecutionConfig, ExecutionConfigV7, TransactionShufflerType, BlockGasLimitType, TransactionDeduperType};
    use consensus::transaction_shuffler::create_transaction_shuffler;
    
    // Create config with deprecated SenderAwareV2 shuffler
    let malicious_config = OnChainExecutionConfig::V7(ExecutionConfigV7 {
        transaction_shuffler_type: TransactionShufflerType::SenderAwareV2(32),
        block_gas_limit_type: BlockGasLimitType::NoLimit,
        enable_per_block_gas_limit: false,
        transaction_deduper_type: TransactionDeduperType::TxnHashAndAuthenticatorV1,
        gas_price_to_burn: 90,
        persisted_auxiliary_info_version: 1,
    });
    
    // Serialize to BCS (succeeds - no validation)
    let serialized = bcs::to_bytes(&malicious_config).unwrap();
    assert!(serialized.len() > 0);
    
    // Attempt to create shuffler (will panic)
    let result = std::panic::catch_unwind(|| {
        create_transaction_shuffler(malicious_config.transaction_shuffler_type())
    });
    
    // Verify panic occurred
    assert!(result.is_err(), "Expected panic from deprecated shuffler type");
}
```

**Governance Proposal PoC:**
```move
script {
    use aptos_framework::execution_config;
    use aptos_framework::aptos_governance;
    
    fun malicious_proposal(framework: &signer) {
        // Malicious config bytes containing SenderAwareV2 variant
        // (In practice, generated via generate_execution_config_upgrade_proposal)
        let malicious_config_bytes = /* BCS bytes with SenderAwareV2 */;
        
        execution_config::set_for_next_epoch(framework, malicious_config_bytes);
        aptos_governance::reconfigure(framework);
    }
}
```

**Notes**

This vulnerability demonstrates a critical gap between Move-level validation and Rust-level enforcement. The Move governance system accepts any BCS-serialized `OnChainExecutionConfig` as long as it's non-empty, but the Rust consensus code has stricter requirements that are enforced via `unreachable!()` rather than graceful error handling.

The issue is particularly insidious because:
1. The deprecated variants still exist in the enum definition, making them appear valid
2. No compile-time or Move-level checks prevent their use
3. The failure only manifests at epoch boundaries, making testing more difficult
4. The synchronized nature of epoch transitions means all validators fail simultaneously

Similar issues may exist with other deprecated configuration types that use `unreachable!()` instead of proper error handling. A comprehensive audit of all on-chain config deserialization and application points is recommended.

### Citations

**File:** types/src/on_chain_config/execution_config.rs (L228-240)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")] // cannot use tag = "type" as nested enums cannot work, and bcs doesn't support it
pub enum TransactionShufflerType {
    NoShuffling,
    DeprecatedSenderAwareV1(u32),
    SenderAwareV2(u32),
    DeprecatedFairness,
    UseCaseAware {
        sender_spread_factor: usize,
        platform_use_case_spread_factor: usize,
        user_use_case_spread_factor: usize,
    },
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

**File:** consensus/src/pipeline/execution_client.rs (L71-85)
```rust
    async fn start_epoch(
        &self,
        maybe_consensus_key: Arc<PrivateKey>,
        epoch_state: Arc<EpochState>,
        commit_signer_provider: Arc<dyn CommitSignerProvider>,
        payload_manager: Arc<dyn TPayloadManager>,
        onchain_consensus_config: &OnChainConsensusConfig,
        onchain_execution_config: &OnChainExecutionConfig,
        onchain_randomness_config: &OnChainRandomnessConfig,
        rand_config: Option<RandConfig>,
        fast_rand_config: Option<RandConfig>,
        rand_msg_rx: aptos_channel::Receiver<AccountAddress, IncomingRandGenRequest>,
        secret_sharing_msg_rx: aptos_channel::Receiver<AccountAddress, IncomingSecretShareRequest>,
        highest_committed_round: Round,
    );
```

**File:** consensus/src/pipeline/execution_client.rs (L560-561)
```rust
        let transaction_shuffler =
            create_transaction_shuffler(onchain_execution_config.transaction_shuffler_type());
```

**File:** consensus/src/transaction_shuffler/mod.rs (L64-101)
```rust
pub fn create_transaction_shuffler(
    shuffler_type: TransactionShufflerType,
) -> Arc<dyn TransactionShuffler> {
    use TransactionShufflerType::*;

    match shuffler_type {
        NoShuffling => {
            info!("Using no-op transaction shuffling");
            Arc::new(NoOpShuffler {})
        },
        DeprecatedSenderAwareV1(_) => {
            info!("Using no-op sender aware shuffling v1");
            Arc::new(NoOpShuffler {})
        },
        SenderAwareV2(_) => {
            unreachable!("SenderAware shuffler is no longer supported.")
        },
        DeprecatedFairness => {
            unreachable!("DeprecatedFairness shuffler is no longer supported.")
        },
        UseCaseAware {
            sender_spread_factor,
            platform_use_case_spread_factor,
            user_use_case_spread_factor,
        } => {
            let config = use_case_aware::Config {
                sender_spread_factor,
                platform_use_case_spread_factor,
                user_use_case_spread_factor,
            };
            info!(
                config = ?config,
                "Using use case aware transaction shuffling."
            );
            Arc::new(use_case_aware::UseCaseAwareShuffler { config })
        },
    }
}
```
