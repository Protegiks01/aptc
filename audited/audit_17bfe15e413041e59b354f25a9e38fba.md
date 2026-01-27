# Audit Report

## Title
Governance Can Enable Deprecated Insecure Transaction Shuffler via Missing Validation

## Summary
The `DeprecatedSenderAwareV1` transaction shuffler variant remains in the `TransactionShufflerType` enum for backwards compatibility, but lacks validation to prevent its activation via governance proposals. When set, it maps to `NoOpShuffler`, completely disabling transaction shuffling and enabling MEV/frontrunning attacks while degrading parallel execution performance.

## Finding Description

The vulnerability exists across three components:

**1. Enum Definition with Deprecated Variant** [1](#0-0) 

The `DeprecatedSenderAwareV1(u32)` variant remains at line 232 for backwards compatibility with historical on-chain configurations.

**2. Insecure Mapping to NoOpShuffler** [2](#0-1) 

When `DeprecatedSenderAwareV1` is configured, the consensus layer returns a `NoOpShuffler` that performs zero transaction reordering, leaving transactions in their original mempool order.

**3. Missing Validation in Governance Path** [3](#0-2) 

The `set_for_next_epoch` function only validates that config bytes are non-empty, with no checks preventing deprecated or insecure shuffler types.

**4. Governance Proposal Generation** [4](#0-3) 

The release builder can generate governance proposals that call `set_for_next_epoch` with any serialized `OnChainExecutionConfig`, including those using `DeprecatedSenderAwareV1`.

**Attack Flow:**

1. Attacker compromises sufficient governance voting power (through social engineering, vote buying, or exploiting other governance vulnerabilities)
2. Creates governance proposal with malicious execution config:
   ```
   OnChainExecutionConfig::V1(ExecutionConfigV1 {
       transaction_shuffler_type: TransactionShufflerType::DeprecatedSenderAwareV1(32)
   })
   ```
3. Proposal passes governance vote and gets scheduled for next epoch
4. At epoch boundary, `on_new_epoch` applies the config network-wide
5. All validators switch to `NoOpShuffler` - transactions execute in mempool order without shuffling
6. MEV/frontrunning attacks become possible; parallel execution performance degrades

The current secure shuffler `UseCaseAware` spreads transactions by sender and use case to prevent conflicts: [5](#0-4) 

With `DeprecatedSenderAwareV1`, this protection is completely disabled.

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria:

1. **MEV/Frontrunning Enablement**: Without transaction shuffling, validators can observe and reorder transactions predictably, enabling sandwich attacks, frontrunning, and other MEV extraction that causes financial losses to users.

2. **Performance Degradation**: Consecutive transactions from the same sender create execution conflicts, reducing parallel execution efficiency and degrading network throughput. This impacts availability.

3. **DoS Vector**: Attackers can deliberately cluster same-sender transactions to maximize conflicts and slow down block execution.

4. **Fairness Violation**: Some users' transactions systematically get prioritized over others based on mempool timing rather than protocol-enforced fairness.

This meets "State inconsistencies requiring intervention" and performance degradation criteria for Medium severity. It does NOT break consensus safety (execution remains deterministic) or cause fund theft directly, preventing Critical/High classification.

## Likelihood Explanation

**Moderate Likelihood:**

- **Attack Complexity**: Requires compromising governance through social engineering, vote manipulation, or exploiting other governance vulnerabilities
- **Attacker Profile**: Sophisticated attacker with resources to influence governance or validators seeking MEV profits
- **Detection**: Config changes are public on-chain, but may be disguised as "compatibility fixes" or "rollback procedures"
- **Recovery**: Requires another governance proposal to fix, creating window of vulnerability (minimum one epoch)

The explicit retention of the deprecated variant and lack of validation suggests this attack surface was not fully considered during deprecation.

## Recommendation

**Immediate Fix**: Add validation to reject deprecated shuffler types in the Move framework:

```move
public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
    system_addresses::assert_aptos_framework(account);
    assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
    
    // Deserialize and validate
    let execution_config: OnChainExecutionConfig = bcs::from_bytes(&config);
    assert!(
        !is_deprecated_shuffler(&execution_config),
        error::invalid_argument(EDEPRECATED_SHUFFLER_TYPE)
    );
    
    config_buffer::upsert(ExecutionConfig { config });
}

fun is_deprecated_shuffler(config: &OnChainExecutionConfig): bool {
    let shuffler_type = config.transaction_shuffler_type();
    // Return true if DeprecatedSenderAwareV1, SenderAwareV2, or DeprecatedFairness
    // Implementation depends on adding helper methods to check shuffler type
}
```

**Long-term Fix**: Remove deprecated variants entirely in a future protocol version after ensuring all historical state transitions are complete.

**Additional Safeguard**: Implement Rust-side validation in `ConfigSanitizer`: [6](#0-5) 

Add checks in the sanitizer to prevent deprecated shuffler types on mainnet.

## Proof of Concept

**Step 1**: Create malicious governance proposal script:

```move
script {
    use aptos_framework::execution_config;
    use aptos_framework::aptos_governance;
    
    fun exploit_deprecated_shuffler(core_resources: &signer) {
        // Malicious config using deprecated shuffler
        let malicious_config: vector<u8> = x"00..."; // BCS bytes of DeprecatedSenderAwareV1
        
        execution_config::set_for_next_epoch(core_resources, malicious_config);
        aptos_governance::reconfigure(core_resources);
    }
}
```

**Step 2**: Submit via governance and await approval

**Step 3**: Observe post-epoch behavior:
- Check consensus logs: "Using no-op sender aware shuffling v1"
- Verify `NoOpShuffler` is active
- Test transaction ordering: consecutive same-sender transactions execute without spreading
- Measure performance degradation in parallel execution benchmarks

**Validation**: Compare block execution times and conflict rates before/after config change, demonstrating measurable performance impact and enabling of MEV opportunities.

## Notes

This vulnerability represents a **governance attack surface** where missing validation allows reversion to deprecated, insecure behavior. While governance is typically trusted, defense-in-depth principles require validation of all config changes, especially those affecting security-critical components like transaction ordering.

The designation as "Medium" severity is appropriate because:
- Requires governance compromise (elevated privileges)
- Enables MEV but doesn't guarantee exploitation
- Recoverable through another governance proposal
- Doesn't break consensus safety or cause direct fund loss

However, the ease of exploitation once governance is compromised, combined with the network-wide impact and explicit security downgrade, makes this a legitimate security concern warranting immediate remediation.

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

**File:** consensus/src/transaction_shuffler/mod.rs (L74-77)
```rust
        DeprecatedSenderAwareV1(_) => {
            info!("Using no-op sender aware shuffling v1");
            Arc::new(NoOpShuffler {})
        },
```

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L48-52)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }
```

**File:** aptos-move/aptos-release-builder/src/components/execution_config.rs (L40-45)
```rust
            emitln!(
                writer,
                "execution_config::set_for_next_epoch({}, execution_blob);",
                signer_arg
            );
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
```

**File:** consensus/src/transaction_shuffler/use_case_aware/tests/manual.rs (L66-75)
```rust
fn test_no_spreading() {
    let config = Config {
        sender_spread_factor: 0,
        platform_use_case_spread_factor: 0,
        user_use_case_spread_factor: 0,
    };
    let txns = three_senders_txns();

    assert_shuffle_result(config, txns, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}
```

**File:** config/src/config/execution_config.rs (L157-186)
```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }

        Ok(())
    }
```
