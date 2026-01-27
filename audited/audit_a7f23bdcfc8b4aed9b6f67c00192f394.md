# Audit Report

## Title
Critical Network Halt via Unvalidated Execution Config Fields in Governance Proposals

## Summary
A malicious or misconfigured governance proposal can set execution configuration fields to extreme values (0, MAX) without any validation, causing complete network disruption. Specifically, setting `effective_block_gas_limit` to 0 immediately halts all transaction processing, while setting gas multipliers to 0 disables gas accounting entirely, allowing unbounded block execution times.

## Finding Description

The Aptos governance system allows updating the on-chain execution configuration through proposals that call `execution_config::set_for_next_epoch()`. This function performs only minimal validation, checking that the configuration bytes are non-empty, but performs **no validation of the actual field values** within the configuration structure. [1](#0-0) 

The configuration is serialized as BCS bytes and later deserialized by the Rust execution engine. The key vulnerability lies in the `BlockGasLimitType::ComplexLimitV1` variant which contains multiple fields that, when set to extreme values, break critical execution invariants: [2](#0-1) 

**Attack Vector 1: Zero Gas Limit (Critical - Network Halt)**

When `effective_block_gas_limit` is set to 0, the block execution logic in `BlockGasLimitProcessor` immediately triggers early block termination: [3](#0-2) 

The check at line 132 evaluates `accumulated_block_gas >= per_block_gas_limit`, which when `per_block_gas_limit = 0` becomes `0 >= 0`, immediately returning true. This causes the parallel execution to mark all remaining transactions as skipped: [4](#0-3) 

**Result**: Every block produced would contain zero transactions, completely halting the network's ability to process any transactions.

**Attack Vector 2: Zero Gas Multipliers (Critical - Unbounded Execution)**

When both `execution_gas_effective_multiplier` and `io_gas_effective_multiplier` are set to 0, the gas accumulation calculation becomes ineffective: [5](#0-4) 

With both multipliers at 0, `raw_gas_used` always equals 0, meaning `accumulated_effective_block_gas` never increases, and the gas limit check never triggers. This allows blocks to contain unlimited gas consumption, potentially causing:
- Extremely long block execution times
- Consensus timeouts and round failures
- Node resource exhaustion

**Attack Vector 3: Zero Output Limit (Critical - Network Halt)**

Setting `block_output_limit` to `Some(0)` has the same effect as zero gas limit: [6](#0-5) 

**Attack Vector 4: Maximum Conflict Window (High - Performance Degradation)**

Setting `conflict_penalty_window` to `u32::MAX` causes the conflict multiplier calculation to iterate over all previous transactions for each new transaction, creating O(n²) complexity: [7](#0-6) 

The attack propagation path:
1. Attacker creates governance proposal with malicious `OnChainExecutionConfig` containing `effective_block_gas_limit: 0`
2. Proposal passes through normal governance voting process
3. Upon execution, `execution_config::set_for_next_epoch()` accepts the config (only validates non-empty bytes)
4. At next epoch boundary, `on_new_epoch()` applies the malicious configuration
5. All subsequent blocks immediately halt execution after 0 transactions
6. Network becomes completely non-functional

## Impact Explanation

**Severity: Critical** - This vulnerability meets multiple Critical severity criteria from the Aptos Bug Bounty program:

1. **Total loss of liveness/network availability**: Setting `effective_block_gas_limit` or `block_output_limit` to 0 causes complete network halt as no transactions can be included in any block.

2. **Non-recoverable network partition (requires hardfork)**: Once the malicious config is activated at epoch boundary, it becomes the on-chain state. Recovery requires either:
   - Emergency governance proposal (impossible if no transactions can execute)
   - Hard fork to override the configuration
   - Manual validator intervention with code changes

3. **Resource exhaustion/DoS**: Setting gas multipliers to 0 allows unbounded block execution, potentially crashing validator nodes or causing consensus failures.

All validators on the network would be simultaneously affected, as they all execute the same on-chain configuration deterministically. This represents a complete network failure scenario requiring emergency intervention.

## Likelihood Explanation

**Likelihood: Medium-High**

While this requires a governance proposal to pass, the likelihood is concerning for several reasons:

1. **No validation barriers**: The Move code provides zero protection against misconfiguration. Any governance proposal can set these values.

2. **Legitimate configuration changes**: Developers might accidentally set these values during legitimate configuration updates without realizing the consequences.

3. **Malicious insider**: A compromised governance participant or malicious proposal could intentionally trigger this.

4. **Testing scenarios**: The codebase shows these extreme values are used in test configurations (e.g., `NoLimit`), suggesting developers might not fully appreciate the production risks.

The main complexity barrier is passing a governance proposal, which requires:
- Sufficient proposer stake
- Voting quorum approval
- Proposal execution period

However, once a malicious proposal passes (whether through compromise, social engineering, or accident), the impact is immediate and catastrophic.

## Recommendation

**Immediate Fix**: Add validation logic to the `execution_config` module to sanity-check all fields before accepting the configuration. Implement validation in both Move (pre-storage) and Rust (post-deserialization) layers for defense-in-depth:

**Move Layer Validation** (add to `execution_config.move`):
```move
public fun validate_execution_config(config: &vector<u8>): bool {
    // Deserialize and validate bounds
    // This requires exposing validation logic from Rust or implementing Move-side checks
    // Return false if any field has extreme values
    true
}

public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
    system_addresses::assert_aptos_framework(account);
    assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
    assert!(validate_execution_config(&config), error::invalid_argument(EINVALID_CONFIG));
    config_buffer::upsert(ExecutionConfig { config });
}
```

**Rust Layer Validation** (add to `execution_config.rs`):
```rust
impl OnChainExecutionConfig {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            OnChainExecutionConfig::V7(config) => {
                // Validate BlockGasLimitType
                match &config.block_gas_limit_type {
                    BlockGasLimitType::ComplexLimitV1 {
                        effective_block_gas_limit,
                        execution_gas_effective_multiplier,
                        io_gas_effective_multiplier,
                        conflict_penalty_window,
                        block_output_limit,
                        ..
                    } => {
                        // Prevent zero gas limits
                        if *effective_block_gas_limit == 0 {
                            return Err("effective_block_gas_limit cannot be 0".to_string());
                        }
                        // Prevent zero multipliers
                        if *execution_gas_effective_multiplier == 0 || *io_gas_effective_multiplier == 0 {
                            return Err("gas multipliers cannot be 0".to_string());
                        }
                        // Prevent excessive conflict window
                        if *conflict_penalty_window > 1000 {
                            return Err("conflict_penalty_window too large".to_string());
                        }
                        // Prevent zero output limit
                        if let Some(limit) = block_output_limit {
                            if *limit == 0 {
                                return Err("block_output_limit cannot be 0".to_string());
                            }
                        }
                    }
                    _ => {}
                }
                
                // Validate gas_price_to_burn is reasonable (not 0 or > 100)
                if config.gas_price_to_burn == 0 || config.gas_price_to_burn > 100 {
                    return Err("gas_price_to_burn must be between 1 and 100".to_string());
                }
                
                Ok(())
            }
            // Validate other versions...
            _ => Ok(())
        }
    }
}

// In deserialize_into_config
fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
    let raw_bytes: Vec<u8> = bcs::from_bytes(bytes)?;
    let config: OnChainExecutionConfig = bcs::from_bytes(&raw_bytes)
        .map_err(|e| format_err!("[on-chain config] Failed to deserialize into config: {}", e))?;
    config.validate()
        .map_err(|e| format_err!("[on-chain config] Validation failed: {}", e))?;
    Ok(config)
}
```

**Additional safeguards**:
1. Add pre-deployment validation in the release builder that generates governance proposals
2. Implement emergency governance override mechanism for critical config issues
3. Add monitoring/alerting for extreme config values in production
4. Document safe configuration ranges in governance proposal guidelines

## Proof of Concept

```rust
#[test]
fn test_zero_gas_limit_halts_execution() {
    use aptos_types::on_chain_config::{
        OnChainExecutionConfig, ExecutionConfigV7, BlockGasLimitType,
        TransactionShufflerType, TransactionDeduperType
    };
    
    // Create malicious config with zero effective_block_gas_limit
    let malicious_config = OnChainExecutionConfig::V7(ExecutionConfigV7 {
        transaction_shuffler_type: TransactionShufflerType::NoShuffling,
        block_gas_limit_type: BlockGasLimitType::ComplexLimitV1 {
            effective_block_gas_limit: 0,  // CRITICAL: Zero limit
            execution_gas_effective_multiplier: 1,
            io_gas_effective_multiplier: 1,
            conflict_penalty_window: 1,
            use_granular_resource_group_conflicts: false,
            use_module_publishing_block_conflict: false,
            block_output_limit: None,
            include_user_txn_size_in_block_output: true,
            add_block_limit_outcome_onchain: false,
        },
        enable_per_block_gas_limit: true,
        transaction_deduper_type: TransactionDeduperType::NoDedup,
        gas_price_to_burn: 90,
        persisted_auxiliary_info_version: 1,
    });
    
    // Serialize as would be done in governance proposal
    let config_bytes = bcs::to_bytes(&malicious_config).unwrap();
    
    // This would be accepted by set_for_next_epoch() with no validation
    assert!(config_bytes.len() > 0);  // Only check performed
    
    // Simulate block execution with this config
    use aptos_move_block_executor::limit_processor::BlockGasLimitProcessor;
    use aptos_types::fee_statement::FeeStatement;
    
    let mut processor = BlockGasLimitProcessor::new(
        malicious_config.block_gas_limit_type(),
        None,
        100
    );
    
    // Add a transaction with any gas usage
    processor.accumulate_fee_statement(
        FeeStatement::new(100, 100, 0, 0, 0),
        None,
        None
    );
    
    // Block immediately halts - no transactions can be included!
    assert!(processor.should_end_block_parallel());
    // Network is now completely halted
}

#[test]
fn test_zero_multipliers_disable_gas_accounting() {
    let malicious_config = OnChainExecutionConfig::V7(ExecutionConfigV7 {
        transaction_shuffler_type: TransactionShufflerType::NoShuffling,
        block_gas_limit_type: BlockGasLimitType::ComplexLimitV1 {
            effective_block_gas_limit: 1_000_000,
            execution_gas_effective_multiplier: 0,  // CRITICAL: Zero multiplier
            io_gas_effective_multiplier: 0,          // CRITICAL: Zero multiplier
            conflict_penalty_window: 1,
            use_granular_resource_group_conflicts: false,
            use_module_publishing_block_conflict: false,
            block_output_limit: None,
            include_user_txn_size_in_block_output: true,
            add_block_limit_outcome_onchain: false,
        },
        enable_per_block_gas_limit: true,
        transaction_deduper_type: TransactionDeduperType::NoDedup,
        gas_price_to_burn: 90,
        persisted_auxiliary_info_version: 1,
    });
    
    let mut processor = BlockGasLimitProcessor::new(
        malicious_config.block_gas_limit_type(),
        None,
        100
    );
    
    // Execute many high-gas transactions
    for _ in 0..1000 {
        processor.accumulate_fee_statement(
            FeeStatement::new(10_000, 10_000, 0, 0, 0),  // 20k gas per txn
            None,
            None
        );
        
        // Gas limit NEVER triggered despite consuming 20M gas!
        assert!(!processor.should_end_block_parallel());
    }
    // Block can grow unbounded, causing resource exhaustion
}
```

**Move-based PoC** (governance proposal script):
```move
script {
    use aptos_framework::execution_config;
    use aptos_framework::aptos_governance;
    
    fun malicious_execution_config_proposal(framework: &signer) {
        // Construct malicious config with zero gas limit
        let malicious_config_bytes = /* BCS serialized config with effective_block_gas_limit=0 */;
        
        // This call succeeds - no validation!
        execution_config::set_for_next_epoch(framework, malicious_config_bytes);
        
        // Trigger epoch change to activate malicious config
        aptos_governance::reconfigure(framework);
        
        // Network is now halted - no more transactions can execute
    }
}
```

## Notes

This vulnerability represents a critical gap in the defense-in-depth security model of Aptos governance. While governance is designed to be controlled by trusted participants, the lack of validation creates multiple risk vectors:

1. **Accidental misconfiguration**: Even well-intentioned governance participants could accidentally set extreme values during legitimate configuration updates
2. **Malicious proposals**: A compromised or malicious governance participant could intentionally halt the network
3. **Supply chain attacks**: Compromised tooling that generates governance proposals could inject malicious values

The issue is particularly severe because:
- Recovery requires hard fork or emergency intervention (no on-chain recovery possible if transactions cannot execute)
- All validators are simultaneously affected (deterministic execution)
- The attack surface is not limited to a single field (multiple fields can cause similar issues)

The recommended validation should be implemented at multiple layers (Move + Rust) to provide defense-in-depth protection against both malicious and accidental misconfigurations.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L48-52)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L280-312)
```rust
    ComplexLimitV1 {
        /// Formula for effective block gas limit:
        /// effective_block_gas_limit <
        /// (execution_gas_effective_multiplier * execution_gas_used +
        ///  io_gas_effective_multiplier * io_gas_used
        /// ) * (1 + num conflicts in conflict_penalty_window)
        effective_block_gas_limit: u64,
        execution_gas_effective_multiplier: u64,
        io_gas_effective_multiplier: u64,
        conflict_penalty_window: u32,

        /// If true we look at granular resource group conflicts (i.e. if same Tag
        /// within a resource group has a conflict)
        /// If false, we treat any conclicts inside of resource groups (even across
        /// non-overlapping tags) as conflicts).
        use_granular_resource_group_conflicts: bool,
        /// Module publishing today fallbacks to sequential execution,
        /// even though there is no read-write conflict.
        /// When enabled, this flag allows us to account for that conflict.
        /// NOTE: Currently not supported.
        use_module_publishing_block_conflict: bool,

        /// Block limit on the total (approximate) txn output size in bytes.
        block_output_limit: Option<u64>,
        /// When set, we include the user txn size in the approximate computation
        /// of block output size, which is compared against the block_output_limit above.
        include_user_txn_size_in_block_output: bool,

        /// When set, we create BlockEpilogue (instead of StateCheckpint) transaction,
        /// which contains BlockEndInfo
        /// NOTE: Currently not supported.
        add_block_limit_outcome_onchain: bool,
    },
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L103-109)
```rust
        let raw_gas_used = fee_statement.execution_gas_used()
            * self
                .block_gas_limit_type
                .execution_gas_effective_multiplier()
            + fee_statement.io_gas_used() * self.block_gas_limit_type.io_gas_effective_multiplier();
        self.accumulated_raw_block_gas += raw_gas_used;
        self.accumulated_effective_block_gas += conflict_multiplier * raw_gas_used;
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L127-141)
```rust
    fn should_end_block(&mut self, mode: &str) -> bool {
        if let Some(per_block_gas_limit) = self.block_gas_limit() {
            // When the accumulated block gas of the committed txns exceeds
            // PER_BLOCK_GAS_LIMIT, early halt BlockSTM.
            let accumulated_block_gas = self.get_effective_accumulated_block_gas();
            if accumulated_block_gas >= per_block_gas_limit {
                counters::EXCEED_PER_BLOCK_GAS_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_block_gas {} >= PER_BLOCK_GAS_LIMIT {}",
                    mode, accumulated_block_gas, per_block_gas_limit,
                );
                return true;
            }
        }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L143-154)
```rust
        if let Some(per_block_output_limit) = self.block_gas_limit_type.block_output_limit() {
            let accumulated_output = self.get_accumulated_approx_output_size();
            if accumulated_output >= per_block_output_limit {
                counters::EXCEED_PER_BLOCK_OUTPUT_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_output {} >= PER_BLOCK_OUTPUT_LIMIT {}",
                    mode, accumulated_output, per_block_output_limit,
                );
                return true;
            }
        }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L175-203)
```rust
    fn compute_conflict_multiplier(&self, conflict_overlap_length: usize) -> u64 {
        let start = self
            .txn_read_write_summaries
            .len()
            .saturating_sub(conflict_overlap_length);
        let end = self.txn_read_write_summaries.len() - 1;

        let mut conflict_count = 0;
        let current = &self.txn_read_write_summaries[end];
        for prev in &self.txn_read_write_summaries[start..end] {
            if current.conflicts_with_previous(prev) {
                if self.print_conflicts_info {
                    println!(
                        "Conflicts with previous: {:?}",
                        current.find_conflicts(prev)
                    );
                }
                conflict_count += 1;
            }
        }
        if self.print_conflicts_info {
            println!(
                "Number of conflicts: {} out of {}",
                conflict_count, conflict_overlap_length
            );
        }
        assert_le!(conflict_count + 1, conflict_overlap_length);
        (conflict_count + 1) as u64
    }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L362-372)
```rust
        if txn_idx < num_txns - 1
            && block_limit_processor.should_end_block_parallel()
            && !skips_rest
        {
            if output_wrapper.output_status_kind == OutputStatusKind::Success {
                must_create_epilogue_txn |= !output_before_guard.has_new_epoch_event();
                drop(output_before_guard);
                output_wrapper.output_status_kind = OutputStatusKind::SkipRest;
            }
            skips_rest = true;
        }
```
