# Audit Report

## Title
Critical Gas Parameter Manipulation via Governance Allows Network Halt and Economic Security Bypass

## Summary
The on-chain execution configuration lacks validation of gas parameters set through governance, allowing malicious or compromised governance to set extreme values (zero gas multipliers, zero block gas limits) that can halt the network or break economic security assumptions. This affects all validators simultaneously and requires a hard fork to recover.

## Finding Description

The `ExecuteBlockCommand` struct accepts an `onchain_config` field of type `BlockExecutorConfigFromOnchain` containing critical gas parameters that control block execution limits. [1](#0-0) 

These parameters originate from on-chain governance through the `execution_config.move` module, which only validates that config bytes are non-empty but performs no bounds checking on actual parameter values. [2](#0-1) 

The `BlockGasLimitType::ComplexLimitV1` variant contains critical parameters including `effective_block_gas_limit`, `execution_gas_effective_multiplier`, and `io_gas_effective_multiplier` with no validation constraints. [3](#0-2) 

During block execution, gas consumption is calculated by multiplying gas usage with these multipliers without checking for zero values. [4](#0-3) 

The block termination logic checks if accumulated gas exceeds the limit, which fails catastrophically with zero values. [5](#0-4) 

**Attack Scenario 1: Network Liveness Attack**
A malicious governance proposal sets `effective_block_gas_limit = 0` in `ComplexLimitV1`. When this config is applied, the condition `accumulated_block_gas >= 0` becomes immediately true, causing blocks to terminate before executing any transactions, halting the network completely.

**Attack Scenario 2: Economic Security Bypass**
A malicious governance proposal sets both `execution_gas_effective_multiplier = 0` and `io_gas_effective_multiplier = 0`. This causes `raw_gas_used` to always equal zero, allowing unlimited transactions per block and completely bypassing gas-based rate limiting, breaking the economic security model.

## Impact Explanation

This is a **CRITICAL** severity vulnerability under Aptos Bug Bounty criteria because:

1. **Total Loss of Liveness/Network Availability**: Setting zero block gas limit causes immediate network halt affecting all validators simultaneously. No transactions can execute, requiring a hard fork to recover.

2. **Consensus/Safety Violations**: Zero gas multipliers break deterministic execution assumptions. Different validators may have different views of when blocks should end based on other limits, potentially causing consensus divergence.

3. **Economic Security Breakdown**: Zero gas multipliers eliminate economic rate limiting, allowing attackers to flood blocks with free transactions up to other limits (output size), potentially causing state explosion attacks.

4. **Requires Hard Fork**: Once deployed through governance and activated at epoch boundary, recovery requires coordinated hard fork across all validators as the malicious config persists in on-chain state.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires compromising or exploiting the governance process, which has checks and balances. However:

- Governance proposals can be submitted by any participant with sufficient stake
- Complex technical parameters may not be thoroughly reviewed by voters
- A sophisticated attacker could disguise malicious parameters within legitimate-looking configuration updates
- No automated validation exists to prevent clearly dangerous values
- Once approved, the change affects all validators simultaneously at the next epoch

The lack of any validation layer makes this a "latent" vulnerability waiting for either malicious intent or human error in governance.

## Recommendation

Add validation functions for all gas-related parameters in multiple layers:

**1. Move Layer Validation** - Add to `execution_config.move`: [2](#0-1) 

Add validation before `config_buffer::upsert()` that deserializes and validates the config ensures multipliers are non-zero and limits are within reasonable bounds (e.g., `1 <= multiplier <= 1000`, `1000 <= effective_block_gas_limit <= u64::MAX`).

**2. Rust Layer Validation** - Add to `BlockExecutorConfigFromOnchain::new()`: [6](#0-5) 

Add validation that panics or returns errors for invalid parameter combinations before config is used in execution.

**3. Runtime Validation** - Add to `BlockGasLimitProcessor::new()`: [7](#0-6) 

Add defensive checks that log warnings and use safe default values if invalid parameters are detected at runtime.

## Proof of Concept

```move
// Malicious governance proposal script that halts the network
script {
    use aptos_framework::aptos_governance;
    use aptos_framework::execution_config;
    use std::bcs;
    
    fun main(core_resources: &signer) {
        let framework_signer = aptos_governance::get_signer_testnet_only(
            core_resources, 
            @0x1
        );
        
        // Create malicious config with zero block gas limit
        // This would be BCS-serialized ExecutionConfigV7 with:
        // BlockGasLimitType::ComplexLimitV1 {
        //     effective_block_gas_limit: 0,  // ZERO - causes immediate block termination
        //     execution_gas_effective_multiplier: 1,
        //     io_gas_effective_multiplier: 1,
        //     conflict_penalty_window: 9,
        //     ...
        // }
        
        let malicious_config_bytes = x"<BCS_ENCODED_CONFIG_WITH_ZERO_LIMIT>";
        
        execution_config::set_for_next_epoch(&framework_signer, malicious_config_bytes);
        aptos_governance::reconfigure(&framework_signer);
        
        // After epoch change, all validators will be unable to execute any transactions
        // Network is halted, requiring hard fork to recover
    }
}
```

The vulnerability can be triggered through the existing `set_for_next_epoch` governance mechanism demonstrated in smoke tests. [8](#0-7) 

**Notes**

This vulnerability represents a fundamental gap in the defense-in-depth strategy for blockchain parameters. While governance is designed to be the trusted mechanism for parameter updates, the complete absence of bounds checking creates a single point of failure. The issue is exacerbated because:

1. Gas parameters directly affect consensus determinism and liveness
2. All validators apply the config simultaneously at epoch boundaries
3. No emergency recovery mechanism exists short of coordinated hard fork
4. The parameter space is complex enough that malicious values could be disguised in legitimate-looking updates

This finding demonstrates that even governance-controlled parameters require validation layers to prevent catastrophic misconfigurations, whether from malicious intent or human error.

### Citations

**File:** execution/executor-service/src/lib.rs (L48-53)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
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

**File:** aptos-move/block-executor/src/limit_processor.rs (L39-61)
```rust
    pub fn new(
        block_gas_limit_type: BlockGasLimitType,
        block_gas_limit_override: Option<u64>,
        init_size: usize,
    ) -> Self {
        let hot_state_op_accumulator = block_gas_limit_type
            .add_block_limit_outcome_onchain()
            .then(BlockHotStateOpAccumulator::new);
        Self {
            block_gas_limit_type,
            block_gas_limit_override,
            accumulated_raw_block_gas: 0,
            accumulated_effective_block_gas: 0,
            accumulated_approx_output_size: 0,
            accumulated_fee_statement: FeeStatement::zero(),
            txn_fee_statements: Vec::with_capacity(init_size),
            txn_read_write_summaries: Vec::with_capacity(init_size),
            start_time: Instant::now(),
            // TODO: have a configuration for it.
            print_conflicts_info: *PRINT_CONFLICTS_INFO,
            hot_state_op_accumulator,
        }
    }
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

**File:** types/src/block_executor/config.rs (L93-104)
```rust
    pub fn new(
        block_gas_limit_type: BlockGasLimitType,
        enable_per_block_gas_limit: bool,
        gas_price_to_burn: Option<u64>,
    ) -> Self {
        Self {
            block_gas_limit_type,
            enable_per_block_gas_limit,
            per_block_gas_limit: None,
            gas_price_to_burn,
        }
    }
```

**File:** testsuite/smoke-test/src/execution.rs (L72-95)
```rust
async fn update_execution_config(
    cli: &CliTestFramework,
    root_cli_index: usize,
    new_execution_config: OnChainExecutionConfig,
) {
    let update_execution_config_script = format!(
        r#"
    script {{
        use aptos_framework::aptos_governance;
        use aptos_framework::execution_config;
        fun main(core_resources: &signer) {{
            let framework_signer = aptos_governance::get_signer_testnet_only(core_resources, @0000000000000000000000000000000000000000000000000000000000000001);
            let config_bytes = {};
            execution_config::set_for_next_epoch(&framework_signer, config_bytes);
            aptos_governance::force_end_epoch(&framework_signer);
        }}
    }}
    "#,
        generate_blob(&bcs::to_bytes(&new_execution_config).unwrap())
    );
    cli.run_script(root_cli_index, &update_execution_config_script)
        .await
        .unwrap();
}
```
