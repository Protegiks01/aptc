# Audit Report

## Title
Zero Concurrency Level Causes Validator Node Panic Due to Dual `num_cpus::get()` Evaluation

## Summary
A validator node can panic during block execution if `num_cpus::get()` returns 0 during the second evaluation in `AptosVM::set_concurrency_level_once()`, bypassing the clamp protection in `set_aptos_vm_configurations()` and triggering an assertion failure in `BlockExecutor::new()`.

## Finding Description

The vulnerability exists due to `num_cpus::get()` being called **twice** in the concurrency level initialization path without consistent validation:

**First Call** - In `set_aptos_vm_configurations()`, when `concurrency_level` config is 0 (the default): [1](#0-0) 

The calculation `((num_cpus::get() / 2) as u16).clamp(1, DEFAULT_EXECUTION_CONCURRENCY_LEVEL)` ensures a minimum value of 1. Even if `num_cpus::get()` returns 0, the clamp operation guarantees `effective_concurrency_level` is at least 1.

**Second Call** - Inside `AptosVM::set_concurrency_level_once()`: [2](#0-1) 

The function performs `min(concurrency_level, num_cpus::get())`. If `num_cpus::get()` returns 0 here, then `min(1, 0) = 0`, setting `EXECUTION_CONCURRENCY_LEVEL` to 0.

**Exploitation Path**:
When block execution occurs, the concurrency level is retrieved: [3](#0-2) 

This zero value is then used in the BlockExecutorConfig: [4](#0-3) 

The config is passed to `BlockExecutor::new()`, which has a strict assertion: [5](#0-4) 

The assertion `config.local.concurrency_level > 0` fails, causing an immediate panic and crashing the validator node.

**Triggering Conditions**:
The default configuration uses `concurrency_level = 0` for auto-detection: [6](#0-5) 

Running in a severely misconfigured containerized environment where `num_cpus::get()` returns 0.

## Impact Explanation

**Severity: High** (up to $50,000 per bug bounty criteria)

This qualifies as a **High Severity** issue under "Validator node slowdowns" and "API crashes" categories. Specifically:

- **Single Validator Loss of Liveness**: The affected validator node cannot execute blocks and panics when attempting block execution
- **Non-Recoverable State**: The node requires manual restart and reconfiguration to recover
- **No Network-Wide Impact**: Other validators continue operating normally, so this does NOT cause total network halt or consensus failure

While this doesn't cause consensus safety violations or fund loss directly, it impacts individual validator availability, which qualifies under the High severity category for validator node crashes.

## Likelihood Explanation

**Likelihood: LOW** (Corrected from report's Medium-High assessment)

The vulnerability is theoretically possible but extremely unlikely in production:

1. **Requires Severe Misconfiguration**: The `num_cpus` crate must return 0, which only occurs in extremely misconfigured environments (malformed cgroups, zero CPU affinity masks, etc.)

2. **Unlikely Scenario**: If an environment is so misconfigured that `num_cpus::get()` returns 0, it would likely return 0 consistently for both calls during initialization (milliseconds apart), not change between them

3. **Logic Flaw Exists**: However, the code does have inconsistent validation - the first call applies `.clamp(1, ...)` protection while the second call does not, which is a clear logic flaw

4. **Default Configuration Vulnerability**: The default `concurrency_level = 0` means all validators rely on auto-detection

This is a **logic vulnerability** where inconsistent validation could lead to a panic, even though practical triggering conditions are extremely rare.

## Recommendation

Apply consistent validation in both locations. Fix `set_concurrency_level_once()` to ensure a minimum value:

```rust
pub fn set_concurrency_level_once(mut concurrency_level: usize) {
    concurrency_level = min(concurrency_level, num_cpus::get()).max(1);
    EXECUTION_CONCURRENCY_LEVEL.set(concurrency_level).ok();
}
```

Alternatively, cache the `num_cpus::get()` result from the first call and reuse it in the second call to ensure consistency.

## Proof of Concept

No executable PoC provided. This would require creating an environment where `num_cpus::get()` returns 0, which is extremely difficult to reproduce in practice.

## Notes

While this is a valid logic flaw with real impact, the likelihood has been corrected to LOW (not Medium-High as originally claimed). The vulnerability represents a robustness issue in edge-case handling rather than a practically exploitable security flaw. The inconsistent validation between two `num_cpus::get()` calls is a genuine code defect that should be fixed, but the practical risk to production validators is minimal given the extreme environmental conditions required for triggering.

### Citations

**File:** aptos-node/src/utils.rs (L57-61)
```rust
    let effective_concurrency_level = if node_config.execution.concurrency_level == 0 {
        ((num_cpus::get() / 2) as u16).clamp(1, DEFAULT_EXECUTION_CONCURRENCY_LEVEL)
    } else {
        node_config.execution.concurrency_level
    };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L426-430)
```rust
    pub fn set_concurrency_level_once(mut concurrency_level: usize) {
        concurrency_level = min(concurrency_level, num_cpus::get());
        // Only the first call succeeds, due to OnceCell semantics.
        EXECUTION_CONCURRENCY_LEVEL.set(concurrency_level).ok();
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L436-441)
```rust
    pub fn get_concurrency_level() -> usize {
        match EXECUTION_CONCURRENCY_LEVEL.get() {
            Some(concurrency_level) => *concurrency_level,
            None => 1,
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3110-3119)
```rust
        let config = BlockExecutorConfig {
            local: BlockExecutorLocalConfig {
                blockstm_v2: AptosVM::get_blockstm_v2_enabled(),
                concurrency_level: AptosVM::get_concurrency_level(),
                allow_fallback: true,
                discard_failed_blocks: AptosVM::get_discard_failed_blocks(),
                module_cache_config: BlockExecutorModuleCacheLocalConfig::default(),
            },
            onchain: onchain_config,
        };
```

**File:** aptos-move/block-executor/src/executor.rs (L127-132)
```rust
        assert!(
            config.local.concurrency_level > 0 && config.local.concurrency_level <= num_cpus,
            "Parallel execution concurrency level {} should be between 1 and number of CPUs ({})",
            config.local.concurrency_level,
            num_cpus,
        );
```

**File:** config/src/config/execution_config.rs (L83-84)
```rust
            // use min of (num of cores/2, DEFAULT_CONCURRENCY_LEVEL) as default concurrency level
            concurrency_level: 0,
```
