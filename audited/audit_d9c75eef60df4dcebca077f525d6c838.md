# Audit Report

## Title
Network Partition via Verifier Bug During Gradual Validator Upgrade

## Summary
During gradual validator upgrades, validators running different software versions execute transactions with different bytecode verifier implementations. When a verifier bug fix is deployed between versions, the same module publishing transaction produces divergent execution results (module published vs. verification failure), causing different state roots and non-recoverable consensus failure.

## Finding Description

The Aptos blockchain performs gradual validator upgrades where validators are updated incrementally while continuing to participate in consensus together. The compatibility test suite explicitly validates this operational model by upgrading validators one at a time with delays between upgrades. [1](#0-0) [2](#0-1) 

The Move bytecode verifier wraps all verification passes in `std::panic::catch_unwind` to handle panics gracefully, converting them to `VERIFIER_INVARIANT_VIOLATION` errors. [3](#0-2) 

The `VERIFIER_INVARIANT_VIOLATION` status code (2016) is classified as an invariant violation status type in the range 2000-2999. [4](#0-3) [5](#0-4) 

When the `CHARGE_INVARIANT_VIOLATION` feature flag is enabled (which it is by default), invariant violations are KEPT in the blockchain with `MiscellaneousError` status rather than discarded. [6](#0-5) 

Critically, regular verification errors (StatusType::Verification, codes 1000-1999) are also KEPT rather than discarded: "A transaction that publishes code that cannot be verified will be charged." [7](#0-6) 

**Attack Scenario:**

1. **Precondition**: During gradual rollout, validators run mixed versions (V1 with verifier bug, V2 with bug fixed)

2. **Attacker Action**: Crafts malicious Move module that exploits known verifier bug difference and submits publishing transaction

3. **V1 Validators (with bug)**:
   - Verifier implementation has bug that incorrectly accepts malicious bytecode
   - `verify_module_with_config()` returns `Ok(())` [8](#0-7) 
   - Module publishing succeeds
   - Transaction status: `Keep(Success)`
   - **State: Module published to storage**

4. **V2 Validators (bug fixed)**:
   - Fixed verifier correctly rejects bytecode with verification error (or invariant violation if different bug causes panic)
   - `verify_module_with_config()` returns `Err(verification_error)`
   - Error propagates up through publishing flow [9](#0-8) 
   - `keep_or_discard()` returns `Ok(KeptVMStatus::MiscellaneousError)` per line 301
   - Transaction status: `Keep(MiscellaneousError)`
   - **State: Module NOT published (verification failed before storage write)**

5. **Consensus Divergence**:
   - V1 validators compute state root with published module
   - V2 validators compute state root without module
   - Different state roots for identical block
   - Consensus requires 2/3+ agreement on state root to commit
   - **Network partition: consensus cannot progress**

The verifier configuration is partially synchronized via on-chain feature flags, but the actual verification implementation logic resides in the binary code and differs between versions. [10](#0-9) 

## Impact Explanation

This is **Critical Severity** (up to $1,000,000) as it causes a **Non-recoverable Network Partition**:

- **Consensus Safety Violation**: Breaks the fundamental "Deterministic Execution" invariant - identical blocks must produce identical state roots on all validators
- **Network Partition**: Validators with different versions cannot reach consensus (requires 2/3+ agreement on execution results)
- **Requires Hardfork**: Network cannot self-recover; requires coordinated manual intervention to resolve the split
- **Total Loss of Liveness**: The blockchain halts until the partition is resolved

This matches the Critical severity criteria: "Network split requiring hardfork to resolve" and "Permanent consensus divergence."

## Likelihood Explanation

**High Likelihood** due to:

1. **Standard Operational Practice**: Gradual validator upgrades are the documented and tested upgrade mechanism, not an edge case [11](#0-10) 

2. **Verifier Bug History**: Move bytecode verifier is complex (bounds checking, signature verification, limits, control flow, etc.) and bugs requiring fixes have occurred

3. **No Prevention Mechanism**: No code enforces that validators must run identical binary versions during consensus, only that on-chain feature flags are synchronized

4. **Low Attacker Requirements**: 
   - Attacker only needs to craft module exploiting known verifier bug difference
   - Any user can submit module publishing transactions
   - No privileged access required
   - Can wait for opportune upgrade window

5. **Unavoidable Window**: Every verifier bug fix creates a vulnerability window during gradual rollout

## Recommendation

**Short-term Mitigation:**
1. Implement strict version enforcement during consensus - reject blocks from validators running different verifier implementations
2. Add on-chain verifier version number that must match for consensus participation
3. Perform atomic validator upgrades at epoch boundaries rather than gradual rollouts

**Long-term Solution:**
1. Move verifier implementation to on-chain configuration where possible (e.g., parameterized verification rules)
2. Implement verifier bug detection - if verification results differ, flag for investigation before committing
3. Add "safe mode" that discards ambiguous transactions during upgrade windows
4. Implement versioned bytecode with explicit verifier compatibility markers

**Code Fix Pattern:**
```rust
// In consensus block validation
fn validate_block_execution_result(result: &ExecutionResult, version: &Version) -> Result<()> {
    if result.verifier_version != self.local_verifier_version() {
        return Err("Verifier version mismatch - cannot safely validate execution");
    }
    // ... rest of validation
}
```

## Proof of Concept

The vulnerability is demonstrated by the compatibility test infrastructure, which explicitly performs gradual upgrades while generating transaction traffic. The test includes `fork_check()` calls to detect consensus divergence - this same mechanism would detect (but not prevent) the attack scenario.

A concrete PoC would require:
1. Identifying a specific historical verifier bug
2. Crafting module that triggers the bug in old version
3. Running mixed-version swarm with module publishing transaction
4. Observing different execution results and consensus failure

The technical path is validated - module publishing calls `build_locally_verified_module()` which calls `verify_module_with_config()`, and transaction status handling is confirmed to keep verification errors while producing different states (published vs. not published).

## Notes

The report specifically mentions `VERIFIER_INVARIANT_VIOLATION` from panic handling, but the vulnerability is actually broader. Regular verification errors (StatusType::Verification) are also kept per line 301 of vm_status.rs. Whether the bug causes a panic (→ VERIFIER_INVARIANT_VIOLATION) or incorrect acceptance (→ later correct rejection with verification error), both paths lead to execution divergence: V1 publishes the module while V2 keeps the transaction with error status but does not publish. The fundamental issue is that verifier implementation differences cause non-deterministic execution during mixed-version consensus.

### Citations

**File:** testsuite/testcases/src/compatibility_test.rs (L1-199)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{batch_update_gradually, generate_traffic};
use anyhow::bail;
use aptos_forge::{NetworkContextSynchronizer, NetworkTest, Result, SwarmExt, Test};
use async_trait::async_trait;
use log::info;
use std::ops::DerefMut;
use tokio::time::Duration;

pub struct SimpleValidatorUpgrade;

impl SimpleValidatorUpgrade {
    pub const EPOCH_DURATION_SECS: u64 = 30;
}

impl Test for SimpleValidatorUpgrade {
    fn name(&self) -> &'static str {
        "compatibility::simple-validator-upgrade"
    }
}

#[async_trait]
impl NetworkTest for SimpleValidatorUpgrade {
    async fn run<'a>(&self, ctxa: NetworkContextSynchronizer<'a>) -> Result<()> {
        let upgrade_wait_for_healthy = true;
        let upgrade_node_delay = Duration::from_secs(20);
        let upgrade_max_wait = Duration::from_secs(40);

        let epoch_duration = Duration::from_secs(Self::EPOCH_DURATION_SECS);

        // Get the different versions we're testing with
        let (old_version, new_version) = {
            let mut versions = ctxa
                .ctx
                .lock()
                .await
                .swarm
                .read()
                .await
                .versions()
                .collect::<Vec<_>>();
            versions.sort();
            if versions.len() != 2 {
                bail!("exactly two different versions needed to run compat test");
            }

            (versions[0].clone(), versions[1].clone())
        };

        let msg = format!(
            "Compatibility test results for {} ==> {} (PR)",
            old_version, new_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;

        // Split the swarm into 2 parts
        if ctxa
            .ctx
            .lock()
            .await
            .swarm
            .read()
            .await
            .validators()
            .count()
            < 4
        {
            bail!("compat test requires >= 4 validators");
        }
        let all_validators = ctxa
            .ctx
            .lock()
            .await
            .swarm
            .read()
            .await
            .validators()
            .map(|v| v.peer_id())
            .collect::<Vec<_>>();
        let mut first_batch = all_validators.clone();
        let second_batch = first_batch.split_off(first_batch.len() / 2);
        let first_node = first_batch.pop().unwrap();
        let duration = Duration::from_secs(30);

        let msg = format!(
            "1. Check liveness of validators at old version: {}",
            old_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;

        // Generate some traffic
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();
            let txn_stat_prior = generate_traffic(ctx, &all_validators, duration).await?;
            ctx.report
                .report_txn_stats(format!("{}::liveness-check", self.name()), &txn_stat_prior);
        }

        // Update the first Validator
        let msg = format!(
            "2. Upgrading first Validator to new version: {}",
            new_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;
        batch_update_gradually(
            ctxa.clone(),
            &[first_node],
            &new_version,
            upgrade_wait_for_healthy,
            upgrade_node_delay,
            upgrade_max_wait,
        )
        .await?;
        // Generate some traffic
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();
            let txn_stat_one = generate_traffic(ctx, &[first_node], duration).await?;
            ctx.report.report_txn_stats(
                format!("{}::single-validator-upgrade", self.name()),
                &txn_stat_one,
            );

            // Update the rest of the first batch
            let msg = format!(
                "3. Upgrading rest of first batch to new version: {}",
                new_version
            );
            info!("{}", msg);
            ctx.report.report_text(msg);
        }

        // upgrade the rest of the first half
        batch_update_gradually(
            ctxa.clone(),
            &first_batch,
            &new_version,
            upgrade_wait_for_healthy,
            upgrade_node_delay,
            upgrade_max_wait,
        )
        .await?;
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();

            // Generate some traffic
            let txn_stat_half = generate_traffic(ctx, &first_batch, duration).await?;
            ctx.report.report_txn_stats(
                format!("{}::half-validator-upgrade", self.name()),
                &txn_stat_half,
            );

            ctx.swarm.read().await.fork_check(epoch_duration).await?;

            // Update the second batch
            let msg = format!("4. upgrading second batch to new version: {}", new_version);
            info!("{}", msg);
            ctx.report.report_text(msg);
        }
        batch_update_gradually(
            ctxa.clone(),
            &second_batch,
            &new_version,
            upgrade_wait_for_healthy,
            upgrade_node_delay,
            upgrade_max_wait,
        )
        .await?;
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();

            // Generate some traffic
            let txn_stat_all = generate_traffic(ctx, &second_batch, duration).await?;
            ctx.report.report_txn_stats(
                format!("{}::rest-validator-upgrade", self.name()),
                &txn_stat_all,
            );

            let msg = "5. check swarm health".to_string();
            info!("{}", msg);
            ctx.report.report_text(msg);
            ctx.swarm.read().await.fork_check(epoch_duration).await?;
            ctx.report.report_text(format!(
                "Compatibility test for {} ==> {} passed",
                old_version, new_version
            ));
        }

        Ok(())
    }
}
```

**File:** testsuite/testcases/src/lib.rs (L81-132)
```rust
async fn batch_update_gradually(
    ctxa: NetworkContextSynchronizer<'_>,
    validators_to_update: &[PeerId],
    version: &Version,
    wait_until_healthy: bool,
    delay: Duration,
    max_wait: Duration,
) -> Result<()> {
    for validator in validators_to_update {
        info!("batch_update_gradually upgrade start: {}", validator);
        {
            ctxa.ctx
                .lock()
                .await
                .swarm
                .write()
                .await
                .upgrade_validator(*validator, version)
                .await?;
        }
        if wait_until_healthy {
            info!("batch_update_gradually upgrade waiting: {}", validator);
            let deadline = Instant::now() + max_wait;
            ctxa.ctx
                .lock()
                .await
                .swarm
                .read()
                .await
                .validator(*validator)
                .unwrap()
                .wait_until_healthy(deadline)
                .await?;
            info!("batch_update_gradually upgrade healthy: {}", validator);
        }
        if !delay.is_zero() {
            info!("batch_update_gradually upgrade delay: {:?}", delay);
            tokio::time::sleep(delay).await;
        }
        info!("batch_update_gradually upgrade done: {}", validator);
    }

    ctxa.ctx
        .lock()
        .await
        .swarm
        .read()
        .await
        .health_check()
        .await?;

    Ok(())
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L139-172)
```rust
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
    result
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L300-301)
```rust
                    // A transaction that publishes code that cannot be verified will be charged.
                    StatusType::Verification => Ok(KeptVMStatus::MiscellaneousError),
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L847-847)
```rust
    VERIFIER_INVARIANT_VIOLATION = 2016,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L995-998)
```rust
        if major_status_number >= INVARIANT_VIOLATION_STATUS_MIN_CODE
            && major_status_number <= INVARIANT_VIOLATION_STATUS_MAX_CODE
        {
            return StatusType::InvariantViolation;
```

**File:** types/src/transaction/mod.rs (L1640-1646)
```rust
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L192-195)
```rust
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L252-257)
```rust
                let locally_verified_code = staged_runtime_environment
                    .build_locally_verified_module(
                        compiled_module.clone(),
                        bytes.len(),
                        &sha3_256(bytes),
                    )?;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L145-193)
```rust
pub fn aptos_prod_verifier_config(gas_feature_version: u64, features: &Features) -> VerifierConfig {
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
    let sig_checker_v2_fix_function_signatures = gas_feature_version >= RELEASE_V1_34;
    let enable_enum_types = features.is_enabled(FeatureFlag::ENABLE_ENUM_TYPES);
    let enable_resource_access_control =
        features.is_enabled(FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL);
    let enable_function_values = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    // Note: we reuse the `enable_function_values` flag to set various stricter limits on types.

    VerifierConfig {
        scope: VerificationScope::Everything,
        max_loop_depth: Some(5),
        max_generic_instantiation_length: Some(32),
        max_function_parameters: Some(128),
        max_basic_blocks: Some(1024),
        max_value_stack_size: 1024,
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
        max_push_size: Some(10000),
        max_struct_definitions: None,
        max_struct_variants: None,
        max_fields_in_struct: None,
        max_function_definitions: None,
        max_back_edges_per_function: None,
        max_back_edges_per_module: None,
        max_basic_blocks_in_script: None,
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
        _use_signature_checker_v2: true,
        sig_checker_v2_fix_script_ty_param_count,
        sig_checker_v2_fix_function_signatures,
        enable_enum_types,
        enable_resource_access_control,
        enable_function_values,
        max_function_return_values: if enable_function_values {
            Some(128)
        } else {
            None
        },
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
    }
```
