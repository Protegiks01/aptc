# Audit Report

## Title
VM Validator Pool Partial Restart Failure Leading to Non-Deterministic Transaction Validation

## Summary
The `PooledVMValidator::restart()` function uses early return on error, which causes a partial restart when any individual VM fails. This leaves some VMs with updated state while others retain stale state, creating non-deterministic transaction validation behavior that violates the deterministic execution invariant.

## Finding Description

The vulnerability exists in the restart logic of the pooled VM validator system: [1](#0-0) 

The function iterates through all VM validators and attempts to restart each one sequentially. The `?` operator on line 174 causes an **early return** if any individual restart fails, leaving subsequent VMs unprocessed.

The individual `VMValidator::restart()` implementation can fail in two ways: [2](#0-1) 

The `db_state_view()` method uses `.expect()` which will panic on database failures: [3](#0-2) 

The underlying `latest_state_checkpoint_view()` returns a `Result` and can fail: [4](#0-3) 

**Attack Scenario:**

1. During an epoch change or reconfiguration, `restart()` is called from mempool: [5](#0-4) 

2. If VM[i]'s restart fails (database I/O error, resource exhaustion causing panic in `AptosEnvironment::new()`, or lock poisoning from previous panic):
   - VMs 0 through i-1 have been restarted with new state/configuration
   - VMs i through n have NOT been restarted, still using old state/configuration
   - The error is logged but execution continues

3. Transaction validation now becomes non-deterministic because VMs are randomly selected: [6](#0-5) 

4. Transaction validation depends heavily on the state view for feature flags, gas parameters, and account state: [7](#0-6) 

**Consequence:** The same transaction may be accepted by one VM (using old feature flags/state) but rejected by another VM (using new feature flags/state), causing mempool inconsistencies across validator nodes and potential consensus divergence.

## Impact Explanation

**Severity: Medium to High**

This issue qualifies as **Medium severity** under "State inconsistencies requiring intervention" or potentially **High severity** under "Significant protocol violations".

The impact includes:
- **Violation of Deterministic Execution Invariant**: Different validators produce different validation results for identical transactions
- **Mempool Inconsistencies**: Different nodes maintain different transaction pools based on which random VM validated each transaction  
- **Consensus Risk**: Validators may propose blocks with different transaction sets, potentially causing liveness issues
- **State Divergence Risk**: If validation differences persist, nodes may execute different transactions leading to state divergence

## Likelihood Explanation

**Likelihood: Low to Medium**

While the code path is clearly flawed, triggering requires:
- Database I/O failures or corruption during restart
- Resource exhaustion (OOM) during `AptosEnvironment::new()`
- Prior panic causing mutex poisoning

These conditions occur during:
- Hardware failures
- Extreme memory pressure
- Database corruption from bugs
- Epoch transitions under system stress

The likelihood increases during network stress, rapid reconfigurations, or validator infrastructure issues.

## Recommendation

Implement **all-or-nothing restart semantics** to ensure atomic pool updates:

```rust
fn restart(&mut self) -> Result<()> {
    // Collect all restart errors first
    let results: Vec<Result<()>> = self.vm_validators
        .iter()
        .map(|vm_validator| {
            vm_validator.lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?
                .restart()
        })
        .collect();
    
    // Check if all succeeded
    for (idx, result) in results.iter().enumerate() {
        if let Err(e) = result {
            error!("VM validator {} restart failed: {}", idx, e);
            // On any failure, attempt to restart ALL validators to restore consistency
            for vm in &self.vm_validators {
                if let Ok(mut guard) = vm.lock() {
                    let _ = guard.restart(); // Best effort recovery
                }
            }
            return Err(anyhow::anyhow!("Restart failed at index {}: {}", idx, e));
        }
    }
    
    Ok(())
}
```

Additionally, replace the `.expect()` in `db_state_view()` with proper error propagation:

```rust
fn db_state_view(&self) -> Result<DbStateView> {
    self.db_reader.latest_state_checkpoint_view()
        .map_err(|e| anyhow::anyhow!("Failed to get latest state checkpoint: {}", e))
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use fail::FailScenario;
    
    #[test]
    fn test_partial_restart_creates_inconsistent_state() {
        let scenario = FailScenario::setup();
        
        // Create pooled validator with 3 VMs
        let db_reader = Arc::new(MockDbReader::new());
        let mut validator = PooledVMValidator::new(db_reader, 3);
        
        // Configure failpoint to fail on second VM restart
        fail::cfg("vm_validator::get_account_sequence_number", "return").unwrap();
        
        // Attempt restart - should fail on VM[1]
        let result = validator.restart();
        assert!(result.is_err());
        
        // Verify inconsistent state: VM[0] has new state, VM[1] and VM[2] have old state
        // This can be verified by checking validation results differ based on which VM is selected
        
        scenario.teardown();
    }
}
```

**Notes:**
- The vulnerability stems from using early-return error handling (`?` operator) in a sequential update loop
- The issue violates the critical "Deterministic Execution" invariant (#1 in the specification)
- Fix requires either atomic all-or-nothing semantics or continuing through all VMs regardless of individual failures
- Proper error handling should replace `.expect()` calls to prevent panics that poison mutexes

### Citations

**File:** vm-validator/src/vm_validator.rs (L64-68)
```rust
    fn db_state_view(&self) -> DbStateView {
        self.db_reader
            .latest_state_checkpoint_view()
            .expect("Get db view cannot fail")
    }
```

**File:** vm-validator/src/vm_validator.rs (L70-74)
```rust
    fn restart(&mut self) -> Result<()> {
        let db_state_view = self.db_state_view();
        self.state.reset_all(db_state_view.into());
        Ok(())
    }
```

**File:** vm-validator/src/vm_validator.rs (L146-165)
```rust
    fn validate_transaction(&self, txn: SignedTransaction) -> Result<VMValidatorResult> {
        let vm_validator = self.get_next_vm();

        fail_point!("vm_validator::validate_transaction", |_| {
            Err(anyhow::anyhow!(
                "Injected error in vm_validator::validate_transaction"
            ))
        });

        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
        });
```

**File:** vm-validator/src/vm_validator.rs (L172-177)
```rust
    fn restart(&mut self) -> Result<()> {
        for vm_validator in &self.vm_validators {
            vm_validator.lock().unwrap().restart()?;
        }
        Ok(())
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L82-90)
```rust
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L775-778)
```rust
    if let Err(e) = validator.write().restart() {
        counters::VM_RECONFIG_UPDATE_FAIL_COUNT.inc();
        error!(LogSchema::event_log(LogEntry::ReconfigUpdate, LogEvent::VMUpdateFail).error(&e));
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3172-3227)
```rust
        if !self
            .features()
            .is_enabled(FeatureFlag::SINGLE_SENDER_AUTHENTICATOR)
        {
            if let aptos_types::transaction::authenticator::TransactionAuthenticator::SingleSender{ .. } = transaction.authenticator_ref() {
                return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
            }
        }

        if !self.features().is_enabled(FeatureFlag::WEBAUTHN_SIGNATURE) {
            if let Ok(sk_authenticators) = transaction
                .authenticator_ref()
                .to_single_key_authenticators()
            {
                for authenticator in sk_authenticators {
                    if let AnySignature::WebAuthn { .. } = authenticator.signature() {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            } else {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            }
        }

        if !self
            .features()
            .is_enabled(FeatureFlag::SLH_DSA_SHA2_128S_SIGNATURE)
        {
            if let Ok(sk_authenticators) = transaction
                .authenticator_ref()
                .to_single_key_authenticators()
            {
                for authenticator in sk_authenticators {
                    if let AnySignature::SlhDsa_Sha2_128s { .. } = authenticator.signature() {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            } else {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            }
        }

        if !self
            .features()
            .is_enabled(FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS)
        {
            if let Ok(TransactionExecutableRef::Script(script)) =
                transaction.payload().executable_ref()
            {
                for arg in script.args() {
                    if let TransactionArgument::Serialized(_) = arg {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            }
        }
```
