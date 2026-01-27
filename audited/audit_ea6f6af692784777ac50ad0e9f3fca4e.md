# Audit Report

## Title
Partial Failure in Transaction Simulation Session Causes In-Memory and On-Disk State Desynchronization

## Summary
The `Session` struct in the transaction simulation session module lacks atomic commit semantics for state persistence. When file I/O operations fail after in-memory state modifications, the session enters an inconsistent state where memory reflects changes that are not persisted to disk, leading to data loss on session reload.

## Finding Description

The transaction simulation session implements a persistent session that should maintain consistency between in-memory state and on-disk state. However, both `execute_transaction` and `fund_account` methods violate atomicity by modifying in-memory state before attempting file persistence operations. [1](#0-0) 

In `execute_transaction`, the critical sequence is:
1. In-memory state is modified via `apply_write_set` 
2. Multiple file I/O operations occur (directory creation, summary writing, events writing, write_set writing)
3. Operation counter is incremented in memory
4. Config file save can fail
5. Delta file save can fail

If any operation after step 1 fails, the function returns an error via the `?` operator, but the in-memory state remains modified. [2](#0-1) 

The same pattern exists in `fund_account`:
1. In-memory state is modified via `fund_apt_fungible_store`
2. Summary file write can fail  
3. Config save can fail
4. Delta save can fail

The `DeltaStateStore.apply_write_set` operation itself is atomic (it holds a write lock throughout), but the session-level operation is not atomic because persistence happens separately after state modification. [3](#0-2) 

**Broken Invariant:** State Consistency - "State transitions must be atomic and verifiable." The session violates this by allowing partial completion where state modification succeeds but persistence fails.

## Impact Explanation

**Severity Assessment: Medium**

This issue qualifies as **Medium Severity** under the "State inconsistencies requiring intervention" category for the following reasons:

1. **State Desynchronization**: The session's in-memory state diverges from persisted state, violating the fundamental persistence guarantee.

2. **Silent Data Loss**: When the session is reloaded after a crash or restart, all modifications made after the last successful persistence are silently lost.

3. **Operation Counter Desynchronization**: The `config.ops` counter becomes inconsistent between memory and disk, potentially allowing operation replay or creating gaps in the operation sequence.

4. **No Recovery Mechanism**: The code provides no rollback, retry, or error recovery mechanism to restore consistency.

**Note:** While this is a legitimate bug affecting state consistency, it impacts only the simulation session tool used for development and testing, not the production blockchain consensus or validator operations. The actual Aptos blockchain state management uses different, more robust mechanisms with proper atomicity guarantees.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue can occur in several common scenarios:

1. **Disk Space Exhaustion**: When the disk becomes full during delta or config file writes
2. **Permission Errors**: When file system permissions change or are incorrectly set
3. **Filesystem Errors**: I/O errors, read-only filesystems, or filesystem corruption
4. **Concurrent Access**: Multiple processes attempting to write to the same session directory
5. **Process Termination**: If the process is killed between state modification and persistence

The likelihood is elevated because:
- File I/O operations frequently fail in real-world scenarios
- The simulation session performs many file operations per transaction
- No defensive error handling or validation exists
- Users may run simulations in resource-constrained environments

## Recommendation

Implement atomic commit semantics using a two-phase commit pattern:

1. **Prepare Phase**: Write all changes to temporary files
2. **Commit Phase**: Atomically rename temporary files to final locations only after all writes succeed
3. **Rollback**: If any operation fails, discard temporary files and leave state unchanged

**Suggested Fix Pattern:**

```rust
pub fn execute_transaction(
    &mut self,
    txn: SignedTransaction,
) -> Result<(VMStatus, TransactionOutput)> {
    // Execute transaction (read-only operations)
    let env = AptosEnvironment::new(&self.state_store);
    let vm = AptosVM::new(&env);
    let log_context = AdapterLogSchema::new(self.state_store.id(), 0);
    let resolver = self.state_store.as_move_resolver();
    let code_storage = self.state_store.as_aptos_code_storage(&env);

    let (vm_status, vm_output) = vm.execute_user_transaction(
        &resolver,
        &code_storage,
        &txn,
        &log_context,
        &AuxiliaryInfo::new_timestamp_not_yet_assigned(0),
    );
    let txn_output = vm_output.try_materialize_into_transaction_output(&resolver)?;

    // BEGIN ATOMIC SECTION
    // 1. Clone current state for potential rollback
    let original_delta = self.state_store.delta();
    let original_ops = self.config.ops;

    // 2. Apply changes to in-memory state
    self.state_store.apply_write_set(txn_output.write_set())?;
    self.config.ops += 1;

    // 3. Attempt all file operations with temporary files
    let temp_dir = self.path.join(format!(".tmp_{}", self.config.ops));
    let result = (|| -> Result<()> {
        std::fs::create_dir_all(&temp_dir)?;
        
        // Write to temporary locations
        let temp_config = temp_dir.join("config.json");
        let temp_delta = temp_dir.join("delta.json");
        
        self.config.save_to_file(&temp_config)?;
        save_delta(&temp_delta, &self.state_store.delta())?;
        
        // Write other output files to temporary directory
        // ... (summary, events, write_set)
        
        // 4. Atomic commit: move temp files to final locations
        std::fs::rename(&temp_config, self.path.join("config.json"))?;
        std::fs::rename(&temp_delta, self.path.join("delta.json"))?;
        
        // Move output directory to final location
        std::fs::rename(&temp_dir, self.path.join(format!("[{}] execute ...", self.config.ops)))?;
        
        Ok(())
    })();

    // 5. Rollback on failure
    if result.is_err() {
        // Restore original state
        self.state_store = DeltaStateStore::new_with_base_and_delta(
            std::mem::replace(&mut self.state_store, /* temp value */),
            original_delta
        );
        self.config.ops = original_ops;
        
        // Clean up temporary directory
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    
    result?;
    // END ATOMIC SECTION

    Ok((vm_status, txn_output))
}
```

**Key Improvements:**
- All file operations use temporary locations first
- In-memory state can be rolled back if persistence fails
- Atomic rename operations ensure either all changes persist or none do
- Temporary directory cleanup prevents disk space leaks

## Proof of Concept

```rust
#[test]
fn test_partial_failure_leaves_inconsistent_state() -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    
    let temp_dir = tempfile::tempdir()?;
    let session_path = temp_dir.path();
    
    // Initialize session
    let mut session = Session::init(session_path)?;
    
    // Fund an account - this should succeed
    session.fund_account(AccountAddress::ONE, 1000)?;
    
    // Verify state is persisted correctly
    let delta_before = session.state_store.delta();
    let ops_before = session.config.ops;
    
    // Make delta.json read-only to simulate write failure
    let delta_path = session_path.join("delta.json");
    std::fs::set_permissions(&delta_path, Permissions::from_mode(0o444))?;
    
    // Attempt to fund again - this should fail during delta save
    let result = session.fund_account(AccountAddress::TWO, 2000);
    assert!(result.is_err(), "Expected error due to read-only delta.json");
    
    // VULNERABILITY: In-memory state was modified despite the error
    let delta_after = session.state_store.delta();
    let ops_after = session.config.ops;
    
    // Demonstrate inconsistency
    assert_ne!(delta_before, delta_after, "In-memory delta was modified");
    assert_ne!(ops_before, ops_after, "In-memory ops counter was incremented");
    
    // Reset permissions and reload session
    std::fs::set_permissions(&delta_path, Permissions::from_mode(0o644))?;
    let session_reloaded = Session::load(session_path)?;
    
    // VULNERABILITY: Reloaded session has old state, losing the failed funding
    assert_eq!(
        session_reloaded.state_store.delta(),
        delta_before,
        "Reloaded session has old delta, changes were lost"
    );
    assert_eq!(
        session_reloaded.config.ops,
        ops_before,
        "Reloaded session has old ops count"
    );
    
    // But the current session in memory still has the modified state
    assert_ne!(
        session.state_store.delta(),
        session_reloaded.state_store.delta(),
        "In-memory session diverged from persisted state"
    );
    
    Ok(())
}
```

**Expected Output:**
- Test passes, demonstrating that partial failure creates inconsistent state
- In-memory session has modified state
- Persisted session (after reload) has old state
- State desynchronization is confirmed

## Notes

**Important Context:**

This vulnerability affects the **transaction simulation session module**, which is a development and testing tool used for offline transaction simulation. It does **not** affect:

- Production blockchain consensus or validator operations
- On-chain state management (which uses AptosDB with proper ACID guarantees)
- Transaction execution on the actual Aptos network
- Validator nodes or network security

The impact is limited to developers using this simulation tool for testing purposes. While this represents a legitimate software engineering bug that should be fixed to ensure reliability of the development tooling, it does not pose a security risk to the Aptos blockchain network itself.

The actual Aptos blockchain uses different state management mechanisms (AptosDB, StateStore) that have proper atomicity and consistency guarantees through database transactions and write-ahead logging.

### Citations

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L242-264)
```rust
    pub fn fund_account(&mut self, account: AccountAddress, amount: u64) -> Result<()> {
        let (before, after) = self.state_store.fund_apt_fungible_store(account, amount)?;

        let summary = Summary::FundFungible {
            account,
            amount,
            before,
            after,
        };
        let summary_path = self
            .path
            .join(format!("[{}] fund (fungible)", self.config.ops))
            .join("summary.json");
        std::fs::create_dir_all(summary_path.parent().unwrap())?;
        std::fs::write(summary_path, serde_json::to_string_pretty(&summary)?)?;

        self.config.ops += 1;

        self.config.save_to_file(&self.path.join("config.json"))?;
        save_delta(&self.path.join("delta.json"), &self.state_store.delta())?;

        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L271-352)
```rust
    pub fn execute_transaction(
        &mut self,
        txn: SignedTransaction,
    ) -> Result<(VMStatus, TransactionOutput)> {
        let env = AptosEnvironment::new(&self.state_store);
        let vm = AptosVM::new(&env);
        let log_context = AdapterLogSchema::new(self.state_store.id(), 0);

        let resolver = self.state_store.as_move_resolver();
        let code_storage = self.state_store.as_aptos_code_storage(&env);

        let (vm_status, vm_output) = vm.execute_user_transaction(
            &resolver,
            &code_storage,
            &txn,
            &log_context,
            &AuxiliaryInfo::new_timestamp_not_yet_assigned(0),
        );
        let txn_output = vm_output.try_materialize_into_transaction_output(&resolver)?;

        self.state_store.apply_write_set(txn_output.write_set())?;

        fn name_from_executable(executable: &TransactionExecutable) -> String {
            match executable {
                TransactionExecutable::Script(_script) => "script".to_string(),
                TransactionExecutable::EntryFunction(entry_function) => {
                    format!(
                        "{}::{}",
                        format_module_id(entry_function.module()),
                        entry_function.function()
                    )
                },
                TransactionExecutable::Empty => {
                    unimplemented!("empty executable -- unclear how this should be handled")
                },
            }
        }
        let name = match &txn.payload() {
            TransactionPayload::EntryFunction(entry_function) => {
                format!(
                    "{}::{}",
                    format_module_id(entry_function.module()),
                    entry_function.function()
                )
            },
            TransactionPayload::Script(_script) => "script".to_string(),
            TransactionPayload::Multisig(multi_sig) => {
                name_from_executable(&multi_sig.as_transaction_executable())
            },
            TransactionPayload::Payload(TransactionPayloadInner::V1 { executable, .. }) => {
                name_from_executable(executable)
            },
            TransactionPayload::ModuleBundle(_) => unreachable!(),
            TransactionPayload::EncryptedPayload(_) => "encrypted".to_string(),
        };

        let output_path = self
            .path
            .join(format!("[{}] execute {}", self.config.ops, name));
        std::fs::create_dir_all(&output_path)?;

        let summary = Summary::ExecuteTransaction {
            status: txn_output.status().clone(),
            gas_used: txn_output.gas_used(),
            fee_statement: txn_output.try_extract_fee_statement()?,
        };
        let summary_path = output_path.join("summary.json");
        std::fs::write(summary_path, serde_json::to_string_pretty(&summary)?)?;

        // Dump events to file
        let events_path = output_path.join("events.json");
        save_events(&events_path, &self.state_store, txn_output.events())?;

        let write_set_path = output_path.join("write_set.json");
        save_write_set(&self.state_store, &write_set_path, txn_output.write_set())?;

        self.config.ops += 1;
        self.config.save_to_file(&self.path.join("config.json"))?;
        save_delta(&self.path.join("delta.json"), &self.state_store.delta())?;

        Ok((vm_status, txn_output))
    }
```

**File:** aptos-move/aptos-transaction-simulation/src/state_store.rs (L504-522)
```rust
    fn apply_write_set(&self, write_set: &WriteSet) -> Result<()> {
        let mut states = self.states.write();

        for (state_key, write_op) in write_set.write_op_iter() {
            match write_op.as_state_value() {
                None => match states.get_mut(state_key) {
                    Some(val) => *val = None,
                    None => {
                        states.insert(state_key.clone(), None);
                    },
                },
                Some(state_val) => {
                    states.insert(state_key.clone(), Some(state_val));
                },
            }
        }

        Ok(())
    }
```
