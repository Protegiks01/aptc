# Audit Report

## Title
Memory Exhaustion and DoS via Unlimited Write Sets in Feature Version < 3

## Summary
For `feature_version < 3`, Aptos blockchain has no enforcement of write set size limits or memory quotas, allowing attackers to craft transactions that consume arbitrary amounts of validator memory, causing denial of service and consensus slowdowns.

## Finding Description

In `ChangeSetConfigs::new()`, when `feature_version < 3`, the system uses unlimited configuration for all write set limits. [1](#0-0) 

This sets all protection limits to `u64::MAX` (effectively unlimited). [2](#0-1) 

The `check_change_set()` validation function checks write operations against these limits. [3](#0-2) 

However, with unlimited configuration, these checks become no-ops, allowing:
- Unlimited number of write operations per transaction
- Unlimited bytes per individual write operation  
- Unlimited total bytes across all write operations
- Unlimited bytes per event
- Unlimited total event sizes

Additionally, memory quota enforcement is completely disabled for `feature_version < 3` in the `StandardMemoryAlgebra` implementation. [4](#0-3) 

This creates a two-layer vulnerability where both size limits AND memory tracking are disabled.

**Attack Path:**

1. Attacker submits a transaction to a network running `feature_version < 3`
2. Transaction executes and creates an extremely large write set (e.g., millions of write operations or gigabyte-sized individual writes)
3. During `UserSessionChangeSet::new()`, `check_change_set()` is called but passes due to unlimited limits [5](#0-4) 
4. The entire write set is materialized in validator memory before gas charging occurs
5. Memory tracking returns `Ok()` without enforcement, allowing unbounded memory consumption
6. Only when `charge_change_set()` is called will gas be charged, but by this point validators have already allocated massive memory [6](#0-5) 

The vulnerability is explicitly documented in the version changelog, which states that V3 introduced memory quotas and write set size limits. [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Processing gigabyte-sized write sets causes significant performance degradation
- **Consensus disruption**: Validators struggle to process blocks containing such transactions, causing timeouts and liveness issues
- **Resource exhaustion DoS**: Repeated exploitation can exhaust validator memory, forcing node restarts
- **Network instability**: Affects all validators processing the transaction, compromising network reliability

The attack breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**For networks running feature_version < 3:**
- **High likelihood**: Any unprivileged attacker can submit such transactions
- **Low complexity**: Requires only crafting a Move transaction with large write sets
- **Immediate impact**: Each transaction causes instant memory consumption on all validators

**Current practical impact:**
- Aptos mainnet runs `feature_version` 45 (latest), so is NOT vulnerable
- However, this affects:
  - Private Aptos deployments that haven't upgraded from early versions
  - Historical testnet configurations
  - Disaster recovery scenarios requiring rollback to old versions
  - Academic/research networks using older codebase versions

The vulnerability is a **known historical issue** that was fixed in version 3, as evidenced by the explicit changelog entry.

## Recommendation

This issue was correctly addressed in `feature_version >= 3` by:

1. **Enforcing ChangeSetConfigs limits**: Use bounded limits instead of `u64::MAX` [8](#0-7) 

2. **Enabling memory quota enforcement**: Memory tracking checks limits and returns `MEMORY_LIMIT_EXCEEDED` errors [9](#0-8) 

**For any network still running feature_version < 3:**
- Immediately upgrade to `feature_version >= 3` via governance proposal
- The current latest version is 45, which includes comprehensive protections

**For new deployments:**
- Ensure genesis initialization uses `LATEST_GAS_FEATURE_VERSION` to avoid legacy vulnerabilities

## Proof of Concept

```rust
// Conceptual PoC - would need full Aptos test harness to execute
#[test]
fn test_memory_exhaustion_pre_v3() {
    // Setup network with feature_version = 2
    let mut env = TestEnvironment::new_with_feature_version(2);
    
    // Create transaction with massive write set
    let mut write_ops = vec![];
    for i in 0..1_000_000 {
        // Create 1 million write operations
        write_ops.push(WriteOp::Creation {
            key: StateKey::raw(format!("key_{}", i).as_bytes()),
            value: vec![0u8; 1024], // 1KB each = 1GB total
        });
    }
    
    let txn = create_transaction_with_write_ops(write_ops);
    
    // Submit transaction
    let result = env.execute_transaction(txn);
    
    // For feature_version < 3:
    // - check_change_set() passes (all limits are u64::MAX)
    // - memory tracking returns Ok() (disabled for v < 3)
    // - Validator consumes 1GB+ memory before gas charging
    // - If gas runs out, transaction fails but memory damage is done
    
    assert!(env.validator_memory_usage() > 1_000_000_000); // 1GB+
    // Validators experience slowdown/OOM
}
```

## Notes

This is a **historical vulnerability** that was intentionally fixed in version 3 of the gas feature system. The changelog explicitly documents this fix. Modern Aptos networks running current versions are NOT vulnerable.

However, the vulnerability remains exploitable on:
- Legacy private networks
- Educational/research deployments
- Any system using older codebase versions

The question asks specifically about "known exploits in the unlimited configuration" for `feature_version < 3`, and this analysis confirms that such exploits exist and are documented in the codebase itself.

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L20-29)
```rust
    pub fn unlimited_at_gas_feature_version(gas_feature_version: u64) -> Self {
        Self::new_impl(
            gas_feature_version,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        )
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L31-39)
```rust
    pub fn new(feature_version: u64, gas_params: &AptosGasParameters) -> Self {
        if feature_version >= 5 {
            Self::from_gas_params(feature_version, gas_params)
        } else if feature_version >= 3 {
            Self::for_feature_version_3()
        } else {
            Self::unlimited_at_gas_feature_version(feature_version)
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L68-72)
```rust
    fn for_feature_version_3() -> Self {
        const MB: u64 = 1 << 20;

        Self::new_impl(3, MB, u64::MAX, MB, 10 * MB, u64::MAX)
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L86-128)
```rust
    pub fn check_change_set(&self, change_set: &impl ChangeSetInterface) -> Result<(), VMStatus> {
        let storage_write_limit_reached = |maybe_message: Option<&str>| {
            let mut err = PartialVMError::new(StatusCode::STORAGE_WRITE_LIMIT_REACHED);
            if let Some(message) = maybe_message {
                err = err.with_message(message.to_string())
            }
            Err(err.finish(Location::Undefined).into_vm_status())
        };

        if self.max_write_ops_per_transaction != 0
            && change_set.num_write_ops() as u64 > self.max_write_ops_per_transaction
        {
            return storage_write_limit_reached(Some("Too many write ops."));
        }

        let mut write_set_size = 0;
        for (key, op_size) in change_set.write_set_size_iter() {
            if let Some(len) = op_size.write_len() {
                let write_op_size = len + (key.size() as u64);
                if write_op_size > self.max_bytes_per_write_op {
                    return storage_write_limit_reached(None);
                }
                write_set_size += write_op_size;
            }
            if write_set_size > self.max_bytes_all_write_ops_per_transaction {
                return storage_write_limit_reached(None);
            }
        }

        let mut total_event_size = 0;
        for event in change_set.events_iter() {
            let size = event.event_data().len() as u64;
            if size > self.max_bytes_per_event {
                return storage_write_limit_reached(None);
            }
            total_event_size += size;
            if total_event_size > self.max_bytes_all_events_per_transaction {
                return storage_write_limit_reached(None);
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L47-63)
```rust
    #[inline]
    fn use_heap_memory(&mut self, amount: AbstractValueSize) -> PartialVMResult<()> {
        if self.feature_version >= 3 {
            match self.remaining_memory_quota.checked_sub(amount) {
                Some(remaining_quota) => {
                    self.remaining_memory_quota = remaining_quota;
                    Ok(())
                },
                None => {
                    self.remaining_memory_quota = 0.into();
                    Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED))
                },
            }
        } else {
            Ok(())
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L24-35)
```rust
    pub(crate) fn new(
        change_set: VMChangeSet,
        module_write_set: ModuleWriteSet,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<Self, VMStatus> {
        let user_session_change_set = Self {
            change_set,
            module_write_set,
        };
        change_set_configs.check_change_set(&user_session_change_set)?;
        Ok(user_session_change_set)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1142-1166)
```rust
    fn charge_change_set_and_respawn_session<'r>(
        &self,
        mut user_session_change_set: UserSessionChangeSet,
        resolver: &'r impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
    ) -> Result<EpilogueSession<'r>, VMStatus> {
        let storage_refund = self.charge_change_set(
            &mut user_session_change_set,
            gas_meter,
            txn_data,
            resolver,
            module_storage,
        )?;

        // TODO[agg_v1](fix): Charge for aggregator writes
        Ok(EpilogueSession::on_user_session_success(
            self,
            txn_data,
            resolver,
            user_session_change_set,
            storage_refund,
        ))
    }
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L64-70)
```rust
/// - V3
///   - Add memory quota
///   - Storage charges:
///     - Distinguish between new and existing resources
///     - One item write comes with 1K free bytes
///     - abort with STORAGE_WRITE_LIMIT_REACHED if WriteOps or Events are too large
/// - V2
```
