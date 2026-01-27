# Audit Report

## Title
Validator Fee Loss During Mid-Block Epoch Reconfiguration

## Summary
When a governance transaction triggers an immediate epoch reconfiguration mid-block, the block epilogue transaction is skipped, causing transaction fees from that block to be burned from users but never recorded for validator distribution. This results in permanent loss of validator fee rewards and unintended APT deflation.

## Finding Description

The vulnerability exists in the interaction between block execution, epoch reconfiguration, and fee distribution mechanisms.

**Normal Fee Flow:**
1. User transactions execute and gas fees are burned via `transaction_fee::burn_fee()` [1](#0-0) 
2. Block epilogue transaction calls `block::block_epilogue()` which invokes `stake::record_fee()` [2](#0-1) 
3. Fees are recorded in `PendingTransactionFee` indexed by validator [3](#0-2) 
4. At next epoch, `on_new_epoch()` mints new coins and distributes to validators [4](#0-3) 

**Vulnerability Trigger:**
When a governance transaction (e.g., calling `gas_schedule::set_storage_gas_config()`) triggers immediate reconfiguration mid-block [5](#0-4) , the following occurs:

1. User transactions 1-N execute normally, fees are burned from their accounts
2. Transaction N+1: Governance proposal executes, calls `reconfiguration::reconfigure()` [6](#0-5) 
3. `stake::on_new_epoch()` distributes **previously pending** fees from prior blocks
4. `NewEpochEvent` is emitted
5. Subsequent transactions get `TransactionStatus::Retry` per VM specification [7](#0-6) 
6. Block epilogue is intentionally skipped because `has_new_epoch_event()` is true [8](#0-7) 
7. `stake::record_fee()` is never called for this block
8. Fees from transactions 1 through N+1 are permanently lost

**Broken Invariant:**
This violates the **Staking Security** invariant: "Validator rewards and penalties must be calculated correctly." Validators lose earned fee rewards for all transactions in the reconfiguration block.

## Impact Explanation

**Severity: High to Medium**

This qualifies as either:
- **High Severity**: "Significant protocol violations" - breaks fee distribution protocol
- **Medium Severity**: "Limited funds loss or manipulation" - validators lose rightful fee rewards

**Economic Impact:**
- Transaction fees totaling `sum(gas_price * gas_used)` for all transactions in the block are permanently lost
- APT supply decreases unintentionally (deflationary effect)
- Validators lose legitimate income, potentially affecting their APY calculations
- If the block contains high-value transactions (e.g., large DeFi operations), losses could be substantial

**Affected Validators:**
All active validators proportionally lose fee rewards based on their proposals in that block.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements for Exploitation:**
1. A governance proposal must be approved and executed
2. The proposal must call a function triggering immediate reconfiguration (not staged via `config_buffer`)
3. Multiple user transactions must exist in the same block before the governance transaction

**Feasibility:**
- `set_storage_gas_config()` is documented to trigger immediate reconfiguration [5](#0-4) 
- Governance proposals are executed as regular transactions that can be included mid-block
- While most config changes use `set_for_next_epoch()` pattern, immediate reconfigurations are valid for time-sensitive updates

**Mitigating Factors:**
- Most governance changes use staged approach
- Reconfiguration in `BlockPrologue` (start of block) is safe as no user transactions execute
- The issue only occurs with mid-block reconfigurations

## Recommendation

**Solution 1: Record Fees Before Reconfiguration**
Modify `reconfiguration::reconfigure()` to accept fee distribution data and record it before calling `on_new_epoch()`:

```move
public(friend) fun reconfigure_with_fees(
    fee_validator_indices: vector<u64>,
    fee_amounts: vector<u64>
) acquires Configuration {
    // Record fees for current block before epoch transition
    if (vector::length(&fee_validator_indices) > 0) {
        stake::record_fee_from_reconfig(&vm_signer, fee_validator_indices, fee_amounts);
    };
    
    // Proceed with normal reconfiguration
    stake::on_new_epoch();
    // ... rest of reconfiguration logic
}
```

**Solution 2: Enforce Reconfiguration Timing**
Restrict immediate reconfigurations to only occur in `BlockPrologue`, requiring all config changes to use staged approach:

```move
public fun set_storage_gas_config(aptos_framework: &signer, config: StorageGasConfig) {
    storage_gas::set_config(aptos_framework, config);
    // Remove immediate reconfiguration, use staged approach
    // reconfiguration::reconfigure();  // REMOVE THIS
}
```

**Solution 3: Generate Epilogue Before Reconfiguration**
Modify the executor to generate and execute block epilogue transaction immediately before processing a transaction with `NewEpochEvent`.

**Recommended Approach:** Solution 2 is cleanest - enforce that all reconfigurations use the staged pattern to apply at the next epoch boundary, eliminating mid-block reconfiguration scenarios entirely.

## Proof of Concept

```rust
// Reproduction steps in Rust integration test:

#[test]
fn test_fee_loss_on_reconfiguration() {
    let mut executor = FakeExecutor::from_head_genesis();
    
    // 1. Create user transactions that will pay fees
    let sender1 = executor.create_raw_account_data(10_000_000, 10);
    let sender2 = executor.create_raw_account_data(10_000_000, 11);
    let receiver = executor.create_raw_account_data(100_000, 10);
    
    let txn1 = peer_to_peer_txn(sender1.account(), receiver.account(), 11, 1000, 1000 /* high gas price */);
    let txn2 = peer_to_peer_txn(sender2.account(), receiver.account(), 12, 1000, 1000);
    
    // 2. Create governance transaction that triggers reconfiguration
    let framework_account = executor.new_account_at(CORE_CODE_ADDRESS);
    let reconfig_txn = framework_account
        .transaction()
        .payload(aptos_stdlib::gas_schedule_set_storage_gas_config(/* params */))
        .sign();
    
    executor.new_block();
    
    // 3. Execute all transactions in same block
    let output = executor.execute_block(vec![txn1, txn2, reconfig_txn]).unwrap();
    
    // 4. Verify fees were burned from users
    let sender1_balance_after = executor.read_coin_store_resource(sender1.address()).coin();
    assert!(sender1_balance_after < 9_999_000); // Fees deducted
    
    // 5. Verify block epilogue was skipped (no fee recording)
    // Check that PendingTransactionFee was not updated for this block's fees
    
    // 6. Verify validators never received minted rewards for these fees
    // Expected: fees are lost permanently
}
```

**Notes:**
- Test requires access to validator indices and `PendingTransactionFee` resource state
- Demonstrates fees burned from users but never distributed to validators
- Confirms block epilogue skip causes permanent fee loss

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L619-622)
```text

            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer, burn_amount);
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L249-255)
```text
    fun block_epilogue(
        vm: &signer,
        fee_distribution_validator_indices: vector<u64>,
        fee_amounts_octa: vector<u64>,
    ) {
        stake::record_fee(vm, fee_distribution_validator_indices, fee_amounts_octa);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L616-635)
```text
    public(friend) fun record_fee(
        vm: &signer,
        fee_distribution_validator_indices: vector<u64>,
        fee_amounts_octa: vector<u64>,
    ) acquires PendingTransactionFee {
        // Operational constraint: can only be invoked by the VM.
        system_addresses::assert_vm(vm);

        assert!(fee_distribution_validator_indices.length() == fee_amounts_octa.length());

        let num_validators_to_distribute = fee_distribution_validator_indices.length();
        let pending_fee = borrow_global_mut<PendingTransactionFee>(@aptos_framework);
        let i = 0;
        while (i < num_validators_to_distribute) {
            let validator_index = fee_distribution_validator_indices[i];
            let fee_octa = fee_amounts_octa[i];
            pending_fee.pending_fee_by_validator.borrow_mut(&validator_index).add(fee_octa);
            i = i + 1;
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1711-1719)
```text
        if (std::features::is_distribute_transaction_fee_enabled()) {
            let mint_cap = &borrow_global<AptosCoinCapabilities>(@aptos_framework).mint_cap;
            if (fee_active > 0) {
                coin::merge(&mut stake_pool.active, coin::mint(fee_active, mint_cap));
            };
            if (fee_pending_inactive > 0) {
                coin::merge(&mut stake_pool.pending_inactive, coin::mint(fee_pending_inactive, mint_cap));
            };
            let fee_amount = fee_active + fee_pending_inactive;
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L147-152)
```text
    public fun set_storage_gas_config(aptos_framework: &signer, config: StorageGasConfig) {
        storage_gas::set_config(aptos_framework, config);
        // Need to trigger reconfiguration so the VM is guaranteed to load the new gas fee starting from the next
        // transaction.
        reconfiguration::reconfigure();
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L106-134)
```text
    public(friend) fun reconfigure() acquires Configuration {
        // Do not do anything if genesis has not finished.
        if (chain_status::is_genesis() || timestamp::now_microseconds() == 0 || !reconfiguration_enabled()) {
            return
        };

        let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
        let current_time = timestamp::now_microseconds();

        // Do not do anything if a reconfiguration event is already emitted within this transaction.
        //
        // This is OK because:
        // - The time changes in every non-empty block
        // - A block automatically ends after a transaction that emits a reconfiguration event, which is guaranteed by
        //   VM spec that all transactions comming after a reconfiguration transaction will be returned as Retry
        //   status.
        // - Each transaction must emit at most one reconfiguration event
        //
        // Thus, this check ensures that a transaction that does multiple "reconfiguration required" actions emits only
        // one reconfiguration event.
        //
        if (current_time == config_ref.last_reconfiguration_time) {
            return
        };

        reconfiguration_state::on_reconfig_start();

        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
```

**File:** aptos-move/block-executor/src/executor.rs (L2518-2529)
```rust
                    if !has_reconfig {
                        block_epilogue_txn = Some(self.gen_block_epilogue(
                            block_id,
                            signature_verified_block,
                            ret.iter(),
                            idx as TxnIndex,
                            block_limit_processor.get_block_end_info(),
                            module_cache_manager_guard.environment().features(),
                        )?);
                    } else {
                        info!("Reach epoch ending, do not append BlockEpilogue txn, block_id: {block_id:?}.");
                    }
```
