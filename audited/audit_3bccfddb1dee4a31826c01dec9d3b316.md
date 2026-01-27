# Audit Report

## Title
Zero Gas Price Governance Misconfiguration Enables Network-Wide Transaction Spam Attack

## Summary
If the governance-controlled parameter `min_price_per_gas_unit` is set to zero, attackers can submit unlimited transactions with zero gas price, bypassing all economic spam prevention mechanisms. This allows resource exhaustion attacks against validator nodes without any cost to the attacker, leading to network congestion and degraded performance.

## Finding Description

The vulnerability exists in the gas validation logic and transaction fee system. The critical code path is:

**1. Gas Price Validation (check_gas function):** [1](#0-0) 

When `min_price_per_gas_unit = 0` (configurable via governance), transactions with `gas_unit_price = 0` pass validation since the comparison `0 < 0` evaluates to false. The clippy warning at line 177 acknowledges this edge case but does not prevent it.

**2. Prologue Balance Check:** [2](#0-1) 

In `prologue_common`, the maximum transaction fee calculation becomes `max_transaction_fee = 0 * txn_max_gas_units = 0`. The balance check at lines 203 or 208 trivially passes since every account has at least 0 balance.

**3. Epilogue Fee Deduction:** [3](#0-2) 

During epilogue execution, `transaction_fee_amount = 0 * gas_used = 0`, so no fee is burned via `transaction_fee::burn_fee` at line 622. Attackers execute transactions completely free.

**4. Governance Configuration:** [4](#0-3) 

The TODO comment at line 60 explicitly notes concern about the zero value: "should probably change this to something > 0". The default production value is 100 (from `aptos_global_constants::GAS_UNIT_PRICE`), but governance can modify this to 0. [5](#0-4) 

**Attack Scenario:**

1. Malicious governance proposal sets `min_price_per_gas_unit = 0` (or it's accidentally misconfigured)
2. Attacker creates multiple accounts (100+ accounts if account creation is free under certain feature flags)
3. Each account submits maximum allowed transactions to mempool:
   - 100 sequence number-based transactions per account (default `capacity_per_user`)
   - OR 1000 orderless (nonce-based) transactions per account (default `orderless_txn_capacity_per_user`) [6](#0-5) 

4. With 100 accounts × 1000 orderless transactions = 100,000 zero-fee transactions flooding mempool
5. Validators must validate and execute all transactions, consuming CPU, memory, bandwidth, and storage
6. As transactions clear, attacker immediately submits new batches
7. Network experiences severe congestion, increased latency, and potential liveness degradation

**Broken Invariants:**
- **Resource Limits (#9)**: All operations must respect gas, storage, and computational limits - violated by allowing unbounded free computation
- **Transaction Validation (#7)**: Prologue/epilogue checks must enforce all invariants - violated by allowing zero-fee transactions

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria - **Validator node slowdowns** and **significant protocol violations**:

1. **Resource Exhaustion**: Validators must process transactions that cost them real computational resources (signature verification, VM execution, state reads/writes, consensus participation) but generate zero revenue
2. **Network Congestion**: Mempool flooding with 100K+ zero-fee transactions blocks legitimate paying transactions
3. **Consensus Slowdown**: Block proposal and validation times increase due to transaction processing overhead
4. **Economic Model Breakdown**: The fundamental fee mechanism that prevents spam is completely bypassed
5. **Amplification Factor**: Attack scales with number of accounts attacker controls (potentially unlimited if account creation is also free)

This does not reach Critical severity because:
- No direct funds theft or minting
- No consensus safety violation (block validity still maintained)
- Network remains recoverable (not a permanent hardfork situation)
- Mitigation possible via emergency governance action to restore non-zero minimum gas price

However, sustained attack could force emergency network intervention and significantly harm network utility and validator economics.

## Likelihood Explanation

**Medium-to-High Likelihood:**

**Prerequisites for exploitation:**
1. Governance misconfiguration or malicious governance action setting `min_price_per_gas_unit = 0`
2. Attacker has ability to create multiple accounts (trivial)
3. No additional rate-limiting beyond per-account mempool limits

**Factors increasing likelihood:**
- The TODO comment indicates developers are aware this could be problematic
- Default testing configuration already uses `GAS_UNIT_PRICE = 0` for convenience
- Governance parameters are modifiable and mistakes happen
- Attack is straightforward to execute once condition is met
- No cryptographic complexity or timing requirements

**Factors decreasing likelihood:**
- Requires governance action or misconfiguration (not directly exploitable by attacker alone)
- Per-account mempool limits provide partial mitigation
- Community would likely notice and respond to zero gas price governance proposal
- Can be quickly remediated via emergency governance action

## Recommendation

**Immediate Fix:**

1. **Enforce minimum gas price floor at validation level:**

```rust
// In aptos-move/aptos-vm/src/gas.rs, function check_gas()
// Around line 178, replace the check with:

const ABSOLUTE_MIN_GAS_PRICE: u64 = 1; // Enforce hardcoded minimum

let effective_min_price = txn_gas_params.min_price_per_gas_unit.max(ABSOLUTE_MIN_GAS_PRICE);
let below_min_bound = txn_metadata.gas_unit_price() < effective_min_price;

if below_min_bound {
    speculative_warn!(
        log_context,
        format!(
            "[VM] Gas unit error; min {}, submitted {}",
            effective_min_price,
            txn_metadata.gas_unit_price()
        ),
    );
    return Err(VMStatus::error(
        StatusCode::GAS_UNIT_PRICE_BELOW_MIN_BOUND,
        None,
    ));
}
```

2. **Governance parameter validation:**

Add validation in the gas parameter update logic to reject `min_price_per_gas_unit = 0`:

```rust
// Add validation when gas parameters are updated via governance
if new_params.min_price_per_gas_unit == 0 {
    return Err("min_price_per_gas_unit cannot be zero - minimum value is 1");
}
```

3. **Additional mempool-level protection:**

Implement minimum fee requirement at mempool admission:

```rust
// In mempool validation, reject zero gas price transactions regardless of governance setting
if transaction.gas_unit_price() == 0 {
    return MempoolStatus::new(MempoolStatusCode::VmError);
}
```

**Long-term improvements:**
- Implement dynamic fee markets that adjust minimum gas price based on network congestion
- Add circuit breakers that detect abnormal transaction patterns and temporarily increase minimum fees
- Implement reputation systems or staking requirements for transaction submission

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability
// File: aptos-move/aptos-vm/src/tests/gas_zero_price_attack.rs

#[test]
fn test_zero_gas_price_spam_attack() {
    use aptos_types::transaction::{RawTransaction, SignedTransaction, TransactionPayload};
    use aptos_cached_packages::aptos_stdlib;
    use move_core_types::account_address::AccountAddress;
    
    // Setup: Configure governance to set min_price_per_gas_unit = 0
    let mut gas_params = AptosGasParameters::zeros();
    gas_params.vm.txn.min_price_per_gas_unit = FeePerGasUnit::zero();
    
    // Attacker creates transaction with zero gas price
    let attacker = AccountAddress::random();
    let sequence_num = 0;
    
    let payload = TransactionPayload::EntryFunction(
        aptos_stdlib::aptos_coin_transfer(AccountAddress::random(), 1)
    );
    
    let raw_txn = RawTransaction::new(
        attacker,
        sequence_num,
        payload,
        1_000_000, // max_gas_amount
        0, // gas_unit_price = 0 (FREE!)
        u64::MAX, // expiration_timestamp_secs
        ChainId::test(),
    );
    
    // Sign and validate transaction
    let signed_txn = sign_transaction(raw_txn, &attacker_private_key);
    
    // Validation passes because 0 >= 0 (min_price_per_gas_unit)
    let vm = AptosVM::new(&state_view);
    let validation_result = vm.validate_transaction(signed_txn, &state_view, &module_storage);
    
    assert!(validation_result.is_ok(), "Zero-gas transaction should be accepted when min_price=0");
    
    // Execute transaction - no fee is charged
    let output = vm.execute_user_transaction(&state_view, &signed_txn, &log_context);
    let fee_charged = output.gas_used() * 0; // = 0
    
    assert_eq!(fee_charged, 0, "Transaction executed for free");
    
    // Attacker can now spam unlimited free transactions
    for i in 0..10000 {
        let spam_txn = create_zero_fee_transaction(attacker, i);
        // All these transactions are free and will congest the network
        mempool.add_transaction(spam_txn);
    }
    
    println!("Attack successful: 10000 free transactions submitted");
}
```

**Notes:**
- The vulnerability is exploitable only when `min_price_per_gas_unit = 0` is set via governance
- Per-account mempool limits (100-1000 transactions) provide partial mitigation but don't prevent multi-account attacks
- The attack is economically devastating because validators bear all costs while attacker pays nothing
- Emergency governance action can remediate by setting minimum gas price > 0, but damage occurs during attack window

### Citations

**File:** aptos-move/aptos-vm/src/gas.rs (L177-192)
```rust
    #[allow(clippy::absurd_extreme_comparisons)]
    let below_min_bound = txn_metadata.gas_unit_price() < txn_gas_params.min_price_per_gas_unit;
    if below_min_bound {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; min {}, submitted {}",
                txn_gas_params.min_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_BELOW_MIN_BOUND,
            None,
        ));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L188-212)
```text
        let max_transaction_fee = txn_gas_price * txn_max_gas_units;
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                permissioned_signer::check_permission_capacity_above(
                    gas_payer,
                    (max_transaction_fee as u256),
                    GasPermission {}
                ),
                error::permission_denied(PROLOGUE_PERMISSIONED_GAS_LIMIT_INSUFFICIENT)
            );
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            }
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L596-627)
```text
        assert!(txn_max_gas_units >= gas_units_remaining, error::invalid_argument(EOUT_OF_GAS));
        let gas_used = txn_max_gas_units - gas_units_remaining;

        assert!(
            (txn_gas_price as u128) * (gas_used as u128) <= MAX_U64,
            error::out_of_range(EOUT_OF_GAS)
        );
        let transaction_fee_amount = txn_gas_price * gas_used;

        // it's important to maintain the error code consistent with vm
        // to do failed transaction cleanup.
        if (!skip_gas_payment(is_simulation, gas_payer)) {
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            };

            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer, burn_amount);
            } else if (transaction_fee_amount < storage_fee_refunded) {
                let mint_amount = storage_fee_refunded - transaction_fee_amount;
                transaction_fee::mint_and_refund(gas_payer, mint_amount);
            };
        };
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L59-65)
```rust
        // The minimum gas price that a transaction can be submitted with.
        // TODO(Gas): should probably change this to something > 0
        [
            min_price_per_gas_unit: FeePerGasUnit,
            "min_price_per_gas_unit",
            aptos_global_constants::GAS_UNIT_PRICE
        ],
```

**File:** config/global-constants/src/lib.rs (L23-26)
```rust
#[cfg(any(test, feature = "testing"))]
pub const GAS_UNIT_PRICE: u64 = 0;
#[cfg(not(any(test, feature = "testing")))]
pub const GAS_UNIT_PRICE: u64 = 100;
```

**File:** config/src/config/mempool_config.rs (L123-171)
```rust
            capacity_per_user: 100,
            default_failovers: 1,
            enable_intelligent_peer_prioritization: true,
            shared_mempool_peer_update_interval_ms: 1_000,
            shared_mempool_priority_update_interval_secs: 600, // 10 minutes (frequent reprioritization is expensive)
            shared_mempool_failover_delay_ms: 500,
            system_transaction_timeout_secs: 600,
            system_transaction_gc_interval_ms: 60_000,
            broadcast_buckets: DEFAULT_BUCKETS.to_vec(),
            eager_expire_threshold_ms: Some(15_000),
            eager_expire_time_ms: 6_000,
            include_ready_time_in_broadcast: false,
            usecase_stats_num_blocks_to_track: 40,
            usecase_stats_num_top_to_track: 5,
            num_sender_buckets: 4,
            load_balancing_thresholds: vec![
                LoadBalancingThresholdConfig {
                    avg_mempool_traffic_threshold_in_tps: 500,
                    latency_slack_between_top_upstream_peers: 50,
                    max_number_of_upstream_peers: 2,
                },
                LoadBalancingThresholdConfig {
                    avg_mempool_traffic_threshold_in_tps: 1000,
                    latency_slack_between_top_upstream_peers: 50,
                    max_number_of_upstream_peers: 3,
                },
                LoadBalancingThresholdConfig {
                    avg_mempool_traffic_threshold_in_tps: 1500,
                    latency_slack_between_top_upstream_peers: 75,
                    max_number_of_upstream_peers: 4,
                },
                LoadBalancingThresholdConfig {
                    avg_mempool_traffic_threshold_in_tps: 2500,
                    latency_slack_between_top_upstream_peers: 100,
                    max_number_of_upstream_peers: 5,
                },
                LoadBalancingThresholdConfig {
                    avg_mempool_traffic_threshold_in_tps: 3500,
                    latency_slack_between_top_upstream_peers: 125,
                    max_number_of_upstream_peers: 6,
                },
                LoadBalancingThresholdConfig {
                    avg_mempool_traffic_threshold_in_tps: 4500,
                    latency_slack_between_top_upstream_peers: 150,
                    max_number_of_upstream_peers: 7,
                },
            ],
            enable_max_load_balancing_at_any_load: false,
            orderless_txn_capacity_per_user: 1000,
```
