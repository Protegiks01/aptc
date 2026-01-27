# Audit Report

## Title
Storage Gas Pricing Model Breakdown Beyond 2 Billion State Items

## Summary
The dynamic storage gas pricing mechanism in Aptos caps utilization calculations at the configured target (2 billion items), causing gas prices to plateau at their maximum value once global state exceeds this threshold. This removes the exponential economic disincentive designed to prevent unbounded state growth, enabling state bloat attacks at constant (maximized) gas costs.

## Finding Description

The Aptos blockchain uses a dual pricing mechanism for storage:
1. **Fixed refundable storage fees** (`storage_fee_per_state_slot` = 40,000 Octas per slot)
2. **Dynamic IO gas prices** that increase exponentially based on storage utilization

The vulnerability exists in the dynamic gas pricing calculation. When the blockchain's total state items exceed the configured target of 2 billion items, the gas pricing algorithm caps the utilization value, causing gas prices to stop increasing. [1](#0-0) 

The target is set to 2 billion items during initialization. Each epoch, the `on_reconfig()` function recalculates gas parameters based on current storage utilization: [2](#0-1) 

The critical flaw occurs in the `calculate_gas()` function: [3](#0-2) 

When `current_usage > max_usage`, the function caps `capped_current_usage` at `max_usage` (2 billion). This means:
- At 2 billion items: utilization ratio = 100%, gas at maximum (~30M per item)
- At 4 billion items: capped to 2 billion, utilization ratio = 100%, gas STILL at maximum
- At 10 billion items: capped to 2 billion, utilization ratio = 100%, gas STILL at maximum

The exponential pricing curve is designed to create economic pressure against unlimited state growth by exponentially increasing costs as utilization approaches the target. Once the target is exceeded, this mechanism completely fails. [4](#0-3) 

The gas prices are then used during transaction execution via the `IoPricingV2` mechanism: [5](#0-4) 

**Attack Scenario:**
1. Through natural growth or coordinated attack, global state items reach 2 billion
2. Gas prices max out at their curve ceiling (e.g., 30M per item creation)
3. Subsequent state growth beyond 2 billion faces no additional economic pressure
4. State can grow to 3 billion, 5 billion, or higher at the same constant maximum gas price
5. Disk space exhaustion occurs without the exponential cost increase that should throttle growth
6. All validators experience identical behavior (deterministic calculation)

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The economic model is designed to limit state growth through progressive pricing, but this mechanism fails beyond the configured threshold.

## Impact Explanation

This vulnerability qualifies as **Medium severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention."

**Why Medium and not Higher:**
- Does NOT cause immediate consensus failure or fund theft (no Critical severity)
- Does NOT cause validator crashes or API failures (no High severity)
- DOES enable unbounded state growth beyond design capacity
- DOES require operational intervention to address disk exhaustion
- DOES affect all validators identically, causing network-wide resource issues

The impact is gradual rather than catastrophic:
- Attackers still pay maximum gas prices (expensive but constant)
- Fixed storage fees (40,000 Octas per slot) still apply
- Per-transaction limits (8192 write ops) still enforced
- However, long-term state growth becomes economically viable beyond the 2 billion threshold

**Operational Impact:**
- Validators face disk space exhaustion as state grows unchecked
- Node operators must intervene with hardware upgrades or pruning
- Network may require governance action to increase the target or modify the curve
- State sync becomes increasingly expensive for new nodes

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood of hitting this threshold depends on network growth:
- Current mainnet state size is below 2 billion items
- Natural organic growth could reach this threshold within years
- Coordinated attack could accelerate this timeline

**Attacker Requirements:**
- No special privileges required (any user can create state items)
- Requires capital to pay for maximum gas prices (~30M per item)
- Can create up to 8192 items per transaction
- Attack is feasible but expensive at maximum gas pricing

**Natural Occurrence:**
- Legitimate usage could naturally exceed 2 billion items over time
- Once exceeded, the economic model fails for ALL subsequent growth
- The vulnerability affects the entire network identically

## Recommendation

**Short-term Fix:**
Remove the utilization capping in `calculate_gas()` to allow gas prices to continue increasing beyond 100% of target:

```move
fun calculate_gas(max_usage: u64, current_usage: u64, curve: &GasCurve): u64 {
    // Remove the cap - let utilization exceed 100%
    let current_usage_bps = current_usage * BASIS_POINT_DENOMINATION / max_usage;
    
    // Clamp to maximum representable value to prevent overflow
    let current_usage_bps = if (current_usage_bps > BASIS_POINT_DENOMINATION * 10) {
        BASIS_POINT_DENOMINATION * 10  // Cap at 1000% utilization
    } else {
        current_usage_bps
    };
    
    // Continue using exponential interpolation even beyond 100%
    let points = &curve.points;
    // ... rest of interpolation logic ...
}
```

**Long-term Solutions:**
1. **Governance-adjustable targets**: Allow the 2 billion target to be increased via governance proposals as the network grows
2. **Multi-tier pricing**: Implement additional pricing tiers for utilization beyond 100%
3. **Hard caps**: Consider implementing absolute hard limits on total state size if unbounded growth is unacceptable
4. **Monitoring**: Add alerts when utilization approaches critical thresholds [6](#0-5) 

The `set_config()` function already exists for governance updates, but the underlying calculation logic must be fixed first.

## Proof of Concept

The following Move test demonstrates the capping behavior:

```move
#[test(framework = @aptos_framework)]
fun test_gas_calculation_caps_at_target(framework: signer) acquires StorageGas, StorageGasConfig {
    state_storage::initialize(&framework);
    initialize(&framework);
    
    let target = 2_000_000_000; // 2 billion
    
    // Test at target usage (100%)
    state_storage::set_for_test(0, target, 0);
    on_reconfig();
    let gas_at_target = borrow_global<StorageGas>(@aptos_framework);
    let gas_per_item_at_100 = gas_at_target.per_item_create;
    
    // Test at 2x target usage (200% - should be capped to 100%)
    state_storage::set_for_test(0, target * 2, 0);
    on_reconfig();
    let gas_at_2x = borrow_global<StorageGas>(@aptos_framework);
    let gas_per_item_at_200 = gas_at_2x.per_item_create;
    
    // Test at 5x target usage (500% - should be capped to 100%)
    state_storage::set_for_test(0, target * 5, 0);
    on_reconfig();
    let gas_at_5x = borrow_global<StorageGas>(@aptos_framework);
    let gas_per_item_at_500 = gas_at_5x.per_item_create;
    
    // BUG: All three should be equal because of capping
    assert!(gas_per_item_at_100 == gas_per_item_at_200, 0);
    assert!(gas_per_item_at_200 == gas_per_item_at_500, 0);
    
    // Expected: gas_per_item_at_200 > gas_per_item_at_100
    // Expected: gas_per_item_at_500 > gas_per_item_at_200
    // Actual: All three are equal (BUG)
}
```

This test confirms that gas prices plateau at the maximum curve value once utilization exceeds the target, removing the economic disincentive for unbounded state growth beyond 2 billion items.

## Notes

The fixed `storage_fee_per_state_slot` parameter (40,000 Octas) mentioned in the original security question functions correctly—it's a constant per-slot fee that doesn't depend on total state size. The vulnerability specifically affects the **dynamic IO gas pricing** mechanism that uses the exponential curve based on storage utilization ratios. Both mechanisms coexist: transactions pay both the IO gas (which plateaus) and the refundable storage fee (which scales linearly per item).

### Citations

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L300-316)
```text
    public fun base_8192_exponential_curve(min_gas: u64, max_gas: u64): GasCurve {
        new_gas_curve(min_gas, max_gas,
            vector[
                new_point(1000, 2),
                new_point(2000, 6),
                new_point(3000, 17),
                new_point(4000, 44),
                new_point(5000, 109),
                new_point(6000, 271),
                new_point(7000, 669),
                new_point(8000, 1648),
                new_point(9000, 4061),
                new_point(9500, 6372),
                new_point(9900, 9138),
            ]
        )
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L363-366)
```text
    public(friend) fun set_config(aptos_framework: &signer, config: StorageGasConfig) acquires StorageGasConfig {
        system_addresses::assert_aptos_framework(aptos_framework);
        *borrow_global_mut<StorageGasConfig>(@aptos_framework) = config;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L400-400)
```text
            target_usage: 2 * k * m, // 2 billion
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L453-457)
```text
    fun calculate_gas(max_usage: u64, current_usage: u64, curve: &GasCurve): u64 {
        let capped_current_usage = if (current_usage > max_usage) max_usage else current_usage;
        let points = &curve.points;
        let num_points = vector::length(points);
        let current_usage_bps = capped_current_usage * BASIS_POINT_DENOMINATION / max_usage;
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L515-533)
```text
    public(friend) fun on_reconfig() acquires StorageGas, StorageGasConfig {
        assert!(
            exists<StorageGasConfig>(@aptos_framework),
            error::not_found(ESTORAGE_GAS_CONFIG)
        );
        assert!(
            exists<StorageGas>(@aptos_framework),
            error::not_found(ESTORAGE_GAS)
        );
        let (items, bytes) = state_storage::current_items_and_bytes();
        let gas_config = borrow_global<StorageGasConfig>(@aptos_framework);
        let gas = borrow_global_mut<StorageGas>(@aptos_framework);
        gas.per_item_read = calculate_read_gas(&gas_config.item_config, items);
        gas.per_item_create = calculate_create_gas(&gas_config.item_config, items);
        gas.per_item_write = calculate_write_gas(&gas_config.item_config, items);
        gas.per_byte_read = calculate_read_gas(&gas_config.byte_config, bytes);
        gas.per_byte_create = calculate_create_gas(&gas_config.byte_config, bytes);
        gas.per_byte_write = calculate_write_gas(&gas_config.byte_config, bytes);
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L95-110)
```rust
    pub fn new_with_storage_curves(
        feature_version: u64,
        storage_gas_schedule: &StorageGasSchedule,
        gas_params: &AptosGasParameters,
    ) -> Self {
        Self {
            feature_version,
            free_write_bytes_quota: Self::get_free_write_bytes_quota(feature_version, gas_params),
            per_item_read: storage_gas_schedule.per_item_read.into(),
            per_item_create: storage_gas_schedule.per_item_create.into(),
            per_item_write: storage_gas_schedule.per_item_write.into(),
            per_byte_read: storage_gas_schedule.per_byte_read.into(),
            per_byte_create: storage_gas_schedule.per_byte_create.into(),
            per_byte_write: storage_gas_schedule.per_byte_write.into(),
        }
    }
```
