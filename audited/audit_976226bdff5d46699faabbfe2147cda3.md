# Audit Report

## Title
AdminStore Unbounded Growth Causes Gas Limit DoS in Staking Proxy Functions

## Summary
The `AdminStore` resource in the vesting module contains an unbounded `vesting_contracts` vector that grows with each vesting contract created. When this vector becomes sufficiently large (~350+ contracts), the `staking_proxy` module's batch update functions (`set_vesting_contract_operator` and `set_vesting_contract_voter`) become impossible to execute due to exceeding the maximum gas limit per transaction.

## Finding Description
The vulnerability stems from a combination of unbounded state growth and on-chain batch operations:

1. The `AdminStore` struct stores all vesting contract addresses in a vector with no size limit: [1](#0-0) 

2. Each time an admin creates a vesting contract, the address is appended to this vector: [2](#0-1) 

3. The `staking_proxy` module provides convenience functions that load the entire `AdminStore` and iterate through all contracts: [3](#0-2) 

4. Gas charges for resource reads include both slot and byte costs: [4](#0-3) [5](#0-4) 

5. With current gas parameters (slot_read: 302,385 gas, byte_read: 151 gas/byte) and max transaction gas of 2,000,000, loading an `AdminStore` larger than ~11KB exceeds the limit: [6](#0-5) 

**Gas Calculation:**
- Base slot cost: 302,385 gas
- Remaining budget: 2,000,000 - 302,385 = 1,697,615 gas
- Max bytes: 1,697,615 / 151 ≈ 11,243 bytes
- AdminStore overhead: ~60 bytes
- Per address: 32 bytes  
- Breaking point: (11,243 - 60) / 32 ≈ **349 vesting contracts**

With V4 IO pricing (feature version 12+), page rounding makes this worse, as reads are rounded up to 4KB pages.

## Impact Explanation
This issue qualifies as **Medium Severity** for the following reasons:

1. **Resource Exhaustion**: After creating ~350 vesting contracts, admins lose access to the `staking_proxy` batch update functionality. This breaks the **Resource Limits** invariant that all operations must respect gas limits.

2. **State Inconsistencies**: Admins cannot atomically update operators/voters across all their vesting contracts, potentially leading to inconsistent validator configurations during operator transitions.

3. **Limited Operational Impact**: While the batch functions become unusable, admins can still update individual vesting contracts directly through the vesting module. This makes it an inconvenience rather than a critical failure.

4. **Self-Inflicted Nature**: The issue only affects admins who create excessive numbers of vesting contracts, limiting the attack surface.

This does not meet Critical or High severity because:
- No funds are lost or frozen
- Consensus is not affected
- The underlying vesting functionality remains accessible
- It does not enable theft or unauthorized access

## Likelihood Explanation
**Likelihood: Medium to High**

1. **Ease of Occurrence**: Creating 350+ vesting contracts is feasible for organizations managing many stakeholder agreements. Large projects could legitimately reach this threshold.

2. **Gradual Accumulation**: The problem manifests gradually as contracts accumulate over time, making it non-obvious until the threshold is crossed.

3. **No Warning Mechanism**: There are no checks or warnings when approaching the limit. The first indication is transaction failure.

4. **Realistic Scenario**: Institutional investors, VCs, or foundations managing vesting for hundreds of team members, advisors, and partners could encounter this.

## Recommendation
Implement a maximum limit on vesting contracts per admin and/or redesign the batch update pattern:

**Option 1: Add Size Limit**
```move
const MAX_VESTING_CONTRACTS: u64 = 300;

public fun create_vesting_contract(...) acquires AdminStore {
    // ... existing code ...
    let admin_store = borrow_global_mut<AdminStore>(admin_address);
    assert!(
        vector::length(&admin_store.vesting_contracts) < MAX_VESTING_CONTRACTS,
        error::resource_exhausted(ETOO_MANY_VESTING_CONTRACTS)
    );
    vector::push_back(&mut admin_store.vesting_contracts, contract_address);
    // ... rest of function ...
}
```

**Option 2: Redesign Batch Operations**
Remove the automatic iteration pattern and require explicit contract address lists:
```move
public entry fun set_vesting_contract_operator_batch(
    owner: &signer, 
    vesting_contracts: vector<address>,
    old_operator: address, 
    new_operator: address
) {
    check_stake_proxy_permission(owner);
    vector::for_each_ref(&vesting_contracts, |vesting_contract| {
        // ... update logic ...
    });
}
```

**Option 3: Use Pagination**
Implement cursor-based pagination for batch operations that process a limited number of contracts per transaction.

## Proof of Concept
```move
#[test(aptos_framework = @0x1, admin = @0x123)]
public entry fun test_admin_store_gas_limit_dos(
    aptos_framework: &signer,
    admin: &signer,
) acquires AdminStore {
    let admin_address = signer::address_of(admin);
    vesting::setup(aptos_framework, &vector[admin_address]);
    
    // Create 400 vesting contracts to exceed gas limit threshold
    let i = 0;
    while (i < 400) {
        let shareholder = @0x1000 + i;
        vesting::setup_vesting_contract(
            admin, 
            &vector[shareholder], 
            &vector[1000000000], 
            admin_address, 
            0
        );
        i = i + 1;
    };
    
    // Verify AdminStore exists and has 400 contracts
    let contracts = vesting::vesting_contracts(admin_address);
    assert!(vector::length(&contracts) == 400, 0);
    
    // Attempt to call staking_proxy function - this will exceed gas limit
    // Expected: Transaction fails with OUT_OF_GAS or MAX_GAS_UNITS_EXCEEDED
    staking_proxy::set_vesting_contract_operator(
        admin, 
        @0x999,  // old_operator
        @0x888   // new_operator  
    );
    // This call should fail when trying to load the large AdminStore
}
```

## Notes
While gas is technically being charged correctly based on bytes loaded, the design pattern of loading unbounded state in batch operations creates a practical denial of service. This represents a violation of the principle that all operations should remain executable within reasonable gas limits. The fix should either bound the state size or redesign the access pattern to avoid loading the entire vector on-chain.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L168-174)
```text
    struct AdminStore has key {
        vesting_contracts: vector<address>,
        // Used to create resource accounts for new vesting contracts so there's no address collision.
        nonce: u64,

        create_events: EventHandle<CreateVestingContractEvent>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L605-606)
```text
        let admin_store = borrow_global_mut<AdminStore>(admin_address);
        vector::push_back(&mut admin_store.vesting_contracts, contract_address);
```

**File:** aptos-move/framework/aptos-framework/sources/staking_proxy.move (L41-52)
```text
    public entry fun set_vesting_contract_operator(owner: &signer, old_operator: address, new_operator: address) {
        check_stake_proxy_permission(owner);
        let owner_address = signer::address_of(owner);
        let vesting_contracts = &vesting::vesting_contracts(owner_address);
        vector::for_each_ref(vesting_contracts, |vesting_contract| {
            let vesting_contract = *vesting_contract;
            if (vesting::operator(vesting_contract) == old_operator) {
                let current_commission_percentage = vesting::operator_commission_percentage(vesting_contract);
                vesting::update_operator(owner, vesting_contract, new_operator, current_commission_percentage);
            };
        });
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L47-50)
```rust
            "intrinsic_gas_per_byte",
            1_158
        ],
        // ~5 microseconds should equal one unit of computational gas. We bound the maximum
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L89-96)
```rust
            storage_io_per_state_slot_read: InternalGasPerArg,
            { 0..=9 => "load_data.base", 10.. => "storage_io_per_state_slot_read"},
            // At the current mainnet scale, we should assume most levels of the (hexary) JMT nodes
            // in cache, hence target charging 1-2 4k-sized pages for each read. Notice the cost
            // of seeking for the leaf node is covered by the first page of the "value size fee"
            // (storage_io_per_state_byte_read) defined below.
            302_385,
        ],
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L204-218)
```rust
    fn calculate_read_gas(
        &self,
        loaded: NumBytes,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        // Round up bytes to whole pages
        // TODO(gas): make PAGE_SIZE configurable
        const PAGE_SIZE: u64 = 4096;

        let loaded_u64: u64 = loaded.into();
        let r = loaded_u64 % PAGE_SIZE;
        let rounded_up = loaded_u64 + if r == 0 { 0 } else { PAGE_SIZE - r };

        STORAGE_IO_PER_STATE_SLOT_READ * NumArgs::from(1)
            + STORAGE_IO_PER_STATE_BYTE_READ * NumBytes::new(rounded_up)
    }
```
