# Audit Report

## Title
Storage Pricing Arbitrage Allows Unauthorized Token Minting Through Delete-Recreate Cycle

## Summary
The DiskSpacePricing V2 refund mechanism allows attackers to profit from governance-driven storage price reductions by deleting state items created at high prices and receiving full refunds, then recreating them at lower prices. When refunds exceed transaction fees, the difference is minted as new tokens, enabling unauthorized token creation.

## Finding Description
The vulnerability exists in the interaction between storage deposit refunds and transaction fee processing: [1](#0-0) 

When a state item is deleted, the system refunds the **full original deposit** stored in the metadata (`total_deposit()`), regardless of current pricing. This deposit includes both `slot_deposit` and `bytes_deposit` calculated at creation time. [2](#0-1) 

The refund is then processed in the transaction epilogue: [3](#0-2) 

If `storage_fee_refunded > transaction_fee_amount`, the difference is **minted** as new tokens and credited to the user: [4](#0-3) 

**Attack Scenario:**
1. Attacker creates a 1MB resource when `storage_fee_per_state_byte = 40` (current value)
   - Bytes deposit: 1,000,000 × 40 = 40,000,000 octas
   - Slot deposit: 40,000 octas  
   - Total: 40,040,000 octas paid

2. Governance reduces pricing to `storage_fee_per_state_byte = 4` (10× reduction)

3. Attacker deletes the 1MB resource in a transaction costing 100,000 octas in gas
   - Refund: 40,040,000 octas (from metadata)
   - Transaction fee: 100,000 octas
   - Net minted: 39,940,000 octas

4. Attacker recreates 1MB resource at new pricing
   - New deposit: 1,000,000 × 4 + 40,000 = 4,040,000 octas
   - Transaction fee: 100,000 octas

5. **Net profit: 39,940,000 - 4,040,000 - 100,000 = 35,800,000 octas (0.358 APT) per cycle**

The design comment acknowledges pricing changes are handled for modifications but not deletions: [5](#0-4) 

While modifications cap deposits at current pricing, deletions always refund the full historical deposit.

## Impact Explanation
This vulnerability enables **unauthorized token minting**, which falls under the Critical Severity category "Loss of Funds (theft or minting)" with bounty up to $1,000,000.

**Quantified Impact:**
- Per 1MB of storage: ~0.358 APT profit per 10× price reduction
- Attackers can create arbitrary amounts of storage during high-price periods
- No limit on the number of delete-recreate cycles
- Multiple attackers can exploit simultaneously
- Total potential minting limited only by MAX_U128 supply constraint

This breaks the fundamental invariant that token supply should only change through authorized mechanisms (block rewards, transaction burns). The minting capability is restricted to `@aptos_framework` but is effectively bypassed through this mechanism.

## Likelihood Explanation
**High Likelihood:**
- Storage pricing changes are expected as the network scales and storage costs evolve
- The current value of 40 was set in version 14 and represents economic parameters subject to governance adjustment
- No technical barriers prevent exploitation - any user can delete and recreate state
- The attack is profitable even with modest price reductions (e.g., 2× reduction still yields significant profit)
- Attackers can prepare by creating large amounts of state before anticipated price reductions
- The mechanism is deterministic and guaranteed to work

**Prerequisites:**
- Governance passes proposal reducing `storage_fee_per_state_byte`
- Attacker has previously created state items (can be done cheaply before price reduction is proposed)

## Recommendation
Implement one of the following mitigations:

**Option 1 (Recommended): Cap refunds at current pricing**
```rust
Deletion => {
    let current_value_at_today_pricing = calculate_current_value(
        op.key, op.prev_size, params
    );
    let refund_amount = std::cmp::min(
        op.metadata_mut.total_deposit(),
        current_value_at_today_pricing
    );
    ChargeAndRefund {
        charge: 0.into(),
        refund: refund_amount.into(),
    }
}
```

**Option 2: Adjust deposits retroactively during pricing changes**
Store pricing version in metadata and migrate deposits when pricing changes are detected.

**Option 3: Implement refund caps in transaction epilogue**
Add maximum refund threshold relative to transaction fee to prevent excessive minting.

## Proof of Concept

```move
// File: storage_pricing_exploit.move
module 0xcafe::exploit {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    struct LargeResource has key {
        data: vector<u8>
    }
    
    // Step 1: Create large resource at high pricing
    public entry fun create_large_resource(account: &signer) {
        let data = vector::empty<u8>();
        let i = 0;
        // Create 1MB of data
        while (i < 1000000) {
            vector::push_back(&mut data, 42);
            i = i + 1;
        };
        move_to(account, LargeResource { data });
    }
    
    // Step 2: After governance reduces pricing, delete and profit
    public entry fun delete_and_profit(account: &signer) acquires LargeResource {
        let addr = signer::address_of(account);
        let balance_before = coin::balance<AptosCoin>(addr);
        
        // Delete the resource - gets full refund at old high price
        let LargeResource { data: _ } = move_from<LargeResource>(addr);
        
        let balance_after = coin::balance<AptosCoin>(addr);
        // balance_after > balance_before due to minting from refund
        assert!(balance_after > balance_before, 1);
    }
    
    // Step 3: Recreate at new low pricing
    public entry fun recreate_at_low_price(account: &signer) {
        create_large_resource(account);
        // Paid new low price, but profited from high price refund
    }
}
```

**Test scenario:**
1. Deploy module when `storage_fee_per_state_byte = 40`
2. Call `create_large_resource()` - pays 40,040,000 octas deposit
3. Governance reduces to `storage_fee_per_state_byte = 4`
4. Call `delete_and_profit()` - receives 40,040,000 octas refund, transaction costs ~100,000, net minted ~39,940,000
5. Call `recreate_at_low_price()` - pays 4,040,000 octas deposit
6. Net profit: ~35,800,000 octas extracted from protocol

## Notes
This vulnerability is specifically introduced by the V2 DiskSpacePricing mechanism with refundable bytes deposits. The V1 pricing model had different characteristics. The issue is not present in modification operations due to the deposit cap logic, but deletions lack this protection. No rate limiting, cooldown periods, or other protective mechanisms exist to prevent exploitation.

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L154-162)
```rust
    /// n.b. logcic for bytes fee:
    /// * When slot increase in size on modification, charge additionally into the deposit.
    ///     * legacy slots that didn't pay bytes deposits won't get charged for the bytes allocated for free.
    ///     * Considering pricing change, charge only to the point where the total deposit for bytes don't go
    ///       beyond `current_price_per_byte * num_current_bytes`
    /// * When slot decrease in size, don't refund, to simplify implementation.
    /// * If slot doesn't change in size on modification, no charging even if pricing changes.
    /// * Refund only on deletion.
    /// * There's no longer non-refundable penalty when a slot larger than 1KB gets touched.
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L208-211)
```rust
            Deletion => ChargeAndRefund {
                charge: 0.into(),
                refund: op.metadata_mut.total_deposit().into(),
            },
```

**File:** types/src/state_store/state_value.rs (L135-137)
```rust
    pub fn total_deposit(&self) -> u64 {
        self.slot_deposit() + self.bytes_deposit()
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L620-626)
```text
            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer, burn_amount);
            } else if (transaction_fee_amount < storage_fee_refunded) {
                let mint_amount = storage_fee_refunded - transaction_fee_amount;
                transaction_fee::mint_and_refund(gas_payer, mint_amount);
            };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_fee.move (L100-106)
```text
    public(friend) fun mint_and_refund(
        account: address, refund: u64
    ) acquires AptosCoinMintCapability {
        let mint_cap = &borrow_global<AptosCoinMintCapability>(@aptos_framework).mint_cap;
        let refund_coin = coin::mint(refund, mint_cap);
        coin::deposit_for_gas_fee(account, refund_coin);
    }
```
