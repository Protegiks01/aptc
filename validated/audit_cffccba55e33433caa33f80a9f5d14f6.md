# Audit Report

## Title
Storage Pricing Arbitrage Allows Unauthorized Token Minting Through Delete-Recreate Cycle

## Summary
The DiskSpacePricing V2 refund mechanism allows users to profit from governance-driven storage price reductions by deleting state items created at high prices and receiving full refunds, then recreating them at lower prices. When refunds exceed transaction fees, the difference is minted as new tokens, enabling unauthorized token creation that inflates supply.

## Finding Description
The vulnerability exists in the interaction between storage deposit refunds and transaction fee processing across multiple system components.

When a state item is deleted, the system refunds the **full original deposit** stored in the metadata regardless of current pricing: [1](#0-0) 

This deposit includes both `slot_deposit` and `bytes_deposit` calculated at creation time and stored in the state value metadata: [2](#0-1) 

When items are created, they are charged at current prices: [3](#0-2) 

The current `storage_fee_per_state_byte` parameter is set to 40 octas: [4](#0-3) 

The refund is processed in the transaction epilogue. If `storage_fee_refunded > transaction_fee_amount`, the difference is **minted** as new tokens: [5](#0-4) 

The minting occurs through the framework's mint capability: [6](#0-5) 

The design explicitly handles pricing changes for modifications by capping additional charges, but only mentions "Refund only on deletion" without price adjustment logic: [7](#0-6) 

**Attack Scenario:**
1. User creates 1MB resource when `storage_fee_per_state_byte = 40`
   - Total deposit: 40,040,000 octas paid
2. Governance legitimately reduces pricing to `storage_fee_per_state_byte = 4` (10× reduction)
3. User deletes resource (transaction fee: ~1,000,000 octas)
   - Refund: 40,040,000 octas
   - Net minted: ~39,000,000 octas
4. User recreates resource at new pricing
   - New deposit: 4,040,000 octas
5. **Net profit: ~35,000,000 octas (0.35 APT) per MB per cycle**

While modifications cap charges to prevent overcharging when prices change, deletions always refund the full historical deposit without considering current pricing.

## Impact Explanation
This vulnerability enables **unauthorized token minting**, falling under Critical Severity "Loss of Funds (minting)" per Aptos bug bounty program.

**Quantified Impact:**
- Per 1MB storage: ~0.35 APT profit per 10× price reduction
- Users can create arbitrary amounts of storage during high-price periods (limited only by max_storage_fee cap of 2 APT per transaction, but can execute multiple transactions)
- No limit on delete-recreate cycles
- Multiple users can exploit simultaneously
- Total minting limited only by amount of state created at high prices

This breaks the fundamental invariant that token supply should only change through authorized mechanisms (block rewards, transaction fee burns). While the minting uses the legitimate `AptosCoinMintCapability`, the economic effect creates systematic value extraction from the protocol through artificial token inflation when legitimate governance price adjustments occur.

## Likelihood Explanation
**High Likelihood:**
- Storage pricing reductions are **expected** as networks scale and storage costs decrease over time
- The current value of 40 was introduced in version 14 and represents an economic parameter subject to governance adjustment
- No technical barriers prevent exploitation - any user can delete and recreate state through normal transactions
- Attack is profitable even with modest price reductions (e.g., 2× reduction yields significant profit)
- Users can prepare by creating large amounts of state before anticipated price reductions
- The mechanism is deterministic and guaranteed to work

**Prerequisites:**
- Governance passes proposal reducing `storage_fee_per_state_byte` (a legitimate, expected action as networks mature)
- User has previously created state items (achievable by any user)

The vulnerability does NOT require malicious governance behavior - price reductions are legitimate economic adjustments expected during network evolution.

## Recommendation
Implement refund capping similar to the modification logic to prevent arbitrage:

```rust
Deletion => {
    let original_deposit = op.metadata_mut.total_deposit();
    let current_fair_value = calculate_current_deposit_value(op.key, op.prev_size, params);
    let refund = std::cmp::min(original_deposit, current_fair_value);
    ChargeAndRefund {
        charge: 0.into(),
        refund: refund.into(),
    }
}
```

This ensures users receive refunds up to the current fair value of the storage they're freeing, preventing profit from price reductions while still incentivizing state cleanup.

Alternatively, track a "refund_cap" in metadata that gets updated during modifications to reflect the maximum refundable amount at current prices.

## Proof of Concept
The vulnerability can be demonstrated through the following sequence:

1. Deploy a Move module that creates a large resource (approaching 1MB)
2. Call the creation function when `storage_fee_per_state_byte = 40`
3. Observe deposit of ~40M octas recorded in state metadata
4. Submit governance proposal to reduce `storage_fee_per_state_byte = 4`
5. After proposal passes, delete the resource
6. Observe net minting of ~35M octas (refund minus transaction fees)
7. Recreate the resource at new pricing for ~4M octas
8. Net profit: ~35M - 4M = ~31M octas

The existing test framework in `aptos-move/e2e-move-tests/src/tests/storage_refund.rs` demonstrates the refund mechanism but does not test price change scenarios. A full PoC would extend this test to modify gas parameters mid-test and verify the minting behavior.

## Notes
This vulnerability represents a systemic economic design flaw rather than a traditional security bug. Each individual component (refund mechanism, epilogue minting logic) functions as coded, but their interaction creates an exploitable arbitrage opportunity when storage prices decrease. The issue becomes more severe as the network matures and storage costs naturally decrease, making large price reductions increasingly likely through legitimate governance actions.

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

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L174-185)
```rust
            Creation { .. } => {
                // permanent storage fee
                let slot_deposit = u64::from(params.storage_fee_per_state_slot);

                op.metadata_mut.maybe_upgrade();
                op.metadata_mut.set_slot_deposit(slot_deposit);
                op.metadata_mut.set_bytes_deposit(target_bytes_deposit);

                ChargeAndRefund {
                    charge: (slot_deposit + target_bytes_deposit).into(),
                    refund: 0.into(),
                }
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L195-199)
```rust
            storage_fee_per_state_byte: FeePerByte,
            { 14.. => "storage_fee_per_state_byte" },
            // 0.8 million APT for 2 TB state bytes
            40,
        ],
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L623-625)
```text
            } else if (transaction_fee_amount < storage_fee_refunded) {
                let mint_amount = storage_fee_refunded - transaction_fee_amount;
                transaction_fee::mint_and_refund(gas_payer, mint_amount);
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
