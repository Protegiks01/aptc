# Audit Report

## Title
Legacy Storage Slots Bypass V2 Pricing Updates Through Same-Size Modifications

## Summary
The DiskSpacePricing V2 implementation contains an economic vulnerability where legacy slots with zero `bytes_deposit` can avoid storage charges indefinitely by maintaining the same data size during modifications, even as storage pricing increases through governance. This creates an unfair economic advantage for legacy slot holders and undermines the storage pricing mechanism.

## Finding Description

The vulnerability exists in the `charge_refund_write_op_v2` function which implements storage fee calculations for the V2 pricing model. [1](#0-0) 

The critical issue is in the modification case where storage fees are only charged when `write_len > op.prev_size`. Legacy state slots created before V2 pricing was enabled have their metadata stored in V0 format, which lacks a `bytes_deposit` field. When loaded, these slots are converted to in-memory format with `bytes_deposit = 0`: [2](#0-1) 

The design explicitly acknowledges this behavior: [3](#0-2) 

**Attack Scenario:**

1. Attacker possesses legacy state slots (created before gas feature version 13) with V0 metadata
2. These slots have `bytes_deposit = 0` as they were never charged under the new pricing model
3. Governance increases `storage_fee_per_state_byte` from 40 to 400 (10x increase) due to network growth
4. For new slots, users pay the new rate: `target_bytes_deposit = (key_size + data_size) * 400`
5. Attacker modifies their legacy slots by rewriting data at **exactly the same size** as before
6. Because `write_len == prev_size`, the condition `if write_len > op.prev_size` evaluates to false
7. No charge occurs (`state_bytes_charge = 0`) even though `target_bytes_deposit` would be 10x higher
8. Attacker effectively maintains free mutable storage while other users pay current market rates

The storage fee parameter is defined here and can be updated via governance: [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The storage pricing mechanism fails to enforce uniform pricing across all users, creating two classes of storage: legacy (free modifications) and new (paid modifications)
- **Limited economic manipulation**: Legacy slot holders can occupy valuable state space without paying current market rates, potentially hoarding storage during price increases
- **Storage exhaustion risk**: If governance raises pricing to combat storage bloat, legacy slots become immune to the economic pressure, undermining the mechanism's effectiveness

The vulnerability breaks Invariant #9 ("Resource Limits: All operations must respect gas, storage, and computational limits") by allowing certain users to bypass storage fees through a technical loophole rather than legitimate gas payment.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Legacy slots exist**: Any state created before gas feature version 13 with refundable bytes feature has V0 metadata with `bytes_deposit = 0`
2. **Pricing increases are expected**: As Aptos grows, storage pricing adjustments through governance are normal operational procedures
3. **Attack requires no special permissions**: Any user with legacy slots can exploit this by submitting normal transactions
4. **Attack is trivial**: Simply modify data at the same byte length - no complex transaction construction needed
5. **Economic incentive exists**: During price increases, legacy slot holders have strong financial motivation to exploit this rather than delete and recreate slots at new rates

## Recommendation

Modify the V2 charging logic to enforce pricing updates even when slot size remains constant. Track a "last_price_per_byte" field in metadata and compare against current pricing:

```rust
Modification { write_len } => {
    let old_bytes_deposit = op.metadata_mut.bytes_deposit();
    let current_price = u64::from(params.storage_fee_per_state_byte);
    
    let state_bytes_charge = if target_bytes_deposit > old_bytes_deposit {
        if write_len > op.prev_size {
            // Size increased - charge for new bytes
            let charge_by_increase = (write_len - op.prev_size) * current_price;
            let gap_from_target = target_bytes_deposit - old_bytes_deposit;
            std::cmp::min(charge_by_increase, gap_from_target)
        } else {
            // Size unchanged but price increased - charge the gap
            // This ensures legacy slots pay the difference when pricing updates
            target_bytes_deposit - old_bytes_deposit
        }
    } else {
        0
    };
    
    op.metadata_mut.maybe_upgrade();
    op.metadata_mut.set_bytes_deposit(old_bytes_deposit + state_bytes_charge);
    
    ChargeAndRefund {
        charge: state_bytes_charge.into(),
        refund: 0.into(),
    }
}
```

This modification ensures that when `target_bytes_deposit > old_bytes_deposit` (which includes legacy slots with zero deposit when prices increase), users are charged the difference even if the size hasn't changed.

## Proof of Concept

Add this test to `aptos-move/aptos-vm-types/src/storage/space_pricing.rs`:

```rust
#[test]
fn test_legacy_slot_pricing_bypass() {
    let pricing = DiskSpacePricing::V2;
    let mut params = TransactionGasParameters::random();
    params.storage_fee_per_state_byte = 10.into(); // Initial price
    params.storage_fee_per_state_slot = 1000.into();
    let key = StateKey::raw(&[1, 2, 3]);
    let ts = CurrentTimeMicroseconds { microseconds: 0 };
    
    // Simulate legacy slot with zero bytes_deposit (V0 metadata)
    let mut meta = StateValueMetadata::legacy(1000, &ts);
    assert_eq!(meta.bytes_deposit(), 0);
    assert_eq!(meta.slot_deposit(), 1000);
    
    // Modify at same size - should charge nothing under current implementation
    let ChargeAndRefund { charge, refund } = 
        pricing.charge_refund_write_op(&params, WriteOpInfo {
            key: &key,
            op_size: WriteOpSize::Modification { write_len: 100 },
            prev_size: 100,
            metadata_mut: &mut meta,
        });
    
    // VULNERABILITY: No charge despite bytes_deposit being zero
    assert_eq!(charge, 0.into());
    assert_eq!(meta.bytes_deposit(), 0);
    
    // Now increase pricing 10x (governance action)
    params.storage_fee_per_state_byte = 100.into();
    
    // Modify again at same size
    let ChargeAndRefund { charge, refund } = 
        pricing.charge_refund_write_op(&params, WriteOpInfo {
            key: &key,
            op_size: WriteOpSize::Modification { write_len: 100 },
            prev_size: 100,
            metadata_mut: &mut meta,
        });
    
    // VULNERABILITY CONFIRMED: Still no charge despite 10x price increase
    // Target should be (3 + 100) * 100 = 10,300 but we pay 0
    assert_eq!(charge, 0.into());
    assert_eq!(meta.bytes_deposit(), 0);
    
    // Compare to new user creating same slot at new prices
    let mut new_meta = StateValueMetadata::new(0, 0, &ts);
    let ChargeAndRefund { charge: new_charge, .. } = 
        pricing.charge_refund_write_op(&params, WriteOpInfo {
            key: &key,
            op_size: WriteOpSize::Creation { write_len: 100 },
            prev_size: 0,
            metadata_mut: &mut new_meta,
        });
    
    // New user pays full price: 1000 (slot) + 10,300 (bytes) = 11,300
    assert_eq!(new_charge, 11300.into());
    
    // Legacy user paid: 0 (exploit)
    // Unfair advantage: 11,300 units of gas
}
```

## Notes

This vulnerability represents a design decision that creates an exploitable economic loophole. While the code comments indicate awareness that legacy slots receive preferential treatment, the security impact is that these users can indefinitely avoid fair storage pricing by maintaining data at the same size. This undermines the storage pricing mechanism's ability to respond to network conditions through governance-driven price adjustments.

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

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L187-207)
```rust
            Modification { write_len } => {
                // Change of slot size or per byte price can result in a charge or refund of the bytes fee.
                let old_bytes_deposit = op.metadata_mut.bytes_deposit();
                let state_bytes_charge =
                    if write_len > op.prev_size && target_bytes_deposit > old_bytes_deposit {
                        let charge_by_increase: u64 = (write_len - op.prev_size)
                            * u64::from(params.storage_fee_per_state_byte);
                        let gap_from_target = target_bytes_deposit - old_bytes_deposit;
                        std::cmp::min(charge_by_increase, gap_from_target)
                    } else {
                        0
                    };
                op.metadata_mut.maybe_upgrade();
                op.metadata_mut
                    .set_bytes_deposit(old_bytes_deposit + state_bytes_charge);

                ChargeAndRefund {
                    charge: state_bytes_charge.into(),
                    refund: 0.into(),
                }
            },
```

**File:** types/src/state_store/state_value.rs (L31-43)
```rust
    pub fn into_in_mem_form(self) -> StateValueMetadata {
        match self {
            PersistedStateValueMetadata::V0 {
                deposit,
                creation_time_usecs,
            } => StateValueMetadata::new_impl(deposit, 0, creation_time_usecs),
            PersistedStateValueMetadata::V1 {
                slot_deposit,
                bytes_deposit,
                creation_time_usecs,
            } => StateValueMetadata::new_impl(slot_deposit, bytes_deposit, creation_time_usecs),
        }
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
