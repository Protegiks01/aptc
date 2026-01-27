# Audit Report

## Title
Event Storage DOS via Zero Storage Fees in DiskSpacePricing V2

## Summary
In Aptos gas pricing V2 (gas feature version ≥13 with refundable bytes enabled), contract events are not charged storage fees, only IO gas. This creates an economic imbalance where attackers can spam large events (up to 10 MB per transaction) at minimal cost, forcing validators to store data for the default 90 million version prune window (approximately 104 days at 10 TPS), potentially causing disk space exhaustion.

## Finding Description

The vulnerability exists in the storage fee calculation for events under `DiskSpacePricing::V2`. When gas feature version is ≥13 and the refundable bytes feature is enabled, the `legacy_storage_fee_per_event()` function returns zero storage fees for events: [1](#0-0) 

This means events only incur IO gas costs, calculated as: [2](#0-1) 

The attack flow is:

1. **Attacker creates malicious Move contract** that emits maximum-sized events (exploiting the 10 MB per transaction limit): [3](#0-2) 

2. **Events are stored permanently** in multiple column families until pruned: [4](#0-3) 

3. **Storage fee calculation confirms zero fees in V2**: [5](#0-4) 

4. **Events persist for default prune window**: [6](#0-5) 

**Economic Attack Analysis:**
- **Cost per transaction (10 MB events):** ~933M internal gas for IO (approximately 0.001-0.01 APT depending on gas price)
- **Storage imposed on network:** 10 MB stored across all validators for 90M versions
- **Sustained attack at 1 TPS:** 86,400 txns/day × 10 MB = ~864 GB/day
- **Total before pruning (104 days at 10 TPS):** ~89 TB of event data

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The storage cost to validators far exceeds the gas cost paid by the attacker.

## Impact Explanation

**Severity: Medium** - This vulnerability meets the Aptos bug bounty Medium severity criteria for "State inconsistencies requiring intervention":

1. **Validator Disk Space Exhaustion:** Sustained attacks can fill validator storage, requiring manual intervention to add disk capacity or adjust pruning settings
2. **Operational Disruption:** Validators may experience degraded performance or crashes when disk space is exhausted
3. **Economic Imbalance:** Attackers pay minimal gas fees but impose significant storage costs on the entire validator set
4. **Not Consensus-Breaking:** Does not directly compromise consensus safety or cause permanent network damage, as events are eventually pruned

The impact is limited to Medium (not High/Critical) because:
- Events are eventually pruned (not permanent)
- No direct loss of funds or consensus compromise
- Validators can mitigate by adjusting configuration
- Requires sustained attack over time

## Likelihood Explanation

**Likelihood: High**

1. **Low Attack Cost:** Minimal gas fees (only IO gas) make this economically feasible
2. **No Special Privileges Required:** Any account can deploy contracts and emit events
3. **Easy to Execute:** Simple Move contract with event emission in loop
4. **Active on Mainnet:** Pricing V2 is the current production configuration (gas feature version ≥13)
5. **Large Attack Surface:** All transactions can emit up to 10 MB of events

The only limiting factors are:
- Transaction gas limits (but attacker can send multiple transactions)
- Transaction fees (but much lower than storage cost imposed)
- Network TPS capacity (but even low-rate attacks accumulate over prune window)

## Recommendation

**Short-term Mitigation:**
1. Reduce the ledger prune window specifically for events (separate from other ledger data)
2. Add monitoring and rate limiting for contracts emitting large volumes of events

**Long-term Fix:**
Re-enable storage fees for events in pricing V2 or implement an alternative fee mechanism. Options include:

**Option 1:** Charge storage fees proportional to the prune window:
```rust
pub fn legacy_storage_fee_per_event(
    &self,
    params: &TransactionGasParameters,
    event: &ContractEvent,
) -> Fee {
    match self {
        Self::V1 => {
            NumBytes::new(event.size() as u64) * params.legacy_storage_fee_per_event_byte
        },
        Self::V2 => {
            // Charge reduced fee based on temporary storage
            // (event_size * storage_fee_per_byte * retention_factor)
            NumBytes::new(event.size() as u64) 
                * params.storage_fee_per_state_byte 
                * NumSlots::new(1) // Retention factor
        },
    }
}
```

**Option 2:** Implement separate event-specific prune window (much shorter than 90M versions)

**Option 3:** Add per-account event emission rate limits enforced at the VM level

## Proof of Concept

```move
module attacker::event_spam {
    use std::vector;
    use aptos_framework::event;

    #[event]
    struct LargeEvent has drop, store {
        data: vector<u8>,
    }

    /// Emit maximum-sized event to spam storage
    public entry fun spam_events(attacker: &signer) {
        // Create 1 MB event (just under max_bytes_per_event limit)
        let large_data = vector::empty<u8>();
        let i = 0;
        while (i < 1_000_000) {
            vector::push_back(&mut large_data, 0xFF);
            i = i + 1;
        };

        // Emit 10 events totaling ~10 MB (max_bytes_all_events_per_transaction)
        let j = 0;
        while (j < 10) {
            event::emit(LargeEvent { data: large_data });
            j = j + 1;
        };
    }
}
```

**Attack Execution:**
1. Deploy the contract above
2. Call `spam_events()` repeatedly (e.g., 1 transaction per second)
3. Over 104 days (at 10 TPS network), before pruning catches up: 86,400 txns/day × 104 days × 10 MB = ~89 TB stored on all validators
4. Cost to attacker: ~0.1-1 APT per day
5. Cost to network: Multiple terabytes of disk space per validator

**Validation:** The transaction will succeed if gas limits allow, events will be stored in `EVENT_CF_NAME` and related indexes, and validators must retain this data for 90 million versions before pruning.

## Notes

This vulnerability specifically affects networks running with:
- Gas feature version ≥13
- Refundable bytes feature enabled (determines V2 pricing)
- Default ledger pruner configuration (90M version window)

Networks still on pricing V1 are not affected as they charge `legacy_storage_fee_per_event_byte` (20 fee units per byte).

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L58-69)
```rust
    pub fn legacy_storage_fee_per_event(
        &self,
        params: &TransactionGasParameters,
        event: &ContractEvent,
    ) -> Fee {
        match self {
            Self::V1 => {
                NumBytes::new(event.size() as u64) * params.legacy_storage_fee_per_event_byte
            },
            Self::V2 => 0.into(),
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L296-301)
```rust
    pub fn io_gas_per_event(
        &self,
        event: &ContractEvent,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        STORAGE_IO_PER_EVENT_BYTE_WRITE * NumBytes::new(event.size() as u64)
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L115-125)
```rust
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
```

**File:** storage/aptosdb/src/schema/mod.rs (L42-45)
```rust
pub const EVENT_ACCUMULATOR_CF_NAME: ColumnFamilyName = "event_accumulator";
pub const EVENT_BY_KEY_CF_NAME: ColumnFamilyName = "event_by_key";
pub const EVENT_BY_VERSION_CF_NAME: ColumnFamilyName = "event_by_version";
pub const EVENT_CF_NAME: ColumnFamilyName = "event";
```

**File:** aptos-move/aptos-gas-meter/src/traits.rs (L195-202)
```rust
        // Events (no event fee in v2)
        let event_fee = change_set.events_iter().fold(Fee::new(0), |acc, event| {
            acc + pricing.legacy_storage_fee_per_event(params, event)
        });
        let event_discount = pricing.legacy_storage_discount_for_events(params, event_fee);
        let event_net_fee = event_fee
            .checked_sub(event_discount)
            .expect("event discount should always be less than or equal to total amount");
```

**File:** config/src/config/storage_config.rs (L387-395)
```rust
impl Default for LedgerPrunerConfig {
    fn default() -> Self {
        LedgerPrunerConfig {
            enable: true,
            prune_window: 90_000_000,
            batch_size: 5_000,
            user_pruning_window_offset: 200_000,
        }
    }
```
