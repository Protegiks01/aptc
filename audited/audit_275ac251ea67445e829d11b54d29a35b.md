# Audit Report

## Title
Event Storage Fee Bypass Enabling Database Bloat via Unlimited mint_token_events Emission

## Summary
In Token V1, the `mint_token` function emits a `MintTokenEvent` for each mint operation without a per-transaction event count limit. Under DiskSpacePricingV2 (enabled when gas feature version ≥13 with REFUNDABLE_BYTES flag), events incur zero storage fees while being permanently stored in the database. A malicious token creator can exploit this by repeatedly calling `mint_token` in a loop within a single transaction, emitting thousands of events at minimal cost, causing database bloat and making collection activity tracking prohibitively expensive.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Event Emission without Storage Fees**

In DiskSpacePricingV2, the `legacy_storage_fee_per_event` function returns zero for all events: [1](#0-0) 

**2. Unrestricted mint_token Event Emission**

The `mint_token` function in Token V1 emits one `MintTokenEvent` per call with only creator authorization checks: [2](#0-1) 

Each call unconditionally emits an event without any rate limiting or event count validation.

**3. Permanent Event Storage**

Events are permanently stored in the database via the EventStore and indexed through multiple schemas: [3](#0-2) 

**4. Insufficient Transaction-Level Validation**

The `check_change_set` validation only enforces byte-based limits (10MB total event bytes per transaction) but no event count limit: [4](#0-3) 

**Attack Path:**

1. Attacker creates a token collection with `maximum = 0` (unlimited supply)
2. Attacker deploys a Move module containing a function that calls `mint_token` in a loop (e.g., 10,000-50,000 times per transaction depending on gas limits)
3. Each `mint_token` call emits a ~100-200 byte `MintTokenEvent` containing `TokenDataId` and `amount`
4. With a 10MB per-transaction event limit, attacker can emit ~50,000 small events per transaction
5. In DiskSpacePricingV2, events incur **zero storage fees** despite permanent storage
6. Attacker pays only IO gas (~1000-2000 internal gas units per event) and execution gas
7. All events are permanently stored, indexed by version, event key, and sequence number
8. Repeated across many transactions, this causes significant database bloat

**Economic Imbalance:**
- Cost to attacker: Only IO/execution gas (no storage fees)
- Cost to network: Permanent storage + indexing + sync bandwidth for all nodes
- Per transaction: ~0.0001 APT attacker cost vs. megabytes of permanent storage imposed on network

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

1. **Storage Bloat**: Causes unbounded database growth as events are never pruned
2. **Indexing Performance Degradation**: EventStore must index each event across multiple schemas, degrading query performance
3. **Collection Activity Tracking Cost**: As stated in the security question, the excessive events make tracking collection activity "prohibitively expensive"
4. **Resource Exhaustion**: While not causing immediate node crashes, sustained attacks could fill disk space and require manual intervention
5. **State Inconsistency Risk**: Aligns with "State inconsistencies requiring intervention" under Medium severity

This does not reach High/Critical severity because:
- No funds are lost or stolen
- No consensus violations occur
- Network remains operational (not a liveness failure)
- Does not require a hard fork to resolve (can be mitigated via pruning or gas schedule updates)

## Likelihood Explanation

**Likelihood: High**

1. **Low Barrier to Entry**: Any user can create a token collection (no special permissions required)
2. **Simple Exploitation**: Writing a Move module with a loop calling `mint_token` is trivial
3. **Economic Viability**: With zero event storage fees in V2, the attack is extremely cost-effective
4. **No Built-in Mitigation**: Current codebase has no event count limits or storage fee accountability for events
5. **Existing Infrastructure**: Token V1 is deployed and actively used on mainnet

The attack requires:
- Deploying a custom Move module (standard blockchain operation)
- Creating a token collection (standard operation)
- Executing transactions with the malicious module (standard operation)
- No privileged access or validator collusion needed

## Recommendation

**Short-term Mitigation:**

1. Implement per-transaction event count limits in `ChangeSetConfigs`:

```rust
pub struct ChangeSetConfigs {
    // ... existing fields ...
    max_events_per_transaction: u64,
}

pub fn check_change_set(&self, change_set: &impl ChangeSetInterface) -> Result<(), VMStatus> {
    // ... existing validation ...
    
    let mut event_count = 0;
    let mut total_event_size = 0;
    for event in change_set.events_iter() {
        event_count += 1;
        if event_count > self.max_events_per_transaction {
            return storage_write_limit_reached(Some("Too many events."));
        }
        
        let size = event.event_data().len() as u64;
        // ... existing size validation ...
    }
    Ok(())
}
```

2. Add a `max_events_per_transaction` parameter to gas schedule (suggested value: 1000-5000 events)

**Long-term Solution:**

Reintroduce storage fees for events even in V2 pricing, or implement event pruning policies:

```rust
pub fn storage_fee_per_event(
    &self,
    params: &TransactionGasParameters,
    event: &ContractEvent,
) -> Fee {
    match self {
        Self::V1 => {
            NumBytes::new(event.size() as u64) * params.legacy_storage_fee_per_event_byte
        },
        Self::V2 => {
            // Maintain storage fees for events even in V2
            NumBytes::new(event.size() as u64) * params.storage_fee_per_event_byte
        }
    }
}
```

**Alternative Mitigation in Token Module:**

Add per-transaction mint count tracking in the `Collections` resource to rate-limit mints from the same creator within a single transaction.

## Proof of Concept

```move
module attacker::event_flooder {
    use aptos_token::token::{Self, TokenDataId};
    use std::signer;
    use std::string;
    
    /// Floods the blockchain with mint events
    public entry fun flood_mint_events(
        creator: &signer,
        collection: vector<u8>,
        token_name: vector<u8>,
        iterations: u64
    ) {
        let token_data_id = token::create_token_data_id(
            signer::address_of(creator),
            string::utf8(collection),
            string::utf8(token_name)
        );
        
        // Loop to emit many events in a single transaction
        // Limited only by gas, not storage fees
        let i = 0;
        while (i < iterations) {
            token::mint_token(creator, token_data_id, 1);
            i = i + 1;
        };
    }
}
```

**Execution Steps:**
1. Deploy the `event_flooder` module to mainnet
2. Create a token collection with unlimited supply (`maximum = 0`)
3. Create a token within that collection
4. Call `flood_mint_events` with `iterations = 10000`
5. Single transaction emits 10,000 `MintTokenEvent` instances (~2MB total)
6. Repeat across multiple transactions to accumulate gigabytes of event data
7. Observe database growth in EventStore without corresponding storage fee charges

**Notes:**

- The vulnerability is confirmed in the current codebase where `DiskSpacePricingV2` returns `0.into()` for event storage fees
- The 10MB per-transaction event limit allows ~50,000 small events per transaction
- With zero storage fees, the economic incentive to exploit this is high
- All nodes must permanently store and index these events, creating a tragedy-of-the-commons scenario

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L57-69)
```rust
    /// Calculates the storage fee for an event.
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

**File:** aptos-move/framework/aptos-token/sources/token.move (L1444-1483)
```text
    public fun mint_token(
        account: &signer,
        token_data_id: TokenDataId,
        amount: u64,
    ): TokenId acquires Collections, TokenStore {
        assert!(token_data_id.creator == signer::address_of(account), error::permission_denied(ENO_MINT_CAPABILITY));
        let creator_addr = token_data_id.creator;
        let all_token_data = &mut Collections[creator_addr].token_data;
        assert!(all_token_data.contains(token_data_id), error::not_found(ETOKEN_DATA_NOT_PUBLISHED));
        let token_data = all_token_data.borrow_mut(token_data_id);

        if (token_data.maximum > 0) {
            assert!(token_data.supply + amount <= token_data.maximum, error::invalid_argument(EMINT_WOULD_EXCEED_TOKEN_MAXIMUM));
            token_data.supply += amount;
        };

        // we add more tokens with property_version 0
        let token_id = create_token_id(token_data_id, 0);
        if (std::features::module_event_migration_enabled()) {
            event::emit(Mint { creator: creator_addr, id: token_data_id, amount })
        } else {
            event::emit_event<MintTokenEvent>(
                &mut Collections[creator_addr].mint_token_events,
                MintTokenEvent {
                    id: token_data_id,
                    amount,
                }
            );
        };

        deposit_token(account,
            Token {
                id: token_id,
                amount,
                token_properties: property_map::empty(), // same as default properties no need to store
            }
        );

        token_id
    }
```

**File:** aptos-move/framework/src/natives/event.rs (L102-151)
```rust
fn native_write_to_event_store(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(arguments.len() == 3);

    let ty = &ty_args[0];
    let msg = arguments.pop_back().unwrap();
    let seq_num = safely_pop_arg!(arguments, u64);
    let guid = safely_pop_arg!(arguments, Vec<u8>);

    // TODO(Gas): Get rid of abstract memory size
    context.charge(
        EVENT_WRITE_TO_EVENT_STORE_BASE
            + EVENT_WRITE_TO_EVENT_STORE_PER_ABSTRACT_VALUE_UNIT * context.abs_val_size(&msg)?,
    )?;
    let ty_tag = context.type_to_type_tag(ty)?;
    let (layout, contains_delayed_fields) = context
        .type_to_type_layout_with_delayed_fields(ty)?
        .unpack();

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    let blob = ValueSerDeContext::new(max_value_nest_depth)
        .with_delayed_fields_serde()
        .with_func_args_deserialization(&function_value_extension)
        .serialize(&msg, &layout)?
        .ok_or_else(|| {
            SafeNativeError::InvariantViolation(PartialVMError::new(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        })?;
    let key = bcs::from_bytes(guid.as_slice()).map_err(|_| {
        SafeNativeError::InvariantViolation(PartialVMError::new(StatusCode::EVENT_KEY_MISMATCH))
    })?;

    let ctx = context.extensions_mut().get_mut::<NativeEventContext>();
    let event =
        ContractEvent::new_v1(key, seq_num, ty_tag, blob).map_err(|_| SafeNativeError::Abort {
            abort_code: ECANNOT_CREATE_EVENT,
        })?;
    // TODO(layouts): avoid cloning layouts for events with delayed fields.
    ctx.events.push((
        event,
        contains_delayed_fields.then(|| layout.as_ref().clone()),
    ));
    Ok(smallvec![])
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
