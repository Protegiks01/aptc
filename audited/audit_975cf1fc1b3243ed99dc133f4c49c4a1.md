# Audit Report

## Title
Stale State View Used for Event Conversion Causes Cross-Epoch Deserialization Inconsistency in Events API

## Summary
The `get_events_by_creation_number()` function uses a stale `latest_ledger_info` snapshot to query events from a specific version, but then uses the **current latest** state view to deserialize those events. This mismatch can cause events to be deserialized using Move module definitions from a different epoch than when the events were emitted, leading to API response inconsistencies or failures during epoch transitions.

## Finding Description

In the `get_events_by_creation_number()` endpoint, there is a critical inconsistency in version handling: [1](#0-0) 

The Account is created with the latest ledger info at the time of the API call. However, in the subsequent `list()` function, there's a version mismatch: [2](#0-1) 

Events are fetched at `ledger_version` extracted from the potentially stale `latest_ledger_info`. But critically: [3](#0-2) 

The `latest_state_view_poem()` function is called to get a state view for conversion. This function retrieves the **current latest** state view, not the state view at `ledger_version`: [4](#0-3) 

The implementation calls `latest_state_checkpoint_view()` which returns the current latest state, ignoring the `ledger_info` parameter (used only for error reporting).

**Attack Scenario:**
1. Client calls `get_events_by_creation_number()` at time T1
2. Account is created with `latest_ledger_info` at version V1 (epoch E1)
3. Between Account creation and event conversion, new blocks are committed including an epoch transition
4. Blockchain advances to version V2 (epoch E2) with upgraded Move modules
5. Events are fetched at version V1 (correct - from epoch E1)
6. But `latest_state_view_poem()` returns state at version V2 (wrong - from epoch E2)
7. Event deserialization uses Move module definitions from epoch E2 to interpret events emitted in epoch E1
8. If module definitions changed during the upgrade, deserialization can fail or produce incorrect data

The vulnerability is that events from epoch E1 are being interpreted using type information from epoch E2. While Move has compatibility guarantees, these are forward-compatibility focused (new code reading old data), not cross-epoch consistency for API responses.

## Impact Explanation

This is a **High Severity** issue per the Aptos bug bounty criteria:

1. **API Crashes**: If Move module layouts changed incompatibly between epochs (despite compatibility checks), deserialization can fail, causing API endpoint failures

2. **Significant Protocol Violations**: The API returns event data that was deserialized using incorrect module versions, violating the integrity guarantee that historical data should be interpreted using historical type definitions

3. **Data Consistency**: Clients querying events at a specific version receive responses influenced by state from a different version, breaking temporal consistency

The issue doesn't rise to Critical severity because it doesn't directly cause:
- Loss of funds
- Consensus violations
- Network-wide unavailability

However, it significantly impacts API reliability and data correctness, especially during epoch transitions when protocol upgrades occur.

## Likelihood Explanation

**High Likelihood:**

1. **Race Window**: The vulnerability triggers whenever blocks are committed between Account creation (line 79) and event conversion (line 184). Given Aptos's ~4 second block time, this race window exists on every API call.

2. **Epoch Transitions**: The impact is magnified during epoch transitions when Move framework modules are upgraded. Epoch transitions occur regularly (approximately every 2 hours on mainnet).

3. **No Attack Required**: The issue manifests naturally during normal blockchain operation - no attacker intervention needed.

4. **High API Traffic**: Events APIs are frequently used by dApps, indexers, and wallets, increasing exposure.

## Recommendation

Use a version-consistent state view for event conversion. Replace the call to `latest_state_view_poem()` with `state_view_at_version()`:

**File:** `api/src/events.rs`

**Current implementation (line 182-186):** [3](#0-2) 

**Recommended fix:**

```rust
let events = self
    .context
    .state_view_at_version(ledger_version)
    .context("Failed to get state view at ledger version")
    .map_err(|err| {
        BasicErrorWith404::internal_with_code(
            err,
            AptosErrorCode::InternalError,
            &latest_ledger_info,
        )
    })?
    .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
    .try_into_versioned_events(&events)
    .context("Failed to convert events from storage into response")
    .map_err(|err| {
        BasicErrorWith404::internal_with_code(
            err,
            AptosErrorCode::InternalError,
            &latest_ledger_info,
        )
    })?;
```

This ensures events from version V are deserialized using module definitions from version V, maintaining temporal consistency.

**Similar Fix Needed:**
The `get_events_by_event_handle()` function has the same issue and should be fixed identically: [5](#0-4) 

## Proof of Concept

```rust
// Reproduction scenario:
// 1. Start with blockchain at version V1, epoch E1
// 2. Deploy Move module with event type EventTypeV1 { field_a: u64 }
// 3. Emit events using EventTypeV1
// 4. Upgrade module during epoch transition to E2
//    - Module now has EventTypeV2 { field_a: u64, field_b: address }
// 5. Call get_events_by_creation_number() immediately after epoch transition
//
// Expected: Events should deserialize using EventTypeV1 (the type at emission time)
// Actual: Events attempt to deserialize using EventTypeV2 (current type), causing:
//    - Deserialization error if layout incompatible
//    - Missing fields in response if layout compatible but semantics changed

// To test:
// 1. Set up two validator nodes with synchronized time
// 2. Trigger epoch transition with module upgrade
// 3. Query events API during/after transition
// 4. Observe deserialization failures or incorrect field interpretations
// 5. Compare with correct behavior using state_view_at_version()

// The vulnerability is timing-dependent and requires epoch transition to trigger,
// making it observable in testnet/mainnet conditions but difficult to reproduce
// in isolated unit tests without full blockchain infrastructure.
```

## Notes

- This vulnerability exists in both `get_events_by_creation_number()` and `get_events_by_event_handle()` endpoints
- The same pattern of using `latest_state_view_poem()` appears in `render_transactions_sequential()` and `render_transactions_non_sequential()`, which may have similar issues but require separate analysis
- Move's compatibility checking provides some protection but doesn't guarantee cross-epoch deserialization correctness for all cases
- The fix is straightforward: use version-consistent state views throughout the API layer

### Citations

**File:** api/src/events.rs (L79-85)
```rust
            let account = Account::new(api.context.clone(), address.0, None, None, None)?;
            api.list(
                account.latest_ledger_info,
                accept_type,
                page,
                EventKey::new(creation_number.0 .0, address.0.into()),
            )
```

**File:** api/src/events.rs (L144-148)
```rust
        api_spawn_blocking(move || {
            let account = Account::new(api.context.clone(), address.0, None, None, None)?;
            let key = account.find_event_key(event_handle.0, field_name.0.into())?;
            api.list(account.latest_ledger_info, accept_type, page, key)
        })
```

**File:** api/src/events.rs (L162-170)
```rust
        let ledger_version = latest_ledger_info.version();
        let events = self
            .context
            .get_events(
                &event_key,
                page.start_option(),
                page.limit(&latest_ledger_info)?,
                ledger_version,
            )
```

**File:** api/src/events.rs (L182-186)
```rust
                let events = self
                    .context
                    .latest_state_view_poem(&latest_ledger_info)?
                    .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
                    .try_into_versioned_events(&events)
```

**File:** api/src/context.rs (L160-168)
```rust
    pub fn latest_state_view_poem<E: InternalError>(
        &self,
        ledger_info: &LedgerInfo,
    ) -> Result<DbStateView, E> {
        self.db
            .latest_state_checkpoint_view()
            .context("Failed to read latest state checkpoint from DB")
            .map_err(|e| E::internal_with_code(e, AptosErrorCode::InternalError, ledger_info))
    }
```
