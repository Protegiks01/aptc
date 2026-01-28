# Audit Report

## Title
State View Version Mismatch in Events API Causes Type Confusion and API Inconsistency

## Summary
The Events API retrieves events at a specific ledger version but deserializes them using the latest state checkpoint's type information, creating a version mismatch that causes API failures and potential data corruption when Move modules are upgraded between these operations.

## Finding Description

The vulnerability exists in the event conversion flow. The execution path demonstrates a critical version mismatch:

**Step 1: Version Capture**
The events endpoint calls `Account::new()` which captures the current ledger state at a specific version. [1](#0-0) 

This retrieves `latest_ledger_info` by calling `get_latest_ledger_info_and_verify_lookup_version()`. [2](#0-1) 

The function captures the latest ledger info at time T1. [3](#0-2) 

**Step 2: Event Retrieval**
The `list()` function extracts this version and retrieves events at that specific version. [4](#0-3) 

**Step 3: Critical Bug - Version Mismatch**
The code then calls `latest_state_view_poem()` to get a state view for type conversion. [5](#0-4) 

This function **critically ignores** the `ledger_info` parameter's version and always retrieves the LATEST state checkpoint. [6](#0-5) 

The implementation calls `latest_state_checkpoint_view()` which gets the latest checkpoint version from the database, not the version from the ledger_info parameter. [7](#0-6) 

**Step 4: Type Deserialization with Wrong Version**
This state view is used by `try_into_versioned_events()` to deserialize event data using Move type layouts from the wrong version. [8](#0-7) 

**Correct Pattern**
The correct approach is demonstrated elsewhere in the API codebase, where `state_view_at_version()` is used to get state at a specific version. [9](#0-8) 

This same pattern exists for creating versioned state views. [10](#0-9) 

**Exploitation Scenario:**

When a Move module is upgraded between event retrieval (version V1) and type deserialization (version V2), the following issues occur:

- **Incompatible type layouts**: Deserialization fails, causing the API to return InternalError responses
- **Compatible but semantically different layouts**: Events deserialize successfully but with wrong field names/mappings, returning corrupted data to clients

This breaks the API's consistency guarantee that all data in a response corresponds to a single ledger version.

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria for "API Crashes (High)":

1. **API Availability**: When type layouts are incompatible between versions, deserialization fails and the API returns errors instead of valid event data, affecting network participants who rely on the Events API (indexers, monitoring tools, user applications)

2. **Data Integrity**: When type layouts are compatible but semantically different (e.g., field names changed), the API returns events with incorrect field mappings, potentially causing client applications to make wrong decisions based on corrupted data

3. **Protocol Violation**: The API guarantees consistent data at a specific ledger version, but this bug mixes type information from different versions, violating this fundamental consistency guarantee that is critical for blockchain API reliability

The same vulnerability pattern exists in the resources endpoint. [11](#0-10) 

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers during normal blockchain operation:

- Occurs naturally whenever Move modules are upgraded via governance (regular occurrence on Aptos mainnet)
- The timing window exists because operations execute in an async context via `api_spawn_blocking`. [12](#0-11) 
- Between capturing the ledger version and deserializing events, the blockchain can progress and a module upgrade can be committed
- No attacker sophistication required - just normal blockchain progression
- Affects any API user querying events during or shortly after module upgrades
- No special permissions needed

## Recommendation

Replace `latest_state_view_poem()` with `state_view_at_version()` to ensure the state view matches the version at which events were retrieved:

```rust
// In api/src/events.rs line 184, change from:
let state_view = self.context.latest_state_view_poem(&latest_ledger_info)?;

// To:
let state_view = self.context.state_view_at_version(ledger_version)
    .map_err(|err| {
        BasicErrorWith404::internal_with_code(
            err,
            AptosErrorCode::InternalError,
            &latest_ledger_info,
        )
    })?;
```

Apply the same fix to the resources endpoint in `api/src/accounts.rs`.

## Proof of Concept

While a full PoC would require triggering a module upgrade during API query execution, the bug is clearly demonstrated in the code paths traced above. The execution flow shows:
1. Events retrieved at version V1
2. Type information retrieved at version V2 (latest)
3. Deserialization uses mismatched versions

This can be reproduced by:
1. Deploying a Move module with event type T1
2. Emitting events with type T1
3. Upgrading the module to change type T1 to T2 (incompatible or with different field names)
4. Querying events immediately after the upgrade
5. Observing API failures or incorrect field mappings in the response

## Notes

This vulnerability demonstrates a critical consistency violation in the Aptos REST API. The bug affects multiple endpoints (events, resources) that perform type conversions, suggesting a systemic issue with how state views are obtained for deserialization operations. The fix requires ensuring version consistency between data retrieval and type resolution operations throughout the API layer.

### Citations

**File:** api/src/events.rs (L79-79)
```rust
            let account = Account::new(api.context.clone(), address.0, None, None, None)?;
```

**File:** api/src/events.rs (L162-178)
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
            .context(format!("Failed to find events by key {}", event_key))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &latest_ledger_info,
                )
            })?;
```

**File:** api/src/events.rs (L184-184)
```rust
                    .latest_state_view_poem(&latest_ledger_info)?
```

**File:** api/src/accounts.rs (L243-246)
```rust
        let (latest_ledger_info, requested_version) = context
            .get_latest_ledger_info_and_verify_lookup_version(
                requested_ledger_version.map(|inner| inner.0),
            )?;
```

**File:** api/src/accounts.rs (L476-478)
```rust
                let state_view = self
                    .context
                    .latest_state_view_poem(&self.latest_ledger_info)?;
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

**File:** api/src/context.rs (L177-195)
```rust
    pub fn state_view<E: StdApiError>(
        &self,
        requested_ledger_version: Option<u64>,
    ) -> Result<(LedgerInfo, u64, DbStateView), E> {
        let (latest_ledger_info, requested_ledger_version) =
            self.get_latest_ledger_info_and_verify_lookup_version(requested_ledger_version)?;

        let state_view = self
            .state_view_at_version(requested_ledger_version)
            .map_err(|err| {
                E::internal_with_code(err, AptosErrorCode::InternalError, &latest_ledger_info)
            })?;

        Ok((latest_ledger_info, requested_ledger_version, state_view))
    }

    pub fn state_view_at_version(&self, version: Version) -> Result<DbStateView> {
        Ok(self.db.state_view_at_version(Some(version))?)
    }
```

**File:** api/src/context.rs (L294-316)
```rust
    pub fn get_latest_ledger_info_and_verify_lookup_version<E: StdApiError>(
        &self,
        requested_ledger_version: Option<Version>,
    ) -> Result<(LedgerInfo, Version), E> {
        let latest_ledger_info = self.get_latest_ledger_info()?;

        let requested_ledger_version =
            requested_ledger_version.unwrap_or_else(|| latest_ledger_info.version());

        // This is too far in the future, a retriable case
        if requested_ledger_version > latest_ledger_info.version() {
            return Err(version_not_found(
                requested_ledger_version,
                &latest_ledger_info,
            ));
        } else if requested_ledger_version < latest_ledger_info.oldest_ledger_version.0 {
            return Err(version_pruned(
                requested_ledger_version,
                &latest_ledger_info,
            ));
        }

        Ok((latest_ledger_info, requested_ledger_version))
```

**File:** api/src/context.rs (L1645-1654)
```rust
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L82-90)
```rust
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L93-105)
```rust
pub trait DbStateViewAtVersion {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView>;
}

impl DbStateViewAtVersion for Arc<dyn DbReader> {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version,
            maybe_verify_against_state_root_hash: None,
        })
    }
}
```

**File:** api/types/src/convert.rs (L612-624)
```rust
    pub fn try_into_versioned_events(
        &self,
        events: &[EventWithVersion],
    ) -> Result<Vec<VersionedEvent>> {
        let mut ret = vec![];
        for event in events {
            let data = self
                .inner
                .view_value(event.event.type_tag(), event.event.event_data())?;
            ret.push((event, MoveValue::try_from(data)?.json()?).into());
        }
        Ok(ret)
    }
```
