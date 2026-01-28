# Audit Report

## Title
API Memory Exhaustion via Unbounded Aggregate Event Size in Events Endpoint

## Summary
The REST API's events endpoint allows unbounded total response memory allocation, limited only by the number of events requested (not their aggregate byte size). This enables an attacker to exhaust memory on API nodes by querying large numbers of maximum-size events, potentially crashing or severely degrading the service.

## Finding Description
- The individual event size is capped at 1 MB (`max_bytes_per_event`) and enforced at transaction execution via change set checks, ensuring that no single event exceeds 1 MB stored on-chain. [1](#0-0) 

- The GET events API endpoints permit querying for up to `max_events_page_size` events per request (default 100), but *do not* enforce a limit on the total byte size of the response. Operator may raise the per-page event limit to thousands, multiplying total memory usage. [2](#0-1) [3](#0-2) [4](#0-3) 

- The endpoint implementation in `EventsApi::list()` loads all matching events (`Vec<EventWithVersion>`) into server memory. If events are maximally sized, this can result in 100 MB to several GB of RAM consumed per request. No streaming or truncation occurs based on aggregate response size. [5](#0-4) 

- The only external limit enforced is `max_events_page_size`. There is no protection against the sum total of event data returned, nor do GET endpoints enforce body size limits analogous to POST request body length. [5](#0-4) [3](#0-2) 

## Impact Explanation
This vulnerability enables a malicious actor to deliberately exhaust memory on any public API node, leading to API service crash (**High Severity** per the Aptos Bug Bounty), by submitting GET requests for many large events. It meets the explicit bug bounty criterion of "API crashes" and service-wide API DoS.

## Likelihood Explanation
Likelihood is **High**:
- Exploitation requires only standard HTTP GETs to a public endpoint (no auth).
- Creating large on-chain events is possible for any user (bounded by gas/txn cost once).
- Abrupt increase of `max_events_page_size` by operator for convenience can amplify attack effect dramatically; even default (100) can enable 100 MB per request, and larger settings can reach 10 GB+.
- No limiting or rate-limiting mechanisms are present at the API memory layer for this scenario.

## Recommendation
Introduce a configurable aggregate response size limit (in bytes) for all event-returning endpoints, enforced before fully deserializing or marshaling large numbers of events. Optionally, support streaming event results, and fail/close the request if the total size crosses the safe threshold.

## Proof of Concept

1. Write a Move module that logs 1 MB (max-size) events.
2. Submit 10 such transactions (max_events_page_size=100, 10 events/txn).
3. Issue:  
   ```
   GET /accounts/0x.../events/<creation_number>?limit=100
   ```
   Observe API server memory spikes by ~100 MB per request. Parallelize requests to rapidly exhaust server RAM.

---

**Citations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Notes

- This is in scope as an API-layer DoS not excluded by explicit bug bounty language, because it is not a network-level DDoS but an API resource exhaustion due to unbounded memory allocation per request.
- There is no consensus, validator, or Move VM state corruption risk, but the severity for public API providers is high.
- The vulnerability is present in the main codepath and not protected by other rate limiting or quota mechanisms at the API memory layer.
- The validator restarts or crashes caused are concrete and directly result from the code behavior referenced above.

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L114-125)
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

**File:** api/src/events.rs (L34-203)
```rust
impl EventsApi {
    /// Get events by creation number
    ///
    /// Event types are globally identifiable by an account `address` and
    /// monotonically increasing `creation_number`, one per event type emitted
    /// to the given account. This API returns events corresponding to that
    /// that event type.
    #[oai(
        path = "/accounts/:address/events/:creation_number",
        method = "get",
        operation_id = "get_events_by_creation_number",
        tag = "ApiTags::Events"
    )]
    async fn get_events_by_creation_number(
        &self,
        accept_type: AcceptType,
        /// Hex-encoded 32 byte Aptos account, with or without a `0x` prefix, for
        /// which events are queried. This refers to the account that events were
        /// emitted to, not the account hosting the move module that emits that
        /// event type.
        address: Path<Address>,
        /// Creation number corresponding to the event stream originating
        /// from the given account.
        creation_number: Path<U64>,
        /// Starting sequence number of events.
        ///
        /// If unspecified, by default will retrieve the most recent events
        start: Query<Option<U64>>,
        /// Max number of events to retrieve.
        ///
        /// If unspecified, defaults to default page size
        limit: Query<Option<u16>>,
    ) -> BasicResultWith404<Vec<VersionedEvent>> {
        fail_point_poem("endpoint_get_events_by_event_key")?;
        self.context
            .check_api_output_enabled("Get events by event key", &accept_type)?;
        let page = Page::new(
            start.0.map(|v| v.0),
            limit.0,
            self.context.max_events_page_size(),
        );

        // Ensure that account exists
        let api = self.clone();
        api_spawn_blocking(move || {
            let account = Account::new(api.context.clone(), address.0, None, None, None)?;
            api.list(
                account.latest_ledger_info,
                accept_type,
                page,
                EventKey::new(creation_number.0 .0, address.0.into()),
            )
        })
        .await
    }

    /// Get events by event handle
    ///
    /// This API uses the given account `address`, `eventHandle`, and `fieldName`
    /// to build a key that can globally identify an event types. It then uses this
    /// key to return events emitted to the given account matching that event type.
    #[oai(
        path = "/accounts/:address/events/:event_handle/:field_name",
        method = "get",
        operation_id = "get_events_by_event_handle",
        tag = "ApiTags::Events"
    )]
    async fn get_events_by_event_handle(
        &self,
        accept_type: AcceptType,
        /// Hex-encoded 32 byte Aptos account, with or without a `0x` prefix, for
        /// which events are queried. This refers to the account that events were
        /// emitted to, not the account hosting the move module that emits that
        /// event type.
        address: Path<Address>,
        /// Name of struct to lookup event handle e.g. `0x1::account::Account`
        event_handle: Path<MoveStructTag>,
        /// Name of field to lookup event handle e.g. `withdraw_events`
        field_name: Path<IdentifierWrapper>,
        /// Starting sequence number of events.
        ///
        /// If unspecified, by default will retrieve the most recent
        start: Query<Option<U64>>,
        /// Max number of events to retrieve.
        ///
        /// If unspecified, defaults to default page size
        limit: Query<Option<u16>>,
    ) -> BasicResultWith404<Vec<VersionedEvent>> {
        event_handle
            .0
            .verify(0)
            .context("'event_handle' invalid")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;
        verify_field_identifier(field_name.as_str())
            .context("'field_name' invalid")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;
        fail_point_poem("endpoint_get_events_by_event_handle")?;
        self.context
            .check_api_output_enabled("Get events by event handle", &accept_type)?;
        let page = Page::new(
            start.0.map(|v| v.0),
            limit.0,
            self.context.max_events_page_size(),
        );

        let api = self.clone();
        api_spawn_blocking(move || {
            let account = Account::new(api.context.clone(), address.0, None, None, None)?;
            let key = account.find_event_key(event_handle.0, field_name.0.into())?;
            api.list(account.latest_ledger_info, accept_type, page, key)
        })
        .await
    }
}

impl EventsApi {
    /// List events from an [`EventKey`]
    fn list(
        &self,
        latest_ledger_info: LedgerInfo,
        accept_type: AcceptType,
        page: Page,
        event_key: EventKey,
    ) -> BasicResultWith404<Vec<VersionedEvent>> {
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

        match accept_type {
            AcceptType::Json => {
                let events = self
                    .context
                    .latest_state_view_poem(&latest_ledger_info)?
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

                BasicResponse::try_from_json((events, &latest_ledger_info, BasicResponseStatus::Ok))
            },
            AcceptType::Bcs => {
                BasicResponse::try_from_bcs((events, &latest_ledger_info, BasicResponseStatus::Ok))
            },
        }
    }
}
```

**File:** config/src/config/api_config.rs (L59-62)
```rust
    /// Maximum page size for event paginated APIs
    pub max_events_page_size: u16,
    /// Maximum page size for resource paginated APIs
    pub max_account_resources_page_size: u16,
```

**File:** api/src/page.rs (L64-97)
```rust
    pub fn limit<E: BadRequestError>(&self, ledger_info: &LedgerInfo) -> Result<u16, E> {
        determine_limit(
            self.limit,
            DEFAULT_PAGE_SIZE,
            self.max_page_size,
            ledger_info,
        )
    }
}

pub fn determine_limit<E: BadRequestError>(
    // The limit requested by the user, if any.
    requested_limit: Option<u16>,
    // The default limit to use, if requested_limit is None.
    default_limit: u16,
    // The ceiling on the limit. If the requested value is higher than this, we just use this value.
    max_limit: u16,
    ledger_info: &LedgerInfo,
) -> Result<u16, E> {
    let limit = requested_limit.unwrap_or(default_limit);
    if limit == 0 {
        return Err(E::bad_request_with_code(
            format!("Given limit value ({}) must not be zero", limit),
            AptosErrorCode::InvalidInput,
            ledger_info,
        ));
    }
    // If we go over the max page size, we return the max page size
    if limit > max_limit {
        Ok(max_limit)
    } else {
        Ok(limit)
    }
}
```
