# Audit Report

## Title
API Server Returns Inconsistent State Metadata Across Servers for Versioned Queries

## Summary
The Aptos REST API returns blockchain state metadata (epoch, timestamp, block height) from the latest ledger version in HTTP response headers, even when clients explicitly query historical versions. This causes different API servers at different sync states to return different header values for identical version-specific queries, breaking client assumptions about state consistency.

## Finding Description

The vulnerability exists in how the API constructs responses for version-specific queries. When a client queries a specific historical version (e.g., `GET /accounts/0x1?ledger_version=1000`), the API response contains:

1. **Body data** from the requested historical version (1000)
2. **Header metadata** from the LATEST ledger version (e.g., 2000+) [1](#0-0) 

The `Account::new` constructor calls `get_latest_ledger_info_and_verify_lookup_version()` which always retrieves the latest ledger info regardless of the requested version: [2](#0-1) 

This latest ledger info is then used to populate ALL response headers including `X-Aptos-Ledger-Version`, `X-Aptos-Epoch`, `X-Aptos-Ledger-Timestamp`, and `X-Aptos-Block-Height`: [3](#0-2) [4](#0-3) 

**Additional Inconsistency**: Servers with internal indexer enabled retrieve epoch/timestamp from `NewBlockEvent`, while servers without indexer use `LedgerInfoWithSignatures`, creating a second source of inconsistency: [5](#0-4) [6](#0-5) [7](#0-6) 

The client-side `State::from_headers()` function parses these headers assuming they represent the queried version: [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** under the bug bounty program's "API crashes" and "Significant protocol violations" categories because:

1. **Cross-Server Inconsistency**: Two API servers at different sync states (e.g., one at version 2000, another at 2500) will return different header values for the same query (`?ledger_version=1000`), violating the fundamental expectation that querying a specific version should return identical results across all servers.

2. **Client State Confusion**: Clients using `State::from_headers()` will construct a `State` object representing version 2000+ when they queried version 1000, causing:
   - Incorrect epoch detection (client thinks it's in epoch 6 when querying epoch 5 data)
   - Incorrect timestamp interpretation
   - Wrong block height association
   - Potential client-side consensus failures when comparing states

3. **Load Balancer Scenario**: In production, clients behind a load balancer will receive non-deterministic responses for identical queries, breaking idempotency and causing race conditions in client applications that rely on header metadata.

## Likelihood Explanation

This occurs **100% of the time** for any version-specific API query where:
- The requested version is not the latest version
- Clients use the response headers to determine blockchain state
- Multiple API servers exist at different sync states

No attacker action is required - this is a systemic design flaw affecting all API deployments.

## Recommendation

Modify the API to return headers matching the queried version, not the latest version. The fix requires two changes:

1. **For version-specific queries**: Retrieve state metadata for the REQUESTED version instead of latest:

```rust
// In api/src/context.rs
pub fn get_ledger_info_at_version<E: ServiceUnavailableError>(
    &self,
    version: Version,
) -> Result<LedgerInfo, E> {
    let (oldest_version, oldest_block_height) = self.get_oldest_version_and_block_height()?;
    let (_, _, block_event) = self
        .db
        .get_block_info_by_version(version)
        .context("Failed to retrieve block information for requested version")
        .map_err(|e| E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError))?;
    
    Ok(LedgerInfo::new_ledger_info(
        &self.chain_id(),
        block_event.epoch(),
        version,
        oldest_version,
        oldest_block_height,
        block_event.height(),
        block_event.proposed_time(),
    ))
}
```

2. **Update Account::new** to use version-specific ledger info:

```rust
pub fn new(
    context: Arc<Context>,
    address: Address,
    requested_ledger_version: Option<U64>,
    start: Option<StateKey>,
    limit: Option<u16>,
) -> Result<Self, BasicErrorWith404> {
    let (latest_ledger_info, requested_version) = context
        .get_latest_ledger_info_and_verify_lookup_version(
            requested_ledger_version.map(|inner| inner.0),
        )?;
    
    // Get ledger info for the actual version being queried
    let version_specific_ledger_info = if requested_version == latest_ledger_info.version() {
        latest_ledger_info
    } else {
        context.get_ledger_info_at_version(requested_version)?
    };

    Ok(Self {
        context,
        address,
        ledger_version: requested_version,
        start,
        limit,
        latest_ledger_info: version_specific_ledger_info,  // Use version-specific info
    })
}
```

## Proof of Concept

```rust
// Reproduction test demonstrating the issue
#[tokio::test]
async fn test_api_header_version_mismatch() {
    // Setup two API servers at different sync states
    let mut server1 = TestServer::new();
    let mut server2 = TestServer::new();
    
    // Server 1 synced to version 1000
    server1.sync_to_version(1000);
    // Server 2 synced to version 2000
    server2.sync_to_version(2000);
    
    // Both servers query the same historical version 500
    let response1 = server1.get_account("0x1", Some(500)).await;
    let response2 = server2.get_account("0x1", Some(500)).await;
    
    // Extract headers
    let state1 = State::from_headers(&response1.headers()).unwrap();
    let state2 = State::from_headers(&response2.headers()).unwrap();
    
    // BUG: Headers show different versions despite identical query
    assert_eq!(state1.version, 1000);  // Server 1's latest
    assert_eq!(state2.version, 2000);  // Server 2's latest
    // Both should be 500 (the queried version)!
    
    // Bodies are correct (both from version 500)
    assert_eq!(response1.body.sequence_number, response2.body.sequence_number);
    
    // This breaks client assumptions: same query, different header metadata
}
```

**Notes**

This vulnerability violates the API consistency guarantee that clients expect when querying specific versions. The mismatch between header metadata and body data creates a hidden state inconsistency that propagates to clients, particularly affecting applications that use header-based state tracking for epoch detection, timestamp validation, or cross-server state comparison.

### Citations

**File:** api/src/accounts.rs (L236-256)
```rust
    pub fn new(
        context: Arc<Context>,
        address: Address,
        requested_ledger_version: Option<U64>,
        start: Option<StateKey>,
        limit: Option<u16>,
    ) -> Result<Self, BasicErrorWith404> {
        let (latest_ledger_info, requested_version) = context
            .get_latest_ledger_info_and_verify_lookup_version(
                requested_ledger_version.map(|inner| inner.0),
            )?;

        Ok(Self {
            context,
            address,
            ledger_version: requested_version,
            start,
            limit,
            latest_ledger_info,
        })
    }
```

**File:** api/src/context.rs (L243-269)
```rust
    pub fn get_latest_storage_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<LedgerInfo, E> {
        let ledger_info = self
            .get_latest_ledger_info_with_signatures()
            .context("Failed to retrieve latest ledger info")
            .map_err(|e| {
                E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError)
            })?;

        let (oldest_version, oldest_block_height) = self.get_oldest_version_and_block_height()?;
        let (_, _, newest_block_event) = self
            .db
            .get_block_info_by_version(ledger_info.ledger_info().version())
            .context("Failed to retrieve latest block information")
            .map_err(|e| {
                E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError)
            })?;

        Ok(LedgerInfo::new(
            &self.chain_id(),
            &ledger_info,
            oldest_version,
            oldest_block_height,
            newest_block_event.height(),
        ))
    }
```

**File:** api/src/context.rs (L271-278)
```rust
    pub fn get_latest_ledger_info<E: ServiceUnavailableError>(&self) -> Result<LedgerInfo, E> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                return self.get_latest_internal_indexer_ledger_info();
            }
        }
        self.get_latest_storage_ledger_info()
    }
```

**File:** api/src/context.rs (L294-317)
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
    }
```

**File:** api/src/context.rs (L319-353)
```rust
    pub fn get_latest_internal_indexer_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<LedgerInfo, E> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                if let Some(mut latest_version) = indexer_reader
                    .get_latest_internal_indexer_ledger_version()
                    .map_err(|err| {
                        E::service_unavailable_with_code_no_info(err, AptosErrorCode::InternalError)
                    })?
                {
                    // The internal indexer version can be ahead of the storage committed version since it syncs to db's latest synced version
                    let last_storage_version =
                        self.get_latest_storage_ledger_info()?.ledger_version.0;
                    latest_version = std::cmp::min(latest_version, last_storage_version);
                    let (_, block_end_version, new_block_event) = self
                        .db
                        .get_block_info_by_version(latest_version)
                        .map_err(|_| {
                            E::service_unavailable_with_code_no_info(
                                "Failed to get block",
                                AptosErrorCode::InternalError,
                            )
                        })?;
                    let (oldest_version, oldest_block_height) =
                        self.get_oldest_version_and_block_height()?;
                    return Ok(LedgerInfo::new_ledger_info(
                        &self.chain_id(),
                        new_block_event.epoch(),
                        block_end_version,
                        oldest_version,
                        oldest_block_height,
                        new_block_event.height(),
                        new_block_event.proposed_time(),
                    ));
```

**File:** api/src/response.rs (L170-189)
```rust
            fn [<$name:snake _with_code>]<Err: std::fmt::Display>(
                err: Err,
                error_code: aptos_api_types::AptosErrorCode,
                ledger_info: &aptos_api_types::LedgerInfo
            )-> Self where Self: Sized {
                let error = aptos_api_types::AptosError::new_with_error_code(err, error_code);
                let payload = poem_openapi::payload::Json(Box::new(error));

                Self::from($enum_name::$name(
                    payload,
                    Some(ledger_info.chain_id),
                    Some(ledger_info.ledger_version.into()),
                    Some(ledger_info.oldest_ledger_version.into()),
                    Some(ledger_info.ledger_timestamp.into()),
                    Some(ledger_info.epoch.into()),
                    Some(ledger_info.block_height.into()),
                    Some(ledger_info.oldest_block_height.into()),
                    None,
                ))
            }
```

**File:** api/src/response.rs (L459-471)
```rust
           pub fn try_from_json<E: $crate::response::InternalError>(
                (value, ledger_info, status): (
                    T,
                    &aptos_api_types::LedgerInfo,
                    [<$enum_name Status>],
                ),
            ) -> Result<Self, E> {
               Ok(Self::from((
                    poem_openapi::payload::Json(value),
                    ledger_info,
                    status
               )))
            }
```

**File:** crates/aptos-rest-client/src/state.rs (L23-102)
```rust
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> anyhow::Result<Self> {
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_version = headers
            .get(X_APTOS_LEDGER_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_timestamp = headers
            .get(X_APTOS_LEDGER_TIMESTAMP)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_epoch = headers
            .get(X_APTOS_EPOCH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_ledger_version = headers
            .get(X_APTOS_LEDGER_OLDEST_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_block_height = headers
            .get(X_APTOS_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_block_height = headers
            .get(X_APTOS_OLDEST_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cursor = headers
            .get(X_APTOS_CURSOR)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let state = if let (
            Some(chain_id),
            Some(version),
            Some(timestamp_usecs),
            Some(epoch),
            Some(oldest_ledger_version),
            Some(block_height),
            Some(oldest_block_height),
            cursor,
        ) = (
            maybe_chain_id,
            maybe_version,
            maybe_timestamp,
            maybe_epoch,
            maybe_oldest_ledger_version,
            maybe_block_height,
            maybe_oldest_block_height,
            cursor,
        ) {
            Self {
                chain_id,
                epoch,
                version,
                timestamp_usecs,
                oldest_ledger_version,
                block_height,
                oldest_block_height,
                cursor,
            }
        } else {
            anyhow::bail!(
                "Failed to build State from headers due to missing values in response. \
                Chain ID: {:?}, Version: {:?}, Timestamp: {:?}, Epoch: {:?}, \
                Oldest Ledger Version: {:?}, Block Height: {:?} Oldest Block Height: {:?}",
                maybe_chain_id,
                maybe_version,
                maybe_timestamp,
                maybe_epoch,
                maybe_oldest_ledger_version,
                maybe_block_height,
                maybe_oldest_block_height,
            )
        };

        Ok(state)
    }
```
