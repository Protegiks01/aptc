# Audit Report

## Title
Configuration Validation Bypass Allows Zero-Limit Pagination Breaking Account Resources API

## Summary
The `max_account_resources_page_size` configuration parameter lacks validation, allowing it to be set to unsafe values including 0. When set to 0, a logic flaw in the `determine_limit` function causes complete denial of service for the `/accounts/:address/resources` endpoint, as pagination returns empty results with advancing cursors that never retrieve any resources.

## Finding Description

The vulnerability exists across three components that fail to properly validate and handle the `max_account_resources_page_size` configuration:

**1. Missing Configuration Validation**

The API configuration sanitizer does not validate `max_account_resources_page_size`: [1](#0-0) 

The sanitizer checks failpoints and runtime workers but never validates that `max_account_resources_page_size` is non-zero or within reasonable bounds.

**2. Logic Flaw in Limit Determination**

When a user provides an explicit limit parameter and the configuration value is 0, the `determine_limit` function incorrectly returns 0 instead of an error: [2](#0-1) 

The flaw occurs because:
- Line 83: When user provides `limit=100`, it becomes the working value
- Line 84-90: The zero-check passes since 100 ≠ 0
- Line 92-93: Since 100 > max_limit (0), it returns max_limit which is 0
- This bypasses the zero validation, returning an invalid limit of 0

**3. Broken Pagination Logic**

The 0 limit is passed to the pagination function, which breaks the pagination invariant: [3](#0-2) 

With `limit=0`:
- Line 525: Iterator takes at most 1 item (`limit + 1 = 1`)
- Line 528: Response collects 0 items (`take(0)`)
- Line 553: Cursor is set to the first uncollected item

This creates an impossible state where the response contains zero resources but includes a cursor, causing clients to loop indefinitely without ever retrieving data.

**Attack Execution Path:**

1. Operator sets `max_account_resources_page_size: 0` in node configuration (typo, misconfiguration, or malicious)
2. Node passes configuration sanitization (no validation exists)
3. User makes API request: `GET /accounts/0x1/resources?limit=1000`
4. The `resources()` function invokes determine_limit: [4](#0-3) 

5. API returns empty array with pagination cursor
6. Client follows cursor, receives empty array with new cursor
7. Loop continues indefinitely - resources are never retrievable

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability causes:
- **Complete DoS of `/accounts/:address/resources` endpoint** for all accounts
- **API availability failure** - clients cannot retrieve account resources
- **Resource waste** - clients make infinite requests consuming server resources
- **Service degradation** - breaks dependent applications and frontends

This qualifies as Medium severity because:
1. It affects API availability but not blockchain consensus or state
2. Requires operator-level configuration access
3. Can be mitigated by configuration change and node restart
4. Comparable to "State inconsistencies requiring intervention" (Medium category)

The impact is contained to the API layer and does not affect:
- Blockchain consensus or safety
- On-chain state or funds
- Validator operation or staking
- Core protocol execution

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can occur through:

1. **Configuration Error** (Most Likely):
   - Operator typo: `max_account_resources_page_size: 0` instead of `10000`
   - Misunderstanding: Setting 0 thinking it means "unlimited" or "disabled"
   - Copy-paste errors from example configs

2. **Malicious Operator** (Less Likely):
   - Intentional misconfiguration to DoS the API
   - Requires insider access with configuration privileges

3. **Default Value Issues** (Unlikely):
   - Currently defaults to 9999, but future changes could introduce issues

The lack of validation means this is a "silent failure" - the node starts successfully but the API is broken, making it harder to detect during deployment.

## Recommendation

Add comprehensive validation for pagination configuration parameters:

**1. Add Config Validation in Sanitizer:**

Add validation in `api_config.rs` sanitizer (after line 193):

```rust
// Validate pagination limits
if api_config.max_account_resources_page_size == 0 {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "max_account_resources_page_size must be greater than 0!".into(),
    ));
}

if api_config.max_account_modules_page_size == 0 {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "max_account_modules_page_size must be greater than 0!".into(),
    ));
}

// Optionally enforce maximum reasonable limits
const MAX_REASONABLE_PAGE_SIZE: u16 = 20_000;
if api_config.max_account_resources_page_size > MAX_REASONABLE_PAGE_SIZE {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        format!("max_account_resources_page_size ({}) exceeds maximum reasonable value ({})",
            api_config.max_account_resources_page_size, MAX_REASONABLE_PAGE_SIZE).into(),
    ));
}
```

**2. Defense in Depth - Validate max_limit in determine_limit:**

Modify `determine_limit` in `page.rs` to validate max_limit parameter (before line 83):

```rust
pub fn determine_limit<E: BadRequestError>(
    requested_limit: Option<u16>,
    default_limit: u16,
    max_limit: u16,
    ledger_info: &LedgerInfo,
) -> Result<u16, E> {
    // Validate configuration parameters
    if max_limit == 0 {
        return Err(E::internal_with_code(
            "Internal error: max_limit configuration is 0",
            AptosErrorCode::InternalError,
            ledger_info,
        ));
    }
    
    let limit = requested_limit.unwrap_or(default_limit);
    if limit == 0 {
        return Err(E::bad_request_with_code(
            format!("Given limit value ({}) must not be zero", limit),
            AptosErrorCode::InvalidInput,
            ledger_info,
        ));
    }
    
    if limit > max_limit {
        Ok(max_limit)
    } else {
        Ok(limit)
    }
}
```

## Proof of Concept

**Rust Test Demonstrating the Vulnerability:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_api_types::LedgerInfo;
    
    #[test]
    fn test_zero_max_limit_bypass() {
        let ledger_info = LedgerInfo::default();
        
        // Scenario: max_account_resources_page_size = 0
        let max_config = 0;
        
        // User provides explicit limit
        let user_limit = Some(100);
        
        // Call determine_limit as done in resources()
        let result = determine_limit::<BasicErrorWith404>(
            user_limit,
            max_config,  // default_limit = 0
            max_config,  // max_limit = 0
            &ledger_info,
        );
        
        // Bug: This returns Ok(0) instead of error!
        match result {
            Ok(limit) => {
                assert_eq!(limit, 0, "Limit should be 0 due to max_limit clamping");
                println!("VULNERABILITY: determine_limit returned 0 without error");
                println!("This will break pagination in get_resources_by_pagination");
            },
            Err(_) => {
                panic!("Expected Ok(0) due to bug, but got error");
            }
        }
    }
    
    #[test]
    fn test_zero_max_limit_without_user_input() {
        let ledger_info = LedgerInfo::default();
        
        // Scenario: max_account_resources_page_size = 0, no user limit
        let max_config = 0;
        let user_limit = None;
        
        // This correctly returns an error
        let result = determine_limit::<BasicErrorWith404>(
            user_limit,
            max_config,
            max_config,
            &ledger_info,
        );
        
        assert!(result.is_err(), "Should error when limit resolves to 0");
    }
}
```

**Integration Test Scenario:**

1. Configure node with `max_account_resources_page_size: 0` in config.yaml
2. Start node (it will start without validation error)
3. Make API request: `curl http://localhost:8080/accounts/0x1/resources?limit=100`
4. Observe: Empty array with X-Aptos-Cursor header
5. Make follow-up request with cursor
6. Observe: Infinite loop of empty responses with advancing cursors

## Notes

**Secondary Issue - High Limit Values:**

While the primary vulnerability is the 0 case, setting `max_account_resources_page_size` to u16::MAX (65535) can also cause problems:
- Exceeds `MAX_REQUEST_LIMIT` (20,000) used elsewhere in the codebase
- Can cause resource exhaustion (memory, CPU) for accounts with many resources
- Could be used for API DoS by requesting maximum page sizes repeatedly

The recommended fix addresses both issues by:
1. Rejecting 0 during configuration validation
2. Optionally enforcing a maximum reasonable limit (e.g., 20,000) aligned with storage layer limits

This ensures consistent pagination behavior across all API endpoints and prevents both the zero-limit DoS and resource exhaustion attacks.

### Citations

**File:** config/src/config/api_config.rs (L163-200)
```rust
impl ConfigSanitizer for ApiConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let api_config = &node_config.api;

        // If the API is disabled, we don't need to do anything
        if !api_config.enabled {
            return Ok(());
        }

        // Verify that failpoints are not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
        }

        // Validate basic runtime properties
        if api_config.max_runtime_workers.is_none() && api_config.runtime_worker_multiplier == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "runtime_worker_multiplier must be greater than 0!".into(),
            ));
        }

        // Sanitize the gas estimation config
        GasEstimationConfig::sanitize(node_config, node_type, chain_id)?;

        Ok(())
    }
}
```

**File:** api/src/page.rs (L74-97)
```rust
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

**File:** api/src/context.rs (L470-558)
```rust
    pub fn get_resources_by_pagination(
        &self,
        address: AccountAddress,
        prev_state_key: Option<&StateKey>,
        version: u64,
        limit: u64,
    ) -> Result<(Vec<(StructTag, Vec<u8>)>, Option<StateKey>)> {
        let account_iter = if !db_sharding_enabled(&self.node_config) {
            Box::new(
                self.db
                    .get_prefixed_state_value_iterator(
                        &StateKeyPrefix::from(address),
                        prev_state_key,
                        version,
                    )?
                    .map(|item| item.map_err(|err| anyhow!(err.to_string()))),
            )
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(
                    &StateKeyPrefix::from(address),
                    prev_state_key,
                    version,
                )?
        };
        // TODO: Consider rewriting this to consider resource groups:
        // * If a resource group is found, expand
        // * Return Option<Result<(PathType, StructTag, Vec<u8>)>>
        // * Count resources and only include a resource group if it can completely fit
        // * Get next_key as the first struct_tag not included
        let mut resource_iter = account_iter
            .filter_map(|res| match res {
                Ok((k, v)) => match k.inner() {
                    StateKeyInner::AccessPath(AccessPath { address: _, path }) => {
                        match Path::try_from(path.as_slice()) {
                            Ok(Path::Resource(struct_tag)) => {
                                Some(Ok((struct_tag, v.bytes().to_vec())))
                            }
                            // TODO: Consider expanding to Path::Resource
                            Ok(Path::ResourceGroup(struct_tag)) => {
                                Some(Ok((struct_tag, v.bytes().to_vec())))
                            }
                            Ok(Path::Code(_)) => None,
                            Err(e) => Some(Err(anyhow::Error::from(e))),
                        }
                    }
                    _ => {
                        error!("storage prefix scan return inconsistent key ({:?}) with expected key prefix ({:?}).", k, StateKeyPrefix::from(address));
                        Some(Err(format_err!( "storage prefix scan return inconsistent key ({:?})", k )))
                    }
                },
                Err(e) => Some(Err(e)),
            })
            .take(limit as usize + 1);
        let kvs = resource_iter
            .by_ref()
            .take(limit as usize)
            .collect::<Result<Vec<(StructTag, Vec<u8>)>>>()?;

        // We should be able to do an unwrap here, otherwise the above db read would fail.
        let state_view = self.state_view_at_version(version)?;
        let converter = state_view.as_converter(self.db.clone(), self.indexer_reader.clone());

        // Extract resources from resource groups and flatten into all resources
        let kvs = kvs
            .into_iter()
            .map(|(tag, value)| {
                if converter.is_resource_group(&tag) {
                    // An error here means a storage invariant has been violated
                    bcs::from_bytes::<ResourceGroup>(&value)
                        .map(|map| map.into_iter().collect::<Vec<_>>())
                        .map_err(|e| e.into())
                } else {
                    Ok(vec![(tag, value)])
                }
            })
            .collect::<Result<Vec<Vec<(StructTag, Vec<u8>)>>>>()?
            .into_iter()
            .flatten()
            .collect();

        let next_key = if let Some((struct_tag, _v)) = resource_iter.next().transpose()? {
            Some(StateKey::resource(&address, &struct_tag)?)
        } else {
            None
        };
        Ok((kvs, next_key))
```

**File:** api/src/accounts.rs (L448-471)
```rust
    pub fn resources(self, accept_type: &AcceptType) -> BasicResultWith404<Vec<MoveResource>> {
        let max_account_resources_page_size = self.context.max_account_resources_page_size();
        let (resources, next_state_key) = self
            .context
            .get_resources_by_pagination(
                self.address.into(),
                self.start.as_ref(),
                self.ledger_version,
                // Just use the max as the default
                determine_limit(
                    self.limit,
                    max_account_resources_page_size,
                    max_account_resources_page_size,
                    &self.latest_ledger_info,
                )? as u64,
            )
            .context("Failed to get resources from storage")
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &self.latest_ledger_info,
                )
            })?;
```
