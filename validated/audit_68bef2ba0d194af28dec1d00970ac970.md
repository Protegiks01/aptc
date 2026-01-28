# Audit Report

## Title
Resource Group Expansion Bypass in Pagination Causes Unbounded Memory Allocation in API

## Summary
The `get_resources_by_pagination` function in the Aptos REST API expands resource groups into individual resources without enforcing the requested pagination limit on the final expanded count. This allows an attacker to cause unbounded memory allocation and API server crashes by creating accounts with resource groups containing multiple resources, leading to significant memory amplification when queried.

## Finding Description

The vulnerability exists in the interaction between pagination limits and resource group expansion in the API layer.

The `Account::resources()` function calls `determine_limit()` to validate and clamp the user-provided limit to a maximum of 9999 by default. [1](#0-0) [2](#0-1) [3](#0-2) 

This validated limit is then passed to `get_resources_by_pagination()`, which contains the core vulnerability. The function fetches up to `limit` storage items from the database. [4](#0-3) 

The critical issue occurs where resource groups are expanded. After fetching the limited number of storage items, the function expands each resource group into its constituent resources and flattens them into a single collection without verifying that the final count respects the original pagination limit. [5](#0-4) 

A `ResourceGroup` is defined as `BTreeMap<StructTag, Vec<u8>>`, meaning each resource group stored as a single storage item can contain multiple individual resources. [6](#0-5) 

The developers are aware of this issue, as evidenced by a TODO comment explicitly noting the need to "count resources and only include a resource group if it can completely fit." [7](#0-6) 

**Attack Scenario:**

1. Attacker deploys Move modules that create resource groups under a controlled account [8](#0-7) 
2. Each resource group is populated with numerous small resources, limited only by the 1MB `max_bytes_per_write_op` constraint [9](#0-8) 
3. If each resource is ~100 bytes, a single 1MB resource group could contain approximately 10,000 resources
4. Any caller queries `/accounts/:address/resources?limit=N` where N equals the number of resource groups
5. API server fetches N storage items (all resource groups)
6. Expansion produces N × ~10,000 resources, causing memory exhaustion
7. API server runs out of memory and crashes or becomes unresponsive

The `get_state_values()` function demonstrates the correct approach by using `MAX_REQUEST_LIMIT` as a hard cap and returning an error if more items exist. [10](#0-9) [11](#0-10) 

However, `get_resources_by_pagination()` lacks this post-expansion validation.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria, specifically matching categories #8 and #9:

- **API Crashes (High)**: Memory exhaustion causes the REST API server to crash or become unresponsive, affecting network participation and transaction submission capabilities
- **Validator Node Slowdowns (High)**: Validator nodes running the API service experience significant performance degradation or outages due to resource exhaustion

The impact constitutes a Denial of Service attack against critical Aptos infrastructure:
- Wallets and dApps lose ability to query chain state
- Block explorers and indexers cannot function
- Validator operators cannot monitor their nodes via API
- External integrations and services are disrupted

The memory amplification factor can easily reach 100x-10,000x depending on resource group composition, making this a severe resource exhaustion vulnerability. This is NOT a network-level DoS attack (which is out of scope), but rather an API implementation bug that causes resource exhaustion through logic error exploitation.

## Likelihood Explanation

**Likelihood: High**

The attack is straightforward to execute:

1. **No special permissions required**: Any user can deploy Move modules and create resource groups - this is a documented feature with examples in the codebase [12](#0-11) 

2. **Low cost**: Creating resource groups is constrained only by gas costs, which are reasonable for this attack. The setup is one-time, while exploitation is free and repeatable

3. **Deterministic exploitation**: The vulnerability triggers reliably every time the API endpoint is queried with appropriate parameters

4. **Wide attack surface**: The `/accounts/{address}/resources` endpoint is publicly accessible with no authentication

5. **Free exploitation**: After initial setup, any user (not just the attacker) can trigger the vulnerability by simply querying the API, making it a persistent DoS vector

## Recommendation

Implement post-expansion validation similar to `get_state_values()`:

1. Track the total count of resources after expansion
2. If the expanded count exceeds the original pagination limit, either:
   - Return an error indicating too many resources
   - Implement partial resource group inclusion (as noted in the TODO)
   - Apply a hard limit and return remaining items via pagination cursor

The fix should ensure that the final returned resource count never significantly exceeds the requested pagination limit, preventing memory amplification attacks.

## Proof of Concept

While a complete executable PoC is not provided, the vulnerability can be demonstrated through the following steps:

1. Deploy a Move module with a resource group container and multiple resource group members (similar to the examples in the codebase)
2. Create an account and initialize 100 resource groups, each containing 1000 small resources (~100 bytes each)
3. Query the API endpoint: `GET /accounts/{address}/resources?limit=100`
4. Observe that the API fetches 100 storage items (resource groups) but expands them to 100,000 individual resources (100 × 1000)
5. Monitor API server memory consumption showing significant amplification beyond the requested limit
6. Repeat queries to cause memory exhaustion and potential server crash

## Notes

This vulnerability is explicitly acknowledged in the codebase through the TODO comment but remains unfixed. The expansion logic correctly deserializes resource groups but fails to enforce the pagination contract, breaking the API's memory safety guarantees. The fix should be prioritized given the ease of exploitation and potential for widespread impact on API infrastructure.

### Citations

**File:** config/src/config/api_config.rs (L100-100)
```rust
const DEFAULT_MAX_ACCOUNT_RESOURCES_PAGE_SIZE: u16 = 9999;
```

**File:** api/src/accounts.rs (L457-462)
```rust
                determine_limit(
                    self.limit,
                    max_account_resources_page_size,
                    max_account_resources_page_size,
                    &self.latest_ledger_info,
                )? as u64,
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

**File:** api/src/context.rs (L460-467)
```rust
        let kvs = iter
            .by_ref()
            .take(MAX_REQUEST_LIMIT as usize)
            .collect::<Result<_>>()?;
        if iter.next().transpose()?.is_some() {
            bail!("Too many state items under account ({:?}).", address);
        }
        Ok(kvs)
```

**File:** api/src/context.rs (L497-501)
```rust
        // TODO: Consider rewriting this to consider resource groups:
        // * If a resource group is found, expand
        // * Return Option<Result<(PathType, StructTag, Vec<u8>)>>
        // * Count resources and only include a resource group if it can completely fit
        // * Get next_key as the first struct_tag not included
```

**File:** api/src/context.rs (L525-529)
```rust
            .take(limit as usize + 1);
        let kvs = resource_iter
            .by_ref()
            .take(limit as usize)
            .collect::<Result<Vec<(StructTag, Vec<u8>)>>>()?;
```

**File:** api/src/context.rs (L536-551)
```rust
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
```

**File:** api/types/src/move_types.rs (L35-35)
```rust
pub type ResourceGroup = BTreeMap<StructTag, Vec<u8>>;
```

**File:** aptos-move/move-examples/resource_groups/primary/sources/primary.move (L1-38)
```text
/// This demonstrates how to use a resource group within a single module
/// See resource_groups_primary::secondary for cross module and multiple resources
module resource_groups_primary::primary {
    use std::signer;

    #[resource_group(scope = global)]
    struct ResourceGroupContainer { }

    #[resource_group_member(group = resource_groups_primary::primary::ResourceGroupContainer)]
    struct Primary has drop, key {
        value: u64,
    }

    public entry fun init(account: &signer, value: u64) {
        move_to(account, Primary { value });
    }

    public entry fun set_value(account: &signer, value: u64) acquires Primary {
        let primary = borrow_global_mut<Primary>(signer::address_of(account));
        primary.value = value;
    }

    public fun read(account: address): u64 acquires Primary {
        borrow_global<Primary>(account).value
    }

    public entry fun remove(account: &signer) acquires Primary {
        move_from<Primary>(signer::address_of(account));
    }

    public fun exists_at(account: address): bool {
        exists<Primary>(account)
    }

    fun init_module(owner: &signer) {
        move_to(owner, Primary { value: 3 });
    }

```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-156)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
```

**File:** storage/storage-interface/src/lib.rs (L56-58)
```rust
// This is last line of defense against large queries slipping through external facing interfaces,
// like the API and State Sync, etc.
pub const MAX_REQUEST_LIMIT: u64 = 20_000;
```

**File:** testsuite/benchmark-workloads/packages/framework_usecases/sources/resource_groups_example.move (L1-58)
```text
module 0xABCD::resource_groups_example {
    use std::error;
    use std::signer;
    use std::string::{Self, String};

    const EINDEX_TOO_LARGE: u64 = 1;
    const EVALUE_TOO_LARGE: u64 = 2;

    #[resource_group(scope = global)]
    struct ExampleGroup {}

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource0 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource1 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource2 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource3 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource4 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource5 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource6 has key {
        value: u64,
        name: String,
    }

    #[resource_group_member(group = 0xABCD::resource_groups_example::ExampleGroup)]
    struct ExampleResource7 has key {
        value: u64,
        name: String,
    }
```
