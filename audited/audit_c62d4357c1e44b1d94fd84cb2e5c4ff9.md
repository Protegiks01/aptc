# Audit Report

## Title
Resource Account Address Linkability via Public Container Resource Exposure

## Summary
The `resource_account` module stores a publicly readable `Container` resource at the source account's address that maps all created resource account addresses to their `SignerCapability` objects. This allows any observer to query the Aptos REST API and enumerate all resource accounts created by a given source address, compromising user privacy and enabling cross-account linkability analysis.

## Finding Description

When a user creates resource accounts using the `resource_account::create_resource_account()` function, the framework stores a `Container` resource at the **source account's address** (not the resource account's address). This Container contains a `SimpleMap<address, account::SignerCapability>` that maps each resource account address to its signer capability. [1](#0-0) 

The Container is populated during resource account creation: [2](#0-1) 

While the Move module restricts direct access to the Container through module functions, the Aptos REST API provides a public endpoint `/accounts/:address/resource/:resource_type` that allows **anyone** to read **any** resource from **any** account without authentication: [3](#0-2) 

The API directly queries the database without VM-level access control checks: [4](#0-3) 

**Attack Path:**
1. Attacker identifies a target source address (e.g., a known user or protocol)
2. Attacker queries: `GET /accounts/{source_address}/resource/0x1::resource_account::Container`
3. API returns the full Container resource including the `SimpleMap` with all resource account addresses as keys
4. Attacker extracts all resource account addresses from the `data` field of the SimpleMap
5. Attacker can now link all these resource accounts to the same source address

The `SimpleMap` structure exposes its internal data: [5](#0-4) 

## Impact Explanation

This is a **Low Severity** privacy vulnerability per Aptos bug bounty criteria (Minor information leaks, up to $1,000). While it does not compromise funds, consensus, or availability, it breaks privacy expectations:

- Users creating multiple resource accounts for privacy/anonymity purposes can be fully deanonymized
- Protocol patterns can be analyzed (e.g., identifying all liquidity pools created by a DEX)
- Cross-account activity correlation becomes trivial for observers
- Breaks unlinkability assumptions for resource accounts used in voting, DeFi positions, or other privacy-sensitive applications

## Likelihood Explanation

**Likelihood: Very High**

- The exploit requires zero special permissions or resources
- The API endpoint is publicly accessible and documented
- The attack is passive observation requiring only HTTP GET requests
- No transaction submission or gas costs required
- The Container resource is created by default when any resource account is created using the standard framework functions

## Recommendation

**Option 1: Do not store Container at source address (Breaking Change)**
Store the Container at a derived address that cannot be linked to the source account, or use encrypted storage where keys are only available to the source account.

**Option 2: Add access control to API (Recommended)**
Implement resource-level read access control in the API layer that respects Move module privacy. Resources with only `key` ability and no public read functions should require authentication from the owning account.

**Option 3: Documentation Update (Minimal)**
If this is intended behavior, clearly document that all resource accounts created via the standard framework are publicly linkable to their source address, so users can make informed decisions about privacy-sensitive operations.

## Proof of Concept

```rust
// Proof of Concept using Aptos REST Client
use aptos_rest_client::Client;
use aptos_api_types::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Container {
    store: SimpleMapData,
}

#[derive(Debug, Deserialize, Serialize)]
struct SimpleMapData {
    data: Vec<Element>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Element {
    key: Address,
    value: SignerCapability,
}

#[derive(Debug, Deserialize, Serialize)]
struct SignerCapability {
    account: Address,
}

#[tokio::main]
async fn main() {
    let client = Client::new(url::Url::parse("https://fullnode.mainnet.aptoslabs.com").unwrap());
    
    // Target any source address that created resource accounts
    let source_address = Address::from_hex_literal("0x1234...").unwrap();
    
    // Query the Container resource
    let container: Container = client
        .get_account_resource(
            source_address,
            "0x1::resource_account::Container"
        )
        .await
        .unwrap()
        .into_inner();
    
    // Extract all resource account addresses
    println!("Resource accounts created by {:?}:", source_address);
    for element in container.store.data {
        println!("  - Resource account: {:?}", element.key);
    }
    
    // All resource accounts are now linked to the source address
}
```

**Notes:**
- This vulnerability is by design in the current implementation
- The `Container` resource is intentionally stored at the source address for capability management
- The privacy leak is a consequence of making all resources publicly queryable via the REST API
- Users expecting privacy when creating resource accounts should be aware of this limitation

### Citations

**File:** aptos-move/framework/aptos-framework/sources/resource_account.move (L79-81)
```text
    struct Container has key {
        store: SimpleMap<address, account::SignerCapability>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/resource_account.move (L147-154)
```text
        let origin_addr = signer::address_of(origin);
        if (!exists<Container>(origin_addr)) {
            move_to(origin, Container { store: simple_map::create() })
        };

        let container = borrow_global_mut<Container>(origin_addr);
        let resource_addr = signer::address_of(&resource);
        simple_map::add(&mut container.store, resource_addr, resource_signer_cap);
```

**File:** api/src/state.rs (L38-84)
```rust
    /// Get account resource
    ///
    /// Retrieves an individual resource from a given account and at a specific ledger version. If the
    /// ledger version is not specified in the request, the latest ledger version is used.
    ///
    /// The Aptos nodes prune account state history, via a configurable time window.
    /// If the requested ledger version has been pruned, the server responds with a 410.
    #[oai(
        path = "/accounts/:address/resource/:resource_type",
        method = "get",
        operation_id = "get_account_resource",
        tag = "ApiTags::Accounts"
    )]
    async fn get_account_resource(
        &self,
        accept_type: AcceptType,
        /// Address of account with or without a `0x` prefix
        address: Path<Address>,
        /// Name of struct to retrieve e.g. `0x1::account::Account`
        resource_type: Path<MoveStructTag>,
        /// Ledger version to get state of account
        ///
        /// If not provided, it will be the latest version
        ledger_version: Query<Option<U64>>,
    ) -> BasicResultWith404<MoveResource> {
        resource_type
            .0
            .verify(0)
            .context("'resource_type' invalid")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;
        fail_point_poem("endpoint_get_account_resource")?;
        self.context
            .check_api_output_enabled("Get account resource", &accept_type)?;

        let api = self.clone();
        api_spawn_blocking(move || {
            api.resource(
                &accept_type,
                address.0,
                resource_type.0,
                ledger_version.0.map(|inner| inner.0),
            )
        })
        .await
    }
```

**File:** api/src/state.rs (L274-327)
```rust
    fn resource(
        &self,
        accept_type: &AcceptType,
        address: Address,
        resource_type: MoveStructTag,
        ledger_version: Option<u64>,
    ) -> BasicResultWith404<MoveResource> {
        let tag: StructTag = (&resource_type)
            .try_into()
            .context("Failed to parse given resource type")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;

        let (ledger_info, ledger_version, state_view) = self.context.state_view(ledger_version)?;
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

        match accept_type {
            AcceptType::Json => {
                let resource = state_view
                    .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
                    .try_into_resource(&tag, &bytes)
                    .context("Failed to deserialize resource data retrieved from DB")
                    .map_err(|err| {
                        BasicErrorWith404::internal_with_code(
                            err,
                            AptosErrorCode::InternalError,
                            &ledger_info,
                        )
                    })?;

                BasicResponse::try_from_json((resource, &ledger_info, BasicResponseStatus::Ok))
            },
            AcceptType::Bcs => BasicResponse::try_from_encoded((
                bytes.to_vec(),
                &ledger_info,
                BasicResponseStatus::Ok,
            )),
        }
```

**File:** aptos-move/framework/aptos-stdlib/sources/simple_map.move (L22-29)
```text
    struct SimpleMap<Key, Value> has copy, drop, store {
        data: vector<Element<Key, Value>>,
    }

    struct Element<Key, Value> has copy, drop, store {
        key: Key,
        value: Value,
    }
```
