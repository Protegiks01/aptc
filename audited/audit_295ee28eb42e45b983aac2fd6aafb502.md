# Audit Report

## Title
Unbounded BCS Deserialization of ObjectGroupResource in Balance API Enables API-Level DoS

## Summary
The `Account::balance()` function deserializes `ObjectGroupResource` from storage using `bcs::from_bytes()` without any size or depth limits, unlike other API endpoints that use `bcs::from_bytes_with_limit()`. An attacker can create a malicious fungible asset with a bloated ObjectGroup (up to 1MB with thousands of entries) and trigger excessive CPU and memory consumption during balance queries, causing API server degradation or denial of service.

## Finding Description
The vulnerability exists in the balance retrieval logic for fungible assets. [1](#0-0) 

When querying a balance, the API retrieves the `ObjectGroupResource` for the primary fungible store and deserializes it without limits. The `ObjectGroupResource` structure contains a `BTreeMap<StructTag, Vec<u8>>` that can store multiple resources. [2](#0-1) 

While storage writes are limited to 1MB per operation during transaction execution [3](#0-2) , there is no corresponding limit during API-layer deserialization. In contrast, the transaction submission API uses `bcs::from_bytes_with_limit()` with a depth limit of 16. [4](#0-3) 

**Attack Vector:**
1. Attacker deploys a Move module defining many resource types marked as `#[resource_group_member(group = aptos_framework::object::ObjectGroup)]`
2. Attacker creates a malicious fungible asset and populates its primary store's ObjectGroup with thousands of small resources (staying within the 1MB write limit)
3. When users or monitoring systems query the balance for this asset, the API must deserialize the entire 1MB ObjectGroup
4. BCS deserialization of a BTreeMap with thousands of entries consumes significant CPU (for map operations and tree rebalancing) and allocates temporary memory
5. Multiple concurrent queries amplify the impact, potentially exhausting API server thread pool resources

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria ("API crashes" / "State inconsistencies requiring intervention"). The impact includes:

- **API Server DoS**: Repeated queries to malicious asset balances cause CPU exhaustion and memory pressure
- **Performance Degradation**: Legitimate API requests are delayed or timeout due to resource contention
- **Service Availability**: In extreme cases, the API server may become unresponsive or crash

The impact is limited to the API layer and does not affect consensus, validator operations, or fund security. However, it represents a clear availability attack against a critical user-facing service.

## Likelihood Explanation
**Likelihood: Medium**

The attack requires:
- Deploying a Move module (publicly available to all users)
- Creating a fungible asset (permissionless operation)
- Paying gas to populate the ObjectGroup over multiple transactions
- Triggering balance API queries (can be automated)

The cost to the attacker is relatively low (one-time gas costs), while the cost per victim query is high. The attack is feasible and does not require any privileged access or validator collusion.

## Recommendation
Apply deserialization size or depth limits to the ObjectGroup deserialization in the balance API, consistent with other API endpoints.

**Recommended Fix:**
Replace the unbounded `bcs::from_bytes()` call with `bcs::from_bytes_with_limit()`:

```rust
// In api/src/accounts.rs, line 378
// Before:
if let Ok(object_group) = bcs::from_bytes::<ObjectGroupResource>(&data_blob) {

// After:
const MAX_OBJECT_GROUP_DEPTH: usize = 16;  // Consistent with transactions API
if let Ok(object_group) = bcs::from_bytes_with_limit::<ObjectGroupResource>(
    &data_blob, 
    MAX_OBJECT_GROUP_DEPTH
) {
```

This prevents maliciously deep or complex structures from causing excessive deserialization costs while maintaining compatibility with legitimate ObjectGroups.

## Proof of Concept

**Move Module (malicious_asset.move):**
```move
module attacker::malicious_asset {
    use aptos_framework::object::{Self, Object, ObjectGroup};
    use aptos_framework::fungible_asset;
    
    // Define many resource types as ObjectGroup members
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Payload1 has key { data: vector<u8> }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Payload2 has key { data: vector<u8> }
    
    // ... repeat for Payload3 through Payload1000 ...
    
    public entry fun create_bloated_asset(creator: &signer) {
        // Create fungible asset with metadata
        let metadata = fungible_asset::create_metadata(...);
        
        // Get primary store address
        let store_addr = /* derive primary store address */;
        
        // Populate with many resources
        move_to(&create_signer(store_addr), Payload1 { data: vector::empty() });
        move_to(&create_signer(store_addr), Payload2 { data: vector::empty() });
        // ... repeat for all payloads ...
    }
}
```

**Rust Test (api_dos_test.rs):**
```rust
#[tokio::test]
async fn test_objectgroup_deserialization_dos() {
    // Setup: Deploy malicious module and create bloated asset
    let mut harness = TestHarness::new();
    let attacker = harness.new_account();
    
    // Deploy module with 1000 resource types
    harness.publish_module(&attacker, malicious_module_bytecode());
    
    // Create asset and populate ObjectGroup (up to 1MB)
    harness.run_entry_function(&attacker, "create_bloated_asset", vec![]);
    
    // Measure API response time for balance query
    let start = Instant::now();
    let result = harness.api_get_balance(&attacker.address(), &malicious_asset_type);
    let duration = start.elapsed();
    
    // Verify excessive time spent (should be >100ms vs normal <10ms)
    assert!(duration > Duration::from_millis(100));
    
    // Verify multiple concurrent requests cause thread pool exhaustion
    let handles: Vec<_> = (0..20).map(|_| {
        tokio::spawn(async {
            harness.api_get_balance(&attacker.address(), &malicious_asset_type)
        })
    }).collect();
    
    // Some requests should timeout or fail
    let results = futures::join_all(handles).await;
    assert!(results.iter().any(|r| r.is_err()));
}
```

**Notes**
- This vulnerability is specific to the balance API endpoint and does not affect transaction execution or consensus
- The 1MB storage limit prevents unbounded growth but still allows creation of structures with thousands of entries that are expensive to deserialize
- Other API endpoints properly use `bcs::from_bytes_with_limit()` suggesting this is an oversight rather than intentional design
- The fix is straightforward and maintains backward compatibility with legitimate ObjectGroups

### Citations

**File:** api/src/accounts.rs (L370-378)
```rust
        if let Some(data_blob) = self.context.get_state_value_poem(
            &StateKey::resource_group(
                &primary_fungible_store_address,
                &ObjectGroupResource::struct_tag(),
            ),
            self.ledger_version,
            &self.latest_ledger_info,
        )? {
            if let Ok(object_group) = bcs::from_bytes::<ObjectGroupResource>(&data_blob) {
```

**File:** types/src/account_config/resources/object.rs (L18-22)
```rust
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ObjectGroupResource {
    pub group: BTreeMap<StructTag, Vec<u8>>,
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-156)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
```

**File:** api/src/transactions.rs (L851-851)
```rust
    const MAX_SIGNED_TRANSACTION_DEPTH: usize = 16;
```
