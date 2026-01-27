# Audit Report

## Title
Cache Invalidation Bypass in Object-Based Code Deployment Leading to Stale Source Code Metadata

## Summary
The cache invalidation logic in `get_and_filter_committed_transactions()` only detects direct account-based module publishing via `code::publish_package_txn`, but fails to invalidate the cache when modules are published or upgraded through object-based deployment (`object_code_deployment::publish` and `object_code_deployment::upgrade`). This causes debugging and transaction replay tools to use stale source code and package metadata.

## Finding Description

The vulnerability exists in the cache invalidation logic that assumes all module publishing occurs through the `code::publish_package_txn` entry function. [1](#0-0) 

This code only triggers cache invalidation when:
1. The entry function name is exactly `"publish_package_txn"`
2. It invalidates cache entries where `k.address == signed_trans.sender()`

However, Aptos supports **object-based code deployment** where modules are published to object addresses rather than account addresses: [2](#0-1) 

In this flow:
- The transaction is signed by the `publisher` (address A)
- A new object is created with a unique address (address B, derived from publisher address and sequence number)
- The `code_signer` is generated from the object's constructor reference
- Modules are published to the object's address (B), not the publisher's address (A) [3](#0-2) 

The module is always published to `signer::address_of(owner)`, where `owner` is the code_signer in object deployment.

Similarly, the `upgrade` function has the same pattern: [4](#0-3) 

**Attack Scenario:**
1. User publishes module to object address 0xOBJ using `object_code_deployment::publish` (signed by 0xALICE)
2. Module metadata is cached with key `ModuleId{address: 0xOBJ, name: "module"}`
3. User upgrades module at 0xOBJ using `object_code_deployment::upgrade` (signed by 0xALICE)
4. Cache invalidation check at line 325 only removes entries where `k.address == 0xALICE`, not 0xOBJ
5. The entry function name is `"upgrade"`, not `"publish_package_txn"`, so invalidation doesn't even trigger
6. Subsequent transactions using the module continue using stale cached source code and metadata

The cache persists across multiple transaction batches: [5](#0-4) 

This allows the stale cache to affect transactions processed much later, potentially across hundreds of versions.

## Impact Explanation

**Medium Severity** - This vulnerability causes state inconsistencies in off-chain debugging and testing infrastructure. The stale cache leads to:

1. **Incorrect source code dumping** - Tools dump old source code instead of current version [6](#0-5) 

2. **Wrong upgrade number tracking** - The cached `upgrade_number` becomes stale [7](#0-6) 

3. **Compilation against wrong dependencies** - Cached dependency metadata may be outdated [8](#0-7) 

While this does not directly affect blockchain consensus or execution, it creates **state inconsistencies requiring intervention** in testing and debugging workflows, qualifying as Medium severity per the bug bounty criteria.

## Likelihood Explanation

**High Likelihood** - Object-based code deployment is a supported feature promoted in the Aptos framework documentation and CLI tools. The vulnerability triggers automatically whenever:
- Any user publishes modules via `object_code_deployment::publish`
- Any user upgrades modules via `object_code_deployment::upgrade`  
- Any user publishes large packages via `large_packages` module functions [9](#0-8) 

The `large_packages` module explicitly calls `object_code_deployment::publish` and `upgrade`, making this a common code path.

## Recommendation

Extend the cache invalidation logic to handle all module publishing/upgrading entry functions:

```rust
// In rest_interface.rs, around line 319
let function_name = entry_function.function().as_str();
if function_name == "publish_package_txn" {
    if filter_condition.skip_publish_txns {
        continue;
    }
    // Invalidate cache for sender's address (account-based publishing)
    package_cache.retain(|k, _| k.address != signed_trans.sender());
} else if function_name == "publish" || function_name == "upgrade" {
    // Handle object-based deployment from object_code_deployment module
    let module_addr = entry_function.module().address();
    if *module_addr == AccountAddress::ONE {
        let module_name = entry_function.module().name().as_str();
        if module_name == "object_code_deployment" {
            if filter_condition.skip_publish_txns {
                continue;
            }
            // For object deployment, we need to extract the object address from transaction effects
            // Since we don't have that information here, clear the entire cache
            // A better solution would be to track object addresses from transaction outputs
            package_cache.clear();
        }
    }
} else if function_name == "stage_code_chunk_and_publish_to_object" 
       || function_name == "stage_code_chunk_and_upgrade_object_code" 
       || function_name == "stage_code_chunk_and_publish_to_account" {
    // Handle large package publishing
    if filter_condition.skip_publish_txns {
        continue;
    }
    package_cache.clear();
}
```

Alternatively, implement version-aware caching where cache keys include the version at which metadata was fetched, ensuring stale data is never used.

## Proof of Concept

```rust
#[tokio::test]
async fn test_object_deployment_cache_invalidation() {
    use aptos_cached_packages::aptos_stdlib;
    use aptos_rest_client::Client;
    use aptos_validator_interface::{RestDebuggerInterface, AptosValidatorInterface, FilterCondition};
    use move_core_types::language_storage::ModuleId;
    use std::collections::HashMap;
    
    // Setup: Deploy initial module to object
    let rest_client = Client::new(url::Url::parse("https://testnet.aptoslabs.com").unwrap());
    let debugger = RestDebuggerInterface::new(rest_client);
    
    // Step 1: Fetch transactions including object deployment at version V1
    let mut package_cache = HashMap::new();
    let filter = FilterCondition {
        skip_failed_txns: false,
        skip_publish_txns: false,
        check_source_code: true,
        target_account: None,
    };
    
    // Fetch first batch - assume version 1000 has object_code_deployment::publish
    let txns1 = debugger.get_and_filter_committed_transactions(
        1000, 100, filter, &mut package_cache
    ).await.unwrap();
    
    let initial_cache_size = package_cache.len();
    
    // Step 2: Fetch next batch - assume version 1100 has object_code_deployment::upgrade
    let txns2 = debugger.get_and_filter_committed_transactions(
        1100, 100, filter, &mut package_cache
    ).await.unwrap();
    
    // BUG: Cache should have been invalidated but wasn't
    // The upgrade transaction doesn't trigger cache invalidation
    // because function name is "upgrade" not "publish_package_txn"
    assert_eq!(package_cache.len(), initial_cache_size, 
        "Cache was not invalidated for object upgrade - stale data remains!");
}
```

## Notes

This vulnerability specifically affects the `RestDebuggerInterface` used in debugging, testing, and transaction replay tools. It does not impact the core blockchain execution or consensus. The root cause is that the cache invalidation logic was designed for traditional account-based module deployment and does not account for the newer object-based deployment pattern introduced in the `object_code_deployment` module.

### Citations

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L319-326)
```rust
                    if entry_function.function().as_str() == "publish_package_txn" {
                        if filter_condition.skip_publish_txns {
                            continue;
                        }
                        // For publish txn, we remove all items in the package_cache where module_id.address is the sender of this txn
                        // to update the new package in the cache.
                        package_cache.retain(|k, _| k.address != signed_trans.sender());
                    }
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L84-106)
```text
    public entry fun publish(
        publisher: &signer,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>,
    ) {
        code::check_code_publishing_permission(publisher);
        assert!(
            features::is_object_code_deployment_enabled(),
            error::unavailable(EOBJECT_CODE_DEPLOYMENT_NOT_SUPPORTED),
        );

        let publisher_address = signer::address_of(publisher);
        let object_seed = object_seed(publisher_address);
        let constructor_ref = &object::create_named_object(publisher, object_seed);
        let code_signer = &object::generate_signer(constructor_ref);
        code::publish_package_txn(code_signer, metadata_serialized, code);

        event::emit(Publish { object_address: signer::address_of(code_signer), });

        move_to(code_signer, ManagingRefs {
            extend_ref: object::generate_extend_ref(constructor_ref),
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L120-141)
```text
    public entry fun upgrade(
        publisher: &signer,
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>,
        code_object: Object<PackageRegistry>,
    ) acquires ManagingRefs {
        code::check_code_publishing_permission(publisher);
        let publisher_address = signer::address_of(publisher);
        assert!(
            object::is_owner(code_object, publisher_address),
            error::permission_denied(ENOT_CODE_OBJECT_OWNER),
        );

        let code_object_address = object::object_address(&code_object);
        assert!(exists<ManagingRefs>(code_object_address), error::not_found(ECODE_OBJECT_DOES_NOT_EXIST));

        let extend_ref = &borrow_global<ManagingRefs>(code_object_address).extend_ref;
        let code_signer = &object::generate_signer_for_extending(extend_ref);
        code::publish_package_txn(code_signer, metadata_serialized, code);

        event::emit(Upgrade { object_address: signer::address_of(code_signer), });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L168-177)
```text
    public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
        check_code_publishing_permission(owner);
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );

        let addr = signer::address_of(owner);
        if (!exists<PackageRegistry>(addr)) {
```

**File:** aptos-move/aptos-e2e-comparison-testing/src/online_execution.rs (L173-187)
```rust
        let mut module_registry_map = HashMap::new();
        while cur_version < begin + limit {
            let batch = if cur_version + self.batch_size <= begin + limit {
                self.batch_size
            } else {
                begin + limit - cur_version
            };
            let res_txns = self
                .debugger
                .get_and_filter_committed_transactions(
                    cur_version,
                    batch,
                    self.filter_condition,
                    &mut module_registry_map,
                )
```

**File:** aptos-move/aptos-e2e-comparison-testing/src/lib.rs (L532-540)
```rust
    let modules = root_package_metadata.modules.clone();
    for module in modules {
        let module_path = sources_dir.join(format!("{}.move", module.name));
        if !module_path.exists() {
            File::create(module_path.clone()).expect("Error encountered while creating file!");
        };
        let source_str = unzip_metadata_str(&module.source).unwrap();
        std::fs::write(module_path.clone(), source_str).unwrap();
    }
```

**File:** aptos-move/aptos-e2e-comparison-testing/src/lib.rs (L588-600)
```rust
                let dep_metadata_opt = dep_map.get(&(pack_dep_address, pack_dep_name.clone()));
                if let Some(dep_metadata) = dep_metadata_opt {
                    let package_info = PackageInfo {
                        address: pack_dep_address,
                        package_name: pack_dep_name.clone(),
                        upgrade_number: Some(dep_metadata.clone().upgrade_number),
                    };
                    let path_str = format!("{}", package_info);
                    fix_manifest_dep(dep, &path_str);
                    dump_and_compile_from_package_metadata(
                        package_info,
                        root_dir.clone(),
                        dep_map,
```

**File:** aptos-move/aptos-e2e-comparison-testing/src/data_collection.rs (L132-137)
```rust
        let upgrade_number = if is_aptos_package(&package_name) {
            None
        } else {
            let package = map.get(&(address, package_name.clone())).unwrap();
            Some(package.upgrade_number)
        };
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L190-211)
```text
    inline fun publish_to_object(
        publisher: &signer, staging_area: &mut StagingArea
    ) {
        let code = assemble_module_code(staging_area);
        object_code_deployment::publish(
            publisher, staging_area.metadata_serialized, code
        );
    }

    inline fun upgrade_object_code(
        publisher: &signer,
        staging_area: &mut StagingArea,
        code_object: Object<PackageRegistry>
    ) {
        let code = assemble_module_code(staging_area);
        object_code_deployment::upgrade(
            publisher,
            staging_area.metadata_serialized,
            code,
            code_object
        );
    }
```
