# Audit Report

## Title
Cache Invalidation Bypass in REST Debugger Interface via Object Code Deployment

## Summary
The `get_and_filter_committed_transactions()` function in the REST debugger interface only invalidates the package cache for direct calls to `code::publish_package_txn`, missing all object-based code deployment mechanisms (`object_code_deployment::publish`, `object_code_deployment::upgrade`, and `large_packages` variants). Additionally, even for detected publish transactions, the cache invalidation uses the transaction sender's address instead of the actual module publication address, causing incorrect cache invalidation for object deployments where modules are published to addresses different from the transaction sender. [1](#0-0) 

## Finding Description

The cache invalidation logic contains two critical flaws:

**Flaw 1: Incomplete Function Name Detection**

The code only checks if the entry function name equals the literal string `"publish_package_txn"`, missing multiple other code publishing entry functions:

- `object_code_deployment::publish` - Creates a new object and publishes modules to it
- `object_code_deployment::upgrade` - Upgrades modules in an existing object  
- `large_packages::stage_code_chunk_and_publish_to_object` - Chunked publishing to objects
- `large_packages::stage_code_chunk_and_upgrade_object_code` - Chunked upgrades to objects [2](#0-1) [3](#0-2) 

**Flaw 2: Wrong Address for Cache Invalidation**

The invalidation uses `signed_trans.sender()` (the transaction sender), but for object code deployments, modules are published to the object's address, not the sender's address: [4](#0-3) 

In `object_code_deployment::publish`, the `code_signer` is generated from a newly created object, whose address is derived from the publisher address and sequence number, NOT the publisher's address itself. The cache invalidation would remove entries for the publisher's address while modules are actually published to the object's address.

**Attack Scenario:**

1. Attacker publishes benign module `Benign` to object address `0xOBJECT_ADDR` using `object_code_deployment::publish` (transaction sender is `0xATTACKER`)
2. Security monitoring tools/debuggers cache the source code for `0xOBJECT_ADDR::Benign`
3. Attacker upgrades to malicious module using `object_code_deployment::upgrade`
4. Cache invalidation check fails because function name is "upgrade" not "publish_package_txn"
5. Even if it passed, invalidation would target `0xATTACKER`, not `0xOBJECT_ADDR`
6. Tools continue displaying old benign source code while malicious code executes on-chain
7. Security auditors and monitoring systems are deceived about actual on-chain behavior

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria under "Significant protocol violations" because:

- It compromises the integrity of the validator REST debugging interface, a critical tool for security monitoring
- Security analysis tools, auditors, and monitoring systems rely on this interface to verify on-chain code behavior
- Stale source code display can hide malicious contract upgrades from detection
- The bug systematically affects all object-based deployments, an increasingly common pattern in Aptos
- It breaks the trust model that debugging interfaces accurately reflect on-chain state

While this doesn't directly affect consensus or execution, it violates the protocol's guarantee that validator interfaces provide accurate code inspection capabilities.

## Likelihood Explanation

**Likelihood: High**

- No special attacker capabilities required beyond normal code publishing permissions
- Automatically triggered by any use of object code deployment or large packages (increasingly common in production)
- The `object_code_deployment` module is actively used for modular contract deployments
- No mitigation exists in current codebase
- Wide impact surface as any monitoring tool using this interface is affected

## Recommendation

Implement comprehensive cache invalidation that:

1. **Detect all code publishing functions**, not just `publish_package_txn`:
   - Check for `"publish"` and `"upgrade"` from `object_code_deployment` module
   - Check for `"stage_code_chunk_and_publish_to_object"` and `"stage_code_chunk_and_upgrade_object_code"` from `large_packages` module

2. **Invalidate using the correct address**:
   - For `code::publish_package_txn`: use `signed_trans.sender()` (current behavior, correct)
   - For `object_code_deployment::publish`: extract object address from transaction events or derive it
   - For `object_code_deployment::upgrade`: extract `code_object` address from function arguments
   - For `large_packages` variants: handle based on which underlying function is called

3. **Parse entry function arguments** to extract the actual code object address for object-based deployments, rather than relying solely on transaction sender

## Proof of Concept

```rust
// Reproduction steps:
// 1. Set up REST debugger interface with package cache
// 2. Call object_code_deployment::publish to deploy ModuleV1 to object 0xOBJ
// 3. Call entry function from 0xOBJ::ModuleV1, verify cache is populated
// 4. Call object_code_deployment::upgrade to upgrade to ModuleV2 at 0xOBJ
// 5. Call entry function from 0xOBJ::ModuleV2
// 6. Observe that cache still returns ModuleV1 source code for 0xOBJ
//
// Expected: Cache should be invalidated after step 4
// Actual: Cache retains stale ModuleV1 source code
```

## Notes

The vulnerability specifically affects the REST debugger interface used for transaction analysis and source code inspection. While it doesn't directly compromise on-chain execution or consensus, it systematically undermines security monitoring and auditing capabilities by presenting stale source code to analysis tools. The root cause is the incomplete pattern matching that only recognizes the legacy `publish_package_txn` entry function while missing modern object-based deployment mechanisms introduced in recent Aptos upgrades.

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
