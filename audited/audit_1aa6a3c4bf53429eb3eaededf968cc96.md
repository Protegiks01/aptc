# Audit Report

## Title
Function Name Collision Vulnerability in Package Cache Invalidation Logic

## Summary
The `get_and_filter_committed_transactions` function in the REST debugger interface checks only the function name `"publish_package_txn"` without verifying the module address, allowing any user-deployed module to trigger cache invalidation logic intended exclusively for the framework's `0x1::code::publish_package_txn` function.

## Finding Description

The vulnerability exists in the transaction filtering logic that identifies package publishing transactions. [1](#0-0) 

The code checks only the function name string without verifying that the function belongs to the official `0x1::code` module. The legitimate `publish_package_txn` function is defined in the Aptos Framework. [2](#0-1) 

**Attack Propagation**:
1. Attacker deploys a malicious module at their address (e.g., `0xAttacker::malicious`) containing a public entry function named `publish_package_txn`
2. Attacker submits transactions calling `0xAttacker::malicious::publish_package_txn`
3. The debugger interface's filtering logic incorrectly identifies this as a package publishing transaction
4. Cache invalidation logic executes, clearing package metadata for the attacker's address
5. Repeated calls force redundant REST API queries and cache rebuilding

## Impact Explanation

This vulnerability affects the `AptosValidatorInterface` implementation used by critical debugging and analysis infrastructure. [3](#0-2) 

**Impact Classification: Low Severity**

While exploitable, this vulnerability does NOT meet Medium/High/Critical severity criteria because:

- **No Consensus Impact**: Does not affect AptosBFT, block commitment, or validator operations
- **No State Impact**: Does not manipulate blockchain state or Merkle trees  
- **No Funds Impact**: Cannot cause loss, theft, or minting of assets
- **Limited Scope**: Only affects debugging/analysis tools, not production blockchain operations

The impact is confined to:
- Performance degradation of debugging tools through cache thrashing
- Increased load on REST API endpoints
- Potential DoS of analysis infrastructure (non-critical)

This does not break any of the 10 critical invariants (deterministic execution, consensus safety, state consistency, etc.) and affects only auxiliary tooling, not the core blockchain protocol.

## Likelihood Explanation

**Likelihood: High** - The attack is trivial to execute:
- Any user can deploy Move modules with arbitrary function names
- No special permissions or validator access required
- Attack can be automated and repeated indefinitely
- Deployment and execution costs only standard transaction gas fees

However, the **exploitability** is limited because the affected component is not security-critical to blockchain operations.

## Recommendation

Add module address verification to ensure only the official framework function triggers cache invalidation:

```rust
if entry_function.function().as_str() == "publish_package_txn" 
    && entry_function.module().address() == &AccountAddress::ONE
    && entry_function.module().name().as_str() == "code" {
    if filter_condition.skip_publish_txns {
        continue;
    }
    package_cache.retain(|k, _| k.address != signed_trans.sender());
}
```

This ensures only `0x1::code::publish_package_txn` triggers the intended cache invalidation behavior.

## Proof of Concept

```move
module attacker::malicious {
    public entry fun publish_package_txn(
        _owner: &signer, 
        _metadata: vector<u8>, 
        _code: vector<vector<u8>>
    ) {
        // Malicious or no-op implementation
        // When called, triggers cache invalidation in debugger interface
    }
}
```

Deploy this module and repeatedly call `attacker::malicious::publish_package_txn` to trigger cache invalidation in the REST debugger interface, causing performance degradation of debugging tools.

---

## Notes

After thorough validation against the criteria, this finding represents a **logic error in auxiliary tooling** rather than a critical blockchain security vulnerability. While technically exploitable, it fails to meet the severity threshold because:

1. **No Critical Invariant Violation**: Does not break deterministic execution, consensus safety, state consistency, or any of the 10 documented critical invariants
2. **Non-Critical Component**: Affects `AptosValidatorInterface` (debugging utility), not consensus/execution/state layers
3. **Limited Security Impact**: Cannot compromise funds, state integrity, validator operations, or network availability

The bug bounty program's Medium severity criteria specify "state inconsistencies requiring intervention" - this does not cause blockchain state inconsistencies, only debugger cache inconsistencies in off-chain tooling.

**Severity Assessment**: This qualifies as **Low Severity** ("Non-critical implementation bugs") rather than Medium, as it affects debugging infrastructure without compromising core blockchain security guarantees.

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

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
    }
```

**File:** aptos-move/aptos-debugger/src/aptos_debugger.rs (L35-52)
```rust
pub struct AptosDebugger {
    debugger: Arc<dyn AptosValidatorInterface + Send>,
}

impl AptosDebugger {
    pub fn new(debugger: Arc<dyn AptosValidatorInterface + Send>) -> Self {
        Self { debugger }
    }

    pub fn rest_client(rest_client: Client) -> anyhow::Result<Self> {
        Ok(Self::new(Arc::new(RestDebuggerInterface::new(rest_client))))
    }

    pub fn db<P: AsRef<Path> + Clone>(db_root_path: P) -> anyhow::Result<Self> {
        Ok(Self::new(Arc::new(DBDebuggerInterface::open(
            db_root_path,
        )?)))
    }
```
