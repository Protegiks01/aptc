# Audit Report

## Title
Unbounded Source Map Storage Enables State Bloat Attacks via Chunked Package Publishing

## Summary
Source maps are stored on-chain in the `PackageRegistry` resource without size validation, and the chunked publishing mechanism (`large_packages` module) allows bypassing the standard 60KB package size limit. An attacker can publish Move packages with arbitrarily large compressed source maps, causing permanent state bloat in AptosDB despite storage fee charges.

## Finding Description

Source maps are debugging metadata that map bytecode offsets to source code locations (file paths, line numbers, function names, variable names). When Move packages are published with the `--with-source-maps` flag, these source maps are serialized, compressed, and stored on-chain in the `ModuleMetadata.source_map` field. [1](#0-0) 

The vulnerability exists because:

1. **No Size Validation on Source Maps**: The `source_map` field is a `vector<u8>` with no maximum size constraint. While the overall package has a 60KB limit, this can be bypassed. [2](#0-1) 

2. **Chunked Publishing Bypasses Limits**: The `large_packages` module allows publishing packages of arbitrary size by staging chunks without validating accumulated metadata size. [3](#0-2) [4](#0-3) 

3. **Permanent On-Chain Storage**: The entire `PackageMetadata` including source maps is stored in the `PackageRegistry` resource, which persists in AptosDB state storage. [5](#0-4) 

**Attack Path:**
1. Attacker creates Move modules with deliberately inflated source maps (using very long identifiers, file paths, or comments that generate large location mappings)
2. Builds package with `--with-source-maps` flag
3. Uses `--chunked-publish` to bypass the 60KB limit
4. Multiple `stage_code_chunk` transactions accumulate metadata in `StagingArea` without size validation
5. Final `stage_code_chunk_and_publish_to_account` stores the complete metadata on-chain
6. Repeats across multiple packages to maximize state bloat

## Impact Explanation

This vulnerability falls under **High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Bloated state increases database size, slowing down state reads, merkle tree operations, and state synchronization
- **Significant protocol violations**: Breaks the "Resource Limits" invariant that all operations must respect storage constraints

While storage fees are charged, an attacker with sufficient funds can permanently bloat the state, degrading network performance for all validators. The attack is particularly insidious because:
- Source maps serve no execution purpose and are purely debugging metadata
- The bloat is permanent and cannot be pruned without a hard fork
- Multiple accounts can be used to amplify the attack
- State sync becomes slower as new nodes must download and verify inflated state

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Code publishing permission (commonly granted to developers)
- Sufficient APT tokens to pay storage fees (the main barrier)
- Technical ability to generate large source maps (trivial)

**Feasibility:**
- The `--chunked-publish` mechanism is documented and supported
- No warnings about source map size implications
- An attacker can create legitimate-looking packages with inflated metadata
- Storage fees provide economic disincentive but don't prevent determined attackers

The attack becomes more likely if storage fees are underpriced relative to the operational impact of state bloat.

## Recommendation

Implement multi-layered protections:

1. **Add Maximum Source Map Size Limit**:
```move
// In code.move, add validation
const EEXCESSIVE_SOURCE_MAP_SIZE: u64 = 0xC;
const MAX_SOURCE_MAP_SIZE_PER_MODULE: u64 = 100_000; // 100KB per module

public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) {
    // Add validation before storing
    vector::for_each_ref(&pack.modules, |module| {
        let module: &ModuleMetadata = module;
        assert!(
            vector::length(&module.source_map) <= MAX_SOURCE_MAP_SIZE_PER_MODULE,
            error::invalid_argument(EEXCESSIVE_SOURCE_MAP_SIZE)
        );
    });
    // ... rest of function
}
```

2. **Add Cumulative Limit in Chunked Publishing**: [6](#0-5) 

Add size tracking to `StagingArea`:
```move
struct StagingArea has key {
    metadata_serialized: vector<u8>,
    code: SmartTable<u64, vector<u8>>,
    last_module_idx: u64,
    accumulated_size: u64  // ADD THIS
}

const MAX_STAGED_METADATA_SIZE: u64 = 1_000_000; // 1MB total
const EMETADATA_SIZE_EXCEEDED: u64 = 3;

// In stage_code_chunk_internal, add:
staging_area.accumulated_size = staging_area.accumulated_size + vector::length(&metadata_chunk);
assert!(
    staging_area.accumulated_size <= MAX_STAGED_METADATA_SIZE,
    error::invalid_argument(EMETADATA_SIZE_EXCEEDED)
);
```

3. **Increase Storage Fees for Metadata**: Charge higher storage fees specifically for source maps to better reflect their low utility vs. storage cost.

4. **Add CLI Warnings**: Warn users when publishing packages with large source maps about state bloat implications.

## Proof of Concept

```move
// Create a Move module with artificially large source map
// File: sources/bloat_attack.move
module 0xBLOATER::state_bloat_attack {
    // Create extremely long function names and variable names to inflate source map
    public entry fun this_is_an_extremely_long_function_name_that_will_create_a_large_source_map_entry_when_compiled_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa() {
        let this_is_an_extremely_long_variable_name_that_will_also_be_recorded_in_the_source_map_with_full_location_information_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb = 1;
        
        // Repeat pattern with variations to maximize source map size
        // (truncated for brevity - in practice, generate thousands of similar declarations)
    }
}
```

**Exploitation Steps:**
```bash
# 1. Build package with source maps
aptos move compile --save-metadata --included-artifacts all

# 2. Publish using chunked mode to bypass size limits  
aptos move publish --chunked-publish

# 3. Verify large source map stored on-chain
aptos account list --account <address>
# Observe PackageRegistry with inflated modules[].source_map fields

# 4. Repeat with multiple packages to amplify bloat
# Each package adds permanent state that all validators must store
```

**Expected Result:** Package successfully published with source maps exceeding 60KB limit, permanently stored in state, increasing AptosDB size and slowing validator operations.

## Notes

The vulnerability violates the "Resource Limits" critical invariant. While storage fees provide economic disincentive, they don't prevent determined attackers from degrading network performance through state bloat. Source maps are optional debugging metadata with no execution impact, making size limits particularly appropriate. The absence of validation in both standard and chunked publishing paths represents a significant oversight in state management controls.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L58-67)
```text
    struct ModuleMetadata has copy, drop, store {
        /// Name of the module.
        name: String,
        /// Source text, gzipped String. Empty if not provided.
        source: vector<u8>,
        /// Source map, in compressed BCS. Empty if not provided.
        source_map: vector<u8>,
        /// For future extensions.
        extension: Option<Any>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L207-214)
```text
        let packages = &mut borrow_global_mut<PackageRegistry>(addr).packages;
        // Update registry
        let policy = pack.upgrade_policy;
        if (index < len) {
            *vector::borrow_mut(packages, index) = pack
        } else {
            vector::push_back(packages, pack)
        };
```

**File:** crates/aptos/src/move_tool/mod.rs (L984-984)
```rust
pub const MAX_PUBLISH_PACKAGE_SIZE: usize = 60_000;
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L60-64)
```text
    struct StagingArea has key {
        metadata_serialized: vector<u8>,
        code: SmartTable<u64, vector<u8>>,
        last_module_idx: u64
    }
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L132-181)
```text
    inline fun stage_code_chunk_internal(
        owner: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ): &mut StagingArea {
        assert!(
            vector::length(&code_indices) == vector::length(&code_chunks),
            error::invalid_argument(ECODE_MISMATCH)
        );

        let owner_address = signer::address_of(owner);

        if (!exists<StagingArea>(owner_address)) {
            move_to(
                owner,
                StagingArea {
                    metadata_serialized: vector[],
                    code: smart_table::new(),
                    last_module_idx: 0
                }
            );
        };

        let staging_area = borrow_global_mut<StagingArea>(owner_address);

        if (!vector::is_empty(&metadata_chunk)) {
            vector::append(&mut staging_area.metadata_serialized, metadata_chunk);
        };

        let i = 0;
        while (i < vector::length(&code_chunks)) {
            let inner_code = *vector::borrow(&code_chunks, i);
            let idx = (*vector::borrow(&code_indices, i) as u64);

            if (smart_table::contains(&staging_area.code, idx)) {
                vector::append(
                    smart_table::borrow_mut(&mut staging_area.code, idx), inner_code
                );
            } else {
                smart_table::add(&mut staging_area.code, idx, inner_code);
                if (idx > staging_area.last_module_idx) {
                    staging_area.last_module_idx = idx;
                }
            };
            i = i + 1;
        };

        staging_area
    }
```
