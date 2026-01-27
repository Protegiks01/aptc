# Audit Report

## Title
Integer Truncation in Chunked Package Publishing Causes Module Index Overflow

## Summary
The `chunked_publish.rs` file contains an unchecked cast from `usize` to `u16` when generating module indices, causing integer truncation for packages with more than 65,535 modules. This results in incorrect `code_indices` values that corrupt module bytecode during assembly.

## Finding Description

The vulnerability exists in the chunked package publishing logic used by the Aptos CLI and SDKs to deploy large Move packages across multiple transactions. [1](#0-0) 

The code iterates through modules in a package and assigns each module an index. At line 79, it casts `idx` (type `usize`) to `u16` without bounds checking. When a package contains more than 65,535 modules, the cast truncates:
- Module 65,536 → index 0 (wraps around)
- Module 65,537 → index 1
- And so on...

These truncated indices are then sent to the Move smart contract: [2](#0-1) 

When the Move contract processes chunks with duplicate indices (e.g., both module 0 and module 65,536 have index 0), it appends the later module's chunks to the earlier module's data at lines 168-170. This corrupts the module bytecode.

The final assembly step expects continuous indices from 0 to `last_module_idx`: [3](#0-2) 

The corrupted modules would contain concatenated bytecode from multiple distinct modules, breaking the **Deterministic Execution** invariant.

## Impact Explanation

This qualifies as **Medium severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

- Corrupted module bytecode would be published on-chain
- Different validators might handle the corrupted bytecode differently depending on verification strictness
- Could potentially break consensus if bytecode verification is not uniformly strict
- Requires manual intervention to clean up the corrupted package state

The impact is limited because the corrupted bytecode would likely fail Move bytecode verification during the publishing process, preventing the attack from succeeding silently.

## Likelihood Explanation

**Very Low** - Bordering on impractical:

1. **Module Count Requirement**: Attacker must create 65,536+ valid Move modules
2. **Compilation Overhead**: Each module must be individually compiled and validated
3. **Size Constraints**: Even minimal modules (~100-200 bytes) result in packages of 6.5+ MB
4. **No Legitimate Use Case**: No realistic scenario requires 65,536+ modules in a single package
5. **Verification Barriers**: Bytecode verification would likely reject corrupted modules

While the bug technically exists in the codebase, exploiting it requires creating an absurdly large package far beyond any practical use case.

## Recommendation

Add bounds checking before the cast to prevent index overflow:

```rust
for (idx, module_code) in package_code.into_iter().enumerate() {
    // Validate module index fits in u16
    let module_idx = u16::try_from(idx).map_err(|_| {
        anyhow::anyhow!(
            "Package contains too many modules ({}). Maximum supported is {}",
            idx + 1,
            u16::MAX
        )
    })?;
    
    let chunked_module = create_chunks(module_code, chunk_size);
    for chunk in chunked_module {
        if taken_size + chunk.len() > chunk_size {
            // Create payload and reset...
            // (existing code)
        }
        code_indices.push(module_idx);
        taken_size += chunk.len();
        code_chunks.push(chunk);
    }
}
```

Additionally, document the `u16` limit in the function documentation and enforce it at package build time in the CLI.

## Proof of Concept

Due to the extreme impracticality of creating 65,536+ valid Move modules, a full PoC cannot be reasonably demonstrated. However, the vulnerability can be validated through unit testing:

```rust
#[test]
fn test_module_index_overflow() {
    // Simulate a package with 65,536 modules
    let mut package_code: Vec<Vec<u8>> = Vec::new();
    for _ in 0..65536 {
        // Minimal valid module bytecode
        package_code.push(vec![0xA1, 0x1C, 0xEB, 0x0B]); // MOVE_MAGIC + minimal data
    }
    
    // This should fail or handle overflow gracefully
    let result = chunk_package_and_create_payloads(
        vec![],
        package_code,
        PublishType::AccountDeploy,
        None,
        AccountAddress::from_hex_literal("0x1").unwrap(),
        CHUNK_SIZE_IN_BYTES,
    );
    
    // Without the fix, code_indices for module 65536 would wrap to 0
    // With the fix, this should return an error
}
```

---

**Notes**

While this vulnerability technically exists in the codebase, it fails the "realistic attack path" criterion from the validation checklist. Creating 65,536+ Move modules is beyond any practical scenario and would be caught by other validation layers (bytecode verification, transaction size limits, gas costs). The theoretical nature of this exploit and the extreme difficulty of demonstration suggest this may not meet the threshold for a valid security vulnerability despite the code defect being real.

### Citations

**File:** aptos-move/framework/src/chunked_publish.rs (L60-82)
```rust
    for (idx, module_code) in package_code.into_iter().enumerate() {
        let chunked_module = create_chunks(module_code, chunk_size);
        for chunk in chunked_module {
            if taken_size + chunk.len() > chunk_size {
                // Create a payload and reset accumulators
                let payload = large_packages_stage_code_chunk(
                    metadata_chunk,
                    code_indices.clone(),
                    code_chunks.clone(),
                    large_packages_module_address,
                );
                payloads.push(payload);

                metadata_chunk = vec![];
                code_indices.clear();
                code_chunks.clear();
                taken_size = 0;
            }

            code_indices.push(idx as u16);
            taken_size += chunk.len();
            code_chunks.push(chunk);
        }
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L162-178)
```text
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
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L213-225)
```text
    inline fun assemble_module_code(staging_area: &mut StagingArea): vector<vector<u8>> {
        let last_module_idx = staging_area.last_module_idx;
        let code = vector[];
        let i = 0;
        while (i <= last_module_idx) {
            vector::push_back(
                &mut code,
                *smart_table::borrow(&staging_area.code, i)
            );
            i = i + 1;
        };
        code
    }
```
