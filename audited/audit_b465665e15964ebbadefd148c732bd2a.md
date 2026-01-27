# Audit Report

## Title
Governance Upgrade Script Generation Fails for Modules Exceeding 32KB Due to Move Constant Size Limit

## Summary
The `generate_blob_as_hex_string()` function in `release_bundle.rs` generates hex string constants for module bytecode without size validation, causing compilation failures when individual modules exceed 32,767 bytes (producing hex strings >65,535 characters that exceed Move's `CONSTANT_SIZE_MAX` limit). [1](#0-0) 

## Finding Description

The vulnerability exists in the governance upgrade proposal script generation logic. When creating upgrade proposals, the code converts each compiled module's bytecode directly into a hex string constant without chunking: [2](#0-1) 

Each byte becomes 2 hex characters, so a module with N bytes produces a 2N-character hex string. Move enforces a maximum constant size of 65,535 bytes: [3](#0-2) 

This limit is validated during constant deserialization: [4](#0-3) 

**The developers are aware of this limit** and correctly chunk metadata to avoid the issue: [5](#0-4) 

However, they failed to apply the same chunking logic to module bytecode at lines 234-239. Since governance transactions can be up to 1MB in size: [6](#0-5) 

And framework modules can legitimately exceed 32KB (evidenced by the 55KB chunk size used in production): [7](#0-6) 

This creates a scenario where legitimate governance upgrades of large framework modules will fail at the compilation stage.

## Impact Explanation

**Severity: DOES NOT MEET BUG BOUNTY CRITERIA**

While this issue causes operational disruption, it does **not** qualify as a security vulnerability under the Aptos bug bounty program:

- ❌ No loss of funds or manipulation
- ❌ No consensus/safety violations  
- ❌ No state inconsistencies
- ❌ No validator impact
- ❌ No protocol violations

The issue results in **compilation failure** (safe, detectable) rather than **silent truncation** (dangerous). When a module exceeds 32KB:

1. The generated script cannot compile
2. The error is immediately visible to developers
3. No incorrect bytecode is produced
4. No on-chain state is corrupted

**Workarounds exist:** Developers can manually chunk modules or use alternative deployment mechanisms like `large_packages` module.

This is an **operational bug/limitation** that should be fixed for developer experience, but it is **not a security vulnerability** per the strict criteria provided.

## Likelihood Explanation

**High likelihood of occurrence** for large framework modules:
- Framework modules like `aptos_governance` and `stake` contain complex logic
- Governance upgrades are regular occurrences
- Developers would encounter this immediately when attempting upgrades

However, **low security impact** as failures are caught at compile-time, not runtime.

## Recommendation

Apply the same chunking logic used for metadata (lines 245-259) to module bytecode. Replace lines 234-239 with:

```rust
// Chunk each module bytecode similarly to metadata
for (idx, module_code) in self.code.iter().enumerate() {
    let module_chunks = create_chunks(module_code.clone(), chunk_size);
    for (chunk_idx, chunk) in module_chunks.iter().enumerate() {
        emitln!(writer, "let module_{}_{} = ", idx, chunk_idx);
        generate_blob_as_hex_string(&writer, chunk);
        emitln!(writer, ";");
    }
    // Reassemble chunks if needed
    emitln!(writer, "let module_{} = module_{}_0;", idx, idx);
    for chunk_idx in 1..module_chunks.len() {
        emitln!(writer, "vector::append(&mut module_{}, module_{}_{});", 
                idx, idx, chunk_idx);
    }
    emitln!(writer, "vector::push_back(&mut code, module_{});", idx);
}
```

## Proof of Concept

```rust
// File: test_large_module_proposal.rs
use aptos_framework::ReleasePackage;
use move_core_types::account_address::AccountAddress;

#[test]
fn test_large_module_causes_compilation_failure() {
    // Create a mock package with a module >32KB
    let large_bytecode = vec![0u8; 40_000]; // 40KB module
    
    let package = create_mock_package_with_bytecode(large_bytecode);
    let release = ReleasePackage::new(package).unwrap();
    
    let output = PathBuf::from("/tmp/test_proposal.move");
    
    // This will generate a script with a >65K constant
    release.generate_script_proposal(
        AccountAddress::ONE,
        output.clone()
    ).unwrap();
    
    // Attempt to compile the generated script
    let compile_result = compile_move_script(&output);
    
    // Compilation will fail with constant size exceeded error
    assert!(compile_result.is_err());
    assert!(compile_result.unwrap_err()
        .to_string()
        .contains("constant size"));
}
```

---

## Notes

**This finding does NOT meet the security vulnerability criteria** because:
1. The failure mode is **safe** (compilation error, not silent corruption)
2. No security invariants are violated
3. It's an operational limitation with available workarounds
4. Does not fit any bug bounty severity category

**Recommendation:** Close as "Non-Security Operational Bug" and fix for developer experience, but this should **not** be reported as a security vulnerability.

### Citations

**File:** aptos-move/framework/src/release_bundle.rs (L234-239)
```rust
        for i in 0..self.code.len() {
            emitln!(writer, "let chunk{} = ", i);
            generate_blob_as_hex_string(&writer, &self.code[i]);
            emitln!(writer, ";");
            emitln!(writer, "vector::push_back(&mut code, chunk{});", i);
        }
```

**File:** aptos-move/framework/src/release_bundle.rs (L241-247)
```rust
        // The package metadata can be larger than 64k, which is the max for Move constants.
        // We therefore have to split it into chunks. Three chunks should be large enough
        // to cover any current and future needs. We then dynamically append them to obtain
        // the result.
        let mut metadata = bcs::to_bytes(&self.metadata)?;
        let chunk_size = (u16::MAX / 2) as usize;
        let num_of_chunks = (metadata.len() / chunk_size) + 1;
```

**File:** aptos-move/framework/src/release_bundle.rs (L278-284)
```rust
pub fn generate_blob_as_hex_string(writer: &CodeWriter, data: &[u8]) {
    emit!(writer, "x\"");
    for b in data.iter() {
        emit!(writer, "{:02x}", b);
    }
    emit!(writer, "\"");
}
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L69-69)
```rust
pub const CONSTANT_SIZE_MAX: u64 = 65535;
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L382-384)
```rust
fn load_constant_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, CONSTANT_SIZE_MAX)
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L78-81)
```rust
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```

**File:** aptos-move/framework/src/chunked_publish.rs (L19-20)
```rust
/// The default chunk size for splitting code and metadata to fit within the transaction size limits.
pub const CHUNK_SIZE_IN_BYTES: usize = 55_000;
```
