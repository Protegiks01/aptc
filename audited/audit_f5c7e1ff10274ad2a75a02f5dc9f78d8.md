# Audit Report

## Title
Governance Script Generation Fails for Modules Exceeding 32KB Due to Move Constant Size Limit

## Summary
The `generate_script_proposal_impl()` function in `release_bundle.rs` generates governance proposal scripts with hex-encoded module bytecode that can exceed Move's 64KB constant size limit, rendering governance proposals unparseable and blocking critical framework upgrades.

## Finding Description

The vulnerability exists in the governance script generation logic where module bytecode is converted to hex string literals without size validation or chunking. [1](#0-0) 

The `generate_blob_as_hex_string()` function converts raw bytecode to hex format: [2](#0-1) 

**The Critical Issue**: Hex encoding doubles the byte size (each byte becomes 2 hex characters). Move's binary format enforces a constant size maximum of 65,535 bytes (CONSTANT_SIZE_MAX): [3](#0-2) 

This limit is strictly enforced during deserialization: [4](#0-3) [5](#0-4) 

**The developers were aware of this issue for metadata** and properly chunk it at 32,767 bytes: [6](#0-5) 

However, **they failed to apply the same chunking logic to module bytecode**. If a compiled module exceeds 32,767 bytes, its hex representation will exceed 65,535 bytes, violating CONSTANT_SIZE_MAX.

**Evidence that modules can exceed this threshold**: [7](#0-6) [8](#0-7) 

The existence of chunked publishing with a 55KB chunk size proves that large modules are expected in production. When such a module is included in a governance proposal, the generated script will be unparseable.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

This vulnerability causes **governance disruption** by preventing the generation of valid proposal scripts for packages containing any module exceeding 32,767 bytes. The impact includes:

1. **Blocked Framework Upgrades**: Critical Aptos Framework updates cannot be proposed if any module grows beyond the threshold
2. **Governance Deadlock**: No alternative mechanism exists to deploy these modules via governance
3. **Manual Intervention Required**: Requires either code fixes or workarounds to unblock governance

This does not constitute:
- Critical severity: No consensus violation, fund loss, or network partition
- High severity: No validator slowdowns or API crashes
- Low severity: This is not a minor bug but a blocking governance issue

## Likelihood Explanation

**High Likelihood** - This will occur as the Aptos Framework naturally grows:

1. **Realistic Module Sizes**: Test limits allow modules up to 65,355 bytes, and complex framework modules like `aptos_governance` can legitimately approach or exceed 32KB as features are added

2. **Inevitable Trigger**: As governance modules accumulate functionality over time, hitting the 32KB threshold is a matter of when, not if

3. **No Warning Mechanism**: The `generate_script_proposal` functions have no size validation, so this will fail silently during actual governance proposal creation

4. **Already Anticipated**: The existence of chunked publishing infrastructure proves the team expects large modules in production

## Recommendation

Apply the same chunking strategy used for metadata to module bytecode. Modify `generate_script_proposal_impl()` to:

1. Check each module's size before hex encoding
2. For modules exceeding 32,767 bytes, split them into chunks ≤32,767 bytes
3. Generate multiple hex constants and concatenate them at runtime using `vector::append()`

Example fix (pseudo-code):

```rust
// In generate_script_proposal_impl()
for i in 0..self.code.len() {
    let module_bytes = &self.code[i];
    let chunk_size = (u16::MAX / 2) as usize; // 32,767 bytes
    
    if module_bytes.len() <= chunk_size {
        // Small module - emit directly
        emitln!(writer, "let chunk{} = ", i);
        generate_blob_as_hex_string(&writer, module_bytes);
        emitln!(writer, ";");
    } else {
        // Large module - chunk it
        let chunks = module_bytes.chunks(chunk_size).collect::<Vec<_>>();
        for (j, chunk) in chunks.iter().enumerate() {
            emit!(writer, "let chunk{}_part{} = ", i, j);
            generate_blob_as_hex_string(&writer, chunk);
            emitln!(writer, ";");
        }
        // Combine chunks
        emitln!(writer, "let chunk{} = chunk{}_part0;", i, i);
        for j in 1..chunks.len() {
            emitln!(writer, "vector::append(&mut chunk{}, chunk{}_part{});", i, i, j);
        }
    }
    emitln!(writer, "vector::push_back(&mut code, chunk{});", i);
}
```

## Proof of Concept

**Reproduction Steps**:

1. Create a Move module with bytecode size >32,767 bytes (e.g., by including large constant data or many function definitions)
2. Build the module into a `ReleasePackage`
3. Call `generate_script_proposal()` on the package
4. Attempt to compile the generated Move script

**Expected Result**: Move compiler fails with `StatusCode::MALFORMED` error "Uleb greater than max requested" when deserializing the oversized constant

**Rust Test Skeleton**:

```rust
#[test]
fn test_large_module_proposal_generation() {
    // Build a package with a module >32KB
    let large_package = create_large_test_package(); // Helper to create 40KB module
    
    let release_package = ReleasePackage::new(large_package).unwrap();
    
    // Generate governance proposal script
    let output_path = PathBuf::from("/tmp/large_proposal.move");
    release_package.generate_script_proposal(
        AccountAddress::ONE,
        output_path.clone()
    ).unwrap();
    
    // Attempt to compile the generated script
    let result = compile_move_script(&output_path);
    
    // This should fail with constant size error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("MALFORMED"));
}
```

**Notes**

The vulnerability is present in production code and will manifest when legitimate large modules are included in governance proposals. The fix is straightforward - apply the existing metadata chunking pattern to module bytecode. This should be prioritized before any framework modules naturally grow beyond 32KB.

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

**File:** aptos-move/framework/src/release_bundle.rs (L241-259)
```rust
        // The package metadata can be larger than 64k, which is the max for Move constants.
        // We therefore have to split it into chunks. Three chunks should be large enough
        // to cover any current and future needs. We then dynamically append them to obtain
        // the result.
        let mut metadata = bcs::to_bytes(&self.metadata)?;
        let chunk_size = (u16::MAX / 2) as usize;
        let num_of_chunks = (metadata.len() / chunk_size) + 1;

        for i in 1..num_of_chunks + 1 {
            let to_drain = if i == num_of_chunks {
                metadata.len()
            } else {
                chunk_size
            };
            let chunk = metadata.drain(0..to_drain).collect::<Vec<_>>();
            emit!(writer, "let chunk{} = ", i);
            generate_blob_as_hex_string(&writer, &chunk);
            emitln!(writer, ";")
        }
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

**File:** third_party/move/move-binary-format/src/deserializer.rs (L184-186)
```rust
    if x > max {
        return Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Uleb greater than max requested".to_string()));
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L382-384)
```rust
fn load_constant_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, CONSTANT_SIZE_MAX)
}
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L106-106)
```rust
    const MAX_MODULE_SIZE: usize = 65355;
```

**File:** aptos-move/framework/src/chunked_publish.rs (L20-20)
```rust
pub const CHUNK_SIZE_IN_BYTES: usize = 55_000;
```
