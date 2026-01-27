# Audit Report

## Title
Integer Overflow in Signature Complexity Metering Allows Bypass of Module Complexity Limits

## Summary
The `meter_signatures()` function in `check_complexity.rs` contains an integer overflow vulnerability when casting signature indices from `usize` to `u16`. If a module contains more than 65,536 signatures, the cast wraps around, causing later signatures to reuse cached complexity costs from earlier signatures. This allows an attacker to bypass complexity budget checks and publish overly complex modules that can cause validator node slowdowns.

## Finding Description

The vulnerability exists in the signature metering logic that validates module complexity during publishing: [1](#0-0) 

The function iterates through all signatures using a `usize` loop counter, then casts it to `u16` when creating a `SignatureIndex`. Since `SignatureIndex` wraps a `u16`: [2](#0-1) [3](#0-2) 

When `sig_idx >= 65536`, the cast `sig_idx as u16` wraps around: index 65536 becomes 0, index 65537 becomes 1, etc.

The `meter_signature()` function caches complexity costs by `SignatureIndex`: [4](#0-3) 

This means signatures at indices 65536+ incorrectly reuse the cached costs of signatures 0, 1, 2, etc.

**Why This Can Happen:**

During deserialization, there is no validation limiting the signature pool size to `u16::MAX`. The `Table::load` method only checks byte count, not element count: [5](#0-4) 

The table size limit is `TABLE_SIZE_MAX` (u32::MAX bytes), which can accommodate far more than 65,536 minimal signatures: [6](#0-5) 

**Attack Scenario:**

1. Attacker crafts a malicious binary with 66,000 signatures
2. First 65,536 signatures are minimal (e.g., single `Bool` type) - low complexity cost
3. Signatures 65,536-66,000 are highly complex (deeply nested types) - high complexity cost
4. During complexity checking in module publishing: [7](#0-6) 

5. Signatures 0-65,535 are metered correctly with low costs and cached
6. Signatures 65,536+ wrap to indices 0-464, reusing the low cached costs from step 5
7. Module passes complexity check with artificially low total cost
8. When validators load and verify this module at runtime, the actual complexity causes slowdowns

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability enables **validator node slowdowns**, which qualifies as **High Severity** per the Aptos Bug Bounty program criteria.

An attacker can publish modules that bypass complexity limits designed to prevent resource exhaustion. When validators process transactions invoking these modules, they experience:

- Excessive CPU usage during module loading and verification
- Increased memory consumption for type checking complex signatures
- Degraded transaction processing throughput
- Potential denial of service if multiple such modules are deployed

While this doesn't directly cause consensus violations or fund loss, it significantly impacts network availability and validator performance - a critical concern for blockchain infrastructure.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is feasible but requires technical sophistication:

**Feasibility Factors:**
- Attacker must manually craft a malicious binary (cannot use standard Move compiler, which validates signature counts)
- Creating 65,536+ signatures is straightforward (minimal signatures are ~2 bytes each)
- Total payload size of ~131KB for 65,537 minimal signatures is well within limits
- No special privileges required - any user can publish modules

**Constraints:**
- Requires understanding of Move binary format
- Must bypass normal compilation toolchain
- Module publishing costs gas (but attack ROI is high - one malicious module affects all validators)

The barrier is moderate but achievable for motivated attackers with binary format knowledge.

## Recommendation

Add validation during module deserialization to enforce that all table entry counts respect `u16::MAX`:

```rust
// In deserializer.rs, after Table::load for signatures:
impl Table {
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
        
        // Add validation after loading
        if result.len() > TABLE_INDEX_MAX as usize {
            return Err(PartialVMError::new(StatusCode::INDEX_OUT_OF_BOUNDS)
                .with_message(format!(
                    "Table entry count {} exceeds maximum {}",
                    result.len(),
                    TABLE_INDEX_MAX
                )));
        }
        
        Ok(())
    }
}
```

Alternatively, fix the overflow in `meter_signatures()`:

```rust
fn meter_signatures(&self) -> PartialVMResult<()> {
    let sig_count = self.resolver.signatures().len();
    if sig_count > u16::MAX as usize {
        return Err(PartialVMError::new(StatusCode::PROGRAM_TOO_COMPLEX)
            .with_message(format!(
                "Signature pool size {} exceeds maximum {}",
                sig_count, u16::MAX
            )));
    }
    
    for sig_idx in 0..sig_count {
        self.meter_signature(SignatureIndex(sig_idx as u16))?;
    }
    Ok(())
}
```

The first approach (deserialization validation) is preferred as it provides defense-in-depth and prevents invalid modules from entering the system entirely.

## Proof of Concept

```rust
// Proof of concept demonstrating the vulnerability
// This would need to be a Rust test that manually crafts a binary

#[test]
fn test_signature_overflow_bypass() {
    use move_binary_format::{
        file_format::*,
        check_complexity::check_module_complexity,
    };
    
    // Manually construct a CompiledModule with 65537 signatures
    let mut module = CompiledModule {
        version: VERSION_DEFAULT,
        module_handles: vec![/* ... */],
        struct_handles: vec![],
        function_handles: vec![],
        function_instantiations: vec![],
        signatures: vec![],
        identifiers: vec![/* ... */],
        address_identifiers: vec![/* ... */],
        constant_pool: vec![],
        metadata: vec![],
        // ... other fields
    };
    
    // Add 65536 simple signatures (low complexity)
    for _ in 0..65536 {
        module.signatures.push(Signature(vec![SignatureToken::Bool]));
    }
    
    // Add 1 complex signature (high complexity)
    // This should be expensive but will reuse cost from signature 0
    let complex_sig = create_deeply_nested_signature(50); // 50 levels deep
    module.signatures.push(complex_sig);
    
    // The module should have 65537 signatures
    assert_eq!(module.signatures.len(), 65537);
    
    // Budget calculation: 2048 + (small_code_size) * 20
    let budget = 10000;
    
    // This should fail due to complexity but will incorrectly pass
    // because signature 65536 wraps to index 0 and reuses Bool's low cost
    let result = check_module_complexity(&module, budget);
    
    // Without the fix, this passes when it should fail
    assert!(result.is_ok(), "Complexity check incorrectly passed!");
}

fn create_deeply_nested_signature(depth: usize) -> Signature {
    let mut token = SignatureToken::Bool;
    for _ in 0..depth {
        token = SignatureToken::Vector(Box::new(token));
    }
    Signature(vec![token])
}
```

**Note:** The actual PoC requires binary manipulation tools to create a valid serialized module with 65537 signatures, as the normal serialization path includes validation that would prevent this. The conceptual test above demonstrates the logic vulnerability.

### Citations

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L84-102)
```rust
    fn meter_signature(&self, idx: SignatureIndex) -> PartialVMResult<()> {
        let cost = match self.cached_signature_costs.borrow_mut().entry(idx) {
            btree_map::Entry::Occupied(entry) => *entry.into_mut(),
            btree_map::Entry::Vacant(entry) => {
                let sig = safe_get_table(self.resolver.signatures(), idx.0)?;

                let mut cost: u64 = 0;
                for ty in &sig.0 {
                    cost = cost.saturating_add(self.signature_token_cost(ty)?);
                }

                *entry.insert(cost)
            },
        };

        self.charge(cost)?;

        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L104-109)
```rust
    fn meter_signatures(&self) -> PartialVMResult<()> {
        for sig_idx in 0..self.resolver.signatures().len() {
            self.meter_signature(SignatureIndex(sig_idx as u16))?;
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L55-56)
```rust
/// Generic index into one of the tables in the binary format.
pub type TableIndex = u16;
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L151-155)
```rust
define_index! {
    name: SignatureIndex,
    kind: Signature,
    doc: "Index into the `Signature` table.",
}
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L575-588)
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
        while cursor.position() < self.count as u64 {
            result.push(deserializer(&mut cursor)?)
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L40-44)
```rust
pub const TABLE_SIZE_MAX: u64 = 0xFFFF_FFFF;
pub const TABLE_CONTENT_SIZE_MAX: u64 = 0xFFFF_FFFF;

pub const TABLE_INDEX_MAX: u64 = 65535;
pub const SIGNATURE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1554-1559)
```rust
        for (module, blob) in modules.iter().zip(bundle.iter()) {
            // TODO(Gas): Make budget configurable.
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
        }
```
