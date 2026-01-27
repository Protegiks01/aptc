# Audit Report

## Title
Missing VERSION_MIN Validation in Bytecode Deserializer Allows Execution of Deprecated Bytecode Versions

## Summary
The Move bytecode deserializer fails to enforce the `VERSION_MIN` constraint (set to VERSION_5), allowing transaction scripts with deprecated bytecode versions 1-4 to be deserialized and executed. This bypasses intended version restrictions and enables the use of deprecated verification logic that may contain known vulnerabilities. [1](#0-0) 

## Finding Description

The `VersionedBinary::new()` function in the bytecode deserializer performs incomplete version validation. The check only rejects versions that are zero or exceed the maximum: [2](#0-1) 

This validation is missing a critical lower-bound check against `VERSION_MIN`. While `VERSION_MIN` is explicitly defined as `VERSION_5` to mark versions 1-4 as unsupported, the deserializer accepts any version from 1 to `max_version`, creating a security gap.

**Attack Path:**

1. An attacker crafts malicious Move bytecode with the version field set to 1, 2, 3, or 4
2. The bytecode is submitted in a `TransactionScriptABI.code` field via a Script transaction
3. During deserialization, `VersionedCursor::new()` calls `VersionedBinary::new()`: [3](#0-2) 

4. The incomplete version check accepts the deprecated version
5. The script undergoes verification, but for versions < VERSION_5, legacy verification logic is applied: [4](#0-3) 

6. This legacy validation path uses deprecated signature checking with known behavioral differences: [5](#0-4) 

7. The deprecated bytecode executes on the Move VM, potentially exploiting version-specific bugs or using removed features

**Deprecated Features in Versions 1-4:**

- **VERSION_1**: Uses `DEPRECATED_PUBLIC_BIT` flag and `Reference<Signer>` handling [6](#0-5) 

- **Versions < VERSION_5**: Support `DEPRECATED_SCRIPT` visibility modifier [7](#0-6) 

- **VERSION_5 changes**: Script verification became "adapter specific" and metadata was added [8](#0-7) 

The serializer correctly enforces VERSION_MIN, creating an asymmetry: [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

1. **Significant Protocol Violation**: Bypasses the explicitly defined minimum supported version, undermining the security model that deprecated versions for specific security or compatibility reasons

2. **Potential Consensus Violations**: Different nodes might handle deprecated bytecode differently, especially if some have additional safeguards while others don't, leading to consensus splits

3. **VM Safety Compromise**: Deprecated verification logic (VERSION_1's `Reference<Signer>` handling vs newer `Signer` direct type) may have known bugs that were intentionally fixed in VERSION_5+

4. **Deterministic Execution Risk**: If validators process deprecated bytecode using different code paths or with inconsistent behavior, it violates the critical invariant that "all validators must produce identical state roots for identical blocks"

The production VM configuration retrieves the maximum version from on-chain feature flags, but never enforces the minimum: [10](#0-9) 

## Likelihood Explanation

**Likelihood: High**

- **Ease of Exploitation**: Any transaction sender can craft bytecode with a deprecated version by simply modifying the version field in the binary header
- **No Special Privileges Required**: Does not require validator access or governance control
- **Trivial to Execute**: Standard transaction submission through mempool
- **Detection Difficulty**: May go unnoticed unless nodes specifically log version numbers of executed scripts

The test suite validates version rejection for versions exceeding the maximum but never tests rejection of versions below VERSION_MIN: [11](#0-10) 

## Recommendation

Add a lower-bound version check in `VersionedBinary::new()`:

**File**: `third_party/move/move-binary-format/src/file_format_common.rs`

**Current code** (line 617):
```rust
if version == 0 || version > u32::min(max_version, VERSION_MAX) {
```

**Fixed code**:
```rust
if version == 0 || version < VERSION_MIN || version > u32::min(max_version, VERSION_MAX) {
```

Update the error message to reflect both bounds:
```rust
Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
    .with_message(format!(
        "bytecode version {} unsupported (must be between {} and {})",
        version,
        VERSION_MIN,
        u32::min(max_version, VERSION_MAX)
    )))
```

Additionally, add test coverage for VERSION_MIN enforcement:
```rust
#[test]
fn reject_version_below_minimum() {
    for version in 1..VERSION_MIN {
        let mut binary = BinaryConstants::MOVE_MAGIC.to_vec();
        binary.extend(version.to_le_bytes());
        binary.push(0); // table count
        
        let res = CompiledScript::deserialize(&binary);
        assert_eq!(
            res.expect_err("Expected version below minimum to be rejected")
                .major_status(),
            StatusCode::UNKNOWN_VERSION
        );
    }
}
```

## Proof of Concept

```rust
use move_binary_format::{
    file_format::CompiledScript,
    file_format_common::{BinaryConstants, VERSION_MIN},
};

#[test]
fn poc_deprecated_version_accepted() {
    // Craft bytecode with VERSION_1 (which is < VERSION_MIN = VERSION_5)
    let mut binary = BinaryConstants::MOVE_MAGIC.to_vec();
    binary.extend(1u32.to_le_bytes()); // VERSION_1
    binary.push(0); // table count (minimal invalid script)
    
    // This should fail with UNKNOWN_VERSION but currently succeeds in deserialization
    // (will fail later in bounds checking, but version check should reject it first)
    let result = CompiledScript::deserialize(&binary);
    
    // Current behavior: Accepts VERSION_1 during version check
    // Expected behavior: Should reject with UNKNOWN_VERSION
    println!("Deserialization result for VERSION_1 (< VERSION_MIN): {:?}", result);
    
    // Demonstrate the same for other deprecated versions
    for deprecated_version in 1..VERSION_MIN {
        let mut binary = BinaryConstants::MOVE_MAGIC.to_vec();
        binary.extend(deprecated_version.to_le_bytes());
        binary.push(0);
        
        let result = CompiledScript::deserialize(&binary);
        println!("Version {} (deprecated): passes version check = {}", 
                 deprecated_version, 
                 !matches!(result, Err(e) if e.major_status() == move_core_types::vm_status::StatusCode::UNKNOWN_VERSION));
    }
}
```

**Expected Output**: All deprecated versions (1-4) currently pass the version validation check in `VersionedBinary::new()`, when they should be rejected with `UNKNOWN_VERSION`.

---

**Notes**:
- The vulnerability exists at the deserializer level, affecting both scripts and modules
- While bounds checking may catch malformed bytecode later, version validation should be the first line of defense
- The asymmetry between serializer (enforces VERSION_MIN) and deserializer (does not) indicates an oversight rather than intentional design
- Production impact depends on what specific bugs or vulnerabilities existed in versions 1-4 that motivated deprecation

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L534-537)
```rust
/// Version 5: changes compared with version 4
///  +/- script and public(script) verification is now adapter specific
///  + metadata
pub const VERSION_5: u32 = 5;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L561-562)
```rust
/// Mark which oldest version is supported.
pub const VERSION_MIN: u32 = VERSION_5;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-620)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
            } else {
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L654-665)
```rust
        pub fn new(
            binary: &'a [u8],
            max_version: u32,
            max_identifier_size: u64,
        ) -> BinaryLoaderResult<Self> {
            let (binary, cursor) = VersionedBinary::new(binary, max_version, max_identifier_size)?;
            Ok(VersionedCursor {
                version: binary.version,
                max_identifier_size,
                cursor,
            })
        }
```

**File:** third_party/move/move-bytecode-verifier/src/script_signature.rs (L40-42)
```rust
    if script.version >= VERSION_5 {
        return Ok(());
    }
```

**File:** third_party/move/move-bytecode-verifier/src/script_signature.rs (L130-136)
```rust
    let deprecated_logic = resolver.version() < VERSION_5 && is_entry;

    if deprecated_logic {
        legacy_script_signature_checks(resolver, is_entry, parameters_idx, return_idx)?;
    }
    check_signature(resolver, is_entry, parameters_idx, return_idx)
}
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L1656-1663)
```rust
    let (visibility, is_entry, mut extra_flags) = if cursor.version() == VERSION_1 {
        let vis = if (flags & FunctionDefinition::DEPRECATED_PUBLIC_BIT) != 0 {
            flags ^= FunctionDefinition::DEPRECATED_PUBLIC_BIT;
            Visibility::Public
        } else {
            Visibility::Private
        };
        (vis, false, flags)
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L1664-1677)
```rust
    } else if cursor.version() < VERSION_5 {
        let (vis, is_entry) = if flags == Visibility::DEPRECATED_SCRIPT {
            (Visibility::Public, true)
        } else {
            let vis = flags.try_into().map_err(|_| {
                PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Invalid visibility byte".to_string())
            })?;
            (vis, false)
        };
        let extra_flags = cursor.read_u8().map_err(|_| {
            PartialVMError::new(StatusCode::MALFORMED).with_message("Unexpected EOF".to_string())
        })?;
        (vis, is_entry, extra_flags)
```

**File:** third_party/move/move-binary-format/src/serializer.rs (L261-272)
```rust
fn validate_version(version: u32) -> Result<()> {
    if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
        bail!(
            "The requested bytecode version {} is not supported. Only {} to {} are.",
            version,
            VERSION_MIN,
            VERSION_MAX
        )
    } else {
        Ok(())
    }
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L137-142)
```rust
pub fn aptos_prod_deserializer_config(features: &Features) -> DeserializerConfig {
    DeserializerConfig::new(
        features.get_max_binary_format_version(),
        features.get_max_identifier_size(),
    )
}
```

**File:** third_party/move/move-binary-format/src/unit_tests/deserializer_tests.rs (L209-218)
```rust
    // bad version
    let mut binary = BinaryConstants::MOVE_MAGIC.to_vec();
    binary.extend((VERSION_MAX.checked_add(1).unwrap()).to_le_bytes()); // version
    binary.push(10); // table count
    binary.push(0); // rest of binary
    let res = CompiledScript::deserialize(&binary);
    assert_eq!(
        res.expect_err("Expected unknown version").major_status(),
        StatusCode::UNKNOWN_VERSION
    );
```
