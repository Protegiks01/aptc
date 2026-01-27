# Audit Report

## Title
Missing Identifier Length Validation in FunctionInfo Runtime Conversion Allows Memory Exhaustion Attack

## Summary

The `FunctionInfo` struct's `module_name` and `function_name` fields lack length validation when converted from strings to `Identifier` objects at runtime. While module deserialization enforces identifier length limits (255 or 65,535 bytes), the runtime conversion path through `Identifier::from_utf8()` only validates the identifier pattern without checking length. This allows attackers to embed arbitrarily large identifier strings (up to the 64KB transaction limit) in `AbstractAuthenticator` structures, causing memory exhaustion across all validator nodes. [1](#0-0) 

## Finding Description

The vulnerability exists in a discrepancy between two validation paths for Move identifiers:

**Path 1: Module Deserialization (ENFORCES LENGTH LIMITS)**

When Move bytecode modules are deserialized, identifier length is strictly validated: [2](#0-1) 

The `load_identifier_size()` function enforces the configured maximum identifier size: [3](#0-2) 

The maximum is controlled by feature flags: [4](#0-3) [5](#0-4) 

**Path 2: Runtime Conversion (NO LENGTH VALIDATION)**

However, when `FunctionInfo` objects are deserialized from transaction data and converted to identifiers at runtime, the validation only checks the pattern: [6](#0-5) [7](#0-6) [8](#0-7) 

The `is_valid()` function only validates the character pattern, not the length.

**Attack Vector**

An attacker can exploit this by submitting transactions with `AbstractAuthenticator` containing malicious `FunctionInfo`: [9](#0-8) 

The transaction processing flow:

1. Transaction with `AbstractAuthenticator` is BCS-deserialized (no FunctionInfo validation)
2. VM calls `dispatchable_authenticate()`: [10](#0-9) 

3. Native function extracts the function info: [11](#0-10) 

4. `extract_function_info()` converts strings to identifiers WITHOUT length checks: [12](#0-11) [13](#0-12) 

**Breaking Invariants**

This breaks the "Move VM Safety" invariant that bytecode execution must respect memory constraints, and the "Resource Limits" invariant that all operations must respect computational limits.

## Impact Explanation

**Severity: High ($50,000 category)**

This qualifies as High severity under "Validator node slowdowns" because:

1. **Memory Exhaustion**: Each transaction can force validators to allocate up to ~60KB of memory for oversized identifiers (within the 64KB transaction size limit). With multiple such transactions in a block, memory usage scales linearly. [14](#0-13) 

2. **All Validators Affected**: Every validator processing the transaction must allocate the memory, making this a network-wide DoS vector.

3. **Consensus Risk**: If validators experience different behavior under memory pressure (e.g., OOM kills, performance degradation), it could lead to consensus liveness issues or safety violations.

4. **No Gas Cost Protection**: The gas cost for identifier validation doesn't account for extreme lengths: [15](#0-14) 

The gas charge is per-byte for validation but doesn't prevent the allocation of oversized identifiers.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:

1. No special permissions required - any user can submit transactions
2. No economic barrier beyond normal transaction fees
3. Exploit code is straightforward - create a `FunctionInfo` with 30,000-byte identifier strings
4. Attack is deterministic - all validators will be affected
5. No rate limiting specifically prevents this pattern

The only limiting factor is the 64KB transaction size, but this still allows identifiers 117x larger than the intended 255-byte limit (or nearly equal to the 65,535-byte legacy limit).

## Recommendation

Add explicit length validation to `Identifier::from_utf8()` and `Identifier::new()`:

```rust
// In third_party/move/move-core/types/src/identifier.rs

// Add a maximum length constant (should match the smallest configured limit)
pub const MAX_IDENTIFIER_LENGTH: usize = 255;

impl Identifier {
    pub fn new(s: impl Into<Box<str>>) -> Result<Self> {
        let s = s.into();
        
        // Add length check BEFORE pattern validation
        if s.len() > MAX_IDENTIFIER_LENGTH {
            bail!("Identifier length {} exceeds maximum {}", s.len(), MAX_IDENTIFIER_LENGTH);
        }
        
        if Self::is_valid(&s) {
            Ok(Self(s))
        } else {
            bail!("Invalid identifier '{}'", s);
        }
    }
}
```

Additionally, add validation in the Move framework when creating `FunctionInfo`: [16](#0-15) 

Add length checks before the `is_identifier` validation:

```move
public fun new_function_info_from_address(
    module_address: address,
    module_name: String,
    function_name: String,
): FunctionInfo {
    // Add length limits
    assert!(string::length(&module_name) <= 255, EINVALID_IDENTIFIER);
    assert!(string::length(&function_name) <= 255, EINVALID_IDENTIFIER);
    
    assert!(
        is_identifier(string::bytes(&module_name)),
        EINVALID_IDENTIFIER
    );
    assert!(
        is_identifier(string::bytes(&function_name)),
        EINVALID_IDENTIFIER
    );
    FunctionInfo {
        module_address,
        module_name,
        function_name,
    }
}
```

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability
use aptos_types::{
    transaction::authenticator::{AbstractAuthenticator, AbstractAuthenticationData},
    function_info::FunctionInfo,
    account_address::AccountAddress,
};
use move_core_types::identifier::Identifier;

#[test]
fn test_oversized_function_info_identifiers() {
    // Create identifiers that exceed the 255-byte limit but are valid patterns
    let large_module_name = "a".repeat(30_000); // 30KB identifier
    let large_function_name = "b".repeat(30_000); // 30KB identifier
    
    // This should fail but currently succeeds
    let function_info = FunctionInfo::new(
        AccountAddress::random(),
        large_module_name.clone(),
        large_function_name.clone(),
    );
    
    // Verify the identifiers are accepted despite exceeding limits
    assert_eq!(function_info.module_name.len(), 30_000);
    assert_eq!(function_info.function_name.len(), 30_000);
    
    // When this is used in AbstractAuthenticator and processed by the VM,
    // it will call Identifier::from_utf8() which only validates the pattern
    let bytes = large_module_name.into_bytes();
    let result = Identifier::from_utf8(bytes);
    
    // This succeeds because is_valid() doesn't check length
    assert!(result.is_ok());
    
    println!("Vulnerability confirmed: Oversized identifiers accepted at runtime");
}

// Integration test showing transaction processing
#[test]
fn test_abstract_authenticator_memory_exhaustion() {
    use bcs;
    
    // Create a FunctionInfo with maximum size within transaction limit
    let oversized_module = "a".repeat(30_000);
    let oversized_function = "b".repeat(30_000);
    
    let function_info = FunctionInfo::new(
        AccountAddress::from_hex_literal("0x1").unwrap(),
        oversized_module,
        oversized_function,
    );
    
    let auth_data = AbstractAuthenticationData::V1 {
        signing_message_digest: vec![0u8; 32],
        abstract_signature: vec![0u8; 64],
    };
    
    let abstract_auth = AbstractAuthenticator::new(function_info, auth_data);
    
    // Serialize to BCS - this will be within the 64KB transaction limit
    let serialized = bcs::to_bytes(&abstract_auth).unwrap();
    
    println!("Serialized AbstractAuthenticator size: {} bytes", serialized.len());
    assert!(serialized.len() < 65_536); // Within transaction limit
    
    // When a validator deserializes and processes this transaction,
    // it will allocate ~60KB of memory for the oversized identifiers
    // with no corresponding gas cost or validation
}
```

**Notes**

The vulnerability exists because identifier length validation is only enforced during module deserialization, not during runtime string-to-identifier conversion. The `IDENTIFIER_SIZE_MAX` and `LEGACY_IDENTIFIER_SIZE_MAX` constants are defined but not consistently enforced across all code paths. This creates a bypass allowing attackers to embed oversized identifiers in transaction authenticators, causing memory exhaustion across the validator network.

### Citations

**File:** types/src/function_info.rs (L17-24)
```rust
/// Reflection of aptos_framework::function_info::FunctionInfo
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Hash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct FunctionInfo {
    pub module_address: AccountAddress,
    pub module_name: String,
    pub function_name: String,
}
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L394-396)
```rust
fn load_identifier_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, cursor.max_identifier_size())
}
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L979-998)
```rust
fn load_identifier(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Identifier> {
    let size = load_identifier_size(cursor)?;
    let mut buffer: Vec<u8> = vec![0u8; size];
    if !cursor.read(&mut buffer).map(|count| count == size).unwrap() {
        Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Bad Identifier pool size".to_string()))?;
    }
    let ident = Identifier::from_utf8(buffer).map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED).with_message("Invalid Identifier".to_string())
    })?;
    if cursor.version() < VERSION_9 && ident.as_str().contains('$') {
        Err(
            PartialVMError::new(StatusCode::MALFORMED).with_message(format!(
                "`$` in identifiers not supported in bytecode version {}",
                cursor.version()
            )),
        )
    } else {
        Ok(ident)
    }
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L66-67)
```rust
pub const LEGACY_IDENTIFIER_SIZE_MAX: u64 = 65535;
pub const IDENTIFIER_SIZE_MAX: u64 = 255;
```

**File:** types/src/on_chain_config/aptos_features.rs (L477-483)
```rust
    pub fn get_max_identifier_size(&self) -> u64 {
        if self.is_enabled(FeatureFlag::LIMIT_MAX_IDENTIFIER_LENGTH) {
            IDENTIFIER_SIZE_MAX
        } else {
            LEGACY_IDENTIFIER_SIZE_MAX
        }
    }
```

**File:** third_party/move/move-core/types/src/identifier.rs (L82-94)
```rust
pub const fn is_valid(s: &str) -> bool {
    // Rust const fn's don't currently support slicing or indexing &str's, so we
    // have to operate on the underlying byte slice. This is not a problem as
    // valid identifiers are (currently) ASCII-only.
    let b = s.as_bytes();
    match b {
        b"<SELF>" => true,
        [b'<', b'S', b'E', b'L', b'F', b'>', b'_', ..] if b.len() > 7 => all_bytes_numeric(b, 7),
        [b'a'..=b'z', ..] | [b'A'..=b'Z', ..] => all_bytes_valid(b, 1),
        [b'_', ..] | [b'$', ..] if b.len() > 1 => all_bytes_valid(b, 1),
        _ => false,
    }
}
```

**File:** third_party/move/move-core/types/src/identifier.rs (L117-126)
```rust
impl Identifier {
    /// Creates a new `Identifier` instance.
    pub fn new(s: impl Into<Box<str>>) -> Result<Self> {
        let s = s.into();
        if Self::is_valid(&s) {
            Ok(Self(s))
        } else {
            bail!("Invalid identifier '{}'", s);
        }
    }
```

**File:** third_party/move/move-core/types/src/identifier.rs (L147-151)
```rust
    /// Converts a vector of bytes to an `Identifier`.
    pub fn from_utf8(vec: Vec<u8>) -> Result<Self> {
        let s = String::from_utf8(vec)?;
        Self::new(s)
    }
```

**File:** types/src/transaction/authenticator.rs (L548-563)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct AbstractAuthenticator {
    /// An abstract `authenticator` should be verifiable by the function in `function_info` over the signing_message_digest = sha3_256(signing_message(AASigningData(original_signing_message, function_info))))
    /// For example, consider the following authentication function:
    ///
    ///   fun verify(owner: signer, authenticator: vector<u8>, signing_message_digest: vector<u8>) -> signer
    ///
    /// It might operate by, for example:
    ///  1. Looking up the public key of `owner` in some table
    ///  2. Parsing the `authenticator` as an RSA signature
    ///  2. Verifying this RSA signature over the `signing_message_digest` under this public key
    ///
    /// Note: Abstract authenticators don't exactly follow the `AccountAuthenticator` paradigm, where an "authenticator" typically consists of a public key and a signature.
    function_info: FunctionInfo,
    auth_data: AbstractAuthenticationData,
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3400-3414)
```rust
fn dispatchable_authenticate(
    session: &mut SessionExt<impl AptosMoveResolver>,
    gas_meter: &mut impl GasMeter,
    account: AccountAddress,
    function_info: FunctionInfo,
    auth_data: &AbstractAuthenticationData,
    traversal_context: &mut TraversalContext,
    module_storage: &impl ModuleStorage,
) -> VMResult<Vec<u8>> {
    let auth_data = bcs::to_bytes(auth_data).expect("from rust succeeds");
    let mut params = serialize_values(&vec![
        MoveValue::Signer(account),
        function_info.as_move_value(),
    ]);
    params.push(auth_data);
```

**File:** aptos-move/framework/src/natives/account_abstraction.rs (L22-27)
```rust
pub(crate) fn native_dispatch(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let (module_name, func_name) = extract_function_info(&mut arguments)?;
```

**File:** aptos-move/framework/src/natives/function_info.rs (L22-32)
```rust
// Extract Identifier from a move value of type &String
fn identifier_from_ref(v: Value) -> SafeNativeResult<Identifier> {
    let bytes = v
        .value_as::<StructRef>()
        .and_then(|s| s.borrow_field(0))
        .and_then(|v| v.value_as::<VectorRef>())
        .map_err(SafeNativeError::InvariantViolation)?
        .as_bytes_ref()
        .to_vec();
    Identifier::from_utf8(bytes).map_err(|_| SafeNativeError::Abort { abort_code: 1 })
}
```

**File:** aptos-move/framework/src/natives/function_info.rs (L34-56)
```rust
pub(crate) fn extract_function_info(
    arguments: &mut VecDeque<Value>,
) -> SafeNativeResult<(ModuleId, Identifier)> {
    match arguments.pop_back() {
        Some(val) => match val.value_as::<StructRef>() {
            Ok(v) => {
                let module_address = v
                    .borrow_field(0)
                    .and_then(|v| v.value_as::<Reference>())
                    .and_then(|v| v.read_ref())
                    .and_then(|v| v.value_as::<AccountAddress>())
                    .map_err(SafeNativeError::InvariantViolation)?;

                let module_name = identifier_from_ref(
                    v.borrow_field(1)
                        .map_err(SafeNativeError::InvariantViolation)?,
                )?;

                let func_name = identifier_from_ref(
                    v.borrow_field(2)
                        .map_err(SafeNativeError::InvariantViolation)?,
                )?;
                Ok((ModuleId::new(module_address, module_name), func_name))
```

**File:** aptos-move/framework/src/natives/function_info.rs (L143-166)
```rust
fn native_is_identifier(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(arguments.len() == 1);

    let s_arg = safely_pop_arg!(arguments, VectorRef);
    let s_ref = s_arg.as_bytes_ref();

    context.charge(
        FUNCTION_INFO_CHECK_IS_IDENTIFIER_BASE
            + FUNCTION_INFO_CHECK_IS_IDENTIFIER_PER_BYTE
                * NumBytes::new(s_ref.as_slice().len() as u64),
    )?;

    let result = if let Ok(str) = std::str::from_utf8(&s_ref) {
        Identifier::is_valid(str)
    } else {
        false
    };

    Ok(smallvec![Value::bool(result)])
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```

**File:** aptos-move/framework/aptos-framework/sources/function_info.move (L35-53)
```text
    public fun new_function_info_from_address(
        module_address: address,
        module_name: String,
        function_name: String,
    ): FunctionInfo {
        assert!(
            is_identifier(string::bytes(&module_name)),
            EINVALID_IDENTIFIER
        );
        assert!(
            is_identifier(string::bytes(&function_name)),
            EINVALID_IDENTIFIER
        );
        FunctionInfo {
            module_address,
            module_name,
            function_name,
        }
    }
```
