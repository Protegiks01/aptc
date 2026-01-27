# Audit Report

## Title
Gas Charging Bypass via Misclassified Execution Limit Errors on Legacy Gas Path

## Summary
Native functions that charge gas before encountering certain execution limit errors (e.g., `TYPE_TAG_LIMIT_EXCEEDED`) can bypass gas charging on the legacy gas path due to these errors being misclassified as `InvariantViolation` and propagated without wrapping accumulated gas charges.

## Finding Description

The vulnerability exists in how `InvariantViolation` errors are handled in the native function wrapper: [1](#0-0) 

When a native function returns `SafeNativeError::InvariantViolation`, it is converted to a bare `Err(err)` without wrapping the accumulated gas in `context.legacy_gas_used`. This means the error propagates through the interpreter: [2](#0-1) 

The `?` operator causes early return, bypassing all gas charging code for `NativeResult` variants.

The root cause is that certain execution limit errors are incorrectly converted to `InvariantViolation`: [3](#0-2) 

Specifically, `TYPE_TAG_LIMIT_EXCEEDED` (status code 4033) is NOT in the whitelist at lines 32-36, so it gets treated as an `InvariantViolation` by the catch-all at line 45. [4](#0-3) 

This error is user-triggerable by providing complex types that exceed the type tag cost limit.

**Attack Path:**
1. Attacker calls `string_utils::format_list` with a deeply nested or complex type
2. Native charges gas for format string processing: [5](#0-4) 
3. Type-to-type-tag conversion exceeds limit and fails with `TYPE_TAG_LIMIT_EXCEEDED`: [6](#0-5) 
4. Error is converted to `InvariantViolation` and propagated without charging the accumulated gas
5. On legacy gas path (gas_feature_version < 36), gas is lost

## Impact Explanation

**Severity: Low to Medium (conditional)**

This breaks the **Resource Limits** invariant: operations must respect gas limits. However, impact is limited:

- **Legacy Path Only**: Only affects `gas_feature_version < 36` where gas accumulates in `context.legacy_gas_used`: [7](#0-6) 

- **Direct Gas Meter Path Safe**: For `gas_feature_version >= 36`, gas is charged directly before the error: [8](#0-7) 

- **Current Mainnet**: Likely uses version 45, making this primarily a historical issue: [9](#0-8) 

The vulnerability allows free computation on legacy configurations, but does not affect current production systems.

## Likelihood Explanation

**Likelihood: Low**

- Current mainnet uses direct gas meter access (version >= 36)
- Legacy gas path is deprecated code
- Requires specific type complexity to trigger `TYPE_TAG_LIMIT_EXCEEDED`
- Only relevant for historical transaction replays or outdated configurations

## Recommendation

Add `TYPE_TAG_LIMIT_EXCEEDED` and other execution limit codes to the whitelist in `LimitExceededError::from_err`:

```rust
StatusCode::OUT_OF_GAS
| StatusCode::EXECUTION_LIMIT_REACHED
| StatusCode::DEPENDENCY_LIMIT_REACHED
| StatusCode::MEMORY_LIMIT_EXCEEDED
| StatusCode::TOO_MANY_TYPE_NODES
| StatusCode::VM_MAX_VALUE_DEPTH_REACHED
| StatusCode::TYPE_TAG_LIMIT_EXCEEDED  // ADD THIS
| StatusCode::IO_LIMIT_REACHED          // ADD THIS
| StatusCode::STORAGE_LIMIT_REACHED     // ADD THIS
```

Additionally, for legacy gas path, wrap `InvariantViolation` errors with accumulated gas:
```rust
InvariantViolation(err) => Ok(NativeResult::err(context.legacy_gas_used, err.major_status() as u64)),
```

## Proof of Concept

**Note:** This vulnerability primarily affects legacy configurations and cannot be easily demonstrated on current mainnet (version 45). However, the following test would demonstrate the issue on a system configured with `gas_feature_version < 36`:

```move
module test_addr::gas_bypass_test {
    use std::string_utils;
    use std::vector;

    // Create deeply nested type to exceed TYPE_TAG_LIMIT
    struct Deep1<T> { val: T }
    struct Deep2<T> { val: Deep1<T> }
    struct Deep3<T> { val: Deep2<T> }
    struct Deep4<T> { val: Deep3<T> }
    struct Deep5<T> { val: Deep4<T> }
    
    public entry fun exploit() {
        // This should charge gas but fail with TYPE_TAG_LIMIT_EXCEEDED
        // On legacy gas path, charged gas would be lost
        let _ = string_utils::format1<Deep5<vector<Deep5<u64>>>>(
            &b"value: {}",
            Deep5 { val: Deep4 { val: Deep3 { val: Deep2 { val: Deep1 { val: vector::empty() }}}}}
        );
    }
}
```

**Notes:**
- The public accessibility of string_utils functions is confirmed: [10](#0-9) 

- The automatic conversion that compounds the issue: [11](#0-10) 

Despite being a real implementation bug with clear gas charging bypass mechanics, this vulnerability has **limited practical impact** on current production systems and primarily affects deprecated legacy code paths.

### Citations

**File:** aptos-move/aptos-native-interface/src/builder.rs (L150-151)
```rust
                    // TODO(Gas): Check if err is indeed an invariant violation.
                    InvariantViolation(err) => Err(err),
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1106-1106)
```rust
        let result = native_function(&mut native_context, ty_args, args)?;
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L29-47)
```rust
impl LimitExceededError {
    pub fn from_err(err: PartialVMError) -> SafeNativeError {
        match err.major_status() {
            StatusCode::OUT_OF_GAS
            | StatusCode::EXECUTION_LIMIT_REACHED
            | StatusCode::DEPENDENCY_LIMIT_REACHED
            | StatusCode::MEMORY_LIMIT_EXCEEDED
            | StatusCode::TOO_MANY_TYPE_NODES
            | StatusCode::VM_MAX_VALUE_DEPTH_REACHED => SafeNativeError::LimitExceeded(
                LimitExceededError::LimitExceeded(MeteringError(err)),
            ),
            // Treat all other code as invariant violations and leave it for the VM to propagate
            // these further. Note that we do not remap the errors. For example, if there is a
            // speculative error returned (signaling Block-STM to stop executing this transaction),
            // we better not remap it.
            // TODO(Gas): Have a single method to convert partial VM error to safe native error.
            _ => SafeNativeError::InvariantViolation(err),
        }
    }
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L105-109)
```rust
impl From<PartialVMError> for SafeNativeError {
    fn from(e: PartialVMError) -> Self {
        SafeNativeError::InvariantViolation(e)
    }
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L50-62)
```rust
    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(
                PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED).with_message(format!(
                    "Exceeded maximum type tag limit of {} when charging {}",
                    self.max_cost, amount
                )),
            )
        } else {
            Ok(())
        }
    }
```

**File:** aptos-move/framework/src/natives/string_utils.rs (L613-613)
```rust
    context.charge(STRING_UTILS_PER_BYTE * NumBytes::new(fmt.len() as u64))?;
```

**File:** aptos-move/framework/src/natives/string_utils.rs (L616-618)
```rust
        if let TypeTag::Struct(struct_tag) = context
            .type_to_type_tag(list_ty)
            .map_err(SafeNativeError::InvariantViolation)?
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L86-89)
```rust
        if self.has_direct_gas_meter_access_in_native_context() {
            self.gas_meter()
                .charge_native_execution(amount)
                .map_err(LimitExceededError::from_err)?;
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L92-92)
```rust
            self.legacy_gas_used += amount;
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L76-76)
```rust
pub const LATEST_GAS_FEATURE_VERSION: u64 = gas_feature_versions::RELEASE_V1_41;
```

**File:** aptos-move/framework/aptos-stdlib/sources/string_utils.move (L40-40)
```text
        native_format_list(fmt, &list1(a))
```
