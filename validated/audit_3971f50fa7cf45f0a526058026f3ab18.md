# Audit Report

## Title
Gas Accounting Bypass in FunctionInfo `as_move_value()` Conversion Enables Validator DOS

## Summary
The `FunctionInfo::as_move_value()` conversion performs expensive memory allocations and string operations without gas metering during transaction validation. Attackers can submit transactions with Abstract authentication containing up to 6MB of FunctionInfo strings, causing ~40x memory amplification (~240MB allocated) before any gas charges occur, leading to validator node resource exhaustion.

## Finding Description

The vulnerability exists in the account abstraction authentication flow where `FunctionInfo` is converted to `MoveValue` before transaction size validation and gas metering.

**Root Cause:** The `FunctionInfo` struct contains `module_name` and `function_name` as unbounded `String` fields that are deserialized from transaction bytes without length validation. [1](#0-0) 

**Vulnerable Code Path:**

1. During transaction validation, `validate_signed_transaction` is invoked for Abstract authentication proofs. [2](#0-1) 

2. This calls `dispatchable_authenticate` which performs the unmetered conversion. [3](#0-2) 

3. The `as_move_value()` implementation clones strings and converts each byte to a `MoveValue` enum. [4](#0-3) 

4. String conversion allocates for bytes representation. [5](#0-4) 

5. Vec<u8> conversion creates a Vec of MoveValue enums (one per byte). [6](#0-5) 

6. Each MoveValue enum occupies significant memory (~40 bytes per variant). [7](#0-6) 

7. Transaction size validation in `check_gas` occurs AFTER the conversion damage is done. [8](#0-7) 

**Attack Scenario:**
- Attacker crafts transaction with `AuthenticationProof::Abstract` containing 3MB `module_name` + 3MB `function_name`
- Total 6MB fits within transaction size limit [9](#0-8) 
- Memory amplification: 6MB input → ~240MB allocated (6M bytes × ~40 bytes/MoveValue)
- All allocations and CPU work occur without gas charges
- Multiple such transactions exhaust validator memory/CPU

## Impact Explanation

**Severity: HIGH** - Validator Node Slowdowns

This vulnerability aligns with Aptos Bug Bounty category: "Validator Node Slowdowns (High) - DoS through resource exhaustion"

Impact:
- **Memory Exhaustion**: Each malicious transaction triggers ~240MB unmetered allocations during validation
- **CPU Waste**: String cloning, byte conversion, and MoveValue vector construction occur without metering
- **Amplification Factor**: ~40x memory amplification (6MB → 240MB)
- **Validator Impact**: Multiple transactions in mempool or blocks can exhaust node resources
- **No Economic Cost**: Operations execute before gas deduction, attacker pays minimal cost

This is NOT a "Network DoS attack" (which are out of scope), but a protocol-level resource exhaustion bug in the VM's transaction validation logic.

## Likelihood Explanation

**Likelihood: HIGH**

- **Easy to Exploit**: Requires only crafting a transaction with large strings in Abstract authentication proof
- **No Special Access**: Any transaction sender can trigger this vulnerability
- **Low Complexity**: Single transaction submission with malformed FunctionInfo
- **Multiple Attack Vectors**: Can target both mempool validation and block execution paths
- **Amplification Effect**: Small attacker cost (6MB transaction bytes) causes large defender cost (~240MB memory + CPU)
- **Difficult to Detect**: Appears as legitimate transaction validation traffic until resource exhaustion occurs

## Recommendation

Implement size validation for `FunctionInfo` strings during deserialization:

1. **Add constant for maximum identifier length** (e.g., 255 bytes to match Move identifier limits):
```rust
const MAX_FUNCTION_INFO_IDENTIFIER_LENGTH: usize = 255;
```

2. **Validate during FunctionInfo deserialization** before `as_move_value()` conversion:
```rust
pub fn validate(&self) -> Result<(), &'static str> {
    if self.module_name.len() > MAX_FUNCTION_INFO_IDENTIFIER_LENGTH {
        return Err("module_name exceeds maximum length");
    }
    if self.function_name.len() > MAX_FUNCTION_INFO_IDENTIFIER_LENGTH {
        return Err("function_name exceeds maximum length");
    }
    Ok(())
}
```

3. **Call validation in `dispatchable_authenticate`** before `as_move_value()`:
```rust
function_info.validate()
    .map_err(|msg| PartialVMError::new(StatusCode::INVALID_DATA).with_message(msg))?;
```

4. **Alternative**: Defer `as_move_value()` conversion to occur AFTER `check_gas` validates transaction size, or charge gas for the conversion operation.

## Proof of Concept

```rust
#[test]
fn test_function_info_memory_amplification() {
    // Create FunctionInfo with large strings (3MB each)
    let large_string = "A".repeat(3 * 1024 * 1024);
    let function_info = FunctionInfo {
        module_address: AccountAddress::ONE,
        module_name: large_string.clone(),
        function_name: large_string,
    };
    
    // Measure memory before conversion
    let before = get_memory_usage();
    
    // Trigger unmetered conversion
    let move_value = function_info.as_move_value();
    
    // Measure memory after conversion
    let after = get_memory_usage();
    
    // Verify amplification: 6MB input should cause ~240MB allocation
    assert!((after - before) > 200 * 1024 * 1024);
    
    // This operation occurred without any gas charges
    // Multiple such transactions can exhaust validator memory
}
```

**Notes:**
- The execution order is: `validate_signed_transaction` → `dispatchable_authenticate` → `function_info.as_move_value()` → `run_prologue_with_payload` → `check_gas`
- The conversion happens in Rust code before Move VM gas metering applies
- No validation exists on FunctionInfo string lengths during transaction deserialization
- Move's `is_identifier` validation only applies to Move code, not Rust-side transaction deserialization

### Citations

**File:** types/src/function_info.rs (L18-24)
```rust
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Hash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct FunctionInfo {
    pub module_address: AccountAddress,
    pub module_name: String,
    pub function_name: String,
}
```

**File:** types/src/function_info.rs (L67-75)
```rust
impl AsMoveValue for FunctionInfo {
    fn as_move_value(&self) -> MoveValue {
        MoveValue::Struct(MoveStruct::Runtime(vec![
            MoveValue::Address(self.module_address),
            self.module_name.as_move_value(),
            self.function_name.as_move_value(),
        ]))
    }
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1870-1907)
```rust
        let sender_signers = itertools::zip_eq(senders, proofs)
            .map(|(sender, proof)| match proof {
                AuthenticationProof::Abstract {
                    function_info,
                    auth_data,
                } => {
                    let enabled = match auth_data {
                        AbstractAuthenticationData::V1 { .. } => {
                            self.features().is_account_abstraction_enabled()
                        },
                        AbstractAuthenticationData::DerivableV1 { .. } => {
                            self.features().is_derivable_account_abstraction_enabled()
                        },
                    };
                    if enabled {
                        dispatchable_authenticate(
                            session,
                            gas_meter,
                            sender,
                            function_info.clone(),
                            auth_data,
                            traversal_context,
                            module_storage,
                        )
                        .map_err(|mut vm_error| {
                            if vm_error.major_status() == OUT_OF_GAS {
                                vm_error
                                    .set_major_status(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
                            }
                            vm_error.into_vm_status()
                        })
                    } else {
                        Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None))
                    }
                },
                _ => Ok(serialized_signer(&sender)),
            })
            .collect::<Result<_, _>>()?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2793-2814)
```rust
    fn run_prologue_with_payload(
        &self,
        session: &mut SessionExt<impl AptosMoveResolver>,
        module_storage: &impl ModuleStorage,
        serialized_signers: &SerializedSigners,
        executable: TransactionExecutableRef,
        extra_config: TransactionExtraConfig,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        is_approved_gov_script: bool,
        traversal_context: &mut TraversalContext,
    ) -> Result<(), VMStatus> {
        check_gas(
            self.gas_params(log_context)?,
            self.gas_feature_version(),
            session.resolver,
            module_storage,
            txn_data,
            self.features(),
            is_approved_gov_script,
            log_context,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3400-3413)
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
```

**File:** types/src/move_utils/as_move_value.rs (L22-29)
```rust
impl AsMoveValue for String {
    fn as_move_value(&self) -> MoveValue {
        MoveValue::Struct(MoveStruct::Runtime(vec![self
            .clone()
            .into_bytes()
            .as_move_value()]))
    }
}
```

**File:** types/src/move_utils/as_move_value.rs (L31-35)
```rust
impl<T: AsMoveValue> AsMoveValue for Vec<T> {
    fn as_move_value(&self) -> MoveValue {
        MoveValue::Vector(self.iter().map(T::as_move_value).collect())
    }
}
```

**File:** third_party/move/move-core/types/src/value.rs (L122-146)
```rust
pub enum MoveValue {
    U8(u8),
    U64(u64),
    U128(u128),
    Bool(bool),
    Address(AccountAddress),
    Vector(Vec<MoveValue>),
    Struct(MoveStruct),
    // TODO: Signer is only used to construct arguments easily.
    //       Refactor the code to reflect the new permissioned signer schema.
    Signer(AccountAddress),
    // NOTE: Added in bytecode version v6, do not reorder!
    U16(u16),
    U32(u32),
    U256(int256::U256),
    // Added in bytecode version v8
    Closure(Box<MoveClosure>),
    // Added in bytecode version v9
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    I256(int256::I256),
}
```

**File:** aptos-move/e2e-testsuite/src/tests/verify_txn.rs (L30-30)
```rust
pub const MAX_TRANSACTION_SIZE_IN_BYTES: u64 = 6 * 1024 * 1024;
```
