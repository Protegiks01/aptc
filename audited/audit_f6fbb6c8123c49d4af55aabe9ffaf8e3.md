# Audit Report

## Title
Consensus Failure via Build Configuration Non-Determinism in Move Bytecode Verifier

## Summary
The `safe_unwrap!` macro in the Move bytecode verifier exhibits build-dependent behavior that can cause consensus divergence when validators run different build configurations (debug vs release). When triggered during module verification, this produces different error codes that propagate into the consensus state commitment, causing validators to disagree on transaction execution results.

## Finding Description

The `safe_unwrap!` macro is defined with compile-time conditional behavior: [1](#0-0) 

This macro is used extensively in type safety verification: [2](#0-1) 

The verification occurs during consensus block execution when modules are published: [3](#0-2) 

When the macro is triggered:
- **Debug builds**: The macro panics, which is caught by `catch_unwind` and returns `StatusCode::VERIFIER_INVARIANT_VIOLATION` (2016)
- **Release builds**: The macro returns `StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR` (2000) [4](#0-3) 

These different error codes become part of `ExecutionStatus::MiscellaneousError(Option<StatusCode>)`: [5](#0-4) 

The `ExecutionStatus` is embedded in `TransactionInfo`, which is cryptographically hashed for consensus: [6](#0-5) 

The `TransactionInfo` hash is added to the transaction accumulator, whose root hash is committed in `LedgerInfo` signed by validators: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Critical Severity** - This is a consensus safety violation. If validators running different build configurations process the same malicious module:

1. Debug validators produce `TransactionInfo` with status code 2016
2. Release validators produce `TransactionInfo` with status code 2000  
3. Different `TransactionInfo` hashes lead to different transaction accumulator roots
4. Different accumulator roots lead to different `LedgerInfo` hashes
5. Validators cannot reach 2f+1 agreement on the same `LedgerInfo`
6. **Consensus halts or the network partitions**

This breaks the fundamental invariant: "All validators must produce identical state roots for identical blocks."

## Likelihood Explanation

**Low Likelihood** - This vulnerability has significant practical limitations:

1. **Requires mixed build configurations**: Production networks should deploy only release builds. Debug builds occurring in production would be a deployment error.

2. **Requires triggering the macro**: The `safe_unwrap!` is designed for invariant violations that "should never happen" if bytecode verification is correct. To trigger it, an attacker would need to craft bytecode that:
   - Passes `StackUsageVerifier` (which validates stack balance)
   - But causes `type_safety::verify` to encounter an empty stack
   - This requires finding a bug in the verifier itself

3. **Defense in depth**: The `catch_unwind` wrapper prevents crashes, but the error code difference remains.

However, the vulnerability is real because:
- Even a single debug-build validator in the network can cause consensus issues
- Verifier bugs (while rare) have been discovered in production blockchain systems
- Testnet/devnet environments commonly run debug builds and could exhibit this issue

## Recommendation

Make the `safe_unwrap!` macro behavior deterministic across build configurations by always returning an error instead of panicking:

```rust
#[macro_export]
macro_rules! safe_unwrap {
    ($e:expr) => {{
        match $e {
            Some(x) => x,
            None => {
                let err = PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(format!("{}:{} (none)", file!(), line!()));
                return Err(err);
            },
        }
    }};
}
```

Additionally, add compile-time assertions to prevent debug builds in production:

```rust
#[cfg(all(debug_assertions, not(feature = "allow_debug_build")))]
compile_error!("Debug builds are not allowed in production. Use --release flag.");
```

## Proof of Concept

While I cannot provide bytecode that triggers the verifier invariant violation without finding a separate verifier bug, I can demonstrate the non-determinism:

```rust
// Compile this test twice: once with --release and once in debug mode
// and observe different error codes

#[test]
fn test_build_dependent_verification() {
    use move_binary_format::errors::{PartialVMError, PartialVMResult};
    use move_core_types::vm_status::StatusCode;
    
    // Simulate the safe_unwrap! behavior
    fn simulate_safe_unwrap(opt: Option<i32>) -> PartialVMResult<i32> {
        match opt {
            Some(x) => Ok(x),
            None => {
                let err = PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR);
                if cfg!(debug_assertions) {
                    panic!("{:?}", err);  // Debug: panics
                } else {
                    return Err(err);       // Release: returns error
                }
            },
        }
    }
    
    let result = std::panic::catch_unwind(|| {
        simulate_safe_unwrap(None)
    });
    
    match result {
        Ok(Err(e)) => {
            // Release build path
            assert_eq!(e.major_status(), StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR);
            println!("Release build: error code 2000");
        },
        Err(_) => {
            // Debug build path (panic was caught)
            println!("Debug build: would return error code 2016 after catch_unwind");
        },
        _ => unreachable!(),
    }
}
```

To observe consensus divergence in a test network:
1. Deploy a network with mixed debug/release validators
2. Submit a module that triggers verifier edge cases
3. Monitor `TransactionInfo` hashes across validators
4. Observe different hashes leading to consensus disagreement

### Citations

**File:** third_party/move/move-binary-format/src/lib.rs (L134-153)
```rust
/// A macro which should be preferred in critical runtime paths for unwrapping an option
/// if a `PartialVMError` is expected. In debug mode, this will panic. Otherwise
/// we return an Err.
#[macro_export]
macro_rules! safe_unwrap {
    ($e:expr) => {{
        match $e {
            Some(x) => x,
            None => {
                let err = PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(format!("{}:{} (none)", file!(), line!()));
                if cfg!(debug_assertions) {
                    panic!("{:?}", err);
                } else {
                    return Err(err);
                }
            },
        }
    }};
}
```

**File:** third_party/move/move-bytecode-verifier/src/type_safety.rs (L130-149)
```rust
// helper for both `ImmBorrowField` and `MutBorrowField`
fn borrow_field(
    verifier: &mut TypeSafetyChecker,
    meter: &mut impl Meter,
    offset: CodeOffset,
    mut_: bool,
    field_handle_index: FieldOrVariantIndex,
    type_args: &Signature,
) -> PartialVMResult<()> {
    // load operand and check mutability constraints
    let operand = safe_unwrap!(verifier.stack.pop());
    if mut_ && !operand.is_mutable_reference() {
        return Err(verifier.error(StatusCode::BORROWFIELD_TYPE_MISMATCH_ERROR, offset));
    }

    // check the reference on the stack is the expected type.
    // Load the type that owns the field according to the instruction.
    // For generic fields access, this step materializes that type
    let (struct_def_index, variants, field_idx) = match field_handle_index {
        FieldOrVariantIndex::FieldIndex(idx) => {
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L245-257)
```rust
            if is_lazy_loading_enabled {
                // Local bytecode verification.
                staged_runtime_environment.paranoid_check_module_address_and_name(
                    compiled_module,
                    compiled_module.self_addr(),
                    compiled_module.self_name(),
                )?;
                let locally_verified_code = staged_runtime_environment
                    .build_locally_verified_module(
                        compiled_module.clone(),
                        bytes.len(),
                        &sha3_256(bytes),
                    )?;
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L134-173)
```rust
pub fn verify_module_with_config(config: &VerifierConfig, module: &CompiledModule) -> VMResult<()> {
    if config.verify_nothing() {
        return Ok(());
    }
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
    result
}
```

**File:** types/src/transaction/mod.rs (L1485-1503)
```rust
/// The status of VM execution, which contains more detailed failure info
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
#[cfg_attr(any(test, feature = "fuzzing"), proptest(no_params))]
pub enum ExecutionStatus {
    Success,
    OutOfGas,
    MoveAbort {
        location: AbortLocation,
        code: u64,
        info: Option<AbortInfo>,
    },
    ExecutionFailure {
        location: AbortLocation,
        function: u16,
        code_offset: u16,
    },
    MiscellaneousError(Option<StatusCode>),
}
```

**File:** types/src/transaction/mod.rs (L2023-2051)
```rust
#[derive(Clone, CryptoHasher, BCSCryptoHash, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TransactionInfoV0 {
    /// The amount of gas used.
    gas_used: u64,

    /// The vm status. If it is not `Executed`, this will provide the general error class. Execution
    /// failures and Move abort's receive more detailed information. But other errors are generally
    /// categorized with no status code or other information
    status: ExecutionStatus,

    /// The hash of this transaction.
    transaction_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during this transaction.
    event_root_hash: HashValue,

    /// The hash value summarizing all changes caused to the world state by this transaction.
    /// i.e. hash of the output write set.
    state_change_hash: HashValue,

    /// The root hash of the Sparse Merkle Tree describing the world state at the end of this
    /// transaction. Depending on the protocol configuration, this can be generated periodical
    /// only, like per block.
    state_checkpoint_hash: Option<HashValue>,

    /// The hash value summarizing PersistedAuxiliaryInfo.
    auxiliary_info_hash: Option<HashValue>,
}
```

**File:** types/src/ledger_info.rs (L51-90)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct LedgerInfo {
    commit_info: BlockInfo,

    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl Display for LedgerInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "LedgerInfo: [commit_info: {}] [Consensus data hash: {}]",
            self.commit_info(),
            self.consensus_data_hash()
        )
    }
}

impl LedgerInfo {
    pub fn dummy() -> Self {
        Self {
            commit_info: BlockInfo::empty(),
            consensus_data_hash: HashValue::zero(),
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.commit_info.is_empty() && self.consensus_data_hash == HashValue::zero()
    }

    /// Constructs a `LedgerInfo` object based on the given commit info and vote data hash.
    pub fn new(commit_info: BlockInfo, consensus_data_hash: HashValue) -> Self {
        Self {
            commit_info,
            consensus_data_hash,
        }
    }
```

**File:** types/src/block_info.rs (L29-44)
```rust
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
}
```
