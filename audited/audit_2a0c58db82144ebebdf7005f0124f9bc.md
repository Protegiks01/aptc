# Audit Report

## Title
Entry Functions with Improper Signer Ordering Deploy Successfully but Become Permanently Non-Invocable, Locking Critical Functionality

## Summary
Entry functions with signer parameters appearing after non-signer parameters can be deployed on-chain (triggering only a compile-time warning) but are permanently non-invocable at runtime due to a validation mismatch in the argument handling logic. This can lock critical functionality such as fund withdrawals, governance actions, or emergency operations.

## Finding Description

The vulnerability stems from a critical mismatch between compile-time and runtime validation of entry function signatures:

**At Compile-Time (Warning Only):**
The extended checker issues a warning when entry functions have improper signer ordering: [1](#0-0) 

This warning allows the module to be compiled and deployed on-chain despite the improper signature.

**At Runtime (Hard Error):**
The runtime validation in `validate_combine_signer_and_txn_args` contains a logic bug: [2](#0-1) 

The code counts ALL signer parameters (regardless of position) but then assumes the first N parameters are signers when validating non-signer arguments: [3](#0-2) 

This causes validation to fail because signer types are explicitly not valid transaction arguments: [4](#0-3) 

**Attack Scenario:**
1. Developer writes an entry function handling critical operations (e.g., emergency withdrawals):
   ```move
   public entry fun emergency_withdraw(amount: u64, owner: &signer) {
       // Critical withdrawal logic
   }
   ```
2. Compiler issues WARNING (not error) about signer ordering
3. Module deploys successfully to blockchain
4. At runtime, ANY invocation attempt fails with `INVALID_MAIN_FUNCTION_SIGNATURE`
5. Funds or functionality locked permanently until module upgrade (if upgradeability is enabled)

**Evidence from Test Suite:**
The test suite confirms this behavior is known but treated as acceptable: [5](#0-4) 

Expected output shows warnings, not errors: [6](#0-5) 

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:
- **Limited funds loss or manipulation**: If the non-invocable function was intended to handle withdrawals, unlock operations, or emergency actions, those funds become inaccessible until a module upgrade
- **State inconsistencies requiring intervention**: Modules deployed with this bug require governance intervention or admin upgrade to fix

**Specific Impact Scenarios:**
1. **Fund Locking**: Treasury or vault withdrawal functions become non-invocable
2. **Governance Deadlock**: Critical governance functions (proposal execution, emergency actions) become unusable
3. **Staking Issues**: Unlock or unstake functions with improper signatures lock user funds
4. **Smart Contract Bricking**: Modules without upgrade capabilities become permanently unusable

The NonInvocablePublicScript diagnostic code exists but is never actually used: [7](#0-6) 

This suggests awareness of the issue but incomplete implementation of proper safeguards.

## Likelihood Explanation

**Medium-High Likelihood:**
- Developers may overlook warnings during development, especially if coming from other blockchain backgrounds where signer ordering is less strict
- The warning message is not explicit about runtime failure - it says "to be used as an entry function" but doesn't state it will be completely non-invocable
- No runtime prevention - modules deploy successfully despite the issue
- The test suite treats this as acceptable behavior (warnings only)

**Compounding Factors:**
- If upgradeability is disabled for security reasons, the module becomes permanently bricked
- Multi-sig or governance-controlled modules cannot be quickly fixed
- Users may deploy funds before discovering the function is non-invocable

## Recommendation

**Immediate Fix:**
Upgrade the compile-time warning to a blocking error for entry functions with improper signer ordering:

```rust
// In aptos-move/framework/src/extended_checks.rs, line 229-232
fn check_signer_args(&self, arg_tys: &[Parameter]) {
    let mut seen_non_signer = false;
    for Parameter(_, ty, loc) in arg_tys {
        let ty_is_signer = ty.skip_reference().is_signer();
        if seen_non_signer && ty_is_signer {
            // Change from warning to error
            self.env.error(  // Changed from self.env.warning
                loc,
                "entry function cannot have signer parameters after non-signer parameters",
            );
        }
        if !ty_is_signer {
            seen_non_signer = true;
        }
    }
}
```

**Additional Safeguards:**
1. Implement the NonInvocablePublicScript diagnostic properly as a compile-time error
2. Add runtime detection during module publishing to reject such modules
3. Add linter rules to catch this in IDE/CI pipelines
4. Update documentation to explicitly warn about this breaking behavior

## Proof of Concept

```move
module test_addr::vulnerable_module {
    use std::signer;
    
    struct Vault has key {
        balance: u64,
    }
    
    // This compiles with WARNING but cannot be invoked at runtime
    public entry fun emergency_withdraw(amount: u64, owner: &signer) {
        let owner_addr = signer::address_of(owner);
        // Critical withdrawal logic here
        // This code is UNREACHABLE due to runtime validation failure
    }
    
    // Correct version - signers first
    public entry fun proper_withdraw(owner: &signer, amount: u64) {
        let owner_addr = signer::address_of(owner);
        // This works correctly
    }
}
```

**Test Steps:**
1. Compile the module above - observe WARNING on `emergency_withdraw`
2. Deploy module to blockchain - succeeds
3. Attempt to invoke `emergency_withdraw` with arguments `[100]` - FAILS with `INVALID_MAIN_FUNCTION_SIGNATURE`
4. Invoke `proper_withdraw` with arguments `[100]` - succeeds

**Runtime Failure Evidence:**
Test showing script with signer in wrong position fails at runtime: [8](#0-7) 

## Notes

This vulnerability directly answers the security question about forward compatibility breaks. While the NonInvocablePublicScript diagnostic was intended to warn about future breaking changes, the breaking behavior already exists today - functions with improper signer ordering are non-invocable at runtime despite being deployable at compile-time.

The mismatch between compile-time warnings and runtime hard errors creates a dangerous deployment trap for developers, particularly those building critical financial or governance infrastructure on Aptos.

### Citations

**File:** aptos-move/framework/src/extended_checks.rs (L220-238)
```rust
    fn check_signer_args(&self, arg_tys: &[Parameter]) {
        // All signer args should precede non-signer args, for an entry function to be
        // used as an entry function.
        let mut seen_non_signer = false;
        for Parameter(_, ty, loc) in arg_tys {
            // We assume `&mut signer` are disallowed by checks elsewhere, so it is okay
            // for `skip_reference()` below to skip both kinds of reference.
            let ty_is_signer = ty.skip_reference().is_signer();
            if seen_non_signer && ty_is_signer {
                self.env.warning(
                    loc,
                    "to be used as an entry function, all signers should precede non-signers",
                );
            }
            if !ty_is_signer {
                seen_non_signer = true;
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L127-133)
```rust
    let mut signer_param_cnt = 0;
    // find all signer params at the beginning
    for ty in func.param_tys() {
        if ty.is_signer_or_signer_ref() {
            signer_param_cnt += 1;
        }
    }
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L139-149)
```rust
    for ty in func.param_tys()[signer_param_cnt..].iter() {
        let subst_res = ty_builder.create_ty_with_subst(ty, func.ty_args());
        let ty = subst_res.map_err(|e| e.finish(Location::Undefined).into_vm_status())?;
        let valid = is_valid_txn_arg(loader.runtime_environment(), &ty, allowed_structs);
        if !valid {
            return Err(VMStatus::error(
                StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE,
                None,
            ));
        }
    }
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L224-224)
```rust
        Signer | Reference(_) | MutableReference(_) | TyParam(_) | Function { .. } => false,
```

**File:** aptos-move/aptos-transactional-test-harness/tests/aptos_test_harness/entry_function_checks.move (L17-22)
```text
    // --- All these should be warnings ---

    entry fun one_signer_later(_x: u64, _s: &signer) {}

    entry fun multiple_signers_later(_x: u64, _y: u64, _s1: &signer, _z: u64, _s2: &signer) {}
}
```

**File:** aptos-move/aptos-transactional-test-harness/tests/aptos_test_harness/entry_function_checks.exp (L3-19)
```text
warning: to be used as an entry function, all signers should precede non-signers
   ┌─ TEMPFILE:12:41
   │
12 │     entry fun one_signer_later(_x: u64, _s: &signer) {}
   │                                         ^^

warning: to be used as an entry function, all signers should precede non-signers
   ┌─ TEMPFILE:13:56
   │
13 │     entry fun multiple_signers_later(_x: u64, _y: u64, _s1: &signer, _z: u64, _s2: &signer) {}
   │                                                        ^^^

warning: to be used as an entry function, all signers should precede non-signers
   ┌─ TEMPFILE:13:79
   │
13 │     entry fun multiple_signers_later(_x: u64, _y: u64, _s1: &signer, _z: u64, _s2: &signer) {}
   │                                                                               ^^^
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/diagnostics/codes.rs (L191-195)
```rust
        NonInvocablePublicScript: {
            msg: "script function cannot be invoked with this signature \
                (NOTE: this may become an error in the future)",
            severity: Warning
        },
```

**File:** aptos-move/e2e-move-tests/src/tests/scripts.rs (L151-187)
```rust
fn test_script_with_signer_parameter() {
    let mut h = MoveHarness::new();

    let alice = h.new_account_at(AccountAddress::from_hex_literal("0xa11ce").unwrap());

    let package = BuiltPackage::build(
        common::test_dir_path("script_with_signer.data/pack"),
        aptos_framework::BuildOptions::default(),
    )
    .expect("building package must succeed");

    let code = package.extract_script_code().into_iter().next().unwrap();

    let txn = TransactionBuilder::new(alice.clone())
        .script(Script::new(code, vec![], vec![
            TransactionArgument::U64(0),
            TransactionArgument::Serialized(
                MoveValue::Signer(*alice.address())
                    .simple_serialize()
                    .unwrap(),
            ),
        ]))
        .sequence_number(10)
        .max_gas_amount(1_000_000)
        .gas_unit_price(1)
        .sign();

    let status = h.run(txn);
    assert_eq!(
        status,
        TransactionStatus::Keep(
            aptos_types::transaction::ExecutionStatus::MiscellaneousError(Some(
                aptos_types::vm_status::StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE
            ))
        )
    );
}
```
