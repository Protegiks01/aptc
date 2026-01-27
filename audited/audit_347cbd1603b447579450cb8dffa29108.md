# Audit Report

## Title
Gas Metering Bypass in Native Function Dispatch - Missing CALL_PER_LOCAL Charges for Dispatched Functions

## Summary
The `NativeResult::CallFunction` dispatch mechanism bypasses the `charge_call()` gas metering for dispatched functions, resulting in systematic gas undercharging. Dispatched functions avoid paying the per-local-variable gas cost (`CALL_PER_LOCAL`), allowing attackers to execute functions with many local variables while paying significantly less gas than equivalent direct function calls.

## Finding Description

The Move VM's native function dispatch mechanism allows natives to redirect execution to other Move functions via `NativeResult::CallFunction`. This is used by `dispatchable_fungible_asset` and `account_abstraction` modules to enable custom transfer logic. [1](#0-0) 

When a native returns `CallFunction`, the VM charges only the cost specified in the variant, then creates a new call frame for the target function: [2](#0-1) 

The critical issue is that the dispatched function never receives a `charge_call()` invocation. In normal function calls, `charge_call()` is invoked before execution: [3](#0-2) 

The `charge_call()` implementation charges based on arguments AND local variables in feature version 3+: [4](#0-3) 

With gas parameters: [5](#0-4) 

**Exploitation Path:**

1. Attacker creates a custom fungible asset with registered dispatch functions
2. The custom withdraw/deposit functions contain many local variables (e.g., 50+ locals for complex business logic)
3. Each transfer calls the native dispatcher (e.g., `dispatchable_withdraw`)
4. Native charges only `DISPATCHABLE_FUNGIBLE_ASSET_DISPATCH_BASE` (551 gas): [6](#0-5) [7](#0-6) 

5. The dispatched function executes but skips the `charge_call()` that would charge `CALL_PER_LOCAL * num_locals`

**Gas Undercharging Calculation:**

For a dispatched function with N arguments and L local variables:
- **Direct call cost:** `CALL_BASE + CALL_PER_ARG * N + CALL_PER_LOCAL * L = 3676 + 367*N + 367*L`
- **Via dispatch cost:** `CALL_BASE + CALL_PER_ARG * (N+1) + DISPATCH_BASE = 3676 + 367*(N+1) + 551 = 4594 + 367*N`
- **Missing charge:** `367 * L - 918`

Examples:
- L=10 locals: **2,752 gas undercharged**
- L=20 locals: **6,422 gas undercharged**  
- L=50 locals: **17,432 gas undercharged**
- L=100 locals: **35,782 gas undercharged**

A transaction with 100 transfers of a token with 50-local dispatch functions would save **~1.74 million gas units**.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program:

1. **Validator Node Slowdowns**: Transactions can perform substantially more computation than paid for, causing blocks to take longer to execute than the gas limit would suggest, degrading network performance.

2. **Gas Metering Bypass**: Breaks the fundamental invariant that "Move VM Safety: Bytecode execution must respect gas limits and memory constraints" and "Resource Limits: All operations must respect gas, storage, and computational limits."

3. **Economic Attack Vector**: Attackers can create complex dispatchable tokens where each transfer saves thousands of gas units, enabling transactions that consume validator resources disproportionate to their gas payment.

4. **Consensus Impact**: All validators execute the same undercharged transactions, so while this doesn't break consensus safety (determinism is preserved), it degrades liveness by allowing resource exhaustion attacks.

The issue affects core gas metering infrastructure and is exploitable through the documented dispatchable fungible asset feature introduced in AIP-73: [8](#0-7) 

## Likelihood Explanation

**High Likelihood** - The vulnerability is:

1. **Easy to exploit**: Any user can deploy custom fungible assets with dispatch functions
2. **Incentivized**: Attackers save gas costs proportional to the number of locals in dispatch functions
3. **Undetectable**: The dispatch mechanism is a documented feature; creating functions with many locals is legitimate
4. **Scalable**: A single transaction can include multiple transfers, multiplying the gas savings

The dispatchable fungible asset feature is actively used in production for custom transfer logic (deflation tokens, allowlists, loyalty tokens), making this a practical attack vector.

## Recommendation

**Solution 1 (Comprehensive Fix):**
Charge `CALL_PER_LOCAL` when setting up the dispatched function's call frame. In `interpreter.rs`, modify the `CallFunction` handler:

```rust
NativeResult::CallFunction { cost, module_name, func_name, ty_args, args } => {
    gas_meter.charge_native_function(cost, Option::<std::iter::Empty<&Value>>::None)?;
    
    let ty_args_id = self.ty_pool.intern_ty_args(&ty_args);
    let target_func = current_frame.build_loaded_function_from_name_and_ty_args(...)?;
    
    // NEW: Charge for local variables in the dispatched function
    let num_locals = target_func.local_tys().len() as u64;
    gas_meter.charge_call_locals(NumArgs::new(num_locals))?;
    
    // ... rest of the dispatch logic
}
```

Add to `GasMeter` trait:
```rust
fn charge_call_locals(&mut self, num_locals: NumArgs) -> PartialVMResult<()>;
```

**Solution 2 (Adjust Dispatch Base Cost):**
Increase `DISPATCHABLE_FUNGIBLE_ASSET_DISPATCH_BASE` to account for typical local variable counts. However, this is imprecise as different dispatch targets have different local counts.

**Solution 3 (Account in Native):**
Require natives to inspect the target function's local count and include it in their reported cost. This is complex and error-prone.

**Recommended: Solution 1** - It properly mirrors the gas charging semantics of regular function calls.

## Proof of Concept

```move
// File: exploit_token.move
module attacker::exploit_token {
    use aptos_framework::fungible_asset::{Self, FungibleAsset, TransferRef};
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::object::{ConstructorRef, Object};
    use aptos_framework::function_info;
    use std::option;
    use std::signer;
    use std::string;

    public fun initialize(account: &signer, constructor_ref: &ConstructorRef) {
        let withdraw = function_info::new_function_info(
            account,
            string::utf8(b"exploit_token"),
            string::utf8(b"expensive_withdraw"),
        );
        
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::none(),
            option::none()
        );
    }

    // Dispatch target with 100 local variables to maximize gas savings
    public fun expensive_withdraw<T: key>(
        store: Object<T>,
        amount: u64,
        transfer_ref: &TransferRef,
    ): FungibleAsset {
        // 100 local variables - each saves 367 gas units
        let l1 = 0; let l2 = 0; let l3 = 0; let l4 = 0; let l5 = 0;
        let l6 = 0; let l7 = 0; let l8 = 0; let l9 = 0; let l10 = 0;
        // ... repeat to l100
        
        // Do some work with locals to prevent optimization
        l1 = amount;
        l2 = l1 + 1;
        // ... use all locals
        
        // Actual withdraw logic
        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }
}
```

**Expected Gas Savings:**
- Normal call: 3676 + 367*3 + 367*103 = 41,477 gas (3 params + 100 locals + function overhead)
- Via dispatch: 3676 + 367*4 + 551 = 5,695 gas (4 params including selector)
- **Savings: 35,782 gas per transfer** (86% reduction)

**Attack Scenario:**
1. Deploy `exploit_token` with 100-local dispatch function
2. Execute transaction with 100 transfers
3. Pay ~570K gas instead of expected ~4.1M gas
4. Consume validator resources worth ~4.1M gas while only being charged ~570K gas
5. Repeat to degrade network performance

### Citations

**File:** third_party/move/move-vm/types/src/natives/function.rs (L54-60)
```rust
    CallFunction {
        cost: InternalGas,
        module_name: ModuleId,
        func_name: Identifier,
        ty_args: Vec<Type>,
        args: SmallVec<[Value; 1]>,
    },
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L510-519)
```rust
                    gas_meter
                        .charge_call(
                            function.owner_as_module()?.self_id(),
                            function.name(),
                            self.operand_stack
                                .last_n(function.param_tys().len())
                                .map_err(|e| set_err_info!(current_frame, e))?,
                            (function.local_tys().len() as u64).into(),
                        )
                        .map_err(|e| set_err_info!(current_frame, e))?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1168-1175)
```rust
            NativeResult::CallFunction {
                cost,
                module_name,
                func_name,
                ty_args,
                args,
            } => {
                gas_meter.charge_native_function(cost, Option::<std::iter::Empty<&Value>>::None)?;
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L250-265)
```rust
    fn charge_call(
        &mut self,
        _module_id: &ModuleId,
        _func_name: &str,
        args: impl ExactSizeIterator<Item = impl ValueView>,
        num_locals: NumArgs,
    ) -> PartialVMResult<()> {
        let cost = CALL_BASE + CALL_PER_ARG * NumArgs::new(args.len() as u64);

        match self.feature_version() {
            0..=2 => self.algebra.charge_execution(cost),
            3.. => self
                .algebra
                .charge_execution(cost + CALL_PER_LOCAL * num_locals),
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/instr.rs (L80-82)
```rust
        [call_base: InternalGas, "call.base", 3676],
        [call_per_arg: InternalGasPerArg, "call.per_arg", 367],
        [call_per_local: InternalGasPerArg, { 1.. => "call.per_local" }, 367],
```

**File:** aptos-move/framework/src/natives/dispatchable_fungible_asset.rs (L47-47)
```rust
    context.charge(DISPATCHABLE_FUNGIBLE_ASSET_DISPATCH_BASE)?;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L285-285)
```rust
        [dispatchable_fungible_asset_dispatch_base: InternalGas, { RELEASE_V1_13.. => "dispatchable_fungible_asset.dispatch.base" }, 551],
```

**File:** aptos-move/framework/aptos-framework/sources/dispatchable_fungible_asset.move (L1-16)
```text
/// This defines the fungible asset module that can issue fungible asset of any `Metadata` object. The
/// metadata object can be any object that equipped with `Metadata` resource.
///
/// The dispatchable_fungible_asset wraps the existing fungible_asset module and adds the ability for token issuer
/// to customize the logic for withdraw and deposit operations. For example:
///
/// - Deflation token: a fixed percentage of token will be destructed upon transfer.
/// - Transfer allowlist: token can only be transfered to addresses in the allow list.
/// - Predicated transfer: transfer can only happen when some certain predicate has been met.
/// - Loyalty token: a fixed loyalty will be paid to a designated address when a fungible asset transfer happens
///
/// The api listed here intended to be an in-place replacement for defi applications that uses fungible_asset api directly
/// and is safe for non-dispatchable (aka vanilla) fungible assets as well.
///
/// See AIP-73 for further discussion
///
```
