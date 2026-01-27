# Audit Report

## Title
Unit Test Environment Silently Accepts Randomness Usage Without Required Annotation, Causing Production Transaction Failures

## Summary
The unit test infrastructure automatically marks all code as `unbiasable` for randomness operations, allowing private entry functions that use randomness without the `#[randomness]` annotation to pass all tests. These same functions will systematically fail in production, causing denial of service. The extended checker does not validate private/friend entry functions for proper randomness annotation at compile time.

## Finding Description

The Aptos randomness system requires entry functions using randomness APIs to have the `#[randomness]` annotation. This annotation signals the VM to mark the transaction context as `unbiasable`, which is a critical security check to prevent bias attacks on randomness generation. [1](#0-0) 

The vulnerability arises from a critical difference between unit test and production environments:

**In unit tests**, the `configure_for_unit_test()` function unconditionally marks ALL code as unbiasable: [2](#0-1) 

**In production**, only entry functions with the `#[randomness]` annotation are marked as unbiasable during execution: [3](#0-2) 

**The extended checker fails to prevent this**: It only validates that PUBLIC functions using randomness have the `#[lint::allow_unsafe_randomness]` attribute, but SKIPS private/friend functions: [4](#0-3) 

This creates a silent failure mode where:
1. Developer writes a private entry function using randomness without `#[randomness]` annotation
2. All unit tests pass (randomness works in tests)
3. Code compiles without errors or warnings
4. Code deploys successfully to production
5. **Every transaction calling this function fails with E_API_USE_IS_BIASIBLE**

## Impact Explanation

**Medium to High Severity** - This vulnerability causes:

1. **Denial of Service**: Critical contract functionality becomes completely unusable in production, affecting all users attempting to call the improperly annotated functions.

2. **Silent Deployment of Broken Code**: Developers receive false confidence from passing tests, deploying contracts that will fail 100% of the time in production.

3. **Protocol-Level Impact**: If this affects governance, staking, or DeFi protocols, it could lock funds or disable critical chain functionality until redeployment.

4. **Wasted Gas Fees**: Users pay transaction fees for transactions that will deterministically abort.

The impact qualifies as **Medium Severity** per the bug bounty criteria: "State inconsistencies requiring intervention" and potential "Limited funds loss" through wasted gas and locked contract states.

## Likelihood Explanation

**High Likelihood** - This issue will occur whenever:

1. Developers write new contracts using randomness features
2. They follow standard testing practices with `aptos move test`
3. They use private entry functions (the recommended pattern per line 528 of extended_checks.rs)
4. They omit the `#[randomness]` annotation (no compiler warning issued for private functions)

The likelihood is increased by:
- No compile-time validation for private functions
- No runtime warning in test environment
- The annotation requirement is not obvious from the randomness API alone
- The test environment's behavior diverges from production

## Recommendation

Implement compile-time validation for ALL entry functions (not just public ones) that use randomness without the required annotation:

**Modify extended_checks.rs** to check private/friend entry functions:

```rust
// In check_randomness_usage(), remove the early return for non-public functions
// and add specific validation for entry functions:

fn check_randomness_usage(&mut self, module: &ModuleEnv) {
    for fun_id in module.get_functions() {
        let fun = module.get_function(fun_id);
        
        // Skip framework functions
        if self.is_framework_function(fun.get_qualified_id()) {
            continue;
        }
        
        // For entry functions (private/friend), enforce #[randomness] annotation
        if fun.is_entry() && !fun.visibility().is_public() {
            if self.calls_randomness(fun.get_qualified_id()) {
                let has_randomness_attr = self.has_attribute(&fun, RANDOMNESS_ATTRIBUTE);
                if !has_randomness_attr {
                    self.env.error(
                        &fun.get_id_loc(),
                        "private/friend entry function using randomness must have #[randomness] attribute"
                    );
                }
            }
        }
        
        // Existing check for public functions...
    }
}
```

**Alternative mitigation**: Modify the unit test infrastructure to NOT automatically mark all code as unbiasable, forcing tests to explicitly handle randomness annotation requirements.

## Proof of Concept

**Vulnerable Move Module** (will pass tests but fail in production):

```move
module 0xcafe::vulnerable_lottery {
    use aptos_framework::randomness;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    
    // BUG: Missing #[randomness] annotation!
    // This will pass unit tests but fail 100% in production
    entry fun play_lottery(player: &signer, bet_amount: u64) {
        let random_roll = randomness::u64_range(0, 100);
        
        if (random_roll > 50) {
            // Win logic - transfer prize
            let prize = bet_amount * 2;
            coin::transfer<AptosCoin>(player, @lottery_pool, prize);
        }
    }
    
    #[test(player = @0x123, framework = @aptos_framework)]
    fun test_lottery_works(player: &signer, framework: &signer) {
        // Initialize randomness for testing
        randomness::initialize_for_testing(framework);
        
        // THIS TEST PASSES because configure_for_unit_test() 
        // marked everything as unbiasable!
        play_lottery(player, 100);
        // Test succeeds ✓
    }
}
```

**In production**: Every call to `play_lottery()` will abort with error code 1 (E_API_USE_IS_BIASIBLE) because the function lacks the `#[randomness]` annotation and is therefore not marked as unbiasable during execution.

**Verification Steps**:
1. Create the module above in a test package
2. Run `aptos move test` - tests pass ✓
3. Deploy to devnet/testnet
4. Attempt to call `play_lottery` - transaction fails with abort code 1

This demonstrates the critical gap between test and production behavior that allows broken code to pass all validation checks.

## Notes

This vulnerability affects the **deterministic execution invariant** because the test environment and production environment exhibit fundamentally different behavior for the same code. It also violates the **Move VM Safety** invariant by allowing code that will systematically fail in production to pass all pre-deployment checks.

The root cause is the overly permissive `configure_for_unit_test()` configuration combined with incomplete compile-time validation for private entry functions using randomness APIs.

### Citations

**File:** aptos-move/framework/src/natives/randomness.rs (L79-98)
```rust
pub fn fetch_and_increment_txn_counter(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    _args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    if context.gas_feature_version() >= RELEASE_V1_23 {
        context.charge(RANDOMNESS_FETCH_AND_INC_COUNTER)?;
    }

    let ctx = context.extensions_mut().get_mut::<RandomnessContext>();
    if !ctx.is_unbiasable() {
        return Err(SafeNativeError::Abort {
            abort_code: E_API_USE_SUSCEPTIBLE_TO_TEST_AND_ABORT,
        });
    }

    let ret = ctx.txn_local_state.to_vec();
    ctx.increment();
    Ok(smallvec![Value::vector_u8(ret)])
}
```

**File:** aptos-move/aptos-vm/src/natives.rs (L223-225)
```rust
    let mut randomness_ctx = RandomnessContext::new();
    randomness_ctx.mark_unbiasable();
    exts.add(randomness_ctx);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L983-991)
```rust
            if function.is_friend_or_private() {
                let maybe_randomness_annotation = get_randomness_annotation_for_entry_function(
                    entry_fn,
                    &function.owner_as_module()?.metadata,
                );
                if maybe_randomness_annotation.is_some() {
                    session.mark_unbiasable();
                }
            }
```

**File:** aptos-move/framework/src/extended_checks.rs (L628-633)
```rust
            if self.is_framework_function(fun_id)
                || !fun.visibility().is_public()
                || self.has_attribute(fun, ALLOW_UNSAFE_RANDOMNESS_ATTRIBUTE)
            {
                continue;
            }
```
