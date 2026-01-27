# Audit Report

## Title
Debug Natives Registered in Production VM Without Environment Validation Creating Consensus Non-Determinism Risk

## Summary
The `make_all()` function in `debug.rs` unconditionally registers debug native functions in production VM instances without validating that the build environment is test-only. While the implementation uses `cfg!(feature = "testing")` guards, this creates a consensus non-determinism vulnerability if validators compile with different feature flags, and an information disclosure risk if any validator enables testing features in production.

## Finding Description

The debug native functions are registered in **all** production VM instances without any validation: [1](#0-0) 

These natives are unconditionally included in the production VM environment: [2](#0-1) 

The production environment initialization calls this without restrictions: [3](#0-2) 

The debug module is published on-chain as part of aptos-stdlib with **public functions** callable by any Move code: [4](#0-3) 

This breaks the **Deterministic Execution** invariant: If Validator A compiles without `--features testing` and Validator B compiles with `--features testing`, executing the same transaction calling `aptos_std::debug::print()` will:
- Validator A: Execute as no-op
- Validator B: Print to stdout and potentially execute different code paths [5](#0-4) 

## Impact Explanation

**High Severity** - Significant protocol violation with potential for consensus issues:

1. **Consensus Non-Determinism**: Different validators with different compile-time features could execute transactions differently, risking state divergence
2. **Information Disclosure**: If any validator enables testing features, sensitive transaction data leaks to logs
3. **Attack Surface**: Unnecessary callable functions in production increase attack surface for future vulnerabilities

While current implementation has guards, the **lack of validation** means there's no enforcement preventing production deployment with testing features enabled.

## Likelihood Explanation

**Medium Likelihood**: Requires validator operator error (compiling with wrong features), but:
- No explicit warnings prevent this
- CI/CD pipeline errors could enable wrong features
- No runtime checks detect misconfiguration
- Multiple validators with different configurations is realistic in distributed environments

## Recommendation

Add explicit validation in `make_all()` to prevent registration in production:

```rust
pub fn make_all(
    builder: &SafeNativeBuilder,
) -> impl Iterator<Item = (String, NativeFunction)> + '_ {
    // Explicitly fail if debug natives are being registered in non-test builds
    if !cfg!(feature = "testing") {
        panic!("Debug natives must not be registered in production builds. \
                Remove debug::make_all() from production native registration.");
    }
    
    let natives = [
        ("native_print", native_print as RawSafeNative),
        ("native_stack_trace", native_stack_trace),
        ("print", native_old_debug_print),
        ("print_stack_trace", native_old_print_stacktrace),
    ];
    
    builder.make_named_natives(natives)
}
```

Better: Remove debug natives registration from production entirely by conditionally compiling the registration:

```rust
// In mod.rs
#[cfg(feature = "testing")]
add_natives_from_module!("debug", debug::make_all(builder));
```

## Proof of Concept

```move
// This Move code can be deployed and executed on-chain in production
script {
    use aptos_std::debug;
    
    fun test_debug_in_production() {
        // This function is PUBLIC and callable in production
        // If any validator compiled with --features testing, this leaks to logs
        debug::print(&b"Sensitive transaction data");
        debug::print_stack_trace();
    }
}
```

**Demonstration Steps:**
1. Deploy the above Move script to production network
2. If Validator A compiled without testing features: No-op execution
3. If Validator B compiled with testing features: Prints to validator logs
4. Result: Consensus non-determinism and information disclosure

**Notes**

The vulnerability exists at the **architecture level**: there's no validation preventing debug natives from being registered in production. While `cfg!(feature = "testing")` provides runtime guards, the lack of compile-time or registration-time validation means:

- No explicit error if production builds accidentally include testing features
- No protection against heterogeneous validator configurations
- Debug module remains callable from on-chain code in production

This violates defense-in-depth principles by relying solely on correct build configuration without validation.

### Citations

**File:** aptos-move/framework/src/natives/debug.rs (L36-44)
```rust
    if cfg!(feature = "testing") {
        let val = safely_pop_arg!(args, Struct);
        let bytes = val.unpack()?.next().unwrap();

        println!(
            "[debug] {}",
            std::str::from_utf8(&bytes.value_as::<Vec<u8>>()?).unwrap()
        );
    }
```

**File:** aptos-move/framework/src/natives/debug.rs (L111-123)
```rust
pub fn make_all(
    builder: &SafeNativeBuilder,
) -> impl Iterator<Item = (String, NativeFunction)> + '_ {
    let natives = [
        ("native_print", native_print as RawSafeNative),
        ("native_stack_trace", native_stack_trace),
        // For re-playability on-chain we still implement the old versions of these functions
        ("print", native_old_debug_print),
        ("print_stack_trace", native_old_print_stacktrace),
    ];

    builder.make_named_natives(natives)
}
```

**File:** aptos-move/framework/src/natives/mod.rs (L88-88)
```rust
    add_natives_from_module!("debug", debug::make_all(builder));
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L275-275)
```rust
        let natives = aptos_natives_with_builder(&mut builder, inject_create_signer_for_gov_sim);
```

**File:** aptos-move/framework/aptos-stdlib/sources/debug.move (L5-11)
```text
    public fun print<T>(x: &T) {
        native_print(format(x));
    }

    public fun print_stack_trace() {
        native_print(native_stack_trace());
    }
```
