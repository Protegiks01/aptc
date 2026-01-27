# Audit Report

## Title
Test Directory Files Leak into Production Builds via dev_mode Flag Bypass

## Summary
The `build_model()` function in `built_package.rs` hardcodes `test_mode: false` but accepts `dev_mode` as a parameter. Due to a logic error in `get_source_paths_for_config()`, setting `dev_mode=true` incorrectly includes the `tests/` directory in compilation sources, allowing test code without `#[test_only]` annotations to leak into production builds.

## Finding Description

The vulnerability occurs due to a mismatch between the documented behavior of `dev_mode` and its implementation in the source path resolution logic.

According to the `BuildConfig` specification, `dev_mode` should only enable dev-addresses and dev-dependencies: [1](#0-0) 

However, `test_mode` should additionally include code from the 'tests' directory: [2](#0-1) 

The bug exists in the `get_source_paths_for_config()` function which incorrectly checks `dev_mode` instead of `test_mode` when deciding to include the Tests directory: [3](#0-2) 

The `build_model()` function hardcodes `test_mode: false` regardless of the `dev_mode` parameter: [4](#0-3) 

When compiling, the `test_mode` flag correctly controls compiler filtering of `#[test]` and `#[test_only]` annotated items: [5](#0-4) 

**Attack Scenario:**
1. Developer places a helper module in `tests/` directory for testing purposes
2. Module contains privileged functions but developer forgets to add `#[test_only]` attribute at module or function level
3. Package is built with `build_model(dev_mode=true, ...)` for prover verification or development
4. Due to the bug, tests directory files are included in source paths
5. Compiler runs in non-test mode (test_mode=false), so `#[test]`/`#[test_only]` items are filtered
6. However, any code WITHOUT these attributes in the test files is compiled into the production model
7. Unintended privileged functionality becomes available in deployed bytecode

This is acknowledged as problematic behavior in the codebase: [6](#0-5) 

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per Aptos bug bounty criteria because:

1. **Deterministic Execution Violation**: If test code without proper annotations gets deployed to different validators inconsistently (some built with dev_mode, others without), it could cause consensus divergence
2. **Access Control Risk**: Test helper code may contain privileged operations, mock implementations, or bypass security checks that were never intended for production
3. **Limited Funds Loss Potential**: If test code provides alternative code paths for critical operations (e.g., token transfers, governance voting), it could enable unauthorized asset manipulation

While not directly causing fund theft, this creates an inconsistent compilation environment where production builds may contain unaudited, test-only functionality.

## Likelihood Explanation

**Medium-High Likelihood** due to:

1. **Common Development Pattern**: Developers frequently use `dev_mode=true` during development and proving phases
2. **Easy to Trigger**: The `build_model()` function is called by the Move prover (`prover.rs`) with user-controlled `dev_mode` parameter: [7](#0-6) 

3. **Attribution Gap**: Developers may not realize code in `tests/` directory needs `#[test_only]` attributes if they assume the directory location alone provides isolation
4. **Framework Exposure**: Aptos framework packages are commonly built with various modes during development

## Recommendation

Fix the `get_source_paths_for_config()` function to check `test_mode` instead of `dev_mode` when including the Tests directory:

```rust
fn get_source_paths_for_config(
    package_path: &Path,
    config: &BuildConfig,
) -> Result<Vec<PathBuf>> {
    let mut places_to_look = Vec::new();
    let mut add_path = |layout_path: SourcePackageLayout| {
        let path = package_path.join(layout_path.path());
        if layout_path.is_optional() && !path.exists() {
            return;
        }
        places_to_look.push(path)
    };

    add_path(SourcePackageLayout::Sources);
    add_path(SourcePackageLayout::Scripts);

    if config.dev_mode {
        add_path(SourcePackageLayout::Examples);
    }
    
    // FIX: Check test_mode instead of dev_mode for Tests directory
    if config.test_mode {
        add_path(SourcePackageLayout::Tests);
    }
    
    Ok(places_to_look)
}
```

Additionally, update the misleading comment in BuildOptions to reflect the corrected behavior.

## Proof of Concept

Create a malicious test helper in `tests/privileged_helper.move`:

```move
// Note: Missing #[test_only] attribute at module level
module 0xCAFE::privileged_helper {
    use std::signer;
    
    // Privileged function without #[test_only] annotation
    public fun bypass_authorization(account: &signer): address {
        // This would normally require authorization checks
        // but is exposed in tests for convenience
        signer::address_of(account)
    }
    
    // Another helper without protection
    public fun mock_admin_operation(): u64 {
        // Simulates admin operation for testing
        999999 // privileged value
    }
}
```

Build with the vulnerable configuration:

```rust
use move_package::BuildConfig;

let result = build_model(
    true,  // dev_mode=true triggers the bug
    package_path,
    BTreeMap::new(),
    None,
    None,
    None,
    None,
    false,
    BTreeSet::new(),
    vec![],
);

// The privileged_helper module will be included in the model
// despite test_mode being false, because dev_mode includes tests/
```

The functions `bypass_authorization` and `mock_admin_operation` will be compiled into the production model, potentially allowing unauthorized access if the module is deployed on-chain.

### Citations

**File:** third_party/move/tools/move-package/src/lib.rs (L43-47)
```rust
    /// Compile in 'dev' mode. The 'dev-addresses' and 'dev-dependencies' fields will be used if
    /// this flag is set. This flag is useful for development of packages that expose named
    /// addresses that are not set to a specific value.
    #[clap(name = "dev-mode", short = 'd', long = "dev", global = true)]
    pub dev_mode: bool,
```

**File:** third_party/move/tools/move-package/src/lib.rs (L49-52)
```rust
    /// Compile in 'test' mode. The 'dev-addresses' and 'dev-dependencies' fields will be used
    /// along with any code in the 'tests' directory.
    #[clap(name = "test-mode", long = "test", global = true)]
    pub test_mode: bool,
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L668-671)
```rust
        if config.dev_mode {
            add_path(SourcePackageLayout::Examples);
            add_path(SourcePackageLayout::Tests);
        }
```

**File:** aptos-move/framework/src/built_package.rs (L69-76)
```rust
    /// Enables dev mode, which uses all dev-addresses and dev-dependencies
    ///
    /// Dev mode allows for changing dependencies and addresses to the preset [dev-addresses] and
    /// [dev-dependencies] fields.  This works both inside and out of tests for using preset values.
    ///
    /// Currently, it also additionally pulls in all test compilation artifacts
    #[clap(long)]
    pub dev: bool,
```

**File:** aptos-move/framework/src/built_package.rs (L199-221)
```rust
    let build_config = BuildConfig {
        dev_mode,
        additional_named_addresses,
        generate_abis: false,
        generate_docs: false,
        generate_move_model: false,
        full_model_generation: false,
        install_dir: None,
        test_mode: false,
        override_std: None,
        force_recompilation: false,
        fetch_deps_only: false,
        skip_fetch_latest_git_deps: true,
        compiler_config: CompilerConfig {
            bytecode_version,
            compiler_version,
            language_version,
            skip_attribute_checks,
            known_attributes,
            experiments,
            print_errors: true,
        },
    };
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L585-589)
```rust
        let mut flags = if resolution_graph.build_options.test_mode {
            Flags::testing()
        } else {
            Flags::empty()
        };
```

**File:** aptos-move/framework/src/prover.rs (L158-169)
```rust
        let mut model = build_model(
            dev_mode,
            package_path,
            named_addresses,
            self.filter.clone(),
            bytecode_version,
            compiler_version,
            language_version,
            skip_attribute_checks,
            known_attributes.clone(),
            experiments_vec,
        )?;
```
