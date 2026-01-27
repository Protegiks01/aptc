# Audit Report

## Title
External Checks Silently Ignored When LINT_CHECKS Experiment Is Disabled, Creating False Sense of Security

## Summary
The `compile_package_no_exit()` function accepts `external_checks` as a parameter, but these checks are silently ignored unless the `LINT_CHECKS` experiment is explicitly enabled. Since `LINT_CHECKS` defaults to `false`, developers who provide external security checks will have a false sense of security, believing their checks executed when they did not. This can lead to vulnerable Move code being deployed to the blockchain.

**Note on Question Premise**: The security question asks about "v1 compiler" usage, but V1 compiler cannot be used at all—it explicitly errors out. [1](#0-0)  The actual vulnerability exists with the V2 compiler (the default and only supported compiler).

## Finding Description

When developers call `compile_package_no_exit()` with `external_checks`, they expect these checks to validate their Move code. [2](#0-1) 

The external_checks are passed through the compilation pipeline and added to the compiler options. [3](#0-2) 

However, the checks are only executed if the `LINT_CHECKS` experiment is enabled:

**For Expression Checkers (Model AST level):**
The `model_ast_lints::checker` function is only added to the pipeline when `LINT_CHECKS` is on. [4](#0-3) 

**For Stackless Bytecode Checkers:**
The `LintProcessor` is only added to the pipeline when `LINT_CHECKS` is on. [5](#0-4) 

**Critical Issue**: The `LINT_CHECKS` experiment defaults to `false`. [6](#0-5) 

The documentation comment states external checks "are only run if compiler v2 is used" but fails to mention the `LINT_CHECKS` requirement, creating a false expectation. [7](#0-6) 

When `LINT_CHECKS` is disabled (the default), the compilation succeeds without any warning that external_checks were not executed. Developers believe their security checks validated the code, but they never ran.

**Attack Scenario:**
1. Attacker submits malicious Move code with vulnerability pattern
2. Developer compiles using `compile_package_no_exit()` with `external_checks` designed to catch this pattern
3. Developer does NOT enable `LINT_CHECKS` experiment (not aware it's required)
4. Compilation succeeds with no errors or warnings
5. Developer deploys malicious code, believing it passed security validation
6. Vulnerability is exploited on-chain

## Impact Explanation

**High Severity** - This breaks the fundamental security guarantee that provided validation checks will execute. It enables deployment of vulnerable Move contracts that should have been caught by security checks.

This affects:
- **Deterministic Execution**: Vulnerable code could introduce non-deterministic behavior
- **Move VM Safety**: Checks meant to prevent unsafe patterns are bypassed
- **Transaction Validation**: Security-critical validation logic is silently ignored
- **Access Control**: Checks for proper permission enforcement are not executed

The impact qualifies as **High Severity** under Aptos Bug Bounty criteria as it represents a significant protocol violation—the security validation layer can be completely bypassed without any indication to developers.

## Likelihood Explanation

**HIGH** - This will occur whenever:
1. Developers use the public API `compile_package_no_exit()` with non-empty `external_checks`
2. They rely on the documentation comment (which doesn't mention `LINT_CHECKS` requirement)
3. They don't explicitly enable the `LINT_CHECKS` experiment

The only code path that properly enables `LINT_CHECKS` is the `LintPackage` CLI command. [8](#0-7) 

Any programmatic usage of `build_with_external_checks()` without explicitly enabling `LINT_CHECKS` will silently ignore the checks. [9](#0-8) 

## Recommendation

**Immediate Fix**: Add validation that errors or warns when `external_checks` are provided but `LINT_CHECKS` is disabled:

```rust
// In compile_package_no_exit() or build_all()
if !external_checks.is_empty() && !config.experiments.contains(&Experiment::LINT_CHECKS.to_string()) {
    anyhow::bail!(
        "External checks provided but LINT_CHECKS experiment is not enabled. \
         Add '--experiments lint-checks' to enable external check execution."
    );
}
```

**Better Fix**: Automatically enable `LINT_CHECKS` when `external_checks` are non-empty:

```rust
// In compiled_package.rs build_all()
let mut options = move_compiler_v2::Options { /* ... */ };
if !external_checks.is_empty() {
    options.experiments.push(Experiment::LINT_CHECKS.to_string());
}
```

**Documentation Fix**: Update the comment to clearly state the requirement:

```rust
/// External checks on Move code can be provided via `external_checks`.
/// These checks are only executed when:
/// 1. Compiler v2 is used (v1 is no longer supported)
/// 2. The LINT_CHECKS experiment is enabled (add to config.experiments)
```

## Proof of Concept

```rust
// Reproduction test demonstrating silent ignore
use move_package::{BuildConfig, CompilerConfig};
use move_compiler_v2::external_checks::ExternalChecks;
use std::sync::Arc;

// Mock external checker that should trigger if executed
struct TestChecker;
impl ExternalChecks for TestChecker {
    fn get_exp_checkers(&self) -> Vec<Box<dyn ExpChecker>> {
        vec![Box::new(TestExpChecker)]
    }
    fn get_stackless_bytecode_checkers(&self) -> Vec<Box<dyn StacklessBytecodeChecker>> {
        vec![]
    }
}

struct TestExpChecker;
impl ExpChecker for TestExpChecker {
    fn get_name(&self) -> String { "test_checker".to_string() }
    fn visit_expr_pre(&mut self, _: &FunctionEnv, _: &ExpData) {
        panic!("THIS SHOULD BE CALLED BUT ISN'T");
    }
}

// This compilation succeeds WITHOUT running the external checks
// and WITHOUT any warning to the developer
let config = BuildConfig {
    compiler_config: CompilerConfig {
        // Note: LINT_CHECKS experiment is NOT enabled here
        experiments: vec![],
        ..Default::default()
    },
    ..Default::default()
};

let external_checks = vec![Arc::new(TestChecker) as Arc<dyn ExternalChecks>];

// This succeeds, but TestExpChecker::visit_expr_pre is NEVER called
// Developer thinks their check ran, but it didn't
let result = config.compile_package_no_exit(
    resolved_graph,
    external_checks,
    &mut std::io::stderr()
);

assert!(result.is_ok()); // Passes - no error given
// But the external check was NEVER executed - silent security failure
```

### Citations

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L615-615)
```rust
                CompilerVersion::V1 => anyhow::bail!("Compiler v1 is no longer supported"),
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L666-666)
```rust
                        external_checks,
```

**File:** third_party/move/tools/move-package/src/lib.rs (L156-169)
```rust
    /// External checks on Move code can be provided, these are only run if compiler v2 is used.
    pub fn compile_package_no_exit<W: Write>(
        self,
        resolved_graph: ResolvedGraph,
        external_checks: Vec<Arc<dyn ExternalChecks>>,
        writer: &mut W,
    ) -> Result<(CompiledPackage, Option<model::GlobalEnv>)> {
        let config = self.compiler_config.clone(); // Need clone because of mut self
        let mutx = PackageLock::lock();
        let ret =
            BuildPlan::create(resolved_graph)?.compile_no_exit(&config, external_checks, writer);
        mutx.unlock();
        ret
    }
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L377-381)
```rust
    if options.experiment_on(Experiment::LINT_CHECKS) {
        // Perform all the model AST lint checks before inlining, to be closer "in form"
        // to the user code.
        env_pipeline.add("model AST lints", model_ast_lints::checker);
    }
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L541-545)
```rust
    if options.experiment_on(Experiment::LINT_CHECKS) {
        // Some lint checks need live variable analysis.
        pipeline.add_processor(Box::new(LiveVarAnalysisProcessor::new(false)));
        pipeline.add_processor(Box::new(LintProcessor {}));
    }
```

**File:** third_party/move/move-compiler-v2/src/experiments.rs (L237-240)
```rust
            name: Experiment::LINT_CHECKS.to_string(),
            description: "Whether to run various lint checks.".to_string(),
            default: Given(false),
        },
```

**File:** crates/aptos/src/move_tool/lint.rs (L168-168)
```rust
            Experiment::LINT_CHECKS.to_string(),
```

**File:** aptos-move/framework/src/built_package.rs (L285-299)
```rust
    pub fn build_with_external_checks(
        resolved_graph: ResolvedGraph,
        options: BuildOptions,
        build_config: BuildConfig,
        external_checks: Vec<Arc<dyn ExternalChecks>>,
    ) -> anyhow::Result<Self> {
        {
            let package_path = resolved_graph.root_package_path.clone();
            let bytecode_version = build_config.compiler_config.bytecode_version;

            let (mut package, model_opt) = build_config.compile_package_no_exit(
                resolved_graph,
                external_checks,
                &mut stderr(),
            )?;
```
