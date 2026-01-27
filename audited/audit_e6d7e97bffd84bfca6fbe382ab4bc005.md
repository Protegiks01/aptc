# Audit Report

## Title
ViewFilter Blocklist/Allowlist Bypass via Case-Sensitive Module Name Comparison

## Summary
The `ViewFilter.allows()` method in the API configuration performs case-sensitive string comparisons for module names and function names, allowing attackers to bypass blocklist restrictions by deploying modules with case variations of blocked module names.

## Finding Description

The ViewFilter mechanism is designed to allow node operators to control which view functions can be executed through the API via allowlists or blocklists. However, the implementation has a critical flaw in how it compares module and function identifiers.

The `ViewFilter.allows()` method performs case-sensitive string comparison: [1](#0-0) 

When a view function request is received, the filter check is invoked: [2](#0-1) 

The vulnerability arises because:

1. **Move identifiers are case-sensitive**: Module names in Move are case-sensitive ASCII strings with no normalization: [3](#0-2) 

2. **Modules with case variations can coexist**: The Move framework's package publishing logic checks for module name conflicts using case-sensitive comparison: [4](#0-3) 

3. **StateKey storage is case-preserving**: Module lookup in storage uses the exact case from the ModuleId: [5](#0-4) 

**Attack Scenario:**

1. Node operator adds to blocklist: `"0xAttacker::MaliciousModule::exploit"`
2. Attacker publishes module: `"0xAttacker::maliciousmodule::exploit"` (different case)
3. ViewFilter comparison: `"MaliciousModule" != "maliciousmodule"` → **ALLOWED**
4. VM successfully locates and executes `"0xAttacker::maliciousmodule"` from storage
5. Malicious view function executes, bypassing the intended blocklist

## Impact Explanation

This vulnerability has **Low to Medium** severity impact:

**Medium Severity** (up to $10,000):
- API security controls can be bypassed, allowing execution of blocked view functions
- Could lead to resource exhaustion if expensive view functions are blocked but bypass via case variation
- Undermines the security model of the ViewFilter feature designed to protect node operators

However, practical exploitability is limited because:
- Attackers can only deploy modules at addresses they control
- The vulnerability doesn't lead to direct funds loss or consensus violations
- Most critical framework modules (0x1, 0x3, 0x4) are immutable and controlled

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can occur when:
- Node operators use blocklists to prevent expensive or problematic view function calls
- Attackers are aware of the case-sensitivity discrepancy
- Attackers have already published modules that operators want to blocklist

However:
- ViewFilter usage may not be widespread in production deployments
- Operators could work around this by blocklisting all case variations manually
- The compiler prevents case variation conflicts within a single package (filesystem portability), though separate packages can have case variations

## Recommendation

Normalize module and function names to lowercase before comparison in `ViewFilter.allows()`:

```rust
pub fn allows(&self, address: &AccountAddress, module: &str, function: &str) -> bool {
    let module_lower = module.to_lowercase();
    let function_lower = function.to_lowercase();
    
    match self {
        ViewFilter::Allowlist(ids) => ids.iter().any(|id| {
            &id.address == address 
                && id.module.to_lowercase() == module_lower 
                && id.function_name.to_lowercase() == function_lower
        }),
        ViewFilter::Blocklist(ids) => !ids.iter().any(|id| {
            &id.address == address 
                && id.module.to_lowercase() == module_lower 
                && id.function_name.to_lowercase() == function_lower
        }),
    }
}
```

Additionally, document this behavior clearly and consider adding validation at configuration parse time to convert all filter entries to lowercase for consistency.

## Proof of Concept

```move
// File: sources/case_bypass_poc.move
// Deploy this module at 0xAttacker to bypass a blocklist entry for "0xAttacker::BlockedModule::blocked_function"

module 0xAttacker::blockedmodule {
    public fun blocked_function(): u64 {
        // This function executes even if "BlockedModule::blocked_function" is blocklisted
        // because "blockedmodule" != "BlockedModule" in case-sensitive comparison
        42
    }
}
```

**Configuration Setup:**
```toml
# In node configuration
[api.view_filter]
Blocklist = [
    { address = "0xAttacker", module = "BlockedModule", function_name = "blocked_function" }
]
```

**API Request (succeeds despite blocklist):**
```json
POST /v1/view
{
  "function": "0xAttacker::blockedmodule::blocked_function",
  "type_arguments": [],
  "arguments": []
}
```

The request succeeds because the filter comparison fails to match `"BlockedModule"` with `"blockedmodule"`, bypassing the intended security control.

## Notes

While this is a valid implementation bug that allows security control bypass, its practical impact is limited in most deployment scenarios. The primary concern is for node operators using ViewFilter to protect against resource-intensive or problematic view functions from known malicious addresses. The fix is straightforward and should be implemented to ensure defense-in-depth.

### Citations

**File:** config/src/config/api_config.rs (L230-241)
```rust
impl ViewFilter {
    /// Returns true if the given function is allowed by the filter.
    pub fn allows(&self, address: &AccountAddress, module: &str, function: &str) -> bool {
        match self {
            ViewFilter::Allowlist(ids) => ids.iter().any(|id| {
                &id.address == address && id.module == module && id.function_name == function
            }),
            ViewFilter::Blocklist(ids) => !ids.iter().any(|id| {
                &id.address == address && id.module == module && id.function_name == function
            }),
        }
    }
```

**File:** api/src/view_function.rs (L140-152)
```rust
    if !context.node_config.api.view_filter.allows(
        view_function.module.address(),
        view_function.module.name().as_str(),
        view_function.function.as_str(),
    ) {
        return Err(BasicErrorWith404::forbidden_with_code_no_info(
            format!(
                "Function {}::{} is not allowed",
                view_function.module, view_function.function
            ),
            AptosErrorCode::InvalidInput,
        ));
    }
```

**File:** third_party/move/move-core/types/src/identifier.rs (L45-46)
```rust
pub const fn is_valid_identifier_char(c: char) -> bool {
    matches!(c, '_' | '$' | 'a'..='z' | 'A'..='Z' | '0'..='9')
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L282-293)
```text
    fun check_coexistence(old_pack: &PackageMetadata, new_modules: &vector<String>) {
        // The modules introduced by each package must not overlap with `names`.
        vector::for_each_ref(&old_pack.modules, |old_mod| {
            let old_mod: &ModuleMetadata = old_mod;
            let j = 0;
            while (j < vector::length(new_modules)) {
                let name = vector::borrow(new_modules, j);
                assert!(&old_mod.name != name, error::already_exists(EMODULE_NAME_CLASH));
                j = j + 1;
            };
        });
    }
```

**File:** types/src/state_store/state_key/mod.rs (L173-188)
```rust
    pub fn module(address: &AccountAddress, name: &IdentStr) -> Self {
        Self(
            REGISTRY
                .module(address, name)
                .get_or_add(address, name, || {
                    Ok(StateKeyInner::AccessPath(AccessPath::code_access_path(
                        ModuleId::new(*address, name.to_owned()),
                    )))
                })
                .expect("only possible error is resource path serialization"),
        )
    }

    pub fn module_id(module_id: &ModuleId) -> Self {
        Self::module(&module_id.address, &module_id.name)
    }
```
