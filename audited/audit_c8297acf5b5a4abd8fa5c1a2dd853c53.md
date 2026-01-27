# Audit Report

## Title
Package Name Validation Bypass via Legacy Parser Allows Unicode Homograph Attacks

## Summary
While `is_ascii_alphanumeric()` correctly rejects extended ASCII (0x80-0xFF) and Unicode characters, the Aptos CLI uses a legacy package parser that bypasses this validation entirely, allowing attackers to publish packages with Unicode or extended ASCII characters in their names. This enables homograph attacks where malicious packages can impersonate legitimate ones using lookalike characters.

## Finding Description

The security question asks whether `is_ascii_alphanumeric()` correctly rejects extended ASCII. The answer is **yes**, it does correctly reject extended ASCII and all non-ASCII Unicode characters. [1](#0-0) 

However, there are **two separate PackageName types** in the codebase:

1. **Validated PackageName** (`move-package-manifest` crate): Uses custom Deserialize with `is_valid_package_name()` validation that enforces ASCII-only alphanumeric + hyphen + underscore. [2](#0-1) 

2. **Unvalidated PackageName** (`move-package` crate): Just a type alias for `Symbol` with **no validation**. [3](#0-2) 

The legacy manifest parser converts any TOML string to Symbol without validation: [4](#0-3) 

The `Symbol::from()` implementation accepts any UTF-8 string: [5](#0-4) 

**The Aptos CLI uses the legacy unvalidated parser**, not the new validated one: [6](#0-5) 

When packages are published, the unvalidated Symbol name is extracted and sent on-chain: [7](#0-6) 

The on-chain Move code performs no validation on package names during publishing: [8](#0-7) 

**Attack Scenario:**
1. Attacker creates `Move.toml` with package name containing Unicode lookalikes (e.g., "аptos_framework" using Cyrillic 'а' U+0430 instead of Latin 'a')
2. Builds package using `aptos move compile` (uses legacy parser, no validation)
3. Publishes using `aptos move publish`
4. Malicious package is published with visually identical name
5. Users depend on wrong package, executing malicious code
6. Funds loss through backdoored functions

## Impact Explanation

This qualifies as **Medium severity** under "Limited funds loss or manipulation". While not a direct funds theft, it enables supply chain attacks where users unknowingly depend on malicious packages with lookalike names, leading to:
- Execution of backdoored Move code in user contracts
- Potential theft of user funds through malicious package functions
- Ecosystem trust degradation

This does not reach High/Critical severity because it requires user error (depending on the wrong package) and doesn't directly compromise consensus, state integrity, or the Move VM.

## Likelihood Explanation

**High likelihood** of occurrence because:
- The Aptos CLI is the primary tool for package publishing
- The validation bypass is in the production code path
- No warnings prevent Unicode in package names
- Homograph attacks are well-known in software supply chains (e.g., npm, PyPI)
- Attackers can easily test and exploit this

## Recommendation

**Fix 1**: Make the Aptos CLI use the validated package manifest system:
- Update `crates/aptos/Cargo.toml` to depend on `move-package-resolver` 
- Migrate CLI commands to use the validated `move-package-manifest::PackageName`

**Fix 2**: Add validation at the Move level during package publishing:
- Add package name validation in `code.move::publish_package()` that rejects non-ASCII characters
- This provides defense-in-depth even if client-side validation is bypassed

**Fix 3**: Add validation to the legacy parser as an interim fix:
- Modify `manifest_parser.rs` to validate package names before converting to Symbol
- Reject any name containing non-ASCII characters

## Proof of Concept

Create a malicious `Move.toml`:

```toml
[package]
name = "аptos_framework"  # Contains Cyrillic 'а' (U+0430)
version = "1.0.0"

[addresses]
std = "0x1"
```

Build and attempt to publish:
```bash
aptos move compile
aptos move publish --assume-yes
```

The package will build and publish successfully despite containing non-ASCII characters, bypassing the intended validation in `is_valid_package_name()`. On-chain comparison will treat this as distinct from the legitimate "aptos_framework" (with Latin 'a'), allowing both to coexist and enabling user confusion attacks.

## Notes

The `is_ascii_alphanumeric()` function itself is correctly implemented and would prevent this attack if consistently enforced. The vulnerability lies in the dual parser architecture where the validated system exists but isn't used by the primary publishing tool.

### Citations

**File:** third_party/move/tools/move-package-manifest/src/package_name.rs (L58-67)
```rust
fn is_valid_package_name(s: &str) -> bool {
    let mut chars = s.chars();

    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => (),
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
```

**File:** third_party/move/tools/move-package-manifest/src/package_name.rs (L69-86)
```rust
impl<'de> Deserialize<'de> for PackageName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let make_err = || {
            serde::de::Error::custom("Invalid package name -- must start with a letter or _; only letters, digits, - and _ allowed.")
        };

        let s = String::deserialize(deserializer)?;

        if !is_valid_package_name(&s) {
            return Err(make_err());
        }

        Ok(Self(s))
    }
}
```

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L10-10)
```rust
pub type PackageName = Symbol;
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L124-127)
```rust
            let name = name
                .as_str()
                .ok_or_else(|| format_err!("Package name must be a string"))?;
            let name = PM::PackageName::from(name);
```

**File:** third_party/move/move-symbol-pool/src/symbol.rs (L50-67)
```rust
impl<'a> From<Cow<'a, str>> for Symbol {
    fn from(s: Cow<'a, str>) -> Self {
        let mut pool = SYMBOL_POOL.lock().expect("could not acquire lock on pool");
        let address = pool.insert(s).as_ptr() as u64;
        Symbol(NonZeroU64::new(address).expect("address of symbol cannot be null"))
    }
}

impl From<&str> for Symbol {
    fn from(s: &str) -> Self {
        Self::from(Cow::Borrowed(s))
    }
}

impl From<String> for Symbol {
    fn from(s: String) -> Self {
        Self::from(Cow::Owned(s))
    }
```

**File:** crates/aptos/Cargo.toml (L87-87)
```text
move-package = { workspace = true }
```

**File:** aptos-move/framework/src/built_package.rs (L581-582)
```rust
        Ok(PackageMetadata {
            name: self.name().to_string(),
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L168-228)
```text
    public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
        check_code_publishing_permission(owner);
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );

        let addr = signer::address_of(owner);
        if (!exists<PackageRegistry>(addr)) {
            move_to(owner, PackageRegistry { packages: vector::empty() })
        };

        // Checks for valid dependencies to other packages
        let allowed_deps = check_dependencies(addr, &pack);

        // Check package against conflicts
        // To avoid prover compiler error on spec
        // the package need to be an immutable variable
        let module_names = get_module_names(&pack);
        let package_immutable = &borrow_global<PackageRegistry>(addr).packages;
        let len = vector::length(package_immutable);
        let index = len;
        let upgrade_number = 0;
        vector::enumerate_ref(package_immutable
        , |i, old| {
            let old: &PackageMetadata = old;
            if (old.name == pack.name) {
                upgrade_number = old.upgrade_number + 1;
                check_upgradability(old, &pack, &module_names);
                index = i;
            } else {
                check_coexistence(old, &module_names)
            };
        });

        // Assign the upgrade counter.
        pack.upgrade_number = upgrade_number;

        let packages = &mut borrow_global_mut<PackageRegistry>(addr).packages;
        // Update registry
        let policy = pack.upgrade_policy;
        if (index < len) {
            *vector::borrow_mut(packages, index) = pack
        } else {
            vector::push_back(packages, pack)
        };

        event::emit(PublishPackage {
            code_address: addr,
            is_upgrade: upgrade_number > 0
        });

        // Request publish
        if (features::code_dependency_check_enabled())
            request_publish_with_allowed_deps(addr, module_names, allowed_deps, code, policy.policy)
        else
        // The new `request_publish_with_allowed_deps` has not yet rolled out, so call downwards
        // compatible code.
            request_publish(addr, module_names, code, policy.policy)
    }
```
