# Audit Report

## Title
Missing Package Name Format Validation in On-Chain Package Publishing

## Summary
The Aptos Framework's `publish_package_txn()` entry function accepts package metadata without validating the package name format, allowing attackers to publish packages with names containing Unicode homoglyphs, zero-width characters, or special characters. This bypasses the validation enforced by standard build tools and can cause display spoofing, namespace confusion, and parsing errors in ecosystem tooling.

## Finding Description

The package publishing flow has a validation gap between off-chain build tools and on-chain execution:

**Expected Security Guarantee:** Package names should follow the documented format (start with ASCII letter/underscore, contain only ASCII alphanumeric/hyphen/underscore) to prevent confusion attacks and ensure tool compatibility. [1](#0-0) 

**Off-Chain Validation:** The `move-package-manifest` crate enforces name validation when parsing Move.toml manifests: [2](#0-1) 

**Validation Bypass:** However, the on-chain `publish_package_txn()` entry function accepts pre-serialized `PackageMetadata` without re-validating the name field: [3](#0-2) 

The `PackageMetadata` struct stores the name as an unvalidated `String`: [4](#0-3) 

**Attack Path:**
1. Attacker constructs `PackageMetadata` in Rust with malicious name (e.g., "AptοsFramework" with Cyrillic 'о', or names with zero-width characters U+200B)
2. Serializes metadata using BCS: `bcs::to_bytes(&metadata)`
3. Compiles legitimate Move modules
4. Submits transaction calling `code_publish_package_txn(metadata_serialized, code)`
5. On-chain code deserializes and stores the package without name validation [5](#0-4) 

The only check performed is string equality comparison for detecting upgrades, which doesn't validate format.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria - "State inconsistencies requiring intervention":

1. **Display Spoofing**: Packages with homoglyph names (e.g., "AptοsToken" vs "AptosToken") appear identical in UIs, enabling phishing attacks
2. **Tool Breakage**: Ecosystem tools assuming validated names may crash or behave incorrectly when parsing package registries
3. **Namespace Pollution**: Attackers can squat on visually-identical variants of legitimate package names
4. **Parsing Ambiguity**: Zero-width characters create invisible differences between package names

This does not cause direct fund loss or consensus violations, but degrades system integrity and user trust. The state inconsistency (invalid names in `PackageRegistry`) requires manual intervention to mitigate confusion attacks.

## Likelihood Explanation

**Medium Likelihood:**

- Requires attacker to bypass standard Aptos CLI/SDK tools and manually construct transactions
- Needs Rust programming knowledge to serialize `PackageMetadata`
- No privileged access required - any account can publish packages
- Attack is technically straightforward once validation gap is understood
- Economic barrier is minimal (only transaction gas fees)

The barrier is higher than trivial exploits but lower than complex multi-step attacks requiring validator collusion.

## Recommendation

Add on-chain validation in the `publish_package` function before storing the metadata:

```move
fun is_valid_package_name(name: &String): bool {
    let bytes = string::bytes(name);
    let len = vector::length(bytes);
    if (len == 0) return false;
    
    let first = *vector::borrow(bytes, 0);
    // Must start with ASCII letter (a-z, A-Z) or underscore
    if (!((first >= 97 && first <= 122) || (first >= 65 && first <= 90) || first == 95)) {
        return false
    };
    
    // All characters must be ASCII alphanumeric, hyphen, or underscore
    let i = 1;
    while (i < len) {
        let c = *vector::borrow(bytes, i);
        if (!((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || 
              (c >= 48 && c <= 57) || c == 45 || c == 95)) {
            return false
        };
        i = i + 1;
    };
    true
}

public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) 
acquires PackageRegistry {
    // Add validation before existing checks
    assert!(is_valid_package_name(&pack.name), error::invalid_argument(EINVALID_PACKAGE_NAME));
    
    // ... existing implementation
}
```

## Proof of Concept

```rust
// Rust PoC demonstrating malicious metadata construction
use aptos_framework::natives::code::{PackageMetadata, UpgradePolicy, ModuleMetadata, PackageDep};
use aptos_types::account_address::AccountAddress;

fn create_spoofed_package() -> Vec<u8> {
    // Create package with Cyrillic 'о' instead of Latin 'o' 
    let malicious_metadata = PackageMetadata {
        name: "AptοsFramework".to_string(), // Contains U+03BF (Greek omicron)
        upgrade_policy: UpgradePolicy::compat(),
        upgrade_number: 0,
        source_digest: "".to_string(),
        manifest: vec![],
        modules: vec![],
        deps: vec![],
        extension: None,
    };
    
    // Serialize and submit via publish_package_txn
    bcs::to_bytes(&malicious_metadata).unwrap()
}

// Alternative: zero-width character injection
fn create_invisible_variant() -> Vec<u8> {
    let metadata = PackageMetadata {
        name: "AptosToken\u{200B}".to_string(), // Contains zero-width space
        // ... rest of fields
    };
    bcs::to_bytes(&metadata).unwrap()
}
```

**Move Test:**
```move
#[test(owner = @0x123)]
fun test_invalid_package_name_accepted(owner: signer) {
    // Currently this would succeed but should fail
    let metadata_with_unicode = /* construct with homoglyphs */;
    code::publish_package_txn(&owner, metadata_with_unicode, vector[]);
}
```

## Notes

- The `PackageIdentity` struct in `identity.rs` is a tool-side construct for dependency resolution and doesn't directly participate in on-chain publishing
- The actual vulnerability is in the Move smart contract layer (`code.move`)
- This represents a defense-in-depth failure where client-side validation is not enforced at the protocol level
- Similar validation should be added for module names and dependency package names to ensure comprehensive protection

### Citations

**File:** third_party/move/tools/move-package-manifest/src/package_name.rs (L13-19)
```rust
///
/// A valid package name must:
/// - Begin with an ASCII letter (`a–z`, `A–Z`) or an underscore (`_`)
/// - Contain only ASCII letters, digits (`0–9`), hyphens (`-`), or underscores (`_`)
///
/// TODO: The rules above are tentative and are subject to change if we find incompatibility
///       in production.
```

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

**File:** aptos-move/framework/aptos-framework/sources/code.move (L30-49)
```text
    struct PackageMetadata has copy, drop, store {
        /// Name of this package.
        name: String,
        /// The upgrade policy of this package.
        upgrade_policy: UpgradePolicy,
        /// The numbers of times this module has been upgraded. Also serves as the on-chain version.
        /// This field will be automatically assigned on successful upgrade.
        upgrade_number: u64,
        /// The source digest of the sources in the package. This is constructed by first building the
        /// sha256 of each individual source, than sorting them alphabetically, and sha256 them again.
        source_digest: String,
        /// The package manifest, in the Move.toml format. Gzipped text.
        manifest: vector<u8>,
        /// The list of modules installed by this package.
        modules: vector<ModuleMetadata>,
        /// Holds PackageDeps.
        deps: vector<PackageDep>,
        /// For future extension
        extension: Option<Any>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L192-202)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
    }
```
