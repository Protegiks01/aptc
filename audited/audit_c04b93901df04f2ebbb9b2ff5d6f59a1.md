# Audit Report

## Title
Missing Reserved Package Name Validation Enables Framework Package Name Impersonation

## Summary
The `is_valid_package_name()` function in `package_name.rs` lacks validation against reserved framework package names (e.g., "AptosFramework", "AptosStdlib", "MoveStdlib"), allowing any user to publish packages with names identical to critical system packages at arbitrary addresses. While the blockchain's (address, name) identification system technically prevents direct shadowing, this creates vectors for developer confusion and supply chain attacks.

## Finding Description

The package name validation function only checks syntactic rules without verifying against reserved framework package names. [1](#0-0) 

When packages are published on-chain via `publish_package()`, the only validation performed is checking upgrade policies and code permissions—there is no check preventing use of framework package names: [2](#0-1) 

The framework packages are recognized in the build system as special packages: [3](#0-2) 

However, there is no enforcement preventing arbitrary addresses from publishing packages with these exact names.

**Attack Vectors:**

1. **Dependency Confusion**: An attacker publishes malicious package "AptosFramework" at address `0xattacker`. Through social engineering, documentation spoofing, or compromised tutorials, developers are tricked into adding the wrong address in their `Move.toml`.

2. **Transitive Dependency Poisoning**: Attacker creates a seemingly legitimate utility package that depends on their malicious "AptosFramework". When developers add this utility as a dependency, the build system may process the malicious framework first.

3. **Build-Time Conflicts**: During dependency resolution, if both legitimate and malicious packages with identical names are in the dependency graph, the build fails or resolves unpredictably: [4](#0-3) 

## Impact Explanation

**Severity: Medium to Low**

This issue does NOT meet Critical or High severity because:

1. **Technical Safeguards Exist**: Packages are identified by (address, name) pairs. Dependencies must explicitly specify both: [5](#0-4) [6](#0-5) 

2. **Requires Social Engineering**: Exploitation requires developers to make configuration errors, which falls under excluded attack categories per the bug bounty rules.

3. **No Direct Protocol Impact**: This doesn't cause consensus violations, fund loss, or network availability issues without developer error.

However, it does create:
- Developer confusion and potential for mistakes
- Supply chain attack surface through impersonation
- Build-time failures if conflicting names are used

## Likelihood Explanation

**Likelihood: Low to Medium**

While technically possible, successful exploitation requires:
1. Attacker publishing malicious packages with framework names
2. Creating convincing documentation/tutorials
3. Developers making configuration mistakes
4. No code review catching the wrong address

The Aptos ecosystem's mature tooling and documentation reduce likelihood, but new developers or those copying code snippets remain vulnerable.

## Recommendation

Add reserved package name validation to `is_valid_package_name()`:

```rust
// In package_name.rs
const RESERVED_PACKAGE_NAMES: &[&str] = &[
    "AptosFramework",
    "AptosStdlib", 
    "AptosToken",
    "AptosTokenObjects",
    "MoveStdlib",
];

fn is_valid_package_name(s: &str) -> bool {
    // Existing syntax checks
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => (),
        _ => return false,
    }
    
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return false;
    }
    
    // Check against reserved names
    !RESERVED_PACKAGE_NAMES.contains(&s)
}
```

Additionally, add validation in `publish_package()` to reject reserved names at non-framework addresses:

```move
// In code.move publish_package()
assert!(
    !is_reserved_package_name(&pack.name) || system_addresses::is_framework_reserved_address(addr),
    error::invalid_argument(ERESERVED_PACKAGE_NAME)
);
```

## Proof of Concept

```move
// Malicious package published at attacker's address
module 0xattacker::AptosFramework {
    // Package successfully publishes despite using framework name
    // because no validation exists in is_valid_package_name()
    
    public fun malicious_function(): u64 {
        // Attacker's code
        999
    }
}
```

```toml
# Victim's Move.toml - if tricked into using wrong address
[dependencies]
AptosFramework = { aptos = "https://fullnode.mainnet.aptoslabs.com", address = "0xattacker" }
# Should be: address = "0x1"
```

The package would successfully compile and execute against the malicious framework.

---

**Notes:**

While this represents a gap in defensive programming, the practical exploitation requires social engineering which is explicitly out of scope per the bug bounty rules. The technical (address, name) identification system provides adequate protection when developers follow best practices. This is more accurately classified as a **code quality improvement** rather than a critical security vulnerability. The recommendation would improve developer safety but doesn't fix a direct protocol-level exploit.

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

**File:** aptos-move/framework/aptos-framework/sources/code.move (L51-55)
```text
    /// A dependency to a package published at address
    struct PackageDep has store, drop, copy {
        account: address,
        package_name: String
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L168-174)
```text
    public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
        check_code_publishing_permission(owner);
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );
```

**File:** third_party/move/tools/move-package/src/source_package/std_lib.rs (L56-77)
```rust
    /// Returns the name of the standard library.
    pub fn as_str(&self) -> &'static str {
        match self {
            StdLib::AptosToken => "AptosToken",
            StdLib::AptosTokenObjects => "AptosTokenObjects",
            StdLib::AptosFramework => "AptosFramework",
            StdLib::AptosStdlib => "AptosStdlib",
            StdLib::MoveStdlib => "MoveStdlib",
        }
    }

    /// Returns the standard library from the given package name, or `None` if the package name is not a standard library.
    pub fn from_package_name(package_name: Symbol) -> Option<StdLib> {
        match package_name.as_str() {
            "AptosToken" => Some(StdLib::AptosToken),
            "AptosTokenObjects" => Some(StdLib::AptosTokenObjects),
            "AptosFramework" => Some(StdLib::AptosFramework),
            "AptosStdlib" => Some(StdLib::AptosStdlib),
            "MoveStdlib" => Some(StdLib::MoveStdlib),
            _ => None,
        }
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L220-232)
```rust
        let package_node_id = match self.package_table.get(&package_name) {
            None => self.get_or_add_node(package_name)?,
            // Same package and we've already resolved it: OK, return early
            Some(other) if other.source_package == package => return Ok(()),
            // Different packages, with same name: Not OK
            Some(other) => {
                bail!(
                    "Conflicting dependencies found: package '{}' conflicts with '{}'",
                    other.source_package.package.name,
                    package.package.name,
                )
            },
        };
```

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L149-155)
```rust
    Aptos {
        /// URL to the Aptos full-node connected to the network where the package is published.
        node_url: String,

        /// Address of the published package.
        package_addr: AccountAddress,
    },
```
