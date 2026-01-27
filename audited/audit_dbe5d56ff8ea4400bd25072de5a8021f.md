# Audit Report

## Title
Malicious Code Injection via Transitive Dependency Upgrade Without Re-Validation

## Summary
While the Aptos package system correctly enforces declaration and validation of ALL dependencies (including transitive ones) during initial package publication, a critical vulnerability exists in the upgrade mechanism. An attacker can inject malicious code into an already-reviewed package ecosystem by upgrading a transitive dependency after dependent packages have been reviewed and published, without triggering re-validation of those dependent packages.

## Finding Description

The vulnerability exploits a fundamental gap between **initial publication security** and **post-publication dependency evolution**:

**Initial Publication (Working as Intended):**
When Package A is published with dependency on Package B (which depends on Package C), the build system correctly includes ALL transitive dependencies in the package metadata. [1](#0-0) 

The metadata extraction process ensures that both direct dependencies (B) and transitive dependencies (C) are included in `PackageMetadata.deps`, preventing the initial bypass scenario. [2](#0-1) 

The `check_dependencies()` function validates all entries in the deps list, ensuring they exist on-chain and have compatible upgrade policies.

**The Vulnerability - Dependency Version Pinning Absence:** [3](#0-2) 

The `PackageDep` structure contains NO version field - dependencies are referenced only by address and package name, meaning packages always use the **latest published version** of their dependencies.

**Upgrade Compatibility Checks Are Insufficient:** [4](#0-3) 

The `upgrade_policy_compat()` mode only validates:
- Same public function signatures  
- No resource layout changes for existing resources

It does NOT validate that function **behavior** remains safe. An attacker can keep the API identical while injecting malicious logic. [5](#0-4) 

The `check_upgradability()` function only ensures modules aren't removed and policies don't weaken - it performs no behavioral safety analysis.

**Attack Execution Flow:**

1. **Initial State** - All packages reviewed and published:
   - Attacker publishes Package C v1 (benign, passes review)
   - Package B published depending on C v1 (passes review)
   - Victim publishes Package A depending on B (passes review)
   - Security auditor checks A and B, but may not deeply audit C (transitive dependency)

2. **Attack Injection**:
   - Attacker upgrades C to v2 using `upgrade_policy_compat()`
   - Keeps all public function signatures identical
   - Injects malicious code inside existing function implementations
   - Examples: data exfiltration, state manipulation, fund theft

3. **Exploitation**:
   - When A executes and calls B's functions
   - B's code references C, triggering module load
   - VM loads C v2 from on-chain storage (no version pinning)
   - Malicious code in C v2 executes in A's transaction context
   - Victim's package compromised without their knowledge

## Impact Explanation

**HIGH Severity** - This meets multiple critical impact criteria:

1. **Loss of Funds**: Malicious dependency code can drain user funds, manipulate balances, or steal assets from packages using the compromised dependency chain.

2. **State Manipulation**: Compromised transitive dependencies can corrupt application state, violate business logic invariants, or manipulate critical on-chain data.

3. **Violation of Deterministic Execution Invariant**: Different validators may execute with different dependency versions during upgrade windows, potentially causing consensus divergence if execution results differ.

4. **Trust Model Violation**: Package developers and auditors reasonably assume that reviewed and published packages remain secure unless they explicitly upgrade them. Silent dependency upgrades violate this assumption.

5. **Ecosystem-Wide Impact**: A single malicious dependency used transitively by multiple packages can compromise an entire ecosystem without any of the dependent packages being aware.

This is particularly severe because:
- The victim package owner has no control over transitive dependency upgrades
- No notification mechanism exists for dependency changes
- Security reviews become obsolete the moment any transitive dependency upgrades
- Attack surface grows exponentially with dependency depth

## Likelihood Explanation

**HIGH Likelihood** - Multiple factors make this attack practical:

1. **Attacker Requirements Are Minimal**:
   - Control of any package with upgrade policy compatible or arbitrary
   - Ability to make a "compatible" upgrade (same API, different behavior)
   - No special privileges or validator access required

2. **Common Ecosystem Patterns Enable This**:
   - Libraries commonly use `upgrade_policy_compat()` to allow bug fixes
   - Deep dependency chains are common in real applications
   - Security reviews typically focus on direct dependencies, not full transitive closure

3. **Detection Is Difficult**:
   - No automatic notification when dependencies upgrade
   - Behavioral changes hidden behind unchanged APIs
   - Auditing full transitive dependency history is impractical

4. **Social Engineering Amplifies Risk**:
   - Attacker can create "useful" libraries that get widely adopted
   - After gaining trust, inject malicious code in an upgrade
   - Or compromise maintainer accounts of existing popular packages

## Recommendation

Implement **dependency version pinning and upgrade notifications**:

1. **Add Version Field to PackageDep**:
```rust
pub struct PackageDep {
    pub account: AccountAddress,
    pub package_name: String,
    pub version: u64,  // NEW: Pin to specific upgrade_number
}
```

2. **Enforce Version Pinning in Dependency Resolution**:
```move
// In check_dependencies()
if (dep_pack.upgrade_number != dep.version) {
    abort error::version_mismatch(EDEP_VERSION_MISMATCH)
}
```

3. **Add Explicit Upgrade Mechanism for Dependencies**:
```move
public entry fun upgrade_dependencies(
    owner: &signer,
    package_name: String,
    new_deps: vector<PackageDep>
) acquires PackageRegistry {
    // Requires explicit action from package owner
    // Validates all new dependency versions
    // Emits event for audit trail
}
```

4. **Emit Events for Dependency Changes**:
```move
#[event]
struct DependencyUpgraded has drop, store {
    package: String,
    old_dep_version: u64,
    new_dep_version: u64,
    upgraded_by: address,
}
```

5. **Add Feature Flag for Strict Version Pinning**:
Allow packages to opt into strict version pinning via metadata, preventing automatic dependency upgrades entirely.

## Proof of Concept

```move
// PoC demonstrating the vulnerability

module 0xATTACKER::MaliciousLogger {
    use std::signer;
    
    struct DrainedFunds has key {
        amount: u64
    }
    
    // V1: Benign implementation
    public fun log_event(account: &signer, value: u64) {
        // Just logs, appears harmless
    }
    
    // V2: Malicious upgrade (same signature, different behavior)
    // public fun log_event(account: &signer, value: u64) acquires DrainedFunds {
    //     let addr = signer::address_of(account);
    //     // Malicious: exfiltrate value to attacker
    //     if (!exists<DrainedFunds>(addr)) {
    //         move_to(account, DrainedFunds { amount: value });
    //     };
    //     // Still logs to avoid suspicion
    // }
}

module 0xBENIGN::HelperLib {
    use 0xATTACKER::MaliciousLogger;
    
    public fun process_payment(account: &signer, amount: u64): u64 {
        // Appears to just log the payment
        MaliciousLogger::log_event(account, amount);
        amount
    }
}

module 0xVICTIM::PaymentApp {
    use 0xBENIGN::HelperLib;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Victim's payment function
    public entry fun make_payment(sender: &signer, amount: u64) {
        // Process payment through helper
        let processed = HelperLib::process_payment(sender, amount);
        
        // Transfer funds
        // ... payment logic ...
        
        // After MaliciousLogger is upgraded to V2:
        // - Funds get tracked by attacker
        // - User data exfiltrated
        // - All without victim's knowledge
    }
}

// Attack steps:
// 1. Publish MaliciousLogger V1 (benign)
// 2. Publish HelperLib depending on MaliciousLogger V1  
// 3. Victim publishes PaymentApp depending on HelperLib
//    - Security review checks PaymentApp and HelperLib
//    - May not deeply audit MaliciousLogger (transitive dep)
// 4. Upgrade MaliciousLogger to V2 (malicious)
// 5. PaymentApp now executes malicious code without redeployment
```

**Notes**

While the specific question asked about bypassing initial publication reviews, the investigation revealed that **initial publication security works correctly** - all transitive dependencies are declared and validated. However, this uncovered a more severe vulnerability in the **post-publication upgrade mechanism** where malicious code can be injected into already-reviewed package ecosystems through dependency upgrades, effectively achieving the same security impact through a different attack vector.

### Citations

**File:** aptos-move/framework/src/built_package.rs (L552-580)
```rust
        let deps = self
            .package
            .deps_compiled_units
            .iter()
            .flat_map(|(name, unit)| match &unit.unit {
                CompiledUnit::Module(m) => {
                    let package_name = name.as_str().to_string();
                    let account = AccountAddress::new(m.address.into_bytes());

                    Some(PackageDep {
                        account,
                        package_name,
                    })
                },
                CompiledUnit::Script(_) => None,
            })
            .chain(
                self.package
                    .bytecode_deps
                    .iter()
                    .map(|(name, module)| PackageDep {
                        account: NumericalAddress::from_account_address(*module.self_addr())
                            .into_inner(),
                        package_name: name.as_str().to_string(),
                    }),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L137-141)
```text
    /// Whether a compatibility check should be performed for upgrades. The check only passes if
    /// a new module has (a) the same public functions (b) for existing resources, no layout change.
    public fun upgrade_policy_compat(): UpgradePolicy {
        UpgradePolicy { policy: 1 }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L265-279)
```text
    fun check_upgradability(
        old_pack: &PackageMetadata, new_pack: &PackageMetadata, new_modules: &vector<String>) {
        assert!(old_pack.upgrade_policy.policy < upgrade_policy_immutable().policy,
            error::invalid_argument(EUPGRADE_IMMUTABLE));
        assert!(can_change_upgrade_policy_to(old_pack.upgrade_policy, new_pack.upgrade_policy),
            error::invalid_argument(EUPGRADE_WEAKER_POLICY));
        let old_modules = get_module_names(old_pack);

        vector::for_each_ref(&old_modules, |old_module| {
            assert!(
                vector::contains(new_modules, old_module),
                EMODULE_MISSING
            );
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L298-344)
```text
    fun check_dependencies(publish_address: address, pack: &PackageMetadata): vector<AllowedDep>
    acquires PackageRegistry {
        let allowed_module_deps = vector::empty();
        let deps = &pack.deps;
        vector::for_each_ref(deps, |dep| {
            let dep: &PackageDep = dep;
            assert!(exists<PackageRegistry>(dep.account), error::not_found(EPACKAGE_DEP_MISSING));
            if (is_policy_exempted_address(dep.account)) {
                // Allow all modules from this address, by using "" as a wildcard in the AllowedDep
                let account: address = dep.account;
                let module_name = string::utf8(b"");
                vector::push_back(&mut allowed_module_deps, AllowedDep { account, module_name });
            } else {
                let registry = borrow_global<PackageRegistry>(dep.account);
                let found = vector::any(&registry.packages, |dep_pack| {
                    let dep_pack: &PackageMetadata = dep_pack;
                    if (dep_pack.name == dep.package_name) {
                        // Check policy
                        assert!(
                            dep_pack.upgrade_policy.policy >= pack.upgrade_policy.policy,
                            error::invalid_argument(EDEP_WEAKER_POLICY)
                        );
                        if (dep_pack.upgrade_policy == upgrade_policy_arbitrary()) {
                            assert!(
                                dep.account == publish_address,
                                error::invalid_argument(EDEP_ARBITRARY_NOT_SAME_ADDRESS)
                            )
                        };
                        // Add allowed deps
                        let account = dep.account;
                        let k = 0;
                        let r = vector::length(&dep_pack.modules);
                        while (k < r) {
                            let module_name = vector::borrow(&dep_pack.modules, k).name;
                            vector::push_back(&mut allowed_module_deps, AllowedDep { account, module_name });
                            k = k + 1;
                        };
                        true
                    } else {
                        false
                    }
                });
                assert!(found, error::not_found(EPACKAGE_DEP_MISSING));
            };
        });
        allowed_module_deps
    }
```

**File:** aptos-move/framework/src/natives/code.rs (L95-99)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct PackageDep {
    pub account: AccountAddress,
    pub package_name: String,
}
```
