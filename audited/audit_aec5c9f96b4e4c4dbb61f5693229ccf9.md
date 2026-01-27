# Audit Report

## Title
Unmetered Access Control Checks Enable Resource Exhaustion DoS on Validator Nodes

## Summary
The access control checking mechanism in the Move VM performs O(n*m) clause comparisons per resource access, where n is the number of specifiers on the call stack and m is the number of clauses per specifier. These checks are not gas-metered, creating an asymmetric resource consumption vulnerability where attackers can cause significant CPU overhead on validators while paying only normal gas costs.

## Finding Description

The vulnerability exists in the access control system's interaction between the `check_access()` function and the `enables()` method. While the security question mentions "thousands of clauses," the actual bytecode limit is 64 clauses per function, but the attack vector remains valid through call stack depth. [1](#0-0) 

When a function is entered, its access specifier (containing up to 64 clauses) is pushed onto the access control stack: [2](#0-1) 

The stack can grow up to 256 specifiers: [3](#0-2) 

Every resource access operation (BorrowGlobal, Exists, MoveFrom, MoveTo) triggers access control validation against ALL specifiers on the stack: [4](#0-3) 

Each specifier's `enables()` method iterates through its inclusion and exclusion clauses: [5](#0-4) 

**Critical Issue:** Gas is charged for resource operations BEFORE access control checks, and the checks themselves are not metered: [6](#0-5) 

**Attack Path:**
1. Attacker deploys Move modules with functions having 64 access specifier clauses each (maximum allowed)
2. Creates transaction with deep call chain (e.g., 50-100 levels within gas limits)
3. Each function in the chain has 64 access specifier clauses
4. Within these functions, performs multiple resource access operations
5. Each resource access triggers O(stack_depth * clauses_per_specifier) comparisons
6. Example: 50 specifiers * 64 clauses = 3,200 comparisons per resource access
7. With 200 resource accesses per transaction: 640,000 total clause comparisons
8. At ~100 CPU instructions per comparison: ~64 million instructions of unmetered computation

The feature is enabled by default: [7](#0-6) 

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program:
- **Validator node slowdowns**: The unmetered CPU overhead can degrade validator performance
- **Resource exhaustion**: Creates asymmetric resource consumption where gas paid < computational cost
- **DoS potential**: Attackers can send many such transactions to amplify the effect

The impact does not reach High or Critical severity because:
- No consensus safety violation (deterministic execution preserved)
- No fund theft or manipulation
- No complete liveness failure (only performance degradation)
- Attack is bounded by transaction gas limits and stack limits

However, the vulnerability violates **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits." Access control checks bypass gas metering, allowing operations whose computational cost exceeds their gas cost.

## Likelihood Explanation

**Likelihood: Medium**

**Attacker Requirements:**
- Ability to deploy Move modules (standard network operation)
- No privileged validator access needed
- No complex cryptographic attack required

**Feasibility:**
- Attack is straightforward to implement
- Within transaction gas limits (MAX_GAS_AMOUNT = 2,000,000)
- Call stack limit (1024) and access stack limit (256) allow sufficient depth
- Can craft access specifiers that are permissive enough to succeed but complex enough to be expensive

**Constraints:**
- Limited to 64 clauses per function (not thousands as question suggests)
- Transaction gas limits constrain total operations
- Per-clause cost is relatively low (just comparisons)
- Attack requires sustained transaction volume for meaningful DoS

## Recommendation

**Solution: Add gas metering for access control checks**

Modify the `check_access()` method to charge gas proportional to the number of specifiers and clauses checked:

```rust
pub(crate) fn check_access(&self, access: AccessInstance, gas_meter: &mut impl GasMeter) -> PartialVMResult<()> {
    let mut checks_performed = 0;
    for specifier in self.specifier_stack.iter().rev() {
        if !specifier.enables(&access) {
            return Err(PartialVMError::new(StatusCode::ACCESS_DENIED)
                .with_message(format!("not allowed to perform `{}`", access)));
        }
        // Count clause checks performed
        checks_performed += match specifier {
            AccessSpecifier::Any => 0,
            AccessSpecifier::Constraint(incls, excls) => incls.len() + excls.len(),
        };
    }
    
    // Charge gas proportional to checks performed
    gas_meter.charge_access_control_check(checks_performed)?;
    Ok(())
}
```

**Alternative: Enforce tighter limits**
- Reduce ACCESS_SPECIFIER_COUNT_MAX from 64 to 16
- Reduce ACCESS_STACK_SIZE_LIMIT from 256 to 64
- Add per-transaction limit on total access control checks

**Recommended Fix:** Implement gas metering with a small per-clause cost (e.g., 10 gas units per clause checked) to align computational cost with gas payment.

## Proof of Concept

```move
// Malicious module designed to exploit unmetered access control checks
module attacker::dos_module {
    use std::signer;
    
    struct Resource1 has key { value: u64 }
    struct Resource2 has key { value: u64 }
    // ... define up to 32 resource types ...
    
    // Function with maximum 64 access specifier clauses
    // Each 'reads' clause adds to the inclusion list
    public fun expensive_check_1(account: &signer)
        reads Resource1(*), reads Resource2(*), 
        // ... add 62 more 'reads' clauses for different resources ...
    {
        // Perform resource accesses that trigger expensive checks
        borrow_global<Resource1>(signer::address_of(account));
        borrow_global<Resource2>(signer::address_of(account));
    }
    
    public fun expensive_check_2(account: &signer) 
        reads Resource1(*), reads Resource2(*),
        // ... 62 more clauses ...
    {
        expensive_check_1(account);
        // More resource accesses
        borrow_global<Resource1>(signer::address_of(account));
    }
    
    // Chain of 50 functions, each with 64 clauses
    // Each calling the previous, building stack to 50 specifiers
    // Each performing 4 resource accesses
    // Total: 50 * 64 = 3,200 checks per resource access
    // With 200 resource accesses: 640,000 unmetered clause checks
}
```

**Exploitation Steps:**
1. Deploy the module above with functions having maximum access specifiers
2. Create transaction calling the deepest function in the chain
3. Transaction pays normal gas (~2M gas limit) but causes:
   - 640,000 clause comparisons
   - ~64 million unmetered CPU instructions
   - ~20ms validator CPU time per transaction
4. Send 50 transactions per second = 1 full CPU core of unmetered overhead
5. Amplify with multiple attackers or higher transaction rates

**Expected Result:** Validators experience measurable performance degradation while attackers pay only normal transaction gas costs, demonstrating the gas metering invariant violation.

## Notes

The security question's premise is slightly inaccurate—attackers cannot create specifiers with "thousands" of clauses due to the 64-clause limit enforced at bytecode deserialization. However, the underlying vulnerability is valid: through deep call stacks (up to 256 specifiers) combined with maximum clause counts (64 per specifier), attackers can force validators to perform up to 16,384 unmetered clause comparisons per resource access, creating an exploitable asymmetry between gas cost and computational cost.

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L86-86)
```rust
pub const ACCESS_SPECIFIER_COUNT_MAX: u64 = 64;
```

**File:** third_party/move/move-vm/runtime/src/access_control.rs (L26-48)
```rust
    pub(crate) fn enter_function(
        &mut self,
        env: &impl AccessSpecifierEnv,
        fun: &LoadedFunction,
    ) -> PartialVMResult<()> {
        if matches!(fun.access_specifier(), AccessSpecifier::Any) {
            // Shortcut case that no access is specified
            return Ok(());
        }
        if self.specifier_stack.len() >= ACCESS_STACK_SIZE_LIMIT {
            Err(
                PartialVMError::new(StatusCode::ACCESS_STACK_LIMIT_EXCEEDED).with_message(format!(
                    "access specifier stack overflow (limit = {})",
                    ACCESS_STACK_SIZE_LIMIT
                )),
            )
        } else {
            // Specialize the functions access specifier and push it on the stack.
            let mut fun_specifier = fun.access_specifier().clone();
            fun_specifier.specialize(env)?;
            self.specifier_stack.push(fun_specifier);
            Ok(())
        }
```

**File:** third_party/move/move-vm/runtime/src/access_control.rs (L69-77)
```rust
    pub(crate) fn check_access(&self, access: AccessInstance) -> PartialVMResult<()> {
        for specifier in self.specifier_stack.iter().rev() {
            if !specifier.enables(&access) {
                return Err(PartialVMError::new(StatusCode::ACCESS_DENIED)
                    .with_message(format!("not allowed to perform `{}`", access)));
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1380-1398)
```rust
        gas_meter.charge_borrow_global(
            is_mut,
            is_generic,
            TypeWithRuntimeEnvironment {
                ty,
                runtime_environment,
            },
            res.is_ok(),
        )?;
        self.check_access(
            runtime_environment,
            if is_mut {
                AccessKind::Writes
            } else {
                AccessKind::Reads
            },
            ty,
            addr,
        )?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1768-1768)
```rust
pub(crate) const ACCESS_STACK_SIZE_LIMIT: usize = 256;
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L144-153)
```rust
    pub fn enables(&self, access: &AccessInstance) -> bool {
        use AccessSpecifier::*;
        match self {
            Any => true,
            Constraint(incls, excls) => {
                (incls.is_empty() && !excls.is_empty() || incls.iter().any(|c| c.includes(access)))
                    && excls.iter().all(|c| !c.excludes(access))
            },
        }
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L245-245)
```rust
            FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL,
```
