# Audit Report

## Title
CryptoHasher Domain Separation Check is Not Mandatory in CI Pipeline

## Summary
The `check-cryptohasher-symbols.py` script that detects dangerous hash collision scenarios is only executed when a specific CI label is applied, not on every pull request. This creates a risk of deploying code with duplicate CryptoHasher type names that break cryptographic domain separation, as the error detection is optional rather than mandatory. [1](#0-0) 

## Finding Description
The CryptoHasher derive macro generates cryptographic hashers with domain separation based on type names. When two types with identical names exist in different modules (e.g., `module_a::Transaction` and `module_b::Transaction`), they receive identical cryptographic seeds based on their serde names, breaking domain separation. [2](#0-1) 

The script explicitly warns about this vulnerability, stating that duplicate symbol names "can be a potential vulnerability" leading to "hash input collision across domains." [3](#0-2) 

However, the CI workflow only executes this check when the pull request has the `CICD:non-required-tests` label applied. Without this label, code with duplicate CryptoHasher names can be merged without detection.

The cryptographic seed generation in the derive macro relies on `serde_name::trace_name` which returns the base type name without module path qualification: [4](#0-3) 

This means `consensus::BlockData` and `storage::BlockData` would both get seed `b"APTOS::BlockData"`, creating a hash collision vulnerability that violates the cryptographic domain separation guarantee documented in the hash module: [5](#0-4) 

## Impact Explanation
**Medium Severity** - This issue creates a path for insecure deployments through inadequate error detection rather than a direct exploitable vulnerability. The impact includes:

1. **Broken Domain Separation**: Different data structures could hash to the same value, violating the fundamental security property that "hashes of values of a given type never collide with hashes of values from another type"
2. **Potential Consensus Issues**: If consensus-critical types like block data or vote data had naming collisions, different nodes could produce different state roots
3. **No Compile-Time Error**: The collision is silent - code compiles and runs normally
4. **Obscure Error Messages**: When detected (if the script runs), the warning mentions "hash input collision across domains" but developers unfamiliar with cryptographic domain separation might not understand the security implications

This doesn't meet Critical or High severity because exploitation requires the collision to be merged through code review, but it represents a dangerous gap in security tooling.

## Likelihood Explanation
**Medium Likelihood** - The issue can occur through several realistic scenarios:

1. Developer creates a new type with a common name (e.g., `Metadata`, `Config`, `Transaction`) in a different module
2. Pull request doesn't receive the `CICD:non-required-tests` label
3. Code reviewers don't manually notice the duplicate name
4. Code is merged and deployed without the collision being detected

The test unit acknowledges that domain separation issues exist even for the same type with different generic parameters: [6](#0-5) 

## Recommendation
Make the cryptohasher domain separation check mandatory for all pull requests by moving it to the required `rust-lints` job or creating a separate required check:

```yaml
# In .github/workflows/lint-test.yaml
rust-cryptohasher-domain-separation-check:
  needs: file_change_determinator
  runs-on: runs-on,cpu=64,family=c7,disk=large,image=aptos-ubuntu-x64,run-id=${{ github.run_id }}
  # Remove the conditional label requirement
  steps:
    - uses: actions/checkout@v4
    - run: python3 scripts/check-cryptohasher-symbols.py
```

Additionally, enhance the error message in the script to be more explicit about the security implications:

```python
print(f'ERROR: CRITICAL SECURITY ISSUE - Multiple types share the same CryptoHasher name.')
print(f'This breaks cryptographic domain separation and could lead to:')
print(f'  - Hash collisions between different data structures')
print(f'  - Consensus divergence if used in consensus-critical types')  
print(f'  - Transaction signature replay attacks')
print(f'Please rename one of the conflicting types to ensure unique names.')
```

## Proof of Concept
The vulnerability can be demonstrated by:

1. Creating two modules with identically-named types that derive CryptoHasher:
```rust
// In module consensus/src/new_type.rs
#[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct Metadata { data: Vec<u8> }

// In module storage/src/new_type.rs  
#[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct Metadata { value: String }
```

2. Opening a pull request without the `CICD:non-required-tests` label
3. Observing that CI passes without detecting the collision
4. After merge, verifying that both types have identical seeds:
```rust
assert_eq!(
    <consensus::Metadata as CryptoHash>::Hasher::seed(),
    <storage::Metadata as CryptoHash>::Hasher::seed()
); // This assertion would pass, demonstrating the collision
```

This breaks the domain separation invariant and could lead to security issues if these types are used in cryptographically sensitive contexts like consensus messages or transaction signing.

## Notes
The actual `camel_to_snake()` function referenced in the security question is only used for generating static variable identifiers, not for the cryptographic seed itself. The real security issue is in the overall CryptoHasher system's reliance on optional CI checks rather than mandatory compile-time or runtime enforcement of unique domain separators. The error messages from the Python script are reasonably clear when the script runs, but the problem is that the script execution is optional, creating a deployment risk path.

### Citations

**File:** .github/workflows/lint-test.yaml (L57-63)
```yaml
  rust-cryptohasher-domain-separation-check:
    needs: file_change_determinator
    runs-on: runs-on,cpu=64,family=c7,disk=large,image=aptos-ubuntu-x64,run-id=${{ github.run_id }}
    if: contains(github.event.pull_request.labels.*.name, 'CICD:non-required-tests')
    steps:
      - uses: actions/checkout@v4
      - run: python3 scripts/check-cryptohasher-symbols.py
```

**File:** scripts/check-cryptohasher-symbols.py (L1-10)
```python
'''
Today if 2 structs/enums use `CryptoHasher` derive and share the same name,
the current `CryptoHasher` implementation does not prevent hash input collision.
This can be a potential vulnerability.

The easiest way is to let aptos developers ensure unique symbol names.

This script is a quick and dirty script to help find enum/structs in this repo that
use `CryptoHasher` derive and share the same name.
'''
```

**File:** scripts/check-cryptohasher-symbols.py (L59-61)
```python
    print(f'WARNING: the symbol name(s) below are used by 2+ structs/enums that implement `CryptoHasher`. Please ensure unique symbol names to avoid potential hash input collision across domains.')
    pprint(reused_symbol_names)
    exit(2)
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L408-412)
```rust
                #static_seed_name.get_or_init(|| {
                    let name = aptos_crypto::_serde_name::trace_name::<#type_name #param>()
                        .expect("The `CryptoHasher` macro only applies to structs and enums.").as_bytes();
                    aptos_crypto::hash::DefaultHasher::prefixed_hash(&name)
                })
```

**File:** crates/aptos-crypto/src/hash.rs (L27-30)
```rust
//! Regarding (2), this library provides the `CryptoHasher` abstraction to easily manage
//! cryptographic seeds for hashing. Hashing seeds aim to ensure that
//! the hashes of values of a given type `MyNewStruct` never collide with hashes of values
//! from another type.
```

**File:** crates/aptos-crypto/src/unit_tests/cryptohasher.rs (L121-123)
```rust
    // WARNING: There is no domain separation between `Foo<A>` and `Foo<B>`. This might be on purpose,
    // so as to avoid changing the hash when the type of A or B needs to be changed in the code, but
    // it means we should exercise extreme caution when using the CryptoHasher derive.
```
