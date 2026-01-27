# Audit Report

## Title
Domain Separation Bypass via Serde Name Collision in CryptoHasher Implementation

## Summary
The CryptoHasher domain separation mechanism relies solely on Serde type names to generate unique seeds, allowing types with identical Serde names (via `#[serde(rename)]` or accidental collisions) to share the same hasher seed. This creates a theoretical signature reuse vulnerability across different message types. While a detection mechanism exists, it is not enforced as a required CI check.

## Finding Description

The domain separation mechanism in the signing flow uses a seed derived from Serde type names: [1](#0-0) 

The seed generation relies on the Serde name: [2](#0-1) 

The CryptoHasher derive macro uses the Serde name to create the seed: [3](#0-2) 

**Critical Weakness Demonstrated in Unit Tests:** [4](#0-3) [5](#0-4) 

This test explicitly proves that `Baz` (renamed to "Foo") produces identical hashes to `Foo` for the same underlying data, demonstrating signature reuse potential.

**Known Issue with Incomplete Protection:**

The Aptos team acknowledges this vulnerability: [6](#0-5) 

However, the CI check is NOT required: [7](#0-6) 

**Generic Type Parameter Issue:** [8](#0-7) 

**Real Collision Identified:** [9](#0-8) [10](#0-9) 

Both `PersistedStateValue` (with `rename="StateValue"`) and `StateValue` derive CryptoHasher, creating a seed collision.

## Impact Explanation

**Severity Assessment: Medium** (Design Weakness with Incomplete Mitigation)

While this represents a CRITICAL design flaw in the domain separation mechanism, I cannot assign Critical severity because:

1. **No Active Exploit Found**: Despite thorough investigation, I could not identify a concrete case where two types with colliding Serde names are both used in critical signing operations (consensus votes, transactions) with different semantic meanings that would allow fund theft or consensus violation.

2. **StateValue Collision Not Exploitable**: The identified collision involves serialization helpers rather than types directly used in signature operations.

3. **Detection Mechanism Exists**: The `check-cryptohasher-symbols.py` script provides detection capability, even if not enforced.

4. **Known and Monitored**: The team is aware of this limitation (evidenced by the script and test warnings).

However, this remains a **significant security concern** because:
- The unit test proves exploitability in principle
- Future code changes could introduce exploitable collisions
- The CI check is optional, not mandatory
- Generic types lack proper domain separation

## Likelihood Explanation

**Likelihood: Low-to-Medium**

- **Low** for current codebase: No exploitable collision exists in critical signing paths
- **Medium** for future risk: Without mandatory enforcement, new code could introduce collisions
- **High** for theoretical attack: The mechanism demonstrably allows signature reuse if collision exists

The attack complexity is LOW if a collision exists (just craft messages with matching BCS encodings), but finding or introducing such a collision requires either:
1. Accidental naming collision in future code
2. Malicious code introduction with intentional `#[serde(rename)]`

## Recommendation

**Immediate Actions:**

1. **Make CI Check Required**:
```yaml
# In .github/workflows/lint-test.yaml
rust-cryptohasher-domain-separation-check:
  needs: file_change_determinator
  runs-on: runs-on,cpu=64,family=c7,disk=large,image=aptos-ubuntu-x64,run-id=${{ github.run_id }}
  # Remove the conditional: if: contains(github.event.pull_request.labels.*.name, 'CICD:non-required-tests')
  steps:
    - uses: actions/checkout@v4
    - run: python3 scripts/check-cryptohasher-symbols.py
```

2. **Enhance Seed Generation** to include type parameters:
```rust
// In CryptoHasher derive macro
fn seed() -> &'static [u8; 32] {
    $seed_name.get_or_init(|| {
        let name = aptos_crypto::_serde_name::trace_name::<#type_name #param>()
            .expect("The `CryptoHasher` macro only applies to structs and enums.");
        // Include full type information including parameters
        let full_type_name = format!("{}{:?}", name, stringify!(#param));
        aptos_crypto::hash::DefaultHasher::prefixed_hash(full_type_name.as_bytes())
    })
}
```

3. **Add Static Assertion** to prevent renames:
```rust
// In CryptoHasher derive
compile_error_if!(
    stringify!(#type_name) != serde_name,
    "CryptoHasher types must not use #[serde(rename)] - use struct name for domain separation"
);
```

## Proof of Concept

The existing unit test already demonstrates the vulnerability: [5](#0-4) 

To demonstrate signature reuse:

```rust
use aptos_crypto::{ed25519::Ed25519PrivateKey, SigningKey, Uniform};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
struct TypeA { value: u64 }

#[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[serde(rename = "TypeA")]  // Collision!
struct TypeB { value: u64 }

#[test]
fn test_signature_reuse() {
    let key = Ed25519PrivateKey::generate_for_testing();
    
    let msg_a = TypeA { value: 42 };
    let msg_b = TypeB { value: 42 };
    
    let sig_a = key.sign(&msg_a).unwrap();
    // sig_a is a valid signature for msg_b too!
    assert_eq!(msg_a.hash(), msg_b.hash());
}
```

---

**Notes:**

Despite identifying the design weakness and providing concrete evidence of its existence, I must acknowledge that **no currently exploitable vulnerability in production code was found**. The StateValue collision does not create a signature reuse attack vector, and no consensus or transaction types were discovered with dangerous collisions. The team has implemented monitoring (though not enforced), and the issue is documented in tests.

This represents a **significant security debt** that should be addressed through mandatory CI enforcement and design improvements, but falls short of an immediately exploitable critical vulnerability per the strict validation criteria.

### Citations

**File:** crates/aptos-crypto/src/traits/mod.rs (L170-177)
```rust
pub fn signing_message<T: CryptoHash + Serialize>(
    message: &T,
) -> Result<Vec<u8>, CryptoMaterialError> {
    let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
    bcs::serialize_into(&mut bytes, &message)
        .map_err(|_| CryptoMaterialError::SerializationError)?;
    Ok(bytes)
}
```

**File:** crates/aptos-crypto/src/hash.rs (L522-529)
```rust
    pub fn prefixed_hash(buffer: &[u8]) -> [u8; HashValue::LENGTH] {
        // The salt is initial material we prefix to actual value bytes for
        // domain separation. Its length is variable.
        let salt: Vec<u8> = [HASH_PREFIX, buffer].concat();
        // The seed is a fixed-length hash of the salt, thereby preventing
        // suffix attacks on the domain separation bytes.
        HashValue::sha3_256_of(&salt[..]).hash
    }
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L407-413)
```rust
            fn seed() -> &'static [u8; 32] {
                #static_seed_name.get_or_init(|| {
                    let name = aptos_crypto::_serde_name::trace_name::<#type_name #param>()
                        .expect("The `CryptoHasher` macro only applies to structs and enums.").as_bytes();
                    aptos_crypto::hash::DefaultHasher::prefixed_hash(&name)
                })
            }
```

**File:** crates/aptos-crypto/src/unit_tests/cryptohasher.rs (L26-31)
```rust
#[derive(Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[serde(rename = "Foo")]
pub struct Baz<T> {
    a: T,
    b: u32,
}
```

**File:** crates/aptos-crypto/src/unit_tests/cryptohasher.rs (L84-90)
```rust
#[test]
fn test_bcs_cryptohash_with_generics() {
    let value = Baz { a: 5u64, b: 1025 };
    let expected = CryptoHash::hash(&Foo { a: 5, b: 1025 });
    let actual = CryptoHash::hash(&value);
    assert_eq!(expected, actual);
}
```

**File:** crates/aptos-crypto/src/unit_tests/cryptohasher.rs (L121-127)
```rust
    // WARNING: There is no domain separation between `Foo<A>` and `Foo<B>`. This might be on purpose,
    // so as to avoid changing the hash when the type of A or B needs to be changed in the code, but
    // it means we should exercise extreme caution when using the CryptoHasher derive.
    assert_eq!(
        <Duplo<usize, u8> as CryptoHash>::Hasher::seed(),
        &prefixed_sha3(b"Duplo")
    );
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

**File:** types/src/state_store/state_value.rs (L161-169)
```rust
#[derive(BCSCryptoHash, CryptoHasher, Deserialize, Serialize)]
#[serde(rename = "StateValue")]
enum PersistedStateValue {
    V0(Bytes),
    WithMetadata {
        data: Bytes,
        metadata: PersistedStateValueMetadata,
    },
}
```

**File:** types/src/state_store/state_value.rs (L182-187)
```rust
#[derive(Clone, Debug, BCSCryptoHash, CryptoHasher)]
pub struct StateValue {
    data: Bytes,
    metadata: StateValueMetadata,
    maybe_rapid_hash: Option<(u64, usize)>,
}
```
