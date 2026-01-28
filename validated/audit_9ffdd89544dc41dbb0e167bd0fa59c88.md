# Audit Report

## Title
JWK Ord Trait Contract Violation Enables Potential Consensus Liveness Failure Through Non-Deterministic Sorting

## Summary
The `Ord` implementation for the `JWK` enum violates Rust's trait contract by comparing only by `id()` while `PartialEq` compares all fields. Combined with HashMap usage in the per-key consensus path, this can lead to non-deterministic behavior when JWKs with identical IDs but different cryptographic properties are processed, potentially causing consensus liveness failures.

## Finding Description

The JWK consensus system contains a fundamental trait contract violation that breaks Aptos's deterministic execution guarantees:

**Trait Contract Violation:**

The `Ord::cmp()` implementation compares JWKs solely by their `id()` method: [1](#0-0) 

However, `PartialEq` is derived on the enum and compares all fields including cryptographic properties: [2](#0-1) 

The RSA_JWK structure contains multiple fields beyond the `kid`: [3](#0-2) 

This violates Rust's `Ord` trait requirement: "If `a.cmp(b) == Ordering::Equal`, then `a == b` must be true." Two JWKs with identical `kid` but different `n`, `e`, or `alg` values will compare as Equal via `Ord` but return false for `PartialEq`.

**Exploitation Path:**

1. A malicious or compromised OIDC provider returns a JWK set containing multiple RSA_JWK entries with identical `kid` values but different cryptographic properties (different modulus `n` or exponent `e`)

2. Validators fetch this JWK set and invoke sorting: [4](#0-3) 

3. Due to the Ord violation, when two JWKs have the same `kid`, they compare as Equal. The stable sort maintains relative order from the input, but different validators may receive different JSON array orders from the OIDC provider (via CDN routing, IP-based responses, or intentional provider behavior)

4. In per-key consensus mode, the sorted vector is converted to a HashMap where duplicate IDs cause only the last JWK in iteration order to survive: [5](#0-4) 

5. Different validators end up with different JWKs for the same key ID, leading to divergent consensus proposals

6. Validators fail to reach quorum on JWK updates, causing consensus liveness failure for the JWK subsystem

**Invariant Violation:**

This breaks Aptos's **Deterministic Execution** invariant. The codebase explicitly mandates deterministic data structures for consensus: [6](#0-5) 

The Aptos secure coding guidelines explicitly state that HashMap is non-deterministic and should be avoided in consensus-critical paths. The per-key consensus manager violates this by using HashMap to index observed JWKs.

The Move framework expects JWKs to be sorted and unique by ID: [7](#0-6) 

The Move upsert logic assumes JWKs with identical IDs are equivalent and replaces them: [8](#0-7) 

This assumption is violated when JWKs have the same ID but different cryptographic properties.

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

- **Validator node slowdowns**: JWK consensus would repeatedly fail to reach quorum for the affected issuer, causing delays and retries. The consensus manager would be unable to certify updates, requiring manual intervention or provider removal.

- **Significant protocol violations**: Violates the deterministic execution guarantee explicitly documented in RUST_SECURE_CODING.md. Breaks the JWK consensus protocol's correctness assumptions.

The per-key consensus mode is controlled by a feature flag: [9](#0-8) 

When this mode is enabled, the vulnerability becomes exploitable. The trait contract violation exists regardless of mode, but the HashMap usage in per-key mode creates the actual attack surface.

## Likelihood Explanation

**Likelihood: Medium-Low**

Exploitation requires:

1. **Malicious OIDC Provider**: An attacker must control or compromise an OIDC provider configured in `SupportedOIDCProviders`. OIDC providers are external third-party services (Google, Facebook, etc.) that could be compromised through supply chain attacks, misconfigurations, or infrastructure breaches.

2. **Duplicate Key IDs**: The provider must return JWKs with identical `kid` values but different cryptographic properties (`n`, `e`, `alg`). While non-standard, nothing prevents a malicious provider from doing this.

3. **Per-Key Mode Enabled**: The `JWK_CONSENSUS_PER_KEY_MODE` feature flag must be enabled for the HashMap conversion to occur in the vulnerable code path.

4. **Different Orderings**: Different validators must receive different JSON array orders from the provider (achievable via CDN routing, IP-based responses, or intentional provider manipulation).

While requiring external system compromise, this does not require insider validator access or >1/3 Byzantine validators. OIDC providers are untrusted external actors in Aptos's threat model.

## Recommendation

**Fix the Ord trait contract violation:**

Implement `Ord` to be consistent with `PartialEq` by comparing all fields, not just `id()`. Alternatively, if JWKs are truly meant to be identified solely by `id()`, implement `PartialEq` to also compare only by `id()`.

**Option 1: Fix Ord to match PartialEq (compare all fields):**
```rust
impl Ord for JWK {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare by ID for primary ordering
        match self.id().cmp(&other.id()) {
            Ordering::Equal => {
                // If IDs are equal, compare by full content
                // This ensures Ord is consistent with PartialEq
                match self {
                    JWK::RSA(a) => match other {
                        JWK::RSA(b) => (a.kid.as_str(), &a.kty, &a.alg, &a.e, &a.n)
                            .cmp(&(b.kid.as_str(), &b.kty, &b.alg, &b.e, &b.n)),
                        JWK::Unsupported(_) => Ordering::Less,
                    },
                    JWK::Unsupported(a) => match other {
                        JWK::RSA(_) => Ordering::Greater,
                        JWK::Unsupported(b) => (&a.id, &a.payload).cmp(&(&b.id, &b.payload)),
                    },
                }
            },
            other => other,
        }
    }
}
```

**Option 2: Add validation to reject duplicate kids from OIDC providers:**

Add explicit validation in `fetch_jwks` to detect and reject JWK sets with duplicate `kid` values, failing the fetch operation if duplicates are found.

**Option 3: Use BTreeMap instead of HashMap:**

Replace the HashMap usage in per-key consensus with BTreeMap for deterministic ordering, as mandated by RUST_SECURE_CODING.md.

## Proof of Concept

A complete PoC would require:
1. Mock OIDC provider returning duplicate kids
2. Multiple validator instances
3. Per-key mode enabled

Simplified demonstration of the trait violation:

```rust
use aptos_types::jwks::{jwk::JWK, rsa::RSA_JWK};

#[test]
fn test_ord_partialeq_violation() {
    let jwk1 = JWK::RSA(RSA_JWK::new_from_strs(
        "test_kid",
        "RSA", 
        "RS256",
        "AQAB",
        "modulus1"
    ));
    
    let jwk2 = JWK::RSA(RSA_JWK::new_from_strs(
        "test_kid",  // Same kid
        "RSA",
        "RS256", 
        "AQAB",
        "modulus2"  // Different modulus
    ));
    
    // Ord says they're equal (same id)
    assert_eq!(jwk1.cmp(&jwk2), std::cmp::Ordering::Equal);
    
    // But PartialEq says they're not equal (different fields)
    assert_ne!(jwk1, jwk2);
    
    // This violates Rust's Ord trait contract
}
```

### Citations

**File:** types/src/jwks/jwk/mod.rs (L53-56)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Union)]
pub enum JWK {
    RSA(RSA_JWK),
    Unsupported(UnsupportedJWK),
```

**File:** types/src/jwks/jwk/mod.rs (L74-78)
```rust
impl Ord for JWK {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(&other.id())
    }
}
```

**File:** types/src/jwks/rsa/mod.rs (L18-25)
```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct RSA_JWK {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub e: String,
    pub n: String,
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L79-79)
```rust
                        jwks.sort();
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L115-116)
```rust
        let observed_jwks_by_kid: HashMap<KID, JWK> =
            jwks.into_iter().map(|jwk| (jwk.id(), jwk)).collect();
```

**File:** RUST_SECURE_CODING.md (L121-125)
```markdown
### Data Structures with Deterministic Internal Order

Certain data structures, like HashMap and HashSet, do not guarantee a deterministic order for the elements stored within them. This lack of order can lead to problems in operations that require processing elements in a consistent sequence across multiple executions. In the Aptos blockchain, deterministic data structures help in achieving consensus, maintaining the integrity of the ledger, and ensuring that computations can be reliably reproduced across different nodes.

Below is a list of deterministic data structures available in Rust. Please note, this list may not be exhaustive:
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L104-105)
```text
        /// Vector of `JWK`'s sorted by their unique ID (from `get_jwk_id`) in dictionary order.
        jwks: vector<JWK>,
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L643-647)
```text
        let ret = if (found) {
            let entry = vector::borrow_mut(&mut set.jwks, index);
            let old_entry = option::some(*entry);
            *entry = jwk;
            old_entry
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L699-705)
```text
    const JWK_CONSENSUS_PER_KEY_MODE: u64 = 92;

    public fun get_jwk_consensus_per_key_mode_feature(): u64 { JWK_CONSENSUS_PER_KEY_MODE }

    public fun is_jwk_consensus_per_key_mode_enabled(): bool acquires Features {
        is_enabled(JWK_CONSENSUS_PER_KEY_MODE)
    }
```
