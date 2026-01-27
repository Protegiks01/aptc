# Audit Report

## Title
JWK Ord Trait Contract Violation Enables Potential Consensus Liveness Failure Through Non-Deterministic Sorting

## Summary
The `Ord` implementation for the `JWK` enum violates Rust's trait contract by comparing only by `id()` while `PartialEq` compares all fields. This can lead to non-deterministic sorting behavior when JWKs with identical IDs but different cryptographic properties are processed, potentially causing consensus liveness failures. [1](#0-0) 

## Finding Description
The JWK consensus system fetches JSON Web Keys from external OIDC providers and sorts them before processing. The `Ord` trait implementation for `JWK` violates Rust's fundamental ordering contract:

**Trait Contract Violation:**
The `Ord::cmp()` implementation compares JWKs solely by their `id()` method, while the `PartialEq` trait (derived on the enum) compares all fields including cryptographic properties like RSA modulus `n`, exponent `e`, and algorithm `alg`. [2](#0-1) [3](#0-2) 

According to Rust's `Ord` trait requirements: *"If `a.cmp(b) == Ordering::Equal`, then `a == b` must be true."* This implementation violates that contract, making the sort behavior unspecified.

**Exploitation Path:**

1. A malicious or compromised OIDC provider returns a JWK set containing multiple RSA_JWK entries with identical `kid` values but different cryptographic properties (different modulus `n` or exponent `e`)

2. Validators fetch this JWK set and invoke sorting: [4](#0-3) 

3. Due to the Ord violation, the sort produces unspecified ordering. While typically deterministic within a single binary, Rust's documentation explicitly states that violating trait contracts leads to unspecified behavior

4. The sorted vector is converted to a HashMap, where duplicate IDs cause only the last JWK in iteration order to survive: [5](#0-4) 

5. Different validators may end up with different JWKs for the same key ID (depending on iteration order), leading to divergent consensus proposals

6. Validators fail to reach quorum on JWK updates, causing consensus liveness failure for the JWK subsystem

**Invariant Violation:**
This breaks Aptos's **Deterministic Execution** invariant, which requires all validators to produce identical results for identical inputs. The codebase explicitly mandates deterministic data structures: [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

- **Validator node slowdowns**: JWK consensus would repeatedly fail to reach quorum, causing delays and retries
- **Significant protocol violations**: Violates the deterministic execution guarantee and breaks the JWK consensus protocol

The Move framework explicitly expects JWKs to be sorted and unique by ID: [7](#0-6) 

The Move code's upsert logic assumes JWKs with identical IDs are equivalent and replaces them: [8](#0-7) 

This assumption is violated when JWKs have the same ID but different cryptographic properties, creating a mismatch between Rust and Move layer expectations.

## Likelihood Explanation
**Likelihood: Medium-Low**

Exploitation requires:
1. **Malicious OIDC Provider**: An attacker must control or compromise an OIDC provider configured in `SupportedOIDCProviders`
2. **Duplicate Key IDs**: The provider must return JWKs with identical `kid` values but different cryptographic properties
3. **Active Validators**: Validators must be actively running JWK consensus for the affected provider

While requiring external system compromise, this does not require insider validator access. OIDC providers are external third parties and could be compromised through standard attack vectors (supply chain, misconfiguration, etc.).

## Recommendation
**Fix the Ord implementation to be consistent with PartialEq:**

```rust
impl Ord for JWK {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare by ID
        let id_cmp = self.id().cmp(&other.id());
        if id_cmp != Ordering::Equal {
            return id_cmp;
        }
        
        // If IDs are equal, compare by variant type and all fields
        // to ensure total ordering consistency with PartialEq
        match (self, other) {
            (JWK::RSA(a), JWK::RSA(b)) => {
                // Compare all RSA_JWK fields
                a.kid.cmp(&b.kid)
                    .then_with(|| a.kty.cmp(&b.kty))
                    .then_with(|| a.alg.cmp(&b.alg))
                    .then_with(|| a.e.cmp(&b.e))
                    .then_with(|| a.n.cmp(&b.n))
            },
            (JWK::Unsupported(a), JWK::Unsupported(b)) => {
                a.id.cmp(&b.id).then_with(|| a.payload.cmp(&b.payload))
            },
            (JWK::RSA(_), JWK::Unsupported(_)) => Ordering::Less,
            (JWK::Unsupported(_), JWK::RSA(_)) => Ordering::Greater,
        }
    }
}
```

**Additionally, add validation to reject duplicate key IDs:**

In `jwk_observer.rs`, add deduplication after fetching:
```rust
let mut seen_ids = std::collections::HashSet::new();
jwks.retain(|jwk| seen_ids.insert(jwk.id()));
```

## Proof of Concept

```rust
#[test]
fn test_jwk_ord_violation() {
    use aptos_types::jwks::{jwk::JWK, rsa::RSA_JWK};
    
    // Create two RSA_JWKs with identical kid but different modulus
    let jwk1 = JWK::RSA(RSA_JWK::new_from_strs(
        "key1",           // same kid
        "RSA",
        "RS256",
        "AQAB",
        "modulus1"        // different modulus
    ));
    
    let jwk2 = JWK::RSA(RSA_JWK::new_from_strs(
        "key1",           // same kid
        "RSA",
        "RS256", 
        "AQAB",
        "modulus2"        // different modulus
    ));
    
    // Ord says they're equal (same ID)
    assert_eq!(jwk1.cmp(&jwk2), std::cmp::Ordering::Equal);
    
    // But PartialEq says they're different (different fields)
    assert_ne!(jwk1, jwk2);
    
    // This violates the Ord trait contract!
    // If a.cmp(b) == Equal, then a == b MUST be true
    
    // Demonstrate unstable sort behavior
    let mut vec1 = vec![jwk1.clone(), jwk2.clone()];
    let mut vec2 = vec![jwk2.clone(), jwk1.clone()];
    
    vec1.sort();
    vec2.sort();
    
    // The sort cannot establish a total ordering, behavior is unspecified
    // Different orderings may result in different HashMap entries
    use std::collections::HashMap;
    
    let map1: HashMap<_, _> = vec1.into_iter().map(|jwk| (jwk.id(), jwk)).collect();
    let map2: HashMap<_, _> = vec2.into_iter().map(|jwk| (jwk.id(), jwk)).collect();
    
    // Maps may contain different JWKs for the same ID
    // This leads to non-deterministic validator state
}
```

### Citations

**File:** types/src/jwks/jwk/mod.rs (L53-57)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Union)]
pub enum JWK {
    RSA(RSA_JWK),
    Unsupported(UnsupportedJWK),
}
```

**File:** types/src/jwks/jwk/mod.rs (L74-77)
```rust
impl Ord for JWK {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(&other.id())
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

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L77-80)
```rust
                    if let Ok(mut jwks) = result {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "ok"]).observe(secs);
                        jwks.sort();
                        let _ = observation_tx.push((), (issuer.as_bytes().to_vec(), jwks));
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L115-116)
```rust
        let observed_jwks_by_kid: HashMap<KID, JWK> =
            jwks.into_iter().map(|jwk| (jwk.id(), jwk)).collect();
```

**File:** RUST_SECURE_CODING.md (L121-123)
```markdown
### Data Structures with Deterministic Internal Order

Certain data structures, like HashMap and HashSet, do not guarantee a deterministic order for the elements stored within them. This lack of order can lead to problems in operations that require processing elements in a consistent sequence across multiple executions. In the Aptos blockchain, deterministic data structures help in achieving consensus, maintaining the integrity of the ledger, and ensuring that computations can be reliably reproduced across different nodes.
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L104-105)
```text
        /// Vector of `JWK`'s sorted by their unique ID (from `get_jwk_id`) in dictionary order.
        jwks: vector<JWK>,
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L632-647)
```text
            let comparison = compare_u8_vector(get_jwk_id(&jwk), get_jwk_id(cur_entry));
            if (is_greater_than(&comparison)) {
                index = index + 1;
            } else {
                found = is_equal(&comparison);
                break
            }
        };

        // Now if `found == true`, `index` points to the JWK we want to update/remove; otherwise, `index` points to
        // where we want to insert.
        let ret = if (found) {
            let entry = vector::borrow_mut(&mut set.jwks, index);
            let old_entry = option::some(*entry);
            *entry = jwk;
            old_entry
```
