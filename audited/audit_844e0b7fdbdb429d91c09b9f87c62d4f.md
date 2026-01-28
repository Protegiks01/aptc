# Audit Report

## Title
Non-Deterministic JSON Serialization in UnsupportedJWK Causes JWK Consensus Failures

## Summary
The `UnsupportedJWK::from(serde_json::Value)` implementation uses non-canonical JSON serialization via `to_string()`, which can produce different byte representations when OIDC providers return JSON with varying key orderings. This causes different validators to compute different hashes for the same JWK, breaking multi-signature verification and preventing JWK updates from reaching consensus.

## Finding Description
When validators fetch JWKs from OIDC providers through the JWK consensus protocol, non-RSA keys are converted to `UnsupportedJWK` structures. The conversion process re-serializes the parsed JSON using `json_value.to_string()`: [1](#0-0) 

The implementation contains a TODO comment explicitly acknowledging the need for canonical serialization. This non-canonical approach violates the documented security guidelines in the Aptos codebase: [2](#0-1) 

HTTP servers commonly use HashMaps internally and may return JSON object keys in non-deterministic order across different requests. When validators fetch JWKs at different times via the JWK consensus protocol: [3](#0-2) 

The parsed `serde_json::Value` objects are converted to `JWK` enum types, which fall back to `UnsupportedJWK` for non-RSA keys: [4](#0-3) 

These `UnsupportedJWK` structures are embedded in `JWKMoveStruct` via the `Any` type's `data` field, which then get included in `ProviderJWKs` structures that validators must sign for consensus: [5](#0-4) 

The `ProviderJWKs` struct is derived with `CryptoHasher` and `BCSCryptoHash`, making it subject to cryptographic hashing during the signing process. When validators sign `ProviderJWKs` containing `UnsupportedJWK` instances with different payloads due to different JSON key orderings, they produce signatures over different message hashes.

During validator transaction processing, multi-signature verification occurs: [6](#0-5) 

The verification implementation performs cryptographic validation of the aggregate signature: [7](#0-6) 

The verification fails because validators signed different messages (different payload bytes in `UnsupportedJWK`), preventing the JWK update from being applied on-chain.

**Attack Path:**
1. OIDC provider serves non-RSA JWKs (e.g., EC keys) or malformed RSA keys
2. Provider's HTTP server returns JSON with non-deterministic key ordering (common HashMap behavior)
3. Validator A fetches JWK, receives: `{"kty":"EC","kid":"key1","crv":"P-256",...}`
4. Validator B fetches JWK, receives: `{"kid":"key1","kty":"EC","crv":"P-256",...}`
5. Both parse and convert to `UnsupportedJWK` with different `payload` bytes due to preserved key ordering
6. Both compute different SHA3-256 hashes for the `id` field
7. Both create `ProviderJWKs` with different BCS-serialized content
8. Multi-signature verification fails with `MultiSigVerificationFailed` error, update rejected

## Impact Explanation
This vulnerability breaks the **Deterministic Execution** invariant specifically for the JWK consensus subsystem, as documented in Aptos security guidelines. While it doesn't directly compromise blockchain consensus or fund safety, it prevents critical keyless account infrastructure from functioning correctly.

**Impact Classification: Medium Severity**

The vulnerability causes state inconsistencies requiring manual intervention:
- JWK updates for affected OIDC providers cannot reach consensus
- Keyless accounts depending on those providers may become inaccessible
- Users cannot authenticate or sign transactions with affected keyless accounts
- Manual intervention or provider reconfiguration required to restore functionality

This aligns with the Aptos bug bounty **Medium Severity** category: "State inconsistencies requiring manual intervention" and "Limited funds loss or manipulation" (users lose access to funds through keyless accounts).

This does not meet Critical severity because:
- Core blockchain consensus remains unaffected (only JWK consensus subsystem impacted)
- No direct fund theft or loss occurs
- Network remains available for non-keyless transactions

It exceeds Low severity because:
- Affects user access to funds through keyless accounts
- Requires operational intervention to resolve
- Impacts production keyless account functionality

## Likelihood Explanation
**Likelihood: Medium**

This vulnerability can manifest without malicious intent through natural system behavior:

1. **Common Server Behavior**: Many HTTP servers and JSON libraries use HashMaps that don't guarantee consistent key ordering across requests (e.g., Go's `encoding/json`, some Python JSON libraries, older Node.js versions)

2. **Legitimate OIDC Providers**: Major providers may rotate between EC and RSA keys, or use non-RSA algorithms like ES256 (ECDSA with P-256), triggering the `UnsupportedJWK` path

3. **No Attack Required**: Natural server behavior causes the issue - no attacker action needed

4. **Evidence in Code**: The TODO comment acknowledges this is a known limitation requiring canonical serialization

Factors reducing immediate likelihood:
- Most major OIDC providers (Google, Facebook, Microsoft) currently use RSA keys
- Issue only affects non-RSA or malformed keys that fail RSA parsing
- Developers aware of the issue (TODO comment present) but haven't implemented a fix

## Recommendation
Implement canonical JSON serialization for `UnsupportedJWK` to ensure deterministic byte representation regardless of key ordering. The fix should:

1. Sort JSON object keys alphabetically before serialization
2. Use a canonical JSON library or implement custom serialization
3. Ensure the `id` hash is computed over the canonical representation

Example fix approach:
- Replace `json_value.to_string()` with canonical JSON serialization
- Consider using `serde_json::to_vec()` with a custom serializer that enforces key ordering
- Alternatively, parse the JSON into a BTreeMap to ensure sorted keys before serialization

This follows the pattern used elsewhere in the codebase for deterministic serialization: [8](#0-7) 

## Proof of Concept
The vulnerability can be demonstrated by:

1. Setting up a dummy OIDC provider that returns EC keys (non-RSA) with varying JSON key orderings
2. Having different validators fetch the JWK at different times
3. Observing that validators compute different `UnsupportedJWK` hashes
4. Verifying that multi-signature verification fails due to signing different messages

The smoke test infrastructure demonstrates equivocation handling but doesn't test the specific case of identical semantic content with different JSON key ordering: [9](#0-8) 

A proper PoC would need to extend this test to return the same semantic JSON content with different key orderings to different validators.

## Notes
- The TODO comment at line 53 of `types/src/jwks/unsupported/mod.rs` indicates developers are aware of this limitation but haven't implemented a fix
- This vulnerability only affects non-RSA JWKs; RSA keys parse JSON fields directly and are not affected
- The issue violates documented Aptos security guidelines requiring deterministic data structures for consensus operations
- While the JWK consensus subsystem is affected, core blockchain consensus remains secure

### Citations

**File:** types/src/jwks/unsupported/mod.rs (L51-59)
```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        let payload = json_value.to_string().into_bytes(); //TODO: canonical to_string.
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
}
```

**File:** RUST_SECURE_CODING.md (L121-132)
```markdown
### Data Structures with Deterministic Internal Order

Certain data structures, like HashMap and HashSet, do not guarantee a deterministic order for the elements stored within them. This lack of order can lead to problems in operations that require processing elements in a consistent sequence across multiple executions. In the Aptos blockchain, deterministic data structures help in achieving consensus, maintaining the integrity of the ledger, and ensuring that computations can be reliably reproduced across different nodes.

Below is a list of deterministic data structures available in Rust. Please note, this list may not be exhaustive:

- **BTreeMap:** maintains its elements in sorted order by their keys.
- **BinaryHeap:** It maintains its elements in a heap order, which is a complete binary tree where each parent node is less than or equal to its child nodes.
- **Vec**: It maintains its elements in the order in which they were inserted. ⚠️
- **LinkedList:** It maintains its elements in the order in which they were inserted. ⚠️
- **VecDeque:** It maintains its elements in the order in which they were inserted. ⚠️

```

**File:** crates/jwk-utils/src/lib.rs (L21-37)
```rust
/// Given a JWK URL, fetch its JWKs.
///
/// Optionally, if an address is given, send it as the cookie payload.
/// The optional logic is only used in smoke tests, e.g., `jwk_consensus_basic`.
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

**File:** types/src/jwks/jwk/mod.rs (L80-89)
```rust
impl From<serde_json::Value> for JWK {
    fn from(value: serde_json::Value) -> Self {
        match RSA_JWK::try_from(&value) {
            Ok(rsa) => Self::RSA(rsa),
            Err(_) => {
                let unsupported = UnsupportedJWK::from(value);
                Self::Unsupported(unsupported)
            },
        }
    }
```

**File:** types/src/jwks/mod.rs (L120-128)
```rust
/// Move type `0x1::jwks::ProviderJWKs` in rust.
/// See its doc in Move for more details.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct ProviderJWKs {
    #[serde(with = "serde_bytes")]
    pub issuer: Issuer,
    pub version: u64,
    pub jwks: Vec<JWKMoveStruct>,
}
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L140-142)
```rust
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;
```

**File:** types/src/validator_verifier.rs (L345-386)
```rust
    pub fn verify_multi_signatures<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        multi_signature: &AggregateSignature,
    ) -> std::result::Result<(), VerifyError> {
        // Verify the number of signature is not greater than expected.
        Self::check_num_of_voters(self.len() as u16, multi_signature.get_signers_bitvec())?;
        let mut pub_keys = vec![];
        let mut authors = vec![];
        for index in multi_signature.get_signers_bitvec().iter_ones() {
            let validator = self
                .validator_infos
                .get(index)
                .ok_or(VerifyError::UnknownAuthor)?;
            authors.push(validator.address);
            pub_keys.push(validator.public_key());
        }
        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.iter(), true)?;
        #[cfg(any(test, feature = "fuzzing"))]
        {
            if self.quorum_voting_power == 0 {
                // This should happen only in case of tests.
                // TODO(skedia): Clean up the test behaviors to not rely on empty signature
                // verification
                return Ok(());
            }
        }
        // Verify empty multi signature
        let multi_sig = multi_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;
        // Verify the optimistically aggregated signature.
        let aggregated_key =
            PublicKey::aggregate(pub_keys).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

        multi_sig
            .verify(message, &aggregated_key)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;
        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/delta.rs (L16-16)
```rust
    // Use BTreeMap to ensure deterministic ordering
```

**File:** testsuite/smoke-test/src/jwks/jwk_consensus_basic.rs (L152-156)
```rust
    alice_jwks_server.update_request_handler(Some(Arc::new(EquivocatingServer::new(
        r#"{"keys": ["ALICE_JWK_V1A"]}"#.as_bytes().to_vec(),
        r#"{"keys": ["ALICE_JWK_V1B"]}"#.as_bytes().to_vec(),
        1,
    ))));
```
