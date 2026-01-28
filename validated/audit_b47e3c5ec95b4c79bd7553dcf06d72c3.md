# Audit Report

## Title
Type Conversion Invalidates Cryptographic Signatures Leading to Consensus Split

## Summary
The conversion from `ProofOfStoreMsg<BatchInfo>` to `ProofOfStoreMsg<BatchInfoExt>` preserves multi-signatures but changes the underlying data structure being signed. This causes signatures to become cryptographically invalid for the converted type, breaking the fundamental invariant that digital signatures must be independently verifiable. The system masks this invalidity through ephemeral caching, creating a critical dependency where consensus safety relies on cache state rather than cryptographic validity.

## Finding Description

The vulnerability exists in the proof message conversion flow where `ProofOfStore<BatchInfo>` is converted to `ProofOfStore<BatchInfoExt>` while preserving the original signature.

**Root Cause:**

Both `BatchInfo` and `BatchInfoExt` derive `BCSCryptoHash` and `CryptoHasher`, meaning they generate different cryptographic hashes based on their type structure. [1](#0-0) [2](#0-1) 

The `CryptoHasher` derive macro generates type-specific hashers with seeds based on the type name, using `trace_name::<#type_name>()` to create domain-separated hash seeds. [3](#0-2) 

When signatures are verified, the `signing_message` function prepends the hasher seed to the BCS-serialized message: `<T::Hasher as CryptoHasher>::seed().to_vec()` + BCS-serialized data. This means `BatchInfo` produces `seed("BatchInfo") + BCS(struct)` while `BatchInfoExt::V1` produces `seed("BatchInfoExt") + BCS(enum_discriminator + struct)`, creating cryptographically different signing messages. [4](#0-3) 

**The Conversion Flow:**

When `ProofOfStoreMsg<BatchInfo>` is received, it's verified against the `BatchInfo` type (signature valid) at the network message handling layer. [5](#0-4) 

The conversion preserves the signature while changing the info type from `BatchInfo` to `BatchInfoExt::V1 { info }`. [6](#0-5) 

During verification, the system relies on caching to mask the invalidity. When `ProofOfStore<BatchInfo>` is verified, the signature is cached under a `BatchInfoExt` key (line 636, 649), but verification happens against `self.info` which is still `BatchInfo` (line 643). [7](#0-6) 

Later, when `ProofOfStore<BatchInfoExt>` is verified in proposals, if the cache has the entry, verification succeeds without re-checking. If cache misses, `verify_multi_signatures(&self.info, &self.multi_signature)` is called where `self.info` is now `BatchInfoExt`, but the signature was created for `BatchInfo`, causing verification failure. [8](#0-7) 

**Attack Scenario:**

The vulnerability manifests when cache coherency is broken:

1. **Cache Eviction/TTL Expiration**: The `ProofCache` has a 20-second TTL (hardcoded) and configurable capacity. Under normal operation, entries are evicted when capacity is exceeded or TTL expires. [9](#0-8) 

2. **Node Restart**: The cache is in-memory only (mini_moka::sync::Cache) with no persistence. When a validator restarts, all cached signatures are lost.

3. **Late-Joining Validators**: New validators joining the network won't have cached entries for previously verified proofs.

**Exploitation Path:**

1. All validators receive and verify `ProofOfStoreMsg<BatchInfo>` → Signatures cached under `BatchInfoExt` keys
2. Node A's cache evicts entries OR Node A restarts OR Node A is a new validator  
3. Node B creates a proposal including `ProofOfStore<BatchInfoExt>` (pulled from proof queue after conversion)
4. Node A receives the proposal and attempts verification via `Payload::verify()` [10](#0-9) 

5. Verification calls `verify_with_cache()` which filters for unverified proofs by checking the cache [11](#0-10) 

6. Cache miss occurs, triggering `proof.verify(validator, proof_cache)` where `self.info` is `BatchInfoExt` but signature was for `BatchInfo`
7. Signature verification fails because the hash is different
8. Verification FAILS → Node A rejects proposal, others with cache hits accept → **CONSENSUS SPLIT**

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability causes **Consensus Safety Violations**, meeting Critical severity criteria:

1. **Consensus Split**: Different validators accept/reject the same block based on their ephemeral cache state, violating the fundamental BFT safety property that honest validators must agree on block validity. This occurs without any Byzantine behavior.

2. **Network Partition**: Validators with expired cache entries cannot verify converted proofs and diverge from the main chain. Recovery requires manual intervention or hardfork to reconcile divergent states.

3. **Liveness Failure**: If sufficient validators lose cache entries through restarts, evictions, or late joins, quorum cannot be reached for block proposals containing converted proofs, halting network progress.

4. **Cryptographic Invariant Violation**: The system breaks the fundamental security assumption that digital signatures are independently verifiable. Signature validity depends on ephemeral cache state rather than cryptographic properties, undermining the security foundation of the consensus protocol.

This meets the Critical severity criteria for "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)" per the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will manifest in production environments due to:

1. **Cache TTL Expiration**: The 20-second TTL (hardcoded) means entries expire quickly. If a converted proof is included in a proposal more than 20 seconds after initial verification, the cache will be expired, triggering re-verification with the wrong type.

2. **Validator Restarts**: Validators regularly restart for upgrades, configuration changes, or crash recovery. Each restart clears the in-memory cache, immediately exposing the vulnerability.

3. **Network Growth**: New validators continuously join the network. These nodes lack cached proof entries and will immediately encounter verification failures when receiving proposals with converted proofs.

4. **Cache Capacity Limits**: The proof cache has bounded size with LRU eviction. In high-throughput environments processing thousands of batches per epoch, cache eviction is inevitable under normal load.

5. **Normal Operation**: No attacker action required. The vulnerability triggers during routine consensus operations when validators create proposals using converted proofs from their local queues.

The combination of short TTL, non-persistent storage, node restarts, and type conversion in the critical consensus path makes this vulnerability highly likely to occur in production.

## Recommendation

Implement one of the following fixes:

**Option 1: Re-sign after conversion (Recommended)**
- Modify the `From<ProofOfStore<BatchInfo>>` implementation to re-aggregate signatures for the new type
- This ensures cryptographic validity is maintained across type conversions

**Option 2: Use type-agnostic hashing**
- Modify both types to hash only the underlying `BatchInfo` data, not the wrapper type
- This would require changing the `CryptoHasher` implementation to use a shared seed

**Option 3: Eliminate conversion**
- Keep `ProofOfStore<BatchInfo>` throughout the consensus flow
- Only convert to `BatchInfoExt` when absolutely necessary for storage/API purposes
- This avoids the fundamental type mismatch issue

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a `ProofOfStore<BatchInfo>` with valid multi-signature
2. Converting it to `ProofOfStore<BatchInfoExt>` using the `From` trait
3. Verifying the converted proof WITHOUT cache (e.g., with empty cache)
4. Observing verification failure despite valid original signature

The cryptographic difference can be proven by comparing:
- `signing_message(&batch_info)` where `batch_info: BatchInfo`
- `signing_message(&batch_info_ext)` where `batch_info_ext: BatchInfoExt::V1 { info: batch_info }`

These produce different byte arrays due to different hasher seeds and BCS serialization, making signatures for one type invalid for the other.

## Notes

This vulnerability represents a fundamental architectural flaw where consensus safety depends on ephemeral cache state rather than cryptographic validity. The issue is particularly severe because:

1. It affects the core consensus protocol, not just performance optimizations
2. It violates the fundamental cryptographic invariant that signatures must be independently verifiable
3. The cache dependency is implicit and not documented as a safety-critical component
4. The 20-second TTL is hardcoded with no configuration option, making the window of vulnerability fixed
5. The issue can manifest during normal operations without any malicious activity

The vulnerability demonstrates that while the caching optimization improves performance, it inadvertently masks a critical type safety violation in the cryptographic verification layer.

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L46-58)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub struct BatchInfo {
    author: PeerId,
    batch_id: BatchId,
    epoch: u64,
    expiration: u64,
    digest: HashValue,
    num_txns: u64,
    num_bytes: u64,
    gas_bucket_start: u64,
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L192-203)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub enum BatchInfoExt {
    V1 {
        info: BatchInfo,
    },
    V2 {
        info: BatchInfo,
        extra: ExtraBatchInfo,
    },
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-652)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
        let result = validator
            .verify_multi_signatures(&self.info, &self.multi_signature)
            .context(format!(
                "Failed to verify ProofOfStore for batch: {:?}",
                self.info
            ));
        if result.is_ok() {
            cache.insert(batch_info_ext, self.multi_signature.clone());
        }
        result
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L702-710)
```rust
impl From<ProofOfStore<BatchInfo>> for ProofOfStore<BatchInfoExt> {
    fn from(proof: ProofOfStore<BatchInfo>) -> Self {
        let (info, sig) = proof.unpack();
        Self {
            info: info.into(),
            multi_signature: sig,
        }
    }
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L351-422)
```rust
#[proc_macro_derive(CryptoHasher)]
pub fn hasher_dispatch(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let hasher_name = Ident::new(
        &format!("{}Hasher", &item.ident.to_string()),
        Span::call_site(),
    );
    let snake_name = camel_to_snake(&item.ident.to_string());
    let static_seed_name = Ident::new(
        &format!("{}_SEED", snake_name.to_uppercase()),
        Span::call_site(),
    );

    let static_hasher_name = Ident::new(
        &format!("{}_HASHER", snake_name.to_uppercase()),
        Span::call_site(),
    );
    let type_name = &item.ident;
    let param = if item.generics.params.is_empty() {
        quote!()
    } else {
        let args = proc_macro2::TokenStream::from_iter(std::iter::repeat_n(
            quote!((),),
            item.generics.params.len(),
        ));
        quote!(<#args>)
    };

    let out = quote!(
        /// Cryptographic hasher for an BCS-serializable #item
        #[derive(Clone)]
        pub struct #hasher_name(aptos_crypto::hash::DefaultHasher);

        static #static_seed_name: aptos_crypto::_once_cell::sync::OnceCell<[u8; 32]> = aptos_crypto::_once_cell::sync::OnceCell::new();

        impl #hasher_name {
            fn new() -> Self {
                let name = aptos_crypto::_serde_name::trace_name::<#type_name #param>()
                    .expect("The `CryptoHasher` macro only applies to structs and enums");
                #hasher_name(
                    aptos_crypto::hash::DefaultHasher::new(&name.as_bytes()))
            }
        }

        static #static_hasher_name: aptos_crypto::_once_cell::sync::Lazy<#hasher_name> =
            aptos_crypto::_once_cell::sync::Lazy::new(|| #hasher_name::new());


        impl std::default::Default for #hasher_name
        {
            fn default() -> Self {
                #static_hasher_name.clone()
            }
        }

        impl aptos_crypto::hash::CryptoHasher for #hasher_name {
            fn seed() -> &'static [u8; 32] {
                #static_seed_name.get_or_init(|| {
                    let name = aptos_crypto::_serde_name::trace_name::<#type_name #param>()
                        .expect("The `CryptoHasher` macro only applies to structs and enums.").as_bytes();
                    aptos_crypto::hash::DefaultHasher::prefixed_hash(&name)
                })
            }

            fn update(&mut self, bytes: &[u8]) {
                self.0.update(bytes);
            }

            fn finish(self) -> aptos_crypto::hash::HashValue {
                self.0.finish()
            }
        }
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L168-177)
```rust
/// Returns the signing message for the given message.
/// It is used by `SigningKey#sign` function.
pub fn signing_message<T: CryptoHash + Serialize>(
    message: &T,
) -> Result<Vec<u8>, CryptoMaterialError> {
    let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
    bcs::serialize_into(&mut bytes, &message)
        .map_err(|_| CryptoMaterialError::SerializationError)?;
    Ok(bytes)
}
```

**File:** consensus/src/round_manager.rs (L212-220)
```rust
            UnverifiedEvent::ProofOfStoreMsg(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(Box::new((*p).into()))
            },
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

**File:** consensus/src/epoch_manager.rs (L250-254)
```rust
            proof_cache: Cache::builder()
                .max_capacity(node_config.consensus.proof_cache_capacity)
                .initial_capacity(1_000)
                .time_to_live(Duration::from_secs(20))
                .build(),
```

**File:** consensus/consensus-types/src/common.rs (L517-539)
```rust
    fn verify_with_cache<T>(
        proofs: &[ProofOfStore<T>],
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
    ) -> anyhow::Result<()>
    where
        T: TBatchInfo + Send + Sync + 'static,
        BatchInfoExt: From<T>,
    {
        let unverified: Vec<_> = proofs
            .iter()
            .filter(|proof| {
                proof_cache
                    .get(&BatchInfoExt::from(proof.info().clone()))
                    .is_none_or(|cached_proof| cached_proof != *proof.multi_signature())
            })
            .collect();
        unverified
            .par_iter()
            .with_min_len(2)
            .try_for_each(|proof| proof.verify(validator, proof_cache))?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/common.rs (L574-632)
```rust
    pub fn verify(
        &self,
        verifier: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> anyhow::Result<()> {
        match (quorum_store_enabled, self) {
            (false, Payload::DirectMempool(_)) => Ok(()),
            (true, Payload::InQuorumStore(proof_with_status)) => {
                Self::verify_with_cache(&proof_with_status.proofs, verifier, proof_cache)
            },
            (true, Payload::InQuorumStoreWithLimit(proof_with_status)) => Self::verify_with_cache(
                &proof_with_status.proof_with_data.proofs,
                verifier,
                proof_cache,
            ),
            (true, Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _))
            | (true, Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _)) => {
                Self::verify_with_cache(&proof_with_data.proofs, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    inline_batches.iter().map(|(info, txns)| (info, txns)),
                )?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V1(p))) => {
                let proof_with_data = p.proof_with_data();
                Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    p.inline_batches()
                        .iter()
                        .map(|batch| (batch.info(), batch.transactions())),
                )?;
                Self::verify_opt_batches(verifier, p.opt_batches())?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V2(p))) => {
                if true {
                    bail!("OptQuorumStorePayload::V2 cannot be accepted yet");
                }
                #[allow(unreachable_code)]
                {
                    let proof_with_data = p.proof_with_data();
                    Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                    Self::verify_inline_batches(
                        p.inline_batches()
                            .iter()
                            .map(|batch| (batch.info(), batch.transactions())),
                    )?;
                    Self::verify_opt_batches(verifier, p.opt_batches())?;
                    Ok(())
                }
            },
            (_, _) => Err(anyhow::anyhow!(
                "Wrong payload type. Expected Payload::InQuorumStore {} got {} ",
                quorum_store_enabled,
                self
            )),
        }
    }
```
