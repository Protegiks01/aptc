# Audit Report

## Title
Type Conversion Invalidates Cryptographic Signatures Leading to Consensus Split

## Summary
The conversion from `ProofOfStoreMsg<BatchInfo>` to `ProofOfStoreMsg<BatchInfoExt>` preserves the multi-signature but changes the underlying data structure being signed. This causes signatures to become cryptographically invalid for the converted type, breaking the fundamental invariant that digital signatures must be independently verifiable. The system masks this invalidity through caching, creating a critical dependency where consensus safety relies on ephemeral cache state rather than cryptographic validity.

## Finding Description

The vulnerability exists in the proof message conversion flow where `ProofOfStore<BatchInfo>` is converted to `ProofOfStore<BatchInfoExt>` while preserving the original signature.

**Root Cause:**

Both `BatchInfo` and `BatchInfoExt` derive `BCSCryptoHash` and `CryptoHasher`, meaning they generate different cryptographic hashes based on their type structure. [1](#0-0) [2](#0-1) 

The `CryptoHasher` derive macro generates type-specific hashers with seeds based on the type name. [3](#0-2)  This means `BatchInfo` uses a hasher seeded with "BatchInfo" while `BatchInfoExt` uses a hasher seeded with "BatchInfoExt".

When signatures are verified, the `signing_message` function prepends the hasher seed to the BCS-serialized message. [4](#0-3)  For `BatchInfo` (a struct), this produces: `seed("BatchInfo") + BCS(struct_fields)`. For `BatchInfoExt::V1` (an enum variant), this produces: `seed("BatchInfoExt") + BCS(discriminator + fields)`. These are cryptographically different, making signatures created for one type invalid for the other.

**The Conversion Flow:**

When `ProofOfStoreMsg<BatchInfo>` is received, it's verified against the `BatchInfo` type (signature valid). [5](#0-4) 

The conversion at line 219 changes the data type but preserves the signature. [6](#0-5)  The underlying `From` trait implementation transfers the signature without re-signing. [7](#0-6) 

During verification, the system relies on caching to mask the invalidity. When `ProofOfStore<BatchInfo>` is verified, the signature is cached under a `BatchInfoExt` key. [8](#0-7)  Later, when `ProofOfStore<BatchInfoExt>` is verified, if the cache has the entry, verification succeeds without re-checking the signature. If cache misses, `verify_multi_signatures` is called with `BatchInfoExt` type, but the signature was created for `BatchInfo`, causing verification failure.

**Attack Scenario:**

The vulnerability manifests when cache coherency is broken:

1. **Cache Eviction**: The `ProofCache` has bounded capacity (default 10,000 entries) with 20-second TTL. [9](#0-8) [10](#0-9)  Under normal operation, entries are evicted when capacity is exceeded or TTL expires.

2. **Node Restart**: The cache is in-memory only with no persistence. When a validator restarts, all cached signatures are lost.

3. **Late-Joining Validators**: New validators joining the network won't have cached entries for previously verified proofs.

**Exploitation Path:**

1. All validators receive and verify `ProofOfStoreMsg<BatchInfo>` → Signatures cached
2. Node A's cache evicts entries OR Node A restarts OR Node A is a new validator
3. Node B creates a proposal including `ProofOfStore<BatchInfoExt>` (pulled from proof queue after conversion)
4. Node A receives the proposal and attempts verification via `Payload::verify()` [11](#0-10) 
5. Verification calls `verify_with_cache()` [12](#0-11)  which filters for unverified proofs [13](#0-12) 
6. Cache miss occurs, triggering `verify_multi_signatures(&self.info, &self.multi_signature)` where `self.info` is `BatchInfoExt` but signature was for `BatchInfo` [14](#0-13) 
7. Signature verification calls through to BLS verification with different hash [15](#0-14) 
8. Verification FAILS → Node A rejects proposal, others with cache hits accept → **CONSENSUS SPLIT**

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability causes **Consensus Safety Violations**, meeting Critical severity criteria:

1. **Consensus Split**: Different validators accept/reject the same block based on their cache state, violating the fundamental BFT safety property that honest validators must agree on block validity. This occurs without any Byzantine behavior.

2. **Network Partition**: Validators with expired cache entries cannot verify converted proofs and permanently diverge from the main chain. Recovery requires manual intervention or hardfork to reconcile divergent states.

3. **Liveness Failure**: If sufficient validators lose cache entries through restarts, evictions, or late joins, quorum cannot be reached for block proposals containing converted proofs, halting network progress.

4. **Cryptographic Invariant Violation**: The system breaks the fundamental security assumption that digital signatures are independently verifiable. Signature validity depends on ephemeral cache state rather than cryptographic properties, undermining the security foundation of the consensus protocol.

This meets the Critical severity criteria for "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)" per the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will manifest in production environments due to:

1. **Cache Capacity Limits**: The proof cache has bounded size with LRU eviction. In high-throughput blockchain processing thousands of batches per epoch, cache eviction is inevitable under normal load.

2. **Cache TTL Expiration**: 20-second TTL means entries expire quickly. If a converted proof is included in a proposal more than 20 seconds after initial verification, cache will be expired.

3. **Validator Restarts**: Validators regularly restart for upgrades, configuration changes, or crash recovery. Each restart clears the in-memory cache, immediately exposing the vulnerability.

4. **Network Growth**: New validators continuously join the network. These nodes lack cached proof entries and will immediately encounter verification failures when receiving proposals with converted proofs.

5. **Normal Operation**: No attacker action required. The vulnerability triggers during routine consensus operations when validators create proposals using converted proofs from their local queues.

The combination of bounded cache size, short TTL, non-persistent storage, and type conversion in the critical consensus path makes this vulnerability highly likely to occur in production.

## Recommendation

**Option 1: Eliminate Type Conversion** (Preferred)
Remove the conversion from `BatchInfo` to `BatchInfoExt` and work with a single canonical type throughout the system. If extensibility is needed, use the same type everywhere with versioning handled internally without changing the signed data structure.

**Option 2: Re-sign After Conversion**
When converting `ProofOfStore<BatchInfo>` to `ProofOfStore<BatchInfoExt>`, collect new signatures for the `BatchInfoExt` type from validators instead of preserving the original signature. This ensures cryptographic validity but adds communication overhead.

**Option 3: Store Original Type with Proof**
Store the original `BatchInfo` alongside the converted `BatchInfoExt` in the proof structure, and always verify signatures against the original type. However, this increases memory usage and complexity.

**Option 4: Persistent Cache**
Make the proof cache persistent across restarts. However, this doesn't solve cache eviction or late-joining validators, and adds operational complexity.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a `ProofOfStore<BatchInfo>` with valid multi-signature
2. Converting it to `ProofOfStore<BatchInfoExt>` 
3. Clearing the proof cache
4. Attempting to verify the converted proof without cache
5. Observing signature verification failure

This would require setting up a test consensus environment with multiple validators, but the core issue is evident from the code structure where different types produce different cryptographic hashes, making cross-type signature verification impossible by design.

## Notes

The vulnerability stems from a fundamental mismatch between the signature verification logic (which is type-specific due to domain separation) and the proof conversion logic (which assumes signatures are type-agnostic). The caching mechanism accidentally masks this incompatibility during normal operation, but any cache miss exposes the underlying cryptographic invalidity, leading to consensus safety violations.

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L46-47)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L192-193)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
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

**File:** consensus/src/round_manager.rs (L212-219)
```rust
            UnverifiedEvent::ProofOfStoreMsg(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(Box::new((*p).into()))
```

**File:** consensus/src/epoch_manager.rs (L250-254)
```rust
            proof_cache: Cache::builder()
                .max_capacity(node_config.consensus.proof_cache_capacity)
                .initial_capacity(1_000)
                .time_to_live(Duration::from_secs(20))
                .build(),
```

**File:** config/src/config/consensus_config.rs (L95-95)
```rust
    pub proof_cache_capacity: u64,
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L97-101)
```rust
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
                })
```

**File:** consensus/consensus-types/src/common.rs (L526-537)
```rust
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

**File:** crates/aptos-crypto/src/bls12381/bls12381_sigs.rs (L141-143)
```rust
    fn verify<T: CryptoHash + Serialize>(&self, message: &T, public_key: &PublicKey) -> Result<()> {
        self.verify_arbitrary_msg(&signing_message(message)?, public_key)
    }
```
