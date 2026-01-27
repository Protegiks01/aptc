# Audit Report

## Title
Signature Verification Failure Due to Type Conversion in Batch Signing Process

## Summary
A critical flaw exists in the batch signing mechanism where `SignedBatchInfo<BatchInfo>` is converted to `SignedBatchInfo<BatchInfoExt>` while retaining the original signature. This signature was computed over a different hash (using `BatchInfoHasher::seed()`), but after conversion it's verified against `BatchInfoExt` (using `BatchInfoExtHasher::seed()`), causing verification failures and preventing signature aggregation needed for consensus.

## Finding Description

The vulnerability stems from inconsistent cryptographic hash computation during the batch signing and verification flow.

**Root Cause - Different Hash Seeds for Different Types:**

The `signing_message()` function prepends a type-specific seed to the serialized data: [1](#0-0) 

The `CryptoHasher` derive macro generates different seeds based on the Serde type name: [2](#0-1) 

This means `BatchInfo` and `BatchInfoExt` have completely different hash seeds, resulting in different signature messages.

**The Vulnerable Code Path:**

In `batch_store.rs`, the `persist_inner()` method handles V1 batches incorrectly: [3](#0-2) 

For V1 batches (`!batch_info.is_v2()`):
1. Line 516: Extracts the inner `BatchInfo` via `batch_info.info().clone()`
2. Line 516: Signs this `BatchInfo` creating `SignedBatchInfo<BatchInfo>`
3. Line 518: Converts to `SignedBatchInfo<BatchInfoExt>` via `.into()`

The conversion implementation preserves the signature: [4](#0-3) 

**The Problem:**
- Original signature computed over: `BatchInfoHasher::seed()` + `BCS(BatchInfo {...})`  
- After conversion, signature associated with: `BatchInfoExt::V1 { info: BatchInfo {...} }`
- Verification computes: `BatchInfoExtHasher::seed()` + `BCS(BatchInfoExt::V1 {...})`
- These are **different values** → signature verification fails

**Signature Verification Fails During Aggregation:**

When signatures are aggregated in `SignatureAggregator::aggregate_and_verify()`: [5](#0-4) 

Line 523 verifies the aggregated signature against `self.data`, which for V1 batches is `BatchInfoExt`. The verification will compute the hash using `BatchInfoExtHasher::seed()`, but the signature was computed using `BatchInfoHasher::seed()`, causing failure.

**Attack Scenario:**

Different validators may use different batch formats based on the `enable_batch_v2` config flag: [6](#0-5) 

If validators have inconsistent configs or handle V1 batches from legacy nodes, the signature verification mismatch prevents consensus quorum formation.

## Impact Explanation

**Severity: High (potentially Critical)**

This vulnerability breaks the **Consensus Safety** invariant by preventing validators from aggregating signatures for batch proofs, which are required for the quorum store consensus mechanism.

**Concrete Impact:**
- **Consensus Liveness Failure**: Validators cannot create `ProofOfStore` for batches due to signature verification failures, blocking transaction inclusion
- **Network Partition Risk**: If different validators have different `enable_batch_v2` configurations, they cannot agree on batch signatures, potentially causing a network split
- **Transaction Censorship**: Batches with invalid signatures are rejected, preventing legitimate transactions from being processed

This qualifies as **High Severity** under the Aptos bug bounty program ("Validator node slowdowns, Significant protocol violations") and potentially **Critical** if it causes a non-recoverable partition requiring intervention.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability will trigger when:
1. Validators handle V1 batches (common during upgrades or with legacy compatibility)
2. The `persist_inner()` method is called for received batches with `!batch_info.is_v2() == true`
3. Multiple validators attempt to aggregate signatures for the same batch

The likelihood increases if:
- Network has mixed validator versions with different `enable_batch_v2` configs
- Legacy V1 batches are still circulating  
- Validators upgrade asynchronously

The attack requires no special privileges - simply sending V1-format batches to validators will trigger the bug.

## Recommendation

**Fix: Always sign the actual type being transmitted**

Modify `persist_inner()` to sign the `BatchInfoExt` directly instead of extracting and signing the inner `BatchInfo`:

```rust
fn persist_inner(
    &self,
    batch_info: BatchInfoExt,
    persist_request: PersistedValue<BatchInfoExt>,
) -> Option<SignedBatchInfo<BatchInfoExt>> {
    assert!(
        &batch_info == persist_request.batch_info(),
        "Provided batch info doesn't match persist request batch info"
    );
    match self.save(&persist_request) {
        Ok(needs_db) => {
            trace!("QS: sign digest {}", persist_request.digest());
            if needs_db {
                if !batch_info.is_v2() {
                    let persist_request =
                        persist_request.try_into().expect("Must be a V1 batch");
                    self.db
                        .save_batch(persist_request)
                        .expect("Could not write to DB");
                } else {
                    self.db
                        .save_batch_v2(persist_request)
                        .expect("Could not write to DB")
                }
            }
            // FIX: Always sign BatchInfoExt regardless of variant
            self.generate_signed_batch_info(batch_info).ok()
        },
        Err(e) => {
            debug!("QS: failed to store to cache {:?}", e);
            None
        },
    }
}
```

**Alternative Fix: Remove the problematic conversion**

Remove the `From<SignedBatchInfo<BatchInfo>> for SignedBatchInfo<BatchInfoExt>` implementation to prevent incorrect type conversions with mismatched signatures.

## Proof of Concept

```rust
#[cfg(test)]
mod signature_mismatch_test {
    use super::*;
    use aptos_consensus_types::proof_of_store::{BatchInfo, BatchInfoExt, SignedBatchInfo};
    use aptos_crypto::{bls12381, hash::CryptoHash, PrivateKey, Uniform};
    use aptos_types::{validator_signer::ValidatorSigner, PeerId};
    use std::sync::Arc;

    #[test]
    fn test_batch_info_signature_verification_fails_after_conversion() {
        // Setup validator signer
        let private_key = bls12381::PrivateKey::generate_for_testing();
        let signer = ValidatorSigner::new(
            PeerId::random(),
            Arc::new(private_key)
        );

        // Create a BatchInfo
        let batch_info = BatchInfo::new(
            signer.author(),
            aptos_types::quorum_store::BatchId::new(1),
            1, // epoch
            1000000, // expiration
            aptos_crypto::HashValue::random(),
            10, // num_txns
            1024, // num_bytes
            0, // gas_bucket_start
        );

        // Sign the BatchInfo (this computes hash with BatchInfoHasher::seed())
        let signed_batch_info_v1 = SignedBatchInfo::new(batch_info.clone(), &signer)
            .expect("Signing should succeed");

        // Convert to SignedBatchInfo<BatchInfoExt> (keeps same signature!)
        let signed_batch_info_ext: SignedBatchInfo<BatchInfoExt> = signed_batch_info_v1.into();

        // Create validator verifier
        let validator_verifier = aptos_types::validator_verifier::ValidatorVerifier::new_single(
            signer.author(),
            signer.public_key()
        );

        // Try to verify the converted signature
        // This should FAIL because the signature was computed over BatchInfo
        // but now we're verifying it against BatchInfoExt
        let result = validator_verifier.verify_signature(
            signer.author(),
            signed_batch_info_ext.batch_info(),
            signed_batch_info_ext.signature()
        );

        // This assertion demonstrates the vulnerability
        assert!(result.is_err(), "Signature verification should fail due to type mismatch");
        
        // The hashes are different
        let batch_info_hash = batch_info.hash();
        let batch_info_ext: BatchInfoExt = batch_info.into();
        let batch_info_ext_hash = batch_info_ext.hash();
        
        assert_ne!(batch_info_hash, batch_info_ext_hash, 
            "BatchInfo and BatchInfoExt produce different hashes");
    }
}
```

This PoC demonstrates that:
1. A signature computed over `BatchInfo` becomes invalid when associated with `BatchInfoExt`
2. The hash values differ between the two types even with identical data
3. Signature verification fails, breaking consensus aggregation

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

**File:** crates/aptos-crypto-derive/src/lib.rs (L351-438)
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

        impl std::io::Write for #hasher_name {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                use aptos_crypto::hash::CryptoHasher;

                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

    );
    out.into()
}
```

**File:** consensus/src/quorum_store/batch_store.rs (L515-521)
```rust
                if !batch_info.is_v2() {
                    self.generate_signed_batch_info(batch_info.info().clone())
                        .ok()
                        .map(|inner| inner.into())
                } else {
                    self.generate_signed_batch_info(batch_info).ok()
                }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L505-517)
```rust
impl From<SignedBatchInfo<BatchInfo>> for SignedBatchInfo<BatchInfoExt> {
    fn from(signed_batch_info: SignedBatchInfo<BatchInfo>) -> Self {
        let SignedBatchInfo {
            info,
            signer,
            signature,
        } = signed_batch_info;
        Self {
            info: info.into(),
            signer,
            signature,
        }
    }
```

**File:** types/src/ledger_info.rs (L517-535)
```rust
    pub fn aggregate_and_verify(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<(T, AggregateSignature), VerifyError> {
        let aggregated_sig = self.try_aggregate(verifier)?;

        match verifier.verify_multi_signatures(&self.data, &aggregated_sig) {
            Ok(_) => {
                // We are not marking all the signatures as "verified" here, as two malicious
                // voters can collude and create a valid aggregated signature.
                Ok((self.data.clone(), aggregated_sig))
            },
            Err(_) => {
                self.filter_invalid_signatures(verifier);

                let aggregated_sig = self.try_aggregate(verifier)?;
                Ok((self.data.clone(), aggregated_sig))
            },
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L190-211)
```rust
        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
```
