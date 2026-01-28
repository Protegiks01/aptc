> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

Notes:
- There is no production invocation of `DigestKey::verify()`, `verify_pf()`, or `verify_all()` to cryptographically check the correctness of `eval_proof` when it is persisted to the `EncryptedPayload` struct or used in the state. 
- The only verification performed in the `EncryptedPayload::verify()` method is for the ciphertext and its associated data, not the `eval_proof`. 
- The pipeline accepts any computed or supplied `eval_proof` for state; it is not checked on-chain or in consensus by validators, so accountability can be subverted in post-hoc auditing as claimed.
- Evaluation proofs are only used for pairing computations in decryption and not for verification against the digest in any consensus/production path.
- This substantiates the report’s claim that the audit/accountability guarantee is broken, but consensus safety and funds are not at risk due to each validator independently computing decryption and eval_proofs (so severity is not critical).

The claim is valid as described.

### Citations

**File:** types/src/transaction/encrypted_payload.rs (L42-151)
```rust
pub enum EncryptedPayload {
    Encrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
    },
    FailedDecryption {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,
    },
    Decrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,

        // decrypted things
        executable: TransactionExecutable,
        decryption_nonce: u64,
    },
}

impl EncryptedPayload {
    pub fn ciphertext(&self) -> &Ciphertext {
        match self {
            Self::Encrypted { ciphertext, .. }
            | Self::FailedDecryption { ciphertext, .. }
            | Self::Decrypted { ciphertext, .. } => ciphertext,
        }
    }

    pub fn executable(&self) -> Result<TransactionExecutable> {
        let Self::Decrypted { executable, .. } = self else {
            bail!("Transaction is encrypted");
        };
        Ok(executable.clone())
    }

    pub fn executable_ref(&self) -> Result<TransactionExecutableRef<'_>> {
        let Self::Decrypted { executable, .. } = self else {
            bail!("Transaction is encrypted");
        };
        Ok(executable.as_ref())
    }

    pub fn extra_config(&self) -> &TransactionExtraConfig {
        match self {
            EncryptedPayload::Encrypted { extra_config, .. } => extra_config,
            EncryptedPayload::FailedDecryption { extra_config, .. } => extra_config,
            EncryptedPayload::Decrypted { extra_config, .. } => extra_config,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted { .. })
    }

    pub fn into_decrypted(
        &mut self,
        eval_proof: EvalProof,
        executable: TransactionExecutable,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let Self::Encrypted {
            ciphertext,
            extra_config,
            payload_hash,
        } = self
        else {
            bail!("Payload is not in Encrypted state");
        };

        *self = Self::Decrypted {
            ciphertext: ciphertext.clone(),
            extra_config: extra_config.clone(),
            payload_hash: *payload_hash,
            eval_proof,
            executable,
            decryption_nonce: nonce,
        };
        Ok(())
    }

    pub fn into_failed_decryption(&mut self, eval_proof: EvalProof) -> anyhow::Result<()> {
        let Self::Encrypted {
            ciphertext,
            extra_config,
            payload_hash,
        } = self
        else {
            bail!("Payload is not in Encrypted state");
        };

        // TODO(ibalajiarun): Avoid the clone
        *self = Self::FailedDecryption {
            ciphertext: ciphertext.clone(),
            extra_config: extra_config.clone(),
            payload_hash: *payload_hash,
            eval_proof,
        };
        Ok(())
    }

    pub fn verify(&self, sender: AccountAddress) -> anyhow::Result<()> {
        let associated_data = PayloadAssociatedData::new(sender);
        self.ciphertext().verify(&associated_data)
    }
}
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L138-158)
```rust
    fn verify_pf(&self, digest: &Digest, id: Id, pf: G1Affine) -> Result<()> {
        // TODO use multipairing here?
        Ok((PairingSetting::pairing(
            pf,
            self.tau_g2 - G2Projective::from(G2Affine::generator() * id.x()),
        ) == PairingSetting::pairing(digest.as_g1(), G2Affine::generator()))
        .then_some(())
        .ok_or(BatchEncryptionError::EvalProofVerifyError)?)
    }

    pub fn verify(&self, digest: &Digest, pfs: &EvalProofs, id: Id) -> Result<()> {
        let pf = pfs.computed_proofs[&id];
        self.verify_pf(digest, id, pf)
    }

    pub fn verify_all(&self, digest: &Digest, pfs: &EvalProofs) -> Result<()> {
        pfs.computed_proofs
            .iter()
            .try_for_each(|(id, pf)| self.verify_pf(digest, *id, *pf))
    }
}
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L204-231)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalProof(#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G1Affine);

impl Deref for EvalProof {
    type Target = G1Affine;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EvalProof {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<G1Affine> for EvalProof {
    fn from(value: G1Affine) -> Self {
        Self(value)
    }
}

impl EvalProof {
    pub fn random() -> Self {
        Self(G1Affine::generator())
    }
}
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L343-416)
```rust
    fn eval_proofs_compute_all(
        proofs: &Self::EvalProofsPromise,
        digest_key: &DigestKey,
    ) -> Self::EvalProofs {
        proofs.compute_all(digest_key)
    }

    fn eval_proofs_compute_all_vzgg_multi_point_eval(
        proofs: &Self::EvalProofsPromise,
        digest_key: &DigestKey,
    ) -> Self::EvalProofs {
        proofs.compute_all_vgzz_multi_point_eval(digest_key)
    }

    fn eval_proof_for_ct(
        proofs: &Self::EvalProofs,
        ct: &Self::Ciphertext,
    ) -> Option<Self::EvalProof> {
        proofs.get(&ct.id())
    }

    fn derive_decryption_key_share(
        msk_share: &Self::MasterSecretKeyShare,
        digest: &Self::Digest,
    ) -> Result<Self::DecryptionKeyShare> {
        msk_share.derive_decryption_key_share(digest)
    }

    fn reconstruct_decryption_key(
        shares: &[Self::DecryptionKeyShare],
        config: &Self::ThresholdConfig,
    ) -> anyhow::Result<Self::DecryptionKey> {
        BIBEDecryptionKey::reconstruct(config, shares)
    }

    fn prepare_cts(
        cts: &[Self::Ciphertext],
        digest: &Self::Digest,
        eval_proofs: &Self::EvalProofs,
    ) -> Result<Vec<Self::PreparedCiphertext>> {
        cts.into_par_iter()
            .map(|ct| ct.prepare(digest, eval_proofs))
            .collect::<anyhow::Result<Vec<Self::PreparedCiphertext>>>()
    }

    fn decrypt<'a, P: Plaintext>(
        decryption_key: &Self::DecryptionKey,
        cts: &[Self::PreparedCiphertext],
    ) -> anyhow::Result<Vec<P>> {
        cts.into_par_iter()
            .map(|ct| {
                let plaintext: Result<P> = decryption_key.decrypt(ct);
                plaintext
            })
            .collect::<anyhow::Result<Vec<P>>>()
    }

    fn verify_decryption_key_share(
        verification_key: &Self::VerificationKey,
        digest: &Self::Digest,
        decryption_key_share: &Self::DecryptionKeyShare,
    ) -> anyhow::Result<()> {
        verification_key.verify_decryption_key_share(digest, decryption_key_share)
    }

    fn decrypt_individual<P: Plaintext>(
        decryption_key: &Self::DecryptionKey,
        ct: &Self::Ciphertext,
        digest: &Self::Digest,
        eval_proof: &Self::EvalProof,
    ) -> Result<P> {
        decryption_key.decrypt(&ct.prepare_individual(digest, eval_proof)?)
    }
}
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L24-154)
```rust
impl PipelineBuilder {
    /// Precondition: Block is materialized and the transactions are available locally
    /// What it does: Decrypt encrypted transactions in the block
    pub(crate) async fn decrypt_encrypted_txns(
        materialize_fut: TaskFuture<MaterializeResult>,
        block: Arc<Block>,
        author: Author,
        secret_share_config: Option<SecretShareConfig>,
        derived_self_key_share_tx: oneshot::Sender<Option<SecretShare>>,
        secret_shared_key_rx: oneshot::Receiver<Option<SecretSharedKey>>,
    ) -> TaskResult<DecryptionResult> {
        let mut tracker = Tracker::start_waiting("decrypt_encrypted_txns", &block);
        let (input_txns, max_txns_from_block_to_execute, block_gas_limit) = materialize_fut.await?;

        tracker.start_working();

        if secret_share_config.is_none() {
            return Ok((input_txns, max_txns_from_block_to_execute, block_gas_limit));
        }

        let (encrypted_txns, unencrypted_txns): (Vec<_>, Vec<_>) = input_txns
            .into_iter()
            .partition(|txn| txn.is_encrypted_txn());

        // TODO: figure out handling of
        if encrypted_txns.is_empty() {
            return Ok((
                unencrypted_txns,
                max_txns_from_block_to_execute,
                block_gas_limit,
            ));
        }

        let digest_key: DigestKey = secret_share_config
            .as_ref()
            .expect("must exist")
            .digest_key()
            .clone();
        let msk_share: MasterSecretKeyShare = secret_share_config
            .as_ref()
            .expect("must exist")
            .msk_share()
            .clone();

        // TODO(ibalajiarun): FIXME
        let len = 10;
        let encrypted_txns = if encrypted_txns.len() > len {
            let mut to_truncate = encrypted_txns;
            to_truncate.truncate(len);
            to_truncate
        } else {
            encrypted_txns
        };

        let txn_ciphertexts: Vec<Ciphertext> = encrypted_txns
            .iter()
            .map(|txn| {
                // TODO(ibalajiarun): Avoid clone and use reference instead
                txn.payload()
                    .as_encrypted_payload()
                    .expect("must be a encrypted txn")
                    .ciphertext()
                    .clone()
            })
            .collect();

        // TODO(ibalajiarun): Consider using commit block height to reduce trusted setup size
        let encryption_round = block.round();
        let (digest, proofs_promise) =
            FPTXWeighted::digest(&digest_key, &txn_ciphertexts, encryption_round)?;

        let metadata = SecretShareMetadata::new(
            block.epoch(),
            block.round(),
            block.timestamp_usecs(),
            block.id(),
            digest.clone(),
        );

        let derived_key_share = FPTXWeighted::derive_decryption_key_share(&msk_share, &digest)?;
        derived_self_key_share_tx
            .send(Some(SecretShare::new(
                author,
                metadata.clone(),
                derived_key_share,
            )))
            .expect("must send properly");

        // TODO(ibalajiarun): improve perf
        let proofs = FPTXWeighted::eval_proofs_compute_all(&proofs_promise, &digest_key);

        let maybe_decryption_key = secret_shared_key_rx
            .await
            .expect("decryption key should be available");
        // TODO(ibalajiarun): account for the case where decryption key is not available
        let decryption_key = maybe_decryption_key.expect("decryption key should be available");

        let decrypted_txns = encrypted_txns
            .into_par_iter()
            .zip(txn_ciphertexts)
            .map(|(mut txn, ciphertext)| {
                let eval_proof = proofs.get(&ciphertext.id()).expect("must exist");
                if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
                    &decryption_key.key,
                    &ciphertext,
                    &digest,
                    &eval_proof,
                ) {
                    let (executable, nonce) = payload.unwrap();
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| {
                            p.into_decrypted(eval_proof, executable, nonce)
                                .expect("must happen")
                        })
                        .expect("must exist");
                } else {
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| p.into_failed_decryption(eval_proof).expect("must happen"))
                        .expect("must exist");
                }
                txn
            })
            .collect();

        let output_txns = [decrypted_txns, unencrypted_txns].concat();

        Ok((output_txns, max_txns_from_block_to_execute, block_gas_limit))
    }
}
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L111-132)
```rust
    pub fn verify(&self, associated_data: &impl AssociatedData) -> Result<()> {
        let hashed_id = Id::from_verifying_key(&self.vk);

        (self.bibe_ct.id() == hashed_id).then_some(()).ok_or(
            BatchEncryptionError::CTVerifyError(CTVerifyError::IdDoesNotMatchHashedVK),
        )?;
        (self.associated_data_bytes == bcs::to_bytes(associated_data)?)
            .then_some(())
            .ok_or(BatchEncryptionError::CTVerifyError(
                CTVerifyError::AssociatedDataDoesNotMatch,
            ))?;

        let to_verify = (&self.bibe_ct, &self.associated_data_bytes);

        self.vk
            .verify(&bcs::to_bytes(&to_verify)?, &self.signature)
            .map_err(|e| {
                BatchEncryptionError::CTVerifyError(CTVerifyError::SigVerificationFailed(e))
            })?;

        Ok(())
    }
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L92-107)
```rust
    fn prepare_individual(
        &self,
        digest: &Digest,
        eval_proof: &EvalProof,
    ) -> Result<PreparedBIBECiphertext> {
        let pairing_output = PairingSetting::pairing(digest.as_g1(), self.ct_g2[0])
            + PairingSetting::pairing(**eval_proof, self.ct_g2[1]);

        Ok(PreparedBIBECiphertext {
            pairing_output,
            ct_g2: self.ct_g2[2].into(),
            padded_key: self.padded_key.clone(),
            symmetric_ciphertext: self.symmetric_ciphertext.clone(),
        })
    }
}
```
