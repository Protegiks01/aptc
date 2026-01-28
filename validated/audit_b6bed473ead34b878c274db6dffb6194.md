> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L172-184)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.secret_share_store
            .lock()
            .update_highest_known_round(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L211-304)
```rust
    secret_share_map: HashMap<Round, SecretShareItem>,
    highest_known_round: u64,
    decision_tx: Sender<SecretSharedKey>,
}

impl SecretShareStore {
    pub fn new(
        epoch: u64,
        author: Author,
        dec_config: SecretShareConfig,
        decision_tx: Sender<SecretSharedKey>,
    ) -> Self {
        Self {
            epoch,
            self_author: author,
            secret_share_config: dec_config,
            secret_share_map: HashMap::new(),
            highest_known_round: 0,
            decision_tx,
        }
    }

    pub fn update_highest_known_round(&mut self, round: u64) {
        self.highest_known_round = std::cmp::max(self.highest_known_round, round);
    }

    pub fn add_self_share(&mut self, share: SecretShare) -> anyhow::Result<()> {
        assert!(
            self.self_author == share.author,
            "Only self shares can be added with metadata"
        );
        let peer_weights = self.secret_share_config.get_peer_weights();
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share_with_metadata(share, peer_weights)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(())
    }

    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }

    /// This should only be called after the block is added, returns None if already decided
    /// Otherwise returns existing shares' authors
    pub fn get_all_shares_authors(
        &self,
        metadata: &SecretShareMetadata,
    ) -> Option<HashSet<Author>> {
        self.secret_share_map
            .get(&metadata.round)
            .and_then(|item| item.get_all_shares_authors())
    }

    pub fn get_self_share(
        &mut self,
        metadata: &SecretShareMetadata,
    ) -> anyhow::Result<Option<SecretShare>> {
        ensure!(
            metadata.round <= self.highest_known_round,
            "Request share from future round {}, highest known round {}",
            metadata.round,
            self.highest_known_round
        );
        Ok(self
            .secret_share_map
            .get(&metadata.round)
            .and_then(|item| item.get_self_share())
            .filter(|share| &share.metadata == metadata))
    }
}
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L64-77)
```rust
    pub fn set_secret_shared_key(&mut self, round: Round, key: SecretSharedKey) {
        let offset = self.offset(round);
        if self.pending_secret_key_rounds.contains(&round) {
            observe_block(
                self.blocks()[offset].timestamp_usecs(),
                BlockStage::SECRET_SHARING_ADD_DECISION,
            );
            let block = &self.blocks_mut()[offset];
            if let Some(tx) = block.pipeline_tx().lock().as_mut() {
                tx.secret_shared_key_tx.take().map(|tx| tx.send(Some(key)));
            }
            self.pending_secret_key_rounds.remove(&round);
        }
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L90-154)
```rust
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

**File:** consensus/src/pipeline/buffer_manager.rs (L69-72)
```rust
pub enum ResetSignal {
    Stop,
    TargetRound(u64),
}
```

**File:** consensus/src/pipeline/execution_client.rs (L674-709)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };

        if let Some(mut reset_tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx: ack_tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::RandResetDropped)?;
            ack_rx.await.map_err(|_| Error::RandResetDropped)?;
        }

        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }

        Ok(())
    }
```
