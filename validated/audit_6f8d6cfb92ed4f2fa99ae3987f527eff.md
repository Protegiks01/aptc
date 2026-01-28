# Audit Report

## Title
Silent Deserialization Failures in `get_all_aug_data()` Cause Consensus Divergence Through Incomplete Augmented Data Recovery

## Summary
The `get_all_aug_data()` function in the RandDb storage implementation silently skips augmented data entries that fail BCS deserialization, causing validators to recover incomplete sets of augmented data after restarts. This leads to validators having inconsistent views of certified augmented public keys (APKs), breaking the deterministic execution invariant and causing consensus safety violations in the randomness generation subsystem.

## Finding Description

The vulnerability exists in the database storage layer for consensus randomness generation. When validators restart, they recover previously persisted augmented data, but the recovery mechanism silently drops entries that fail deserialization.

The `get_all()` helper method uses `filter_map` with error suppression - any entry that fails deserialization returns `Err(_)` which gets mapped to `None` and is silently dropped from the result vector: [1](#0-0) 

No error is logged, no metric is recorded, and the validator proceeds as if these entries never existed.

This incomplete data is then used to initialize the `AugDataStore`: [2](#0-1) [3](#0-2) 

For each recovered certified augmented data entry, the `augment()` method is called which adds the delta to the RandConfig: [4](#0-3) [5](#0-4) 

When validators attempt to verify randomness shares, missing APKs cause verification failures: [6](#0-5) 

During share aggregation, the verification is enforced before shares can be added: [7](#0-6) 

When share verification fails due to missing APK, the share is rejected and not included in aggregation. Different validators with different APK sets will aggregate different shares, producing different randomness values: [8](#0-7) 

The different randomness values are then included in the block metadata transaction, which updates the PerBlockRandomness resource: [9](#0-8) [10](#0-9) [11](#0-10) 

This causes validators to execute blocks with different metadata transactions, producing different state roots. When validators vote on the block, they sign different ledger info values (different state roots), preventing consensus from being reached.

The production code uses these types, confirming this affects mainnet: [12](#0-11) 

## Impact Explanation

This vulnerability constitutes a **HIGH severity** issue per the Aptos bug bounty program criteria:

1. **Consensus Safety Violation**: Validators with different augmented data views will have inconsistent RandConfigs, leading to different share verification outcomes and different randomness generation results. This causes them to compute different state roots for the same block, preventing consensus from being reached. This breaks the fundamental consensus invariant that all honest validators must agree on the same state, qualifying as a "Consensus/Safety Violation" under CRITICAL severity criteria.

2. **Significant Protocol Violations**: The randomness generation protocol requires all validators to have consistent views of augmented data. Silent failures violate this requirement without any error indication, making diagnosis extremely difficult.

3. **Network Liveness Risk**: If enough validators have inconsistent augmented data views, the network may fail to reach consensus on blocks requiring randomness, causing liveness failures.

While this doesn't directly cause loss of funds, it breaks the **Consensus Safety** critical invariant, which is foundational to blockchain security.

## Likelihood Explanation

The likelihood is **LOW to MEDIUM**:

**Triggers:**
- Database corruption from disk failures, power outages, or hardware issues
- BCS schema changes during software upgrades causing deserialization incompatibility
- Incomplete or corrupted database backups/replications
- Storage layer bugs or race conditions

**Real-world scenarios:**
- A validator restarts after a crash with partial database corruption
- A validator upgrades to a new version with schema changes and has old data
- Database replication failures leave validators with inconsistent data
- Storage backend failures corrupt specific database entries

**Critical constraint:** This requires ASYMMETRIC failures - different validators must have different corrupted entries to cause consensus divergence. If all validators have the same schema issues, they would all drop the same entries (no divergence).

The issue is particularly insidious because:
1. No error is raised to alert operators
2. No monitoring or metrics track deserialization failures
3. Validators appear to function normally until randomness generation fails
4. Root cause diagnosis is extremely difficult without detailed investigation

## Recommendation

Add comprehensive error handling and logging to the `get_all()` method:

```rust
fn get_all<S: Schema>(&self) -> Result<Vec<(S::Key, S::Value)>, DbError> {
    let mut iter = self.db.iter::<S>()?;
    iter.seek_to_first();
    let mut results = Vec::new();
    let mut failed_count = 0;
    
    for item in iter {
        match item {
            Ok((k, v)) => results.push((k, v)),
            Err(e) => {
                failed_count += 1;
                error!("Failed to deserialize entry from database: {:?}", e);
                // Increment metric
                counters::DATABASE_DESERIALIZATION_FAILURES.inc();
            }
        }
    }
    
    if failed_count > 0 {
        return Err(DbError::Other(format!(
            "Failed to deserialize {} entries from database", 
            failed_count
        )));
    }
    
    Ok(results)
}
```

Additionally, add integrity checks during AugDataStore initialization to verify completeness of recovered augmented data against expected validator set.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Corrupting a specific augmented data entry in RandDb storage
2. Restarting the validator node
3. Observing that the corrupted entry is silently dropped during recovery
4. Verifying that the RandConfig is missing the corresponding APK
5. Attempting share verification and observing failures for that validator

The code path is fully traced through the actual production codebase as shown in the citations above.

## Notes

This is a reliability and robustness issue in the consensus randomness generation system. While not directly exploitable by malicious actors, database corruption and schema incompatibilities are real-world scenarios that can trigger this vulnerability. The silent nature of the failure makes it particularly dangerous, as operators have no visibility into the incomplete data recovery until consensus failures occur. The impact on consensus safety is severe, potentially preventing the network from reaching agreement on blocks requiring randomness.

### Citations

**File:** consensus/src/rand/rand_gen/storage/db.rs (L73-82)
```rust
    fn get_all<S: Schema>(&self) -> Result<Vec<(S::Key, S::Value)>, DbError> {
        let mut iter = self.db.iter::<S>()?;
        iter.seek_to_first();
        Ok(iter
            .filter_map(|e| match e {
                Ok((k, v)) => Some((k, v)),
                Err(_) => None,
            })
            .collect::<Vec<(S::Key, S::Value)>>())
    }
```

**File:** consensus/src/rand/rand_gen/storage/db.rs (L102-108)
```rust
    fn get_all_aug_data(&self) -> Result<Vec<(AugDataId, AugData<D>)>> {
        Ok(self.get_all::<AugDataSchema<D>>()?)
    }

    fn get_all_certified_aug_data(&self) -> Result<Vec<(AugDataId, CertifiedAugData<D>)>> {
        Ok(self.get_all::<CertifiedAugDataSchema<D>>()?)
    }
```

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L51-71)
```rust
        let all_data = db.get_all_aug_data().unwrap_or_default();
        let (to_remove, aug_data) = Self::filter_by_epoch(epoch, all_data.into_iter());
        if let Err(e) = db.remove_aug_data(to_remove) {
            error!("[AugDataStore] failed to remove aug data: {:?}", e);
        }

        let all_certified_data = db.get_all_certified_aug_data().unwrap_or_default();
        let (to_remove, certified_data) =
            Self::filter_by_epoch(epoch, all_certified_data.into_iter());
        if let Err(e) = db.remove_certified_aug_data(to_remove) {
            error!(
                "[AugDataStore] failed to remove certified aug data: {:?}",
                e
            );
        }

        for (_, certified_data) in &certified_data {
            certified_data
                .data()
                .augment(&config, &fast_config, certified_data.author());
        }
```

**File:** consensus/src/rand/rand_gen/types.rs (L52-81)
```rust
    fn verify(
        &self,
        rand_config: &RandConfig,
        rand_metadata: &RandMetadata,
        author: &Author,
    ) -> anyhow::Result<()> {
        let index = *rand_config
            .validator
            .address_to_validator_index()
            .get(author)
            .ok_or_else(|| anyhow!("Share::verify failed with unknown author"))?;
        let maybe_apk = &rand_config.keys.certified_apks[index];
        if let Some(apk) = maybe_apk.get() {
            WVUF::verify_share(
                &rand_config.vuf_pp,
                apk,
                bcs::to_bytes(&rand_metadata)
                    .map_err(|e| anyhow!("Serialization failed: {}", e))?
                    .as_slice(),
                &self.share,
            )?;
        } else {
            bail!(
                "[RandShare] No augmented public key for validator id {}, {}",
                index,
                author
            );
        }
        Ok(())
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L97-148)
```rust
    fn aggregate<'a>(
        shares: impl Iterator<Item = &'a RandShare<Self>>,
        rand_config: &RandConfig,
        rand_metadata: RandMetadata,
    ) -> anyhow::Result<Randomness>
    where
        Self: Sized,
    {
        let timer = std::time::Instant::now();
        let mut apks_and_proofs = vec![];
        for share in shares {
            let id = rand_config
                .validator
                .address_to_validator_index()
                .get(share.author())
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with invalid share author: {}",
                        share.author
                    )
                })?;
            let apk = rand_config
                .get_certified_apk(share.author())
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with missing apk for share from {}",
                        share.author
                    )
                })?;
            apks_and_proofs.push((Player { id }, apk.clone(), share.share().share));
        }

        let proof = WVUF::aggregate_shares(&rand_config.wconfig, &apks_and_proofs);
        let metadata_serialized = bcs::to_bytes(&rand_metadata).map_err(|e| {
            anyhow!("Share::aggregate failed with metadata serialization error: {e}")
        })?;
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
        debug!("WVUF derivation time: {} ms", timer.elapsed().as_millis());
        let eval_bytes = bcs::to_bytes(&eval)
            .map_err(|e| anyhow!("Share::aggregate failed with eval serialization error: {e}"))?;
        let rand_bytes = Sha3_256::digest(eval_bytes.as_slice()).to_vec();
        Ok(Randomness::new(rand_metadata, rand_bytes))
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L178-194)
```rust
    fn augment(
        &self,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        author: &Author,
    ) {
        let AugmentedData { delta, fast_delta } = self;
        rand_config
            .add_certified_delta(author, delta.clone())
            .expect("Add delta should succeed");

        if let (Some(config), Some(fast_delta)) = (fast_rand_config, fast_delta) {
            config
                .add_certified_delta(author, fast_delta.clone())
                .expect("Add delta for fast path should succeed");
        }
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L661-665)
```rust
    pub fn add_certified_delta(&self, peer: &Author, delta: Delta) -> anyhow::Result<()> {
        let apk = self.derive_apk(peer, delta)?;
        self.add_certified_apk(peer, apk)?;
        Ok(())
    }
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L131-151)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.rand_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.rand_metadata,
            share.metadata()
        );
        share.verify(&self.rand_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveRandShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.rand_store.lock();
        let aggregated = if store.add_share(share, PathType::Slow)? {
            Some(())
        } else {
            None
        };
        Ok(aggregated)
    }
```

**File:** types/src/block_metadata_ext.rs (L23-34)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMetadataWithRandomness {
    pub id: HashValue,
    pub epoch: u64,
    pub round: u64,
    pub proposer: AccountAddress,
    #[serde(with = "serde_bytes")]
    pub previous_block_votes_bitvec: Vec<u8>,
    pub failed_proposer_indices: Vec<u32>,
    pub timestamp_usecs: u64,
    pub randomness: Option<Randomness>,
}
```

**File:** aptos-move/framework/aptos-framework/sources/randomness.move (L64-72)
```text
    public(friend) fun on_new_block(vm: &signer, epoch: u64, round: u64, seed_for_new_block: Option<vector<u8>>) acquires PerBlockRandomness {
        system_addresses::assert_vm(vm);
        if (exists<PerBlockRandomness>(@aptos_framework)) {
            let randomness = borrow_global_mut<PerBlockRandomness>(@aptos_framework);
            randomness.epoch = epoch;
            randomness.round = round;
            randomness.seed = seed_for_new_block;
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L221-247)
```text
    fun block_prologue_ext(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64,
        randomness_seed: Option<vector<u8>>,
    ) acquires BlockResource, CommitHistory {
        let epoch_interval = block_prologue_common(
            &vm,
            hash,
            epoch,
            round,
            proposer,
            failed_proposer_indices,
            previous_block_votes_bitvec,
            timestamp
        );
        randomness::on_new_block(&vm, epoch, round, randomness_seed);

        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration_with_dkg::try_start();
        };
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L240-251)
```rust
        let rand_manager = RandManager::<Share, AugmentedData>::new(
            self.author,
            epoch_state.clone(),
            signer,
            rand_config,
            fast_rand_config,
            rand_ready_block_tx,
            network_sender.clone(),
            self.rand_storage.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );
```
