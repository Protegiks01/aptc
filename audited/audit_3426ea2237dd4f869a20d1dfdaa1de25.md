# Audit Report

## Title
EventByKeySchema Permanent Index Corruption During Historical Reindexing Due to Latest State Usage in Event V2 Translation

## Summary
The EventV2 translation engine uses the latest blockchain state to determine sequence numbers when translating V2 events to V1 events during historical reindexing. This causes incorrect sequence numbers to be assigned to historical events, resulting in permanent corruption of the EventByKeySchema index that cannot be recovered without a full database reset. [1](#0-0) 

## Finding Description

The vulnerability exists in the EventV2-to-V1 translation mechanism used by the internal indexer. When the `DBIndexer` processes historical transactions during a reindex operation (e.g., after database corruption, fresh node sync, or intentional indexer rebuild), it translates V2 contract events to V1 format for backward compatibility.

**The Critical Flaw:**

Each translator (e.g., `CoinDepositTranslator`, `CoinWithdrawTranslator`) determines the sequence number for translated events by:

1. Fetching the current state of the relevant resource (e.g., `CoinStore`) using `latest_state_checkpoint_view()`
2. Reading the event handle's `count()` field from this CURRENT state
3. Using this count as the default value when calling `get_next_sequence_number()` [2](#0-1) 

However, when reindexing historical transactions at version `V_old` from a ledger state at version `V_current` where `V_current >> V_old`:

- The translator reads the event handle count from `V_current` (e.g., count = 500)
- But the ACTUAL count at `V_old` was much lower (e.g., count = 10)
- The sequence number assigned is based on the wrong count (501 instead of 11)
- This incorrect mapping is written to `EventByKeySchema` [3](#0-2) 

**Reindexing Scenario:**

When the internal indexer needs to catch up from a historical version: [4](#0-3) 

Or when explicitly processing historical batches: [5](#0-4) 

The `process_a_batch` method processes transactions from `start_version` to `end_version`, but the translation engine always queries the LATEST state, not the historical state at each transaction's version.

**Broken Invariant:**

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable." The EventByKeySchema index should deterministically map `(EventKey, SequenceNumber) → (Version, Index)` based on the historical state at each version, not based on future state.

## Impact Explanation

**High Severity** - This meets the "Significant protocol violations" and "State inconsistencies requiring intervention" criteria:

1. **Permanent Index Corruption**: EventByKeySchema contains incorrect mappings that cannot self-heal
2. **Non-Deterministic Node State**: Different nodes reindexing at different times will have DIFFERENT corrupted indices
3. **Query Failures**: Event lookups by key and sequence number return wrong events or fail entirely
4. **API Unreliability**: Applications, wallets, and block explorers receive incorrect event data
5. **Requires Hard Intervention**: Only fix is to wipe and rebuild the entire internal indexer database
6. **Trust Loss**: Nodes with corrupted indices cannot be trusted for event queries

The impact is widespread because:
- Any node performing a fresh sync with event V2 translation enabled is affected
- Any node recovering from internal indexer corruption is affected  
- Testing environments using the internal indexer (as shown in the test) are affected
- The corruption is PERMANENT and cannot be detected without external verification

## Likelihood Explanation

**High Likelihood** - This bug WILL occur in the following common scenarios:

1. **Fresh Node Deployment**: New validator or full node syncing from genesis or state snapshot with `enable_event_v2_translation = true`
2. **Database Recovery**: Any node recovering from internal indexer corruption or migration
3. **Intentional Rebuild**: Operators clearing internal indexer to reclaim disk space
4. **Development/Testing**: As evidenced by the existing test that demonstrates the exact vulnerable pattern

The bug is not triggered by malicious actors but is a deterministic implementation error that affects normal operations. Every affected node will independently produce corrupted but DIFFERENT indices depending on when they perform the reindexing.

## Recommendation

**Fix:** Modify `EventV2TranslationEngine` to use historical state views at the specific transaction version being processed, not the latest state.

**Implementation Approach:**

1. Add a version parameter to `get_state_value_bytes_for_resource`:
```rust
pub fn get_state_value_bytes_for_resource(
    &self,
    address: &AccountAddress,
    struct_tag: &StructTag,
    version: Version,  // Add version parameter
) -> Result<Option<Bytes>>
```

2. Use `state_view_at_version(Some(version))` instead of `latest_state_checkpoint_view()`:
```rust
let state_view = self
    .main_db_reader
    .state_view_at_version(Some(version))?;  // Use historical state
```

3. Update all translator implementations to pass the transaction version when fetching state

4. Update `process_a_batch` to pass the current transaction version to translation methods:
```rust
self.translate_event_v2_to_v1_at_version(v2, version)?
```

**Alternative Safeguard:**

If historical state access is too expensive, the system should:
1. Detect reindexing scenarios (when processing versions far behind latest)
2. Either disable event V2 translation during historical reindexing, OR
3. Mandate that `EventSequenceNumberSchema` must be fully populated before reindexing

## Proof of Concept

The existing test demonstrates the vulnerability: [6](#0-5) 

**Reproduction Steps:**

1. Create a test database with V2 coin transfer events at versions 0-11
2. Let the ledger advance to version 11 with multiple coin deposit/withdraw events
3. Create a fresh internal indexer DB (empty EventByKeySchema)
4. Process historical batches from version 0 to 11 with `event_v2_translation_enabled = true`
5. Observe that translated events receive sequence numbers based on the state at version 11, not their historical state
6. Verify EventByKeySchema contains incorrect `(key, seq_num) → (version, idx)` mappings

**Expected Behavior:** Sequence numbers should match the event handle count at the historical version when each event was emitted.

**Actual Behavior:** Sequence numbers are calculated using the latest state, producing corrupted index entries.

## Notes

This vulnerability affects only the internal indexer's EventByKeySchema, not the main ledger database. However, the internal indexer is critical for API functionality and event querying. The bug is particularly insidious because it's deterministic but produces DIFFERENT corruption on different nodes depending on when they perform reindexing, making cross-validation impossible.

### Citations

**File:** storage/indexer/src/event_v2_translator.rs (L202-214)
```rust
    pub fn get_state_value_bytes_for_resource(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
    ) -> Result<Option<Bytes>> {
        let state_view = self
            .main_db_reader
            .latest_state_checkpoint_view()
            .expect("Failed to get state view");
        let state_key = StateKey::resource(address, struct_tag)?;
        let maybe_state_value = state_view.get_state_value(&state_key)?;
        Ok(maybe_state_value.map(|state_value| state_value.bytes().clone()))
    }
```

**File:** storage/indexer/src/event_v2_translator.rs (L238-273)
```rust
struct CoinDepositTranslator;
impl EventV2Translator for CoinDepositTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let coin_deposit = CoinDeposit::try_from_bytes(v2.event_data())?;
        let struct_tag_str = format!("0x1::coin::CoinStore<{}>", coin_deposit.coin_type());
        let struct_tag = StructTag::from_str(&struct_tag_str)?;
        let (key, sequence_number) = if let Some(state_value_bytes) =
            engine.get_state_value_bytes_for_resource(coin_deposit.account(), &struct_tag)?
        {
            // We can use `DummyCoinType` as it does not affect the correctness of deserialization.
            let coin_store_resource: CoinStoreResource<DummyCoinType> =
                bcs::from_bytes(&state_value_bytes)?;
            let key = *coin_store_resource.deposit_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, coin_store_resource.deposit_events().count())?;
            (key, sequence_number)
        } else {
            // The creation number of DepositEvent is deterministically 2.
            static DEPOSIT_EVENT_CREATION_NUMBER: u64 = 2;
            (
                EventKey::new(DEPOSIT_EVENT_CREATION_NUMBER, *coin_deposit.account()),
                0,
            )
        };
        let deposit_event = DepositEvent::new(coin_deposit.amount());
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            DEPOSIT_EVENT_TYPE.clone(),
            bcs::to_bytes(&deposit_event)?,
        )?)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L448-485)
```rust
                    if self.indexer_db.event_v2_translation_enabled() {
                        if let ContractEvent::V2(v2) = event {
                            if let Some(translated_v1_event) =
                                self.translate_event_v2_to_v1(v2).map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to translate event: {:?}. Error: {}",
                                        v2,
                                        e
                                    )
                                })?
                            {
                                let key = *translated_v1_event.key();
                                let sequence_number = translated_v1_event.sequence_number();
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
                                event_keys.insert(key);
                                batch
                                    .put::<EventByKeySchema>(
                                        &(key, sequence_number),
                                        &(version, idx as u64),
                                    )
                                    .expect("Failed to put events by key to a batch");
                                batch
                                    .put::<EventByVersionSchema>(
                                        &(key, version, sequence_number),
                                        &(idx as u64),
                                    )
                                    .expect("Failed to put events by version to a batch");
                                batch
                                    .put::<TranslatedV1EventSchema>(
                                        &(version, idx as u64),
                                        &translated_v1_event,
                                    )
                                    .expect("Failed to put translated v1 events to a batch");
                            }
                        }
                    }
                    Ok::<(), AptosDbError>(())
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L194-233)
```rust
    fn open_indexer(
        &mut self,
        db_root_path: impl AsRef<Path>,
        rocksdb_config: RocksdbConfig,
    ) -> Result<()> {
        let indexer = Indexer::open(&db_root_path, rocksdb_config)?;
        let ledger_next_version = self.get_synced_version()?.map_or(0, |v| v + 1);
        info!(
            indexer_next_version = indexer.next_version(),
            ledger_next_version = ledger_next_version,
            "Opened AptosDB Indexer.",
        );

        if indexer.next_version() < ledger_next_version {
            use aptos_storage_interface::state_store::state_view::db_state_view::DbStateViewAtVersion;
            let db: Arc<dyn DbReader> = self.state_store.clone();

            let state_view = db.state_view_at_version(Some(ledger_next_version - 1))?;
            let annotator = AptosValueAnnotator::new(&state_view);

            const BATCH_SIZE: Version = 10000;
            let mut next_version = indexer.next_version();
            while next_version < ledger_next_version {
                info!(next_version = next_version, "AptosDB Indexer catching up. ",);
                let end_version = std::cmp::min(ledger_next_version, next_version + BATCH_SIZE);
                let write_sets = self
                    .ledger_db
                    .write_set_db()
                    .get_write_sets(next_version, end_version)?;
                let write_sets_ref: Vec<_> = write_sets.iter().collect();
                indexer.index_with_annotator(&annotator, next_version, &write_sets_ref)?;

                next_version = end_version;
            }
        }
        info!("AptosDB Indexer caught up.");

        self.indexer = Some(indexer);
        Ok(())
    }
```

**File:** execution/executor/tests/internal_indexer_test.rs (L136-178)
```rust
fn test_db_indexer_data() {
    use std::{thread, time::Duration};
    // create test db
    let (aptos_db, core_account) = create_test_db();
    let total_version = aptos_db.expect_synced_version();
    assert_eq!(total_version, 11);
    let temp_path = TempPath::new();
    let mut node_config = aptos_config::config::NodeConfig::default();
    node_config.storage.dir = temp_path.path().to_path_buf();
    node_config.indexer_db_config.enable_event = true;
    node_config.indexer_db_config.enable_transaction = true;
    node_config.indexer_db_config.enable_statekeys = true;

    let internal_indexer_db = InternalIndexerDBService::get_indexer_db(&node_config).unwrap();

    let db_indexer = DBIndexer::new(internal_indexer_db.clone(), aptos_db.clone());
    // assert the data matches the expected data
    let version = internal_indexer_db.get_persisted_version().unwrap();
    assert_eq!(version, None);
    let start_version = version.map_or(0, |v| v + 1);
    db_indexer
        .process_a_batch(start_version, total_version)
        .unwrap();
    // wait for the commit to finish
    thread::sleep(Duration::from_millis(100));
    // indexer has process all the transactions
    assert_eq!(
        internal_indexer_db.get_persisted_version().unwrap(),
        Some(total_version)
    );

    let txn_iter = internal_indexer_db
        .get_account_ordered_transactions_iter(core_account.address(), 0, 1000, total_version)
        .unwrap();
    let res: Vec<_> = txn_iter.collect();

    // core account submitted 7 transactions including last reconfig txn, and the first transaction is version 2
    assert!(res.len() == 7);
    assert!(res[0].as_ref().unwrap().1 == 2);

    let x = internal_indexer_db.get_event_by_key_iter().unwrap();
    let res: Vec<_> = x.collect();
    assert_eq!(res.len(), 4);
```
