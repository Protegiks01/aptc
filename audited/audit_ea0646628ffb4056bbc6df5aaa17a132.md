# Audit Report

## Title
Non-Deterministic Event Translation Due to Incorrect State View Usage in Indexer

## Summary
The event V2 translator uses `latest_state_checkpoint_view()` to query resources when translating events, instead of querying the state at the specific version being indexed. This causes non-deterministic event translation when resources are unavailable in the latest checkpoint, with five translators proceeding with hardcoded fallback values that can be incorrect.

## Finding Description

The `get_state_value_bytes_for_resource()` function queries resources using the latest state checkpoint rather than the state at the transaction version being indexed: [1](#0-0) 

When the indexer processes transactions at version V, it retrieves events emitted at that version but queries resource state from the latest checkpoint (which could be V+N or even V-M due to sync lag): [2](#0-1) 

Five translators (CoinDeposit, CoinWithdraw, CoinRegister, KeyRotation, Transfer) have fallback logic that proceeds with hardcoded creation numbers and sequence number 0 when the resource is not found: [3](#0-2) [4](#0-3) 

In contrast, other translators properly error when resources are not found: [5](#0-4) 

**Exploitation Scenario:**

1. Account A has CoinStore with deposit_events.counter = 50
2. Transaction at version V emits CoinDeposit V2 event (should translate to sequence 50)
3. Transaction at version V+10 deletes the CoinStore (migration to FungibleAsset)
4. Node X indexes version V when its latest checkpoint is V+10
5. Translator queries latest state, finds no CoinStore (deleted at V+10)
6. Fallback assigns sequence number 0 instead of 50
7. This creates event sequence collision and incorrect indexing

Real-world evidence of CoinStore deletion exists: [6](#0-5) 

The translated events are served via API to external applications: [7](#0-6) 

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria ("State inconsistencies requiring intervention"):

1. **Non-Deterministic Indexing**: Different nodes processing the same transaction can generate different translated events if they have different latest checkpoint states
2. **Incorrect Event Sequencing**: Events can be assigned wrong sequence numbers, causing collisions with existing events
3. **Application Impact**: External applications relying on event APIs receive inconsistent or incorrect event data across nodes, potentially leading to accounting errors in DeFi protocols, wallets, or indexers
4. **Data Integrity Violation**: The indexer no longer provides consistent views of blockchain history

While this doesn't affect consensus or on-chain state, it violates the indexer's correctness guarantees and requires code intervention to fix.

## Likelihood Explanation

**High Likelihood**: This vulnerability triggers during normal operation whenever:
- There's lag between transaction commitment and indexing
- Resources are created/deleted around the indexed version
- Multiple nodes index the same version with different sync states

The issue is systematic, not dependent on attacker action. It affects all deployments using event V2 translation.

## Recommendation

Replace `latest_state_checkpoint_view()` with `state_view_at_version()` to query state at the specific version being indexed:

```rust
pub fn get_state_value_bytes_for_resource(
    &self,
    address: &AccountAddress,
    struct_tag: &StructTag,
    version: Version, // Add version parameter
) -> Result<Option<Bytes>> {
    let state_view = self
        .main_db_reader
        .state_view_at_version(Some(version))? // Query at specific version
        .expect("Failed to get state view");
    let state_key = StateKey::resource(address, struct_tag)?;
    let maybe_state_value = state_view.get_state_value(&state_key)?;
    Ok(maybe_state_value.map(|state_value| state_value.bytes().clone()))
}
```

Update all translator calls to pass the transaction version being indexed. The `state_view_at_version` trait is already available: [8](#0-7) 

## Proof of Concept

Reproduction steps:

1. Create account A with CoinStore, emit 50 deposit events (counter=50)
2. Submit transaction T1 at version V: emit CoinDeposit V2 event
3. Submit transaction T2 at version V+5: delete CoinStore
4. Configure indexer with delayed processing
5. When indexer processes V with latest checkpoint at V+5:
   - Translator queries for CoinStore using latest state
   - CoinStore not found (deleted at V+5)
   - Fallback assigns sequence 0 instead of 50
   - Verify collision with original sequence 0 event

Expected: Event should have sequence number 50
Actual: Event has sequence number 0 (incorrect)

This demonstrates non-deterministic indexing where the same transaction produces different indexed events depending on timing.

## Notes

The alternative implementation using `state_view_at_version(Some(version-1))` would query the pre-state before the transaction, which should contain the CoinStore resource before any modifications. The version parameter needs to be threaded through the translator interface from the indexer's transaction processing loop.

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

**File:** storage/indexer/src/event_v2_translator.rs (L248-265)
```rust
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
```

**File:** storage/indexer/src/event_v2_translator.rs (L286-303)
```rust
        let (key, sequence_number) = if let Some(state_value_bytes) =
            engine.get_state_value_bytes_for_resource(coin_withdraw.account(), &struct_tag)?
        {
            // We can use `DummyCoinType` as it does not affect the correctness of deserialization.
            let coin_store_resource: CoinStoreResource<DummyCoinType> =
                bcs::from_bytes(&state_value_bytes)?;
            let key = *coin_store_resource.withdraw_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, coin_store_resource.withdraw_events().count())?;
            (key, sequence_number)
        } else {
            // The creation number of WithdrawEvent is deterministically 3.
            static WITHDRAW_EVENT_CREATION_NUMBER: u64 = 3;
            (
                EventKey::new(WITHDRAW_EVENT_CREATION_NUMBER, *coin_withdraw.account()),
                0,
            )
        };
```

**File:** storage/indexer/src/event_v2_translator.rs (L440-456)
```rust
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_object_group_resource(
                token_mutation.token_address(),
                &struct_tag,
            )? {
            let token_resource: TokenResource = bcs::from_bytes(&state_value_bytes)?;
            let key = *token_resource.mutation_events().key();
            let sequence_number =
                engine.get_next_sequence_number(&key, token_resource.mutation_events().count())?;
            (key, sequence_number)
        } else {
            // If the token resource is not found, we skip the event translation to avoid panic
            // because the creation number cannot be decided. The token may have been burned.
            return Err(AptosDbError::from(anyhow::format_err!(
                "Token resource not found"
            )));
        };
```

**File:** storage/indexer/src/db_indexer.rs (L410-450)
```rust
    pub fn process_a_batch(&self, start_version: Version, end_version: Version) -> Result<Version> {
        let _timer: aptos_metrics_core::HistogramTimer = TIMER.timer_with(&["process_a_batch"]);
        let mut version = start_version;
        let num_transactions = self.get_num_of_transactions(version, end_version)?;
        // This promises num_transactions should be readable from main db
        let mut db_iter = self.get_main_db_iter(version, num_transactions)?;
        let mut batch = SchemaBatch::new();
        let mut event_keys: HashSet<EventKey> = HashSet::new();
        db_iter.try_for_each(|res| {
            let (txn, events, writeset) = res?;
            if let Some(signed_txn) = txn.try_as_signed_user_txn() {
                if self.indexer_db.transaction_enabled() {
                    if let ReplayProtector::SequenceNumber(seq_num) = signed_txn.replay_protector()
                    {
                        batch.put::<OrderedTransactionByAccountSchema>(
                            &(signed_txn.sender(), seq_num),
                            &version,
                        )?;
                    }
                }
            }

            if self.indexer_db.event_enabled() {
                events.iter().enumerate().try_for_each(|(idx, event)| {
                    if let ContractEvent::V1(v1) = event {
                        batch
                            .put::<EventByKeySchema>(
                                &(*v1.key(), v1.sequence_number()),
                                &(version, idx as u64),
                            )
                            .expect("Failed to put events by key to a batch");
                        batch
                            .put::<EventByVersionSchema>(
                                &(*v1.key(), version, v1.sequence_number()),
                                &(idx as u64),
                            )
                            .expect("Failed to put events by version to a batch");
                    }
                    if self.indexer_db.event_v2_translation_enabled() {
                        if let ContractEvent::V2(v2) = event {
                            if let Some(translated_v1_event) =
```

**File:** ecosystem/indexer-grpc/indexer-test-transactions/src/json_transactions/imported_mainnet_txns/2186504987_coin_store_deletion_no_event.json (L129-149)
```json
        "type": "TYPE_DELETE_RESOURCE",
        "deleteResource": {
          "address": "0x3e91d912e7c62dfd884fd8b9a2261fecd33c78cf4da1b1ef2e7452c585c6f30d",
          "stateKeyHash": "6wWhpePmC1JSowDM3jtgsL1AABc0vJSAgy2F2MO3RTs=",
          "type": {
            "address": "0x1",
            "module": "coin",
            "name": "CoinStore",
            "genericTypeParams": [
              {
                "type": "MOVE_TYPES_STRUCT",
                "struct": {
                  "address": "0x1",
                  "module": "aptos_coin",
                  "name": "AptosCoin"
                }
              }
            ]
          },
          "typeStr": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        }
```

**File:** api/src/context.rs (L1040-1064)
```rust
        events: &mut [ContractEvent],
    ) -> Result<()> {
        let mut count_map: HashMap<EventKey, u64> = HashMap::new();
        for event in events.iter_mut() {
            if let ContractEvent::V2(v2) = event {
                let translated_event = self
                    .indexer_reader
                    .as_ref()
                    .ok_or(anyhow!("Internal indexer reader doesn't exist"))?
                    .translate_event_v2_to_v1(v2)?;
                if let Some(v1) = translated_event {
                    let count = count_map.get(v1.key()).unwrap_or(&0);
                    let v1_adjusted = ContractEventV1::new(
                        *v1.key(),
                        v1.sequence_number() + count,
                        v1.type_tag().clone(),
                        v1.event_data().to_vec(),
                    )?;
                    *event = ContractEvent::V1(v1_adjusted);
                    count_map.insert(*v1.key(), count + 1);
                }
            }
        }
        Ok(())
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L93-105)
```rust
pub trait DbStateViewAtVersion {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView>;
}

impl DbStateViewAtVersion for Arc<dyn DbReader> {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version,
            maybe_verify_against_state_root_hash: None,
        })
    }
}
```
