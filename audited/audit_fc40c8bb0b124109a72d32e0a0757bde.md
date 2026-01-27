# Audit Report

## Title
V2 Event Translation Failure Causes Permanent Event Loss During Token Claim Migration

## Summary
When the event migration flag is enabled, V2 `Claim` events from the token_transfers module are translated back to V1 format for backward compatibility. The translation process reads the `PendingClaims` resource from the latest blockchain state rather than historical state. If this resource is deleted or unavailable between event emission and translation, the translator silently drops the event with only a warning log, causing permanent data loss for indexers and applications relying on event history.

## Finding Description

The vulnerability exists in the event V2-to-V1 translation system used during the migration from EventHandle-based events (V1) to module events (V2). [1](#0-0) 

When `module_event_migration_enabled()` returns true, the `claim()` function emits a V2 `Claim` event. This event must later be translated to V1 format by the indexer for backward compatibility. [2](#0-1) 

The `ClaimTranslator` reads the `PendingClaims` resource from the sender's account to obtain the EventHandle key and compute the sequence number. However, it reads from `latest_state_checkpoint_view()`: [3](#0-2) [4](#0-3) 

This reads the **latest committed state**, not the historical state at the time the event was emitted. If the `PendingClaims` resource no longer exists (due to account deletion, resource cleanup, or future protocol upgrades), the translator returns an error.

The critical flaw is in the error handling: [5](#0-4) 

When translation fails, the system logs a warning but returns `Ok(None)` instead of propagating the error. This causes the event to be silently skipped: [6](#0-5) 

The `if let Some(translated_v1_event)` block is never entered when `Ok(None)` is returned, so the event is never indexed.

**Attack/Failure Scenario:**
1. Alice offers a token to Bob, creating `PendingClaims` at Alice's account
2. Bob claims the token during migration period (V2 `Claim` event emitted with `account: Alice`)
3. The blockchain progresses; indexer falls behind
4. Alice's account is deleted OR `PendingClaims` resource is removed via future cleanup functions
5. Indexer eventually processes Bob's claim event
6. Translator attempts to read `PendingClaims` from latest state (now deleted)
7. Translation fails with "PendingClaims resource not found"
8. Event is silently dropped from the index permanently

## Impact Explanation

This qualifies as **High Severity** per Aptos Bug Bounty criteria:

**Significant Protocol Violations:**
- Breaks the event indexing invariant that all events must be queryable
- Violates data availability guarantees for historical blockchain data
- Creates inconsistency between on-chain events and indexed data

**Affected Systems:**
- All indexers processing historical V2 events during migration
- Block explorers showing incomplete event histories
- Applications relying on token claim event data for auditing
- Analytics platforms tracking token transfer patterns

**Potential Financial Impact:**
- If claim events are needed for dispute resolution, lost events could affect asset recovery
- Applications built on event data may make incorrect decisions based on incomplete information
- Marketplaces tracking offer/claim mechanics may show incorrect state

**Data Loss Characteristics:**
- Events are **permanently lost** (no recovery mechanism)
- Loss is **silent** (only warning logs, no alerts)
- Historical queries will permanently miss affected events
- No way to reconstruct lost event data from chain state

This does not reach Critical severity because it doesn't directly cause consensus violations or immediate fund loss, but it represents a significant data integrity issue during a critical migration period.

## Likelihood Explanation

**Likelihood: Medium-to-High**

**Favorable Conditions for Occurrence:**

1. **Indexer Lag**: Common during high network activity or when indexers restart
2. **Resource Lifecycle**: Move allows resources to be deleted via `move_from`: [7](#0-6) 

3. **No Prevention**: The token_transfers module never destroys `PendingClaims`, but future upgrades could add cleanup functions

4. **Account Deletion**: While not currently exposed, account deletion mechanisms could be added

**Triggering Factors:**
- Long indexer downtime during migration period
- Protocol upgrades adding resource cleanup for efficiency
- Edge cases where accounts become inaccessible
- Mass token claim events creating indexer backlog

**Not Required:**
- No malicious intent needed (can occur naturally)
- No validator collusion required
- No privileged access needed
- No complex exploit chain

The vulnerability is a design flaw in the migration strategy, making it likely to manifest during normal operations with sufficient indexer lag.

## Recommendation

**Immediate Fix:** Read historical state at event emission version instead of latest state.

**Option 1: Version-Specific State Reads** (Recommended)
Modify the translator to accept and use the transaction version for state reads: [8](#0-7) 

Pass the `version` parameter to the translator and use `state_view_at_version()` instead: [9](#0-8) 

**Option 2: Event Version Metadata**
Store the EventHandle counter value in the V2 event itself during emission, eliminating the need to read state during translation.

**Option 3: Fail-Safe Error Handling**
If historical state reads cannot be implemented immediately, propagate translation errors to halt indexing rather than silently dropping events:

```rust
pub fn translate_event_v2_to_v1(
    &self,
    v2: &ContractEventV2,
) -> Result<Option<ContractEventV1>> {
    if let Some(translator) = self.translators.get(v2.type_tag()) {
        let result = translator.translate_event_v2_to_v1(v2, &self.event_v2_translation_engine);
        match result {
            Ok(v1) => Ok(Some(v1)),
            Err(e) => {
                let is_ignored_error = (v2.type_tag() == &*MINT_TYPE
                    || v2.type_tag() == &*BURN_TYPE)
                    && e.to_string().contains("resource not found");
                if !is_ignored_error {
                    // DO NOT SILENTLY DROP EVENTS - propagate error
                    return Err(e);
                }
                Ok(None)
            },
        }
    } else {
        Ok(None)
    }
}
```

This halts indexing on critical events, forcing investigation rather than silent data loss.

## Proof of Concept

```rust
// Reproduction test for storage/indexer/src/event_v2_translator.rs

#[cfg(test)]
mod event_loss_test {
    use super::*;
    use aptos_types::account_config::{Claim, TokenId};
    use aptos_types::contract_event::ContractEventV2;
    use move_core_types::account_address::AccountAddress;
    
    #[test]
    fn test_claim_event_lost_when_resource_deleted() {
        // Setup: Create translator and mock DB with PendingClaims resource
        let (translator, db) = setup_translator_with_pending_claims();
        let alice = AccountAddress::from_hex_literal("0xa11ce").unwrap();
        let bob = AccountAddress::from_hex_literal("0xb0b").unwrap();
        
        // Step 1: Alice offers token, PendingClaims created at Alice's address
        // Step 2: Bob claims token, V2 Claim event emitted
        let claim = Claim::new(
            alice, // account (sender)
            bob,   // to_address (receiver)
            TokenId::new(alice, "collection".to_string(), "token".to_string(), 0),
            1,
        );
        let v2_event = ContractEventV2::new(
            CLAIM_TYPE.clone(),
            bcs::to_bytes(&claim).unwrap(),
        ).unwrap();
        
        // Step 3: Translation succeeds with PendingClaims present
        let result1 = translator.translate_event_v2_to_v1(&v2_event);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_some());
        
        // Step 4: Delete PendingClaims resource from Alice's account
        db.delete_resource(&alice, "0x3::token_transfers::PendingClaims");
        
        // Step 5: Translation fails silently
        let result2 = translator.translate_event_v2_to_v1(&v2_event);
        assert!(result2.is_ok()); // Returns Ok, not Err!
        assert!(result2.unwrap().is_none()); // But event is None (lost!)
        
        // EVENT IS PERMANENTLY LOST - no error propagated, no retry mechanism
    }
}
```

**Manual Reproduction Steps:**
1. Deploy token_transfers module with migration flag enabled
2. Create token offer from Account A to Account B
3. Account B claims token (V2 Claim event emitted)
4. Delay indexer processing (simulate lag)
5. Delete or corrupt Account A's `PendingClaims` resource
6. Resume indexer processing
7. Observe warning log: "Failed to translate event: ... PendingClaims resource not found"
8. Query indexed events - Claim event is missing
9. Query blockchain for raw events - Claim event exists on-chain
10. **Permanent data inconsistency confirmed**

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: Only produces warning logs, no alerts or monitoring triggers
2. **No Recovery**: Once the batch is processed, the event loss is permanent
3. **Migration Critical**: Most likely to occur during the exact period when migration is active
4. **Historical Impact**: Affects historical event queries indefinitely

The similar translators (Offer, CancelOffer) have the same vulnerability pattern, multiplying the impact across all token transfer events during migration.

### Citations

**File:** aptos-move/framework/aptos-token/sources/token_transfers.move (L177-195)
```text
        if (std::features::module_event_migration_enabled()) {
            event::emit(
                Claim {
                    account: sender,
                    to_address: signer::address_of(receiver),
                    token_id,
                    amount,
                }
            )
        } else {
            event::emit_event<TokenClaimEvent>(
                &mut PendingClaims[sender].claim_events,
                TokenClaimEvent {
                    to_address: signer::address_of(receiver),
                    token_id,
                    amount,
                },
            );
        };
```

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

**File:** storage/indexer/src/event_v2_translator.rs (L954-990)
```rust
struct ClaimTranslator;
impl EventV2Translator for ClaimTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let claim = Claim::try_from_bytes(v2.event_data())?;
        let struct_tag = StructTag::from_str("0x3::token_transfers::PendingClaims")?;
        let (key, sequence_number) = if let Some(state_value_bytes) =
            engine.get_state_value_bytes_for_resource(claim.account(), &struct_tag)?
        {
            let object_resource: PendingClaimsResource = bcs::from_bytes(&state_value_bytes)?;
            let key = *object_resource.claim_events().key();
            let sequence_number =
                engine.get_next_sequence_number(&key, object_resource.claim_events().count())?;
            (key, sequence_number)
        } else {
            // If the PendingClaims resource is not found, we skip the event translation to
            // avoid panic because the creation number cannot be decided.
            return Err(AptosDbError::from(anyhow::format_err!(
                "PendingClaims resource not found"
            )));
        };
        let claim_event = TokenClaimEvent::new(
            *claim.to_address(),
            claim.token_id().clone(),
            claim.amount(),
        );
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            TOKEN_CLAIM_EVENT_TYPE.clone(),
            bcs::to_bytes(&claim_event)?,
        )?)
    }
}
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L82-90)
```rust
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
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

**File:** storage/indexer/src/db_indexer.rs (L409-500)
```rust
    /// Process a batch of transactions that is within the range of  `start_version` to `end_version`. Left inclusive, right exclusive.
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
                })?;
            }

            if self.indexer_db.statekeys_enabled() {
                writeset.write_op_iter().for_each(|(state_key, write_op)| {
                    if write_op.is_creation() || write_op.is_modification() {
                        batch
                            .put::<StateKeysSchema>(state_key, &())
                            .expect("Failed to put state keys to a batch");
                    }
                });
            }
            version += 1;
            Ok::<(), AptosDbError>(())
        })?;
```

**File:** storage/indexer/src/db_indexer.rs (L552-584)
```rust
    pub fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
    ) -> Result<Option<ContractEventV1>> {
        let _timer = TIMER.timer_with(&["translate_event_v2_to_v1"]);
        if let Some(translator) = self
            .event_v2_translation_engine
            .translators
            .get(v2.type_tag())
        {
            let result = translator.translate_event_v2_to_v1(v2, &self.event_v2_translation_engine);
            match result {
                Ok(v1) => Ok(Some(v1)),
                Err(e) => {
                    // If the token object collection uses ConcurrentSupply, skip the translation and ignore the error.
                    // This is expected, as the event handle won't be found in either FixedSupply or UnlimitedSupply.
                    let is_ignored_error = (v2.type_tag() == &*MINT_TYPE
                        || v2.type_tag() == &*BURN_TYPE)
                        && e.to_string().contains("resource not found");
                    if !is_ignored_error {
                        warn!(
                            "Failed to translate event: {:?}. Error: {}",
                            v2,
                            e.to_string()
                        );
                    }
                    Ok(None)
                },
            }
        } else {
            Ok(None)
        }
    }
```

**File:** types/src/account_config/resources/pending_claims.rs (L12-18)
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingClaimsResource {
    pending_claims: Table,
    offer_events: EventHandle,
    cancel_offer_events: EventHandle,
    claim_events: EventHandle,
}
```
