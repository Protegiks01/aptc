# Audit Report

## Title
Event Indexing State Version Mismatch Causes Silent Event Loss in Collection Mutation Translations

## Summary
The event V2-to-V1 translation system reads blockchain state from the **latest checkpoint** instead of the transaction's version, causing valid CollectionMutation events to be silently skipped when collections are modified or deleted in later transactions. This creates permanent indexing inconsistencies where historical events are lost.

## Finding Description

To answer the security question directly: **When Collection resource is not found, other events are processed normally** - the error is caught and converted to `Ok(None)`, preventing cascade failure. [1](#0-0) 

However, this error handling masks a deeper vulnerability: the **state version mismatch** that causes legitimate events to fail translation.

The `CollectionMutationTranslator` returns an error when the Collection resource is not found. [2](#0-1) 

The root cause is that `get_state_value_bytes_for_object_group_resource()` uses `latest_state_checkpoint_view()` to read state. [3](#0-2) 

This method reads from the **latest** checkpoint version, not the transaction version being indexed. [4](#0-3) 

When the indexer processes a batch of transactions, it iterates through versions but the translator always reads the latest state. [5](#0-4) 

**Attack Scenario:**
1. Transaction at version N emits a `CollectionMutation` event for Collection X
2. Transaction at version N+100 deletes/burns Collection X  
3. Indexer processes version N (possibly hours later), but reads state from version N+100+
4. Collection X doesn't exist in latest state → translation fails with "Collection resource not found"
5. Error is converted to `Ok(None)`, event is silently skipped from indexing
6. Historical event is permanently lost from the index

This breaks the **State Consistency** invariant for the indexer - indexed events must accurately reflect the blockchain's historical state.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria - "State inconsistencies requiring intervention"

**Affected Systems:**
- API event queries return incomplete historical data
- NFT/Token tracking systems miss mutation events
- Analytics and monitoring dashboards show incorrect data
- Any application relying on complete event history is compromised

**Scope:** All CollectionMutation events (and potentially other event types) are vulnerable when resources are deleted after emission but before indexing. This affects:
- Collection description/URI/maximum updates
- Token property mutations
- Any resource-dependent event translation

**Not a Consensus Issue:** This affects the indexer only, not consensus or execution, so it does not qualify as Critical severity.

## Likelihood Explanation

**Likelihood: High**

This occurs naturally in normal operation without malicious intent:
- Collections are frequently created, modified, and burned in NFT workflows
- The indexer runs asynchronously and may lag behind the chain tip
- Any collection burned between transaction execution and indexing triggers the bug
- No special privileges or coordination required

**Trigger Frequency:** Increases with:
- Indexer lag (catch-up mode, network delays, high transaction volume)
- Collection lifecycle operations (common in NFT platforms)
- Time window between transaction execution and indexing

## Recommendation

The `EventV2TranslationEngine` must read state at the **specific version** being indexed, not the latest version.

**Fix Approach:**
1. Modify `EventV2TranslationEngine` to accept a version parameter
2. Replace `latest_state_checkpoint_view()` with `state_view_at_version(Some(version))`
3. Pass the transaction version through the translation pipeline

The codebase already provides `state_view_at_version()` for this purpose. [6](#0-5) 

**Code Changes Required:**
- Update `EventV2TranslationEngine` methods to accept `version: Version` parameter
- Update `EventV2Translator::translate_event_v2_to_v1()` trait to accept version
- Update all translator implementations to pass version to engine methods
- Update `DBIndexer::translate_event_v2_to_v1()` to accept and pass version
- Update `process_a_batch()` to pass current transaction version to translator

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_collection_mutation_indexing_race() {
    // Setup: Create a node with indexer
    let (node, indexer) = setup_test_node_with_indexer();
    
    // Step 1: Create collection and emit mutation event at version 100
    let collection_addr = create_collection(&node, "TestCollection");
    let mutation_txn = mutate_collection_description(
        &node, 
        collection_addr, 
        "Old", 
        "New"
    );
    assert_eq!(node.get_version(), 100);
    
    // Step 2: Delete collection at version 101
    burn_collection(&node, collection_addr);
    assert_eq!(node.get_version(), 101);
    
    // Step 3: Indexer processes version 100
    // It will read state from version 101 where collection doesn't exist
    indexer.process_a_batch(100, 101).unwrap();
    
    // Step 4: Verify the mutation event was NOT indexed (BUG!)
    let events = indexer.get_events_by_version(100);
    
    // Expected: 1 CollectionMutation event
    // Actual: 0 events (silently skipped)
    assert!(events.is_empty(), "Event was silently lost due to state version mismatch");
    
    // The event EXISTS in the transaction but is NOT in the index
    let txn = node.get_transaction_by_version(100);
    assert!(!txn.events.is_empty(), "Event exists in transaction");
}
```

**Notes**

This vulnerability demonstrates a systematic design flaw in the event indexing architecture where asynchronous state reads create temporal inconsistencies. The error handling correctly prevents cascade failures (answering the original question), but masks data loss that accumulates over time. Any resource-dependent event translation is vulnerable, not just CollectionMutation events. The fix requires threading version context through the entire translation pipeline to ensure point-in-time state consistency.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L448-457)
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
```

**File:** storage/indexer/src/db_indexer.rs (L563-580)
```rust
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
```

**File:** storage/indexer/src/event_v2_translator.rs (L221-224)
```rust
        let state_view = self
            .main_db_reader
            .latest_state_checkpoint_view()
            .expect("Failed to get state view");
```

**File:** storage/indexer/src/event_v2_translator.rs (L492-497)
```rust
            // If the token resource is not found, we skip the event translation to avoid panic
            // because the creation number cannot be decided.
            return Err(AptosDbError::from(anyhow::format_err!(
                "Collection resource not found"
            )));
        };
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

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L98-100)
```rust
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
```
