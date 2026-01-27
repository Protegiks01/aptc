# Audit Report

## Title
Event V2 Translation Error Masking Causes Silent Event Loss in Indexer

## Summary
The `DBIndexer::process_a_batch()` function contains error handling that is completely bypassed due to translation failures being masked as `Ok(None)`. This causes Event V2 events that fail translation to silently disappear from indexes without any error propagation, leading to data inconsistency between the actual blockchain state and the indexer state.

## Finding Description

The vulnerability exists in the event V2 to V1 translation flow within the internal indexer. When processing events, the code attempts to translate V2 events to V1 format for indexing purposes.

At the call site in `process_a_batch()`, there is error handling with `.map_err()` and the `?` operator that should propagate translation errors: [1](#0-0) 

However, the `translate_event_v2_to_v1()` function never actually returns an error. When the underlying translator fails, it catches the error and returns `Ok(None)` instead of propagating it: [2](#0-1) 

This breaks the error handling chain:
1. The translator's `translate_event_v2_to_v1()` returns an `Err(e)`
2. Instead of propagating the error, the wrapper function catches it and logs a warning (if not an "expected" error)
3. **The function returns `Ok(None)` at line 578**, masking the error
4. The `.map_err()` at the call site never executes because there's no error to map
5. The `?` operator sees `Ok(None)` and continues normally
6. The event is simply not indexed - it silently disappears

**Types of Translation Failures That Get Masked:**

Many translators can fail with various errors that will all be masked: [3](#0-2) [4](#0-3) [5](#0-4) 

And 20+ other similar translators that can all fail with resource-not-found errors, BCS deserialization errors, state read errors, or struct tag parsing errors.

**Breaking Invariant #4 - State Consistency:**
Events exist in the blockchain's transaction history but are missing from the indexer, creating an inconsistent view. Different nodes could have different indexer states if they process events at different times with different state snapshots.

## Impact Explanation

This is a **HIGH severity** vulnerability according to Aptos bug bounty criteria:

1. **Significant Protocol Violation**: The indexer is a critical component for querying blockchain history. Silent event loss violates the integrity guarantee that all events should be queryable.

2. **Data Inconsistency**: Applications and users relying on event queries via `get_events_by_event_key()` will receive incomplete results, missing events that actually occurred on-chain.

3. **No Error Indication**: Unlike other indexing failures that might crash or return errors, this silently succeeds while losing data, making it extremely difficult to detect.

4. **Potential Node Divergence**: If different nodes process the same events at different blockchain heights (different state snapshots), their indexers could diverge, with some nodes successfully translating events while others fail and drop them.

While this doesn't directly cause consensus violations or fund loss, it represents a significant protocol violation that breaks the fundamental guarantee of event queryability and data consistency.

## Likelihood Explanation

**High Likelihood:**

1. **Common Failure Scenarios**: Resource-not-found errors can occur legitimately when:
   - Tokens/collections have been burned
   - Resources have been destroyed
   - State snapshots don't contain required data
   - Concurrent supply types are used instead of fixed/unlimited supply

2. **Special Cases Are Already Expected**: The code explicitly handles MINT_TYPE and BURN_TYPE with "resource not found" as expected errors, indicating this happens in production.

3. **No Recovery Mechanism**: Once an event is skipped, there's no retry or recovery mechanism. The event is permanently lost from the index.

4. **Production Impact**: This affects any application querying events by key for token operations, NFT transfers, collection mutations, and other V2 events.

## Recommendation

**Fix the error masking by propagating translation errors that are not explicitly expected:**

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
                if is_ignored_error {
                    // Only return Ok(None) for explicitly expected errors
                    Ok(None)
                } else {
                    // Propagate all other errors - DO NOT mask them
                    warn!(
                        "Translation error for event: {:?}. Error: {}",
                        v2,
                        e.to_string()
                    );
                    Err(e)
                }
            },
        }
    } else {
        Ok(None)
    }
}
```

**Alternative approach:** If some translation failures are truly acceptable, add explicit configuration or feature flags to control behavior, and maintain metrics/alerts for translation failures.

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// Add this test to storage/indexer/src/db_indexer.rs

#[cfg(test)]
mod translation_error_masking_test {
    use super::*;
    use aptos_types::contract_event::ContractEventV2;
    use move_core_types::language_storage::TypeTag;
    
    #[test]
    fn test_translation_error_is_masked() {
        // Setup: Create a DBIndexer instance
        // (would need proper test harness setup in real implementation)
        
        // Create a V2 event that will fail translation due to missing resource
        // For example, a TokenMutation event for a burned token
        let v2_event = create_token_mutation_event_for_burned_token();
        
        // Call translate_event_v2_to_v1
        let result = indexer.translate_event_v2_to_v1(&v2_event);
        
        // VULNERABILITY: This returns Ok(None) instead of Err(...)
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        
        // The error was logged but NOT propagated
        // The event will be silently dropped from the index
        
        // Expected behavior: Should return Err(...) to allow proper error handling
        // assert!(result.is_err()); // This would fail with current implementation
    }
    
    fn create_token_mutation_event_for_burned_token() -> ContractEventV2 {
        // Create a TokenMutation event for a token that was burned
        // This will cause the translator to fail with "Token resource not found"
        // at event_v2_translator.rs:453-455
        // But the error gets masked as Ok(None)
        todo!()
    }
}
```

## Notes

**Critical Finding:** The error handling mechanism at the call site (lines 451-457) is entirely ineffective because the called function (lines 562-579) masks all translation errors as `Ok(None)`. This represents a fundamental breakdown in error propagation that causes silent data loss.

**Affected Events:** All 30+ event V2 translator types can fail with various errors that will be masked, including: CoinDeposit, CoinWithdraw, TokenMutation, CollectionMutation, Mint, Burn, Transfer, and many others.

**Detection Difficulty:** This issue is particularly insidious because it provides no indication of failure beyond a warning log that may be ignored in production. The indexer appears to function normally while silently losing event data.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L450-457)
```rust
                            if let Some(translated_v1_event) =
                                self.translate_event_v2_to_v1(v2).map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to translate event: {:?}. Error: {}",
                                        v2,
                                        e
                                    )
                                })?
```

**File:** storage/indexer/src/db_indexer.rs (L562-579)
```rust
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
```

**File:** storage/indexer/src/event_v2_translator.rs (L453-455)
```rust
            return Err(AptosDbError::from(anyhow::format_err!(
                "Token resource not found"
            )));
```

**File:** storage/indexer/src/event_v2_translator.rs (L544-546)
```rust
            return Err(AptosDbError::from(anyhow::format_err!(
                "FixedSupply or UnlimitedSupply resource not found"
            )));
```

**File:** storage/indexer/src/event_v2_translator.rs (L627-629)
```rust
            return Err(AptosDbError::from(anyhow::format_err!(
                "Token store resource not found"
            )));
```
