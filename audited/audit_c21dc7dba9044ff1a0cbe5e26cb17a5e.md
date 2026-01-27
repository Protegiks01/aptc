# Audit Report

## Title
Silent Event Dropping in Event V2 Translation Breaks Backward Compatibility Guarantee

## Summary
The `MoveEventV2Type` trait does NOT guarantee backward compatibility with older event indexers. Events implementing this trait but lacking registered translators in `EventV2TranslationEngine` are silently dropped when `enable_event_v2_translation` is enabled, causing critical system events (fungible asset transfers, fee statements) to be lost without any warning or error.

## Finding Description

The event translation system is designed to provide backward compatibility by translating V2 module events to V1 event handle format for older indexers. However, the implementation has a critical design flaw:

When a V2 event implements `MoveEventV2Type` but lacks a corresponding translator in `EventV2TranslationEngine`, the event is silently dropped with no error or warning logged. [1](#0-0) 

The `translate_event_v2_to_v1` method returns `Ok(None)` when no translator exists (line 582), causing the event to be skipped during indexing without any indication of failure.

Critical system events affected include:
- **Fungible Asset Events**: `WithdrawFAEvent` and `DepositFAEvent` from `fungible_asset.move`
- **Fee Statement Events**: `FeeStatement` emitted on every transaction [2](#0-1) [3](#0-2) 

These events are emitted by the framework but have no translators registered in the engine: [4](#0-3) 

The translator registration HashMap contains only legacy token/coin events, not the newer fungible asset events or fee statements.

**Exploitation Path:**
1. Operator enables `enable_event_v2_translation = true` in `InternalIndexerDBConfig` for backward compatibility
2. Framework emits fungible asset Deposit/Withdraw events during transfers
3. Framework emits FeeStatement events for every transaction  
4. Event translation attempts to find translators but fails (no translator registered)
5. Events are silently dropped via `Ok(None)` return (no warning logged)
6. Indexer database lacks these critical events
7. APIs serving from this indexer return incomplete data
8. Services relying on complete event history experience data inconsistencies

## Impact Explanation

This qualifies as **Medium Severity** under the bug bounty program category "State inconsistencies requiring intervention":

1. **Data Consistency Violation**: Different indexer configurations produce inconsistent event histories
2. **Silent Failure**: No errors or warnings are logged, making detection extremely difficult
3. **System Events Lost**: Fungible asset transfers and fee statements are fundamental blockchain operations
4. **API Data Corruption**: Services querying the indexer receive incomplete transaction histories
5. **Operational Impact**: Exchanges, wallets, and analytics tools relying on indexer data will have incorrect account states

The inconsistency breaks the fundamental indexer invariant that all emitted events should be queryable. This requires manual intervention to:
- Detect the missing events
- Rebuild the indexer database with correct configuration
- Reconcile data for affected users/services

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability triggers automatically when:
- `enable_event_v2_translation = true` (an advertised backward compatibility feature)
- Any fungible asset transfer occurs (extremely common operation)
- Any transaction executes (every block)

No attacker action required - this is a passive data loss bug affecting normal operations. The configuration option is specifically designed for backward compatibility, so operators enabling it expect complete event translation, not silent event dropping.

The fungible asset framework is actively used in the Aptos ecosystem, making this affect production deployments immediately upon enabling the translation feature.

## Recommendation

**Immediate Fix:**
1. Add translators for missing event types to `EventV2TranslationEngine::new()`:

```rust
// In storage/indexer/src/event_v2_translator.rs
// Add to the translators HashMap:
(WITHDRAW_FA_TYPE.clone(), Box::new(WithdrawFATranslator)),
(DEPOSIT_FA_TYPE.clone(), Box::new(DepositFATranslator)),
(FEE_STATEMENT_EVENT_TYPE.clone(), Box::new(FeeStatementTranslator)),
```

2. Add warning when translator not found (instead of silent drop):

```rust
// In storage/indexer/src/db_indexer.rs, replace line 581-582:
} else {
    warn!("No translator registered for event type: {:?}. Event will be dropped.", v2.type_tag());
    Ok(None)
}
```

**Long-term Fix:**
Implement compile-time checks or runtime validation to ensure every `MoveEventV2Type` implementation has a registered translator when translation is enabled. Consider using a macro or trait bound to enforce this invariant.

## Proof of Concept

```rust
// Verification test demonstrating silent event drop
#[test]
fn test_fungible_asset_event_translation_missing() {
    // Setup internal indexer with event_v2_translation enabled
    let config = InternalIndexerDBConfig {
        enable_event: true,
        enable_event_v2_translation: true,
        ..Default::default()
    };
    
    // Create a fungible asset Withdraw V2 event
    let withdraw_event = WithdrawFAEvent {
        store: AccountAddress::from_hex_literal("0x1").unwrap(),
        amount: 1000,
    };
    let v2_event = withdraw_event.create_event_v2().unwrap();
    
    // Attempt translation
    let db_indexer = create_db_indexer_with_config(config);
    let result = db_indexer.translate_event_v2_to_v1(&v2_event.v2().unwrap());
    
    // VULNERABILITY: Returns Ok(None) instead of error
    // Event is silently dropped - no warning logged
    assert!(result.unwrap().is_none());
    
    // Expected: Should return error OR translated V1 event
    // Actual: Returns None, event is lost
}
```

**Notes:**
- This is a design flaw, not an active attack vector
- Affects data availability, not blockchain consensus  
- Violates the documented purpose of the translation feature
- No compile-time guarantees that `MoveEventV2Type` implementations have translators

### Citations

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

**File:** types/src/account_config/events/fungible_asset.rs (L10-36)
```rust
/// Struct that represents a Withdraw event.
#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawFAEvent {
    pub store: AccountAddress,
    pub amount: u64,
}

impl MoveEventV2Type for WithdrawFAEvent {}

impl MoveStructType for WithdrawFAEvent {
    const MODULE_NAME: &'static IdentStr = ident_str!("fungible_asset");
    const STRUCT_NAME: &'static IdentStr = ident_str!("Withdraw");
}

/// Struct that represents a Deposit event.
#[derive(Debug, Serialize, Deserialize)]
pub struct DepositFAEvent {
    pub store: AccountAddress,
    pub amount: u64,
}

impl MoveEventV2Type for DepositFAEvent {}

impl MoveStructType for DepositFAEvent {
    const MODULE_NAME: &'static IdentStr = ident_str!("fungible_asset");
    const STRUCT_NAME: &'static IdentStr = ident_str!("Deposit");
}
```

**File:** types/src/fee_statement.rs (L103-108)
```rust
impl MoveEventV2Type for FeeStatement {}

impl MoveStructType for FeeStatement {
    const MODULE_NAME: &'static IdentStr = ident_str!("transaction_fee");
    const STRUCT_NAME: &'static IdentStr = ident_str!("FeeStatement");
}
```

**File:** storage/indexer/src/event_v2_translator.rs (L76-154)
```rust
impl EventV2TranslationEngine {
    pub fn new(main_db_reader: Arc<dyn DbReader>, internal_indexer_db: Arc<DB>) -> Self {
        let translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>> = [
            (
                COIN_DEPOSIT_TYPE.clone(),
                Box::new(CoinDepositTranslator) as Box<dyn EventV2Translator + Send + Sync>,
            ),
            (COIN_WITHDRAW_TYPE.clone(), Box::new(CoinWithdrawTranslator)),
            (COIN_REGISTER_TYPE.clone(), Box::new(CoinRegisterTranslator)),
            (KEY_ROTATION_TYPE.clone(), Box::new(KeyRotationTranslator)),
            (TRANSFER_TYPE.clone(), Box::new(TransferTranslator)),
            (
                TOKEN_MUTATION_TYPE.clone(),
                Box::new(TokenMutationTranslator),
            ),
            (
                COLLECTION_MUTATION_TYPE.clone(),
                Box::new(CollectionMutationTranslator),
            ),
            (MINT_TYPE.clone(), Box::new(MintTranslator)),
            (BURN_TYPE.clone(), Box::new(BurnTranslator)),
            (TOKEN_DEPOSIT_TYPE.clone(), Box::new(TokenDepositTranslator)),
            (
                TOKEN_WITHDRAW_TYPE.clone(),
                Box::new(TokenWithdrawTranslator),
            ),
            (BURN_TOKEN_TYPE.clone(), Box::new(BurnTokenTranslator)),
            (
                MUTATE_PROPERTY_MAP_TYPE.clone(),
                Box::new(MutatePropertyMapTranslator),
            ),
            (MINT_TOKEN_TYPE.clone(), Box::new(MintTokenTranslator)),
            (
                CREATE_COLLECTION_TYPE.clone(),
                Box::new(CreateCollectionTranslator),
            ),
            (
                TOKEN_DATA_CREATION_TYPE.clone(),
                Box::new(TokenDataCreationTranslator),
            ),
            (OFFER_TYPE.clone(), Box::new(OfferTranslator)),
            (CANCEL_OFFER_TYPE.clone(), Box::new(CancelOfferTranslator)),
            (CLAIM_TYPE.clone(), Box::new(ClaimTranslator)),
            (
                COLLECTION_DESCRIPTION_MUTATE_TYPE.clone(),
                Box::new(CollectionDescriptionMutateTranslator),
            ),
            (
                COLLECTION_URI_MUTATE_TYPE.clone(),
                Box::new(CollectionUriMutateTranslator),
            ),
            (
                COLLECTION_MAXIMUM_MUTATE_TYPE.clone(),
                Box::new(CollectionMaximumMutateTranslator),
            ),
            (URI_MUTATION_TYPE.clone(), Box::new(UriMutationTranslator)),
            (
                DEFAULT_PROPERTY_MUTATE_TYPE.clone(),
                Box::new(DefaultPropertyMutateTranslator),
            ),
            (
                DESCRIPTION_MUTATE_TYPE.clone(),
                Box::new(DescriptionMutateTranslator),
            ),
            (
                ROYALTY_MUTATE_TYPE.clone(),
                Box::new(RoyaltyMutateTranslator),
            ),
            (
                MAXIMUM_MUTATE_TYPE.clone(),
                Box::new(MaximumMutateTranslator),
            ),
            (
                OPT_IN_TRANSFER_TYPE.clone(),
                Box::new(OptInTransferTranslator),
            ),
        ]
        .into_iter()
        .collect();
```
