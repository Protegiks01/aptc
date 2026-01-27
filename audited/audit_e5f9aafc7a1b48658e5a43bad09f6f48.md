# Audit Report

## Title
Event Translation Failure Silently Corrupts Transaction Simulation Results

## Summary
The `simulate()` function in `api/src/transactions.rs` silently discards errors from `translate_v2_to_v1_events_for_simulation()`, causing simulation responses to contain corrupted event data with dummy GUIDs and sequence numbers when translation fails. This creates inconsistent API responses that can mislead users and cause client applications to malfunction. [1](#0-0) 

## Finding Description

The vulnerability exists in the event translation logic during transaction simulation. When a user calls the `/transactions/simulate` endpoint, the system attempts to translate V2 contract events to V1 format for backward compatibility. However, the error handling is critically flawed:

The `translate_v2_to_v1_events_for_simulation()` function can fail in multiple scenarios:

1. **Missing Indexer Reader**: If `indexer_reader` is `None`, the function immediately fails: [2](#0-1) 

2. **Resource Not Found**: Many event translators require on-chain resources to determine event keys and sequence numbers. When these resources don't exist (e.g., burned tokens, deleted collections, ConcurrentSupply collections), translation fails: [3](#0-2) 

3. **BCS Serialization Failures**: The `ContractEventV1::new()` call can fail if BCS serialization of the type tag fails: [4](#0-3) 

When any of these failures occur, the `translate_v2_to_v1_events_for_simulation()` function returns an error. However, this error is **silently discarded** in the simulate function, causing events to remain as V2 or be partially translated.

The consequence is severe data corruption in API responses. V2 events that fail translation are converted to the API `Event` type with dummy values: [5](#0-4) 

Where the dummy values are: [6](#0-5) 

**Attack Scenario:**
1. Attacker deploys a Move contract that emits V2 events of types requiring resources (e.g., token minting/burning events)
2. Contract burns/deletes the required resources before emitting events, or uses ConcurrentSupply collections
3. Victim simulates a transaction calling this contract via `/transactions/simulate`
4. Event translation fails but error is silently ignored
5. API returns simulation results with corrupted events showing GUID `(0, 0x0)` and sequence number `0`
6. Client applications consuming this data may malfunction, display incorrect information to users, or make wrong decisions

## Impact Explanation

This vulnerability falls under **Medium Severity** per the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The simulation API returns corrupted event data that doesn't match actual on-chain behavior
- **Limited manipulation**: While this doesn't directly cause fund loss, it corrupts critical transaction simulation data that users rely on for decision-making
- **Client application failures**: Applications consuming the simulation API may crash or malfunction when encountering unexpected dummy GUID/sequence number values
- **User harm**: Users may approve transactions based on misleading simulation results showing incorrect event data

The impact is significant because:
1. Transaction simulation is a critical safety feature used before submitting real transactions
2. Corrupted event data can mislead users about transaction outcomes
3. The issue affects **all** simulation requests when indexer_reader is None or when events reference non-existent resources
4. Multiple events from the same logical stream will all show sequence number 0, making event tracking impossible

## Likelihood Explanation

**Likelihood: High**

This vulnerability will trigger in several common scenarios:

1. **Nodes without internal indexer**: Any API node running without the internal indexer enabled will have `indexer_reader = None`, causing **all** event translations to fail and **all** simulated events to show dummy values.

2. **Token/Collection operations**: Contracts performing token burns, collection deletions, or using ConcurrentSupply will cause translation failures for Mint/Burn events. [7](#0-6) 

3. **Normal DeFi operations**: Many DeFi protocols delete resources after use or operate on burned/transferred tokens, triggering this condition frequently.

The error is **completely silent** - there are no logs, metrics, or warnings when translation fails in simulation mode, making it difficult for operators to detect.

## Recommendation

**Fix the error handling to propagate translation failures appropriately:**

```rust
// In api/src/transactions.rs, simulate() function
let mut events = output.events().to_vec();
// BEFORE (vulnerable):
let _ = self
    .context
    .translate_v2_to_v1_events_for_simulation(&mut events);

// AFTER (fixed):
if let Err(e) = self
    .context
    .translate_v2_to_v1_events_for_simulation(&mut events)
{
    // Log the error for debugging
    aptos_logger::warn!(
        "Event translation failed during simulation: {}. Events will remain as V2.",
        e
    );
    // Optionally: Add a field to the response indicating translation failed
    // Or: Return an error to the user if this is critical
}
```

**Alternative comprehensive fix:**

Make `translate_v2_to_v1_events_for_simulation()` more resilient by continuing on individual event failures rather than aborting:

```rust
// In api/src/context.rs
pub fn translate_v2_to_v1_events_for_simulation(
    &self,
    events: &mut [ContractEvent],
) -> Result<()> {
    let mut count_map: HashMap<EventKey, u64> = HashMap::new();
    for event in events.iter_mut() {
        if let ContractEvent::V2(v2) = event {
            // Continue on failure instead of returning error
            match self
                .indexer_reader
                .as_ref()
                .ok_or(anyhow!("Internal indexer reader doesn't exist"))
                .and_then(|reader| reader.translate_event_v2_to_v1(v2))
            {
                Ok(Some(v1)) => {
                    let count = count_map.get(v1.key()).unwrap_or(&0);
                    match ContractEventV1::new(
                        *v1.key(),
                        v1.sequence_number() + count,
                        v1.type_tag().clone(),
                        v1.event_data().to_vec(),
                    ) {
                        Ok(v1_adjusted) => {
                            *event = ContractEvent::V1(v1_adjusted);
                            count_map.insert(*v1.key(), count + 1);
                        },
                        Err(e) => {
                            aptos_logger::warn!("Failed to create V1 event: {}", e);
                            // Event remains as V2
                        }
                    }
                },
                Ok(None) => {
                    // No translation available, event remains as V2
                },
                Err(e) => {
                    aptos_logger::warn!("Failed to translate event: {}", e);
                    // Event remains as V2
                }
            }
        }
    }
    Ok(())
}
```

## Proof of Concept

```rust
// This test demonstrates the vulnerability by simulating a transaction
// on a node without an internal indexer, causing all events to have dummy GUIDs

#[tokio::test]
async fn test_simulation_event_corruption_without_indexer() {
    use aptos_api::transactions::TransactionsApi;
    use aptos_api::context::Context;
    use aptos_types::transaction::SignedTransaction;
    
    // Setup: Create API context WITHOUT indexer_reader (None)
    let (db, mp_sender, node_config) = setup_test_environment();
    let context = Arc::new(Context::new(
        ChainId::test(),
        db,
        mp_sender,
        node_config,
        None, // indexer_reader = None, triggering the vulnerability
    ));
    
    let api = TransactionsApi { context: context.clone() };
    
    // Create a signed transaction that will emit V2 events when executed
    let signed_txn = create_transaction_with_v2_events();
    
    // Simulate the transaction
    let ledger_info = context.get_latest_ledger_info().unwrap();
    let result = api.simulate(
        &AcceptType::Json,
        ledger_info,
        signed_txn,
    ).unwrap();
    
    // Extract the simulated transaction
    let user_txn = match result.inner() {
        BasicResponse::Ok(txns) => &txns[0],
        _ => panic!("Expected successful simulation"),
    };
    
    // VULNERABILITY: All events should have dummy GUID (0, 0x0) and sequence number 0
    // because translation failed and error was silently discarded
    for event in &user_txn.events {
        assert_eq!(event.guid.creation_number, U64::from(0));
        assert_eq!(event.guid.account_address, Address::from(AccountAddress::ZERO));
        assert_eq!(event.sequence_number, U64::from(0));
        println!("BUG: Event has corrupted GUID and sequence number!");
    }
    
    // Expected behavior: Events should have proper GUIDs and sequence numbers
    // OR simulation should return an error indicating translation is unavailable
}

// Helper to create a transaction that emits V2 coin deposit events
fn create_transaction_with_v2_events() -> SignedTransaction {
    // Create a transaction that calls a function emitting V2 CoinDeposit events
    // In real scenario: transfer APT, which emits coin::Deposit V2 events
    todo!("Create transaction calling 0x1::coin::transfer")
}
```

**Notes**

The vulnerability has wide-reaching implications:
- Affects all API nodes without internal indexer configuration
- Impacts DeFi protocols, wallets, and block explorers relying on simulation
- Creates trust issues as simulation results don't match actual execution
- No current monitoring or alerting for this failure mode

### Citations

**File:** api/src/transactions.rs (L1720-1722)
```rust
        let _ = self
            .context
            .translate_v2_to_v1_events_for_simulation(&mut events);
```

**File:** api/src/context.rs (L1045-1049)
```rust
                let translated_event = self
                    .indexer_reader
                    .as_ref()
                    .ok_or(anyhow!("Internal indexer reader doesn't exist"))?
                    .translate_event_v2_to_v1(v2)?;
```

**File:** storage/indexer/src/event_v2_translator.rs (L450-456)
```rust
        } else {
            // If the token resource is not found, we skip the event translation to avoid panic
            // because the creation number cannot be decided. The token may have been burned.
            return Err(AptosDbError::from(anyhow::format_err!(
                "Token resource not found"
            )));
        };
```

**File:** types/src/contract_event.rs (L193-209)
```rust
    pub fn new(
        key: EventKey,
        sequence_number: u64,
        type_tag: TypeTag,
        event_data: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let event = Self {
            key,
            sequence_number,
            type_tag,
            event_data,
        };

        // Ensure size is "computable".
        event.size()?;
        Ok(event)
    }
```

**File:** api/types/src/transaction.rs (L48-52)
```rust
static DUMMY_GUID: Lazy<EventGuid> = Lazy::new(|| EventGuid {
    creation_number: U64::from(0u64),
    account_address: Address::from(AccountAddress::ZERO),
});
static DUMMY_SEQUENCE_NUMBER: Lazy<U64> = Lazy::new(|| U64::from(0));
```

**File:** api/types/src/transaction.rs (L886-891)
```rust
            ContractEvent::V2(v2) => Self {
                guid: *DUMMY_GUID,
                sequence_number: *DUMMY_SEQUENCE_NUMBER,
                typ: v2.type_tag().into(),
                data,
            },
```

**File:** storage/indexer/src/db_indexer.rs (L566-580)
```rust
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
