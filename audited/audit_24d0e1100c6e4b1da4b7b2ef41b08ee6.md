# Audit Report

## Title
ValidatorTransaction Events Incorrectly Filtered Out by EventFilter in Indexer-gRPC

## Summary
The `APIFilter::matches()` function in the indexer-grpc transaction filter incorrectly returns `false` for `ValidatorTransaction` types when processing `EventFilter` queries. This causes valid events emitted during ValidatorTransaction execution (such as DKG and JWK update events) to be silently filtered out, breaking event monitoring for security-critical validator operations.

## Finding Description

In the transaction filter implementation, when an `EventFilter` is matched against transactions, the code treats three transaction types specially by returning `false`: [1](#0-0) 

The logic assumes these three transaction types do not contain events. However, this assumption is **incorrect for ValidatorTransaction**.

**Evidence that ValidatorTransaction HAS events:**

1. The protobuf schema explicitly defines an `events` field for ValidatorTransaction: [2](#0-1) 

2. Both ValidatorTransaction variants have event fields in their API representations: [3](#0-2) [4](#0-3) 

3. ValidatorTransaction provides an `events()` method to access these events: [5](#0-4) 

4. The conversion logic explicitly includes ValidatorTransaction events: [6](#0-5) 

5. Real events are emitted during ValidatorTransaction execution:
   - DKGStartEvent in DKG operations: [7](#0-6) 
   
   - ObservedJWKsUpdated in JWK operations: [8](#0-7) 

**Contrast with StateCheckpoint and BlockEpilogue:**

StateCheckpointTransaction correctly has NO events field: [9](#0-8) 

BlockEpilogueTransaction correctly has NO events field: [10](#0-9) 

Therefore, returning `false` for StateCheckpoint and BlockEpilogue is correct, but returning `false` for Validator is a bug.

## Impact Explanation

This qualifies as **Medium severity** per Aptos bug bounty criteria for the following reasons:

1. **Data Integrity Issue**: The indexer provides incomplete event data to clients, violating the expectation that all matching events will be returned.

2. **Security-Critical Events Affected**: ValidatorTransaction events include:
   - `0x1::dkg::DKGStartEvent` - Critical for randomness setup and validator coordination
   - `0x1::jwks::ObservedJWKsUpdated` - Critical for keyless account infrastructure

3. **Silent Failure Mode**: Applications monitoring these events will receive no error or indication that events are being filtered out. This could cause:
   - Delayed response to validator operations
   - Missed security-critical state changes
   - Application logic failures due to incomplete data

4. **Deterministic and Systematic**: Every indexer client using EventFilters for ValidatorTransaction events is affected.

While this does not directly affect consensus or cause fund loss (which would be Critical), it represents a **state inconsistency requiring intervention** in the indexing layer, fitting the Medium severity category.

## Likelihood Explanation

This bug will **definitely occur** whenever:
1. An indexer client creates an `EventFilter` to monitor ValidatorTransaction events (e.g., DKG or JWK update events)
2. A ValidatorTransaction matching the filter criteria is processed
3. The event is silently dropped despite matching the filter

**Likelihood: HIGH** - This is a deterministic bug affecting all indexer deployments. Any application that needs to monitor validator operations, randomness setup, or keyless account updates will experience this issue.

## Recommendation

Modify the `APIFilter::matches()` function to check ValidatorTransaction events instead of returning `false`:

```rust
APIFilter::EventFilter(events_filter) => {
    if let Some(txn_data) = &txn.txn_data {
        let events = match txn_data {
            TxnData::BlockMetadata(bm) => &bm.events,
            TxnData::Genesis(g) => &g.events,
            TxnData::StateCheckpoint(_) => return false,
            TxnData::User(u) => &u.events,
            TxnData::Validator(v) => &v.events,  // FIX: Check validator events
            TxnData::BlockEpilogue(_) => return false,
        };
        events_filter.matches_vec(events)
    } else {
        false
    }
}
```

The fix requires accessing the `events` field from the `ValidatorTransaction` protobuf message, similar to how `BlockMetadata`, `Genesis`, and `User` transactions are handled.

## Proof of Concept

To demonstrate this vulnerability:

1. Deploy an indexer-grpc instance with the current code
2. Create an EventFilter for ValidatorTransaction events:
```rust
let event_filter = EventFilterBuilder::default()
    .struct_type(
        MoveStructTagFilterBuilder::default()
            .address("0x1")
            .module("dkg")
            .name("DKGStartEvent")
            .build()?
    )
    .build()?;
```
3. Subscribe to the transaction stream with this filter
4. Trigger a DKG session (or wait for one to occur naturally during epoch transitions)
5. Observe that the DKGStartEvent is NOT delivered to the subscriber, despite being present in the ValidatorTransaction

**Expected behavior**: The event should match the filter and be delivered to subscribers.

**Actual behavior**: The event is filtered out because the function returns `false` for all ValidatorTransaction types.

This can be verified by:
- Querying the raw transaction data (which will show the events exist)
- Comparing against the filtered stream (which will be missing those events)

## Notes

This bug specifically affects the indexer-grpc filtering layer and does not impact:
- On-chain consensus or execution
- The actual emission or storage of ValidatorTransaction events
- Raw transaction data queries that don't use EventFilters

The events are correctly generated, stored, and available in the blockchain; they are simply being incorrectly filtered out by the indexer's event filtering logic.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L467-476)
```rust
            APIFilter::EventFilter(events_filter) => {
                if let Some(txn_data) = &txn.txn_data {
                    let events = match txn_data {
                        TxnData::BlockMetadata(bm) => &bm.events,
                        TxnData::Genesis(g) => &g.events,
                        TxnData::StateCheckpoint(_) => return false,
                        TxnData::User(u) => &u.events,
                        TxnData::Validator(_) => return false,
                        TxnData::BlockEpilogue(_) => return false,
                    };
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L91-143)
```text
message ValidatorTransaction {
  oneof ValidatorTransactionType {
    ObservedJwkUpdate observed_jwk_update = 1;
    DkgUpdate dkg_update = 2;
  }

  message ObservedJwkUpdate {
    message ExportedProviderJWKs {
      string issuer = 1;
      uint64 version = 2;
      message JWK {
        message RSA {
          string kid = 1;
          string kty = 2;
          string alg = 3;
          string e = 4;
          string n = 5;
        }
        message UnsupportedJWK {
          bytes id = 1;
          bytes payload = 2;
        }
        oneof JwkType {
          UnsupportedJWK unsupported_jwk = 1;
          RSA rsa = 2;
        }
      }

      repeated JWK jwks = 3;
    }
    message ExportedAggregateSignature {
      repeated uint64 signer_indices = 1;
      // HexToBytes.
      bytes sig = 2;
    }
    message QuorumCertifiedUpdate {
      ExportedProviderJWKs update = 1;
      ExportedAggregateSignature multi_sig = 2;
    }
    QuorumCertifiedUpdate quorum_certified_update = 1;
  }

  message DkgUpdate {
    message DkgTranscript {
      uint64 epoch = 1;
      string author = 2;
      bytes payload = 3;
    }
    DkgTranscript dkg_transcript = 1;
  }

  repeated Event events = 3;
}
```

**File:** api/types/src/transaction.rs (L417-422)
```rust
pub struct StateCheckpointTransaction {
    #[serde(flatten)]
    #[oai(flatten)]
    pub info: TransactionInfo,
    pub timestamp: U64,
}
```

**File:** api/types/src/transaction.rs (L434-440)
```rust
pub struct BlockEpilogueTransaction {
    #[serde(flatten)]
    #[oai(flatten)]
    pub info: TransactionInfo,
    pub timestamp: U64,
    pub block_end_info: Option<BlockEndInfo>,
}
```

**File:** api/types/src/transaction.rs (L714-719)
```rust
    pub fn events(&self) -> &[Event] {
        match self {
            ValidatorTransaction::ObservedJwkUpdate(t) => &t.events,
            ValidatorTransaction::DkgResult(t) => &t.events,
        }
    }
```

**File:** api/types/src/transaction.rs (L759-767)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct JWKUpdateTransaction {
    #[serde(flatten)]
    #[oai(flatten)]
    pub info: TransactionInfo,
    pub events: Vec<Event>,
    pub timestamp: U64,
    pub quorum_certified_update: ExportedQuorumCertifiedUpdate,
}
```

**File:** api/types/src/transaction.rs (L831-839)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct DKGResultTransaction {
    #[serde(flatten)]
    #[oai(flatten)]
    pub info: TransactionInfo,
    pub events: Vec<Event>,
    pub timestamp: U64,
    pub dkg_transcript: ExportedDKGTranscript,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L1025-1025)
```rust
        events: convert_events(api_validator_txn.events()),
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L81-84)
```text
        emit(DKGStartEvent {
            start_time_us,
            session_metadata: new_session_metadata,
        });
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L502-503)
```text
        let epoch = reconfiguration::current_epoch();
        emit(ObservedJWKsUpdated { epoch, jwks: observed_jwks.jwks });
```
