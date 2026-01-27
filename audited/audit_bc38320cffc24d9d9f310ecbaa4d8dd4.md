# Audit Report

## Title
Incomplete Transaction Data Stripping in Indexer GRPC Service for Non-User Transaction Types

## Summary
The `strip_transactions()` function in the indexer-grpc-data-service only strips payload, signature, and events for `TxnData::User` transactions, while failing to strip events from `BlockMetadataTransaction`, `GenesisTransaction`, and `ValidatorTransaction` types when they match the configured filter. This results in information disclosure when operators configure stripping filters that match non-User transaction types.

## Finding Description
The vulnerability exists in the `strip_transactions()` function which implements selective data removal based on transaction filters. When an operator configures a filter (via `BooleanTransactionFilter`) to strip certain transactions for privacy or bandwidth optimization, the implementation contains an incomplete type check: [1](#0-0) 

The code only handles the `TxnData::User` variant for stripping events, payload, and signature. However, the filtering system can match other transaction types that contain sensitive fields:

**BlockMetadataTransaction** contains an `events` field: [2](#0-1) 

**GenesisTransaction** contains both `payload` and `events` fields: [3](#0-2) 

**ValidatorTransaction** contains an `events` field: [4](#0-3) 

The filter system can match these transaction types through `EventFilter` and `TransactionRootFilter`: [5](#0-4) [6](#0-5) 

**Attack Path:**
1. Operator configures a stripping filter using `EventFilter` to match events in BlockMetadata transactions or `TransactionRootFilter` to match genesis transactions
2. The filter's `matches()` method returns true for these non-User transactions
3. The `strip_transactions()` function increments the stripped counter but only clears `info.changes`
4. Events from BlockMetadata/Genesis/Validator transactions and payload from Genesis transactions remain in the response
5. Downstream consumers receive unstripped data despite the configuration intent

## Impact Explanation
This is classified as **Low Severity** rather than Medium because:

1. **No Consensus Impact**: The indexer-grpc service is an auxiliary data service, not part of the core blockchain consensus, execution, or state management layers
2. **Public Data**: All blockchain transaction data (including events, genesis payload, block metadata) is inherently public and already available on-chain. The "leaked" information is not secret
3. **Limited Scope**: This affects only indexer operators who configure stripping filters, and only results in bandwidth waste or configuration intent violations, not security breaches

Per the Aptos bug bounty criteria, this falls under "Minor information leaks" (Low Severity, up to $1,000) rather than "State inconsistencies requiring intervention" (Medium Severity). The indexer service does not maintain blockchain state or affect validator operations.

## Likelihood Explanation
**Likelihood: Medium**

This will occur whenever:
1. An indexer operator configures transaction stripping filters (common for bandwidth optimization)
2. The filter uses `EventFilter` or `TransactionRootFilter` that can match non-User transactions
3. BlockMetadata transactions (occur at every block boundary) or Genesis transactions (version 0) exist in the data stream

The bug is deterministic and will consistently fail to strip the intended data.

## Recommendation
Extend the stripping logic to handle all transaction types with events and payloads:

```rust
fn strip_transactions(
    transactions: Vec<Transaction>,
    txns_to_strip_filter: &BooleanTransactionFilter,
) -> (Vec<Transaction>, usize) {
    let mut stripped_count = 0;

    let stripped_transactions: Vec<Transaction> = transactions
        .into_iter()
        .map(|mut txn| {
            if txns_to_strip_filter.matches(&txn) {
                stripped_count += 1;
                // Strip changes from TransactionInfo (applies to all transaction types)
                if let Some(info) = txn.info.as_mut() {
                    info.changes = vec![];
                }
                // Strip transaction-type-specific fields
                match txn.txn_data.as_mut() {
                    Some(TxnData::User(user_transaction)) => {
                        user_transaction.events = vec![];
                        if let Some(utr) = user_transaction.request.as_mut() {
                            utr.payload = None;
                            utr.signature = None;
                        }
                    }
                    Some(TxnData::BlockMetadata(block_metadata)) => {
                        block_metadata.events = vec![];
                    }
                    Some(TxnData::Genesis(genesis)) => {
                        genesis.events = vec![];
                        genesis.payload = None;
                    }
                    Some(TxnData::Validator(validator)) => {
                        validator.events = vec![];
                    }
                    Some(TxnData::StateCheckpoint(_)) | Some(TxnData::BlockEpilogue(_)) | None => {
                        // No events or payloads to strip
                    }
                }
            }
            txn
        })
        .collect();

    (stripped_transactions, stripped_count)
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_non_user_stripping {
    use super::*;
    use aptos_protos::transaction::v1::{
        transaction::TxnData, BlockMetadataTransaction, Event, GenesisTransaction, 
        Transaction, TransactionInfo, WriteSet, WriteSetChange,
    };
    use aptos_transaction_filter::{
        boolean_transaction_filter::APIFilter, 
        filters::{EventFilterBuilder, MoveStructTagFilterBuilder},
    };

    #[test]
    fn test_block_metadata_events_not_stripped() {
        // Create a BlockMetadata transaction with events
        let txn = Transaction {
            version: 100,
            txn_data: Some(TxnData::BlockMetadata(BlockMetadataTransaction {
                id: "block_id".to_string(),
                round: 50,
                events: vec![Event::default()], // This should be stripped
                previous_block_votes_bitvec: vec![],
                proposer: "0x1".to_string(),
                failed_proposer_indices: vec![],
            })),
            info: Some(TransactionInfo {
                changes: vec![WriteSetChange::default()],
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create an EventFilter that matches all events
        let filter = BooleanTransactionFilter::from(APIFilter::EventFilter(
            EventFilterBuilder::default()
                .struct_type(
                    MoveStructTagFilterBuilder::default()
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        ));

        let (stripped_txns, num_stripped) = strip_transactions(vec![txn], &filter);
        
        // Bug: The transaction is counted as stripped...
        assert_eq!(num_stripped, 1);
        
        // But the events are NOT actually removed!
        let stripped_txn = stripped_txns.first().unwrap();
        if let Some(TxnData::BlockMetadata(bm)) = &stripped_txn.txn_data {
            assert_eq!(bm.events.len(), 1); // Events still present - BUG!
        } else {
            panic!("Expected BlockMetadata transaction");
        }
        
        // Changes ARE stripped correctly
        assert_eq!(stripped_txn.info.as_ref().unwrap().changes.len(), 0);
    }

    #[test]
    fn test_genesis_payload_not_stripped() {
        // Create a Genesis transaction with payload and events
        let txn = Transaction {
            version: 0,
            txn_data: Some(TxnData::Genesis(GenesisTransaction {
                payload: Some(WriteSet::default()), // Should be stripped
                events: vec![Event::default()],      // Should be stripped
            })),
            info: Some(TransactionInfo {
                changes: vec![WriteSetChange::default()],
                ..Default::default()
            }),
            ..Default::default()
        };

        // Filter that matches genesis transactions
        let filter = BooleanTransactionFilter::from(APIFilter::EventFilter(
            EventFilterBuilder::default()
                .struct_type(MoveStructTagFilterBuilder::default().build().unwrap())
                .build()
                .unwrap(),
        ));

        let (stripped_txns, num_stripped) = strip_transactions(vec![txn], &filter);
        
        assert_eq!(num_stripped, 1);
        
        let stripped_txn = stripped_txns.first().unwrap();
        if let Some(TxnData::Genesis(genesis)) = &stripped_txn.txn_data {
            // BUG: Payload and events are NOT stripped
            assert!(genesis.payload.is_some()); // Still present - BUG!
            assert_eq!(genesis.events.len(), 1); // Still present - BUG!
        } else {
            panic!("Expected Genesis transaction");
        }
    }
}
```

**Notes:**
- This is an implementation bug in the indexer-grpc auxiliary service, not a core blockchain security vulnerability
- All "leaked" data is already publicly available on the blockchain
- The impact is limited to bandwidth waste and configuration intent violations
- The severity is **Low** per bug bounty criteria (minor information leak), not Medium as suggested in the security question
- This does not affect consensus, execution, state management, governance, or staking - the core security-critical components

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L935-948)
```rust
            if txns_to_strip_filter.matches(&txn) {
                stripped_count += 1;
                if let Some(info) = txn.info.as_mut() {
                    info.changes = vec![];
                }
                if let Some(TxnData::User(user_transaction)) = txn.txn_data.as_mut() {
                    user_transaction.events = vec![];
                    if let Some(utr) = user_transaction.request.as_mut() {
                        // Wipe the payload and signature.
                        utr.payload = None;
                        utr.signature = None;
                    }
                }
            }
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L124-137)
```rust
pub struct BlockMetadataTransaction {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub round: u64,
    #[prost(message, repeated, tag="3")]
    pub events: ::prost::alloc::vec::Vec<Event>,
    #[prost(bytes="vec", tag="4")]
    pub previous_block_votes_bitvec: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="5")]
    pub proposer: ::prost::alloc::string::String,
    #[prost(uint32, repeated, tag="6")]
    pub failed_proposer_indices: ::prost::alloc::vec::Vec<u32>,
}
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L140-145)
```rust
pub struct GenesisTransaction {
    #[prost(message, optional, tag="1")]
    pub payload: ::core::option::Option<WriteSet>,
    #[prost(message, repeated, tag="2")]
    pub events: ::prost::alloc::vec::Vec<Event>,
}
```

**File:** protos/rust/src/pb/aptos.transaction.v1.rs (L152-157)
```rust
pub struct ValidatorTransaction {
    #[prost(message, repeated, tag="3")]
    pub events: ::prost::alloc::vec::Vec<Event>,
    #[prost(oneof="validator_transaction::ValidatorTransactionType", tags="1, 2")]
    pub validator_transaction_type: ::core::option::Option<validator_transaction::ValidatorTransactionType>,
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L467-483)
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
                    events_filter.matches_vec(events)
                } else {
                    false
                }
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs (L59-76)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        if !self
            .success
            .matches_opt(&item.info.as_ref().map(|i| i.success))
        {
            return false;
        }

        if let Some(txn_type) = &self.txn_type {
            if txn_type
                != &TransactionType::try_from(item.r#type).expect("Invalid transaction type")
            {
                return false;
            }
        }

        true
    }
```
