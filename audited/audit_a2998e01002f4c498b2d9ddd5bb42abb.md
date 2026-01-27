# Audit Report

## Title
Indexer Panic Vector from Unreachable NoAccountSignature Assumption

## Summary
The indexer gRPC fullnode converter uses `unreachable!()` when encountering `NoAccountSignature`, assuming such transactions "can't be committed onchain". This creates a panic vector if invalid chain state exists, causing deterministic indexer service crashes without recovery mechanisms.

## Finding Description

The indexer conversion code contains two instances of `unreachable!()` for `NoAccountSignature`: [1](#0-0) [2](#0-1) 

The assumption is that `NoAccountSignature` transactions cannot be committed because transaction validation requires valid signatures: [3](#0-2) 

The validation path calls `check_signature()` which invokes the authenticator's verify method: [4](#0-3) 

For `NoAccountAuthenticator`, verification explicitly fails: [5](#0-4) 

**However**, the indexer processes **already committed** transactions from chain state. If invalid state exists through any vector (database corruption, deserialization errors, historical validation bugs, consensus disagreements during Byzantine scenarios, or protocol upgrade issues), the indexer will encounter the `NoAccountSignature` and panic.

The indexer reads transactions from storage and converts them: [6](#0-5) 

When `convert_transaction_signature()` is called on line 870, any `NoAccountSignature` triggers the panic, causing immediate service termination. Upon restart, the indexer re-encounters the same transaction and panics again, creating a crash loop.

## Impact Explanation

This qualifies as **High Severity** under "API crashes" and "Significant protocol violations" categories:

1. **Deterministic Service Unavailability**: The indexer service crashes immediately and cannot recover automatically
2. **Crash Loop**: Restarting the service causes it to re-read the same invalid transaction and crash again
3. **Infrastructure Impact**: All indexing services downstream are affected (blockchain explorers, analytics platforms, dApps relying on indexer data)
4. **No Graceful Degradation**: The service completely stops rather than skipping problematic transactions or logging errors
5. **Manual Intervention Required**: Operators must manually identify the problematic transaction and either fix the data or modify code to skip it

While this doesn't directly affect consensus or core blockchain operation, it violates defensive programming principles by trusting external data (committed chain state) without validation.

## Likelihood Explanation

**Likelihood: Low to Medium**

The likelihood depends on whether invalid state can exist on-chain:

**Low probability scenarios:**
- Database corruption from disk failures or bit flips
- Deserialization bugs when reading transactions from storage
- Historical validation bugs that allowed invalid transactions (now fixed but data remains)

**Medium probability scenarios:**
- Protocol upgrades that introduce serialization format changes
- Consensus disagreements during Byzantine scenarios (though < 1/3 validators)
- Edge cases in state synchronization from other nodes

While the core validation logic should prevent `NoAccountSignature` transactions from being committed, the indexer should not assume chain state is always valid. The use of `unreachable!()` creates a single point of failure based on this assumption.

## Recommendation

Replace `unreachable!()` with proper error handling that logs the issue and continues processing:

```rust
pub fn convert_transaction_signature(
    signature: &Option<TransactionSignature>,
) -> Option<transaction::Signature> {
    let signature = match signature {
        None => return None,
        Some(s) => s,
    };
    let r#type = match signature {
        TransactionSignature::Ed25519Signature(_) => transaction::signature::Type::Ed25519,
        TransactionSignature::MultiEd25519Signature(_) => transaction::signature::Type::MultiEd25519,
        TransactionSignature::MultiAgentSignature(_) => transaction::signature::Type::MultiAgent,
        TransactionSignature::FeePayerSignature(_) => transaction::signature::Type::FeePayer,
        TransactionSignature::SingleSender(_) => transaction::signature::Type::SingleSender,
        TransactionSignature::NoAccountSignature(_) => {
            warn!("[Indexer] Encountered NoAccountSignature in committed transaction - this should not happen. Skipping signature conversion.");
            return None;
        },
    };
    // ... rest of function
}
```

Similarly for `convert_account_signature`:

```rust
AccountSignature::NoAccountSignature(_) => {
    warn!("[Indexer] Encountered NoAccountSignature in committed transaction - this indicates invalid chain state.");
    return transaction::AccountSignature {
        r#type: transaction::account_signature::Type::Ed25519 as i32,
        signature: None,
    };
},
```

## Proof of Concept

While a direct PoC cannot be created through normal transaction submission (validation prevents it), the vulnerability can be demonstrated by simulating corrupted state:

```rust
#[test]
fn test_indexer_panic_on_no_account_signature() {
    use aptos_api_types::{TransactionSignature, AccountSignature};
    use aptos_api_types::transaction::NoAccountSignature;
    
    // Simulate a committed transaction with NoAccountSignature
    // (which should never exist but could appear through corruption)
    let no_account_sig = TransactionSignature::NoAccountSignature(NoAccountSignature);
    
    // This will panic with "No account signature can't be committed onchain"
    // demonstrating the crash vector
    let result = std::panic::catch_unwind(|| {
        convert_transaction_signature(&Some(no_account_sig))
    });
    
    assert!(result.is_err(), "Indexer should not panic on invalid state");
}
```

This demonstrates that encountering `NoAccountSignature` in committed state causes a panic rather than graceful error handling, violating the principle of defensive programming for systems that process external data.

---

**Notes:**
The core issue is not that an attacker can create such transactions (validation prevents this), but that the indexer assumes perfect chain state validity and panics rather than handling unexpected data gracefully. This is a robustness issue where auxiliary infrastructure (indexer) should be more resilient to potential data corruption or edge cases, even if they "should never happen" according to the protocol specification.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L732-736)
```rust
        AccountSignature::NoAccountSignature(_) => {
            unreachable!(
                "[Indexer Fullnode] Indexer should never see transactions with NoAccountSignature"
            )
        },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L769-771)
```rust
        TransactionSignature::NoAccountSignature(_) => {
            unreachable!("No account signature can't be committed onchain")
        },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L827-873)
```rust
pub fn convert_transaction(
    transaction: &Transaction,
    block_height: u64,
    epoch: u64,
    size_info: TransactionSizeInfo,
) -> transaction::Transaction {
    let mut timestamp: Option<timestamp::Timestamp> = None;

    let txn_type = match transaction {
        Transaction::UserTransaction(_) => transaction::transaction::TransactionType::User,
        Transaction::GenesisTransaction(_) => transaction::transaction::TransactionType::Genesis,
        Transaction::BlockMetadataTransaction(_) => {
            transaction::transaction::TransactionType::BlockMetadata
        },
        Transaction::StateCheckpointTransaction(_) => {
            transaction::transaction::TransactionType::StateCheckpoint
        },
        Transaction::BlockEpilogueTransaction(_) => {
            transaction::transaction::TransactionType::BlockEpilogue
        },
        Transaction::PendingTransaction(_) => panic!("PendingTransaction is not supported"),
        Transaction::ValidatorTransaction(_) => {
            transaction::transaction::TransactionType::Validator
        },
    };

    let txn_data = match &transaction {
        Transaction::UserTransaction(ut) => {
            timestamp = Some(convert_timestamp_usecs(ut.timestamp.0));
            let expiration_timestamp_secs = Some(convert_timestamp_secs(
                ut.request.expiration_timestamp_secs.0,
            ));
            transaction::transaction::TxnData::User(transaction::UserTransaction {
                request: Some(transaction::UserTransactionRequest {
                    sender: ut.request.sender.to_string(),
                    sequence_number: ut.request.sequence_number.0,
                    max_gas_amount: ut.request.max_gas_amount.0,
                    gas_unit_price: ut.request.gas_unit_price.0,
                    expiration_timestamp_secs,
                    payload: Some(convert_transaction_payload(
                        &ut.request.payload,
                        ut.request.replay_protection_nonce.map(|n| n.into()),
                    )),
                    signature: convert_transaction_signature(&ut.request.signature),
                }),
                events: convert_events(&ut.events),
            })
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3232-3237)
```rust
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
```

**File:** types/src/transaction/mod.rs (L1310-1313)
```rust
    pub fn check_signature(self) -> Result<SignatureCheckedTransaction> {
        self.authenticator.verify(&self.raw_txn)?;
        Ok(SignatureCheckedTransaction(self))
    }
```

**File:** types/src/transaction/authenticator.rs (L777-777)
```rust
            Self::NoAccountAuthenticator => bail!("No signature to verify."),
```
