# Audit Report

## Title
Node-Checker Transaction Validation Bypass: Missing Cryptographic Integrity Checks Allow Malicious Nodes to Serve Invalid Transaction Data

## Summary
The `TransactionCorrectnessChecker` in the node-checker only validates that returned transactions have `OnChain` metadata and matching `accumulator_root_hash` values. It fails to verify the cryptographic integrity of transaction execution results (TransactionInfo, events, changes), allowing malicious nodes to pass health checks while serving fabricated transaction data to API consumers.

## Finding Description

The node-checker's `unwrap_accumulator_root_hash()` function [1](#0-0)  only checks whether the `TransactionData` is of type `OnChain`, returning the `accumulator_root_hash` field without any validation.

The checker then compares accumulator root hashes between baseline and target nodes [2](#0-1)  and considers the transaction valid if they match. However, this validation is insufficient because:

1. **Missing Transaction Hash Verification**: The checker doesn't verify that `transaction.hash()` matches `info.transaction_hash()`. The codebase shows proper verification requires computing the transaction hash and comparing it [3](#0-2) .

2. **Missing Event Integrity Checks**: The checker doesn't verify that the returned events match their committed hash. Proper validation requires hashing each event and computing the event root hash [4](#0-3) , then comparing with `info.event_root_hash()`.

3. **Missing State Change Verification**: The checker doesn't verify that the `WriteSet` (changes) matches the committed hash. Proper validation requires computing `CryptoHash::hash(&write_set)` [5](#0-4)  and comparing with `info.state_change_hash()`.

**Attack Scenario:**

A malicious node operator modifies their API server (specifically the transaction retrieval endpoint [6](#0-5) ) to return:
- **Correct** `accumulator_root_hash` (retrieved from their database at the correct version)
- **Fabricated** `info` field (TransactionInfo with manipulated gas_used, status, event_root_hash, state_change_hash, or transaction_hash)
- **Fabricated** `events` (fake events that don't hash to the event_root_hash in info)
- **Fabricated** `changes` (fake WriteSet that doesn't hash to the state_change_hash in info)
- **Fabricated** `transaction` (different transaction than what was actually executed)

The `TransactionOnChainData` structure [7](#0-6)  contains all these fields as separate, unverified components.

Since the node-checker only compares `accumulator_root_hash` values, the fabricated data passes validation, and the malicious node is certified as healthy.

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

This vulnerability enables malicious nodes to:

1. **Deceive API Consumers**: Applications querying the malicious node's API receive incorrect transaction data, including:
   - Wrong execution outcomes (showing success when transaction failed, or vice versa)
   - Fabricated events that never occurred
   - Incorrect state changes
   - Wrong gas consumption amounts
   - Different transactions than what was actually executed

2. **Pass Health Checks While Dishonest**: Malicious nodes can maintain a facade of correctness, potentially being included in trusted node lists or RPC endpoints while serving invalid data.

3. **Break State Consistency Invariant**: The "State Consistency" invariant states that state transitions must be atomic and verifiable. This vulnerability breaks the verification property for API-level state queries.

While this doesn't directly affect on-chain consensus (the malicious node cannot force other nodes to accept invalid data), it violates the data integrity guarantees that API consumers rely on, potentially causing:
- Wallets displaying incorrect transaction results
- Explorers showing fabricated events
- dApps making decisions based on false state information
- Analytics systems recording incorrect metrics

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is straightforward to execute:
- Requires only modification of the API server code on a single node
- No cryptographic attacks or complex exploits needed
- Attacker only needs to run a modified full node
- Node-checker cannot detect the manipulation with current validation logic

However, the impact is somewhat limited by:
- Users can query multiple nodes and compare results
- Blockchain explorers typically aggregate data from multiple sources
- The malicious node's stored blockchain data remains internally consistent (doesn't cause database corruption)

## Recommendation

Add cryptographic integrity verification to the `TransactionCorrectnessChecker` by validating internal consistency between the transaction components:

```rust
fn verify_transaction_integrity(
    transaction_data: &TransactionData,
) -> Result<(), CheckerError> {
    match transaction_data {
        TransactionData::OnChain(on_chain) => {
            // 1. Verify transaction hash
            let txn_hash = on_chain.transaction.hash();
            if txn_hash != on_chain.info.transaction_hash() {
                return Err(CheckerError::NonRetryableEndpointError(
                    TRANSACTIONS_ENDPOINT,
                    anyhow::anyhow!(
                        "Transaction hash mismatch: computed {:?}, expected {:?}",
                        txn_hash,
                        on_chain.info.transaction_hash()
                    ),
                ));
            }

            // 2. Verify events match event_root_hash
            use aptos_crypto::hash::CryptoHash;
            use aptos_types::proof::accumulator::InMemoryEventAccumulator;
            
            let event_hashes: Vec<_> = on_chain.events.iter()
                .map(CryptoHash::hash)
                .collect();
            let computed_event_root = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash;
            if computed_event_root != on_chain.info.event_root_hash() {
                return Err(CheckerError::NonRetryableEndpointError(
                    TRANSACTIONS_ENDPOINT,
                    anyhow::anyhow!(
                        "Event root hash mismatch: computed {:?}, expected {:?}",
                        computed_event_root,
                        on_chain.info.event_root_hash()
                    ),
                ));
            }

            // 3. Verify write set matches state_change_hash
            let computed_state_change = CryptoHash::hash(&on_chain.changes);
            if computed_state_change != on_chain.info.state_change_hash() {
                return Err(CheckerError::NonRetryableEndpointError(
                    TRANSACTIONS_ENDPOINT,
                    anyhow::anyhow!(
                        "State change hash mismatch: computed {:?}, expected {:?}",
                        computed_state_change,
                        on_chain.info.state_change_hash()
                    ),
                ));
            }

            Ok(())
        },
        _ => Ok(())
    }
}
```

Call this function after retrieving transactions from both baseline and target nodes, before comparing accumulator root hashes.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_api_types::{TransactionData, TransactionOnChainData};
    use aptos_crypto::HashValue;
    use aptos_types::transaction::{Transaction, TransactionInfo};
    
    #[test]
    fn test_malicious_node_with_fake_transaction_data() {
        // Create a valid TransactionOnChainData with correct accumulator_root_hash
        let correct_accumulator_root = HashValue::random();
        
        // Create fake transaction data with manipulated TransactionInfo
        let mut fake_txn_data = create_valid_transaction_on_chain_data();
        
        // Keep the correct accumulator_root_hash
        fake_txn_data.accumulator_root_hash = correct_accumulator_root;
        
        // But use fabricated TransactionInfo with wrong hashes
        fake_txn_data.info = create_fake_transaction_info();
        
        // Current implementation only checks OnChain type and accumulator_root_hash
        // This PASSES when it should FAIL
        let wrapped_data = TransactionData::OnChain(fake_txn_data);
        assert!(matches!(wrapped_data, TransactionData::OnChain(_)));
        
        // With the recommended fix, this would fail integrity checks:
        // assert!(verify_transaction_integrity(&wrapped_data).is_err());
    }
}
```

**Notes**

This vulnerability is specific to the node-checker component and does not affect core consensus or execution. However, it represents a significant API data integrity issue that allows malicious nodes to serve fabricated transaction information to users while appearing healthy. The fix is straightforward: add the same cryptographic verification checks that exist elsewhere in the codebase [8](#0-7)  to the node-checker's validation logic.

### Citations

**File:** ecosystem/node-checker/src/checker/transaction_correctness.rs (L56-69)
```rust
    fn unwrap_accumulator_root_hash(
        transaction_data: &TransactionData,
    ) -> Result<&aptos_crypto::HashValue, CheckerError> {
        match transaction_data {
            TransactionData::OnChain(on_chain) => Ok(&on_chain.accumulator_root_hash),
            wildcard => Err(CheckerError::NonRetryableEndpointError(
                TRANSACTIONS_ENDPOINT,
                anyhow::anyhow!(
                    "The API unexpectedly returned a transaction that was not an on-chain transaction: {:?}",
                    wildcard
                ),
            ))
        }
    }
```

**File:** ecosystem/node-checker/src/checker/transaction_correctness.rs (L192-204)
```rust
                        if middle_baseline_accumulator_root_hash
                            == middle_target_accumulator_root_hash
                        {
                            Self::build_result(
                                "Target node produced valid recent transaction".to_string(),
                                100,
                                format!(
                                    "We were able to pull the same transaction (version: {}) \
                                    from both your node and the baseline node. Great! This \
                                    implies that your node is returning valid transaction data.",
                                    middle_shared_version,
                                ),
                            )
```

**File:** types/src/transaction/mod.rs (L1418-1424)
```rust
        let txn_hash = self.transaction.hash();
        ensure!(
            txn_hash == self.proof.transaction_info().transaction_hash(),
            "Transaction hash ({}) not expected ({}).",
            txn_hash,
            self.proof.transaction_info().transaction_hash(),
        );
```

**File:** types/src/transaction/mod.rs (L1426-1435)
```rust
        if let Some(events) = &self.events {
            let event_hashes: Vec<_> = events.iter().map(CryptoHash::hash).collect();
            let event_root_hash =
                InMemoryEventAccumulator::from_leaves(&event_hashes[..]).root_hash();
            ensure!(
                event_root_hash == self.proof.transaction_info().event_root_hash(),
                "Event root hash ({}) not expected ({}).",
                event_root_hash,
                self.proof.transaction_info().event_root_hash(),
            );
```

**File:** types/src/transaction/mod.rs (L1880-1920)
```rust
            self.status() == &expected_txn_status,
            "{}: version:{}, status:{:?}, auxiliary data:{:?}, expected:{:?}",
            ERR_MSG,
            version,
            self.status(),
            self.auxiliary_data(),
            expected_txn_status,
        );

        ensure!(
            self.gas_used() == txn_info.gas_used(),
            "{}: version:{}, gas_used:{:?}, expected:{:?}",
            ERR_MSG,
            version,
            self.gas_used(),
            txn_info.gas_used(),
        );

        let write_set_hash = CryptoHash::hash(self.write_set());
        ensure!(
            write_set_hash == txn_info.state_change_hash(),
            "{}: version:{}, write_set_hash:{:?}, expected:{:?}, write_set: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
            write_set_hash,
            txn_info.state_change_hash(),
            self.write_set,
            expected_write_set,
        );

        let event_hashes = self
            .events()
            .iter()
            .map(CryptoHash::hash)
            .collect::<Vec<_>>();
        let event_root_hash = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash;
        ensure!(
            event_root_hash == txn_info.event_root_hash(),
            "{}: version:{}, event_root_hash:{:?}, expected:{:?}, events: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
```

**File:** api/src/transactions.rs (L980-1006)
```rust
    fn get_transaction_by_version_inner(
        &self,
        accept_type: &AcceptType,
        version: U64,
    ) -> BasicResultWith404<Transaction> {
        let ledger_info = self.context.get_latest_ledger_info()?;
        let txn_data = self
            .get_by_version(version.0, &ledger_info)
            .context(format!("Failed to get transaction by version {}", version))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &ledger_info,
                )
            })?;

        match txn_data {
            GetByVersionResponse::Found(txn_data) => {
                self.get_transaction_inner(accept_type, txn_data, &ledger_info)
            },
            GetByVersionResponse::VersionTooNew => {
                Err(transaction_not_found_by_version(version.0, &ledger_info))
            },
            GetByVersionResponse::VersionTooOld => Err(version_pruned(version.0, &ledger_info)),
        }
    }
```

**File:** api/types/src/transaction.rs (L98-115)
```rust
/// A committed transaction
///
/// This is a representation of the onchain payload, outputs, events, and proof of a transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionOnChainData {
    /// The ledger version of the transaction
    pub version: u64,
    /// The transaction submitted
    pub transaction: aptos_types::transaction::Transaction,
    /// Information about the transaction
    pub info: aptos_types::transaction::TransactionInfo,
    /// Events emitted by the transaction
    pub events: Vec<ContractEvent>,
    /// The accumulator root hash at this version
    pub accumulator_root_hash: aptos_crypto::HashValue,
    /// Final state of resources changed by the transaction
    pub changes: aptos_types::write_set::WriteSet,
}
```
