# Audit Report

## Title
FeePayer Transaction Filter Performance Degradation via Oversized MultiKey Authenticators

## Summary
FeePayer transactions with secondary signers containing MultiKey authenticators can bypass constructor validation during BCS deserialization, allowing public key counts exceeding the MAX_NUM_OF_SIGS limit. When PublicKey transaction filters are configured, this causes O(N*M) iteration overhead during filtering, where N is the number of secondary signers and M is the number of public keys per authenticator. The excessive iteration occurs before transaction validation rejects the malformed authenticators.

## Finding Description
The vulnerability exists in the transaction filtering pipeline within the mempool's transaction processing flow. The attack exploits a discrepancy between BCS deserialization behavior and constructor validation: [1](#0-0) 

The `MultiKey` struct uses derived `Deserialize`, which directly populates the `public_keys` vector without invoking the `new()` constructor that enforces the 32-key limit: [2](#0-1) 

This allows an attacker to craft BCS-serialized transactions containing MultiKey authenticators with hundreds of public keys, bypassing the validation that would normally occur in the constructor.

The filtering process occurs in the mempool before transaction validation: [3](#0-2) 

When a PublicKey filter is configured, the filter invokes `matches_transaction_authenticator_public_key()`: [4](#0-3) 

For each secondary signer with a MultiKey authenticator, the code iterates through all public keys: [5](#0-4) 

Only after filtering completes does the transaction validation check the signature count limit: [6](#0-5) 

**Attack Flow:**
1. Attacker crafts FeePayer transactions with 10-20 secondary signers
2. Each secondary signer contains a MultiKey with 50-100 public keys (bypassing the 32 limit via BCS deserialization)
3. Transaction size remains under the 64KB limit
4. Transaction is accepted by the network and enters mempool processing
5. If a PublicKey filter is configured, filtering iterates 500-2000+ times per transaction
6. Transaction is eventually rejected during VM validation with MaxSignaturesExceeded
7. The expensive filtering work has already been performed

## Impact Explanation
This qualifies as **Low Severity** per the Aptos bug bounty criteria ("Non-critical implementation bugs"). The attack causes CPU resource consumption during transaction filtering but does not lead to:
- Consensus safety violations
- Fund loss or theft  
- Network availability loss
- State corruption

The impact is limited by:
- Public key comparison operations being computationally inexpensive (nanoseconds per comparison)
- Filtering only occurring when PublicKey filters are explicitly configured
- Malformed transactions being rejected before entering the mempool
- Transaction size limits constraining total key count to hundreds rather than thousands

However, at scale with sustained flooding, this could contribute to mempool processing delays when filters are active.

## Likelihood Explanation
**Likelihood: Low to Medium**

Attack requirements:
- PublicKey filter must be configured in the mempool (not always deployed)
- Attacker must sustain high transaction submission rate
- Each malformed transaction costs network bandwidth (limiting practical attack volume)

The attack is straightforward to execute (crafting BCS payloads), but practical impact requires specific node configurations and sustained resource commitment from the attacker.

## Recommendation
Implement custom BCS deserialization for `MultiKey` and `MultiKeyAuthenticator` that enforces validation constraints during deserialization, preventing malformed authenticators from being created in the first place.

Add validation in the deserialization path:

```rust
impl<'de> Deserialize<'de> for MultiKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct MultiKeyRaw {
            public_keys: Vec<AnyPublicKey>,
            signatures_required: u8,
        }
        
        let raw = MultiKeyRaw::deserialize(deserializer)?;
        MultiKey::new(raw.public_keys, raw.signatures_required)
            .map_err(serde::de::Error::custom)
    }
}
```

Alternatively, add an early validation check before filtering that rejects transactions with invalid authenticator structures.

## Proof of Concept

```rust
use aptos_types::transaction::{
    authenticator::{AccountAuthenticator, AnyPublicKey, MultiKey, MultiKeyAuthenticator, TransactionAuthenticator},
    SignedTransaction, RawTransaction, TransactionPayload, Script,
};
use aptos_crypto::ed25519::Ed25519PrivateKey;
use bcs;

// Create a MultiKey with MORE than 32 keys by directly constructing the struct
// bypassing the new() constructor validation
fn create_oversized_multikey() -> Vec<u8> {
    let mut public_keys = Vec::new();
    for _ in 0..100 {  // Create 100 keys, far exceeding the 32 limit
        let private_key = Ed25519PrivateKey::generate_for_testing();
        public_keys.push(AnyPublicKey::ed25519(private_key.public_key()));
    }
    
    // Directly serialize the struct fields without going through new()
    #[derive(serde::Serialize)]
    struct MultiKeyRaw {
        public_keys: Vec<AnyPublicKey>,
        signatures_required: u8,
    }
    
    let raw = MultiKeyRaw {
        public_keys,
        signatures_required: 50,
    };
    
    bcs::to_bytes(&raw).unwrap()
}

// When this is deserialized, it will bypass the constructor validation
// and create a MultiKey with 100 keys, which will cause O(100) iterations
// during filtering but only be rejected later during verify()
```

## Notes
This vulnerability confirms the security question's premise that FeePayer transactions with excessive secondary signers can cause filtering performance degradation. The root cause is the lack of validation during BCS deserialization, allowing malformed authenticators that violate the MAX_NUM_OF_SIGS invariant to persist through the filtering stage before being rejected during transaction verification.

### Citations

**File:** types/src/transaction/authenticator.rs (L161-169)
```rust
        let num_sigs: usize = self.sender().number_of_signatures()
            + self
                .secondary_signers()
                .iter()
                .map(|auth| auth.number_of_signatures())
                .sum::<usize>();
        if num_sigs > MAX_NUM_OF_SIGS {
            return Err(Error::new(AuthenticationError::MaxSignaturesExceeded));
        }
```

**File:** types/src/transaction/authenticator.rs (L1132-1136)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MultiKey {
    public_keys: Vec<AnyPublicKey>,
    signatures_required: u8,
}
```

**File:** types/src/transaction/authenticator.rs (L1154-1164)
```rust
    pub fn new(public_keys: Vec<AnyPublicKey>, signatures_required: u8) -> Result<Self> {
        ensure!(
            signatures_required > 0,
            "The number of required signatures is 0."
        );

        ensure!(
            public_keys.len() <= MAX_NUM_OF_SIGS, // This max number of signatures is also the max number of public keys.
            "The number of public keys is greater than {}.",
            MAX_NUM_OF_SIGS
        );
```

**File:** mempool/src/shared_mempool/tasks.rs (L318-326)
```rust
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);

    // If there are no transactions left after filtering, return early
    if transactions.is_empty() {
        return statuses;
    }
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L303-308)
```rust
        AccountAuthenticator::MultiKey { authenticator } => authenticator
            .public_keys()
            .public_keys()
            .iter()
            .any(|key| key == any_public_key),
    }
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L558-569)
```rust
        TransactionAuthenticator::FeePayer {
            sender,
            secondary_signers,
            fee_payer_signer,
            ..
        } => {
            matches_account_authenticator_public_key(sender, any_public_key)
                || secondary_signers
                    .iter()
                    .any(|signer| matches_account_authenticator_public_key(signer, any_public_key))
                || matches_account_authenticator_public_key(fee_payer_signer, any_public_key)
        },
```
