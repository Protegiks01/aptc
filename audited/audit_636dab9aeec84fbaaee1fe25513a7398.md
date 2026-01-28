# Audit Report

## Title
Mempool Capacity Bypass via Authenticator Size Underestimation Leading to Memory Exhaustion DoS

## Summary
The mempool's capacity enforcement mechanism contains a critical accounting flaw where transaction size calculations exclude authenticators, allowing attackers to bypass the `capacity_bytes` limit by up to 5x through transactions with large MultiEd25519 or multi-agent authenticators, causing memory exhaustion and validator node degradation.

## Finding Description

The mempool enforces memory limits by tracking `size_bytes` against a configured `capacity_bytes` limit (default 2GB). When inserting transactions, the mempool increments `size_bytes` using `get_estimated_bytes()`: [1](#0-0) 

However, `get_estimated_bytes()` only counts the raw transaction bytes plus fixed overhead, explicitly excluding the authenticator: [2](#0-1) 

The `raw_txn_bytes_len()` method returns only the BCS-serialized size of the `RawTransaction` component: [3](#0-2) 

Despite this, the mempool stores the complete `SignedTransaction` in memory, which includes both the raw transaction and a potentially large `TransactionAuthenticator`: [4](#0-3) [5](#0-4) 

The `TransactionAuthenticator` supports MultiEd25519 multisignatures with up to 32 signatures: [6](#0-5) [7](#0-6) 

With each Ed25519 signature consuming 64 bytes and each public key 32 bytes (96 bytes per signer), a fully-loaded MultiEd25519 authenticator can exceed 3KB. The capacity check uses this underestimated size: [8](#0-7) 

Critically, even the VM's transaction size validation suffers from the same flaw, using only `raw_txn_bytes_len()`: [9](#0-8) 

**Attack Vector:**
1. Attacker crafts transactions with minimal raw payloads (~200 bytes)
2. Attaches maximum-size MultiEd25519 or MultiAgent/FeePayer authenticators (~3KB)
3. Mempool estimates each transaction as ~700 bytes
4. Actual memory consumption is ~3.7KB per transaction
5. With 2GB capacity_bytes, mempool accepts ~2.86M transactions (2GB/700 bytes)
6. Actual memory consumption reaches ~10.6GB (2.86M × 3.7KB), causing 5x amplification

This breaks the Resource Limits invariant by allowing actual memory usage to exceed configured limits through systematic underestimation.

## Impact Explanation

**High Severity** - This vulnerability qualifies under the Aptos bug bounty High Severity category ($50,000 tier) through multiple impact vectors:

1. **Validator Node Slowdowns**: Memory pressure from the 5x amplification causes significant performance degradation, affecting consensus participation and block processing throughput.

2. **API Crashes**: When actual memory consumption exceeds system limits, out-of-memory conditions can crash the mempool service and API layer, disrupting transaction submission and network participation.

3. **Protocol Violation**: The vulnerability fundamentally violates the mempool's resource limit guarantees, as the `capacity_bytes` configuration becomes ineffective - nodes configured for 2GB usage can actually consume 10GB+.

The attack affects all validator and fullnode operators simultaneously, as the flaw is systematic in the protocol implementation. Unlike pure network flooding, this exploits a specific implementation bug in resource accounting to bypass intended protections.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is trivially exploitable with no special requirements:

- **Attacker Access**: Any user can submit transactions to the network through standard APIs
- **Technical Complexity**: Low - simply construct MultiEd25519 signatures with maximum signers or use multi-agent/fee-payer patterns
- **Economic Barriers**: Minimal - only requires normal transaction gas fees
- **Detection**: Difficult - large authenticators are legitimate for multi-signature wallets and cannot be distinguished from attacks
- **Infrastructure**: Multi-sig and fee-payer patterns are already common in production

The vulnerability can be triggered repeatedly with sustained transactions to maintain memory pressure, making it a practical attack vector against production networks.

## Recommendation

Modify `get_estimated_bytes()` to include the full transaction size with authenticator:

```rust
pub(crate) fn get_estimated_bytes(&self) -> usize {
    self.txn.txn_bytes_len() + TXN_FIXED_ESTIMATED_BYTES + TXN_INDEX_ESTIMATED_BYTES
}
```

Where `txn_bytes_len()` returns the complete transaction size: [10](#0-9) 

Additionally, update VM transaction size validation in `TransactionMetadata::new()` to use the full transaction size for accurate gas calculations and limits enforcement.

## Proof of Concept

```rust
// Create a transaction with minimal payload but maximum authenticator
use aptos_types::transaction::{RawTransaction, SignedTransaction, TransactionAuthenticator};
use aptos_crypto::multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature};

// Create 32 Ed25519 key pairs for maximum signature count
let private_keys: Vec<_> = (0..32).map(|_| Ed25519PrivateKey::generate_for_testing()).collect();
let public_keys: Vec<_> = private_keys.iter().map(|k| k.public_key()).collect();

// Create minimal raw transaction (~200 bytes)
let raw_txn = RawTransaction::new_script(
    sender,
    sequence_number,
    Script::new(vec![], vec![], vec![]), // Empty script
    max_gas,
    gas_price,
    expiration,
    chain_id
);

// Create MultiEd25519 with 32 signatures (~3KB authenticator)
let multi_public_key = MultiEd25519PublicKey::new(public_keys, 1).unwrap();
let signatures: Vec<_> = private_keys.iter().map(|k| k.sign(&raw_txn).unwrap()).collect();
let multi_signature = MultiEd25519Signature::new(signatures).unwrap();

let signed_txn = SignedTransaction::new_multi_ed25519(
    raw_txn,
    multi_public_key,
    multi_signature
);

// Verify size mismatch
assert!(signed_txn.raw_txn_bytes_len() < 300); // Tracked size
assert!(signed_txn.txn_bytes_len() > 3000);    // Actual size
// Submit many such transactions to exceed capacity_bytes by 5x
```

## Notes

This vulnerability represents a systematic flaw in resource accounting rather than a pure network DoS attack. The bug exploits incorrect size calculations to bypass protocol-level protections (`capacity_bytes` limits), qualifying it under the "DoS through resource exhaustion" category explicitly listed as High Severity in the Aptos bug bounty criteria. The mempool's intended 2GB limit becomes ineffective, allowing up to 10GB+ actual consumption through the 5x amplification factor.

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L354-354)
```rust
            self.size_bytes += txn.get_estimated_bytes();
```

**File:** mempool/src/core_mempool/transaction_store.rs (L458-460)
```rust
    fn is_full(&self) -> bool {
        self.system_ttl_index.size() >= self.capacity || self.size_bytes >= self.capacity_bytes
    }
```

**File:** mempool/src/core_mempool/transaction.rs (L21-22)
```rust
pub struct MempoolTransaction {
    pub txn: SignedTransaction,
```

**File:** mempool/src/core_mempool/transaction.rs (L70-72)
```rust
    pub(crate) fn get_estimated_bytes(&self) -> usize {
        self.txn.raw_txn_bytes_len() + TXN_FIXED_ESTIMATED_BYTES + TXN_INDEX_ESTIMATED_BYTES
    }
```

**File:** types/src/transaction/mod.rs (L1038-1043)
```rust
pub struct SignedTransaction {
    /// The raw transaction
    raw_txn: RawTransaction,

    /// Public key and signature to authenticate
    authenticator: TransactionAuthenticator,
```

**File:** types/src/transaction/mod.rs (L1294-1298)
```rust
    pub fn raw_txn_bytes_len(&self) -> usize {
        *self.raw_txn_size.get_or_init(|| {
            bcs::serialized_size(&self.raw_txn).expect("Unable to serialize RawTransaction")
        })
    }
```

**File:** types/src/transaction/mod.rs (L1300-1306)
```rust
    pub fn txn_bytes_len(&self) -> usize {
        let authenticator_size = *self.authenticator_size.get_or_init(|| {
            bcs::serialized_size(&self.authenticator)
                .expect("Unable to serialize TransactionAuthenticator")
        });
        self.raw_txn_bytes_len() + authenticator_size
    }
```

**File:** types/src/transaction/authenticator.rs (L32-34)
```rust
/// Maximum number of signatures supported in `TransactionAuthenticator`,
/// across all `AccountAuthenticator`s included.
pub const MAX_NUM_OF_SIGS: usize = 32;
```

**File:** types/src/transaction/authenticator.rs (L73-102)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Single Ed25519 signature
    Ed25519 {
        public_key: Ed25519PublicKey,
        signature: Ed25519Signature,
    },
    /// K-of-N multisignature
    MultiEd25519 {
        public_key: MultiEd25519PublicKey,
        signature: MultiEd25519Signature,
    },
    /// Multi-agent transaction.
    MultiAgent {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    },
    /// Optional Multi-agent transaction with a fee payer.
    FeePayer {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    },
    SingleSender {
        sender: AccountAuthenticator,
    },
}
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L63-63)
```rust
            transaction_size: (txn.raw_txn_bytes_len() as u64).into(),
```
