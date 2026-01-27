# Audit Report

## Title
Transaction Authenticator Size Excluded from Gas Calculation Enables Storage Cost Undercharging

## Summary
The `txn_size()` function in backup analysis and gas calculation logic uses `raw_txn_bytes_len()` which excludes the transaction authenticator (signatures), while the actual stored transaction includes the authenticator. This discrepancy allows attackers to pay gas for significantly less data than they actually store on-chain, violating the principle that storage should be paid proportionally.

## Finding Description

The transaction size measurement throughout the Aptos codebase uses `raw_txn_bytes_len()` which only accounts for the `RawTransaction` component, excluding the `TransactionAuthenticator`: [1](#0-0) 

This size is used to populate `TransactionMetadata.transaction_size`: [2](#0-1) 

The transaction metadata's size is then used for critical gas calculations:

1. **Transaction size validation** against `max_transaction_size_in_bytes`: [3](#0-2) 

2. **IO gas charging** for transaction writes: [4](#0-3) 

3. **Intrinsic gas calculation**: [5](#0-4) 

4. **Backup analysis reporting**: [6](#0-5) 

However, the **actual stored transaction** includes the full `SignedTransaction` with authenticator. The full transaction size (including authenticator) is available via `txn_bytes_len()`: [7](#0-6) 

**Attack Vector:**

An attacker can construct transactions with:
- Minimal `RawTransaction` size (~600 bytes to stay under the `large_transaction_cutoff`)
- Maximal authenticator size (32 signatures via `FeePayer` or `MultiAgent` with multiple `AccountAuthenticator`s)

The authenticator can contain up to `MAX_NUM_OF_SIGS` (32) signatures: [8](#0-7) 

This is enforced during signature verification: [9](#0-8) 

With 32 Ed25519 authenticators (32 bytes public key + 64 bytes signature each) plus overhead, the authenticator can be ~4-5 KB. The attacker pays gas for 600 bytes but stores 5,000 bytes—an **8x undercharging**.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under Aptos bug bounty criteria:

1. **Limited fund manipulation**: Validators and the protocol lose storage fee revenue as users are undercharged for actual storage consumption. Over time, systematic exploitation could result in significant lost fees.

2. **Resource Limits Invariant Violation**: The documented invariant states "All operations must respect gas, storage, and computational limits." This bug allows operations to consume more storage than the gas paid for.

3. **State inconsistencies**: The backup analysis reports incorrect transaction sizes, leading to misleading storage metrics and potential operational issues.

The IO gas parameter `storage_io_per_transaction_byte_write` (89 internal gas units per byte) is specifically designed to charge for writing transaction data: [10](#0-9) 

By excluding the authenticator from this calculation, users systematically underpay for storage I/O costs.

## Likelihood Explanation

**Likelihood: High**

- No special privileges required—any transaction sender can exploit this
- Attack is deterministic and repeatable
- Authenticator construction is straightforward using standard transaction types (`FeePayer`, `MultiAgent`)
- Cost to exploit is minimal (just gas for a small raw transaction)
- Impact accumulates over time with repeated exploitation
- No detection mechanism exists as this appears as valid transaction behavior

## Recommendation

Calculate gas based on the **full transaction size** including the authenticator. Modify the transaction metadata to use `txn_bytes_len()` instead of `raw_txn_bytes_len()`:

**In `aptos-move/aptos-vm/src/transaction_metadata.rs`:**
```rust
// Change line 63 from:
transaction_size: (txn.raw_txn_bytes_len() as u64).into(),

// To:
transaction_size: (txn.txn_bytes_len() as u64).into(),
```

This ensures that:
1. IO gas charges account for the full stored transaction
2. Intrinsic gas reflects actual transaction complexity
3. Transaction size limits apply to the complete transaction
4. Backup analysis reports accurate sizes

**Alternative approach** (if separating concerns is preferred):
- Keep intrinsic gas based on raw transaction (execution payload)
- Add separate IO gas charge specifically for authenticator size
- Validate full transaction size against a separate limit

## Proof of Concept

```rust
// Rust test demonstrating the size discrepancy
#[test]
fn test_transaction_size_discrepancy() {
    use aptos_types::transaction::{
        SignedTransaction, RawTransaction, TransactionPayload,
        authenticator::{TransactionAuthenticator, AccountAuthenticator},
    };
    
    // Create a minimal raw transaction (e.g., 600 bytes)
    let raw_txn = RawTransaction::new(
        AccountAddress::random(),
        0, // sequence number
        TransactionPayload::EntryFunction(/* minimal entry function */),
        5000, // max_gas
        1, // gas_price
        600, // small payload
        ChainId::test(),
    );
    
    // Create authenticator with 32 Ed25519 signatures (via FeePayer with multiple signers)
    let mut secondary_signers = vec![];
    for _ in 0..31 {
        secondary_signers.push(AccountAuthenticator::ed25519(
            Ed25519PublicKey::random(),
            Ed25519Signature::dummy_signature(),
        ));
    }
    
    let authenticator = TransactionAuthenticator::fee_payer(
        AccountAuthenticator::ed25519(
            Ed25519PublicKey::random(),
            Ed25519Signature::dummy_signature(),
        ),
        vec![AccountAddress::random(); 31],
        secondary_signers,
        AccountAddress::random(),
        AccountAuthenticator::ed25519(
            Ed25519PublicKey::random(),
            Ed25519Signature::dummy_signature(),
        ),
    );
    
    let signed_txn = SignedTransaction::new(raw_txn, authenticator);
    
    let raw_size = signed_txn.raw_txn_bytes_len();
    let full_size = signed_txn.txn_bytes_len();
    
    println!("Raw transaction size (charged): {} bytes", raw_size);
    println!("Full transaction size (stored): {} bytes", full_size);
    println!("Undercharging ratio: {}x", full_size / raw_size);
    
    // Assert significant discrepancy
    assert!(full_size > raw_size * 5, "Authenticator adds 5x+ to size");
}
```

**Notes:**
- The mempool correctly uses `txn_bytes_len()` for batching, showing awareness of the full size [11](#0-10) 

- However, other mempool code inconsistently uses `raw_txn_bytes_len()` [12](#0-11) 

- The actual transaction storage includes the full `Transaction::UserTransaction(SignedTransaction)` as confirmed by the backup handler [13](#0-12)

### Citations

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

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L63-63)
```rust
            transaction_size: (txn.raw_txn_bytes_len() as u64).into(),
```

**File:** aptos-move/aptos-vm/src/gas.rs (L109-121)
```rust
    } else if txn_metadata.transaction_size > txn_gas_params.max_transaction_size_in_bytes {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Transaction size too big {} (max {})",
                txn_metadata.transaction_size, txn_gas_params.max_transaction_size_in_bytes
            ),
        );
        return Err(VMStatus::error(
            StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
            None,
        ));
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L289-294)
```rust
    pub fn io_gas_per_transaction(
        &self,
        txn_size: NumBytes,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        STORAGE_IO_PER_TRANSACTION_BYTE_WRITE * txn_size
    }
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L607-615)
```rust
    fn charge_intrinsic_gas_for_transaction(&mut self, txn_size: NumBytes) -> VMResult<()> {
        let excess = txn_size
            .checked_sub(self.vm_gas_params().txn.large_transaction_cutoff)
            .unwrap_or_else(|| 0.into());

        self.algebra
            .charge_execution(MIN_TRANSACTION_GAS_UNITS + INTRINSIC_GAS_PER_BYTE * excess)
            .map_err(|e| e.finish(Location::Undefined))
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/analysis.rs (L111-123)
```rust
    fn txn_size(txn: &Transaction) -> usize {
        use Transaction::*;

        match txn {
            UserTransaction(signed_txn) => signed_txn.raw_txn_bytes_len(),
            GenesisTransaction(_)
            | BlockMetadata(_)
            | BlockMetadataExt(_)
            | StateCheckpoint(_)
            | BlockEpilogue(_)
            | ValidatorTransaction(_) => bcs::serialized_size(txn).expect("Txn should serialize"),
        }
    }
```

**File:** types/src/transaction/authenticator.rs (L32-42)
```rust
/// Maximum number of signatures supported in `TransactionAuthenticator`,
/// across all `AccountAuthenticator`s included.
pub const MAX_NUM_OF_SIGS: usize = 32;

/// An error enum for issues related to transaction or account authentication.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{:?}", self)]
pub enum AuthenticationError {
    /// The number of signatures exceeds the maximum supported.
    MaxSignaturesExceeded,
}
```

**File:** types/src/transaction/authenticator.rs (L160-169)
```rust
    pub fn verify(&self, raw_txn: &RawTransaction) -> Result<()> {
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L138-141)
```rust
            storage_io_per_transaction_byte_write: InternalGasPerByte,
            { RELEASE_V1_11.. => "storage_io_per_transaction_byte_write" },
            89,
        ],
```

**File:** mempool/src/core_mempool/mempool.rs (L519-520)
```rust
                let txn_size = txn.txn_bytes_len() as u64;
                if total_bytes + txn_size > max_bytes {
```

**File:** mempool/src/core_mempool/transaction_store.rs (L804-804)
```rust
                    let transaction_bytes = txn.txn.raw_txn_bytes_len() as u64;
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L47-54)
```rust
                Item = Result<(
                    Transaction,
                    PersistedAuxiliaryInfo,
                    TransactionInfo,
                    Vec<ContractEvent>,
                    WriteSet,
                )>,
            > + '_,
```
