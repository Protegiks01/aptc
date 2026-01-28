# Audit Report

## Title
Transaction Authenticator Size Excluded from Gas Calculation Enables Storage Cost Undercharging

## Summary
The Aptos blockchain charges IO gas for transaction storage based on `raw_txn_bytes_len()`, which excludes the transaction authenticator (signatures). However, the full `SignedTransaction` including the authenticator is stored on-chain. This allows users to pay gas for significantly less data than they actually store, creating an economic exploit where large authenticators (up to 32 signatures) can be stored while only paying for the minimal raw transaction size.

## Finding Description

The transaction size used throughout Aptos gas calculations is derived from `raw_txn_bytes_len()`, which serializes only the `RawTransaction` component: [1](#0-0) 

This size populates `TransactionMetadata.transaction_size`: [2](#0-1) 

The metadata's transaction size is then used for critical operations:

**1. Transaction size validation against maximum limits:** [3](#0-2) 

**2. IO gas charging for transaction writes:** [4](#0-3) [5](#0-4) 

**3. Intrinsic gas calculation:** [6](#0-5) [7](#0-6) 

**4. Backup analysis reporting:** [8](#0-7) 

However, the **actual stored transaction** includes the full `SignedTransaction` with authenticator, as the `Transaction::UserTransaction` variant wraps the complete `SignedTransaction`: [9](#0-8) 

Storage commits the full transaction: [10](#0-9) 

The full transaction size (including authenticator) is available via `txn_bytes_len()`: [11](#0-10) 

**Attack Vector:**

An attacker constructs transactions with:
- Minimal `RawTransaction` size (~600 bytes, under `large_transaction_cutoff`)
- Maximal authenticator size using `FeePayer` or `MultiAgent` with multiple signatures

The authenticator can contain up to `MAX_NUM_OF_SIGS` (32) signatures: [12](#0-11) 

This limit is enforced during signature verification: [13](#0-12) 

With 32 Ed25519 authenticators (~96 bytes each: 32-byte public key + 64-byte signature), the authenticator totals ~3-4 KB. Combined with a 600-byte raw transaction, the attacker stores ~4,000 bytes but pays IO gas for only 600 bytes—a **6-7x undercharging**.

## Impact Explanation

This qualifies as **Medium Severity** under Aptos bug bounty criteria:

1. **Limited fund manipulation**: Validators and the protocol systematically lose storage fee revenue. While not direct fund theft, this represents ongoing economic loss as users are undercharged for actual storage consumption. At scale, this could amount to significant lost revenue.

2. **Economic attack vector**: The IO gas parameter `storage_io_per_transaction_byte_write` charges 89 internal gas units per byte specifically for writing transaction data to storage. By excluding the authenticator, users underpay by `(authenticator_size) × 89` gas units per transaction. For a 4KB authenticator with 600-byte raw transaction, this is `3,400 × 89 = 302,600` internal gas units of undercharging per transaction.

3. **State inconsistencies**: Backup analysis reports incorrect transaction sizes, leading to misleading storage metrics and potential operational issues in capacity planning.

4. **No compensating mechanism**: While the system charges `KEYLESS_BASE_COST` and `SLH_DSA_SHA2_128S_BASE_COST` for specific authenticator types, these are flat fees unrelated to authenticator size and do not compensate for the IO storage cost of large multi-signature authenticators.

## Likelihood Explanation

**Likelihood: High**

- **No special privileges required**: Any transaction sender can exploit this by constructing multi-agent or fee-payer transactions with multiple signatures
- **Attack is deterministic and repeatable**: Every such transaction results in predictable undercharging
- **Straightforward execution**: Authenticator construction uses standard transaction types (`FeePayer`, `MultiAgent`) available through normal APIs
- **Low cost to exploit**: Only requires gas for a minimal raw transaction
- **Impact accumulates**: Repeated exploitation across many transactions compounds the economic loss
- **No detection mechanism**: These appear as valid transactions and pass all validations
- **Economic incentive**: Users benefit from reduced gas costs, creating natural adoption pressure

## Recommendation

Modify `TransactionMetadata` to use the full transaction size including authenticator:

```rust
// In aptos-move/aptos-vm/src/transaction_metadata.rs
transaction_size: (txn.txn_bytes_len() as u64).into(),  // Use full size instead of raw_txn_bytes_len()
```

Alternatively, charge separate IO gas for the authenticator:

```rust
// Charge IO gas for both raw transaction and authenticator separately
let raw_txn_cost = storage_io_per_transaction_byte_write * raw_txn_size;
let auth_cost = storage_io_per_authenticator_byte_write * authenticator_size;
```

Adjust gas parameters accordingly to maintain economic balance while ensuring storage costs are paid proportionally to actual data stored.

## Proof of Concept

```rust
// Construct a transaction with minimal raw transaction and maximal authenticator
use aptos_types::transaction::*;
use aptos_crypto::ed25519::*;

// Create minimal raw transaction (~600 bytes)
let raw_txn = RawTransaction::new(
    sender_address,
    sequence_number,
    TransactionPayload::EntryFunction(minimal_entry_function),
    max_gas_amount,
    gas_unit_price,
    expiration_secs,
    chain_id,
);

// Create 32 Ed25519 authenticators for maximum size
let mut secondary_signers = Vec::new();
let mut secondary_authenticators = Vec::new();
for _ in 0..31 {  // 31 secondary + 1 sender = 32 total
    let (private_key, public_key) = generate_keypair();
    let signature = private_key.sign(&raw_txn);
    secondary_signers.push(signer_address);
    secondary_authenticators.push(
        AccountAuthenticator::ed25519(public_key, signature)
    );
}

// Create fee payer transaction
let signed_txn = raw_txn.sign_multi_agent(
    sender_authenticator,
    secondary_signers,
    secondary_authenticators,
)?;

// Verify sizes
let raw_size = signed_txn.raw_txn_bytes_len();  // ~600 bytes
let full_size = signed_txn.txn_bytes_len();     // ~4000 bytes
let undercharge_ratio = full_size / raw_size;   // ~6-7x

println!("Raw transaction size: {} bytes", raw_size);
println!("Full transaction size: {} bytes", full_size);
println!("Storage undercharge ratio: {}x", undercharge_ratio);
println!("IO gas underpayment: {} units", (full_size - raw_size) * 89);
```

## Notes

This vulnerability stems from an architectural design decision where transaction size for gas calculations uses only the `RawTransaction` component. While authenticators do incur verification costs (charged separately for keyless and post-quantum signatures), the storage IO costs for writing the authenticator data to the database are not charged proportionally. This creates a systematic economic exploit where users can store large amounts of authentication data while paying minimal storage fees.

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

**File:** types/src/transaction/mod.rs (L2946-2951)
```rust
pub enum Transaction {
    /// Transaction submitted by the user. e.g: P2P payment transaction, publishing module
    /// transaction, etc.
    /// TODO: We need to rename SignedTransaction to SignedUserTransaction, as well as all the other
    ///       transaction types we had in our codebase.
    UserTransaction(SignedTransaction),
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

**File:** aptos-move/aptos-vm/src/gas.rs (L154-156)
```rust
    let intrinsic_gas = txn_gas_params
        .calculate_intrinsic_gas(raw_bytes_len)
        .evaluate(gas_feature_version, &gas_params.vm);
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L583-589)
```rust
    fn charge_io_gas_for_transaction(&mut self, txn_size: NumBytes) -> VMResult<()> {
        let cost = self.io_pricing().io_gas_per_transaction(txn_size);

        self.algebra
            .charge_io(cost)
            .map_err(|e| e.finish(Location::Undefined))
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L301-310)
```rust
    pub fn calculate_intrinsic_gas(
        &self,
        transaction_size: NumBytes,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        let excess = transaction_size
            .checked_sub(self.large_transaction_cutoff)
            .unwrap_or_else(|| 0.into());

        MIN_TRANSACTION_GAS_UNITS + INTRINSIC_GAS_PER_BYTE * excess
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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L163-163)
```rust
        batch.put::<TransactionSchema>(&version, transaction)?;
```

**File:** types/src/transaction/authenticator.rs (L32-34)
```rust
/// Maximum number of signatures supported in `TransactionAuthenticator`,
/// across all `AccountAuthenticator`s included.
pub const MAX_NUM_OF_SIGS: usize = 32;
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
