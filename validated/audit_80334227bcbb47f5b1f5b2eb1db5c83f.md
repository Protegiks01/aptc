# Audit Report

## Title
Transaction Authenticator Size Excluded from Gas Calculation Enables Storage Cost Undercharging

## Summary
The Aptos blockchain charges IO gas for transaction storage based on `raw_txn_bytes_len()`, which excludes the transaction authenticator (signatures). However, the full `SignedTransaction` including the authenticator is stored on-chain. This allows users to pay gas for significantly less data than they actually store, creating an economic exploit where large authenticators (up to 32 signatures) can be stored while only paying for the minimal raw transaction size.

## Finding Description

The transaction size used for gas calculations is derived from `raw_txn_bytes_len()`, which serializes only the `RawTransaction` component, explicitly excluding the authenticator. [1](#0-0) 

This raw transaction size populates `TransactionMetadata.transaction_size`, which becomes the basis for all gas-related operations. [2](#0-1) 

The metadata's transaction size is used for critical operations including:

**1. Transaction size validation against maximum limits** [3](#0-2) 

**2. IO gas charging for transaction writes** - The system charges IO gas based on this size [4](#0-3)  using the `storage_io_per_transaction_byte_write` parameter (89 gas units per byte). [5](#0-4) 

**3. Intrinsic gas calculation** [6](#0-5) 

**4. Backup analysis reporting** [7](#0-6) 

However, the **actual stored transaction** includes the full `SignedTransaction` with authenticator. The `Transaction::UserTransaction` variant wraps the complete `SignedTransaction` including its authenticator. [8](#0-7) 

Storage commits the full transaction using BCS serialization [9](#0-8)  which includes all fields of the Transaction enum. [10](#0-9) 

The full transaction size including authenticator is available via `txn_bytes_len()`, which calculates `raw_txn_bytes_len() + authenticator_size`. [11](#0-10) 

**Attack Vector:**

An attacker constructs transactions with minimal `RawTransaction` size (~600 bytes, under `large_transaction_cutoff`) but maximal authenticator size using `FeePayer` or `MultiAgent` with multiple signatures.

The authenticator can contain up to `MAX_NUM_OF_SIGS` (32) signatures. [12](#0-11) 

This limit is enforced during signature verification. [13](#0-12) 

With 32 Ed25519 authenticators (~96 bytes each: 32-byte public key + 64-byte signature), the authenticator totals ~3KB. Combined with a 600-byte raw transaction, the attacker stores ~3,600 bytes but pays IO gas for only 600 bytes—a **6x undercharging**.

## Impact Explanation

This qualifies as **Medium Severity** under Aptos bug bounty criteria for "Limited funds loss or manipulation":

1. **Economic Loss**: Validators and the protocol systematically lose storage fee revenue. The IO gas parameter `storage_io_per_transaction_byte_write` charges 89 internal gas units per byte for writing transaction data to storage. [14](#0-13)  By excluding the authenticator, users underpay by `(authenticator_size) × 89` gas units per transaction. For a 3KB authenticator with 600-byte raw transaction, this is approximately `3,000 × 89 = 267,000` internal gas units of undercharging per transaction.

2. **No Compensating Mechanism**: While the system charges flat fees for specific authenticator types (`KEYLESS_BASE_COST` at 32,000,000 gas units [15](#0-14)  and `SLH_DSA_SHA2_128S_BASE_COST` at 13,800,000 gas units [16](#0-15) ), these are flat fees unrelated to authenticator size and do NOT apply to regular Ed25519 multi-signature authenticators—the most common case.

3. **State Inconsistencies**: Backup analysis reports incorrect transaction sizes, leading to misleading storage metrics.

4. **Accumulating Impact**: Repeated exploitation across many transactions compounds the economic loss to the protocol.

## Likelihood Explanation

**Likelihood: High**

- **No special privileges required**: Any transaction sender can exploit this by constructing multi-agent or fee-payer transactions with multiple signatures
- **Attack is deterministic and repeatable**: Every such transaction results in predictable undercharging
- **Straightforward execution**: Uses standard transaction types (`FeePayer`, `MultiAgent`) available through normal APIs
- **Low cost to exploit**: Only requires gas for a minimal raw transaction
- **No detection mechanism**: These transactions appear valid and pass all validations
- **Economic incentive**: Users benefit from reduced gas costs, creating natural adoption pressure

## Recommendation

Modify the IO gas charging logic to use the full transaction size including authenticator. Change line 1120 in `aptos-move/aptos-vm/src/aptos_vm.rs` from:

```rust
gas_meter.charge_io_gas_for_transaction(txn_data.transaction_size())?;
```

To use a new method that returns the full transaction size:

```rust
gas_meter.charge_io_gas_for_transaction(txn_data.full_transaction_size())?;
```

Add a corresponding field to `TransactionMetadata` that stores the full transaction size (from `txn_bytes_len()` instead of `raw_txn_bytes_len()`), or pass the `SignedTransaction` reference to calculate the full size at the point of charging.

Additionally, update the backup analysis to report the correct full transaction size for accurate storage metrics.

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the undercharging
// Create a transaction with minimal payload
let raw_txn_size = 600; // bytes, under large_transaction_cutoff

// Add maximum signatures (32 Ed25519)
let signatures_count = 32;
let ed25519_authenticator_size = 96; // 32-byte pubkey + 64-byte signature
let total_authenticator_size = signatures_count * ed25519_authenticator_size; // ~3072 bytes

// Total stored data
let total_stored = raw_txn_size + total_authenticator_size; // ~3672 bytes

// Gas charged (at 89 gas units per byte)
let gas_charged = raw_txn_size * 89; // 53,400 gas units

// Gas that SHOULD be charged
let gas_should_charge = total_stored * 89; // ~326,808 gas units

// Undercharging
let undercharged = gas_should_charge - gas_charged; // ~273,408 gas units (~83.6% undercharged)
```

## Notes

This vulnerability exploits the systematic discrepancy between what is charged (raw transaction size) and what is stored (full transaction including authenticator). The existence of both `raw_txn_bytes_len()` and `txn_bytes_len()` methods indicates the system is aware of this distinction, but the gas charging mechanism only uses the raw size. For regular Ed25519 multi-signature transactions—the most common type—there is no compensating gas charge for the authenticator size, resulting in significant economic undercharging that accumulates across the network.

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

**File:** aptos-move/aptos-vm/src/gas.rs (L81-121)
```rust
    let raw_bytes_len = txn_metadata.transaction_size;

    if is_approved_gov_script {
        let max_txn_size_gov = if gas_feature_version >= RELEASE_V1_13 {
            gas_params.vm.txn.max_transaction_size_in_bytes_gov
        } else {
            MAXIMUM_APPROVED_TRANSACTION_SIZE_LEGACY.into()
        };

        if txn_metadata.transaction_size > max_txn_size_gov
            // Ensure that it is only the approved payload that exceeds the
            // maximum. The (unknown) user input should be restricted to the original
            // maximum transaction size.
            || txn_metadata.transaction_size
                > txn_metadata.script_size + txn_gas_params.max_transaction_size_in_bytes
        {
            speculative_warn!(
                log_context,
                format!(
                    "[VM] Governance transaction size too big {} payload size {}",
                    txn_metadata.transaction_size, txn_metadata.script_size,
                ),
            );
            return Err(VMStatus::error(
                StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
                None,
            ));
        }
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1120-1120)
```rust
        gas_meter.charge_io_gas_for_transaction(txn_data.transaction_size())?;
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

**File:** storage/backup/backup-cli/src/backup_types/transaction/analysis.rs (L115-115)
```rust
            UserTransaction(signed_txn) => signed_txn.raw_txn_bytes_len(),
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L163-163)
```rust
        batch.put::<TransactionSchema>(&version, transaction)?;
```

**File:** storage/aptosdb/src/schema/transaction/mod.rs (L38-45)
```rust
impl ValueCodec<TransactionSchema> for Transaction {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L138-141)
```rust
            storage_io_per_transaction_byte_write: InternalGasPerByte,
            { RELEASE_V1_11.. => "storage_io_per_transaction_byte_write" },
            89,
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L261-264)
```rust
            keyless_base_cost: InternalGas,
            { RELEASE_V1_12.. => "keyless.base" },
            32_000_000,
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L281-284)
```rust
            slh_dsa_sha2_128s_base_cost: InternalGas,
            { RELEASE_V1_41.. => "slh_dsa_sha2_128s.base" },
            13_800_000,
        ],
```
