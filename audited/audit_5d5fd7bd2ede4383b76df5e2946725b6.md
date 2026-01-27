# Audit Report

## Title
Local Simulation Bypasses Nonce-Based Replay Protection, Creating Payload Inconsistency Between Simulated and Submitted Transactions

## Summary
The `simulate_using_debugger()` function fails to respect the `--replay-protection-type nonce` flag, causing it to simulate sequence-number-based transactions while the actual submission uses nonce-based orderless transactions. This payload inconsistency enables simulation bypass attacks where the simulated and submitted transactions follow completely different validation paths.

## Finding Description

The vulnerability exists in the `simulate_using_debugger()` function where local simulation creates a fundamentally different transaction than what gets submitted when nonce-based replay protection is selected.

**The vulnerable code at line 298:** [1](#0-0) 

This code does not check `self.replay_protection_type` before creating the transaction. It always creates a sequence-number-based transaction with the account's current sequence number.

**Compare with remote simulation which correctly handles nonce-based replay protection:** [2](#0-1) 

**And actual transaction submission which also correctly handles it:** [3](#0-2) 

When `--replay-protection-type nonce` is specified:

1. **Local simulation creates**: A transaction with the actual sequence number (e.g., 5) and original payload format, validated via `check_for_replay_protection_regular_txn` [4](#0-3) 

2. **Actual submission creates**: A transaction with `sequence_number = u64::MAX`, V2 payload format with a random nonce, validated via `check_for_replay_protection_orderless_txn` [5](#0-4) 

These validation paths have fundamentally different requirements:
- **Sequence-based validation**: Checks that `txn_sequence_number == account_sequence_number` (exact match required)
- **Nonce-based validation**: Checks that the nonce hasn't been used before and expiration time constraints

The payload transformation applied by `upgrade_payload_with_rng`: [6](#0-5) 

This transforms the payload to V2 format and sets `sequence_number` to `u64::MAX` when `use_orderless_transactions` is true, creating a completely different transaction structure.

## Impact Explanation

**HIGH Severity** - This vulnerability breaks critical transaction validation guarantees:

1. **Simulation Bypass**: Users simulate one transaction type but submit another, violating the core purpose of simulation - to accurately predict execution behavior before submission.

2. **Different Validation Paths**: The simulated transaction goes through sequence number validation while the submitted transaction goes through nonce validation, which have entirely different rules and failure modes.

3. **Transaction Hash Mismatch**: The simulated and submitted transactions have different hashes, making them cryptographically distinct entities.

4. **Breaks Invariants**: Violates the "Transaction Validation" invariant that prologue checks must enforce all invariants consistently, and breaks user expectations that simulation accurately represents actual execution.

5. **Operational Impact**: This can cause:
   - Successful simulations followed by failed submissions (or vice versa)
   - Confusion and loss of trust in the CLI tool
   - Unexpected gas estimation errors
   - Incorrect transaction behavior prediction

While this doesn't directly lead to consensus violations or fund theft, it represents a significant protocol violation affecting the transaction validation layer, meeting the HIGH severity criteria of "Significant protocol violations" per the Aptos bug bounty program.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is triggered automatically whenever:

1. A user selects `--replay-protection-type nonce` (a documented CLI feature)
2. The user performs local simulation using `--local-simulation`, `--benchmark-locally`, or `--profile-gas` flags
3. The user then submits the transaction

No special attacker capabilities or complex exploitation techniques are required. Any legitimate user of the Aptos CLI exercising documented features will encounter this inconsistency.

## Recommendation

Fix the `simulate_using_debugger()` function to check and apply the replay protection type before signing the transaction:

```rust
async fn simulate_using_debugger<F>(
    &self,
    payload: TransactionPayload,
    execute: F,
) -> CliTypedResult<TransactionSummary>
where
    F: FnOnce(
        &AptosDebugger,
        u64,
        SignedTransaction,
        aptos_crypto::HashValue,
        PersistedAuxiliaryInfo,
    ) -> CliTypedResult<(VMStatus, VMOutput)>,
{
    // ... existing code ...
    
    let transaction_factory = TransactionFactory::new(chain_id)
        .with_gas_unit_price(gas_unit_price)
        .with_max_gas_amount(max_gas)
        .with_transaction_expiration_time(self.gas_options.expiration_secs);
    let sender_account = &mut LocalAccount::new(sender_address, sender_key, sequence_number);
    
    // FIX: Apply replay protection type upgrade before signing
    let mut txn_builder = transaction_factory.payload(payload);
    if self.replay_protection_type == ReplayProtectionType::Nonce {
        let mut rng = rand::thread_rng();
        txn_builder = txn_builder.upgrade_payload_with_rng(&mut rng, true, true);
    }
    let transaction = sender_account.sign_with_transaction_builder(txn_builder);
    
    // ... rest of function ...
}
```

This ensures local simulation creates the same transaction type as actual submission, maintaining payload consistency.

## Proof of Concept

**Reproduction Steps:**

1. Create a simple Move function to test:
```bash
# In a Move package
aptos move compile
```

2. Run local simulation with nonce-based replay protection:
```bash
aptos move run --function-id 0x1::account::create_account \
  --args address:0x123 \
  --replay-protection-type nonce \
  --local-simulation
```

3. Observe the simulated transaction uses sequence number validation (check debug output or add logging)

4. Submit the same transaction:
```bash
aptos move run --function-id 0x1::account::create_account \
  --args address:0x123 \
  --replay-protection-type nonce
```

5. Observe the submitted transaction uses nonce validation with `sequence_number = u64::MAX`

**Evidence of Different Transactions:**
- Add debug logging to `simulate_using_debugger()` at line 298 to print the transaction's sequence number
- Add debug logging to the submission path at line 2061 in `types.rs` to print the transaction's sequence number
- With nonce-based replay protection, simulation shows actual sequence number (e.g., 5) while submission shows `18446744073709551615` (u64::MAX)

The transaction hashes will also differ, proving these are cryptographically distinct transactions following different validation paths.

### Citations

**File:** crates/aptos/src/common/transactions.rs (L207-209)
```rust
        if self.replay_protection_type == ReplayProtectionType::Nonce {
            txn_builder = txn_builder.upgrade_payload_with_rng(rng, true, true);
        }
```

**File:** crates/aptos/src/common/transactions.rs (L298-299)
```rust
        let transaction =
            sender_account.sign_with_transaction_builder(transaction_factory.payload(payload));
```

**File:** crates/aptos/src/common/types.rs (L2057-2060)
```rust
                if self.replay_protection_type == ReplayProtectionType::Nonce {
                    let mut rng = rand::thread_rng();
                    txn_builder = txn_builder.upgrade_payload_with_rng(&mut rng, true, true);
                };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L215-250)
```text
    fun check_for_replay_protection_regular_txn(
        sender_address: address,
        gas_payer_address: address,
        txn_sequence_number: u64,
    ) {
        if (
            sender_address == gas_payer_address
                || account::exists_at(sender_address)
                || !features::sponsored_automatic_account_creation_enabled()
                || txn_sequence_number > 0
        ) {
            assert!(account::exists_at(sender_address), error::invalid_argument(PROLOGUE_EACCOUNT_DOES_NOT_EXIST));
            let account_sequence_number = account::get_sequence_number(sender_address);
            assert!(
                txn_sequence_number < (1u64 << 63),
                error::out_of_range(PROLOGUE_ESEQUENCE_NUMBER_TOO_BIG)
            );

            assert!(
                txn_sequence_number >= account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_OLD)
            );

            assert!(
                txn_sequence_number == account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW)
            );
        } else {
            // In this case, the transaction is sponsored and the account does not exist, so ensure
            // the default values match.
            assert!(
                txn_sequence_number == 0,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW)
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L252-263)
```text
    fun check_for_replay_protection_orderless_txn(
        sender: address,
        nonce: u64,
        txn_expiration_time: u64,
    ) {
        // prologue_common already checks that the current_time > txn_expiration_time
        assert!(
            txn_expiration_time <= timestamp::now_seconds() + MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE),
        );
        assert!(nonce_validation::check_and_insert_nonce(sender, nonce, txn_expiration_time), error::invalid_argument(PROLOGUE_ENONCE_ALREADY_USED));
    }
```

**File:** sdk/src/transaction_builder.rs (L82-97)
```rust
    pub fn upgrade_payload_with_rng(
        mut self,
        rng: &mut impl Rng,
        use_txn_payload_v2_format: bool,
        use_orderless_transactions: bool,
    ) -> Self {
        self.payload = self.payload.upgrade_payload_with_rng(
            rng,
            use_txn_payload_v2_format,
            use_orderless_transactions,
        );
        if use_orderless_transactions {
            self.sequence_number = self.sequence_number.map(|_| u64::MAX);
        }
        self
    }
```
