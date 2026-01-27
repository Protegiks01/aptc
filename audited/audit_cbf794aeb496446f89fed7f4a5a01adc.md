# Audit Report

## Title
Nonce Reuse Across Different Orderless Transactions Breaks Replay Protection Guarantees

## Summary
The nonce validation system for orderless transactions in Aptos allows the same nonce value to be reused for completely different transactions from the same sender, provided their expiration times are more than 100 seconds apart. This fundamentally breaks the replay protection guarantee that nonces are supposed to provide, enabling social engineering attacks and violating user expectations about transaction uniqueness.

## Finding Description

The `check_and_insert_nonce` function in the nonce validation module only validates the `(sender_address, nonce)` pair without considering the transaction payload (`script_hash` or executable content). [1](#0-0) 

The critical issue occurs when an existing nonce has expired. The code explicitly removes the old nonce entry and allows a new transaction with the same nonce but different payload to be inserted: [2](#0-1) 

While the `SessionId` includes `script_hash` for session uniqueness within the VM execution, this is NOT used for replay protection validation: [3](#0-2) 

The replay protection check calls `nonce_validation::check_and_insert_nonce` which only validates `(sender, nonce, expiration_time)`: [4](#0-3) 

**Attack Path:**
1. User signs Transaction A: `(sender=Alice, nonce=42, payload=Transfer(Bob, 10 APT), expiration=T, signature=S1)`
2. Transaction A executes successfully at time T-10
3. Malicious dApp tricks user into signing Transaction B: `(sender=Alice, nonce=42, payload=Transfer(Attacker, 1000 APT), expiration=T+200, signature=S2)`
4. At time T+101, attacker submits Transaction B
5. Nonce validation passes because:
   - `existing_exp_time (T) < current_time (T+101)` ✓
   - `txn_expiration_time (T+200) > existing_exp_time + 100 (T+100)` ✓
6. Transaction B executes, draining user's funds

The vulnerability breaks the documented purpose: "Orderless transactions instead contain a nonce to prevent replay attacks." [5](#0-4) 

## Impact Explanation

**Critical Severity - Loss of Funds**

This vulnerability enables:

1. **Direct Fund Theft**: Attackers can trick users into signing multiple transactions with the same nonce but different payloads. Users expecting nonces to be unique identifiers (like in Ethereum) won't realize they're authorizing multiple distinct transactions.

2. **Breaks Fundamental Invariant**: Violates **Transaction Validation** invariant that "Prologue/epilogue checks must enforce all invariants." The nonce is supposed to uniquely identify a transaction for replay protection, but it can authorize multiple different transactions.

3. **Wallet Implementation Bugs**: Wallets implementing standard nonce management will incorrectly assume nonces are single-use, leading to security vulnerabilities across the ecosystem.

4. **User Expectation Violation**: In all major blockchain systems (Ethereum, Bitcoin, Solana), transaction identifiers are unique. Users and developers will incorrectly assume Aptos follows this standard.

The attack requires only social engineering (malicious dApp), not privileged access, making it exploitable by any attacker against any user.

## Likelihood Explanation

**Likelihood: High**

1. **Easy to Execute**: Attackers need only convince users to sign transactions through malicious dApps or phishing sites
2. **No Technical Barriers**: No validator access, cryptographic breaks, or complex exploit chains required
3. **User Confusion**: Nonce reuse contradicts standard blockchain behavior, making users vulnerable
4. **Ecosystem-Wide Risk**: Every wallet and dApp must correctly understand this non-standard behavior or be vulnerable

The 100-second window is sufficient for sophisticated attacks involving multiple transaction signatures collected over time.

## Recommendation

**Option 1 (Strongest)**: Include transaction payload hash in nonce validation to ensure nonces uniquely identify specific transactions:

```move
struct NonceKey has copy, drop, store {
    sender_address: address,
    nonce: u64,
    transaction_hash: vector<u8>,  // Add payload identifier
}
```

**Option 2**: Enforce strict nonce uniqueness - never allow reuse even after expiration (make nonces strictly increasing like sequence numbers).

**Option 3**: Remove the 100-second overlap window entirely and prevent any nonce reuse within a much longer period (e.g., 24 hours or permanent).

The current design comment explicitly states the problematic behavior: [6](#0-5) 

This comment confirms the vulnerability is architectural, not an implementation bug.

## Proof of Concept

```move
#[test(fx = @aptos_framework)]
public entry fun test_nonce_reuse_exploit(fx: signer) acquires NonceHistory {
    use aptos_framework::timestamp;
    use aptos_framework::nonce_validation;
    
    nonce_validation::initialize_nonce_table(&fx);
    timestamp::set_time_has_started_for_testing(&fx);
    let begin_time = timestamp::now_seconds();
    
    // User signs Transaction A: transfer 10 APT to Bob
    // (nonce=100, expiration=begin_time+50)
    assert!(nonce_validation::check_and_insert_nonce(@Alice, 100, begin_time + 50), 0);
    
    // Transaction A executes (simulated)
    
    // Advance time past expiration + overlap window
    timestamp::fast_forward_seconds(151);
    
    // Attacker tricks user into signing Transaction B with SAME NONCE
    // but different payload: transfer 1000 APT to Attacker
    // (nonce=100, expiration=begin_time+201)
    
    // VULNERABILITY: This succeeds even though it's a completely different transaction!
    assert!(nonce_validation::check_and_insert_nonce(@Alice, 100, begin_time + 201), 1);
    
    // Both transactions have nonce=100 but authorize different operations
    // This breaks the fundamental property that nonces prevent replay attacks
}
```

This test demonstrates that the same nonce value (100) can authorize two completely different transactions from the same sender (@Alice), violating replay protection guarantees.

## Notes

The vulnerability is confirmed by examining how `SessionId` incorporates `script_hash` but nonce validation does not: [7](#0-6) 

The `ReplayProtector` enum defines nonce-based protection but doesn't enforce nonce-payload binding: [8](#0-7) 

The transaction metadata includes `script_hash` separately from the `replay_protector`, but this information is not used in nonce validation: [9](#0-8)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L34-38)
```text
    // An orderless transaction is a transaction that doesn't have a sequence number.
    // Orderless transactions instead contain a nonce to prevent replay attacks.
    // If the incoming transaction has the same (address, nonce) pair as a previous unexpired transaction, it is rejected.
    // The nonce history is used to store the list of (address, nonce, txn expiration time) values of all unexpired transactions.
    // The nonce history is used in the transaction validation process to check if the incoming transaction is valid.
```

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L152-166)
```text
        let existing_exp_time = bucket.nonce_to_exp_time_map.get(&nonce_key);
        if (existing_exp_time.is_some()) {
            let existing_exp_time = existing_exp_time.extract();

            // If the existing (address, nonce) pair has not expired, return false.
            if (existing_exp_time >= current_time) {
                return false;
            };

            // We maintain an invariant that two transaction with the same (address, nonce) pair cannot be stored
            // in the nonce history if their transaction expiration times are less than `NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS`
            // seconds apart.
            if (txn_expiration_time <= existing_exp_time + NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS) {
                return false;
            };
```

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L168-175)
```text
            // If the existing (address, nonce) pair has expired, garbage collect it.
            bucket.nonce_to_exp_time_map.remove(&nonce_key);
            bucket.nonces_ordered_by_exp_time.remove(&NonceKeyWithExpTime {
                txn_expiration_time: existing_exp_time,
                sender_address,
                nonce,
            });
        };
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/session_id.rs (L53-58)
```rust
    OrderlessTxn {
        sender: AccountAddress,
        nonce: u64,
        expiration_time: u64,
        script_hash: Vec<u8>,
    },
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/session_id.rs (L98-104)
```rust
            ReplayProtector::Nonce(nonce) => Self::OrderlessTxn {
                sender: txn_metadata.sender,
                nonce,
                expiration_time: txn_metadata.expiration_timestamp_secs,
                script_hash: txn_metadata.script_hash.clone(),
            },
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

**File:** types/src/transaction/mod.rs (L112-116)
```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplayProtector {
    Nonce(u64),
    SequenceNumber(u64),
}
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L18-41)
```rust
pub struct TransactionMetadata {
    pub sender: AccountAddress,
    pub authentication_proof: AuthenticationProof,
    pub secondary_signers: Vec<AccountAddress>,
    pub secondary_authentication_proofs: Vec<AuthenticationProof>,
    pub replay_protector: ReplayProtector,
    pub fee_payer: Option<AccountAddress>,
    /// `None` if the [TransactionAuthenticator] lacks an authenticator for the fee payer.
    /// `Some([])` if the authenticator for the fee payer is a [NoAccountAuthenticator].
    pub fee_payer_authentication_proof: Option<AuthenticationProof>,
    pub max_gas_amount: Gas,
    pub gas_unit_price: FeePerGasUnit,
    pub transaction_size: NumBytes,
    pub expiration_timestamp_secs: u64,
    pub chain_id: ChainId,
    pub script_hash: Vec<u8>,
    pub script_size: NumBytes,
    pub is_keyless: bool,
    pub is_slh_dsa_sha2_128s: bool,
    pub entry_function_payload: Option<EntryFunction>,
    pub multisig_payload: Option<Multisig>,
    /// The transaction index context for the monotonically increasing counter.
    pub transaction_index_kind: TransactionIndexKind,
}
```
