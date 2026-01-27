# Audit Report

## Title
Missing BCS Deserialization Fuzzing for Multisig Payloads Enables Potential Validator DoS

## Summary
The `Multisig` and `MultisigTransactionPayload` deserialization implementations lack dedicated fuzzing coverage, creating an untested attack surface where maliciously crafted BCS-encoded payloads stored on-chain could potentially cause validator crashes during transaction execution. Unlike `SignedTransaction` which has fuzzing infrastructure, multisig payloads are deserialized without depth limits and without empirical validation against malformed inputs.

## Finding Description

The security gap exists in the multisig transaction execution path where BCS deserialization occurs without the protections applied elsewhere in the codebase.

**Vulnerable Deserialization Path:** [1](#0-0) 

This code deserializes user-controlled data from on-chain storage using bare `bcs::from_bytes` without the depth limits employed by other security-critical deserialization paths.

**Comparison with Protected Paths:**

The API layer properly uses depth-limited deserialization for user inputs: [2](#0-1) 

The constant is defined as: [3](#0-2) 

**Attack Surface - Unvalidated Storage:**

Multisig payloads are stored on-chain with only a non-empty validation: [4](#0-3) 

**The Complete Attack Path:**

1. Attacker creates a multisig account
2. Attacker crafts a malicious BCS payload with deeply nested structures (Vec<Vec<Vec<...>>>, complex TypeTags, or other edge cases)
3. Payload is stored on-chain via `create_transaction` with no deserialization validation
4. When the multisig transaction executes, the VM deserializes the payload without depth limits
5. If serde-derived `Deserialize` implementations have panic paths for malformed input, validators crash

**Existing Fuzzing Infrastructure (but not for multisig):** [5](#0-4) 

**Crash Handler Limitation:**

The crash handler protects Move bytecode deserialization but NOT BCS deserialization of transaction types: [6](#0-5) 

The `VMState::DESERIALIZER` is only set during Move module deserialization: [7](#0-6) 

This means BCS deserialization panics in the multisig execution path would kill the validator process.

## Impact Explanation

**Severity: Medium** (potentially High if exploitable)

This represents a Medium severity issue per Aptos bug bounty criteria because:

1. **Validator Availability Risk**: If malformed BCS inputs can trigger panics instead of errors, an attacker could craft a single malicious multisig payload that crashes all validators attempting to execute it, causing network-wide consensus disruption.

2. **Deterministic Execution Violation**: Different validators might handle edge cases differently if the deserialization has undefined behavior for certain inputs, breaking the critical invariant that all validators must produce identical results.

3. **No Runtime Protection**: Unlike Move bytecode deserialization which has panic protection via `catch_unwind`, BCS deserialization in this path lacks such safeguards.

The impact could escalate to **High** severity if:
- Reproducible validator crashes are demonstrated
- The attack is easily repeatable
- It causes sustained consensus disruption

## Likelihood Explanation

**Likelihood: Medium**

The attack is moderately likely because:

1. **Low Barrier to Entry**: Any user can create multisig accounts and store arbitrary payloads on-chain with minimal validation
2. **Data Persists**: Malicious payloads remain on-chain until executed, allowing repeated exploitation attempts
3. **Unknown Attack Surface**: Without fuzzing, the actual panic/crash triggers remain undiscovered but potentially exist

Reducing factors:
- Requires discovering specific BCS inputs that cause panics (not proven)
- The BCS library and serde are generally robust, but edge cases exist
- TypeTag nesting is limited to depth 8, reducing some attack vectors

## Recommendation

**Immediate Actions:**

1. **Add Dedicated Fuzzing Target**:

Create `testsuite/fuzzer/fuzz/fuzz_targets/multisig_deserialize.rs`:
```rust
#![no_main]
use aptos_types::transaction::{Multisig, MultisigTransactionPayload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bcs::from_bytes::<Multisig>(data);
    let _ = bcs::from_bytes::<MultisigTransactionPayload>(data);
});
```

2. **Apply Depth Limits**:

Modify the deserialization to use depth limits: [1](#0-0) 

Change to:
```rust
const MAX_MULTISIG_PAYLOAD_DEPTH: usize = 16;
let payload_bytes = bcs::from_bytes_with_limit::<Vec<u8>>(payload_bytes, MAX_MULTISIG_PAYLOAD_DEPTH)
    .map_err(|_| deserialization_error())?;
let payload = bcs::from_bytes_with_limit::<MultisigTransactionPayload>(&payload_bytes, MAX_MULTISIG_PAYLOAD_DEPTH)
    .map_err(|_| deserialization_error())?;
```

3. **Add Validation at Storage Time**:

Validate payloads during `create_transaction` by attempting deserialization before storage to catch malformed inputs early.

## Proof of Concept

While a complete exploit requires fuzzing to discover specific panic-inducing inputs, here's a test framework to validate the fix:

```rust
#[test]
fn test_multisig_deserialization_depth_protection() {
    // Create deeply nested Vec<Vec<Vec<...>>> structure
    let mut nested_bytes = vec![];
    for _ in 0..50 {
        nested_bytes = bcs::to_bytes(&vec![nested_bytes]).unwrap();
    }
    
    // Attempt to deserialize - should fail gracefully, not panic
    let result = bcs::from_bytes::<MultisigTransactionPayload>(&nested_bytes);
    assert!(result.is_err(), "Should reject deeply nested structures");
    
    // With depth limit protection
    let result = bcs::from_bytes_with_limit::<MultisigTransactionPayload>(&nested_bytes, 16);
    assert!(result.is_err(), "Should reject with depth limit");
}
```

## Notes

The absence of fuzzing represents a **testing gap** rather than a definitively proven vulnerability. However, defense-in-depth principles dictate that security-critical deserialization paths handling untrusted on-chain data should have:

1. Empirical validation via fuzzing
2. Depth limits matching other user-input paths  
3. Validation at storage time

The network layer already recognizes this need by defining explicit recursion limits: [8](#0-7) 

The multisig execution path should apply similar protections given that it processes potentially adversarial data with consensus-critical consequences.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1278-1281)
```rust
        let payload_bytes =
            bcs::from_bytes::<Vec<u8>>(payload_bytes).map_err(|_| deserialization_error())?;
        let payload = bcs::from_bytes::<MultisigTransactionPayload>(&payload_bytes)
            .map_err(|_| deserialization_error())?;
```

**File:** api/src/transactions.rs (L851-851)
```rust
    const MAX_SIGNED_TRANSACTION_DEPTH: usize = 16;
```

**File:** api/src/transactions.rs (L1223-1225)
```rust
                let signed_transaction: SignedTransaction =
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
                        .context("Failed to deserialize input into SignedTransaction")
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L954-972)
```text
    public entry fun create_transaction(
        owner: &signer,
        multisig_account: address,
        payload: vector<u8>,
    ) acquires MultisigAccount {
        assert!(vector::length(&payload) > 0, error::invalid_argument(EPAYLOAD_CANNOT_BE_EMPTY));

        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);

        let creator = address_of(owner);
        let transaction = MultisigTransaction {
            payload: option::some(payload),
            payload_hash: option::none<vector<u8>>(),
            votes: simple_map::create<address, bool>(),
            creator,
            creation_time_secs: now_seconds(),
        };
        add_transaction(creator, multisig_account, transaction);
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/signed_transaction_deserialize.rs (L14-16)
```rust
fuzz_target!(|fuzz_data: FuzzData| {
    let _ = bcs::from_bytes::<SignedTransaction>(&fuzz_data.data);
});
```

**File:** crates/crash-handler/src/lib.rs (L52-54)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L56-57)
```rust
        let prev_state = move_core_types::state::set_state(VMState::DESERIALIZER);
        let result = std::panic::catch_unwind(|| {
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L38-39)
```rust
pub const USER_INPUT_RECURSION_LIMIT: usize = 32;
pub const RECURSION_LIMIT: usize = 64;
```
