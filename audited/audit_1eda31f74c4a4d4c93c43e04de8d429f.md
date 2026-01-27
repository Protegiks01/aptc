# Audit Report

## Title
Semantic Validation Failure in BatchResponse::NotFound Enables Consensus Liveness Attack via LedgerInfo Replay

## Summary
The `BatchResponse::NotFound` variant accepts any validly-signed `LedgerInfoWithSignatures` as proof that a batch is unavailable, even though `LedgerInfo` contains no information about batch existence. This allows malicious validators to prevent batch retrieval by replaying unrelated but valid ledger commitments, causing consensus liveness failures.

## Finding Description

The vulnerability stems from a semantic mismatch between what `LedgerInfoWithSignatures` proves and how it's used in batch retrieval.

**The Core Issue:** [1](#0-0) 

The code validates `BatchResponse::NotFound` by checking: (1) epoch matches, (2) timestamp exceeds expiration, and (3) signatures are cryptographically valid. However, it does NOT verify that the `LedgerInfo` has any connection to the requested batch.

**What LedgerInfo Actually Contains:** [2](#0-1) 

A `LedgerInfo` contains `commit_info` (BlockInfo with epoch/timestamp) and `consensus_data_hash`, but **no batch-specific information**. It proves validators agreed on a ledger state, not that any specific batch exists or doesn't exist.

**Attack Execution:**

When a legitimate responder doesn't have a batch, they send their latest ledger info: [3](#0-2) 

However, a malicious validator can send `NotFound` with **any** valid `LedgerInfoWithSignatures` from the network that meets epoch/timestamp criteria, regardless of whether they actually checked for the batch. Since the requester accepts the **first** valid response and returns immediately, a fast malicious response prevents honest validators from serving the batch.

**Invariant Violation:**

This breaks the **Consensus Liveness** invariant. The AptosBFT protocol requires that blocks with valid proofs of store can be executed. By preventing batch retrieval through fake `NotFound` responses, a single malicious signer can stall block execution.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty categories)

This qualifies as "Significant protocol violations" and "Validator node slowdowns" because:

1. **Consensus Liveness Impact**: Blocks containing proofs of store cannot be executed if batch retrieval fails, causing consensus to stall on that block.

2. **Low Attack Threshold**: Only requires ONE malicious validator among the batch signers to race honest responses. Does not require Byzantine majority (>1/3).

3. **Practical Exploitability**: The attacker can cache valid `LedgerInfoWithSignatures` from normal network traffic and replay them instantly when batch requests arrive.

4. **Network-Wide Effect**: Affects all validators trying to execute blocks containing the targeted batch proofs.

While this doesn't cause permanent network partition or fund loss (hence not Critical), it significantly disrupts consensus operation and can cause prolonged liveness failures.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Requirements:**
- Attacker must be a validator included in the batch's proof of store signers
- Attacker needs valid `LedgerInfoWithSignatures` with correct epoch and timestamp > batch expiration (easily obtainable from network traffic)
- Attacker must respond faster than honest validators (achievable through low-latency infrastructure or by skipping actual batch lookup)

**Mitigating Factors:**
- Requires attacker to be in the signer set (but this is common for active validators)
- Multiple retries to different peers may eventually succeed (but attacker can repeatedly race responses)
- Honest validators may serve batches before attacker responds (timing-dependent)

**Why This is Likely:**
Validators are constantly processing batch requests. A malicious validator can pre-compute responses with cached ledger infos and respond in microseconds, while honest validators must perform database lookups. The "first valid response wins" model favors the attacker.

## Recommendation

Implement proper proof of batch non-existence rather than accepting generic ledger commitments:

**Option 1: Multi-Peer Confirmation**
Wait for responses from multiple signers before accepting `NotFound`. Only return error if majority of signers report batch missing.

**Option 2: Batch-Specific Proof**
Extend `BatchResponse::NotFound` to include cryptographic proof that the batch was checked and not found (e.g., signed statement specifically about the requested digest).

**Option 3: Remove Early Exit**
Don't immediately return error on `NotFound`. Instead, continue requesting from other peers. Only fail after exhausting retry limit with all peers reporting not found.

**Recommended Fix (Option 3 - minimal change):**

```rust
Ok(BatchResponse::NotFound(ledger_info)) => {
    counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
    // Validate but don't immediately fail - continue trying other peers
    if ledger_info.commit_info().epoch() == epoch
        && ledger_info.commit_info().timestamp_usecs() > expiration
        && ledger_info.verify_signatures(&validator_verifier).is_ok()
    {
        counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
        debug!("QS: received NotFound for batch {}, continuing with other peers", digest);
        // Don't return here - let the retry loop exhaust attempts
    }
}
```

This ensures that a single malicious `NotFound` response cannot prevent retrieval from honest peers.

## Proof of Concept

```rust
// Demonstration of the vulnerability
// This would be integrated into the batch_requester_test.rs test suite

#[tokio::test]
async fn test_malicious_not_found_blocks_retrieval() {
    // Setup: Create validator set with one malicious validator M
    let malicious_validator = create_validator();
    let honest_validators = create_validator_set(3);
    
    // Create a batch with proof signed by all validators including M
    let batch = create_test_batch();
    let proof = create_proof_of_store(batch.clone(), &all_validators);
    
    // Honest validators have the batch in storage
    for validator in &honest_validators {
        validator.store_batch(batch.clone());
    }
    
    // Create a valid but unrelated LedgerInfo with:
    // - Same epoch as current
    // - Timestamp > batch expiration
    // - Valid signatures from quorum
    let fake_ledger_info = create_valid_ledger_info(
        epoch: batch.epoch(),
        timestamp: batch.expiration() + 1000,
        signed_by: &all_validators
    );
    
    // Requester sends batch request to all signers
    let requester = BatchRequester::new(...);
    
    // Malicious validator responds immediately with NotFound
    mock_network.configure_response(
        malicious_validator,
        BatchResponse::NotFound(fake_ledger_info),
        response_delay: Duration::from_millis(1) // Respond instantly
    );
    
    // Honest validators respond with actual batch
    for validator in &honest_validators {
        mock_network.configure_response(
            validator,
            BatchResponse::Batch(batch.clone()),
            response_delay: Duration::from_millis(100) // Realistic delay
        );
    }
    
    // Execute the request
    let result = requester.request_batch(
        batch.digest(),
        batch.expiration(),
        proof.signers(),
        subscriber_rx
    ).await;
    
    // VULNERABILITY: Even though 3/4 validators have the batch,
    // the malicious validator's fast NotFound response causes failure
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ExecutorError::CouldNotGetData);
    
    // This breaks consensus liveness - the block cannot be executed
    // even though the batch exists on honest validators
}
```

**Notes:**
- Signatures are NOT forged - they are cryptographically valid
- The vulnerability is **semantic**: `LedgerInfo` doesn't prove what the code assumes it proves
- A single malicious signer can exploit the race condition
- This affects consensus liveness under Byzantine behavior < 1/3 threshold

### Citations

**File:** consensus/src/quorum_store/batch_requester.rs (L142-151)
```rust
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
                                }
```

**File:** types/src/ledger_info.rs (L51-59)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct LedgerInfo {
    commit_info: BlockInfo,

    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L416-424)
```rust
                } else {
                    match aptos_db_clone.get_latest_ledger_info() {
                        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
                        Err(e) => {
                            let e = anyhow::Error::from(e);
                            error!(epoch = epoch, error = ?e, kind = error_kind(&e));
                            continue;
                        },
                    }
```
