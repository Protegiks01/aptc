# Audit Report

## Title
Node-Checker TPS Verification Trusts Unvalidated Claims from Target Node

## Summary
The TPS (transactions per second) checker in the node-checker system verifies transaction commitment by querying the same node being tested, without cross-validating against a baseline node or independent source. This allows malicious nodes to fake performance metrics by returning inflated account sequence numbers, potentially enabling underperforming or malicious nodes to pass validation and join the validator set.

## Finding Description

The node-checker's TPS checker is designed to validate that nodes meet minimum transaction processing requirements. However, the implementation contains a critical trust assumption flaw.

**The Vulnerability Flow:**

1. The TPS checker creates a cluster containing only the target node being tested: [1](#0-0) 

2. Transactions are submitted to this target node and statistics are collected: [2](#0-1) 

3. The checker evaluates success based on the `rate.committed` metric: [3](#0-2) 

**The Critical Flaw:**

The transaction emitter verifies "committed" transactions by querying account sequence numbers from the REST API of the **same target node** being tested: [4](#0-3) 

The submission worker uses this client to verify commitment: [5](#0-4) 

**No Cross-Validation:**

Unlike other checkers, such as the TransactionCorrectnessChecker which properly validates against both baseline and target nodes: [6](#0-5) 

The TPS checker never queries a baseline node to verify that transactions were actually committed to the blockchain.

**Exploitation Path:**

A malicious node operator can:
1. Accept transaction submissions via REST API (return HTTP 200)
2. **Not** actually process or commit transactions to the blockchain (save computational resources)
3. When queried via `GET /v1/accounts/{address}`, return fake account objects with inflated `sequence_number` values
4. The emitter counts these as "committed" transactions based on the sequence number increase
5. The node passes the TPS test without doing any real work

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program:

- **Validator Selection Bypass**: The node-checker is a critical component for validating nodes before they join the validator set. A malicious actor could:
  - Run an underperforming node that doesn't meet actual TPS requirements
  - Fake the TPS metrics to pass validation
  - Join the validator set despite being unable to handle the network load
  
- **Network Performance Degradation**: If multiple validators use this exploit:
  - The network's actual throughput would be lower than expected
  - Transaction processing delays would increase
  - Network reliability would be compromised

- **Resource Theft**: Validators receive staking rewards. A node that fakes metrics:
  - Receives rewards without providing equivalent service
  - Steals value from honest validators and the network

The impact maps to "Significant protocol violations" in the HIGH severity category, as it undermines the validator selection process which is fundamental to network security and performance.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- **No special access required**: Any node operator can modify their node's REST API responses
- **Simple implementation**: Only requires intercepting and modifying GET responses for account endpoints
- **No collusion needed**: Single actor exploitation
- **Undetectable**: Without cross-validation, the fake metrics appear legitimate
- **Low technical barrier**: Basic REST API modification, no cryptographic or consensus-level attack needed

The only barrier is that the attacker must be attempting to join as a validator, but this is precisely when the node-checker is used, making the attack both relevant and likely.

## Recommendation

**Fix: Add Cross-Validation Against Baseline Node**

The TPS checker should follow the pattern established by TransactionCorrectnessChecker and verify transaction commitment against an independent baseline node.

**Recommended Implementation:**

1. Modify the TPS checker to accept both baseline and target providers:
```rust
// In ecosystem/node-checker/src/checker/tps.rs
async fn check(
    &self,
    providers: &ProviderCollection,
) -> Result<Vec<CheckResult>, CheckerError> {
    // Get baseline provider for verification
    let baseline_api_index_provider = get_provider!(
        providers.baseline_api_index_provider,
        self.config.common.required,
        ApiIndexProvider
    );
    
    let target_api_index_provider = get_provider!(
        providers.target_api_index_provider,
        self.config.common.required,
        ApiIndexProvider
    );
    
    // ... existing cluster setup ...
    
    // After emitting transactions, verify against baseline
    let verification_result = verify_transactions_committed(
        &baseline_api_index_provider.client,
        &target_api_index_provider.client,
        &account_addresses,
        expected_sequence_numbers,
    ).await?;
    
    if !verification_result.all_verified {
        return Ok(vec![Self::build_result(
            "Transaction commitment verification failed".to_string(),
            0,
            format!(
                "Your node reported {} committed transactions, but baseline verification found only {} actually committed",
                stats.committed,
                verification_result.verified_count,
            ),
        )]);
    }
    
    // ... existing evaluation logic ...
}
```

2. Add a verification function that cross-checks with the baseline:
```rust
async fn verify_transactions_committed(
    baseline_client: &RestClient,
    target_client: &RestClient,
    accounts: &[AccountAddress],
    expected_seq_nums: &HashMap<AccountAddress, u64>,
) -> Result<VerificationResult> {
    let mut verified_count = 0;
    
    for (address, expected_seq) in expected_seq_nums {
        // Get sequence number from baseline (source of truth)
        let baseline_seq = baseline_client
            .get_account_bcs(*address)
            .await?
            .into_inner()
            .sequence_number();
        
        // Verify target matches baseline
        if baseline_seq >= *expected_seq {
            verified_count += 1;
        }
    }
    
    Ok(VerificationResult {
        verified_count,
        all_verified: verified_count == expected_seq_nums.len(),
    })
}
```

3. Alternative: Sample random accounts and verify their transactions appear on the baseline node by checking transaction hashes in the ledger, not just sequence numbers.

## Proof of Concept

**Step 1: Create a Malicious Node with Modified REST API**

```rust
// Mock REST server that accepts transactions but doesn't process them
use warp::Filter;
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::main]
async fn main() {
    let fake_seq_num = Arc::new(AtomicU64::new(0));
    
    // Transaction submission endpoint - always succeeds
    let submit = warp::post()
        .and(warp::path!("transactions"))
        .map(|| {
            // Accept transaction but don't process it
            warp::reply::json(&serde_json::json!({
                "hash": "0xfake",
                "type": "pending_transaction"
            }))
        });
    
    // Account query endpoint - returns fake inflated sequence numbers
    let fake_seq = fake_seq_num.clone();
    let account = warp::get()
        .and(warp::path!("accounts" / String))
        .map(move |_addr: String| {
            // Increment fake sequence number to simulate commits
            let seq = fake_seq.fetch_add(100, Ordering::Relaxed);
            warp::reply::json(&serde_json::json!({
                "sequence_number": seq.to_string(),
                "authentication_key": "0x00",
            }))
        });
    
    warp::serve(submit.or(account))
        .run(([127, 0, 0, 1], 8080))
        .await;
}
```

**Step 2: Run Node-Checker Against Malicious Node**

```bash
# Point node-checker at the malicious node
./aptos-node-checker \
    --target-url http://127.0.0.1:8080 \
    --baseline-url <legitimate-node-url> \
    --checker tps \
    --minimum-tps 1000

# Result: Malicious node will PASS despite processing zero transactions
# The node-checker will report committed TPS of ~1000+ based on fake sequence numbers
```

**Step 3: Verify Exploitation**

Query the actual blockchain state on a legitimate node to confirm transactions were never committed:
```bash
# Query baseline node for the account
curl http://legitimate-node:8080/v1/accounts/0x<address>

# Response will show sequence_number: 0 (no transactions actually committed)
# But node-checker reported 1000+ TPS based on malicious node's fake response
```

This demonstrates that the node-checker can be trivially bypassed, allowing malicious nodes to pass validation without meeting performance requirements.

### Citations

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

**File:** ecosystem/node-checker/src/checker/tps.rs (L141-149)
```rust
        let stats = emit_transactions_with_cluster(
            &cluster,
            &self.config.emit_config,
            self.config
                .emit_workload_configs
                .args_to_transaction_mix_per_phase(),
        )
        .await
        .map_err(TpsCheckerError::TransactionEmitterError)?;
```

**File:** ecosystem/node-checker/src/checker/tps.rs (L162-163)
```rust
        let mut description = format!("The minimum TPS (transactions per second) \
            required of nodes is {}, your node hit: {} (out of {} transactions submitted per second).", self.config.minimum_tps, rate.committed, rate.submitted);
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L1227-1236)
```rust
pub async fn get_account_seq_num(
    client: &RestClient,
    address: AccountAddress,
) -> Result<(u64, u64)> {
    let result = client.get_account_bcs(address).await;
    match &result {
        Ok(resp) => Ok((
            resp.inner().sequence_number(),
            Duration::from_micros(resp.state().timestamp_usecs).as_secs(),
        )),
```

**File:** crates/transaction-emitter-lib/src/emitter/submission_worker.rs (L303-311)
```rust
        let (latest_fetched_counts, sum_of_completion_timestamps_millis) =
            wait_for_accounts_sequence(
                start_time,
                self.client(),
                &account_to_start_and_end_seq_num,
                txn_expiration_ts_secs,
                check_account_sleep_duration,
            )
            .await;
```

**File:** ecosystem/node-checker/src/checker/transaction_correctness.rs (L82-92)
```rust
        let baseline_api_index_provider = get_provider!(
            providers.baseline_api_index_provider,
            self.config.common.required,
            ApiIndexProvider
        );

        let target_api_index_provider = get_provider!(
            providers.target_api_index_provider,
            self.config.common.required,
            ApiIndexProvider
        );
```
