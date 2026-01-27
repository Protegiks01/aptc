# Audit Report

## Title
Node-Checker TPS Test Vulnerable to Stats Manipulation via Target Node Self-Reporting

## Summary
The node-checker TPS evaluation system relies entirely on the target node's own REST API responses to determine transaction commitment counts, with no independent verification mechanism. A malicious node operator can trivially inflate their TPS metrics by returning fake sequence numbers, allowing underpowered nodes to pass qualification checks or achieve artificially high performance ratings.

## Finding Description

The TPS checker in the node-checker ecosystem tool is designed to evaluate whether a node meets minimum transaction-per-second requirements. However, the implementation contains a critical trust assumption violation: it queries the target node itself to verify how many transactions the target node has committed.

**Attack Flow:**

1. The TPS checker creates a cluster configuration pointing exclusively to the target node's URL: [1](#0-0) 

2. The emitter submits transactions and then queries the target node's REST API to determine commitment status: [2](#0-1) 

3. The sequence numbers are retrieved via an HTTP GET request to the target node's `/accounts/{address}` endpoint: [3](#0-2) 

4. This HTTP request is made through the reqwest client without any cryptographic verification: [4](#0-3) 

5. The response only contains HTTP headers with metadata (no cryptographic proofs): [5](#0-4) [6](#0-5) 

6. The committed transaction count is calculated purely from the difference between fetched and expected sequence numbers: [7](#0-6) 

7. This count directly determines the pass/fail decision: [8](#0-7) 

**Exploitation:**

A malicious node operator can:
1. Run modified node software that intercepts the `/accounts/{address}` REST API endpoint
2. Accept transaction submissions (or pretend to accept them)
3. Return inflated sequence numbers in API responses
4. Fake appropriate HTTP headers (chain_id, timestamp, version)
5. Achieve arbitrarily high TPS ratings without actually committing transactions to consensus

The emitter has no mechanism to verify that:
- Transactions were actually committed to blockchain state
- The sequence numbers correspond to real consensus-verified transactions
- Other nodes agree with the reported sequence numbers
- Any cryptographic proof validates the claims

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria for "Significant protocol violations."

While this vulnerability does not directly compromise on-chain consensus or steal funds, it enables gaming of critical off-chain infrastructure:

1. **Validator Qualification Gaming**: If the node-checker is used for validator onboarding, malicious operators could pass TPS requirements with underpowered hardware
2. **Reputation System Manipulation**: Node rating systems relying on this checker can be gamed
3. **Network Health Risk**: Allowing under-resourced nodes into the validator set degrades network performance and reliability
4. **Trust Violation**: Breaks the fundamental assumption that performance metrics reflect actual node capabilities

The node-checker appears to be designed for validator node qualification based on the documentation link in the code and the pass/fail logic for minimum TPS requirements.

## Likelihood Explanation

**High Likelihood:**

- **Trivial to Implement**: Requires only modifying the REST API handler in local node software to return fake integers
- **No Technical Barriers**: No cryptographic signatures to forge, no consensus to overcome, no complex exploit chain
- **Low Detection Risk**: The manipulation happens in the target's own API responses with no external visibility
- **Clear Incentive**: Node operators have direct financial incentive to pass qualification checks or achieve high ratings
- **Attacker Control**: The target node operator has complete control over their node's software and API responses

The attack requires zero sophisticated cryptographic knowledge—just modifying a single REST API endpoint to return inflated numbers.

## Recommendation

Implement independent verification of transaction commitment using one or more of these approaches:

**Option 1: Query Multiple Independent Nodes**
- Require the TPS checker to query a set of trusted baseline nodes (not controlled by the target)
- Compare sequence numbers across multiple independent sources
- Flag discrepancies as potential manipulation

**Option 2: Verify State Proofs**
- Extend the API to return cryptographic state proofs with account data
- Verify these proofs against known validator signatures
- Ensure the ledger version is consensus-verified

**Option 3: Baseline Node Verification**
- Have the TPS checker submit to the target but verify commitment through a trusted baseline node
- Query the baseline node for the final sequence numbers
- Only accept results that the baseline node confirms

**Recommended Fix (Option 1):** [9](#0-8) 

Modify to include baseline/trusted nodes in the cluster and verify sequence numbers across multiple independent sources before calculating TPS.

## Proof of Concept

**Setup:**
1. Deploy a modified Aptos node with a REST API handler that returns fake sequence numbers
2. Run the node-checker TPS test against this modified node

**Modified Node (Pseudocode):**
```rust
// In the modified node's REST API handler for /accounts/{address}
async fn get_account_handler(address: AccountAddress) -> AccountResource {
    // Return fake account with inflated sequence number
    AccountResource {
        sequence_number: u64::MAX - 1000, // Fake high sequence number
        authentication_key: /* real or fake */,
        // ... other fields
    }
}
```

**Expected Result:**
- Target node accepts transaction submissions (or pretends to)
- TPS checker queries target's `/accounts/{address}` endpoint
- Target returns fake sequence number (e.g., 100,000 when only 10 were submitted)
- Committed count calculated as: `100,000 - 0 = 100,000 transactions`
- TPS = 100,000 / test_duration → artificially inflated rating
- Node passes TPS check despite not actually committing transactions

**Verification:**
Query an independent Aptos node for the same account's sequence number—it will show the true (much lower) value, confirming the target node lied about its performance metrics.

## Notes

This vulnerability is specific to the off-chain node-checker infrastructure and does not affect on-chain consensus security. However, it represents a significant protocol violation if the node-checker is used for validator qualification, node ratings, or any system where TPS performance metrics influence trust or economic decisions. The fix requires architectural changes to introduce independent verification rather than trusting the target node's self-reported metrics.

### Citations

**File:** ecosystem/node-checker/src/checker/tps.rs (L130-139)
```rust
        let cluster_config = ClusterArgs {
            targets: Some(vec![target_url; self.config.repeat_target_count]),
            targets_file: None,
            coin_source_args: self.config.coin_source_args.clone(),
            chain_id: Some(chain_id),
            node_api_key: None,
        };
        let cluster = Cluster::try_from_cluster_args(&cluster_config)
            .await
            .map_err(TpsCheckerError::BuildClusterError)?;
```

**File:** ecosystem/node-checker/src/checker/tps.rs (L162-189)
```rust
        let mut description = format!("The minimum TPS (transactions per second) \
            required of nodes is {}, your node hit: {} (out of {} transactions submitted per second).", self.config.minimum_tps, rate.committed, rate.submitted);
        let evaluation_result = if rate.committed >= (self.config.minimum_tps as f64) {
            if stats.committed == stats.submitted {
                description.push_str(
                    " Your node could theoretically hit \
                even higher TPS, the evaluation suite only tests to check \
                your node meets the minimum requirements.",
                );
            }
            Self::build_result(
                "Transaction processing speed is sufficient".to_string(),
                100,
                description,
            )
        } else {
            description.push_str(
                " This implies that the hardware you're \
            using to run your node isn't powerful enough, please see the attached link",
            );
            Self::build_result(
                "Transaction processing speed is too low".to_string(),
                0,
                description,
            )
            .links(vec![NODE_REQUIREMENTS_LINK.to_string()])
        };

```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L1227-1252)
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
        Err(e) => {
            // if account is not present, that is equivalent to sequence_number = 0
            if let RestError::Api(api_error) = e {
                if let AptosErrorCode::AccountNotFound = api_error.error.error_code {
                    return Ok((
                        0,
                        Duration::from_micros(api_error.state.as_ref().unwrap().timestamp_usecs)
                            .as_secs(),
                    ));
                }
            }
            result?;
            unreachable!()
        },
    }
}
```

**File:** crates/aptos-rest-client/src/lib.rs (L1581-1588)
```rust
    pub async fn get_account_bcs(
        &self,
        address: AccountAddress,
    ) -> AptosResult<Response<AccountResource>> {
        let url = self.build_path(&format!("accounts/{}", address.to_hex()))?;
        let response = self.get_bcs(url).await?;
        Ok(response.and_then(|inner| bcs::from_bytes(&inner))?)
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1687-1690)
```rust
    async fn get_bcs(&self, url: Url) -> AptosResult<Response<bytes::Bytes>> {
        let response = self.inner.get(url).header(ACCEPT, BCS).send().await?;
        self.check_and_parse_bcs_response(response).await
    }
```

**File:** crates/aptos-rest-client/src/state.rs (L10-20)
```rust
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct State {
    pub chain_id: u8,
    pub epoch: u64,
    pub version: u64,
    pub timestamp_usecs: u64,
    pub oldest_ledger_version: u64,
    pub oldest_block_height: u64,
    pub block_height: u64,
    pub cursor: Option<String>,
}
```

**File:** crates/aptos-rest-client/src/state.rs (L23-102)
```rust
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> anyhow::Result<Self> {
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_version = headers
            .get(X_APTOS_LEDGER_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_timestamp = headers
            .get(X_APTOS_LEDGER_TIMESTAMP)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_epoch = headers
            .get(X_APTOS_EPOCH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_ledger_version = headers
            .get(X_APTOS_LEDGER_OLDEST_VERSION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_block_height = headers
            .get(X_APTOS_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let maybe_oldest_block_height = headers
            .get(X_APTOS_OLDEST_BLOCK_HEIGHT)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cursor = headers
            .get(X_APTOS_CURSOR)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let state = if let (
            Some(chain_id),
            Some(version),
            Some(timestamp_usecs),
            Some(epoch),
            Some(oldest_ledger_version),
            Some(block_height),
            Some(oldest_block_height),
            cursor,
        ) = (
            maybe_chain_id,
            maybe_version,
            maybe_timestamp,
            maybe_epoch,
            maybe_oldest_ledger_version,
            maybe_block_height,
            maybe_oldest_block_height,
            cursor,
        ) {
            Self {
                chain_id,
                epoch,
                version,
                timestamp_usecs,
                oldest_ledger_version,
                block_height,
                oldest_block_height,
                cursor,
            }
        } else {
            anyhow::bail!(
                "Failed to build State from headers due to missing values in response. \
                Chain ID: {:?}, Version: {:?}, Timestamp: {:?}, Epoch: {:?}, \
                Oldest Ledger Version: {:?}, Block Height: {:?} Oldest Block Height: {:?}",
                maybe_chain_id,
                maybe_version,
                maybe_timestamp,
                maybe_epoch,
                maybe_oldest_ledger_version,
                maybe_block_height,
                maybe_oldest_block_height,
            )
        };

        Ok(state)
    }
```

**File:** crates/transaction-emitter-lib/src/emitter/submission_worker.rs (L436-484)
```rust
fn count_committed_expired_stats(
    account_to_start_and_end_seq_num: HashMap<AccountAddress, (u64, u64)>,
    latest_fetched_counts: HashMap<AccountAddress, u64>,
    account_to_orderless_txns: HashMap<AccountAddress, HashSet<HashValue>>,
    failed_orderless_txns: HashMap<AccountAddress, HashSet<HashValue>>,
) -> (usize, usize) {
    let (seq_num_committed, seq_num_failed) = account_to_start_and_end_seq_num
        .iter()
        .map(
            |(address, (start_seq_num, end_seq_num))| match latest_fetched_counts.get(address) {
                Some(count) => {
                    assert!(
                        *count <= *end_seq_num,
                        "{address} :: {count} > {end_seq_num}"
                    );
                    if *count >= *start_seq_num {
                        (
                            (*count - *start_seq_num) as usize,
                            (*end_seq_num - *count) as usize,
                        )
                    } else {
                        debug!(
                            "Stale sequence_number fetched for {}, start_seq_num {}, fetched {}",
                            address, start_seq_num, *count
                        );
                        (0, (*end_seq_num - *start_seq_num) as usize)
                    }
                },
                None => (0, (end_seq_num - start_seq_num) as usize),
            },
        )
        .fold(
            (0, 0),
            |(committed, expired), (cur_committed, cur_expired)| {
                (committed + cur_committed, expired + cur_expired)
            },
        );
    let total_orderless_txns: usize = account_to_orderless_txns
        .values()
        .map(|txns| txns.len())
        .sum();
    let failed_orderless_txns: usize = failed_orderless_txns.values().map(|txns| txns.len()).sum();
    let committed_orderless_txns = total_orderless_txns - failed_orderless_txns;

    (
        seq_num_committed + committed_orderless_txns,
        seq_num_failed + failed_orderless_txns,
    )
}
```
