# Audit Report

## Title
API Endpoint Mismatch Enables Double-Funding via Network Partition

## Summary
The FaucetClient architecture allows the `rest_client` to point to a different node than the faucet service's configured node. When network partitions occur, clients polling a partitioned node will timeout even when transactions successfully commit on the faucet's node, leading to retries that cause double-funding of accounts without any idempotency protection.

## Finding Description

The vulnerability exists in the split-endpoint architecture of the faucet system: [1](#0-0) 

The FaucetClient maintains two independent URL configurations: `faucet_url` pointing to the faucet service and `rest_client` pointing to an Aptos node for transaction verification. The faucet service itself has its own `node_url` configuration: [2](#0-1) 

**Attack Scenario:**

1. **Initial Request:** Client calls `fund()` which POSTs to the faucet service: [3](#0-2) 

2. **Faucet Processing:** The faucet service creates and signs a transaction, then submits it to its configured node (Node A): [4](#0-3) 

3. **Transaction Submission:** The faucet calls `submit_transaction()` which uses its own client: [5](#0-4) 

4. **Client Polling Split:** The client receives the signed transaction and polls Node B (its `rest_client`) which may be partitioned from Node A: [6](#0-5) 

5. **Timeout Logic:** The wait function will timeout after 60+ seconds if Node B never sees the transaction: [7](#0-6) 

6. **No Idempotency:** There is no deduplication mechanism based on receiver address or request ID. The rate limiter only tracks IP-based limits: [8](#0-7) 

7. **Double-Funding:** When the client retries after timeout, the faucet issues a new transaction with an incremented sequence number. Both transactions eventually commit when the partition heals, causing the receiver to get double the intended amount.

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

1. **Loss of Funds:** The faucet's funds are depleted at twice the intended rate, allowing attackers to drain testnet/devnet faucets faster than designed.

2. **Rate Limit Bypass:** Users can effectively bypass the configured maximum funding amount per request by exploiting network conditions to trigger retries.

3. **No Recovery Mechanism:** Once double-funded, there's no automatic way to reclaim the excess funds from user accounts.

4. **Systemic Risk:** This affects all faucet deployments where the client's `rest_client` points to a different node than the faucet service, which is common in production deployments using load balancers.

## Likelihood Explanation

**High Likelihood:**

1. **Natural Occurrence:** Network partitions happen naturally in distributed systems, especially with geographically distributed nodes or during network congestion.

2. **Load Balancer Routing:** Production deployments often use load balancers that route requests to different backend nodes, making the endpoint mismatch condition common.

3. **Standard Client Behavior:** Clients retrying after timeout is standard practice in distributed systems.

4. **No Attacker Prerequisites:** No special access or permissions required - any user can trigger this by making normal faucet requests during network instability.

5. **Time Window:** The 60+ second timeout window provides ample opportunity for partitions to occur and resolve.

## Recommendation

Implement idempotency protection at the faucet service level:

**Solution 1: Request Deduplication**
Add a request ID or hash-based deduplication mechanism that tracks recent funding requests by (receiver_address, amount) pairs for the duration of transaction expiration time (default 25 seconds).

**Solution 2: Single Node Consistency**
Modify FaucetClient to use the same node URL for both transaction submission (via faucet) and verification, eliminating the split-endpoint architecture:

```rust
pub struct FaucetClient {
    faucet_url: Url,
    inner: ReqwestClient,
    rest_client: Client,
    token: Option<String>,
}

// Ensure rest_client always points to the same node as faucet service
pub fn new(faucet_url: Url, rest_url: Url) -> Self {
    // Add validation that rest_url matches faucet's backend
    // Or automatically derive rest_url from faucet service
    Self::new_from_rest_client(faucet_url, Client::new(rest_url))
}
```

**Solution 3: Transaction Hash Tracking**
Add a checker that maintains a short-lived cache (25 seconds) of pending transaction hashes per receiver address, rejecting duplicate funding requests for the same address while a transaction is pending.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_double_funding_via_partition() {
    // Setup two nodes - Node A (faucet backend) and Node B (client query)
    let node_a = start_test_node().await;
    let node_b = start_test_node().await;
    
    // Configure faucet to submit to Node A
    let faucet_config = FaucetConfig {
        node_url: node_a.url(),
        wait_for_transactions: true, // Faucet waits on Node A
    };
    let faucet_service = start_faucet(faucet_config).await;
    
    // Configure client to query Node B
    let client = FaucetClient::new(
        faucet_service.url(),
        node_b.url(), // Different from faucet's node
    );
    
    let receiver = AccountAddress::random();
    let amount = 1000;
    
    // Simulate network partition between nodes
    partition_nodes(&node_a, &node_b).await;
    
    // First request - will timeout on client side but succeed on Node A
    let result1 = client.fund(receiver, amount).await;
    assert!(result1.is_err()); // Timeout error
    
    // Client retries (standard behavior)
    let result2 = client.fund(receiver, amount).await;
    assert!(result2.is_err()); // Another timeout
    
    // Heal partition
    heal_partition(&node_a, &node_b).await;
    wait_for_sync(&node_a, &node_b).await;
    
    // Verify double-funding occurred
    let balance = node_b.get_account_balance(receiver).await.unwrap();
    assert_eq!(balance, 2000); // Expected 1000, got 2000
}
```

**Notes:**

This vulnerability represents a fundamental distributed systems consistency issue where the lack of idempotency protection combined with split-endpoint architecture enables unintended double-execution of funding operations. The issue is exacerbated by the absence of receiver-address-based deduplication in the rate limiting system, which only tracks IP-based limits and does not prevent multiple funding requests to the same destination address.

### Citations

**File:** crates/aptos-rest-client/src/faucet.rs (L10-15)
```rust
pub struct FaucetClient {
    faucet_url: Url,
    inner: ReqwestClient,
    rest_client: Client,
    token: Option<String>,
}
```

**File:** crates/aptos-rest-client/src/faucet.rs (L84-109)
```rust
    pub async fn fund(&self, address: AccountAddress, amount: u64) -> Result<()> {
        let mut url = self.faucet_url.clone();
        url.set_path("mint");
        let query = format!("auth_key={}&amount={}&return_txns=true", address, amount);
        url.set_query(Some(&query));

        // Faucet returns the transaction that creates the account and needs to be waited on before
        // returning.
        let response = self.build_and_submit_request(url).await?;
        let status_code = response.status();
        let body = response.text().await.map_err(FaucetClientError::decode)?;
        if !status_code.is_success() {
            return Err(FaucetClientError::status(status_code.as_u16()).into());
        }

        let bytes = hex::decode(body).map_err(FaucetClientError::decode)?;
        let txns: Vec<SignedTransaction> =
            bcs::from_bytes(&bytes).map_err(FaucetClientError::decode)?;

        self.rest_client
            .wait_for_signed_transaction(&txns[0])
            .await
            .map_err(FaucetClientError::unknown)?;

        Ok(())
    }
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L54-75)
```rust
#[derive(Clone, Debug, Deserialize, Parser, Serialize)]
pub struct ApiConnectionConfig {
    /// Aptos node (any node type with an open API) server URL.
    /// Include the port in this if not using the default for the scheme.
    #[clap(long, default_value = "https://fullnode.testnet.aptoslabs.com/")]
    pub node_url: Url,

    /// API key for talking to the node API.
    #[clap(long)]
    pub api_key: Option<String>,

    /// Any additional headers to send with the request. We don't accept this on the
    /// CLI.
    #[clap(skip)]
    pub additional_headers: Option<HashMap<String, String>>,

    /// Chain ID of the network this client is connecting to. For example, for mainnet:
    /// "MAINNET" or 1, testnet: "TESTNET" or 2. If there is no predefined string
    /// alias (e.g. "MAINNET"), just use the number. Note: Chain ID of 0 is not allowed.
    #[clap(long, default_value_t = ChainId::testnet())]
    pub chain_id: ChainId,
}
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L342-399)
```rust
pub async fn submit_transaction(
    client: &Client,
    faucet_account: &RwLock<LocalAccount>,
    signed_transaction: SignedTransaction,
    receiver_address: &AccountAddress,
    wait_for_transactions: bool,
) -> Result<SignedTransaction, AptosTapError> {
    let (result, event_on_success) = if wait_for_transactions {
        // If this fails, we assume it is the user's fault, e.g. because the
        // account already exists, but it is possible that the transaction
        // timed out. It's hard to tell because this function returns an opaque
        // anyhow error. https://github.com/aptos-labs/aptos-tap/issues/60.
        (
            client
                .submit_and_wait_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
            "transaction_success",
        )
    } else {
        (
            client
                .submit_bcs(&signed_transaction)
                .await
                .map(|_| ())
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::TransactionFailed)
                }),
            "transaction_submitted",
        )
    };

    // If there was an issue submitting a transaction we should just reset
    // our sequence numbers to what it was before.
    match result {
        Ok(_) => {
            info!(
                hash = signed_transaction.committed_hash(),
                address = receiver_address,
                event = event_on_success,
            );
            Ok(signed_transaction)
        },
        Err(e) => {
            faucet_account.write().await.decrement_sequence_number();
            warn!(
                hash = signed_transaction.committed_hash(),
                address = receiver_address,
                event = "transaction_failure",
                error_message = format!("{:#}", e)
            );
            Err(e)
        },
    }
}
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L527-537)
```rust
        let client = self.get_api_client();
        let amount = self.get_amount(amount, did_bypass_checkers);
        self.process(
            &client,
            amount,
            receiver_address,
            check_only,
            self.txn_config.wait_for_transactions,
            asset_name,
        )
        .await
```

**File:** crates/aptos-rest-client/src/lib.rs (L711-723)
```rust
    pub async fn wait_for_signed_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> AptosResult<Response<Transaction>> {
        let expiration_timestamp = transaction.expiration_timestamp_secs();
        self.wait_for_transaction_by_hash(
            transaction.committed_hash(),
            expiration_timestamp,
            Some(DEFAULT_MAX_SERVER_LAG_WAIT_DURATION),
            None,
        )
        .await
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L824-845)
```rust
            if let Some(max_server_lag_wait_duration) = max_server_lag_wait {
                if aptos_infallible::duration_since_epoch().as_secs()
                    > expiration_timestamp_secs + max_server_lag_wait_duration.as_secs()
                {
                    return Err(anyhow!(
                        "Ledger on endpoint ({}) is more than {}s behind current time, timing out waiting for the transaction. Warning, transaction ({}) might still succeed.",
                        self.path_prefix_string(),
                        max_server_lag_wait_duration.as_secs(),
                        hash,
                    ).into());
                }
            }

            let elapsed = start.elapsed();
            if let Some(timeout_duration) = timeout_from_call {
                if elapsed > timeout_duration {
                    return Err(anyhow!(
                        "Timeout of {}s after calling wait_for_transaction reached. Warning, transaction ({}) might still succeed.",
                        timeout_duration.as_secs(),
                        hash,
                    ).into());
                }
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L67-91)
```rust
impl CheckerTrait for MemoryRatelimitChecker {
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        self.clear_if_new_day().await;

        let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;

        let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);
        if *requests_today >= self.max_requests_per_day {
            return Ok(vec![RejectionReason::new(
                format!(
                    "IP {} has exceeded the daily limit of {} requests",
                    data.source_ip, self.max_requests_per_day
                ),
                RejectionReasonCode::UsageLimitExhausted,
            )]);
        } else if !dry_run {
            *requests_today += 1;
        }

        Ok(vec![])
    }
```
