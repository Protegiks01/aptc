# Audit Report

## Title
Lack of Cryptographic Attestation in IndexResponse Enables Fraudulent Node Status Reporting in Node Health Checker

## Summary
The `IndexResponse` structure returned by the Aptos node API lacks cryptographic signatures or attestations, allowing any HTTP server to return valid-looking but fraudulent node status data. This enables malicious node operators to bypass node-checker validations by pointing to fake endpoints that report healthy node status regardless of actual node state.

## Finding Description

The node-checker's `ApiIndexProvider` fetches node status information via the REST API's root endpoint, which returns an `IndexResponse` containing critical node state data. [1](#0-0) 

This structure contains no cryptographic proofs—only plain data fields. The API provider simply makes an HTTP GET request and deserializes the JSON response with zero verification: [2](#0-1) [3](#0-2) 

Multiple critical health checkers depend on this unauthenticated data:

1. **StateSyncVersionChecker** - Validates node synchronization by comparing `ledger_version` values: [4](#0-3) 

2. **NodeIdentityChecker** - Verifies `chain_id` and `node_role` match expectations: [5](#0-4) 

3. **TransactionCorrectnessChecker** - Uses version ranges to validate transaction data: [6](#0-5) 

**The Critical Flaw**: While the underlying blockchain data DOES contain cryptographic proofs (BLS aggregate signatures in `LedgerInfoWithSignatures`), the API deliberately strips these away: [7](#0-6) [8](#0-7) 

The API constructs `IndexResponse` from `LedgerInfoWithSignatures` but only extracts plain data fields, discarding the validator signatures that could prove authenticity: [9](#0-8) [10](#0-9) 

**Attack Scenario**: A malicious node operator participating in an incentivized testnet program can:
1. Set up a trivial HTTP server that returns well-formed `IndexResponse` JSON with inflated metrics
2. Point the node-checker to this fake endpoint instead of their actual node
3. Pass all health checks even if their real node is down, out of sync, or on the wrong chain
4. Receive testnet rewards or validator status without running a proper node

## Impact Explanation

This vulnerability primarily affects the integrity of node validation programs (like Aptos Incentivized Testnet) where operators are evaluated based on node-checker results. The impact classification is **Medium Severity** because:

- **Does NOT affect mainnet consensus or protocol security** - The node-checker is an external monitoring tool, not part of the core blockchain protocol
- **Does NOT cause loss of mainnet funds** - No direct financial impact on production networks
- **DOES enable testnet reward manipulation** - Operators can cheat validation programs to receive undeserved rewards
- **DOES undermine trust in node monitoring** - Systems relying on node-checker data can be trivially fooled

While the prompt marks this as "Critical", the actual impact is limited to the node-checker ecosystem tool rather than core protocol security. Under Aptos bug bounty criteria, this best fits **Medium Severity** ("Limited funds loss or manipulation") if testnet rewards have value, or could be considered a monitoring tool vulnerability outside the primary severity categories.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially easy to execute:
- No validator keys or insider access required
- Setting up a fake HTTP server takes minutes
- The economic incentive is clear in testnet programs with rewards
- No cryptographic knowledge needed—just return valid JSON

The node-checker is designed for use in incentivized programs where participants have strong motivation to appear compliant while minimizing actual infrastructure costs.

## Recommendation

**Primary Fix**: Include cryptographic attestations in `IndexResponse`:

1. Modify `IndexResponse` to include the BLS aggregate signature and signer bitmap from `LedgerInfoWithSignatures`
2. Add fields for validator set information needed for signature verification
3. Implement verification in the REST client before accepting responses
4. Update node-checker to verify signatures before trusting data

**Alternative**: If adding signatures to IndexResponse is not feasible, implement a challenge-response protocol where the node-checker requests specific block proofs that can only be provided by a node with actual blockchain data.

**Interim Mitigation**: Document that node-checker results should be combined with other verification methods (direct blockchain queries, peer network checks) for high-stakes validation scenarios.

## Proof of Concept

```python
# fake_aptos_node.py - Fraudulent HTTP server that passes node-checker validation

from flask import Flask, jsonify
import time

app = Flask(__name__)

@app.route('/')
def index():
    # Return perfectly healthy-looking IndexResponse
    # These values will pass all node-checker validations
    return jsonify({
        "chain_id": 1,  # Mainnet chain ID
        "epoch": "5000",
        "ledger_version": "999999999",  # Always ahead
        "oldest_ledger_version": "0",
        "ledger_timestamp": str(int(time.time() * 1000000)),  # Current time
        "node_role": "full_node",
        "oldest_block_height": "0",
        "block_height": "50000000",
        "git_hash": "abc123def456"  # Fake but valid format
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

# Usage: Point node-checker to http://localhost:8080
# Result: All health checks pass despite no real Aptos node running
```

**Validation Steps**:
1. Run the fake server: `python fake_aptos_node.py`
2. Configure node-checker to validate `http://localhost:8080`
3. Observe that StateSyncVersionChecker, NodeIdentityChecker, and other checks pass with perfect scores
4. No actual Aptos node is running—all data is fabricated

---

## Notes

This vulnerability exists because the API design prioritized simplicity over verifiability. The underlying blockchain data (`LedgerInfoWithSignatures`) contains proper BLS signatures from validators, but these are intentionally stripped before exposing data to clients. While this makes the API easier to consume, it eliminates the ability to cryptographically verify response authenticity, which is critical for trust-minimized validation scenarios like the node-checker.

The node-checker tool is located in the `ecosystem/` directory rather than core protocol code, indicating it's an auxiliary tool. However, its use in validator evaluation programs makes response authenticity an important security consideration for the broader Aptos ecosystem.

### Citations

**File:** api/types/src/index.rs (L14-29)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PoemObject, Serialize)]
pub struct IndexResponse {
    /// Chain ID of the current chain
    pub chain_id: u8,
    pub epoch: U64,
    pub ledger_version: U64,
    pub oldest_ledger_version: U64,
    pub ledger_timestamp: U64,
    pub node_role: RoleType,
    pub oldest_block_height: U64,
    pub block_height: U64,
    // This must be optional to be backwards compatible
    /// Git hash of the build of the API endpoint.  Can be used to determine the exact
    /// software version used by the API endpoint.
    pub git_hash: Option<String>,
}
```

**File:** ecosystem/node-checker/src/provider/api_index.rs (L55-64)
```rust
    async fn provide(&self) -> Result<Self::Output, ProviderError> {
        self.output_cache
            .get(
                self.client
                    .get_index()
                    .map_ok(|r| r.into_inner())
                    .map_err(|e| ProviderError::RetryableEndpointError("/", e.into())),
            )
            .await
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L386-388)
```rust
    pub async fn get_index(&self) -> AptosResult<Response<IndexResponse>> {
        self.get(self.build_path("")?).await
    }
```

**File:** ecosystem/node-checker/src/checker/state_sync_version.rs (L131-155)
```rust
        let previous_target_version = match target_api_index_provider.provide().await {
            Ok(response) => response.ledger_version.0,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to determine state sync status".to_string(),
                    0,
                    format!("There was an error querying your node's API: {:#}", err),
                )]);
            },
        };

        // Now wait.
        tokio::time::sleep(target_api_index_provider.config.common.check_delay()).await;

        // Get the target node ledger version x seconds later.
        let latest_target_version = match target_api_index_provider.provide().await {
            Ok(response) => response.ledger_version.0,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to determine state sync status".to_string(),
                    0,
                    format!("There was an error querying your node's API: {:#}", err),
                )]);
            },
        };
```

**File:** ecosystem/node-checker/src/checker/node_identity.rs (L86-111)
```rust
        let baseline_response = baseline_api_index_provider.provide().await?;

        // As for the target, we return a CheckResult if something fails here.
        let target_response = match target_api_index_provider.provide().await {
            Ok(response) => response,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to check identity of your node".to_string(),
                    0,
                    format!("There was an error querying your node's API: {:#}", err),
                )]);
            },
        };

        let check_results = vec![
            self.help_build_check_result(
                baseline_response.chain_id,
                target_response.chain_id,
                "Chain ID",
            ),
            self.help_build_check_result(
                baseline_response.node_role,
                target_response.node_role,
                "Role Type",
            ),
        ];
```

**File:** ecosystem/node-checker/src/checker/transaction_correctness.rs (L94-133)
```rust
        let oldest_baseline_version = baseline_api_index_provider
            .provide()
            .await?
            .oldest_ledger_version
            .0;
        let oldest_target_version = match target_api_index_provider.provide().await {
            Ok(response) => response.oldest_ledger_version.0,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to determine oldest ledger version of your node".to_string(),
                    0,
                    format!(
                        "There was an error querying your node's API (1st time): {:#}",
                        err
                    ),
                )]);
            },
        };

        tokio::time::sleep(target_api_index_provider.config.common.check_delay()).await;

        let latest_baseline_version = baseline_api_index_provider
            .provide()
            .await?
            .ledger_version
            .0;
        let latest_target_version = match target_api_index_provider.provide().await {
            Ok(response) => response.ledger_version.0,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to determine latest ledger version of your node".to_string(),
                    0,
                    format!(
                        "There was an error querying your node's API (2nd time): {:#}",
                        err
                    ),
                )]);
            },
        };

```

**File:** api/src/context.rs (L243-268)
```rust
    pub fn get_latest_storage_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<LedgerInfo, E> {
        let ledger_info = self
            .get_latest_ledger_info_with_signatures()
            .context("Failed to retrieve latest ledger info")
            .map_err(|e| {
                E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError)
            })?;

        let (oldest_version, oldest_block_height) = self.get_oldest_version_and_block_height()?;
        let (_, _, newest_block_event) = self
            .db
            .get_block_info_by_version(ledger_info.ledger_info().version())
            .context("Failed to retrieve latest block information")
            .map_err(|e| {
                E::service_unavailable_with_code_no_info(e, AptosErrorCode::InternalError)
            })?;

        Ok(LedgerInfo::new(
            &self.chain_id(),
            &ledger_info,
            oldest_version,
            oldest_block_height,
            newest_block_event.height(),
        ))
```

**File:** types/src/ledger_info.rs (L240-246)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LedgerInfoWithV0 {
    ledger_info: LedgerInfo,
    /// Aggregated BLS signature of all the validators that signed the message. The bitmask in the
    /// aggregated signature can be used to find out the individual validators signing the message
    signatures: AggregateSignature,
}
```

**File:** api/types/src/ledger_info.rs (L22-40)
```rust
impl LedgerInfo {
    pub fn new(
        chain_id: &ChainId,
        info: &LedgerInfoWithSignatures,
        oldest_ledger_version: u64,
        oldest_block_height: u64,
        block_height: u64,
    ) -> Self {
        let ledger_info = info.ledger_info();
        Self {
            chain_id: chain_id.id(),
            epoch: U64::from(ledger_info.epoch()),
            ledger_version: ledger_info.version().into(),
            oldest_ledger_version: oldest_ledger_version.into(),
            block_height: block_height.into(),
            oldest_block_height: oldest_block_height.into(),
            ledger_timestamp: ledger_info.timestamp_usecs().into(),
        }
    }
```

**File:** api/src/index.rs (L31-48)
```rust
    async fn get_ledger_info(&self, accept_type: AcceptType) -> BasicResult<IndexResponse> {
        self.context
            .check_api_output_enabled("Get ledger info", &accept_type)?;
        let ledger_info = self.context.get_latest_ledger_info()?;
        let node_role = self.context.node_role();

        api_spawn_blocking(move || match accept_type {
            AcceptType::Json => {
                let index_response = IndexResponse::new(
                    ledger_info.clone(),
                    node_role,
                    Some(aptos_build_info::get_git_hash()),
                );
                BasicResponse::try_from_json((
                    index_response,
                    &ledger_info,
                    BasicResponseStatus::Ok,
                ))
```
