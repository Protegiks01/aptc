# Audit Report

## Title
REST Client ChainId Manipulation Allows Transaction Execution on Wrong Network

## Summary
The Aptos REST client and CLI do not validate the `chain_id` returned by API endpoints against expected values. An attacker controlling a REST API endpoint can return a malicious `chain_id`, causing clients to construct and sign transactions for the wrong blockchain network. When combined with endpoint control, this enables cross-network transaction replay attacks where users unknowingly execute transactions on unintended networks (e.g., mainnet instead of testnet).

## Finding Description

The vulnerability exists in how the Aptos REST client retrieves and uses the `chain_id` parameter for transaction construction.

**ChainId Retrieval without Validation:**

The REST client parses `chain_id` from HTTP response headers without any validation: [1](#0-0) 

**Blind Trust in CLI Transaction Construction:**

The Aptos CLI retrieves the `chain_id` from the API response state and directly uses it to construct transactions: [2](#0-1) 

This retrieved `chain_id` is then used to initialize the `TransactionFactory`: [3](#0-2) 

**Transaction Signing with Attacker-Controlled ChainId:**

The `chain_id` becomes part of the `RawTransaction` structure that gets signed: [4](#0-3) 

**On-Chain Validation Passes for Wrong Network:**

When the signed transaction is submitted, the on-chain validation checks that the transaction's `chain_id` matches the network's `chain_id`: [5](#0-4) 

**Attack Scenario:**

1. User intends to interact with Aptos testnet (ChainId=2)
2. Attacker controls the REST API endpoint the user connects to
3. Attacker returns mainnet `chain_id=1` in all API responses
4. User constructs transaction with `chain_id=1` (believing it's for testnet)
5. User signs transaction with their private key
6. User submits transaction via `client.submit_bcs(&transaction)` [6](#0-5) 
7. Attacker's endpoint forwards the signed transaction to mainnet
8. Transaction executes successfully on mainnet (on-chain validation passes)
9. User loses real funds thinking they were testing on testnet

**Proof of Missing Validation:**

Unlike the Rosetta API which properly validates chain_id: [7](#0-6) 

The general REST client and CLI lack any such validation, blindly trusting the API endpoint.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

1. **Significant Protocol Violation**: Users lose control over which network their transactions execute on, violating the fundamental security assumption that users can distinguish between mainnet and testnet
2. **Potential Fund Loss**: Users expecting to test on testnet may inadvertently execute transactions on mainnet, causing irreversible loss of real funds
3. **Wide Attack Surface**: Affects any user connecting to a compromised or malicious REST API endpoint, including:
   - Public API endpoints that get compromised
   - Man-in-the-middle attacks on unencrypted connections
   - Malicious infrastructure providers
   - DNS hijacking attacks

## Likelihood Explanation

**Likelihood: Medium-to-High**

**Attacker Requirements:**
- Control over a REST API endpoint (via compromise, MitM, or malicious hosting)
- User must connect to the attacker-controlled endpoint

**Factors Increasing Likelihood:**
1. Many users rely on third-party public API endpoints rather than running their own nodes
2. Users often configure custom REST URLs in their CLI profiles
3. No prominent warnings about endpoint trust in documentation
4. Attack is silent - users receive no indication they're on the wrong network
5. Common scenario: developers testing applications may use untrusted endpoints

**Factors Decreasing Likelihood:**
1. Requires endpoint compromise or MitM position
2. HTTPS connections provide some protection (but not against compromised endpoints)
3. Sophisticated users may notice network mismatch from transaction explorers

## Recommendation

Implement mandatory chain_id validation in the REST client and CLI:

**Solution 1: Client-Side Chain ID Verification**
Add a configuration option to specify the expected `chain_id` and validate all API responses:

```rust
// In crates/aptos-rest-client/src/client_builder.rs
pub struct ClientBuilder {
    // ... existing fields ...
    expected_chain_id: Option<u8>,
}

impl ClientBuilder {
    pub fn with_expected_chain_id(mut self, chain_id: u8) -> Self {
        self.expected_chain_id = Some(chain_id);
        self
    }
}

// In crates/aptos-rest-client/src/lib.rs
impl Client {
    async fn check_response(
        &self,
        response: reqwest::Response,
    ) -> AptosResult<(reqwest::Response, State)> {
        if !response.status().is_success() {
            Err(parse_error(response).await)
        } else {
            let state = parse_state(&response)?;
            
            // Validate chain_id if configured
            if let Some(expected_chain_id) = self.expected_chain_id {
                if state.chain_id != expected_chain_id {
                    return Err(RestError::Unknown(anyhow::anyhow!(
                        "Chain ID mismatch: expected {}, got {}",
                        expected_chain_id,
                        state.chain_id
                    )));
                }
            }
            
            Ok((response, state))
        }
    }
}
```

**Solution 2: CLI Profile Enhancement**
Extend CLI profiles to include expected `chain_id` and validate on every API call:

```rust
// In crates/aptos/src/config.rs
pub struct ProfileConfig {
    // ... existing fields ...
    pub expected_chain_id: Option<u8>,
}

// In transaction submission logic
let state = get_account_with_state(&client, sender_address).await?;
if let Some(expected_chain_id) = profile.expected_chain_id {
    if state.chain_id != expected_chain_id {
        return Err(CliError::ChainIdMismatch {
            expected: expected_chain_id,
            received: state.chain_id,
        });
    }
}
```

**Solution 3: Network Auto-Detection with User Confirmation**
Implement a mechanism that detects network changes and requires explicit user confirmation:

```rust
// Store last known chain_id and alert on changes
if last_known_chain_id.is_some() && last_known_chain_id != Some(state.chain_id) {
    eprintln!("WARNING: Chain ID changed from {:?} to {}!", 
              last_known_chain_id, state.chain_id);
    eprintln!("You may be connecting to a different network.");
    if !prompt_yes("Continue with this transaction?")? {
        return Err(CliError::UserCancelled);
    }
}
```

## Proof of Concept

**Setup:**
1. Create a malicious REST API proxy that intercepts responses and modifies the `chain_id` header
2. Configure Aptos CLI to use the malicious endpoint
3. Attempt to execute a transaction

**Malicious Proxy (simplified):**
```python
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # Intercept Aptos API responses
    if "aptos" in flow.request.host:
        # Change chain_id from testnet (2) to mainnet (1)
        flow.response.headers["X-Aptos-Chain-Id"] = "1"
```

**Victim CLI Execution:**
```bash
# User believes they're on testnet
aptos init --network testnet --rest-url http://malicious-proxy:8080

# User creates transaction (thinks it's for testnet)
aptos account transfer --account 0xVICTIM --amount 100000000

# Transaction gets signed with chain_id=1 (mainnet)
# Transaction gets submitted to mainnet via proxy
# Real funds are transferred on mainnet
```

**Expected Result:** Transaction executes on mainnet instead of testnet  
**Actual Result:** No validation error - transaction proceeds silently  
**Impact:** User loses real APT tokens thinking they were testing

---

## Notes

This vulnerability is particularly insidious because:
1. **Silent Failure**: No warning or error is presented to the user
2. **Trusted Infrastructure**: Users naturally trust the REST endpoints they configure
3. **Existing Precedent**: The Rosetta API implementation shows proper chain_id validation is possible and should be standard practice
4. **Defense in Depth**: Even with HTTPS, compromised endpoints remain a threat

The fix should be mandatory rather than optional, as chain_id validation is a critical security control that protects users from executing transactions on unintended networks.

### Citations

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

**File:** crates/aptos/src/common/types.rs (L1976-1976)
```rust
        let chain_id = ChainId::new(state.chain_id);
```

**File:** crates/aptos/src/common/types.rs (L2045-2048)
```rust
        let transaction_factory = TransactionFactory::new(chain_id)
            .with_gas_unit_price(gas_unit_price)
            .with_max_gas_amount(max_gas)
            .with_transaction_expiration_time(self.gas_options.expiration_secs);
```

**File:** crates/aptos/src/common/types.rs (L2085-2088)
```rust
        client
            .submit_bcs(&transaction)
            .await
            .map_err(|err| CliError::ApiError(err.to_string()))?;
```

**File:** types/src/transaction/mod.rs (L203-205)
```rust
    /// Chain ID of the Aptos network this transaction is intended for.
    chain_id: ChainId,
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L143-143)
```text
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));
```

**File:** crates/aptos-rosetta/src/construction.rs (L461-463)
```rust
    if server_context.chain_id.id() != response.state().chain_id {
        return Err(ApiError::ChainIdMismatch);
    }
```
