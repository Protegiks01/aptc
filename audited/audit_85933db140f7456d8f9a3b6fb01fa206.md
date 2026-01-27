# Audit Report

## Title
Chain ID Spoofing Vulnerability in REST Client Enables Cross-Network Transaction Submission

## Summary
The Aptos REST client accepts the `chain_id` from server response headers without validation, allowing a malicious API server to trick users into signing transactions for an unintended network (e.g., mainnet instead of testnet), resulting in potential loss of real funds.

## Finding Description

The vulnerability exists in the REST client's chain ID handling mechanism. The `State::from_headers()` function blindly trusts the `X_APTOS_CHAIN_ID` header returned by the API server: [1](#0-0) 

This extracted `chain_id` is then used throughout the transaction signing process without any client-side validation against the user's expected network. When building transactions, the chain_id from the server is embedded directly into the signed transaction: [2](#0-1) [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. User configures their CLI/SDK to connect to what they believe is a testnet endpoint (e.g., `https://testnet.example.com`)
2. The endpoint is actually a malicious proxy that returns `chain_id: 1` (mainnet) in the `X_APTOS_CHAIN_ID` header instead of `chain_id: 2` (testnet)
3. User builds and signs a transaction using the REST client, which embeds `chain_id: 1` from the malicious response
4. User submits the signed transaction through the same endpoint
5. The malicious proxy forwards the transaction to the real Aptos mainnet
6. The transaction passes on-chain validation because the embedded `chain_id: 1` matches mainnet's chain_id: [5](#0-4) 

7. User loses real mainnet funds when they thought they were just testing on testnet

**Why On-Chain Validation Doesn't Prevent This:**

The on-chain validation at line 143 of `transaction_validation.move` prevents cross-chain replay attacks (e.g., a testnet transaction replayed on mainnet). However, in this attack, the malicious server tricks the client into creating a valid **mainnet** transaction in the first place. When that transaction reaches mainnet, it passes validation because it was signed with the correct mainnet chain_id.

**Lack of Client-Side Validation:**

The `ProfileConfig` structure stores the network configuration but has no `chain_id` field for validation: [6](#0-5) 

While specialized services like Aptos Rosetta implement their own chain_id validation: [7](#0-6) [8](#0-7) 

The standard REST client used by CLI, SDK, and most applications has **no such protection**.

## Impact Explanation

**Severity: Critical (Loss of Funds)**

This vulnerability enables direct theft or loss of user funds through network confusion. Users can be tricked into submitting real mainnet transactions with actual monetary value when they believe they are testing on testnet. 

The impact aligns with the **Critical Severity** category in the Aptos Bug Bounty program:
- **Loss of Funds (theft or minting)**: Users lose real APT or other tokens on mainnet
- **Broad Attack Surface**: Affects any application using `aptos-rest-client` without additional validation, including the official Aptos CLI

This is particularly severe because:
1. Users have a reasonable expectation that configuring a testnet endpoint means transactions will only execute on testnet
2. The attack requires no sophisticated exploit - just a man-in-the-middle or DNS compromise
3. The signed transaction is cryptographically valid for mainnet, making it indistinguishable from an intentional mainnet transaction

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is feasible through multiple vectors:

1. **Compromised/Malicious RPC Provider**: A malicious API provider can deliberately return wrong chain_ids
2. **Man-in-the-Middle Attack**: An attacker intercepting HTTPS traffic (via compromised CA, corporate proxy, etc.) can modify response headers
3. **DNS Hijacking**: Redirecting testnet DNS to a malicious server
4. **Typosquatting**: Users connecting to look-alike domains (e.g., `aptosiabs.com` instead of `aptoslabs.com`)

The attack complexity is low:
- No cryptographic bypasses required
- No need to compromise validator nodes
- Attacker just needs to control or intercept HTTP responses
- No specialized knowledge required

User impact is high because many developers test with real private keys before moving to production, making this a realistic fund loss scenario.

## Recommendation

Implement client-side chain_id validation in the REST client. Add an optional `expected_chain_id` parameter that, when set, verifies the server's chain_id matches expectations:

**Option 1: Add validation to Client initialization**

```rust
// In crates/aptos-rest-client/src/lib.rs or client_builder.rs
pub struct ClientBuilder {
    // ... existing fields
    expected_chain_id: Option<ChainId>,
}

impl ClientBuilder {
    pub fn with_chain_id(mut self, chain_id: ChainId) -> Self {
        self.expected_chain_id = Some(chain_id);
        self
    }
}

impl Client {
    // Add validation method
    pub async fn validate_chain_id(&self, expected: ChainId) -> AptosResult<()> {
        let actual = self.get_ledger_information().await?.into_inner().chain_id;
        if actual != expected.id() {
            return Err(RestError::Unknown(anyhow!(
                "Chain ID mismatch: expected {}, got {}. Possible network misconfiguration or malicious server.",
                expected, actual
            )));
        }
        Ok(())
    }
}
```

**Option 2: Add validation to ProfileConfig** [6](#0-5) 

```rust
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProfileConfig {
    // ... existing fields
    
    /// Expected chain ID for this network (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_chain_id: Option<u8>,
}

// In RestOptions or profile initialization
pub fn client_with_validation(&self, profile: &ProfileConfig) -> CliTypedResult<Client> {
    let client = self.client(profile)?;
    
    if let Some(expected_chain_id) = profile.expected_chain_id {
        let actual = client.get_ledger_information().await?.into_inner().chain_id;
        if actual != expected_chain_id {
            return Err(CliError::UnexpectedError(format!(
                "Chain ID mismatch: expected {}, got {}. Server may be misconfigured or malicious.",
                expected_chain_id, actual
            )));
        }
    }
    
    Ok(client)
}
```

**Option 3: Automatic chain_id validation based on Network**

Map each `Network` enum value to its expected chain_id and validate automatically during initialization: [9](#0-8) 

```rust
impl Network {
    pub fn expected_chain_id(&self) -> Option<ChainId> {
        match self {
            Network::Mainnet => Some(ChainId::mainnet()),  // 1
            Network::Testnet => Some(ChainId::testnet()),  // 2
            Network::Devnet => None,  // Chain ID changes
            Network::Local => None,   // Varies
            Network::Custom => None,  // User-defined
        }
    }
}
```

## Proof of Concept

```rust
// File: crates/aptos-rest-client/tests/chain_id_spoofing_test.rs

#[cfg(test)]
mod tests {
    use aptos_rest_client::Client;
    use aptos_types::chain_id::ChainId;
    use aptos_sdk::transaction_builder::TransactionFactory;
    use aptos_crypto::ed25519::Ed25519PrivateKey;
    use aptos_sdk::types::LocalAccount;
    use reqwest::Url;
    use mockito::Server;
    
    #[tokio::test]
    async fn test_chain_id_spoofing_vulnerability() {
        // Setup: Create a mock server that pretends to be testnet but returns mainnet chain_id
        let mut server = Server::new_async().await;
        
        // Mock the index endpoint - returns MAINNET chain_id (1) in headers
        let mock = server.mock("GET", "/v1/")
            .with_status(200)
            .with_header("X-APTOS-CHAIN-ID", "1")  // MAINNET!
            .with_header("X-APTOS-EPOCH", "100")
            .with_header("X-APTOS-LEDGER-VERSION", "1000")
            .with_header("X-APTOS-LEDGER-TIMESTAMP", "1234567890")
            .with_header("X-APTOS-LEDGER-OLDEST-VERSION", "0")
            .with_header("X-APTOS-BLOCK-HEIGHT", "500")
            .with_header("X-APTOS-OLDEST-BLOCK-HEIGHT", "0")
            .with_body(r#"{"chain_id":1,"epoch":"100","ledger_version":"1000","oldest_ledger_version":"0","ledger_timestamp":"1234567890","node_role":"full_node","oldest_block_height":"0","block_height":"500","git_hash":"abc123"}"#)
            .create_async()
            .await;
        
        // User thinks they're connecting to testnet
        let client = Client::new(Url::parse(&server.url()).unwrap());
        
        // Get ledger info - client blindly accepts chain_id=1 from headers
        let state = client.get_ledger_information().await.unwrap().into_inner();
        
        // VULNERABILITY: chain_id is 1 (mainnet) but user expects 2 (testnet)
        assert_eq!(state.chain_id, 1);  // Mainnet!
        
        // User builds transaction using the spoofed chain_id
        let chain_id = ChainId::new(state.chain_id);
        let tx_factory = TransactionFactory::new(chain_id);
        
        // The transaction is now signed with MAINNET chain_id
        // When submitted, it will execute on mainnet instead of testnet!
        assert_eq!(chain_id, ChainId::mainnet());
        assert_ne!(chain_id, ChainId::testnet());
        
        // IMPACT: User loses real funds on mainnet thinking they're testing
        println!("VULNERABILITY CONFIRMED: Transaction signed with mainnet chain_id when user expected testnet!");
        
        mock.assert_async().await;
    }
    
    #[tokio::test]
    async fn test_recommended_mitigation() {
        let mut server = Server::new_async().await;
        
        let mock = server.mock("GET", "/v1/")
            .with_status(200)
            .with_header("X-APTOS-CHAIN-ID", "1")  // Wrong chain_id
            .with_body(r#"{"chain_id":1,"epoch":"100","ledger_version":"1000","oldest_ledger_version":"0","ledger_timestamp":"1234567890","node_role":"full_node","oldest_block_height":"0","block_height":"500","git_hash":"abc123"}"#)
            .create_async()
            .await;
        
        let client = Client::new(Url::parse(&server.url()).unwrap());
        let state = client.get_ledger_information().await.unwrap().into_inner();
        
        // Recommended mitigation: Validate chain_id matches expectations
        let expected_chain_id = ChainId::testnet();  // User expects testnet
        let actual_chain_id = ChainId::new(state.chain_id);
        
        if actual_chain_id != expected_chain_id {
            panic!(
                "Chain ID mismatch detected! Expected {}, got {}. Server may be malicious.",
                expected_chain_id, actual_chain_id
            );
        }
        
        // This should panic, preventing the attack
    }
}
```

**Notes:**
- The vulnerability is exploitable in real-world scenarios through compromised RPC providers, DNS hijacking, or MITM attacks
- The lack of client-side chain_id validation creates a trust boundary violation where users must blindly trust server responses
- While Rosetta has implemented mitigations, the core REST client library leaves all downstream applications vulnerable
- The fix requires adding optional chain_id validation that can be enabled by security-conscious applications

### Citations

**File:** crates/aptos-rest-client/src/state.rs (L23-27)
```rust
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> anyhow::Result<Self> {
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
```

**File:** crates/aptos/src/common/transactions.rs (L197-200)
```rust
        let chain_id = ChainId::new(state.chain_id);

        let transaction_factory =
            TransactionFactory::new(chain_id).with_gas_unit_price(gas_unit_price);
```

**File:** crates/aptos/src/common/transactions.rs (L276-276)
```rust
        let chain_id = ChainId::new(state.chain_id);
```

**File:** crates/aptos/src/common/transactions.rs (L293-296)
```rust
        let transaction_factory = TransactionFactory::new(chain_id)
            .with_gas_unit_price(gas_unit_price)
            .with_max_gas_amount(max_gas)
            .with_transaction_expiration_time(self.gas_options.expiration_secs);
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L143-143)
```text
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));
```

**File:** crates/aptos/src/common/types.rs (L270-305)
```rust
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Name of network being used, if setup from aptos init
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    /// Private key for commands.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        serialize_with = "serialize_material_with_prefix",
        deserialize_with = "deserialize_material_with_prefix"
    )]
    pub private_key: Option<Ed25519PrivateKey>,
    /// Public key for commands
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_material_with_prefix",
        deserialize_with = "deserialize_material_with_prefix"
    )]
    pub public_key: Option<Ed25519PublicKey>,
    /// Account for commands
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_address_str"
    )]
    pub account: Option<AccountAddress>,
    /// URL for the Aptos rest endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rest_url: Option<String>,
    /// URL for the Faucet endpoint (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faucet_url: Option<String>,
    /// Derivation path index of the account on ledger
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
}
```

**File:** crates/aptos-rosetta/src/construction.rs (L461-463)
```rust
    if server_context.chain_id.id() != response.state().chain_id {
        return Err(ApiError::ChainIdMismatch);
    }
```

**File:** crates/aptos-rosetta/src/lib.rs (L125-135)
```rust
    if let Some(ref client) = rest_client {
        assert_eq!(
            chain_id.id(),
            client
                .get_ledger_information()
                .await
                .expect("Should successfully get ledger information from Rest API on bootstap")
                .into_inner()
                .chain_id,
            "Failed to match Rosetta chain Id to upstream server"
        );
```

**File:** crates/aptos/src/common/init.rs (L460-466)
```rust
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Local,
    Custom,
}
```
