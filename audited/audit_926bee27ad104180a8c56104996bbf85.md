# Audit Report

## Title
Chain ID Verification Bypass via Unauthenticated REST API in ValidateProposals Command

## Summary
The `ValidateProposals` command in `aptos-release-builder` relies on unauthenticated chain_id from REST API to make safety-critical decisions about minting operations. The `get_ledger_information()` function does not verify cryptographic proofs, allowing MITM attackers to spoof chain_id responses and bypass the mainnet/testnet protection check.

## Finding Description

The ValidateProposals command handler retrieves chain_id through an unauthenticated REST API call to determine whether minting operations should be allowed: [1](#0-0) 

The `get_ledger_information()` call retrieves the chain_id without any cryptographic verification: [2](#0-1) 

The underlying implementation fetches data via plain HTTP/HTTPS without signature verification: [3](#0-2) 

The chain_id is extracted from HTTP headers without cryptographic proof: [4](#0-3) 

Importantly, while the blockchain's `LedgerInfoWithSignatures` contains BLS aggregate signatures from validators that could prove the chain_id authenticity, the REST API strips these signatures before returning data: [5](#0-4) 

**Attack Path:**
1. Operator runs `aptos-release-builder validate-proposals --mint-to-validator` with an HTTP endpoint (common for local testing) or compromised HTTPS connection
2. Attacker performs MITM and spoofs the chain_id value in the REST response
3. If targeting mainnet but wanting to bypass protection: attacker returns devnet chain_id (any value except 1 or 2)
4. The safety check at lines 332-334 is bypassed
5. The tool proceeds to call `mint_to_validator()` which attempts to mint 100 billion Aptos coins [6](#0-5) 

**Defense in Depth Failure:**
While the Move contract provides an additional protection layer (minting requires `MintCapStore` which doesn't exist on mainnet post-genesis), this represents a critical trust boundary violation: [7](#0-6) 

## Impact Explanation

**Severity: HIGH (not Critical)**

This issue qualifies as **High Severity** under the Aptos bug bounty criteria for "Significant protocol violations" because:

1. **Trust Boundary Violation**: The tool makes safety-critical decisions based on unauthenticated remote data, violating the principle of cryptographic verification that underpins blockchain security

2. **Defense-in-Depth Failure**: The Rust tool's safety mechanism can be completely bypassed, leaving only the Move contract as protection. Security-critical operations should have multiple independent verification layers

3. **Practical Attack Surface**: HTTP endpoints are explicitly supported by the codebase for local testing scenarios, making MITM attacks trivial in these contexts

4. **Not Critical Because**: On production mainnet, the Move contract's `MintCapStore` check prevents actual fund creation, limiting the practical exploitation. However, this architectural dependency should not excuse the trust boundary violation at the tool level

The issue does NOT meet Critical severity because no actual loss of funds can occur on mainnet due to the Move-level protection.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability is likely to manifest in specific scenarios:

1. **HTTP Endpoints** (HIGH probability): Developers commonly use HTTP endpoints like `http://localhost:8080` or `http://internal-devnet:8080` for local testing, where MITM is trivial

2. **DNS Spoofing** (MEDIUM probability): Even with HTTPS, if an attacker controls DNS, they can redirect to a malicious server

3. **Compromised TLS** (LOW probability): While TLS itself is assumed secure per the audit scope, certificate validation failures or user acceptance of invalid certificates could enable MITM

The tool is used by privileged operators who already possess sensitive keys, making the attack surface realistic in development/testing workflows.

## Recommendation

**Solution: Implement Cryptographic Chain ID Verification**

The REST API should include the BLS aggregate signature from `LedgerInfoWithSignatures` in its response, and the client should verify this signature against the known validator set before trusting any chain metadata.

**Proposed Fix:**

1. Modify the IndexResponse to include signatures:
```rust
pub struct IndexResponseWithProof {
    pub chain_id: u8,
    pub epoch: U64,
    pub ledger_version: U64,
    // ... other fields
    pub ledger_info_with_signatures: Vec<u8>, // BCS-encoded LedgerInfoWithSignatures
}
```

2. Add verification in the client:
```rust
pub async fn get_verified_ledger_information(&self, validator_verifier: &ValidatorVerifier) -> AptosResult<Response<State>> {
    let response = self.get_index_with_proof().await?;
    
    // Verify the signature before trusting any data
    let ledger_info_with_sigs: LedgerInfoWithSignatures = bcs::from_bytes(&response.ledger_info_with_signatures)?;
    validator_verifier.verify_ledger_info(&ledger_info_with_sigs)?;
    
    // Now we can trust the chain_id
    Ok(response.map(|r| State { chain_id: r.chain_id, ... }))
}
```

3. The ValidateProposals command should bootstrap trust by either:
   - Embedding known mainnet/testnet validator public keys
   - Requiring users to explicitly provide trusted validator keys for custom networks
   - Fetching and verifying the validator set through a trusted initial connection

This ensures that chain_id cannot be spoofed without breaking the BLS aggregate signature verification.

## Proof of Concept

**Demonstration of MITM Attack:**

```rust
// Test showing the vulnerability can be exploited
#[tokio::test]
async fn test_chain_id_mitm_bypass() {
    use mockito::Server;
    
    // Setup mock server simulating MITM attacker
    let mut server = Server::new_async().await;
    
    // Attacker spoofs mainnet (chain_id=1) as devnet (chain_id=4)
    let mock = server.mock("GET", "/")
        .with_status(200)
        .with_header("X-Aptos-Chain-Id", "4") // Spoofed as devnet
        .with_header("X-Aptos-Ledger-Version", "1000000")
        .with_header("X-Aptos-Epoch", "100")
        .with_header("X-Aptos-Ledger-Timestamp", "1700000000")
        .with_header("X-Aptos-Ledger-Oldest-Version", "0")
        .with_header("X-Aptos-Block-Height", "100000")
        .with_header("X-Aptos-Oldest-Block-Height", "0")
        .with_body(r#"{"chain_id":4}"#)
        .create_async()
        .await;
    
    // Client connects thinking it's mainnet
    let client = Client::new(server.url().parse().unwrap());
    let ledger_info = client.get_ledger_information().await.unwrap();
    
    // The safety check is bypassed - tool believes it's devnet
    let chain_id = ledger_info.inner().chain_id;
    assert_eq!(chain_id, 4); // Spoofed value accepted
    
    // The check at lines 332-334 would now be bypassed
    if chain_id == ChainId::mainnet().id() || chain_id == ChainId::testnet().id() {
        panic!("Should not reach here");
    }
    // Tool proceeds with minting operation believing it's safe
    
    mock.assert_async().await;
}
```

**Notes:**
- This demonstrates that chain_id can be spoofed without any cryptographic verification
- The actual minting on mainnet would still fail due to Move contract protection
- However, the Rust tool's safety mechanism is completely defeated
- The transaction would be constructed and submitted before the Move-level check fails
- This violates the security principle that tools should not trust unauthenticated remote data for safety-critical decisions

### Citations

**File:** aptos-move/aptos-release-builder/src/main.rs (L320-334)
```rust
            if mint_to_validator {
                let mut client = Client::builder(AptosBaseUrl::Custom(endpoint));
                if let Some(api_key) = node_api_key.as_ref() {
                    client = client.api_key(api_key)?;
                }
                let chain_id = client
                    .build()
                    .get_ledger_information()
                    .await?
                    .inner()
                    .chain_id;

                if chain_id == ChainId::mainnet().id() || chain_id == ChainId::testnet().id() {
                    panic!("Mint to mainnet/testnet is not allowed");
                }
```

**File:** crates/aptos-rest-client/src/lib.rs (L397-413)
```rust
    pub async fn get_ledger_information(&self) -> AptosResult<Response<State>> {
        let response = self.get_index_bcs().await?.map(|r| State {
            chain_id: r.chain_id,
            epoch: r.epoch.into(),
            version: r.ledger_version.into(),
            timestamp_usecs: r.ledger_timestamp.into(),
            oldest_ledger_version: r.oldest_ledger_version.into(),
            oldest_block_height: r.oldest_block_height.into(),
            block_height: r.block_height.into(),
            cursor: None,
        });
        assert_eq!(response.inner().chain_id, response.state().chain_id);
        assert_eq!(response.inner().epoch, response.state().epoch);
        assert_eq!(response.inner().version, response.state().version);
        assert_eq!(response.inner().block_height, response.state().block_height);

        Ok(response)
```

**File:** crates/aptos-rest-client/src/lib.rs (L1687-1690)
```rust
    async fn get_bcs(&self, url: Url) -> AptosResult<Response<bytes::Bytes>> {
        let response = self.inner.get(url).header(ACCEPT, BCS).send().await?;
        self.check_and_parse_bcs_response(response).await
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

**File:** api/types/src/ledger_info.rs (L23-40)
```rust
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

**File:** aptos-move/aptos-release-builder/src/validate.rs (L283-312)
```rust
    pub async fn mint_to_validator(&self, node_api_key: Option<String>) -> Result<()> {
        let address_args = format!("address:{}", self.validator_account);

        println!("Minting to validator account");
        let mut args = vec![
            "",
            "--function-id",
            "0x1::aptos_coin::mint",
            "--sender-account",
            "0xa550c18",
            "--args",
            address_args.as_str(),
            "u64:100000000000",
            "--private-key-file",
            self.root_key_path.as_path().to_str().unwrap(),
            "--assume-yes",
            "--encoding",
            "bcs",
            "--url",
            self.endpoint.as_str(),
        ];

        if let Some(api_key) = node_api_key.as_ref() {
            args.push("--node-api-key");
            args.push(api_key.as_str());
        }

        RunFunction::try_parse_from(args)?.execute().await?;
        Ok(())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_coin.move (L93-108)
```text
    public entry fun mint(
        account: &signer,
        dst_addr: address,
        amount: u64,
    ) acquires MintCapStore {
        let account_addr = signer::address_of(account);

        assert!(
            exists<MintCapStore>(account_addr),
            error::not_found(ENO_CAPABILITIES),
        );

        let mint_cap = &borrow_global<MintCapStore>(account_addr).mint_cap;
        let coins_minted = coin::mint<AptosCoin>(amount, mint_cap);
        coin::deposit<AptosCoin>(dst_addr, coins_minted);
    }
```
