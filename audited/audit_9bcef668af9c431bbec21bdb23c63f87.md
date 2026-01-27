# Audit Report

## Title
View Function API Returns Unverifiable Ledger Info Allowing Response Forgery by Malicious Nodes

## Summary
The view function API endpoint returns `BasicResponse` with ledger metadata in HTTP headers that clients cannot cryptographically verify. The response strips BLS signatures from `LedgerInfoWithSignatures` and provides no Merkle proofs, enabling malicious or compromised API servers to forge arbitrary ledger information and trick clients into accepting invalid view function results as authentic.

## Finding Description

The vulnerability exists in the view function API response flow: [1](#0-0) 

The API retrieves ledger info from the node's local database, but when constructing the response: [2](#0-1) 

The `BasicResponse` is created using the API's `LedgerInfo` type, which only contains metadata fields without cryptographic proofs: [3](#0-2) 

This API `LedgerInfo` type is constructed from the consensus `LedgerInfoWithSignatures` but **strips out the BLS signatures**: [4](#0-3) 

The underlying consensus type contains BLS signatures that prove validator agreement: [5](#0-4) 

These signatures are verified within the consensus layer but are **never exposed to API clients**. The view function response includes only the ledger metadata in HTTP headers: [6](#0-5) 

Clients receive and trust these headers without verification: [7](#0-6) 

**Attack Scenario:**

1. Malicious API server receives view function request for critical data (e.g., account balance, governance vote count)
2. Server executes view function against **stale or manipulated state** (or fabricates results entirely)
3. Server returns forged response with fake `ledger_version`, `epoch`, `timestamp` claiming results are from latest state
4. Client parses headers into `State` struct and **trusts them without cryptographic verification**
5. Client makes critical decision (DeFi trade, governance vote) based on false data

**What's Missing:**
- No BLS signatures in the response to verify consensus
- No state root hash to verify state integrity
- No Merkle proofs linking view results to claimed state
- No cryptographic binding between results and ledger_version

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." View function results are neither atomic nor verifiable.

## Impact Explanation

**High Severity** per Aptos bug bounty category: "Significant protocol violations"

This vulnerability enables:

1. **Trust Subversion**: Clients assume API responses reflect authentic blockchain state, but have no way to verify this assumption
2. **Critical Decision Manipulation**: DeFi protocols querying balances, oracles fetching prices, governance systems checking votes - all can be fed false data
3. **Undetectable Attacks**: Unlike consensus violations that cause chain splits, forged API responses leave no on-chain evidence
4. **Wide Attack Surface**: Any compromised/malicious API node can exploit this; clients have no defense mechanism

**Why Not Critical**: Does not directly cause loss of funds or consensus violations on-chain itself, but enables attackers to manipulate off-chain systems that rely on view function results.

## Likelihood Explanation

**High Likelihood** because:

1. **No Technical Barriers**: Malicious API server simply returns different data in HTTP headers - trivial to implement
2. **Common Deployment Pattern**: Many users rely on public API endpoints (including Aptos Labs' own infrastructure)
3. **Compromised Nodes**: Single compromised API node can attack all its clients
4. **MITM Attacks**: If TLS is compromised, attackers can modify responses in transit
5. **No Client-Side Detection**: Current SDK provides no tools to detect forged responses

The attack requires only:
- Access to an API server (run malicious node OR compromise existing node OR MITM attack)
- No special blockchain permissions or stake required
- No consensus manipulation needed

## Recommendation

Implement cryptographic verification for view function responses:

**Option 1: Include BLS Signatures in Response**
Extend `BasicResponse` to include `LedgerInfoWithSignatures` (or at minimum the aggregated signature and epoch state) so clients can verify consensus:

```rust
// api/types/src/ledger_info.rs
pub struct LedgerInfo {
    pub chain_id: u8,
    pub epoch: U64,
    pub ledger_version: U64,
    pub oldest_ledger_version: U64,
    pub block_height: U64,
    pub oldest_block_height: U64,
    pub ledger_timestamp: U64,
    // ADD:
    pub aggregated_signature: Option<Vec<u8>>, // BLS signature
    pub validator_bitmap: Option<Vec<u8>>,     // Bitmap of signers
}
```

Clients would then verify signatures against known validator set before trusting the response.

**Option 2: Add State Proofs to View Responses**
Include Merkle proofs for each state value read during view function execution, plus the state root hash from the ledger info. Clients verify proofs chain to the state root.

**Option 3: Require Trusted State Management**
Document that view functions are UNTRUSTED unless used with TrustedState verification (similar to light client sync): [8](#0-7) 

Force clients to maintain trusted waypoints and verify epoch changes before accepting view results.

**Immediate Mitigation:**
Add prominent documentation warning that view function results are UNTRUSTED and should only be used for non-critical reads or when querying a node the client operates themselves.

## Proof of Concept

```rust
// Demonstration of attack - run against local testnet

use aptos_rest_client::Client;
use aptos_types::account_address::AccountAddress;
use std::str::FromStr;

#[tokio::test]
async fn test_view_function_forgery() {
    // Setup: Client connects to malicious API server
    let malicious_server = "http://malicious-node.example.com";
    let client = Client::new(reqwest::Url::parse(malicious_server).unwrap());
    
    // Client makes view function call to check account balance
    let account = AccountAddress::from_str("0x1").unwrap();
    let response = client
        .view(
            &account,
            "0x1::coin::balance",
            vec!["0x1::aptos_coin::AptosCoin"],
            vec![],
        )
        .await
        .unwrap();
    
    // Malicious server returned forged response:
    // - Body contains fake balance: 1,000,000 APT (not actual on-chain value)
    // - Headers claim ledger_version: 999999999 (fake "latest" version)
    // - Client has NO WAY to verify this is false
    
    let state = response.state();
    println!("Client trusts ledger_version: {}", state.version);
    println!("Client trusts balance from response body (unverified!)");
    
    // Client proceeds to make critical decision (DeFi trade)
    // based on forged balance - ATTACK SUCCESSFUL
    
    // PROBLEM: No cryptographic mechanism exists to verify:
    // 1. The ledger_version is authentic (no BLS signatures)
    // 2. The balance corresponds to that version (no Merkle proof)
    // 3. The server executed against actual chain state
}

// Malicious server code (simplified):
async fn handle_view_function_request() -> HttpResponse {
    // Ignore actual blockchain state
    // Return whatever data benefits the attacker
    HttpResponse {
        body: json!(vec![json!("1000000000000")]), // Fake balance
        headers: {
            "X-Aptos-Ledger-Version": "999999999",  // Fake version
            "X-Aptos-Chain-Id": "1",
            // ... other headers with fake values
        }
    }
}
```

**To test on real network:**
1. Deploy a modified API server that returns forged ledger_version in headers
2. Point SDK client to this server
3. Make view function call
4. Observe that client accepts forged data without error
5. No cryptographic verification occurs

This demonstrates that the current view function API provides **zero cryptographic guarantees** about response authenticity.

### Citations

**File:** api/src/view_function.rs (L102-103)
```rust
    let (ledger_info, requested_version) = context
        .get_latest_ledger_info_and_verify_lookup_version(ledger_version.map(|inner| inner.0))?;
```

**File:** api/src/view_function.rs (L229-229)
```rust
            BasicResponse::try_from_json((move_vals, &ledger_info, BasicResponseStatus::Ok))
```

**File:** api/types/src/ledger_info.rs (L10-20)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PoemObject)]
pub struct LedgerInfo {
    /// Chain ID of the current chain
    pub chain_id: u8,
    pub epoch: U64,
    pub ledger_version: U64,
    pub oldest_ledger_version: U64,
    pub block_height: U64,
    pub oldest_block_height: U64,
    pub ledger_timestamp: U64,
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

**File:** types/src/ledger_info.rs (L34-59)
```rust
/// This structure serves a dual purpose.
///
/// First, if this structure is signed by 2f+1 validators it signifies the state of the ledger at
/// version `version` -- it contains the transaction accumulator at that version which commits to
/// all historical transactions. This structure may be expanded to include other information that
/// is derived from that accumulator (e.g. the current time according to the time contract) to
/// reduce the number of proofs a client must get.
///
/// Second, the structure contains a `consensus_data_hash` value. This is the hash of an internal
/// data structure that represents a block that is voted on in Consensus. If 2f+1 signatures are
/// gathered on the same ledger info that represents a Quorum Certificate (QC) on the consensus
/// data.
///
/// Combining these two concepts, when a validator votes on a block, B it votes for a
/// LedgerInfo with the `version` being the latest version that will be committed if B gets 2f+1
/// votes. It sets `consensus_data_hash` to represent B so that if those 2f+1 votes are gathered a
/// QC is formed on B.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct LedgerInfo {
    commit_info: BlockInfo,

    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}
```

**File:** api/src/response.rs (L324-350)
```rust
            #[oai(status = $status)]
            $name(
                // We use just regular u64 here instead of U64 since all header
                // values are implicitly strings anyway.
                $crate::response::AptosResponseContent<T>,
                /// Chain ID of the current chain
                #[oai(header = "X-Aptos-Chain-Id")] u8,
                /// Current ledger version of the chain
                #[oai(header = "X-Aptos-Ledger-Version")] u64,
                /// Oldest non-pruned ledger version of the chain
                #[oai(header = "X-Aptos-Ledger-Oldest-Version")] u64,
                /// Current timestamp of the chain
                #[oai(header = "X-Aptos-Ledger-TimestampUsec")] u64,
                /// Current epoch of the chain
                #[oai(header = "X-Aptos-Epoch")] u64,
                /// Current block height of the chain
                #[oai(header = "X-Aptos-Block-Height")] u64,
                /// Oldest non-pruned block height of the chain
                #[oai(header = "X-Aptos-Oldest-Block-Height")] u64,
                /// The cost of the call in terms of gas
                #[oai(header = "X-Aptos-Gas-Used")] Option<u64>,
                /// Cursor to be used for endpoints that support cursor-based
                /// pagination. Pass this to the `start` field of the endpoint
                /// on the next call to get the next page of results.
                #[oai(header = "X-Aptos-Cursor")] Option<String>,
            ),
            )*
```

**File:** crates/aptos-rest-client/src/state.rs (L22-102)
```rust
impl State {
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

**File:** types/src/trusted_state.rs (L107-145)
```rust
    /// Verify and ratchet forward our trusted state using an [`EpochChangeProof`]
    /// (that moves us into the latest epoch), a [`LedgerInfoWithSignatures`]
    /// inside that epoch, and an [`crate::proof::AccumulatorConsistencyProof`] from our current
    /// version to that last verifiable ledger info.
    ///
    /// If our current trusted state doesn't have an accumulator summary yet
    /// (for example, a client may be starting with an epoch waypoint), then an
    /// initial accumulator summary must be provided.
    ///
    /// For example, a client sends a `GetStateProof` request to an upstream
    /// FullNode and receives some epoch change proof along with a latest
    /// ledger info inside the `StateProof` response. This function
    /// verifies the change proof and ratchets the trusted state version forward
    /// if the response successfully moves us into a new epoch or a new latest
    /// ledger info within our current epoch.
    ///
    /// + If there was a validation error, e.g., the epoch change proof was
    /// invalid, we return an `Err`.
    ///
    /// + If the message was well formed but stale (i.e., the returned latest
    /// ledger is behind our trusted version), we also return an `Err` since
    /// stale responses should always be rejected.
    ///
    /// + If the response is fresh and there is no epoch change, we just ratchet
    /// our trusted version to the latest ledger info and return
    /// `Ok(TrustedStateChange::Version { .. })`.
    ///
    /// + If there is a new epoch and the server provides a correct proof, we
    /// ratchet our trusted version forward, update our verifier to contain
    /// the new validator set, and return `Ok(TrustedStateChange::Epoch { .. })`.
    pub fn verify_and_ratchet<'a>(
        &self,
        state_proof: &'a StateProof,
    ) -> Result<TrustedStateChange<'a>> {
        self.verify_and_ratchet_inner(
            state_proof.latest_ledger_info_w_sigs(),
            state_proof.epoch_changes(),
        )
    }
```
