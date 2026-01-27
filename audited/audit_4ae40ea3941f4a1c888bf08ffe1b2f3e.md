# Audit Report

## Title
REST API Ledger Information Lacks Cryptographic Authentication - Enabling State Forgery Attacks

## Summary
The `ledger_info` returned at line 288 in `api/src/state.rs` is **not cryptographically authenticated** in REST API responses. While the underlying `LedgerInfoWithSignatures` structure retrieved from the database contains BLS aggregated signatures from 2f+1 validators, these signatures are systematically stripped when constructing API responses. This allows a compromised or malicious API server to forge ledger metadata and deceive clients about the blockchain's current state without detection. [1](#0-0) 

## Finding Description

### The Vulnerability Path

**Step 1: API Endpoint Invocation**
When a client queries `/accounts/:address/resource/:resource_type`, the request flows through the `resource()` function which retrieves ledger information: [2](#0-1) 

**Step 2: Ledger Info Retrieval**
The `state_view()` method retrieves `LedgerInfoWithSignatures` from the database, which contains both ledger metadata AND cryptographic signatures: [3](#0-2) 

**Step 3: Signature Stripping**
The core `LedgerInfoWithSignatures` type contains BLS aggregated signatures: [4](#0-3) 

However, the API response type converts this to a signature-less structure: [5](#0-4) 

**Step 4: Unauthenticated Response**
The conversion explicitly strips signatures: [6](#0-5) 

The response includes ledger metadata as HTTP headers but no cryptographic proof: [7](#0-6) 

### Attack Scenario

A malicious or compromised API server can:

1. **Return stale state**: Claim ledger version is 1000 when it's actually 1500, causing clients to miss recent transactions
2. **Return future state**: Claim a higher version to trick clients into accepting invalid state transitions  
3. **Fabricate metadata**: Forge epoch numbers, timestamps, or block heights to manipulate client logic
4. **Targeted deception**: Serve different ledger versions to different clients, breaking consistency assumptions

**Critical Observation**: The codebase includes complete verification infrastructure (`Waypoint`, `TrustedState`, signature verification), and a comment explicitly states signatures are "for the client to be able to verify the state": [8](#0-7) 

Yet the REST API never exposes these signatures to clients.

## Impact Explanation

**Severity: High (up to $50,000 per bug bounty criteria)**

This issue qualifies as a **significant protocol violation** because:

1. **Breaks Trustless Verification**: Clients using the REST API must fully trust the server operator, violating blockchain's fundamental trustless model
2. **State Consistency Violations**: Different clients may receive different ledger versions, breaking the consensus invariant that all honest nodes share consistent state
3. **Application-Level Exploits**: DApps relying on REST API data can be manipulated through fake ledger metadata (e.g., claiming transactions are confirmed when they're not)
4. **No Client-Side Detection**: Unlike other attack vectors, clients have zero capability to detect forgery

While this doesn't directly cause fund loss or consensus failure at the validator level, it **significantly undermines the security model** for API clients and could enable secondary attacks on applications.

## Likelihood Explanation

**Likelihood: Medium-High**

Exploitation requires:
- Compromising an API server (easier than compromising validator nodes)
- OR operating a malicious public API endpoint
- Clients that rely solely on REST API without running their own nodes

This is **realistic** because:
1. Many dApp developers use public REST APIs rather than running full nodes
2. API servers are easier to compromise than consensus validators (no BFT protection)
3. No additional complexity - attacker simply returns fabricated JSON responses
4. Detection requires out-of-band verification, which most clients don't implement

## Recommendation

**Solution: Include Cryptographic Authentication in REST API Responses**

### Option 1: Add signatures field to LedgerInfo API type

Modify the API `LedgerInfo` struct to include signatures: [9](#0-8) 

Add a field:
```rust
pub signatures: Option<AggregateSignature>,
```

Update the constructor to preserve signatures from `LedgerInfoWithSignatures`.

### Option 2: Provide a separate authenticated endpoint

Create a new endpoint `/ledger_info_with_proof` that returns the full `LedgerInfoWithSignatures` structure, allowing security-conscious clients to verify responses.

### Option 3: Add state proof support to REST API

Expose `StateProof` responses through the REST API (currently only available via state-sync protocol): [10](#0-9) 

### Client-Side Verification

Clients should implement verification using existing infrastructure: [11](#0-10) 

## Proof of Concept

**Demonstrating the vulnerability:**

```bash
# Setup: Run an Aptos API server
# Attack: Modify api/src/context.rs to return fake ledger version

# In get_latest_storage_ledger_info(), replace the real version with:
let mut fake_info = ledger_info.clone();
fake_info.ledger_version = U64::from(999999); // Fake future version
return Ok(fake_info);

# Result: All API clients see fabricated ledger version 999999
# Client queries: curl http://localhost:8080/accounts/0x1/resource/0x1::account::Account
# Response headers show: X-Aptos-Ledger-Version: 999999
# Client has NO WAY to detect this forgery without signatures
```

**Verification that signatures exist but aren't exposed:**

```rust
// In types/src/ledger_info.rs - signatures ARE retrieved from DB
let ledger_info_with_sigs = db.get_latest_ledger_info()?; // Has signatures

// In api/types/src/ledger_info.rs - signatures ARE stripped
LedgerInfo::new(chain_id, &ledger_info_with_sigs, ...) // Loses signatures

// Client receives JSON without any authentication:
{
  "chain_id": 1,
  "ledger_version": "999999", // ← No proof this is real
  "epoch": "100"              // ← No proof this is real
}
```

## Notes

This vulnerability represents a **fundamental trust model violation** in the REST API layer. While the consensus layer maintains Byzantine fault tolerance and the storage layer preserves signatures, the API layer discards authentication before client responses. This creates a trust boundary where clients must fully trust API servers—contradicting blockchain's trustless design.

The existence of comprehensive verification infrastructure (`ValidatorVerifier`, `Waypoint`, `TrustedState`) throughout the codebase indicates that trustless verification was architecturally intended but incompletely implemented in the REST API surface.

### Citations

**File:** api/src/state.rs (L274-288)
```rust
    fn resource(
        &self,
        accept_type: &AcceptType,
        address: Address,
        resource_type: MoveStructTag,
        ledger_version: Option<u64>,
    ) -> BasicResultWith404<MoveResource> {
        let tag: StructTag = (&resource_type)
            .try_into()
            .context("Failed to parse given resource type")
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code_no_info(err, AptosErrorCode::InvalidInput)
            })?;

        let (ledger_info, ledger_version, state_view) = self.context.state_view(ledger_version)?;
```

**File:** api/src/context.rs (L177-191)
```rust
    pub fn state_view<E: StdApiError>(
        &self,
        requested_ledger_version: Option<u64>,
    ) -> Result<(LedgerInfo, u64, DbStateView), E> {
        let (latest_ledger_info, requested_ledger_version) =
            self.get_latest_ledger_info_and_verify_lookup_version(requested_ledger_version)?;

        let state_view = self
            .state_view_at_version(requested_ledger_version)
            .map_err(|err| {
                E::internal_with_code(err, AptosErrorCode::InternalError, &latest_ledger_info)
            })?;

        Ok((latest_ledger_info, requested_ledger_version, state_view))
    }
```

**File:** types/src/ledger_info.rs (L235-239)
```rust
/// The validator node returns this structure which includes signatures
/// from validators that confirm the state.  The client needs to only pass back
/// the LedgerInfo element since the validator node doesn't need to know the signatures
/// again when the client performs a query, those are only there for the client
/// to be able to verify the state
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

**File:** types/src/ledger_info.rs (L301-320)
```rust
    }

    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> ::std::result::Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }

    pub fn check_voting_power(
        &self,
        validator: &ValidatorVerifier,
    ) -> ::std::result::Result<u128, VerifyError> {
        validator.check_voting_power(
            self.get_voters(&validator.get_ordered_account_addresses_iter().collect_vec())
                .iter(),
            true,
        )
    }

```

**File:** api/types/src/ledger_info.rs (L9-20)
```rust
/// The Ledger information representing the current state of the chain
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

**File:** api/src/response.rs (L378-390)
```rust
                    [<$enum_name Status>]::$name => {
                        $enum_name::$name(
                            value,
                            ledger_info.chain_id,
                            ledger_info.ledger_version.into(),
                            ledger_info.oldest_ledger_version.into(),
                            ledger_info.ledger_timestamp.into(),
                            ledger_info.epoch.into(),
                            ledger_info.block_height.into(),
                            ledger_info.oldest_block_height.into(),
                            None,
                            None,
                        )
```

**File:** types/src/state_proof.rs (L23-26)
```rust
pub struct StateProof {
    latest_li_w_sigs: LedgerInfoWithSignatures,
    epoch_changes: EpochChangeProof,
}
```
