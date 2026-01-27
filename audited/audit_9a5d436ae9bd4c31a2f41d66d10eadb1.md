# Audit Report

## Title
API Key Plaintext Storage in Transaction Simulation Session Configuration

## Summary
The `api_key` field in `BaseState::Remote` is serialized to plaintext JSON without protection when `Config::save_to_file()` is called, potentially exposing API credentials through filesystem access, accidental version control commits, or insecure backups.

## Finding Description
The `Config` struct in the transaction simulation session component includes an `api_key` field that is serialized without any protection mechanisms. The vulnerability exists in the configuration serialization path: [1](#0-0) 

The `BaseState::Remote` variant contains `api_key: Option<String>` without a `#[serde(skip_serializing)]` attribute. When the config is persisted to disk: [2](#0-1) 

The `serde_json::to_string_pretty(self)` call serializes the entire `Config` struct, including the `api_key` in plaintext. This occurs at multiple points during session operations: [3](#0-2) [4](#0-3) 

API keys provided via the CLI are stored persistently without encryption: [5](#0-4) 

## Impact Explanation
This issue constitutes a **Low Severity** information disclosure vulnerability per the Aptos bug bounty criteria ("Minor information leaks"). While API keys are sensitive credentials that grant access to fullnode endpoints with potential rate limits and billing implications, this vulnerability:

- Does NOT affect validator nodes, consensus, or blockchain state
- Does NOT enable fund theft or protocol manipulation  
- Does NOT break any of the 10 critical blockchain invariants
- Is limited to a CLI development tool, not production blockchain infrastructure

The actual security impact is limited to:
- Potential unauthorized API usage if keys are exposed
- Rate limit exhaustion or billing abuse
- Violation of credential storage best practices

## Likelihood Explanation
The likelihood is **Moderate** in development environments:

- Developers frequently use `--api-key` when initializing sessions against testnet/mainnet
- Session directories may be accidentally committed to version control
- Development machines may have less stringent access controls
- Backup systems may store session directories in plaintext

However, exploitation requires file system access to the user's machine, limiting the attack surface to already-compromised systems or shared development environments.

## Recommendation
Apply the `#[serde(skip_serializing)]` attribute to prevent the `api_key` from being written to disk:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum BaseState {
    Empty,
    Remote {
        node_url: Url,
        network_version: u64,
        #[serde(skip_serializing)]
        api_key: Option<String>,
    },
}
```

Since sessions need to be restorable, either:
1. Require users to re-provide the API key when loading sessions
2. Store API keys in OS-specific secure storage (keychain/credential manager)
3. Prompt users whether to persist API keys with clear security warnings

For comparison, the main CLI config properly handles private keys with custom serialization: [6](#0-5) 

## Proof of Concept

```rust
#[test]
fn test_api_key_serialization_exposure() -> anyhow::Result<()> {
    use aptos_transaction_simulation_session::Config;
    use url::Url;
    
    // Create config with API key
    let config = Config::with_remote(
        Url::parse("https://fullnode.mainnet.aptoslabs.com")?,
        1000000,
        Some("SECRET_API_KEY_12345".to_string()),
    );
    
    // Serialize config
    let json = serde_json::to_string_pretty(&config)?;
    
    // Verify API key is exposed in JSON
    assert!(json.contains("SECRET_API_KEY_12345"), 
            "API key should be present in serialized JSON (vulnerability confirmed)");
    
    println!("Serialized config:\n{}", json);
    // Output will show:
    // {
    //   "base": {
    //     "remote": {
    //       "node_url": "https://fullnode.mainnet.aptoslabs.com/",
    //       "network_version": 1000000,
    //       "api_key": "SECRET_API_KEY_12345"  <-- EXPOSED
    //     }
    //   },
    //   "ops": 0
    // }
    
    Ok(())
}
```

---

**Notes:**

While this is a valid information disclosure vulnerability, it does **not** meet the stated criteria for a high-severity blockchain security finding. This is a CLI tool security best practice issue affecting developer credentials, not a core blockchain protocol vulnerability that impacts consensus, state integrity, validator operations, or fund security. The issue should be addressed for security hygiene but does not constitute a Critical/High/Medium severity blockchain exploit as defined in the audit scope.

### Citations

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L16-20)
```rust
    Remote {
        node_url: Url,
        network_version: u64,
        api_key: Option<String>,
    },
```

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L56-60)
```rust
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L173-175)
```rust
        let config = Config::with_remote(node_url.clone(), network_version, api_key.clone());
        let config_path = session_path.join("config.json");
        config.save_to_file(&config_path)?;
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L258-261)
```rust
        self.config.ops += 1;

        self.config.save_to_file(&self.path.join("config.json"))?;
        save_delta(&self.path.join("delta.json"), &self.state_store.delta())?;
```

**File:** crates/aptos/src/move_tool/sim.rs (L34-38)
```rust
    /// API key for connecting to the fullnode.
    ///
    /// It is strongly recommended to specify an API key to avoid rate limiting.
    #[clap(long)]
    api_key: Option<String>,
```

**File:** crates/aptos/src/common/types.rs (L276-282)
```rust
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        serialize_with = "serialize_material_with_prefix",
        deserialize_with = "deserialize_material_with_prefix"
    )]
    pub private_key: Option<Ed25519PrivateKey>,
```
