# Audit Report

## Title
Credential Leakage in Aptos Rosetta CLI Error Messages

## Summary
The Aptos Rosetta CLI fails to sanitize URLs containing embedded credentials (e.g., `http://user:pass@host`) when displaying error messages, leading to credential leakage through error output.

## Finding Description

The `UrlArgs` structure in the Rosetta CLI accepts a `rosetta_api_url` parameter of type `url::Url` which can contain embedded credentials in the format `http://username:password@host`. [1](#0-0) 

When network operations fail, the error propagation chain exposes these credentials through multiple paths:

1. **Direct URL parsing errors**: When `url::Url::join()` fails in the `RosettaClient::make_call()` method, the error includes the base URL with credentials. [2](#0-1) 

2. **Network request failures**: When the HTTP request fails (connection timeout, DNS failure, etc.), `reqwest::Error` includes the full URL with credentials in its error message, which gets converted to `RestError::Unknown` and propagated. [3](#0-2) 

3. **Error display in main**: All errors are converted to strings and printed to stdout, exposing any credentials present in the error chain. [4](#0-3) 

The Rust `url::Url` type's `Debug` and `Display` implementations do not sanitize userinfo components, meaning credentials appear in plaintext in error messages.

All CLI commands are affected since they use `UrlArgs`:
- Network commands (list, options, status)
- Account commands (balance)
- Block commands (get)
- Construction commands (create account, transfer, etc.) [5](#0-4) [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability results in **credential disclosure** through error messages. While the security question categorizes this as Medium severity, according to the Aptos bug bounty program criteria, information leaks are classified as **Low Severity** (up to $1,000).

The bug bounty program defines:
- **Medium Severity**: "Limited funds loss or manipulation, State inconsistencies requiring intervention"
- **Low Severity**: "Minor information leaks, Non-critical implementation bugs"

Credential leakage constitutes an information leak but does not directly cause funds loss or state inconsistencies. The Rosetta CLI is a client-side tool, not a core consensus or execution component. Leaked credentials could potentially allow unauthorized access to a Rosetta API server, but this doesn't directly compromise the blockchain's integrity, consensus, or user funds.

**However**, the security question explicitly labels this as Medium severity, suggesting context-specific concerns (e.g., if the Rosetta API has privileged access or if credential compromise could lead to broader system access in production environments).

## Likelihood Explanation

**High likelihood** - This vulnerability can be trivially triggered:
1. User provides URL with credentials: `--rosetta_api_url http://admin:secret123@rosetta.example.com`
2. Network failure occurs (invalid hostname, connection refused, timeout, etc.)
3. Error message displays the full URL including credentials to stdout
4. Credentials are exposed in terminal output, logs, or CI/CD pipeline outputs

This is not a race condition or timing-dependent issue - it occurs deterministically whenever network errors are encountered with credential-containing URLs.

## Recommendation

Implement URL sanitization before displaying in error messages. Create a sanitized URL representation that removes userinfo:

```rust
// In crates/aptos-rosetta-cli/src/common.rs
use url::Url;

impl UrlArgs {
    /// Retrieve a [`RosettaClient`] with sanitized error handling
    pub fn client(self) -> RosettaClient {
        RosettaClient::new(self.rosetta_api_url)
    }
    
    /// Get sanitized URL for display/logging (removes credentials)
    pub fn sanitized_url(&self) -> String {
        let mut url = self.rosetta_api_url.clone();
        url.set_username("").ok();
        url.set_password(None).ok();
        url.to_string()
    }
}

// In crates/aptos-rosetta/src/client.rs
impl RosettaClient {
    pub fn new(address: Url) -> RosettaClient {
        RosettaClient {
            address,
            inner: ReqwestClient::new(),
        }
    }
    
    fn sanitized_address(&self) -> String {
        let mut url = self.address.clone();
        url.set_username("").ok();
        url.set_password(None).ok();
        url.to_string()
    }
}

// Wrap errors to sanitize URLs
async fn make_call<'a, I: Serialize + Debug, O: DeserializeOwned>(
    &'a self,
    path: &'static str,
    request: &'a I,
) -> anyhow::Result<O> {
    let response = self
        .inner
        .post(self.address.join(path).map_err(|e| {
            anyhow!("Failed to join URL path: {} (base: {})", e, self.sanitized_address())
        })?)
        .header(CONTENT_TYPE, JSON)
        .body(serde_json::to_string(request)?)
        .send()
        .await
        .map_err(|e| {
            anyhow!("Request failed for {}: {}", self.sanitized_address(), e)
        })?;
    // ... rest of function
}
```

## Proof of Concept

```bash
# Build the Rosetta CLI
cd crates/aptos-rosetta-cli
cargo build

# Trigger credential leakage with invalid host
./target/debug/aptos-rosetta-cli network list \
  --rosetta_api_url http://admin:secretpassword@invalid-host-that-does-not-exist:8082

# Expected vulnerable output:
# {
#   "error": "error sending request for url (http://admin:secretpassword@invalid-host-that-does-not-exist:8082/network/list): ..."
# }

# The credentials "admin:secretpassword" are visible in the error message
```

Alternatively, trigger with connection refused:
```bash
# No server running on localhost:9999
./target/debug/aptos-rosetta-cli network list \
  --rosetta_api_url http://apiuser:apikey123@localhost:9999

# Error will contain: http://apiuser:apikey123@localhost:9999
```

**Note**: While this vulnerability exists and credentials are indeed not sanitized, it qualifies as **Low Severity** under the Aptos bug bounty program criteria (information leak), not Medium severity. The Rosetta CLI is a client-side utility tool, not a core blockchain component affecting consensus, state management, or fund security.

### Citations

**File:** crates/aptos-rosetta-cli/src/common.rs (L46-58)
```rust
#[derive(Debug, Parser)]
pub struct UrlArgs {
    /// URL for the Aptos Rosetta API. e.g. http://localhost:8082
    #[clap(long, default_value = "http://localhost:8082")]
    rosetta_api_url: url::Url,
}

impl UrlArgs {
    /// Retrieve a [`RosettaClient`]
    pub fn client(self) -> RosettaClient {
        RosettaClient::new(self.rosetta_api_url)
    }
}
```

**File:** crates/aptos-rosetta/src/client.rs (L131-149)
```rust
    async fn make_call<'a, I: Serialize + Debug, O: DeserializeOwned>(
        &'a self,
        path: &'static str,
        request: &'a I,
    ) -> anyhow::Result<O> {
        let response = self
            .inner
            .post(self.address.join(path)?)
            .header(CONTENT_TYPE, JSON)
            .body(serde_json::to_string(request)?)
            .send()
            .await?;
        if !response.status().is_success() {
            let error: Error = response.json().await?;
            return Err(anyhow!("Failed API with: {:?}", error));
        }

        Ok(response.json().await?)
    }
```

**File:** crates/aptos-rest-client/src/error.rs (L198-206)
```rust
impl From<reqwest::Error> for RestError {
    fn from(err: reqwest::Error) -> Self {
        if let Some(status) = err.status() {
            RestError::Http(status, err)
        } else {
            RestError::Unknown(err.into())
        }
    }
}
```

**File:** crates/aptos-rosetta-cli/src/main.rs (L41-49)
```rust
    match result {
        Ok(value) => println!("{}", value),
        Err(error) => {
            let error = ErrorWrapper {
                error: error.to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&error).unwrap());
            exit(-1)
        },
```

**File:** crates/aptos-rosetta-cli/src/network.rs (L33-43)
```rust
#[derive(Debug, Parser)]
pub struct NetworkListCommand {
    #[clap(flatten)]
    url_args: UrlArgs,
}

impl NetworkListCommand {
    pub async fn execute(self) -> anyhow::Result<NetworkListResponse> {
        self.url_args.client().network_list().await
    }
}
```

**File:** crates/aptos-rosetta-cli/src/account.rs (L33-47)
```rust
#[derive(Debug, Parser)]
pub struct AccountBalanceCommand {
    #[clap(flatten)]
    network_args: NetworkArgs,
    #[clap(flatten)]
    url_args: UrlArgs,
    #[clap(flatten)]
    block_args: BlockArgs,
    /// Whether to filter the currency to the native coin
    #[clap(long)]
    filter_currency: bool,
    /// Account to list the balance
    #[clap(long, value_parser = aptos::common::types::load_account_arg)]
    account: AccountAddress,
    /// Whether to show the amount of stake instead of the normal balance
```

**File:** crates/aptos-rosetta-cli/src/block.rs (L29-37)
```rust
#[derive(Debug, Parser)]
pub struct GetBlockCommand {
    #[clap(flatten)]
    block_args: BlockArgs,
    #[clap(flatten)]
    network_args: NetworkArgs,
    #[clap(flatten)]
    url_args: UrlArgs,
}
```
