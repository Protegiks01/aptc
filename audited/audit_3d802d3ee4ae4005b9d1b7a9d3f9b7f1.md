# Audit Report

## Title
Faucet Service `RunSimple` Subcommand Lacks Production Environment Safeguards

## Summary
The Aptos faucet service's `RunSimple` subcommand, explicitly documented as "only intended for use alongside local testnets," contains no technical safeguards to prevent its execution in production environments, including mainnet. This subcommand bypasses all security mechanisms and could lead to fund loss or service abuse if mistakenly deployed in production.

## Finding Description

The `Server` enum contains four subcommands, one of which is `RunSimple`: [1](#0-0) 

The `RunSimple` variant is documented with an explicit warning that it is "only intended for use alongside local testnets," yet the main entry point provides no safeguards: [2](#0-1) 

When `RunSimple` is executed, it uses `build_for_cli` which creates a configuration with critical security omissions: [3](#0-2) 

This configuration results in:
- **No rate limiting**: `max_concurrent_requests` set to `None`
- **No authentication/authorization**: Empty `bypasser_configs` and `checker_configs` arrays
- **Information leakage**: `use_helpful_errors` enabled
- **Reduced observability**: Metrics disabled
- **Default test configuration**: Uses `ChainId::test()` if not overridden

The Aptos codebase has an established pattern of using `chain_id.is_mainnet()` checks to prevent unsafe operations on production networks: [4](#0-3) 

However, this pattern is completely absent from the faucet service codebase. The service accepts any chain ID without validation, allowing an operator to accidentally run:

```bash
aptos-faucet-service run-simple --chain-id MAINNET --node-url https://mainnet.aptoslabs.com ...
```

This would expose a production faucet with no security controls.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program's "Limited funds loss or manipulation" category because:

1. **Fund Loss**: If deployed on mainnet with minting capabilities, an unsecured faucet could lead to unauthorized token minting/drainage
2. **Service Abuse**: Lack of rate limiting enables denial-of-service attacks exhausting faucet resources
3. **Information Disclosure**: Helpful error messages expose internal system details
4. **No Authentication**: Anyone can request funds without authorization

While the impact could be significant, this requires operator error rather than an exploitable vulnerability from external attackers.

## Likelihood Explanation

**Likelihood: Medium to Low**

The vulnerability requires:
- An operator with deployment privileges choosing the wrong subcommand
- The operator explicitly specifying a production chain ID
- No organizational processes catching the misconfiguration

However, the likelihood increases due to:
- **Clear documentation warning exists but not enforced**: Developers may overlook warnings in documentation
- **No technical barrier**: Nothing prevents the command from executing
- **Established pattern not followed**: The codebase has proven solutions that aren't applied here
- **Command naming**: "simple" sounds innocuous, potentially encouraging use

## Recommendation

Implement a mainnet check in `RunSimple::run_simple()` that prevents execution on production chains:

```rust
impl RunSimple {
    pub async fn run_simple(&self) -> Result<()> {
        // Prevent RunSimple from being used on mainnet or premainnet
        if self.api_connection_config.chain_id.is_mainnet() {
            anyhow::bail!(
                "RunSimple is not allowed on MAINNET. This mode disables all security \
                 features and is only intended for local testnets. Please use the 'run' \
                 command with a proper configuration file for production deployments."
            );
        }
        
        // Additional check for premainnet
        if matches!(
            NamedChain::from_chain_id(&self.api_connection_config.chain_id),
            Ok(NamedChain::PREMAINNET)
        ) {
            anyhow::bail!(
                "RunSimple is not allowed on PREMAINNET. Please use the 'run' command \
                 with a proper configuration file."
            );
        }

        // Existing implementation...
        let asset_config = AssetConfig::new(None, self.key_file_path.clone());
        // ... rest of implementation
    }
}
```

Additionally, add a warning log even for test networks:

```rust
use aptos_logger::warn;

warn!(
    "Running in simplified mode with NO security checks. \
     Chain ID: {}. This mode is only for local development.",
    self.api_connection_config.chain_id
);
```

## Proof of Concept

Create a test demonstrating the lack of safeguards:

```rust
#[test]
fn test_run_simple_mainnet_rejection() {
    use aptos_sdk::types::chain_id::ChainId;
    use std::path::PathBuf;
    
    let run_simple = RunSimple {
        api_connection_config: ApiConnectionConfig::new(
            reqwest::Url::parse("https://mainnet.aptoslabs.com").unwrap(),
            None,
            None,
            ChainId::mainnet(), // Attempting to use mainnet
        ),
        listen_address: "0.0.0.0".to_string(),
        listen_port: 8081,
        key_file_path: PathBuf::from("/tmp/test.key"),
        mint_account_address: None,
        do_not_delegate: false,
    };
    
    // This should return an error but currently doesn't
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        run_simple.run_simple().await
    });
    
    // Currently this would proceed (if key file exists), but should fail
    assert!(result.is_err(), "RunSimple should reject mainnet chain ID");
    assert!(
        result.unwrap_err().to_string().contains("not allowed on MAINNET"),
        "Error message should explicitly mention mainnet restriction"
    );
}
```

## Notes

While this issue represents a legitimate security concern and operational risk, it's important to note that:

1. **Not externally exploitable**: This requires operator access and deployment privileges
2. **Trusted role mistake**: The vulnerability manifests through trusted operator error, not malicious exploitation
3. **Defense-in-depth principle**: This safeguard represents a missing layer of defense that should exist but whose absence doesn't constitute an exploitable protocol vulnerability

The recommended fix follows the defensive programming pattern consistently used throughout the Aptos codebase for production environment protection.

### Citations

**File:** crates/aptos-faucet/core/src/server/mod.rs (L16-31)
```rust
#[derive(Clone, Debug, Subcommand)]
pub enum Server {
    /// Run the server.
    Run(Run),

    /// Run the server but instead of taking in a config, take in arguments on the CLI.
    /// This is less expressive than Run and is only intended for use alongside local
    /// testnets.
    RunSimple(RunSimple),

    /// Confirm a server config is valid.
    ValidateConfig(ValidateConfig),

    /// Generate the OpenAPI spec.
    GenerateOpenapi(GenerateOpenapi),
}
```

**File:** crates/aptos-faucet/service/src/main.rs (L21-32)
```rust
#[tokio::main]
async fn main() -> Result<()> {
    let root_args = Args::parse();

    aptos_logger::Logger::builder()
        .level(aptos_logger::Level::Info)
        .build();

    info!("Running with root args: {:#?}", root_args);

    root_args.run_command().await
}
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L253-312)
```rust
    pub fn build_for_cli(
        api_url: Url,
        listen_address: String,
        listen_port: u16,
        funder_key: FunderKeyEnum,
        do_not_delegate: bool,
        chain_id: Option<ChainId>,
    ) -> Self {
        let (key_file_path, _key) = match funder_key {
            FunderKeyEnum::KeyFile(key_file_path) => (key_file_path, None),
            FunderKeyEnum::Key(key) => (PathBuf::from_str("/dummy").unwrap(), Some(key)),
        };
        Self {
            server_config: ServerConfig {
                listen_address,
                listen_port,
                api_path_base: "".to_string(),
            },
            metrics_server_config: MetricsServerConfig {
                disable: true,
                listen_address: "0.0.0.0".to_string(),
                listen_port: 1,
            },
            bypasser_configs: vec![],
            checker_configs: vec![],
            funder_config: FunderConfig::MintFunder(MintFunderConfig {
                api_connection_config: ApiConnectionConfig::new(
                    api_url,
                    None,
                    None,
                    chain_id.unwrap_or_else(ChainId::test),
                ),
                transaction_submission_config: TransactionSubmissionConfig::new(
                    None,    // maximum_amount
                    None,    // maximum_amount_with_bypass
                    30,      // gas_unit_price_ttl_secs
                    None,    // gas_unit_price_override
                    500_000, // max_gas_amount
                    30,      // transaction_expiration_secs
                    35,      // wait_for_outstanding_txns_secs
                    false,   // wait_for_transactions
                ),
                assets: HashMap::from([(
                    DEFAULT_ASSET_NAME.to_string(),
                    MintAssetConfig::new(
                        AssetConfig::new(_key, key_file_path),
                        Some(aptos_test_root_address()),
                        do_not_delegate,
                    ),
                )]),
                default_asset: MintFunderConfig::get_default_asset_name(),
                amount_to_fund: 100_000_000_000,
            }),
            handler_config: HandlerConfig {
                use_helpful_errors: true,
                return_rejections_early: false,
                max_concurrent_requests: None,
            },
        }
    }
```

**File:** types/src/chain_id.rs (L84-87)
```rust
    /// Returns true iff the chain ID matches mainnet
    pub fn is_mainnet(&self) -> bool {
        self.matches_named_chain(NamedChain::MAINNET)
    }
```
