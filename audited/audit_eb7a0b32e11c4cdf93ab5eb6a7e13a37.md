# Audit Report

## Title
Unbounded Amount Parameter in Workspace Server Faucet Allows Unlimited Minting

## Summary
The `start_faucet()` function in the workspace server uses `RunConfig::build_for_cli()` which sets `maximum_amount` and `maximum_amount_with_bypass` to `None`, allowing users to bypass the configured `amount_to_fund` limit by specifying arbitrary amounts in request parameters, enabling unlimited token minting.

## Finding Description
The vulnerability exists in the faucet configuration chain used by the aptos-workspace-server:

1. **Configuration Entry Point**: The `start_faucet()` function calls `RunConfig::build_for_cli()` without amount restrictions [1](#0-0) 

2. **Missing Maximum Limits**: The `build_for_cli()` function creates a `TransactionSubmissionConfig` with both `maximum_amount` and `maximum_amount_with_bypass` set to `None` [2](#0-1) 

3. **Uncapped Amount Logic**: The `get_amount()` function in MintFunder returns the user-provided amount directly when `maximum_amount` is `None` [3](#0-2) 

4. **User-Controlled Input**: The `FundRequest` struct accepts an optional `amount` field from HTTP requests [4](#0-3) 

5. **No Minting Restrictions**: The underlying `aptos_coin::mint()` function has no built-in amount limits [5](#0-4) 

An attacker can send a POST request to `/fund` with `amount: 18446744073709551615` (max u64) to mint ~184 billion APT worth of test tokens.

## Impact Explanation
**Severity Assessment: Low to Medium (Context-Dependent)**

This vulnerability's impact depends critically on deployment context:

**In Local Development (Primary Use Case)**: The aptos-workspace-server is designed as a local development tool [6](#0-5) . In this context, unlimited minting is often desired behavior for testing purposes, making this a **non-issue**.

**If Misused in Semi-Public Environments**: If this configuration is inadvertently used for shared development networks or testnets (against its intended design), it could cause:
- Resource exhaustion and denial of service
- Broken economic test assumptions
- Compromised test network integrity

However, this does NOT meet **Critical Severity** criteria because:
- It's not production blockchain code
- No mainnet funds at risk
- No consensus safety violations
- Test environments have no real economic value

## Likelihood Explanation
**Likelihood: Low**

The vulnerability requires specific conditions:
1. The workspace server must be deployed in a network-accessible manner (it's designed for localhost)
2. The faucet endpoint must be exposed without authentication
3. An attacker must know the endpoint exists and is vulnerable

Since this is a development tool typically run locally with no network exposure, exploitation likelihood is minimal in proper usage scenarios.

## Recommendation
Add explicit maximum amount limits in `build_for_cli()`: [2](#0-1) 

Replace the `TransactionSubmissionConfig::new()` call with:
```rust
TransactionSubmissionConfig::new(
    Some(100_000_000_000),  // maximum_amount - cap at default
    Some(1_000_000_000_000), // maximum_amount_with_bypass - 10x for authenticated requests
    30,      // gas_unit_price_ttl_secs
    None,    // gas_unit_price_override
    500_000, // max_gas_amount
    30,      // transaction_expiration_secs
    35,      // wait_for_outstanding_txns_secs
    false,   // wait_for_transactions
)
```

## Proof of Concept
```bash
# Start the workspace server locally
cargo run -p aptos-workspace-server

# Exploit: Mint maximum u64 amount
curl -X POST http://localhost:<FAUCET_PORT>/fund \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 18446744073709551615,
    "address": "0xCAFE"
  }'

# Expected: Transaction succeeds, minting ~184 billion APT to 0xCAFE
# Desired: Transaction should be capped at 100_000_000_000 (100 APT)
```

## Notes
While this finding technically demonstrates the described behavior, its security impact is **minimal** because:

1. The workspace server is explicitly documented as a local development tool, not a production service
2. Test networks are expected to provide generous or unlimited funding for development purposes  
3. No real economic value is at risk in local development environments

This would only become a genuine security issue if the `build_for_cli` configuration were mistakenly used in a public testnet faucet deployment, which would violate the component's intended design and usage guidelines.

### Citations

**File:** aptos-move/aptos-workspace-server/src/services/faucet.rs (L46-53)
```rust
        let faucet_run_config = RunConfig::build_for_cli(
            Url::parse(&format!("http://{}:{}", IP_LOCAL_HOST, api_port)).unwrap(),
            IP_LOCAL_HOST.to_string(),
            0,
            FunderKeyEnum::KeyFile(test_dir.join("mint.key")),
            false,
            None,
        );
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L285-294)
```rust
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
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L540-550)
```rust
    fn get_amount(&self, amount: Option<u64>, did_bypass_checkers: bool) -> u64 {
        match (
            amount,
            self.txn_config.get_maximum_amount(did_bypass_checkers),
        ) {
            (Some(amount), Some(maximum_amount)) => std::cmp::min(amount, maximum_amount),
            (Some(amount), None) => amount,
            (None, Some(maximum_amount)) => std::cmp::min(self.amount_to_fund, maximum_amount),
            (None, None) => self.amount_to_fund,
        }
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L32-47)
```rust
#[derive(Clone, Debug, Default, Object)]
pub struct FundRequest {
    /// If not set, the default is the preconfigured max funding amount. If set,
    /// we will use this amount instead assuming it is < than the maximum,
    /// otherwise we'll just use the maximum.
    pub amount: Option<u64>,

    /// Either this or `address` / `pub_key` must be provided.
    pub auth_key: Option<String>,

    /// Either this or `auth_key` / `pub_key` must be provided.
    pub address: Option<String>,

    /// Either this or `auth_key` / `address` must be provided.
    pub pub_key: Option<String>,
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

**File:** aptos-move/aptos-workspace-server/src/lib.rs (L1-16)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This library runs and manages a set of services that makes up a local Aptos network.
//! - node
//!     - node API
//!     - indexer grpc
//! - faucet
//! - indexer
//!     - postgres db
//!     - processors
//!     - indexer API
//!
//! The services are bound to unique OS-assigned ports to allow for multiple local networks
//! to operate simultaneously, enabling testing and development in isolated environments.
//!
```
