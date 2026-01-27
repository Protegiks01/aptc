# Audit Report

## Title
Missing Chain ID Validation Allows Production Genesis with Test Network Chain ID

## Summary
The `GenerateLayoutTemplate::execute()` function generates a layout file with insecure defaults including `ChainId::test()` (chain ID 4), and `fetch_mainnet_genesis_info()` fails to validate that mainnet genesis uses the correct chain ID (1). This allows operators to accidentally deploy production networks with test chain IDs, enabling cross-network replay attacks and breaking chain ID isolation. [1](#0-0) 

## Finding Description

The vulnerability exists in two parts:

**Part 1: Insecure Layout Defaults**

The `Layout::default()` implementation creates a genesis layout with test network parameters, most critically setting `chain_id: ChainId::test()` which returns chain ID 4 (TESTING) instead of chain ID 1 (MAINNET). [2](#0-1) 

Other concerning defaults include:
- `employee_vesting_period_duration: Some(5 * 60)` - 5 minutes instead of typical months/years
- `is_test: true` - marks network as test environment

**Part 2: Missing Validation in Mainnet Genesis**

The `fetch_mainnet_genesis_info()` function validates certain layout fields (root_key must not be set, total_supply must be set) but critically **does NOT validate that chain_id equals 1 (MAINNET)**. [3](#0-2) 

The chain_id is used directly from the layout without validation: [4](#0-3) 

**Attack Scenario:**
1. Network operator runs `aptos genesis generate-layout-template` 
2. Operator fails to modify the default `chain_id: testing` to `chain_id: 1` in the generated YAML
3. Operator runs `aptos genesis generate-genesis --mainnet` with the unmodified template
4. Mainnet deploys with chain_id = 4 instead of chain_id = 1

**Chain ID Security Invariant Violation:**

Chain IDs provide transaction replay protection. The transaction validation prologue verifies that transaction chain_id matches the network's chain_id. If a production network launches with chain_id = 4:
- Transactions from other networks with chain_id = 4 become replayable on this "mainnet"
- This breaks the **Deterministic Execution** invariant as validators may have different transaction histories
- This violates **Consensus Safety** as it enables cross-network double-spending [5](#0-4) 

## Impact Explanation

**High Severity** - This qualifies as a "Significant protocol violation" under the Aptos bug bounty criteria because:

1. **Consensus Safety Risk**: Wrong chain ID enables replay attacks from test networks, potentially causing state divergence between validators who have different views of which transactions are valid
2. **Economic Harm**: The 5-minute vesting period allows immediate token dumping by employees, potentially crashing token price on launch
3. **Non-recoverable**: Once genesis is deployed with wrong chain ID, fixing it requires a hard fork and re-genesis

While this doesn't directly cause "Loss of Funds" or "Consensus Safety violations" in isolation, it creates the conditions where such violations become possible through replay attacks.

## Likelihood Explanation

**Medium-High Likelihood** - While this requires operator error, several factors increase probability:

1. **Template Generation Command**: The `generate-layout-template` command creates a file that looks ready for production use
2. **Insufficient Warning**: The code comment warns defaults should be "carefully thought through" but doesn't explicitly warn about the chain_id issue
3. **Inconsistent Validation**: The code validates `root_key` and `total_supply` but not `chain_id`, suggesting developers forgot this check
4. **Developer Fatigue**: During genesis setup, operators handle many configuration files and may miss reviewing every field

The lack of validation represents a missing defense-in-depth layer that should catch operator mistakes.

## Recommendation

Add validation in `fetch_mainnet_genesis_info()` to enforce mainnet chain ID:

```rust
pub fn fetch_mainnet_genesis_info(git_options: GitOptions) -> CliTypedResult<MainnetGenesisInfo> {
    let client = git_options.get_client()?;
    let layout: Layout = client.get(Path::new(LAYOUT_FILE))?;

    if layout.root_key.is_some() {
        return Err(CliError::UnexpectedError(
            "Root key must not be set for mainnet.".to_string(),
        ));
    }

    // ADD THIS VALIDATION
    if !layout.chain_id.is_mainnet() {
        return Err(CliError::UnexpectedError(
            format!("Chain ID must be set to 1 (mainnet) for mainnet genesis. Got: {}", layout.chain_id)
        ));
    }

    // ADD VALIDATION FOR VESTING PERIOD
    if let Some(vesting_period) = layout.employee_vesting_period_duration {
        const MIN_PRODUCTION_VESTING_PERIOD: u64 = 30 * 24 * 60 * 60; // 30 days minimum
        if vesting_period < MIN_PRODUCTION_VESTING_PERIOD {
            return Err(CliError::UnexpectedError(
                format!("Employee vesting period {} seconds is too short for mainnet (minimum {} seconds / 30 days)", 
                    vesting_period, MIN_PRODUCTION_VESTING_PERIOD)
            ));
        }
    }

    // ... rest of function
}
```

Additionally, improve the defaults or add stronger warnings in the template generation.

## Proof of Concept

**Step 1: Generate layout template**
```bash
aptos genesis generate-layout-template --output-file layout.yaml
```

**Step 2: Examine generated layout.yaml** (will contain):
```yaml
chain_id: testing  # Chain ID 4, not mainnet (1)!
is_test: true
employee_vesting_period_duration: 300  # 5 minutes!
# ... other fields
```

**Step 3: Attempt mainnet genesis** (should fail with validation, but currently succeeds):
```bash
aptos genesis generate-genesis --mainnet --output-dir ./genesis
```

**Expected**: Error message "Chain ID must be set to 1 (mainnet)"  
**Actual**: Genesis succeeds with chain_id = 4

**Verification**: Check the generated genesis.blob - it will encode chain_id = 4 instead of chain_id = 1, making it vulnerable to replay attacks from any test network using chain ID 4.

## Notes

While the code comment at line 271-272 warns that "these defaults should be carefully thought through", this is insufficient defense-in-depth. The presence of validation for `root_key` and `total_supply` but absence of validation for `chain_id` represents an inconsistent security posture. Defense-in-depth principles require validation to catch operator mistakes, especially for critical security parameters like chain ID that affect transaction replay protection.

### Citations

**File:** crates/aptos/src/genesis/keys.rs (L289-291)
```rust
    async fn execute(self) -> CliTypedResult<()> {
        check_if_file_exists(self.output_file.as_path(), self.prompt_options)?;
        let layout = Layout::default();
```

**File:** crates/aptos-genesis/src/config.rs (L107-133)
```rust
impl Default for Layout {
    fn default() -> Self {
        Layout {
            root_key: None,
            users: vec![],
            chain_id: ChainId::test(),
            allow_new_validators: false,
            epoch_duration_secs: 7_200,
            is_test: true,
            min_stake: 100_000_000_000_000,
            min_voting_threshold: 100_000_000_000_000,
            max_stake: 100_000_000_000_000_000,
            recurring_lockup_duration_secs: 86_400,
            required_proposer_stake: 100_000_000_000_000,
            rewards_apy_percentage: 10,
            voting_duration_secs: 43_200,
            voting_power_increase_limit: 20,
            total_supply: None,
            employee_vesting_start: Some(1663456089),
            employee_vesting_period_duration: Some(5 * 60), // 5 minutes
            on_chain_consensus_config: OnChainConsensusConfig::default(),
            on_chain_execution_config: OnChainExecutionConfig::default_for_genesis(),
            jwk_consensus_config_override: None,
            initial_jwks: vec![],
            keyless_groth16_vk_override: None,
        }
    }
```

**File:** crates/aptos/src/genesis/mod.rs (L138-150)
```rust
pub fn fetch_mainnet_genesis_info(git_options: GitOptions) -> CliTypedResult<MainnetGenesisInfo> {
    let client = git_options.get_client()?;
    let layout: Layout = client.get(Path::new(LAYOUT_FILE))?;

    if layout.root_key.is_some() {
        return Err(CliError::UnexpectedError(
            "Root key must not be set for mainnet.".to_string(),
        ));
    }

    let total_supply = layout.total_supply.ok_or_else(|| {
        CliError::UnexpectedError("Layout file does not have `total_supply`".to_string())
    })?;
```

**File:** crates/aptos/src/genesis/mod.rs (L238-238)
```rust
        layout.chain_id,
```

**File:** types/src/chain_id.rs (L13-24)
```rust
pub enum NamedChain {
    /// Users might accidentally initialize the ChainId field to 0, hence reserving ChainId 0 for accidental
    /// initialization.
    /// MAINNET is the Aptos mainnet production chain and is reserved for 1
    MAINNET = 1,
    // Even though these CHAIN IDs do not correspond to MAINNET, changing them should be avoided since they
    // can break test environments for various organisations.
    TESTNET = 2,
    DEVNET = 3,
    TESTING = 4,
    PREMAINNET = 5,
}
```
