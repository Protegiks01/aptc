# Audit Report

## Title
Mainnet Genesis Can Be Initialized with Test Chain ID Due to Insufficient Validation

## Summary
The `Layout::default()` implementation produces a configuration with `chain_id: ChainId::test()` instead of a mainnet chain ID. When operators generate a layout template and forget to update the `chain_id` field before generating mainnet genesis, the blockchain initializes with chain ID 4 (TESTING) instead of chain ID 1 (MAINNET), making it incompatible with mainnet infrastructure.

## Finding Description
The vulnerability exists in the genesis generation workflow where configuration defaults can lead to mainnet misconfiguration: [1](#0-0) 

The `Layout::default()` sets `chain_id: ChainId::test()` (value 4) and `is_test: true`. When operators run the `GenerateLayoutTemplate` command, it uses this default: [2](#0-1) 

When generating mainnet genesis with `--mainnet` flag, the code reads the layout file and uses `layout.chain_id` directly: [3](#0-2) 

The critical issue is that while `is_test` is hardcoded to `false` for mainnet, the `chain_id` from the layout file passes through without validation. The only validation in mainnet genesis generation checks `is_test`: [4](#0-3) 

The incorrect chain ID gets initialized on-chain: [5](#0-4) [6](#0-5) 

This stores the wrong chain ID in the on-chain resource: [7](#0-6) 

Every transaction validates against this stored chain ID: [8](#0-7) 

## Impact Explanation
This qualifies as **High Severity** per the bug bounty criteria ("Significant protocol violations"). If deployed, the network would:
- Reject all transactions signed for mainnet (chain ID 1) with `PROLOGUE_EBAD_CHAIN_ID`
- Be incompatible with all mainnet tooling, wallets, and services
- Require a hard fork or complete redeployment to fix

The chain would be fundamentally misconfigured and unusable as mainnet, though it would function internally with the wrong chain ID.

## Likelihood Explanation
**Medium-High likelihood** due to:
1. The default template actively suggests the wrong configuration
2. No validation prevents this misconfiguration
3. Operators may not realize chain_id needs manual correction
4. The `--mainnet` flag creates false confidence that all settings are mainnet-appropriate
5. This is a one-time genesis operation where mistakes are permanent

However, this requires genesis operator access, limiting exposure to network setup phase only.

## Recommendation
Add explicit validation in `fetch_mainnet_genesis_info` to ensure the chain ID is actually mainnet:

```rust
pub fn fetch_mainnet_genesis_info(git_options: GitOptions) -> CliTypedResult<MainnetGenesisInfo> {
    let client = git_options.get_client()?;
    let layout: Layout = client.get(Path::new(LAYOUT_FILE))?;

    // ADD THIS VALIDATION:
    if !layout.chain_id.is_mainnet() {
        return Err(CliError::UnexpectedError(format!(
            "Chain ID must be mainnet (1) for mainnet genesis. Found: {} ({})",
            layout.chain_id,
            layout.chain_id.id()
        )));
    }

    if layout.root_key.is_some() {
        return Err(CliError::UnexpectedError(
            "Root key must not be set for mainnet.".to_string(),
        ));
    }
    // ... rest of function
}
```

Additionally, update `Layout::default()` documentation to clearly indicate it's for test environments only.

## Proof of Concept

**Reproduction Steps:**

1. Generate layout template:
```bash
aptos genesis generate-layout-template --output-file layout.yaml
```

2. Observe generated layout.yaml contains:
```yaml
chain_id: testing  # This is ChainId::test() = 4
is_test: true
```

3. User edits other fields but forgets to change `chain_id` to `mainnet`

4. Generate mainnet genesis:
```bash
aptos genesis generate-genesis --mainnet
```

5. The genesis transaction initializes with chain_id=4 instead of chain_id=1

6. Verification: Any node starting with this genesis will reject transactions signed for actual mainnet (chain_id=1) with error code `PROLOGUE_EBAD_CHAIN_ID` (1007).

## Notes
This is a configuration vulnerability rather than a runtime exploit. It affects the genesis ceremony (performed once by trusted operators) rather than ongoing network operation. The lack of validation creates a footgun that could cause catastrophic misconfiguration during the critical network launch phase.

### Citations

**File:** aptos-core-061/crates/aptos-genesis/src/config.rs (L107-134)
```rust

```

**File:** aptos-core-061/crates/aptos/src/genesis/keys.rs (L289-291)
```rust

```

**File:** aptos-core-061/crates/aptos/src/genesis/mod.rs (L238-246)
```rust

```

**File:** aptos-core-061/aptos-move/vm-genesis/src/lib.rs (L143-143)
```rust

```

**File:** aptos-core-061/aptos-move/vm-genesis/src/lib.rs (L168-177)
```rust

```

**File:** aptos-core-061/aptos-move/vm-genesis/src/lib.rs (L553-555)
```rust

```

**File:** aptos-core-061/aptos-move/framework/aptos-framework/sources/chain_id.move (L15-18)
```text

```

**File:** aptos-core-061/aptos-move/framework/aptos-framework/sources/transaction_validation.move (L143-143)
```text

```
