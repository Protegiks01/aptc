# Audit Report

## Title
SafetyRulesTestConfig Production Leak via Insufficient Chain ID Validation

## Summary
The SafetyRulesTestConfig sanitization check only validates against mainnet (chain ID 1), allowing test configurations with predictable consensus keys and waypoints to leak into production validators on testnet, devnet, premainnet, or when the genesis transaction is missing. This violates the Cryptographic Correctness invariant and creates consensus safety risks.

## Finding Description

The sanitizer in `SafetyRulesConfig::sanitize()` contains a critical gap that only prevents `SafetyRulesTestConfig` on mainnet: [1](#0-0) 

This check has three bypass scenarios:

**Bypass 1: Non-Mainnet Chains**
The condition `chain_id.is_mainnet()` only returns true for chain ID 1. Validators on testnet (chain ID 2), devnet (chain ID 3), premainnet (chain ID 5), or custom chains are not protected. The `is_mainnet()` implementation explicitly only checks for chain ID 1: [2](#0-1) 

**Bypass 2: Missing Genesis Transaction**
When genesis is unavailable, the chain ID extraction fails and returns `None`, bypassing the sanitizer entirely: [3](#0-2) 

The node continues running without genesis with just a warning: [4](#0-3) 

**Bypass 3: Sanitizer Disabled**
The `skip_config_sanitizer` flag bypasses all validation: [5](#0-4) 

**Exploitation Path:**

When `SafetyRulesTestConfig` is present, the `storage()` function uses test credentials instead of production ones: [6](#0-5) 

Test configs can be inadvertently created via the public `generate_random_config_with_template()` function: [7](#0-6) 

**Security Impact:**

1. **Predictable Consensus Keys**: Test keys generated with `random_consensus_key(rng)` from a known seed are deterministic and predictable
2. **Key Collision**: Multiple validators using the same test seed will have identical consensus keys
3. **Equivocation Risk**: An attacker who knows the test key generation method could forge signatures
4. **Invalid Waypoints**: Test waypoints may not match the actual genesis, causing consensus divergence

This breaks **Invariant #2 (Consensus Safety)** and **Invariant #10 (Cryptographic Correctness)**.

## Impact Explanation

**Critical Severity** - This qualifies as a Consensus/Safety violation under the Aptos bug bounty program for the following reasons:

1. **Consensus Safety Breach**: Multiple validators with identical test consensus keys can sign conflicting votes, violating the BFT assumption that each validator has unique keys
2. **Byzantine Behavior**: Key collisions enable equivocation without requiring actual Byzantine validators
3. **Cryptographic Compromise**: Predictable test keys derived from known seeds can be precomputed by attackers
4. **Network-Wide Impact**: Affects all validators on non-mainnet production chains (testnet, premainnet) that rely on config sanitization

While testnet is often considered less critical, premainnet and production testnet validators require the same security guarantees as mainnet. The vulnerability also affects mainnet if genesis is missing during node startup.

## Likelihood Explanation

**Medium-High Likelihood** due to multiple realistic scenarios:

1. **Config Copy-Paste**: Validator operators copying configuration from test code that used `generate_random_config_with_template()`
2. **Testnet Deployment**: Operators assuming testnet allows relaxed security, not realizing test configs should never be in production
3. **Genesis Issues**: Mainnet validators with misconfigured genesis paths or missing genesis files
4. **Config Templates**: Use of the `validator_swarm()` function from `generator.rs` for non-test deployments

The public API of `generate_random_config_with_template()` and lack of clear warnings make accidental misuse plausible. [8](#0-7) 

## Recommendation

**Immediate Fix**: Extend sanitization to all production chains, not just mainnet:

```rust
// In safety_rules_config.rs, replace lines 107-112:
if let Some(chain_id) = chain_id {
    // Block test config on ALL named production chains
    if matches!(
        NamedChain::from_chain_id(&chain_id),
        Ok(NamedChain::MAINNET) | Ok(NamedChain::TESTNET) | 
        Ok(NamedChain::DEVNET) | Ok(NamedChain::PREMAINNET)
    ) && safety_rules_config.test.is_some() {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            format!(
                "Safety rules test config must not be used on production networks! Chain ID: {}",
                chain_id
            ),
        ));
    }
}

// Also reject test config when chain_id is None for validators
if chain_id.is_none() 
    && node_type.is_validator() 
    && safety_rules_config.test.is_some() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Safety rules test config cannot be used when chain ID is unknown (missing genesis)!".to_string(),
    ));
}
```

**Additional Hardening**:
1. Make `generate_random_config_with_template()` private or add `#[cfg(test)]`
2. Add explicit documentation warnings that `SafetyRulesTestConfig` is test-only
3. Add a compile-time feature flag check in `storage()` to prevent test config usage in release builds
4. Require genesis transaction for validator nodes during startup

## Proof of Concept

**PoC 1: Testnet Bypass**
```yaml
# testnet_validator.yaml
base:
    role: "validator"
    
consensus:
    safety_rules:
        test:
            author: "0xdeadbeef"
            consensus_key:
                data: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
            waypoint: 
                version: 0
                value: "0:0000000000000000000000000000000000000000000000000000000000000000"

execution:
    genesis_file_location: "testnet_genesis.blob"  # Chain ID 2 (testnet)
```

**Steps to reproduce:**
1. Create config with SafetyRulesTestConfig and testnet genesis
2. Run `NodeConfig::sanitize()` with `NodeType::Validator` and `ChainId::testnet()`
3. Sanitizer passes despite test config being present
4. Validator initializes with test credentials via `storage()` function
5. Multiple validators using same test seed will have key collisions

**PoC 2: Missing Genesis**
```rust
// Reproduction steps:
let mut node_config = NodeConfig::default();
node_config.base.role = RoleType::Validator;
node_config.consensus.safety_rules.test = Some(SafetyRulesTestConfig::new(PeerId::random()));
// Don't set execution.genesis_file_location or execution.genesis

// This passes sanitization because chain_id is None
let result = NodeConfig::sanitize(&node_config, NodeType::Validator, None);
assert!(result.is_ok());  // PASSES - test config allowed!
```

**Notes**

The vulnerability is particularly concerning for premainnet validators, which should have production-grade security despite not being mainnet. The sanitizer's narrow focus on mainnet creates a false sense of security for other production chains. Additionally, the genesis-missing scenario could affect mainnet validators during misconfigured deployments or recovery scenarios.

### Citations

**File:** config/src/config/safety_rules_config.rs (L107-112)
```rust
            if chain_id.is_mainnet() && safety_rules_config.test.is_some() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The safety rules test config should not be used in mainnet!".to_string(),
                ));
            }
```

**File:** types/src/chain_id.rs (L84-87)
```rust
    /// Returns true iff the chain ID matches mainnet
    pub fn is_mainnet(&self) -> bool {
        self.matches_named_chain(NamedChain::MAINNET)
    }
```

**File:** config/src/config/node_config_loader.rs (L117-122)
```rust
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            println!("Failed to extract the chain ID from the genesis transaction: {:?}! Continuing with None.", error);
            (node_type, None)
        },
```

**File:** aptos-node/src/storage.rs (L39-42)
```rust
    } else {
        info ! ("Genesis txn not provided! This is fine only if you don't expect to apply it. Otherwise, the config is incorrect!");
        Ok(None)
    }
```

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L28-43)
```rust
    if let Some(test_config) = &config.test {
        let author = test_config.author;
        let consensus_private_key = test_config
            .consensus_key
            .as_ref()
            .expect("Missing consensus key in test config")
            .private_key();
        let waypoint = test_config.waypoint.expect("No waypoint in config");

        PersistentSafetyStorage::initialize(
            internal_storage,
            author,
            consensus_private_key,
            waypoint,
            config.enable_cached_safety_data,
        )
```

**File:** config/src/config/node_config.rs (L224-226)
```rust
            let mut safety_rules_test_config = SafetyRulesTestConfig::new(peer_id);
            safety_rules_test_config.random_consensus_key(rng);
            node_config.consensus.safety_rules.test = Some(safety_rules_test_config);
```

**File:** config/src/generator.rs (L20-31)
```rust
pub fn validator_swarm(
    template: &NodeConfig,
    count: usize,
    seed: [u8; 32],
    randomize_ports: bool,
) -> ValidatorSwarm {
    let mut rng = StdRng::from_seed(seed);
    let mut nodes = Vec::new();

    for _ in 0..count {
        let mut node = NodeConfig::generate_random_config_with_template(template, &mut rng);
        if randomize_ports {
```
