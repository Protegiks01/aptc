# Audit Report

## Title
Governance Configuration Atomicity Violation Leaves Test Networks Permanently in Fast-Resolution Mode

## Summary
The `ValidateProposals` command handler contains an atomicity violation where the on-chain governance voting duration is set to 30 seconds for fast testing, but if the validation process fails or crashes, the reset to the default 43,200 seconds (12 hours) never executes. This leaves affected networks permanently in a vulnerable fast-resolution state where governance proposals can be executed with minimal review time. [1](#0-0) 

## Finding Description

The vulnerability exists in two locations with the same atomicity pattern:

**Location 1: ValidateProposals command (primary vulnerability)** [1](#0-0) 

**Location 2: execute_release function (secondary instance)** [2](#0-1) 

The `set_fast_resolve` function modifies the **on-chain** `GovernanceConfig` resource by executing a transaction that calls `aptos_governance::update_governance_config`: [3](#0-2) 

This function permanently modifies the blockchain state's `voting_duration_secs` parameter: [4](#0-3) 

**Exploitation Path:**
1. Developer/user runs `ValidateProposals` command on a test network or private network
2. Line 341-343: `set_fast_resolve(FAST_RESOLUTION_TIME)` executes successfully, setting on-chain governance voting duration to 30 seconds
3. Line 344-350: `validate_config_and_generate_release()` fails due to:
   - Network errors (connection timeout, RPC failures)
   - Transaction failures (out of gas, sequence number mismatch)
   - Script execution errors in the validation scripts
   - Process termination (Ctrl+C, OOM killer, system crash)
   - File system errors (disk full, permission issues)
4. The `?` operator propagates the error, skipping line 352-354
5. The reset to `DEFAULT_RESOLUTION_TIME` (43,200 seconds) never executes
6. **The network's governance configuration remains permanently at 30 seconds**

**Security Invariant Broken:**
This violates the **Governance Integrity** invariant by allowing proposals to be resolved in 30 seconds instead of the intended 12-hour review period, reducing time for security review and community response to malicious proposals.

**Scope Limitation:**
This vulnerability is protected from affecting mainnet by the `get_signer_testnet_only` function which checks for mint capability: [5](#0-4) 

However, it **does affect**:
- Public test networks (testnet, devnet) used by the broader developer community
- Private networks and local testing environments
- Any network where core resources has mint capability

## Impact Explanation

**Severity: Medium** per Aptos Bug Bounty criteria - "State inconsistencies requiring intervention"

**Impact on Affected Networks:**
1. **Reduced Security Review Time**: Governance proposals that normally require 12 hours for community review can now pass in 30 seconds, enabling potential governance attacks
2. **Persistent State Corruption**: The misconfiguration persists until manually detected and corrected via another on-chain transaction
3. **Shared Infrastructure Impact**: Public test networks (testnet, devnet) are shared by multiple developers and projects; leaving them in fast-resolve mode affects the entire ecosystem
4. **False Security Assumptions**: Developers testing governance mechanisms may not realize the network is in fast-resolve mode, leading to invalid test results
5. **Attack Window**: Malicious actors could exploit the fast-resolve state to push through proposals before they can be properly reviewed

While this does not affect mainnet production, it does compromise the security and reliability of test infrastructure that is critical for validating releases before mainnet deployment.

## Likelihood Explanation

**Likelihood: High**

The failure scenarios are **highly realistic** in production use:
- **Network instability**: API endpoints can timeout, rate limits can be hit, connections can drop
- **Resource constraints**: Transactions can run out of gas, especially with complex validation scripts
- **Operational errors**: Developers may Ctrl+C the process, or systems may crash
- **Script errors**: Validation scripts may contain bugs that cause transaction failures

The tool provides **no cleanup guarantees**:
- No `Drop` trait implementation for automatic cleanup
- No try-finally or defer mechanisms
- No explicit error handling to ensure reset
- The `?` operator immediately propagates errors, skipping all subsequent code

**Evidence of realistic failures:**
- Multiple async operations with `?` error propagation throughout the call chain
- Complex multi-step validation involving numerous blockchain transactions
- Network I/O dependencies on external REST endpoints
- File system operations that can fail

## Recommendation

Implement proper cleanup guarantees using Rust's `Drop` trait or explicit error handling to ensure the governance configuration is always reset, even on failure:

```rust
// Option 1: Create a RAII guard struct
struct GovernanceConfigGuard {
    network_config: NetworkConfig,
    node_api_key: Option<String>,
    original_time: u64,
}

impl GovernanceConfigGuard {
    async fn new(
        network_config: NetworkConfig, 
        fast_time: u64,
        original_time: u64,
        node_api_key: Option<String>
    ) -> Result<Self> {
        network_config.set_fast_resolve(fast_time).await?;
        Ok(Self { network_config, node_api_key, original_time })
    }
}

impl Drop for GovernanceConfigGuard {
    fn drop(&mut self) {
        // Attempt to reset - log error if fails but don't panic
        let config = self.network_config.clone();
        let api_key = self.node_api_key.clone();
        let time = self.original_time;
        tokio::spawn(async move {
            if let Err(e) = config.set_fast_resolve(time).await {
                eprintln!("Warning: Failed to reset governance config: {}", e);
            }
        });
    }
}

// Option 2: Use explicit error handling
let result = network_config.set_fast_resolve(FAST_RESOLUTION_TIME).await;
if let Err(e) = result {
    return Err(e);
}

let validation_result = aptos_release_builder::validate::validate_config_and_generate_release(
    config,
    network_config.clone(),
    output_dir,
    node_api_key.clone(),
).await;

// Always attempt reset, regardless of validation result
let reset_result = network_config.set_fast_resolve(DEFAULT_RESOLUTION_TIME).await;

// Return validation error if it failed, otherwise reset error
validation_result?;
reset_result?;
```

The fix should guarantee that reset is attempted even on error, and log/warn if the reset itself fails.

## Proof of Concept

**Reproduction Steps:**

1. Set up a local test network with governance enabled
2. Run the `ValidateProposals` command with a configuration that will fail during validation:

```bash
# Create a release config that will cause validation to fail
cat > failing_config.yaml <<EOF
name: "test-release"
proposals:
  - name: "failing-proposal"
    execution_mode: MultiStep
    metadata:
      title: "Test Proposal"
      description: "Will fail"
EOF

# Run the command and kill it after fast resolve is set but before reset
aptos-release-builder validate-proposals \
  --release-config failing_config.yaml \
  --endpoint http://localhost:8080 \
  from-args \
  --root-key <ROOT_KEY> \
  --validator-address <VALIDATOR_ADDR> \
  --validator-key <VALIDATOR_KEY> &

PID=$!
sleep 5  # Wait for set_fast_resolve to execute
kill -9 $PID  # Force kill before reset can execute
```

3. Verify the governance configuration is stuck at 30 seconds:

```rust
// Query on-chain governance config
use aptos_rest_client::Client;
use aptos_types::on_chain_config::GovernanceConfig;

let client = Client::new(url::Url::parse("http://localhost:8080").unwrap());
let config = client.get_account_resource::<GovernanceConfig>(
    AccountAddress::ONE,
    "0x1::aptos_governance::GovernanceConfig"
).await.unwrap();

assert_eq!(config.voting_duration_secs, 30);  // Should be 43200 but stuck at 30
```

4. Observe that the network remains in fast-resolve mode permanently until manually fixed with another transaction.

**Alternative PoC - Simulated Transaction Failure:**

Modify `validate_config_and_generate_release` to inject a failure after the first `set_fast_resolve`:

```rust
// In main.rs ValidateProposals handler, add:
network_config.set_fast_resolve(FAST_RESOLUTION_TIME).await?;

// Simulate failure
return Err(anyhow::anyhow!("Simulated validation failure"));

// This line never executes:
network_config.set_fast_resolve(DEFAULT_RESOLUTION_TIME).await?;
```

This demonstrates the atomicity violation leaves the governance config permanently modified.

---

**Notes:**
- This vulnerability requires access to networks with mint capability (test/private networks only)
- The issue affects the release validation tooling which is critical infrastructure for Aptos releases
- Public test networks (testnet, devnet) are shared resources and leaving them misconfigured impacts the broader ecosystem
- The vulnerability has **two separate instances** of the same atomicity pattern in the codebase

### Citations

**File:** aptos-move/aptos-release-builder/src/main.rs (L341-354)
```rust
            network_config
                .set_fast_resolve(FAST_RESOLUTION_TIME)
                .await?;
            aptos_release_builder::validate::validate_config_and_generate_release(
                config,
                network_config.clone(),
                output_dir,
                node_api_key.clone(),
            )
            .await?;
            // Reset resolution time back to normal after resolution
            network_config
                .set_fast_resolve(DEFAULT_RESOLUTION_TIME)
                .await?;
```

**File:** aptos-move/aptos-release-builder/src/validate.rs (L135-181)
```rust
    pub async fn set_fast_resolve(&self, resolution_time: u64) -> Result<()> {
        let fast_resolve_script = aptos_temppath::TempPath::new();
        fast_resolve_script.create_as_file()?;
        let mut fas_script_path = fast_resolve_script.path().to_path_buf();
        fas_script_path.set_extension("move");

        std::fs::write(fas_script_path.as_path(), format!(r#"
        script {{
            use aptos_framework::aptos_governance;

            fun main(core_resources: &signer) {{
                let core_signer = aptos_governance::get_signer_testnet_only(core_resources, @0000000000000000000000000000000000000000000000000000000000000001);

                let framework_signer = &core_signer;

                aptos_governance::update_governance_config(framework_signer, 0, 0, {});
            }}
        }}
        "#, resolution_time).as_bytes())?;

        let mut args = vec![
            "",
            "--script-path",
            fas_script_path.as_path().to_str().unwrap(),
            "--sender-account",
            "0xa550c18",
            "--private-key-file",
            self.root_key_path.as_path().to_str().unwrap(),
            "--assume-yes",
            "--encoding",
            "bcs",
            "--url",
            self.endpoint.as_str(),
        ];
        let rev = self.framework_git_rev.clone();
        let framework_path = aptos_framework_path();
        if let Some(rev) = &rev {
            args.push("--framework-git-rev");
            args.push(rev.as_str());
        } else {
            args.push("--framework-local-dir");
            args.push(framework_path.as_os_str().to_str().unwrap());
        };

        RunScript::try_parse_from(args)?.execute().await?;
        Ok(())
    }
```

**File:** aptos-move/aptos-release-builder/src/validate.rs (L469-478)
```rust
                network_config.set_fast_resolve(30).await?;
                network_config
                    .submit_and_execute_multi_step_proposal(
                        &proposal.metadata,
                        script_paths,
                        node_api_key.clone(),
                    )
                    .await?;

                network_config.set_fast_resolve(43200).await?;
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L243-275)
```text
    public fun update_governance_config(
        aptos_framework: &signer,
        min_voting_threshold: u128,
        required_proposer_stake: u64,
        voting_duration_secs: u64,
    ) acquires GovernanceConfig, GovernanceEvents {
        system_addresses::assert_aptos_framework(aptos_framework);

        let governance_config = borrow_global_mut<GovernanceConfig>(@aptos_framework);
        governance_config.voting_duration_secs = voting_duration_secs;
        governance_config.min_voting_threshold = min_voting_threshold;
        governance_config.required_proposer_stake = required_proposer_stake;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateConfig {
                    min_voting_threshold,
                    required_proposer_stake,
                    voting_duration_secs
                },
            )
        } else {
            let events = borrow_global_mut<GovernanceEvents>(@aptos_framework);
            event::emit_event<UpdateConfigEvent>(
                &mut events.update_config_events,
                UpdateConfigEvent {
                    min_voting_threshold,
                    required_proposer_stake,
                    voting_duration_secs
                },
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L721-727)
```text
    public fun get_signer_testnet_only(
        core_resources: &signer, signer_address: address): signer acquires GovernanceResponsbility {
        system_addresses::assert_core_resource(core_resources);
        // Core resources account only has mint capability in tests/testnets.
        assert!(aptos_coin::has_mint_capability(core_resources), error::unauthenticated(EUNAUTHORIZED));
        get_signer(signer_address)
    }
```
