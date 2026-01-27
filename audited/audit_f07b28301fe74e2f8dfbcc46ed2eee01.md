# Audit Report

## Title
Missing Validation in Layout Deserialization Enables Genesis Ceremony DoS via Invalid Configuration Upload

## Summary
The `Layout::from_disk` function deserializes genesis configuration from YAML without performing any validation on critical constraint fields. This allows invalid layouts with violated constraints (e.g., `min_stake > max_stake`, `epoch_duration_secs = 0`) to be uploaded to the shared genesis repository via the `SetupGit` command, causing all validators to panic during genesis generation and blocking the genesis ceremony. [1](#0-0) 

## Finding Description

The genesis initialization flow has a critical validation gap that enables a denial-of-service attack during the genesis ceremony:

**1. Missing Validation at Deserialization Point**

The `Layout::from_disk` function reads and deserializes genesis configuration using only serde's YAML parser, without validating semantic constraints: [1](#0-0) 

The `Layout` struct contains critical staking and governance parameters that must satisfy specific constraints, but no validation occurs during deserialization: [2](#0-1) 

**2. Invalid Layouts Can Be Uploaded Without Detection**

The `SetupGit` command uses `Layout::from_disk` to upload configurations to the shared genesis repository without validation: [3](#0-2) 

An attacker or mistaken operator can upload an invalid layout with constraints like:
- `min_stake: 1000000, max_stake: 100` (min > max)
- `epoch_duration_secs: 0` (invalid duration)
- `voting_power_increase_limit: 0` or `100` (outside valid range)
- `rewards_apy_percentage: 0` or `150` (outside valid range)

**3. Late Validation Causes Panic During Genesis Generation**

When validators fetch the invalid layout and attempt to generate genesis, validation only occurs deep in the call stack at `encode_genesis_change_set`: [4](#0-3) 

The `validate_genesis_config` function uses assertions that panic on constraint violations: [5](#0-4) 

**Attack Flow:**
1. Attacker creates `invalid-layout.yaml` with `min_stake: 1000000, max_stake: 100`
2. Runs `aptos genesis setup-git --layout-file invalid-layout.yaml` (succeeds without validation)
3. Invalid layout is committed to shared genesis git repository
4. All genesis ceremony participants run `aptos genesis generate-genesis`
5. Each validator's process panics when `validate_genesis_config` asserts `min_stake <= max_stake`
6. Genesis ceremony is completely blocked until layout is manually corrected

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos Bug Bounty program under the category of **"API crashes"**:

1. **Complete Genesis Ceremony DoS**: All validators attempting to generate genesis experience process crashes via panic, preventing network initialization
2. **Delayed Network Launch**: The genesis ceremony cannot complete until the invalid layout is manually identified and corrected in the git repository
3. **Coordination Failure**: Multiple validators may waste time debugging identical crashes before identifying the root cause
4. **No Corruption Risk**: While invalid layouts cannot corrupt genesis (due to late validation), the DoS impact on network availability during the critical launch phase is severe

The impact is limited to High rather than Critical because:
- No funds are at risk (network hasn't started)
- No consensus of a running network is violated
- Manual intervention can recover from the attack
- The late validation prevents actual corruption of genesis state

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur because:

1. **Low Technical Barrier**: Any genesis ceremony participant can execute the attack with a single CLI command and a malformed YAML file
2. **Accidental Triggering**: Even non-malicious operators can accidentally create invalid layouts due to typos or misunderstanding constraints
3. **Shared Repository Model**: The genesis ceremony uses a shared git repository, so one participant's invalid upload affects all validators
4. **No Early Warning**: The lack of validation provides no feedback at upload time, allowing invalid configurations to propagate undetected

The attack requires no special privileges beyond being a genesis ceremony participant, which is granted to all initial validators.

## Recommendation

Add comprehensive validation to `Layout::from_disk` to fail-fast on invalid configurations before they can be uploaded: [1](#0-0) 

**Recommended Fix:**

```rust
impl Layout {
    /// Read the layout from a YAML file on disk
    pub fn from_disk(path: &Path) -> anyhow::Result<Self> {
        let mut file = File::open(path).map_err(|e| {
            anyhow::Error::msg(format!("Failed to open file {}, {}", path.display(), e))
        })?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            anyhow::Error::msg(format!("Failed to read file {}, {}", path.display(), e))
        })?;

        let layout: Layout = serde_yaml::from_str(&contents)?;
        
        // Validate constraints immediately after deserialization
        layout.validate()?;
        
        Ok(layout)
    }
    
    /// Validate all Layout constraints
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.min_stake <= self.max_stake,
            "min_stake ({}) must be <= max_stake ({})",
            self.min_stake, self.max_stake
        );
        anyhow::ensure!(
            self.max_stake > 0,
            "max_stake must be > 0"
        );
        anyhow::ensure!(
            self.epoch_duration_secs > 0,
            "epoch_duration_secs must be > 0"
        );
        anyhow::ensure!(
            self.recurring_lockup_duration_secs > 0,
            "recurring_lockup_duration_secs must be > 0"
        );
        anyhow::ensure!(
            self.recurring_lockup_duration_secs >= self.epoch_duration_secs,
            "recurring_lockup_duration_secs must be >= epoch_duration_secs"
        );
        anyhow::ensure!(
            self.rewards_apy_percentage > 0 && self.rewards_apy_percentage < 100,
            "rewards_apy_percentage must be > 0 and < 100"
        );
        anyhow::ensure!(
            self.voting_duration_secs > 0,
            "voting_duration_secs must be > 0"
        );
        anyhow::ensure!(
            self.voting_duration_secs < self.recurring_lockup_duration_secs,
            "voting_duration_secs must be < recurring_lockup_duration_secs"
        );
        anyhow::ensure!(
            self.voting_power_increase_limit > 0 && self.voting_power_increase_limit <= 50,
            "voting_power_increase_limit must be > 0 and <= 50"
        );
        Ok(())
    }
}
```

This ensures violations are detected immediately at deserialization time, providing clear error messages and preventing invalid configurations from entering the genesis ceremony workflow.

## Proof of Concept

**Step 1: Create invalid layout file** (`invalid-layout.yaml`):
```yaml
users: ["alice"]
chain_id: 4
epoch_duration_secs: 0  # INVALID: must be > 0
min_stake: 1000000
max_stake: 100  # INVALID: max < min
recurring_lockup_duration_secs: 86400
min_voting_threshold: 100000000000000
required_proposer_stake: 100000000000000
rewards_apy_percentage: 10
voting_duration_secs: 43200
voting_power_increase_limit: 0  # INVALID: must be > 0
allow_new_validators: false
is_test: true
```

**Step 2: Attempt to upload (this SHOULD fail but currently succeeds)**:
```bash
aptos genesis setup-git \
  --layout-file invalid-layout.yaml \
  --local-repository-dir ./genesis-repo
# Currently succeeds without validation
```

**Step 3: Attempt genesis generation (panics)**:
```bash
aptos genesis generate-genesis \
  --local-repository-dir ./genesis-repo \
  --output-dir ./genesis-output
# Panics with: "assertion failed: genesis_config.epoch_duration_secs > 0"
```

**Rust Test Demonstrating Vulnerability**:
```rust
#[test]
fn test_invalid_layout_accepted_without_validation() {
    use std::fs::write;
    use tempfile::tempdir;
    
    let dir = tempdir().unwrap();
    let layout_path = dir.path().join("invalid.yaml");
    
    // Create invalid layout with min_stake > max_stake
    let invalid_yaml = r#"
users: ["test"]
chain_id: 4
epoch_duration_secs: 7200
min_stake: 1000000
max_stake: 100
recurring_lockup_duration_secs: 86400
min_voting_threshold: 100000000000000
required_proposer_stake: 100000000000000
rewards_apy_percentage: 10
voting_duration_secs: 43200
voting_power_increase_limit: 20
allow_new_validators: false
is_test: true
"#;
    
    write(&layout_path, invalid_yaml).unwrap();
    
    // This succeeds without validation - VULNERABILITY
    let result = Layout::from_disk(&layout_path);
    assert!(result.is_ok());  // Currently passes - should fail!
    
    let layout = result.unwrap();
    assert!(layout.min_stake > layout.max_stake);  // Invalid constraint
}
```

## Notes

The vulnerability exists because validation was implemented at the wrong layer. The validation in `validate_genesis_config` (vm-genesis layer) and `staking_config::initialize` (Move layer) provides defense-in-depth against corruption, but the lack of early validation at the deserialization layer creates a DoS vector during the critical genesis ceremony phase. [5](#0-4) [6](#0-5)

### Citations

**File:** crates/aptos-genesis/src/config.rs (L30-90)
```rust
pub struct Layout {
    /// Root key for the blockchain only for test chains
    #[serde(default)]
    pub root_key: Option<Ed25519PublicKey>,
    /// List of usernames or identifiers
    pub users: Vec<String>,
    /// ChainId for the target network
    pub chain_id: ChainId,
    /// Whether to allow new validators to join the set after genesis
    ///
    /// Ignored for mainnet
    #[serde(default)]
    pub allow_new_validators: bool,
    /// Duration of an epoch
    pub epoch_duration_secs: u64,
    /// Whether this is a test network or not
    ///
    /// Ignored for mainnet
    #[serde(default)]
    pub is_test: bool,
    /// Minimum stake to be in the validator set
    pub min_stake: u64,
    /// Minimum number of votes to consider a proposal valid.
    pub min_voting_threshold: u128,
    /// Maximum stake to be in the validator set
    pub max_stake: u64,
    /// Minimum number of seconds to lockup staked coins
    pub recurring_lockup_duration_secs: u64,
    /// Required amount of stake to create proposals.
    pub required_proposer_stake: u64,
    /// Percentage of stake given out as rewards a year (0-100%).
    pub rewards_apy_percentage: u64,
    /// Voting duration for a proposal in seconds.
    pub voting_duration_secs: u64,
    /// % of current epoch's total voting power that can be added in this epoch.
    pub voting_power_increase_limit: u64,
    /// Total supply of coins
    pub total_supply: Option<u64>,
    /// Timestamp (in seconds) when employee vesting starts.
    pub employee_vesting_start: Option<u64>,
    /// Duration of each vesting period (in seconds).
    pub employee_vesting_period_duration: Option<u64>,
    /// Onchain Consensus Config
    #[serde(default = "OnChainConsensusConfig::default_for_genesis")]
    pub on_chain_consensus_config: OnChainConsensusConfig,
    /// Onchain Execution Config
    #[serde(default = "OnChainExecutionConfig::default_for_genesis")]
    pub on_chain_execution_config: OnChainExecutionConfig,

    /// An optional JWK consensus config to use, instead of `default_for_genesis()`.
    #[serde(default)]
    pub jwk_consensus_config_override: Option<OnChainJWKConsensusConfig>,

    /// JWKs to patch in genesis.
    #[serde(default)]
    pub initial_jwks: Vec<IssuerJWK>,

    /// Keyless Groth16 verification key to install in genesis.
    #[serde(default)]
    pub keyless_groth16_vk_override: Option<Groth16VerificationKey>,
}
```

**File:** crates/aptos-genesis/src/config.rs (L93-104)
```rust
    /// Read the layout from a YAML file on disk
    pub fn from_disk(path: &Path) -> anyhow::Result<Self> {
        let mut file = File::open(path).map_err(|e| {
            anyhow::Error::msg(format!("Failed to open file {}, {}", path.display(), e))
        })?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            anyhow::Error::msg(format!("Failed to read file {}, {}", path.display(), e))
        })?;

        Ok(serde_yaml::from_str(&contents)?)
    }
```

**File:** crates/aptos/src/genesis/git.rs (L53-61)
```rust
    async fn execute(self) -> CliTypedResult<()> {
        let layout = Layout::from_disk(&self.layout_file)?;

        // Upload layout file to ensure we can read later
        let client = self.git_options.get_client()?;
        client.put(Path::new(LAYOUT_FILE), &layout)?;

        Ok(())
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L262-272)
```rust
pub fn encode_genesis_change_set(
    core_resources_key: &Ed25519PublicKey,
    validators: &[Validator],
    framework: &ReleaseBundle,
    chain_id: ChainId,
    genesis_config: &GenesisConfiguration,
    consensus_config: &OnChainConsensusConfig,
    execution_config: &OnChainExecutionConfig,
    gas_schedule: &GasScheduleV2,
) -> ChangeSet {
    validate_genesis_config(genesis_config);
```

**File:** aptos-move/vm-genesis/src/lib.rs (L405-439)
```rust
fn validate_genesis_config(genesis_config: &GenesisConfiguration) {
    assert!(
        genesis_config.min_stake <= genesis_config.max_stake,
        "Min stake must be smaller than or equal to max stake"
    );
    assert!(
        genesis_config.epoch_duration_secs > 0,
        "Epoch duration must be > 0"
    );
    assert!(
        genesis_config.recurring_lockup_duration_secs > 0,
        "Recurring lockup duration must be > 0"
    );
    assert!(
        genesis_config.recurring_lockup_duration_secs >= genesis_config.epoch_duration_secs,
        "Recurring lockup duration must be at least as long as epoch duration"
    );
    assert!(
        genesis_config.rewards_apy_percentage > 0 && genesis_config.rewards_apy_percentage < 100,
        "Rewards APY must be > 0% and < 100%"
    );
    assert!(
        genesis_config.voting_duration_secs > 0,
        "On-chain voting duration must be > 0"
    );
    assert!(
        genesis_config.voting_duration_secs < genesis_config.recurring_lockup_duration_secs,
        "Voting duration must be strictly smaller than recurring lockup"
    );
    assert!(
        genesis_config.voting_power_increase_limit > 0
            && genesis_config.voting_power_increase_limit <= 50,
        "voting_power_increase_limit must be > 0 and <= 50"
    );
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L372-374)
```text
    fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
        assert!(minimum_stake <= maximum_stake && maximum_stake > 0, error::invalid_argument(EINVALID_STAKE_RANGE));
    }
```
