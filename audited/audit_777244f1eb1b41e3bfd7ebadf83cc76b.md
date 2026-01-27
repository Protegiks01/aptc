# Audit Report

## Title
Genesis Supply Chain Attack: Unverified GitHub Content Enables Complete Blockchain Compromise

## Summary
The Aptos genesis generation process downloads critical validator configurations and the Move framework from GitHub without cryptographic verification. An attacker who compromises the GitHub repository can inject malicious consensus keys, validator network addresses, or a backdoored framework, achieving complete control over the blockchain from genesis.

## Finding Description

The vulnerability exists in the genesis generation workflow where validator configurations are fetched from a GitHub repository without any integrity verification.

**Vulnerable Code Path:**

1. The `get_file()` function downloads content from GitHub but performs no cryptographic verification: [1](#0-0) 

The function only decodes base64 and strips newlines - there is no hash verification or signature checking of the downloaded content.

2. During genesis generation, this client fetches critical validator configuration files: [2](#0-1) 

3. The `get_config()` function retrieves owner and operator configurations from GitHub: [3](#0-2) 

These configurations contain consensus-critical data:
- `consensus_public_key` - BLS12-381 public key for consensus signing
- `proof_of_possession` - Cryptographic proof for the consensus key
- `validator_network_public_key` - Network identity key
- `validator_host` - Network address for validator communication
- `stake_amount` - Initial stake allocation

4. The Move framework itself is also fetched without verification: [4](#0-3) 

**Attack Scenario:**

1. Attacker compromises the GitHub repository used for genesis (via stolen credentials, compromised CI/CD, or GitHub infrastructure breach)
2. Attacker modifies validator operator.yaml files to inject their own consensus keys and network addresses
3. Attacker optionally modifies framework.mrb to include backdoors in core Move modules
4. Genesis ceremony proceeds normally - operators run `aptos genesis generate-genesis`
5. The malicious configurations are downloaded and included in genesis.blob
6. Network launches with attacker-controlled validators in the consensus set
7. Attacker can now control consensus, halt the chain, or manipulate transactions

This breaks the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" - if the attacker controls enough genesis validators, they exceed the Byzantine threshold from block 0.

It also breaks **Deterministic Execution**: legitimate operators believe they're setting up honest validators, but the attacker has injected malicious keys.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability qualifies for the highest severity tier across multiple categories:

1. **Consensus/Safety Violations**: Attacker controls validator consensus keys from genesis, allowing them to:
   - Sign blocks for validators they don't legitimately control
   - Create equivocating blocks and double-signs
   - Halt consensus by refusing to participate
   - Censor transactions at will

2. **Non-recoverable Network Partition**: Once genesis is deployed with compromised validator keys, the entire blockchain state is built on a compromised foundation. Recovery requires:
   - Complete chain restart with new genesis
   - Loss of all on-chain state and history
   - Coordination across entire validator set

3. **Loss of Funds**: Attacker controlling consensus can:
   - Manipulate transaction ordering for MEV extraction
   - Censor withdrawal transactions
   - If framework is compromised: mint unlimited tokens, steal from any account

4. **Permanent Freezing of Funds**: Network could become permanently unusable if attacker halts consensus, requiring hardfork.

The impact is maximized because:
- Attack occurs at genesis, affecting the entire network from inception
- No on-chain governance exists yet to recover
- All subsequent blocks build on compromised foundation
- Detection is difficult without manual inspection of genesis.blob contents

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This attack requires compromising the GitHub repository, which is a realistic threat:

**Feasibility Factors:**
- GitHub accounts are regularly compromised (credential stuffing, phishing, leaked tokens)
- Supply chain attacks via Git repositories are increasing (SolarWinds, Codecov, etc.)
- Genesis ceremony is a one-time event with high time pressure, making thorough verification difficult
- Multiple operators may trust that "someone else" verified the repository contents
- No automated tooling exists to detect malicious genesis configurations

**Attacker Requirements:**
- Write access to the genesis GitHub repository, achievable via:
  - Compromised maintainer credentials
  - Compromised CI/CD pipeline with write permissions
  - Insider threat from repository administrator
  - GitHub infrastructure breach (low probability but high impact)

**Attack Complexity:**
- LOW - Once GitHub access is obtained, modification is trivial:
  - Edit YAML files to change consensus keys and network addresses
  - Replace framework.mrb with modified version
  - Commit changes before genesis ceremony

**Detection Difficulty:**
- HIGH - Without manual inspection:
  - Genesis.blob is a binary BCS-encoded file
  - Operators don't see raw consensus keys during setup
  - No checksums or signatures to verify against
  - Trust is implicit in the GitHub repository

**Real-World Precedent:**
- Numerous blockchain projects have suffered genesis/launch issues
- Supply chain attacks via package repositories are common (npm, PyPI)
- GitHub has had security incidents affecting repositories

While requiring GitHub compromise raises the bar, the complete network takeover and difficulty of detection make this a serious threat worthy of critical severity.

## Recommendation

Implement cryptographic verification of all genesis inputs using one or more of these approaches:

### Option 1: Multi-Party Checksums (Immediate Fix)

Have each genesis participant independently compute and publish checksums of their validator configurations:

```rust
// In aptos-github-client/src/lib.rs
use sha2::{Sha256, Digest};

pub fn get_file_with_verification(&self, path: &str, expected_hash: &str) -> Result<String, Error> {
    let content = self.get_file(path)?;
    
    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let computed_hash = hex::encode(hasher.finalize());
    
    // Verify against expected hash
    if computed_hash != expected_hash {
        return Err(Error::InternalError(format!(
            "Hash mismatch for {}: expected {}, got {}",
            path, expected_hash, computed_hash
        )));
    }
    
    Ok(content)
}
```

Usage during genesis:
- Each validator publishes SHA-256 hashes of their owner.yaml and operator.yaml on an independent channel (website, Twitter, signed message)
- Genesis coordinator collects all hashes into a manifest
- `generate-genesis` verifies downloaded files against the manifest

### Option 2: Signed Configurations (Stronger)

Require each validator to sign their configuration files with their owner key:

```rust
// Add signature field to ValidatorConfiguration
pub struct ValidatorConfiguration {
    // ... existing fields ...
    pub configuration_signature: Ed25519Signature,
}

// Verification in get_config()
fn verify_config_signature(
    config: &ValidatorConfiguration,
    content_hash: &HashValue,
) -> Result<(), CliError> {
    config.owner_account_public_key
        .verify_signature(content_hash, &config.configuration_signature)
        .map_err(|e| CliError::UnexpectedError(format!(
            "Configuration signature verification failed: {}", e
        )))
}
```

### Option 3: Threshold Signatures (Most Secure)

Use threshold signature scheme where k-of-n genesis coordinators must sign the final genesis.blob:

```rust
// After generating genesis, require threshold signatures
pub struct GenesisBundle {
    pub genesis_blob: Vec<u8>,
    pub signatures: Vec<(Ed25519PublicKey, Ed25519Signature)>,
    pub threshold: usize,
}

impl GenesisBundle {
    pub fn verify(&self, authorized_signers: &[Ed25519PublicKey]) -> Result<(), Error> {
        let genesis_hash = HashValue::sha3_256_of(&self.genesis_blob);
        
        let mut valid_signatures = 0;
        for (pubkey, signature) in &self.signatures {
            if authorized_signers.contains(pubkey) 
                && pubkey.verify_signature(&genesis_hash, signature).is_ok() {
                valid_signatures += 1;
            }
        }
        
        if valid_signatures >= self.threshold {
            Ok(())
        } else {
            Err(Error::InternalError(format!(
                "Insufficient signatures: {} < {}", valid_signatures, self.threshold
            )))
        }
    }
}
```

### Framework Verification

For the framework bundle, use deterministic builds:
- Publish framework source code hash
- Provide reproducible build instructions
- Multiple parties verify framework.mrb matches the source
- Include framework hash in signed genesis manifest

### Implementation Priority

1. **Immediate**: Add checksum verification with operator-published hashes
2. **Short-term**: Implement signed validator configurations
3. **Long-term**: Threshold signature scheme for genesis approval

## Proof of Concept

**Demonstrating the Vulnerability:**

1. **Setup malicious GitHub repository:**
```bash
# Clone genesis repository
git clone https://github.com/example/mainnet-genesis
cd mainnet-genesis

# Modify validator-1/operator.yaml
cat > validator-1/operator.yaml <<EOF
operator_account_address: "0x1234..."
operator_account_public_key: "0xabcd..."
consensus_public_key: "0xATTACKER_CONSENSUS_KEY..."  # Attacker's key
consensus_proof_of_possession: "0xATTACKER_POP..."   # Attacker's PoP
validator_network_public_key: "0xATTACKER_NETWORK_KEY..."
validator_host: "attacker.evil.com:6180"  # Attacker's server
full_node_network_public_key: null
full_node_host: null
EOF

# Commit malicious config
git add validator-1/operator.yaml
git commit -m "Update validator-1 configuration"
git push
```

2. **Victim runs genesis generation:**
```bash
# Legitimate operator runs genesis command
aptos genesis generate-genesis \
    --mainnet \
    --github-repository example/mainnet-genesis \
    --github-branch main \
    --github-token-file ~/.github-token \
    --output-dir ./genesis-output

# genesis.blob now contains attacker's consensus keys
# Validator-1 will use attacker's keys for consensus
# Network launches with compromised validator
```

3. **Verification of compromise:**
```rust
// Script to inspect genesis.blob
use aptos_types::transaction::Transaction;
use aptos_vm_genesis::GenesisTransaction;

fn inspect_genesis(genesis_path: &Path) -> Result<()> {
    let genesis_bytes = std::fs::read(genesis_path)?;
    let genesis_txn: Transaction = bcs::from_bytes(&genesis_bytes)?;
    
    // Extract validator configs from genesis
    // Will show attacker's consensus key in validator-1's config
    println!("Genesis validators: {:#?}", extract_validators(&genesis_txn));
    Ok(())
}
```

**Expected Result:** Genesis blob contains attacker-controlled consensus keys and network addresses that differ from the legitimate operator's intended configuration, demonstrating successful supply chain compromise.

**Notes:**

This vulnerability represents a fundamental architectural weakness in the genesis ceremony design. While the attack requires GitHub repository compromise, the complete absence of cryptographic verification makes such an attack undetectable and enables total network control from genesis. The impact qualifies for Critical severity under multiple bug bounty categories, including consensus violations, non-recoverable network partition, and loss of funds. Implementing multi-party verification with cryptographic signatures is essential before any mainnet genesis ceremony.

### Citations

**File:** crates/aptos-github-client/src/lib.rs (L149-165)
```rust
    pub fn get_file(&self, path: &str) -> Result<String, Error> {
        let value = self.get_internal(path)?;
        if value.len() == 1 && value[0].path == path {
            let content = value[0]
                .content
                .as_ref()
                .ok_or_else(|| Error::InternalError("No content found".into()))?;
            // Apparently GitHub introduces newlines every 60 characters and at the end of content,
            // this strips those characters out.
            Ok(content.lines().collect::<Vec<_>>().join(""))
        } else {
            Err(Error::InternalError(format!(
                "get mismatch, found {} entries",
                value.len()
            )))
        }
    }
```

**File:** crates/aptos/src/genesis/mod.rs (L137-267)
```rust
/// Retrieves all information for mainnet genesis from the Git repository
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

    let account_balance_map: AccountBalanceMap = client.get(Path::new(BALANCES_FILE))?;
    let accounts: Vec<AccountBalance> = account_balance_map.try_into()?;

    // Check that the supply matches the total
    let total_balance_supply: u64 = accounts.iter().map(|inner| inner.balance).sum();
    if total_supply != total_balance_supply {
        return Err(CliError::UnexpectedError(format!(
            "Total supply seen {} doesn't match expected total supply {}",
            total_balance_supply, total_supply
        )));
    }

    // Check that the user has a reasonable amount of APT, since below the minimum gas amount is
    // not useful 1 APT minimally
    const MIN_USEFUL_AMOUNT: u64 = 200000000;
    let ten_percent_of_total = total_supply / 10;
    for account in accounts.iter() {
        if account.balance != 0 && account.balance < MIN_USEFUL_AMOUNT {
            return Err(CliError::UnexpectedError(format!(
                "Account {} has an initial supply below expected amount {} < {}",
                account.account_address, account.balance, MIN_USEFUL_AMOUNT
            )));
        } else if account.balance > ten_percent_of_total {
            return Err(CliError::UnexpectedError(format!(
                "Account {} has an more than 10% of the total balance {} > {}",
                account.account_address, account.balance, ten_percent_of_total
            )));
        }
    }

    // Keep track of accounts for later lookup of balances
    let initialized_accounts: BTreeMap<AccountAddress, u64> = accounts
        .iter()
        .map(|inner| (inner.account_address, inner.balance))
        .collect();

    let employee_vesting_accounts: EmployeePoolMap =
        client.get(Path::new(EMPLOYEE_VESTING_ACCOUNTS_FILE))?;

    let employee_validators: Vec<_> = employee_vesting_accounts
        .inner
        .iter()
        .map(|inner| inner.validator.clone())
        .collect();
    let employee_vesting_accounts: Vec<EmployeePool> = employee_vesting_accounts.try_into()?;
    let validators = get_validator_configs(&client, &layout, true).map_err(parse_error)?;
    let mut unique_accounts = BTreeSet::new();
    let mut unique_network_keys = HashSet::new();
    let mut unique_consensus_keys = HashSet::new();
    let mut unique_consensus_pop = HashSet::new();
    let mut unique_hosts = HashSet::new();

    validate_employee_accounts(
        &employee_vesting_accounts,
        &initialized_accounts,
        &mut unique_accounts,
    )?;

    let mut seen_owners = BTreeMap::new();
    validate_validators(
        &layout,
        &employee_validators,
        &initialized_accounts,
        &mut unique_accounts,
        &mut unique_network_keys,
        &mut unique_consensus_keys,
        &mut unique_consensus_pop,
        &mut unique_hosts,
        &mut seen_owners,
        true,
    )?;
    validate_validators(
        &layout,
        &validators,
        &initialized_accounts,
        &mut unique_accounts,
        &mut unique_network_keys,
        &mut unique_consensus_keys,
        &mut unique_consensus_pop,
        &mut unique_hosts,
        &mut seen_owners,
        false,
    )?;

    let framework = client.get_framework()?;
    Ok(MainnetGenesisInfo::new(
        layout.chain_id,
        accounts,
        employee_vesting_accounts,
        validators,
        framework,
        &GenesisConfiguration {
            allow_new_validators: true,
            epoch_duration_secs: layout.epoch_duration_secs,
            is_test: false,
            min_stake: layout.min_stake,
            min_voting_threshold: layout.min_voting_threshold,
            max_stake: layout.max_stake,
            recurring_lockup_duration_secs: layout.recurring_lockup_duration_secs,
            required_proposer_stake: layout.required_proposer_stake,
            rewards_apy_percentage: layout.rewards_apy_percentage,
            voting_duration_secs: layout.voting_duration_secs,
            voting_power_increase_limit: layout.voting_power_increase_limit,
            employee_vesting_start: layout.employee_vesting_start,
            employee_vesting_period_duration: layout.employee_vesting_period_duration,
            consensus_config: OnChainConsensusConfig::default_for_genesis(),
            execution_config: OnChainExecutionConfig::default_for_genesis(),
            gas_schedule: default_gas_schedule(),
            initial_features_override: None,
            randomness_config_override: None,
            jwk_consensus_config_override: None,
            initial_jwks: vec![],
            keyless_groth16_vk: None,
        },
    )?)
}
```

**File:** crates/aptos/src/genesis/mod.rs (L352-535)
```rust
fn get_config(
    client: &Client,
    user: &str,
    is_mainnet: bool,
) -> CliTypedResult<ValidatorConfiguration> {
    // Load a user's configuration files
    let dir = PathBuf::from(user);
    let owner_file = dir.join(OWNER_FILE);
    let owner_file = owner_file.as_path();
    let owner_config = client.get::<StringOwnerConfiguration>(owner_file)?;

    // Check and convert fields in owner file
    let owner_account_address: AccountAddress = parse_required_option(
        &owner_config.owner_account_address,
        owner_file,
        "owner_account_address",
        AccountAddressWithChecks::from_str,
    )?
    .into();
    let owner_account_public_key = parse_required_option(
        &owner_config.owner_account_public_key,
        owner_file,
        "owner_account_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;

    let operator_account_address: AccountAddress = parse_required_option(
        &owner_config.operator_account_address,
        owner_file,
        "operator_account_address",
        AccountAddressWithChecks::from_str,
    )?
    .into();
    let operator_account_public_key = parse_required_option(
        &owner_config.operator_account_public_key,
        owner_file,
        "operator_account_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;

    let voter_account_address: AccountAddress = parse_required_option(
        &owner_config.voter_account_address,
        owner_file,
        "voter_account_address",
        AccountAddressWithChecks::from_str,
    )?
    .into();
    let voter_account_public_key = parse_required_option(
        &owner_config.voter_account_public_key,
        owner_file,
        "voter_account_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;

    let stake_amount = parse_required_option(
        &owner_config.stake_amount,
        owner_file,
        "stake_amount",
        u64::from_str,
    )?;

    // Default to 0 for commission percentage if missing.
    let commission_percentage = parse_optional_option(
        &owner_config.commission_percentage,
        owner_file,
        "commission_percentage",
        u64::from_str,
    )?
    .unwrap_or(0);

    // Default to true for whether the validator should be joining during genesis.
    let join_during_genesis = parse_optional_option(
        &owner_config.join_during_genesis,
        owner_file,
        "join_during_genesis",
        bool::from_str,
    )?
    .unwrap_or(true);

    // We don't require the operator file if the validator is not joining during genesis.
    if is_mainnet && !join_during_genesis {
        return Ok(ValidatorConfiguration {
            owner_account_address: owner_account_address.into(),
            owner_account_public_key,
            operator_account_address: operator_account_address.into(),
            operator_account_public_key,
            voter_account_address: voter_account_address.into(),
            voter_account_public_key,
            consensus_public_key: None,
            proof_of_possession: None,
            validator_network_public_key: None,
            validator_host: None,
            full_node_network_public_key: None,
            full_node_host: None,
            stake_amount,
            commission_percentage,
            join_during_genesis,
        });
    };

    let operator_file = dir.join(OPERATOR_FILE);
    let operator_file = operator_file.as_path();
    let operator_config = client.get::<StringOperatorConfiguration>(operator_file)?;

    // Check and convert fields in operator file
    let operator_account_address_from_file: AccountAddress = parse_required_option(
        &operator_config.operator_account_address,
        operator_file,
        "operator_account_address",
        AccountAddressWithChecks::from_str,
    )?
    .into();
    let operator_account_public_key_from_file = parse_required_option(
        &operator_config.operator_account_public_key,
        operator_file,
        "operator_account_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;
    let consensus_public_key = parse_required_option(
        &operator_config.consensus_public_key,
        operator_file,
        "consensus_public_key",
        |str| parse_key(bls12381::PublicKey::LENGTH, str),
    )?;
    let consensus_proof_of_possession = parse_required_option(
        &operator_config.consensus_proof_of_possession,
        operator_file,
        "consensus_proof_of_possession",
        |str| parse_key(bls12381::ProofOfPossession::LENGTH, str),
    )?;
    let validator_network_public_key = parse_required_option(
        &operator_config.validator_network_public_key,
        operator_file,
        "validator_network_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;
    let full_node_network_public_key = parse_optional_option(
        &operator_config.full_node_network_public_key,
        operator_file,
        "full_node_network_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;

    // Verify owner & operator agree on operator
    if operator_account_address != operator_account_address_from_file {
        return Err(
            CliError::CommandArgumentError(
                format!("Operator account {} in owner file {} does not match operator account {} in operator file {}",
                        operator_account_address,
                        owner_file.display(),
                        operator_account_address_from_file,
                        operator_file.display()
                )));
    }
    if operator_account_public_key != operator_account_public_key_from_file {
        return Err(
            CliError::CommandArgumentError(
                format!("Operator public key {} in owner file {} does not match operator public key {} in operator file {}",
                        operator_account_public_key,
                        owner_file.display(),
                        operator_account_public_key_from_file,
                        operator_file.display()
                )));
    }

    // Build Validator configuration
    Ok(ValidatorConfiguration {
        owner_account_address: owner_account_address.into(),
        owner_account_public_key,
        operator_account_address: operator_account_address.into(),
        operator_account_public_key,
        voter_account_address: voter_account_address.into(),
        voter_account_public_key,
        consensus_public_key: Some(consensus_public_key),
        proof_of_possession: Some(consensus_proof_of_possession),
        validator_network_public_key: Some(validator_network_public_key),
        validator_host: Some(operator_config.validator_host),
        full_node_network_public_key,
        full_node_host: operator_config.full_node_host,
        stake_amount,
        commission_percentage,
        join_during_genesis,
    })
}
```

**File:** crates/aptos/src/genesis/git.rs (L230-247)
```rust
    pub fn get_framework(&self) -> CliTypedResult<ReleaseBundle> {
        match self {
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(FRAMEWORK_NAME);
                if !path.exists() {
                    return Err(CliError::UnableToReadFile(
                        path.display().to_string(),
                        "File not found".to_string(),
                    ));
                }
                Ok(ReleaseBundle::read(path)?)
            },
            Client::Github(client) => {
                let bytes = base64::decode(client.get_file(FRAMEWORK_NAME)?)?;
                Ok(bcs::from_bytes::<ReleaseBundle>(&bytes)?)
            },
        }
    }
```
