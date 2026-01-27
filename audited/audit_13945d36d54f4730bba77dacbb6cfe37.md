# Audit Report

## Title
Inadequate Protection Against Accidental Private Key Exposure via Git Repositories

## Summary
The Aptos genesis key generation workflow creates similarly-named files (`private-keys.yaml` and `public-keys.yaml`) without adequate safeguards to prevent operators from accidentally committing private keys to git repositories. The `.gitignore` file does not protect these sensitive YAML files, and the validator configuration workflow explicitly involves git repository usage, creating a high-risk scenario for key leakage.

## Finding Description

The genesis key generation system generates validator keys and stores them in YAML files with very similar names: [1](#0-0) 

The `private-keys.yaml` file contains all private cryptographic material: [2](#0-1) 

While the `public-keys.yaml` file contains only public keys: [3](#0-2) 

**Critical Gap #1: No .gitignore Protection**

The repository's `.gitignore` file protects `**/*.key` and `**/*.pub` files but does NOT protect the YAML files containing private keys: [4](#0-3) 

**Critical Gap #2: Git-Based Workflow**

The validator configuration workflow explicitly uses git repositories (local or GitHub) to share configurations: [5](#0-4) [6](#0-5) 

**Critical Gap #3: File Naming Confusion**

The file names differ by only one word ("private" vs "public"), making confusion highly likely in operational scenarios. The documentation shows that operators work with both files in the same directory during genesis setup: [7](#0-6) 

**Critical Gap #4: Insufficient Warnings**

The documentation only provides a generic warning to "backup your key files somewhere safe" without explicitly stating that private key files must NEVER be committed to git: [8](#0-7) 

**Attack Scenario:**

1. Operator generates keys using `aptos genesis generate-keys`
2. Operator receives four files including `private-keys.yaml` and `public-keys.yaml` in the same directory
3. Operator follows documentation to set up validator configuration with git repository
4. Due to similar naming and lack of clear warnings, operator runs `git add private-keys.yaml` instead of `git add public-keys.yaml`
5. Private keys are committed to git repository (potentially public GitHub)
6. Attacker discovers private keys in git history
7. Attacker gains full control of validator account, consensus keys, and network keys

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria for the following reasons:

1. **Loss of Funds**: Leaked `account_private_key` allows theft of all staked funds and rewards
2. **Consensus Compromise**: Leaked `consensus_private_key` enables validator impersonation and potential consensus violations
3. **Network Security**: Leaked network private keys allow man-in-the-middle attacks on validator communications
4. **Permanent Damage**: Once private keys are in git history, they cannot be easily removed (requires force-push and all clones to update)

While not reaching Critical severity (as it requires operator error), the impact of successful exploitation is catastrophic, affecting validator security, potential fund theft, and network integrity.

## Likelihood Explanation

The likelihood is **HIGH** for the following reasons:

1. **Common Operational Pattern**: Validators routinely share configurations via git repositories as documented in official tutorials
2. **High Cognitive Load**: Operators manage multiple YAML files simultaneously during genesis setup
3. **Similar Naming**: Only one-word difference between file names increases confusion risk
4. **No Technical Prevention**: No .gitignore protection or runtime validation prevents this mistake
5. **Documentation Gap**: Official documentation doesn't explicitly warn against this specific risk
6. **Real-World Precedent**: Similar key leakage incidents are common in blockchain operations

The combination of workflow requirements (git usage), similar file names, lack of technical safeguards, and insufficient warnings creates a high-probability scenario for accidental key exposure.

## Recommendation

Implement multiple layers of protection:

**1. Update .gitignore to protect sensitive YAML files:**

```
# Private key files - NEVER commit these
**/private-keys.yaml
**/validator-identity.yaml
**/validator-full-node-identity.yaml
```

**2. Add pre-commit validation in key generation:**

Add a warning message after key generation in `GenerateKeys::execute()`:

```rust
// After line 97 in crates/aptos/src/genesis/keys.rs
eprintln!("\n⚠️  WARNING: NEVER commit private-keys.yaml, validator-identity.yaml, or");
eprintln!("   validator-full-node-identity.yaml to git repositories!");
eprintln!("   These files contain private keys that control your validator.\n");
eprintln!("   ✓ Safe to commit: public-keys.yaml");
eprintln!("   ✗ NEVER commit: private-keys.yaml, validator-identity.yaml, validator-full-node-identity.yaml\n");
```

**3. Rename files for clarity:**

Change naming to make the distinction unmistakable:
- `private-keys.yaml` → `PRIVATE-KEYS-DO-NOT-SHARE.yaml`
- `public-keys.yaml` → `public-keys-safe-to-share.yaml`

**4. Add runtime validation in SetValidatorConfiguration:**

Validate that the provided file contains PublicIdentity, not PrivateIdentity:

```rust
pub fn read_public_identity_file(public_identity_file: &Path) -> CliTypedResult<PublicIdentity> {
    let bytes = read_from_file(public_identity_file)?;
    let content = String::from_utf8(bytes).map_err(CliError::from)?;
    
    // Check if file contains private key fields
    if content.contains("account_private_key") || 
       content.contains("consensus_private_key") ||
       content.contains("network_private_key") {
        return Err(CliError::CommandArgumentError(
            format!("SECURITY ERROR: {} appears to contain PRIVATE keys. This command requires a PUBLIC keys file. Never share or commit private key files!",
                public_identity_file.display())
        ));
    }
    
    from_yaml(&content)
}
```

**5. Generate .gitignore automatically:**

When generating keys, automatically create/update `.gitignore` in the output directory to protect private files.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Demonstrate accidental private key exposure scenario

# Step 1: Generate validator keys
aptos genesis generate-keys --output-dir ./validator-setup

# Step 2: Initialize a git repository (simulating operator workflow)
cd validator-setup
git init

# Step 3: Operator mistake - adds wrong file (this SHOULD be prevented)
# Current state: No error occurs, no warning issued
git add private-keys.yaml  # DANGEROUS - but currently allowed

# Step 4: Commit and push (simulating sharing to GitHub)
git commit -m "Add validator configuration"
# git push origin main  # Private keys now exposed in git history

# Step 5: Demonstrate the exposure
echo "Contents of git repository:"
git show HEAD:private-keys.yaml
# Private keys are now visible in git history

# Expected behavior: Command should FAIL with error at Step 3
# Actual behavior: Succeeds, keys leaked to git
```

To verify the current vulnerability:

1. Run `aptos genesis generate-keys --output-dir test-keys`
2. Check `.gitignore` - it does NOT contain entries for the YAML files
3. Files `private-keys.yaml` and `public-keys.yaml` are created with similar names
4. No warning is issued about git safety
5. Both files can be committed to git without error

**Notes**

This is an operational security vulnerability in the design and implementation of the genesis key management workflow. While it requires operator error to exploit, the combination of (1) similar file naming, (2) lack of .gitignore protection, (3) git-based workflows, and (4) insufficient warnings creates an unacceptable risk for a system managing cryptographic keys worth potentially millions of dollars. The vulnerability exists in the codebase's design choices and can be fixed through the recommended code and documentation changes.

### Citations

**File:** crates/aptos/src/genesis/keys.rs (L28-31)
```rust
const PRIVATE_KEYS_FILE: &str = "private-keys.yaml";
pub const PUBLIC_KEYS_FILE: &str = "public-keys.yaml";
const VALIDATOR_FILE: &str = "validator-identity.yaml";
const VFN_FILE: &str = "validator-full-node-identity.yaml";
```

**File:** crates/aptos/src/genesis/keys.rs (L157-161)
```rust
#[async_trait]
impl CliCommand<()> for SetValidatorConfiguration {
    fn command_name(&self) -> &'static str {
        "SetValidatorConfiguration"
    }
```

**File:** crates/aptos/src/genesis/keys.rs (L258-260)
```rust
        let git_client = self.git_options.get_client()?;
        git_client.put(operator_file.as_path(), &operator_config)?;
        git_client.put(owner_file.as_path(), &owner_config)
```

**File:** crates/aptos-genesis/src/keys.rs (L14-22)
```rust
/// Type for serializing private keys file
#[derive(Deserialize, Serialize)]
pub struct PrivateIdentity {
    pub account_address: AccountAddress,
    pub account_private_key: Ed25519PrivateKey,
    pub consensus_private_key: bls12381::PrivateKey,
    pub full_node_network_private_key: x25519::PrivateKey,
    pub validator_network_private_key: x25519::PrivateKey,
}
```

**File:** crates/aptos-genesis/src/keys.rs (L24-33)
```rust
/// Type for serializing public keys file
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PublicIdentity {
    pub account_address: AccountAddress,
    pub account_public_key: Ed25519PublicKey,
    pub consensus_public_key: Option<bls12381::PublicKey>,
    pub consensus_proof_of_possession: Option<bls12381::ProofOfPossession>,
    pub full_node_network_public_key: Option<x25519::PublicKey>,
    pub validator_network_public_key: Option<x25519::PublicKey>,
}
```

**File:** .gitignore (L166-167)
```ignore
**/*.key
**/*.pub
```

**File:** terraform/aptos-node/gcp/README.md (L114-114)
```markdown
    This will create four files: `public-keys.yaml`, `private-keys.yaml`, `validator-identity.yaml`, `validator-full-node-identity.yaml` for you. **IMPORTANT**: Backup your key files somewhere safe. These key files are important for you to establish ownership of your node, and you will use this information to claim your rewards later if eligible.
```

**File:** terraform/aptos-node/gcp/README.md (L178-186)
```markdown
15. To recap, in your working directory, you should have a list of files:
    - `private-keys.yaml` Private keys for owner account, consensus, networking
    - `validator-identity.yaml` Private keys for setting validator identity
    - `validator-full-node-identity.yaml` Private keys for setting validator full node identity
    - `<username>.yaml` Node info for both validator / fullnode
    - `layout.yaml` layout file to define root key, validator user, and chain ID
    - `framework` folder which contains all the move bytecode for AptosFramework.
    - `waypoint.txt` waypoint for genesis transaction
    - `genesis.blob` genesis binary contains all the info about framework, validatorSet and more.
```
