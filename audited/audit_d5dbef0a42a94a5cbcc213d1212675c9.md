# Audit Report

## Title
Insecure File Permissions on mint.key Allows Local Privilege Escalation in Test Environments

## Summary
The `create_single_node_test_config()` function creates the `mint.key` file containing the blockchain root private key using `fs::File::create()` without setting secure file permissions. On Unix systems, this results in world-readable permissions (typically 0644), allowing any local user to steal the root key and gain complete control over test blockchain networks. [1](#0-0) 

## Finding Description
The vulnerability exists in the key file creation process where the root/mint private key is written to disk without explicit permission restrictions. The code uses Rust's standard `fs::File::create()` method, which creates files with default permissions subject to the process's umask. On most Unix systems with default umask of 0022, this results in 0644 permissions (owner: read/write, group: read, others: read).

This breaks the **Access Control** invariant, as cryptographic private keys must be protected from unauthorized access. The codebase contains secure alternatives that are used elsewhere for key management: [2](#0-1) 

These secure functions explicitly set mode 0o600 (owner read/write only) on Unix systems. However, the test node configuration function does not use them.

The same vulnerability exists in the local swarm implementation: [3](#0-2) 

**Attack Scenario:**
1. Developer runs `aptos-node --test --test-dir /shared/test-node` on a shared development server or CI/CD runner
2. The mint.key file is created with 0644 permissions at `/shared/test-node/mint.key`
3. Attacker with local user access runs: `cat /shared/test-node/mint.key`
4. Attacker extracts the BCS-serialized root private key
5. Attacker gains complete control: can mint unlimited tokens, manipulate governance, control all accounts on the test network

## Impact Explanation
**Severity: High** (considering test-environment scope)

While this vulnerability only affects test mode environments (invoked with `--test` flag), it presents real security risks in several scenarios:

1. **Shared Development Environments**: Multiple developers on the same server
2. **CI/CD Pipelines**: Automated testing on shared runners where other jobs/users may access the filesystem
3. **Docker Containers**: Container escape scenarios where host filesystem access is gained
4. **Academic/Research Settings**: University labs or research clusters with multiple users

The impact includes:
- **Complete test network compromise**: Root key allows unlimited token minting
- **Governance manipulation**: Can execute any governance proposal
- **Account takeover**: Can impersonate any account on the test network
- **Data integrity loss**: Can manipulate blockchain state arbitrarily

Per Aptos bug bounty criteria, this represents a **significant protocol violation** and potential **state inconsistency** issue, though limited to test environments.

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability will trigger automatically whenever:
- The `--test` flag is used to start a single-node test network
- The host operating system is Unix-based (Linux, macOS)
- Multiple users have access to the filesystem (shared servers, CI/CD)
- Default umask settings are in place (0022 is standard)

Mitigating factors:
- Only affects test mode, not production deployments
- Requires local filesystem access
- Developers may use single-user machines where this is less critical

However, modern development practices increasingly use shared infrastructure (CI/CD, cloud development environments, container platforms) where this vulnerability becomes highly exploitable.

## Recommendation
Replace the insecure `fs::File::create()` call with the secure `write_to_user_only_file()` function that already exists in the codebase:

**Current vulnerable code:** [1](#0-0) 

**Recommended fix:**
```rust
// Add import at the top of the file
use crate::utils::write_to_user_only_file;

// Replace lines 618-621 with:
let serialized_keys = bcs::to_bytes(&root_key)?;
write_to_user_only_file(
    aptos_root_key_path.as_path(),
    "mint.key",
    &serialized_keys,
)?;
```

Note: The `write_to_user_only_file()` function may need to be made accessible from the utils module or copied into this module.

Similarly, fix the local swarm implementation: [3](#0-2) 

## Proof of Concept

**Step 1: Start a test node**
```bash
# As user 'developer'
aptos-node --test --test-dir /tmp/test-aptos
```

**Step 2: Check file permissions**
```bash
ls -la /tmp/test-aptos/mint.key
# Expected output: -rw-r--r-- (0644) - VULNERABLE
# Should be: -rw------- (0600) - SECURE
```

**Step 3: Demonstrate unauthorized access**
```bash
# As different user 'attacker' on same machine
cat /tmp/test-aptos/mint.key | xxd
# Successfully reads the root private key
```

**Step 4: Verify the key can be decoded**
```rust
use std::fs;
use aptos_types::account_address::AccountAddress;

fn main() -> anyhow::Result<()> {
    let key_bytes = fs::read("/tmp/test-aptos/mint.key")?;
    let root_key: Ed25519PrivateKey = bcs::from_bytes(&key_bytes)?;
    println!("Successfully extracted root key: {:?}", root_key.public_key());
    Ok(())
}
```

**Comparison with secure implementation:**

The genesis key generation correctly uses secure permissions: [4](#0-3) 

This demonstrates that the secure pattern exists in the codebase but is not consistently applied.

## Notes
- This vulnerability affects test environments only, not production validator deployments
- The security question explicitly marked this as "(Critical)", though practical impact is limited to development/testing scenarios
- Fix is straightforward: use existing secure file writing functions
- Multiple instances of this pattern exist across the codebase and should all be remediated
- Consider adding a security audit checklist for file operations involving cryptographic material

### Citations

**File:** aptos-node/src/lib.rs (L618-621)
```rust
    // Write the mint key to disk
    let serialized_keys = bcs::to_bytes(&root_key)?;
    let mut key_file = fs::File::create(aptos_root_key_path)?;
    key_file.write_all(&serialized_keys)?;
```

**File:** crates/aptos/src/common/utils.rs (L224-228)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
```

**File:** testsuite/forge/src/backend/local/swarm.rs (L230-231)
```rust
        if let Ok(mut out) = File::create(root_key_path.clone()) {
            out.write_all(encoded_root_key.as_slice())?;
```

**File:** crates/aptos/src/genesis/keys.rs (L82-86)
```rust
        write_to_user_only_file(
            private_keys_file.as_path(),
            PRIVATE_KEYS_FILE,
            to_yaml(&private_identity)?.as_bytes(),
        )?;
```
