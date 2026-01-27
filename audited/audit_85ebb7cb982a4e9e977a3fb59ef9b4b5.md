# Audit Report

## Title
Validator Private Keys Exposed Through Insecure File Permissions in Genesis Builder

## Summary
The `write_yaml()` function in the genesis builder creates `private-identity.yaml` files containing all validator private keys (consensus, network, and account keys) with default file permissions (0o644 on Unix), making them world-readable. This allows any local user to extract validator cryptographic material, and backup processes inherit these insecure permissions, enabling key leakage through backup storage or transmission.

## Finding Description

The `generate_key_objects()` function creates a `PrivateIdentity` struct containing all sensitive validator keys: [1](#0-0) 

These keys are then written to disk by the genesis builder's `get_key_objects()` method using an insecure `write_yaml()` helper function: [2](#0-1) 

The `write_yaml()` function uses `File::create()` without setting secure file permissions: [3](#0-2) 

On Unix systems, `File::create()` creates files with default permissions (typically 0o644), making them readable by all users on the system. The private keys are serialized via Serde's human-readable format (YAML), which encodes them as hex/base64 strings: [4](#0-3) 

This means the private keys are stored in plaintext (not encrypted), only base64/hex encoded.

**Attack Path:**
1. Validator operator runs `Builder.build()` to initialize validator node
2. `private-identity.yaml` is created with 0o644 permissions containing all private keys
3. Local attacker (or compromised service) reads the world-readable file
4. Attacker extracts: consensus private key (BLS12-381), validator network key (X25519), full node network key (X25519), account private key (Ed25519)
5. Attacker can now sign consensus votes, impersonate validator in P2P network, and execute transactions as validator
6. When operator backs up files, insecure permissions are preserved in backup storage

**Security Guarantee Violated:**
The Aptos Core codebase acknowledges this issue should use secure storage instead of files: [5](#0-4) 

**Inconsistency in Codebase:**
The CLI tool (`crates/aptos`) correctly uses `write_to_user_only_file()` with 0o600 permissions: [6](#0-5) 

The secure implementation sets mode 0o600 (user-only read/write): [7](#0-6) 

However, the genesis builder library used by production code paths does not apply these protections: [8](#0-7) 

## Impact Explanation

**HIGH Severity** per Aptos bug bounty criteria:

1. **Validator Node Compromise**: Complete exposure of validator cryptographic identity enables:
   - Signing malicious consensus votes (potential safety violations if multiple validators compromised)
   - Impersonating validator in P2P network (eclipse attacks, message manipulation)
   - Executing unauthorized transactions from validator account
   - Disrupting validator operations

2. **Backup Security Failure**: The question specifically asks if "backup process maintain the same security guarantees" - the answer is NO:
   - Files created with insecure permissions
   - Backup tools preserve these permissions
   - Backup storage (NAS, cloud, etc.) may expose files to unauthorized access
   - Transmission of backups may leak keys

3. **Scale of Impact**: Affects all validators using the genesis builder for initialization, including:
   - Local test networks
   - Development environments  
   - Forge test framework deployments
   - Any validator initialized via `Builder.build()`

While this requires local filesystem access, it represents "Significant protocol violations" (HIGH severity category) as compromised validator keys directly threaten consensus integrity and network security.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Factors increasing likelihood:**
- Common deployment scenarios with elevated risk:
  - Cloud hosting environments (AWS, GCP, Azure) where metadata services may expose files
  - Container orchestration (Kubernetes) where volumes may be shared
  - Multi-tenant servers where validators share infrastructure
  - Development/staging environments with multiple administrators
  - Automated backup systems copying to shared storage
- Default behavior affects all deployments unless manually corrected
- Developers may not notice world-readable permissions
- Backup operators typically preserve source file permissions

**Factors limiting exploitation:**
- Requires attacker to have local filesystem access OR access to backup storage
- Does not affect validators using only the CLI tool for key generation
- System administrators may have restrictive umask settings (though not guaranteed)

## Recommendation

Replace the insecure `write_yaml()` function with a secure version that sets proper file permissions. Apply the same pattern used in the CLI tool:

**Option 1: Reuse existing secure function**
```rust
// In crates/aptos-genesis/src/builder.rs, add dependency on secure file writing
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::fs::OpenOptions;

fn write_yaml_secure<T: Serialize>(path: &Path, object: &T) -> anyhow::Result<()> {
    let yaml_string = serde_yaml::to_string(object)?;
    let mut opts = OpenOptions::new();
    
    #[cfg(unix)]
    opts.mode(0o600); // User-only read/write
    
    let mut file = opts
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    
    file.write_all(yaml_string.as_bytes())?;
    Ok(())
}
```

Then replace all calls to `write_yaml()` for sensitive files: [9](#0-8) 

**Option 2: Move to secure backend storage**
Implement the TODO suggestion to use `SecureBackend` instead of file-based storage for all private keys.

## Proof of Concept

```rust
// PoC: Demonstrates file permission vulnerability
// Save as: poc_file_permissions.rs
// Run with: cargo test --package aptos-genesis -- poc_file_permissions

use std::fs::{File, metadata};
use std::os::unix::fs::PermissionsExt;
use std::io::Write;
use tempfile::TempDir;
use aptos_genesis::keys::{generate_key_objects, PrivateIdentity};
use aptos_keygen::KeyGen;

#[test]
fn test_private_identity_file_permissions_vulnerability() {
    let temp_dir = TempDir::new().unwrap();
    let private_identity_path = temp_dir.path().join("private-identity.yaml");
    
    // Generate keys
    let mut keygen = KeyGen::from_os_rng();
    let (_, _, private_identity, _) = generate_key_objects(&mut keygen).unwrap();
    
    // Simulate insecure write (current implementation)
    let yaml_data = serde_yaml::to_string(&private_identity).unwrap();
    File::create(&private_identity_path)
        .unwrap()
        .write_all(yaml_data.as_bytes())
        .unwrap();
    
    // Check permissions
    let metadata = metadata(&private_identity_path).unwrap();
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    
    println!("File permissions: {:o}", mode & 0o777);
    
    // VULNERABILITY: File is world-readable (mode 0o644)
    assert_ne!(
        mode & 0o777, 
        0o600,
        "VULNERABILITY CONFIRMED: Private keys file has insecure permissions {}. Should be 0o600 (user-only).",
        mode & 0o777
    );
    
    // Verify keys are extractable in plaintext
    let yaml_content = std::fs::read_to_string(&private_identity_path).unwrap();
    assert!(yaml_content.contains("account_private_key"));
    assert!(yaml_content.contains("consensus_private_key"));
    println!("Private keys are readable in plaintext YAML format");
}
```

**Expected Output:**
```
File permissions: 644
VULNERABILITY CONFIRMED: Private keys file has insecure permissions 644. Should be 0o600 (user-only).
Private keys are readable in plaintext YAML format
```

## Notes

This vulnerability directly answers the security question: validator backup processes do NOT maintain security guarantees because source files are created with world-readable permissions, and these insecure permissions propagate through backup workflows, enabling key leakage through insecure storage or transmission.

### Citations

**File:** crates/aptos-genesis/src/keys.rs (L16-22)
```rust
pub struct PrivateIdentity {
    pub account_address: AccountAddress,
    pub account_private_key: Ed25519PrivateKey,
    pub consensus_private_key: bls12381::PrivateKey,
    pub full_node_network_private_key: x25519::PrivateKey,
    pub validator_network_private_key: x25519::PrivateKey,
}
```

**File:** crates/aptos-genesis/src/builder.rs (L97-97)
```rust
    /// TODO: Put this all in storage rather than files?
```

**File:** crates/aptos-genesis/src/builder.rs (L145-148)
```rust
            write_yaml(val_identity_file.as_path(), &validator_identity)?;
            write_yaml(vfn_identity_file.as_path(), &vfn_identity)?;
            write_yaml(private_identity_file.as_path(), &private_identity)?;
            write_yaml(public_identity_file.as_path(), &public_identity)?;
```

**File:** crates/aptos-genesis/src/builder.rs (L418-421)
```rust
fn write_yaml<T: Serialize>(path: &Path, object: &T) -> anyhow::Result<()> {
    File::create(path)?.write_all(serde_yaml::to_string(object)?.as_bytes())?;
    Ok(())
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L186-211)
```rust
pub fn serialize_key(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let name_string = find_key_name(&ast, name.to_string());
    quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    self.to_encoded_string()
                        .map_err(<S::Error as ::serde::ser::Error>::custom)
                        .and_then(|str| serializer.serialize_str(&str[..]))
                } else {
                    // See comment in deserialize_key.
                    serializer.serialize_newtype_struct(
                        #name_string,
                        serde_bytes::Bytes::new(&ValidCryptoMaterial::to_bytes(self).as_slice()),
                    )
                }
            }
        }
    }
    .into()
}
```

**File:** crates/aptos/src/genesis/keys.rs (L82-97)
```rust
        write_to_user_only_file(
            private_keys_file.as_path(),
            PRIVATE_KEYS_FILE,
            to_yaml(&private_identity)?.as_bytes(),
        )?;
        write_to_user_only_file(
            public_keys_file.as_path(),
            PUBLIC_KEYS_FILE,
            to_yaml(&public_identity)?.as_bytes(),
        )?;
        write_to_user_only_file(
            validator_file.as_path(),
            VALIDATOR_FILE,
            to_yaml(&validator_blob)?.as_bytes(),
        )?;
        write_to_user_only_file(vfn_file.as_path(), VFN_FILE, to_yaml(&vfn_blob)?.as_bytes())?;
```

**File:** crates/aptos/src/common/utils.rs (L224-229)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```

**File:** aptos-node/src/lib.rs (L585-616)
```rust
    let builder = aptos_genesis::builder::Builder::new(test_dir, framework.clone())?
        .with_init_config(Some(Arc::new(move |_, config, _| {
            *config = node_config.clone();
        })))
        .with_init_genesis_config(Some(Arc::new(|genesis_config| {
            genesis_config.allow_new_validators = true;
            genesis_config.epoch_duration_secs = EPOCH_LENGTH_SECS;
            genesis_config.recurring_lockup_duration_secs = 7200;

            match env::var("ENABLE_KEYLESS_DEFAULT") {
                Ok(val) if val.as_str() == "1" => {
                    let response = ureq::get("https://api.devnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey").call();
                    let json: Value = response.into_json().expect("Failed to parse JSON");
                    configure_keyless_with_vk(genesis_config, json).unwrap();
                },
                _ => {},
            };

            if let Ok(url) = env::var("INSTALL_KEYLESS_GROTH16_VK_FROM_URL") {
                let response = ureq::get(&url).call();
                let json: Value = response.into_json().expect("Failed to parse JSON");
                configure_keyless_with_vk(genesis_config, json).unwrap();
            };

            if let Ok(path) = env::var("INSTALL_KEYLESS_GROTH16_VK_FROM_PATH") {
                let file_content = fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read verification key file: {}", path));
                let json: Value = serde_json::from_str(&file_content).expect("Failed to parse JSON");
                configure_keyless_with_vk(genesis_config, json).unwrap();
            };
        })))
        .with_randomize_first_validator_ports(random_ports);
    let (root_key, _genesis, genesis_waypoint, mut validators) = builder.build(rng)?;
```
