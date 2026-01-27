# Audit Report

## Title
Unencrypted Validator Private Key Backup Enables Complete Validator Compromise and Consensus Attacks

## Summary
Validator private keys exported for backup purposes are stored in plaintext YAML files with no encryption, protected only by filesystem permissions. If an attacker gains access to these backup files through filesystem compromise, backup system breach, cloud storage misconfiguration, or disk theft, they can extract all validator private keys including the consensus signing key, enabling equivocation attacks and complete validator compromise.

## Finding Description

The vulnerability spans the entire key backup workflow in Aptos:

**1. Keys are created as exportable by default:** [1](#0-0) 

All Ed25519 keys in Vault are created with `exportable: true`, allowing them to be extracted.

**2. Export returns plaintext private keys:** [2](#0-1) 

The `export_private_key()` function retrieves keys from Vault and returns them as plaintext `Ed25519PrivateKey` objects without any additional encryption layer.

**3. Vault client exports keys as base64-encoded plaintext:** [3](#0-2) [4](#0-3) 

The export process retrieves base64-encoded keys from Vault's `/v1/transit/export/signing-key/` endpoint, decodes them, and returns plaintext private key material.

**4. Backup files contain plaintext private keys:** [5](#0-4) 

The `PrivateIdentity` struct contains all critical validator private keys in plaintext, including the `consensus_private_key` (BLS12-381) which is used to sign consensus votes.

**5. Keys are written to disk with only filesystem permissions:** [6](#0-5) [7](#0-6) 

Private keys are written to `private-keys.yaml` using `write_to_user_only_file()`, which only sets Unix file permissions to 0o600 (user read/write only). There is no encryption applied to the file contents.

**6. Consensus keys are stored and retrieved from this storage:** [8](#0-7) [9](#0-8) 

The consensus private key stored in the backup is the same key used by SafetyRules to sign consensus votes, making it the most critical asset.

**Attack Scenario:**

1. Validator generates keys using `aptos genesis generate-keys`
2. Keys are saved to `private-keys.yaml` containing plaintext BLS12-381 consensus private key
3. Attacker gains access through:
   - Backup system compromise (cloud storage, backup software)
   - Filesystem access (local privilege escalation, stolen disk)
   - Misconfigured cloud storage (public S3 bucket, weak IAM policies)
   - Memory dump or process inspection
   - Insider threat
4. Attacker reads YAML file and extracts `consensus_private_key`
5. Attacker can now:
   - **Sign conflicting votes** (equivocation) using the stolen consensus key
   - **Violate consensus safety** by double-signing different blocks at the same height
   - **Submit malicious transactions** using the account private key
   - **Impersonate the validator** on the P2P network

This directly violates the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine." With stolen consensus keys, an attacker can make honest validators appear Byzantine by signing conflicting blocks.

## Impact Explanation

This qualifies as **Critical Severity** under the Aptos bug bounty program for multiple reasons:

1. **Consensus/Safety Violations**: An attacker with a stolen consensus private key can perform equivocation attacks by signing conflicting blocks at the same height/round. This violates the fundamental safety guarantee of AptosBFT consensus, which relies on validators not double-signing. If multiple validators' keys are compromised, attackers could cause chain splits or consensus failure.

2. **Complete Validator Compromise**: The backup contains ALL validator private keys:
   - Consensus key (BLS12-381) - enables signing malicious votes
   - Account key (Ed25519) - enables submitting transactions as the validator
   - Network keys (x25519) - enables network impersonation

3. **Scalable Attack**: Unlike attacks requiring real-time access to running validators, backup theft can be performed offline and scaled across multiple validators if backup systems are centrally managed.

4. **No Detection Until Exploitation**: Stolen backups provide no immediate indication of compromise until the attacker actively uses the keys, potentially leaving a window for preparation of coordinated attacks.

5. **Permanent Compromise**: Key rotation doesn't help if the attacker has already extracted keys from historical backups that might still be valid or usable in replay scenarios.

The impact matches the Critical category: "Consensus/Safety violations" and could lead to "Non-recoverable network partition (requires hardfork)" if multiple validators are compromised simultaneously.

## Likelihood Explanation

**High Likelihood** due to multiple realistic attack vectors:

1. **Common Backup Misconfigurations**:
   - Cloud storage buckets (S3, GCS, Azure Blob) are frequently misconfigured with public read access
   - Backup retention policies may keep old, unencrypted backups accessible
   - Third-party backup services may not meet security standards

2. **Filesystem-Level Attacks**:
   - Local privilege escalation on validator nodes
   - Compromised administrator accounts
   - Stolen or improperly disposed hard drives

3. **Supply Chain Attacks**:
   - Compromised backup software or agents
   - Malicious system administrators
   - Insider threats

4. **Operational Security Gaps**:
   - Validators may copy backups to less secure locations for testing
   - Development/staging environments often have weaker security
   - Key files may be accidentally committed to version control

5. **Attack Surface**:
   - Every location where backups are stored (multiple data centers, cloud regions)
   - Every backup copy (daily, weekly, monthly retention)
   - Every person/system with backup access

The attacker only needs READ access to backup files, not write access or real-time system compromise, making this significantly easier than attacking running validators.

## Recommendation

Implement multi-layered protection for exported private keys:

**1. Mandatory Encryption for Exports:**
```rust
// In secure/storage/src/vault.rs
pub fn export_private_key_encrypted(
    &self, 
    name: &str,
    encryption_key: &[u8; 32]  // Provided by user, derived from password
) -> Result<Vec<u8>, Error> {
    let name = self.crypto_name(name);
    let plaintext_key = self.client().export_ed25519_key(&name, None)?;
    
    // Use authenticated encryption (e.g., ChaCha20-Poly1305 or AES-256-GCM)
    let cipher = ChaCha20Poly1305::new(encryption_key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext_key.to_bytes().as_ref())
        .map_err(|e| Error::InternalError(format!("Encryption failed: {}", e)))?;
    
    // Return nonce || ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}
```

**2. Password-Protected Backup Files:**
```rust
// In crates/aptos/src/genesis/keys.rs
// Prompt for strong password when generating keys
let password = prompt_password("Enter backup encryption password (min 20 chars): ")?;
let key = derive_key_from_password(&password); // Use Argon2id

let encrypted_private_identity = encrypt_private_identity(&private_identity, &key)?;
write_to_user_only_file(
    private_keys_file.as_path(),
    PRIVATE_KEYS_FILE,
    &encrypted_private_identity,
)?;
```

**3. Hardware Security Module (HSM) Integration:**
- For production validators, mandate HSM usage where private keys never leave the HSM
- Keys should be non-exportable in production environments
- Only allow exports for disaster recovery with explicit multi-party authorization

**4. Implement Audit Logging:**
```rust
// Log every export operation
fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
    audit_log::log_critical_operation(
        "EXPORT_PRIVATE_KEY",
        name,
        get_caller_identity(),
        chrono::Utc::now(),
    );
    // ... existing export logic
}
```

**5. Secure Key Backup Protocol:**
- Implement Shamir Secret Sharing for consensus keys (require M-of-N key shares to reconstruct)
- Store shares in separate geographic locations with different access controls
- Require multi-party authorization for key reconstruction

**6. Configuration Flag:**
```rust
// Make exportability configurable, default to false for production
pub fn create_key_with_policy(
    &mut self, 
    name: &str, 
    policy: KeyPolicy
) -> Result<Ed25519PublicKey, Error> {
    let exportable = policy.allow_export && !is_production_env();
    self.client().create_ed25519_key(&ns_name, exportable)?;
    // ...
}
```

## Proof of Concept

**Setup:**
```bash
# Generate validator keys
aptos genesis generate-keys --output-dir ./validator-backup

# The following files are created:
# - private-keys.yaml (PLAINTEXT private keys)
# - public-keys.yaml
# - validator-identity.yaml
# - validator-full-node-identity.yaml
```

**Exploit - Read Plaintext Keys:**
```rust
use aptos_genesis::keys::PrivateIdentity;
use std::fs;

fn exploit_stolen_backup() {
    // Attacker gains read access to backup directory
    let backup_contents = fs::read_to_string("./validator-backup/private-keys.yaml")
        .expect("Failed to read backup file");
    
    // Deserialize plaintext private keys
    let private_identity: PrivateIdentity = serde_yaml::from_str(&backup_contents)
        .expect("Failed to parse private keys");
    
    // Extract the consensus private key
    let stolen_consensus_key = private_identity.consensus_private_key;
    
    println!("Successfully extracted consensus private key!");
    println!("Public key: {:?}", stolen_consensus_key.public_key());
    
    // Attacker can now:
    // 1. Sign conflicting consensus votes (equivocation attack)
    // 2. Create malicious quorum certificates
    // 3. Participate in double-signing scenarios
    
    // Example: Sign a malicious vote
    use aptos_consensus_types::vote::Vote;
    use aptos_crypto::Signature;
    
    let malicious_vote = /* construct conflicting vote */;
    let malicious_signature = stolen_consensus_key.sign(&malicious_vote);
    
    println!("Created malicious signature: {:?}", malicious_signature);
    // This signature is cryptographically valid and indistinguishable 
    // from legitimate validator signatures
}
```

**Verification:**
```bash
# Examine the backup file directly
cat ./validator-backup/private-keys.yaml

# Output shows plaintext keys in YAML format:
# account_address: "0x..."
# account_private_key: "0x..." 
# consensus_private_key: "0x..."  # <-- CRITICAL: BLS12-381 key in plaintext
# full_node_network_private_key: "0x..."
# validator_network_private_key: "0x..."

# Any process with file read permission can extract these keys
# No password required, no encryption, no additional protection
```

**Impact Demonstration:**
```rust
// Demonstrate equivocation attack with stolen key
fn equivocation_attack(stolen_key: bls12381::PrivateKey) {
    let epoch = 10;
    let round = 5;
    
    // Sign vote for block A
    let vote_a = create_vote(epoch, round, block_hash_a);
    let signature_a = stolen_key.sign(&vote_a);
    
    // Sign conflicting vote for block B at same height
    let vote_b = create_vote(epoch, round, block_hash_b);  // Different block!
    let signature_b = stolen_key.sign(&vote_b);
    
    // Both signatures are valid, violating consensus safety
    assert!(stolen_key.public_key().verify(&vote_a, &signature_a).is_ok());
    assert!(stolen_key.public_key().verify(&vote_b, &signature_b).is_ok());
    
    // This breaks the "Consensus Safety" invariant
    // Network receives two valid signatures from same validator for conflicting blocks
}
```

**Notes**

- This vulnerability affects ALL validators using the standard key generation and backup procedures
- The issue is not in Vault itself (which provides encryption at rest), but in the export and local backup workflow
- File permissions (0o600) only protect against local user access, not against backup system compromise, disk theft, cloud storage breaches, or privileged processes
- Production validators may use HSMs, but the documentation and tooling encourage file-based backups for disaster recovery
- The plaintext storage in the `KeyBackup` struct explicitly shows `"allow_plaintext_backup": true`, indicating this is an intentional design choice that needs reconsideration for production security

### Citations

**File:** secure/storage/src/vault.rs (L194-204)
```rust
    fn create_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        let ns_name = self.crypto_name(name);
        match self.get_public_key(name) {
            Ok(_) => return Err(Error::KeyAlreadyExists(ns_name)),
            Err(Error::KeyNotSet(_)) => (/* Expected this for new keys! */),
            Err(e) => return Err(e),
        }

        self.client().create_ed25519_key(&ns_name, true)?;
        self.get_public_key(name).map(|v| v.public_key)
    }
```

**File:** secure/storage/src/vault.rs (L206-209)
```rust
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
        let name = self.crypto_name(name);
        Ok(self.client().export_ed25519_key(&name, None)?)
    }
```

**File:** secure/storage/vault/src/lib.rs (L293-305)
```rust
    pub fn export_ed25519_key(
        &self,
        name: &str,
        version: Option<u32>,
    ) -> Result<Ed25519PrivateKey, Error> {
        let request = self.agent.get(&format!(
            "{}/v1/transit/export/signing-key/{}",
            self.host, name
        ));
        let resp = self.upgrade_request(request).call();

        process_transit_export_response(name, version, resp)
    }
```

**File:** secure/storage/vault/src/lib.rs (L614-642)
```rust
pub fn process_transit_export_response(
    name: &str,
    version: Option<u32>,
    resp: Response,
) -> Result<Ed25519PrivateKey, Error> {
    if resp.ok() {
        let export_key: ExportKeyResponse = serde_json::from_str(&resp.into_string()?)?;
        let composite_key = if let Some(version) = version {
            let key = export_key.data.keys.iter().find(|(k, _v)| **k == version);
            let (_, key) = key.ok_or_else(|| Error::NotFound("transit/".into(), name.into()))?;
            key
        } else if let Some(key) = export_key.data.keys.values().last() {
            key
        } else {
            return Err(Error::NotFound("transit/".into(), name.into()));
        };

        let composite_key = base64::decode(composite_key)?;
        if let Some(composite_key) = composite_key.get(0..ED25519_PRIVATE_KEY_LENGTH) {
            Ok(Ed25519PrivateKey::try_from(composite_key)?)
        } else {
            Err(Error::InternalError(
                "Insufficient key length returned by vault export key request".into(),
            ))
        }
    } else {
        Err(resp.into())
    }
}
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

**File:** crates/aptos/src/genesis/keys.rs (L82-86)
```rust
        write_to_user_only_file(
            private_keys_file.as_path(),
            PRIVATE_KEYS_FILE,
            to_yaml(&private_identity)?.as_bytes(),
        )?;
```

**File:** crates/aptos/src/common/utils.rs (L223-229)
```rust
/// Write a User only read / write file
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L63-80)
```rust
    fn initialize_keys_and_accounts(
        internal_store: &mut Storage,
        author: Author,
        consensus_private_key: bls12381::PrivateKey,
    ) -> Result<(), Error> {
        let result = internal_store.set(CONSENSUS_KEY, consensus_private_key);
        // Attempting to re-initialize existing storage. This can happen in environments like
        // forge. Rather than be rigid here, leave it up to the developer to detect
        // inconsistencies or why they did not reset storage between rounds. Do not repeat the
        // checks again below, because it is just too strange to have a partially configured
        // storage.
        if let Err(aptos_secure_storage::Error::KeyAlreadyExists(_)) = result {
            warn!("Attempted to re-initialize existing storage");
            return Ok(());
        }

        internal_store.set(OWNER_ACCOUNT, author)?;
        Ok(())
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L98-130)
```rust
    pub fn default_consensus_sk(
        &self,
    ) -> Result<bls12381::PrivateKey, aptos_secure_storage::Error> {
        self.internal_store
            .get::<bls12381::PrivateKey>(CONSENSUS_KEY)
            .map(|v| v.value)
    }

    pub fn consensus_sk_by_pk(
        &self,
        pk: bls12381::PublicKey,
    ) -> Result<bls12381::PrivateKey, Error> {
        let _timer = counters::start_timer("get", CONSENSUS_KEY);
        let pk_hex = hex::encode(pk.to_bytes());
        let explicit_storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
        let explicit_sk = self
            .internal_store
            .get::<bls12381::PrivateKey>(explicit_storage_key.as_str())
            .map(|v| v.value);
        let default_sk = self.default_consensus_sk();
        let key = match (explicit_sk, default_sk) {
            (Ok(sk_0), _) => sk_0,
            (Err(_), Ok(sk_1)) => sk_1,
            (Err(_), Err(_)) => {
                return Err(Error::ValidatorKeyNotFound("not found!".to_string()));
            },
        };
        if key.public_key() != pk {
            return Err(Error::SecureStorageMissingDataError(format!(
                "Incorrect sk saved for {:?} the expected pk",
                pk
            )));
        }
```
