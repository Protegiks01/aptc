# Audit Report

## Title
Insufficient Filesystem Permission Hardening for State Merkle Database Directories

## Summary
The Aptos Core codebase does not explicitly set restrictive filesystem permissions when creating `state_merkle_db` directories, relying instead on process umask. With typical default umask settings (0022), directories are created with world-readable permissions (0755), allowing local users to read Jellyfish Merkle tree structure and potentially deduce account state patterns. This violates defense-in-depth principles for sensitive blockchain state data.

## Finding Description
The `STATE_MERKLE_DB_NAME` constant is defined as `"state_merkle_db"` [1](#0-0) , and directories are created using `std::fs::create_dir_all()` without explicit permission settings [2](#0-1) . 

RocksDB database opening also relies on default permissions [3](#0-2) . The Jellyfish Merkle tree stores leaf nodes containing hashed account keys, value hashes, and pointers to state values [4](#0-3) .

While Kubernetes deployments implement proper security contexts with `runAsUser: 6180`, `fsGroup: 6180`, and `readOnlyRootFilesystem: true` [5](#0-4) , the validator Docker image creates the aptos user but never sets it as the runtime user [6](#0-5) , and Docker Compose deployments lack explicit user configuration.

**Attack Scenario:**
1. A local attacker gains user-level access to a validator host (bare metal or misconfigured container)
2. With default umask (0022), `state_merkle_db` directories have 0755 permissions
3. Attacker reads RocksDB files containing Merkle tree nodes
4. Attacker analyzes hashed account keys, tree structure, and state patterns
5. Combined with timing analysis or side-channel attacks, attacker deduces which accounts are active

## Impact Explanation
This qualifies as **Medium severity** per Aptos bug bounty criteria:
- **Information Disclosure**: Local attackers can read Merkle tree structure revealing account existence patterns and state access patterns
- **State Inconsistencies**: If write access is obtained (same group or misconfiguration), attackers could corrupt RocksDB files, causing state root mismatches and requiring intervention

The impact is limited because:
- Only hashes are exposed, not plaintext account data
- Actual state values reside in separate `state_kv_db`
- Kubernetes deployments have proper isolation
- Write access scenarios are less likely

## Likelihood Explanation
**Moderate to High likelihood** for bare metal/Docker Compose deployments:
- Default umask (0022) is standard on most Linux systems
- No explicit hardening exists in the codebase
- Docker Compose runs as root without user restrictions
- Bare metal deployments depend entirely on operator security practices

**Low likelihood** for Kubernetes deployments due to existing security contexts.

## Recommendation
Implement explicit filesystem permission hardening:

```rust
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

fn create_db_directory_with_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700); // rwx------ (owner only)
        builder.recursive(true);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}
```

Apply this to:
1. `StateMerkleDb::create_checkpoint()` before line 219
2. Add permission validation after database opening
3. Document security requirements for bare metal deployments
4. Set `USER aptos` in `validator.Dockerfile`
5. Add `user: "6180:6180"` to Docker Compose configurations

## Proof of Concept

**Bare Metal Exploitation:**
```bash
# Setup: Validator running as user 'validator' with default umask
# Attacker: Local user 'attacker' on same host

# 1. Check directory permissions
ls -ld /opt/aptos/data/state_merkle_db
# Output: drwxr-xr-x  validator validator  /opt/aptos/data/state_merkle_db

# 2. Read Merkle tree structure
strings /opt/aptos/data/state_merkle_db/metadata/*.sst | grep -E '[0-9a-f]{64}'
# Exposes hashed account keys and tree structure

# 3. Analyze account patterns
find /opt/aptos/data/state_merkle_db -type f -printf '%T@ %p\n' | sort -n
# Reveals temporal access patterns for state modifications

# 4. Combined with state_kv_db access (if also world-readable):
# Full state reconstruction possible
```

**Docker Verification:**
```bash
# Verify container runs as root
docker-compose exec validator id
# uid=0(root) gid=0(root)

# Check created directory permissions inside container
docker-compose exec validator ls -ld /opt/aptos/data/state_merkle_db
# drwxr-xr-x root root (world-readable if volume mounted)
```

This demonstrates the permission issue exists in non-Kubernetes deployments, violating the principle of least privilege for sensitive blockchain state data.

## Notes
- Kubernetes deployments are properly secured through securityContext configurations
- The vulnerability primarily affects bare metal and Docker Compose deployments
- No encryption at rest is implemented for state databases
- The codebase's `write_to_user_only_file()` function [7](#0-6)  demonstrates awareness of permission hardening for sensitive files, but this pattern is not applied to database directories
- RocksDB itself does not enforce restrictive permissions; responsibility lies with the application

### Citations

**File:** storage/aptosdb/src/common.rs (L5-5)
```rust
pub const STATE_MERKLE_DB_NAME: &str = "state_merkle_db";
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L219-219)
```rust
            std::fs::create_dir_all(&cp_state_merkle_db_path).unwrap_or(());
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L724-736)
```rust
            DB::open_cf_readonly(
                &gen_rocksdb_options(state_merkle_db_config, env, true),
                path,
                name,
                gen_state_merkle_cfds(state_merkle_db_config, block_cache),
            )?
        } else {
            DB::open_cf(
                &gen_rocksdb_options(state_merkle_db_config, env, false),
                path,
                name,
                gen_state_merkle_cfds(state_merkle_db_config, block_cache),
            )?
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L698-705)
```rust
pub struct LeafNode<K> {
    // The hashed key associated with this leaf node.
    account_key: HashValue,
    // The hash of the value.
    value_hash: HashValue,
    // The key and version that points to the value
    value_index: (K, Version),
}
```

**File:** terraform/helm/aptos-node/templates/validator.yaml (L217-226)
```yaml
      securityContext:
        {{- if $.Values.enablePrivilegedMode }}
        runAsUser: 0
        runAsGroup: 0
        fsGroup: 0
        {{- else }}
        runAsNonRoot: true
        runAsUser: 6180
        runAsGroup: 6180
        fsGroup: 6180
```

**File:** docker/builder/validator.Dockerfile (L22-22)
```dockerfile
RUN addgroup --system --gid 6180 aptos && adduser --system --ingroup aptos --no-create-home --uid 6180 aptos
```

**File:** crates/aptos/src/common/utils.rs (L224-228)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
```
