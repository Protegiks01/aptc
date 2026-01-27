# Audit Report

## Title
Memory Exhaustion in Genesis YAML File Loading Due to Missing Size Validation

## Summary
The genesis setup utilities in `crates/aptos/src/common/utils.rs` and `crates/aptos/src/genesis/git.rs` load YAML files into memory without size validation, allowing malicious files to cause memory exhaustion during genesis setup.

## Finding Description
The vulnerability exists in the file reading utilities used during genesis configuration: [1](#0-0) 

This function uses `std::fs::read()` which loads the entire file into memory unconditionally. The `read_public_identity_file` function calls this without any size checks: [2](#0-1) 

During multi-party genesis setup, validator configurations are fetched from a shared git repository. The `Client::get` method also loads entire files without size validation: [3](#0-2) 

For local files, it uses `read_to_string(&mut contents)` and for GitHub files, it downloads and decodes the entire content. The `get_config` function fetches these files during genesis: [4](#0-3) 

**Attack Path:**
1. During multi-party genesis setup, participants share a git repository containing validator configurations
2. A malicious participant commits gigabyte-sized `owner.yaml` or `operator.yaml` files
3. When other participants run `aptos genesis generate-genesis --github-repository owner/repo`, the code attempts to load all validator configurations
4. The malicious large file is loaded entirely into memory causing exhaustion
5. The genesis process crashes or hangs, delaying network launch

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation
This qualifies as **Medium severity** based on:
- **State inconsistencies requiring intervention**: Genesis cannot complete without manual removal of malicious files
- Affects critical one-time genesis setup process
- Delays network launch requiring coordination among all participants
- Does not affect running blockchain nodes, only pre-genesis setup

Not Critical/High because it doesn't impact live network operation, consensus, or funds.

## Likelihood Explanation
**Moderate likelihood** in multi-party genesis scenarios:
- Requires one malicious participant among multiple validator operators
- Common in new blockchain launches with distributed genesis coordination
- Automated scripts may not check file sizes before committing
- Attack is simple to execute (create large YAML, commit to shared repo)

However, likelihood is reduced by:
- Genesis participants are typically vetted validator operators
- Manual review processes may catch obviously large files
- One-time process with limited window for exploitation

## Recommendation
Implement file size validation before loading:

```rust
const MAX_GENESIS_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| CliError::UnableToReadFile(
            format!("{}", path.display()), 
            e.to_string()
        ))?;
    
    if metadata.len() > MAX_GENESIS_FILE_SIZE {
        return Err(CliError::UnableToReadFile(
            format!("{}", path.display()),
            format!("File size {} exceeds maximum allowed size {}", 
                    metadata.len(), MAX_GENESIS_FILE_SIZE)
        ));
    }
    
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(
            format!("{}", path.display()), 
            e.to_string()
        ))
}
```

Apply similar validation to `Client::get` for both local and GitHub file reads.

## Proof of Concept

```rust
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_large_file_memory_exhaustion() {
    let dir = tempdir().unwrap();
    let malicious_file = dir.path().join("malicious.yaml");
    
    // Create 2GB YAML file
    let mut file = File::create(&malicious_file).unwrap();
    let chunk = "a".repeat(1024 * 1024); // 1MB chunk
    for _ in 0..2048 {
        file.write_all(chunk.as_bytes()).unwrap();
    }
    file.flush().unwrap();
    
    // Attempt to read - will exhaust memory
    let result = read_from_file(&malicious_file);
    // Without fix: OOM or hang
    // With fix: Err(file size exceeds limit)
    assert!(result.is_err());
}
```

## Notes
While this vulnerability technically exists, its exploitability is limited by the genesis setup context where participants are typically trusted validator operators. The primary risk is in multi-party genesis scenarios where not all participants are equally trusted or where automated processes don't validate file sizes before committing to shared repositories.

### Citations

**File:** crates/aptos/src/common/utils.rs (L213-216)
```rust
pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

**File:** crates/aptos/src/genesis/keys.rs (L264-267)
```rust
pub fn read_public_identity_file(public_identity_file: &Path) -> CliTypedResult<PublicIdentity> {
    let bytes = read_from_file(public_identity_file)?;
    from_yaml(&String::from_utf8(bytes).map_err(CliError::from)?)
}
```

**File:** crates/aptos/src/genesis/git.rs (L159-184)
```rust
    pub fn get<T: DeserializeOwned + Debug>(&self, path: &Path) -> CliTypedResult<T> {
        match self {
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(path);

                if !path.exists() {
                    return Err(CliError::UnableToReadFile(
                        path.display().to_string(),
                        "File not found".to_string(),
                    ));
                }

                eprintln!("Reading {}", path.display());
                let mut file = std::fs::File::open(path.as_path())
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;

                let mut contents = String::new();
                file.read_to_string(&mut contents)
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;
                from_yaml(&contents)
            },
            Client::Github(client) => {
                from_base64_encoded_yaml(&client.get_file(&path.display().to_string())?)
            },
        }
    }
```

**File:** crates/aptos/src/genesis/mod.rs (L352-361)
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
```
