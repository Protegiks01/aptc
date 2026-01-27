# Audit Report

## Title
Path Traversal Vulnerability in Indexer Transaction Generator Output Name Validation

## Summary
The `output_name` validation in the indexer-transaction-generator only checks for duplicate names but does not sanitize against path traversal sequences, null bytes, or filesystem-unsafe characters. This allows malicious YAML configurations to write transaction files outside the intended output directory.

## Finding Description

The validation logic at [1](#0-0)  only checks for duplicate `output_name` values using a HashSet, without performing any sanitization for path traversal attacks.

The vulnerable code flow:

1. YAML configuration files are read from the `move_fixtures` directory
2. Each `ScriptTransaction` contains an optional `output_name` field [2](#0-1) 
3. Validation only checks for duplicates, not path traversal [3](#0-2) 
4. The unsanitized `output_name` is directly used in file path construction [4](#0-3) 
5. Files are written to the resulting path [5](#0-4) 

An attacker with the ability to create or modify YAML configuration files in the `move_fixtures` directory can specify malicious output names like `"../../../sensitive_location"` to write transaction JSON files outside the intended output directory.

## Impact Explanation

This vulnerability is assessed as **Medium severity** because:

1. **Scope**: While this is not a core blockchain vulnerability affecting consensus or state integrity, it is a legitimate security issue in the official Aptos Core repository that could compromise development and CI/CD infrastructure.

2. **Potential Harm**: 
   - File system tampering on machines running the indexer-transaction-generator
   - Potential code injection if malicious files overwrite build artifacts or source files
   - Compromise of CI/CD pipelines if the tool runs with elevated permissions

3. **Limited Direct Blockchain Impact**: This tool is in the ecosystem components for testing/development, not core validator, consensus, or execution components. It does not directly affect blockchain security guarantees.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- Access to create/modify YAML configuration files in the testing directory
- Ability to execute the indexer-transaction-generator tool
- Typically occurs in development or CI/CD environments

While this requires some level of access, the barrier is relatively low in development environments where multiple contributors may have filesystem access or ability to submit malicious configuration via pull requests.

## Recommendation

Add comprehensive validation for the `output_name` field to prevent path traversal and unsafe filesystem operations:

```rust
fn validate_output_name(output_name: &str) -> anyhow::Result<()> {
    // Check for null bytes
    if output_name.contains('\0') {
        return Err(anyhow::anyhow!("Output name contains null bytes"));
    }
    
    // Check for path traversal sequences
    if output_name.contains("..") || output_name.contains('/') || output_name.contains('\\') {
        return Err(anyhow::anyhow!("Output name contains path traversal sequences"));
    }
    
    // Check for filesystem-unsafe characters
    let unsafe_chars = ['<', '>', ':', '"', '|', '?', '*'];
    if output_name.chars().any(|c| unsafe_chars.contains(&c)) {
        return Err(anyhow::anyhow!("Output name contains unsafe characters"));
    }
    
    // Ensure it's not empty and is reasonable length
    if output_name.is_empty() || output_name.len() > 255 {
        return Err(anyhow::anyhow!("Output name has invalid length"));
    }
    
    Ok(())
}
```

Apply this validation in the existing validation loop at line 165.

## Proof of Concept

Create a malicious YAML configuration file at `move_fixtures/malicious.yaml`:

```yaml
transactions:
  - script_path: "some_script"
    output_name: "../../../tmp/pwned"
    sender_address: "0x1"
```

Run the indexer-transaction-generator:
```bash
cargo run --bin aptos-indexer-transaction-generator -- \
  --testing-folder ./test_data \
  --output-folder ./output \
  --mode script
```

Expected behavior: The file should be written to `output/json_transactions/scripted_transactions/../../../tmp/pwned.json`, which resolves to `/tmp/pwned.json` (or equivalent relative to the output folder).

The validation at lines 156-175 will only check for duplicates and allow this malicious path to proceed to file write operations.

**Notes:**
- This vulnerability is specific to the indexer-transaction-generator development tool and does not affect core blockchain consensus, execution, or state management components
- The security impact is limited to environments where this tool is executed (development machines, CI/CD pipelines)
- This does NOT violate any of the critical blockchain invariants (deterministic execution, consensus safety, Move VM safety, etc.)
- Classification as Medium severity aligns with potential compromise of development infrastructure rather than direct blockchain security impact

### Citations

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/config.rs (L156-175)
```rust
                let mut output_script_transactions_set = HashSet::new();
                for (file_name, script_transactions) in script_transactions_vec.iter() {
                    if script_transactions.transactions.is_empty() {
                        return Err(anyhow::anyhow!(
                            "[Script Transaction Generator] No transactions found in file `{}`",
                            file_name
                        ));
                    }
                    for script_transaction in script_transactions.transactions.iter() {
                        if let Some(output_name) = &script_transaction.output_name {
                            if !output_script_transactions_set.insert(output_name.clone()) {
                                return Err(anyhow::anyhow!(
                                    "[Script Transaction Generator] Output file name `{}` is duplicated in file `{}`",
                                    output_name.clone(),
                                    file_name
                                    ));
                            }
                        }
                    }
                }
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/config.rs (L335-340)
```rust
pub struct ScriptTransaction {
    pub script_path: PathBuf,
    pub output_name: Option<String>,
    // Fund the address and execute the script with the account.
    pub sender_address: String,
}
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs (L180-180)
```rust
            let output_path = output_path.join(output_name).with_extension("json");
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs (L181-186)
```rust
            tokio::fs::write(&output_path, json_string)
                .await
                .context(format!(
                "[Script Transaction Generator] Failed to write transaction at version {} to file.",
                version
            ))?;
```
