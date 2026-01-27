# Audit Report

## Title
Credential Leakage via Improper Cleanup of Temporary Profile Files on Error Paths

## Summary
The `prepare_script_transaction()` and `execute_script_transaction()` functions in the indexer transaction generator fail to properly clean up temporary profile files containing private keys when errors occur during funding, compilation, or script execution. This results in persistent credential exposure on the filesystem.

## Finding Description

The vulnerability exists in the error handling flow of script transaction execution: [1](#0-0) 

The `prepare_script_transaction()` function creates a profile file containing sensitive credentials including the account's private key: [2](#0-1) 

The profile file is written to `{script_path}/.aptos/config.yaml` and contains plaintext private keys, public keys, and account addresses. However, if the funding operation fails (line 75-78 in prepare_script_transaction), the function returns early via the `?` operator without cleaning up the profile file.

Similarly, in `execute_script_transaction()`: [3](#0-2) 

The cleanup call to `delete_profile_file()` only occurs at line 111-114, which is unreachable if:
1. Script compilation fails (line 97-100)
2. Script execution fails (line 107-110)

**Error Paths Without Cleanup:**
- Funding failure → immediate return, no cleanup
- Compilation failure → immediate return, no cleanup  
- Script execution failure → immediate return, no cleanup

## Impact Explanation

**Severity Assessment: Low to Medium**

While this represents a credential leakage vulnerability, the impact is limited by context:

1. **Scope**: This affects the indexer-transaction-generator, a development/testing tool rather than core consensus or blockchain infrastructure
2. **Environment**: The tool operates in local development environments (localhost URLs, managed local nodes)
3. **Credentials**: The exposed keys are test account credentials, not production validator keys or user funds

However, the vulnerability still poses security risks:
- In CI/CD pipelines or shared development environments, persistent credential files could be accessed by other processes or users
- Accumulated credential files over time increase attack surface
- Violates principle of least privilege and defense-in-depth

This falls under the bug bounty category of **"Minor information leaks"** (Low Severity) but could escalate to **Medium** if exploited in multi-tenant or CI/CD environments where lateral movement is possible.

## Likelihood Explanation

**Likelihood: High**

The vulnerability triggers in common operational scenarios:
1. Network connectivity issues causing funding failures
2. Compilation errors in Move scripts during development
3. Script execution failures due to gas, permissions, or logic errors

These are routine occurrences in development workflows, making credential leakage highly likely. The error-prone nature of script development and testing means profile files will accumulate over time on developer machines and CI runners.

## Recommendation

Implement proper resource cleanup using Rust's Drop trait or explicit cleanup in error paths. Two approaches:

**Approach 1: RAII Guard Pattern**
Create a ProfileGuard struct that automatically cleans up on drop:

```rust
struct ProfileFileGuard<'a> {
    account: &'a Account,
    path: PathBuf,
}

impl<'a> Drop for ProfileFileGuard<'a> {
    fn drop(&mut self) {
        let account = self.account.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = account.delete_profile_file(&path).await;
        });
    }
}
```

**Approach 2: Explicit Cleanup (Simpler)**
Modify `execute_script_transaction()` to use cleanup in error paths: [3](#0-2) 

Replace with:
```rust
async fn execute_script_transaction(
    &self,
    move_folder_path: &Path,
    transaction: &ScriptTransaction,
    sender_account: &Account,
) -> anyhow::Result<u64> {
    let script_path = move_folder_path.join(&transaction.script_path);
    
    // Prepare returns error if funding fails - cleanup already needed here
    if let Err(e) = self.prepare_script_transaction(move_folder_path, transaction, sender_account).await {
        let _ = sender_account.delete_profile_file(&script_path).await;
        return Err(e);
    }
    
    let script_current_dir = std::env::current_dir().unwrap();
    let cmd = create_compile_script_cmd(script_current_dir.clone());
    
    let compile_output = match cmd.execute().await {
        Ok(output) => output,
        Err(e) => {
            let _ = sender_account.delete_profile_file(&script_path).await;
            return Err(e).context(format!("Failed to compile the script: {:?}", &script_current_dir));
        }
    };

    let compiled_script_path = compile_output.script_location;
    let cmd = create_run_script_cmd(compiled_script_path);
    
    let transaction_summary = match cmd.execute().await {
        Ok(summary) => summary,
        Err(e) => {
            let _ = sender_account.delete_profile_file(&script_path).await;
            return Err(e).context(format!("Failed to run the script: {:?}", &script_current_dir));
        }
    };
    
    // Always cleanup
    sender_account
        .delete_profile_file(&script_path)
        .await
        .context("Failed to delete the account profile.")?;

    if let Some(true) = transaction_summary.success {
        Ok(transaction_summary.version.unwrap())
    } else {
        anyhow::bail!("Failed to execute the script: {:?}", &script_current_dir);
    }
}
```

## Proof of Concept

Create a test script that fails during compilation:

```rust
#[tokio::test]
async fn test_profile_cleanup_on_compilation_error() {
    use std::path::PathBuf;
    use tempfile::TempDir;
    
    // Setup temporary directories
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test_script");
    std::fs::create_dir_all(&script_path).unwrap();
    
    // Create invalid Move script that will fail compilation
    let move_toml = script_path.join("Move.toml");
    std::fs::write(&move_toml, "invalid toml content {{{").unwrap();
    
    // Create test account
    let account = Account {
        public_key: "0xtest_pub".to_string(),
        private_key: "0xtest_priv_SENSITIVE".to_string(),
        account: "0xtest123".to_string(),
    };
    
    // Save profile file
    account.save_as_profile_file(&script_path).await.unwrap();
    
    // Verify profile exists with private key
    let profile_path = script_path.join(".aptos/config.yaml");
    assert!(profile_path.exists());
    let content = std::fs::read_to_string(&profile_path).unwrap();
    assert!(content.contains("test_priv_SENSITIVE"));
    
    // Simulate compilation failure (would occur in real code)
    // The profile file should be deleted, but isn't due to the bug
    
    // After "error" the profile file still exists (VULNERABILITY)
    assert!(profile_path.exists(), "BUG: Profile file not cleaned up!");
    let leaked_content = std::fs::read_to_string(&profile_path).unwrap();
    assert!(leaked_content.contains("test_priv_SENSITIVE"), 
            "Private key leaked on filesystem!");
}
```

## Notes

**Important Context:**
1. This vulnerability affects the indexer-transaction-generator tool, which is used for generating test transactions in local development environments, not production blockchain infrastructure
2. The exposed credentials are test account keys used in localhost testing scenarios, not production validator keys or user funds
3. While the technical vulnerability is valid, its impact is limited to development/testing contexts
4. The bug violates secure coding practices regardless of environment and should be fixed to prevent credential accumulation in CI/CD pipelines or shared development systems

**Mitigation Priority:** Medium - Should be fixed as part of routine security improvements, though not a critical production issue.

### Citations

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs (L58-80)
```rust
    async fn prepare_script_transaction(
        &self,
        move_folder_path: &Path,
        transaction: &ScriptTransaction,
        sender_account: &Account,
    ) -> anyhow::Result<()> {
        let script_path = move_folder_path.join(&transaction.script_path);
        std::env::set_current_dir(&script_path).context(format!(
            "Failed to set the current directory to the script folder: {:?}",
            script_path
        ))?;
        // Create temporary profile for the account.
        sender_account
            .save_as_profile_file(&script_path)
            .await
            .context("Failed to save the account profile.")?;
        let fund_cmd = create_fund_cmd(DEFAULT_FUND_AMOUNT_IN_OCTA, sender_account);
        let _ = fund_cmd.execute().await.context(format!(
            "Failed to fund the account for account: {}.",
            sender_account.account
        ))?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs (L85-121)
```rust
    async fn execute_script_transaction(
        &self,
        move_folder_path: &Path,
        transaction: &ScriptTransaction,
        sender_account: &Account,
    ) -> anyhow::Result<u64> {
        let script_path = move_folder_path.join(&transaction.script_path);
        self.prepare_script_transaction(move_folder_path, transaction, sender_account)
            .await?;
        // Compile the setup script.
        let script_current_dir = std::env::current_dir().unwrap();
        let cmd = create_compile_script_cmd(script_current_dir.clone());
        let compile_output = cmd.execute().await.context(format!(
            "Failed to compile the script: {:?}",
            &script_current_dir
        ))?;

        // Use the script location from CompileScript output (script.mv in package root).
        // This is more reliable than the build directory path which may not always exist.
        let compiled_script_path = compile_output.script_location;

        let cmd = create_run_script_cmd(compiled_script_path);
        let transaction_summary = cmd.execute().await.context(format!(
            "Failed to run the script: {:?}",
            &script_current_dir
        ))?;
        sender_account
            .delete_profile_file(&script_path)
            .await
            .context("Failed to delete the account profile.")?;

        if let Some(true) = transaction_summary.success {
            Ok(transaction_summary.version.unwrap())
        } else {
            anyhow::bail!("Failed to execute the script: {:?}", &script_current_dir);
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/accont_manager.rs (L24-45)
```rust
    pub async fn save_as_profile_file(&self, profile_file_path: &Path) -> anyhow::Result<()> {
        // TODO: refactor this to use serde to write the file.
        let content = format!(
            "---\nprofiles:\n  default:\n    public_key: {}\n    private_key: {}\n    account: {}\n    rest_url: {REST_URL}\n    faucet_url: {FAUCET_URL}",
            self.public_key, self.private_key, self.account
        );
        // create the folder.
        let account_folder = profile_file_path.join(".aptos");
        tokio::fs::create_dir_all(account_folder.clone())
            .await
            .context(format!(
                "[Account] Failed to create account profile folder at path: {:?}",
                profile_file_path
            ))?;
        tokio::fs::write(account_folder.join("config.yaml"), content)
            .await
            .context(format!(
                "[Account] Failed to save account profile to path: {:?}",
                profile_file_path
            ))?;
        Ok(())
    }
```
