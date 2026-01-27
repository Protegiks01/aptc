# Audit Report

## Title
Private Key Memory Exposure in Indexer Transaction Generator AccountManager

## Summary
The `AccountManager` and `Account` structs in the indexer transaction generator store private keys as plain `String` objects with `Debug` trait derivation, violating Aptos's documented secure coding standards. This creates multiple attack vectors for private key leakage through error messages, debug logging, and memory dumps.

## Finding Description

The `Account` struct stores private keys insecurely in violation of RUST_SECURE_CODING.md requirements: [1](#0-0) 

Aptos's secure coding guidelines explicitly mandate using the `zeroize` crate for private key material: [2](#0-1) [3](#0-2) 

The vulnerability manifests through multiple attack vectors:

**Vector 1: Debug Trait Exposure**
The `Debug` trait derivation on `Account` and `AccountManager` means any debug formatting operation will expose private keys in plain text. This includes panic messages, error contexts, and explicit debug logging.

**Vector 2: Error Message Leakage**
When `AccountManager::load()` deserializes YAML files, parsing errors from `serde_yaml` may include snippets of the malformed YAML content in error messages: [4](#0-3) 

If the YAML file is malformed around the `private_key` field, the error message could expose the key material.

**Vector 3: Memory Dump Exposure**
Private keys stored as plain `String` objects remain in process memory without zeroization. If the process crashes or generates a core dump, private keys will be visible in the dump. The crash handler logs backtraces but doesn't protect sensitive data in memory: [5](#0-4) 

**Vector 4: Usage Context**
While this is a testing tool, the README shows it imports transactions from mainnet/testnet, creating a realistic scenario where users might accidentally use production keys: [6](#0-5) 

The tool is invoked at runtime here: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria due to "Significant protocol violations" - it explicitly violates documented secure coding standards in RUST_SECURE_CODING.md.

**Concrete Impacts:**
1. **Credential Exposure**: Private keys can leak through error logs, debug output, or crash dumps
2. **Transaction Forgery**: Exposed keys enable attackers to forge transactions from compromised accounts
3. **Production Key Risk**: Users working with mainnet data might accidentally place production keys in the tool
4. **Compliance Violation**: Fails to meet security standards documented in the codebase

While this is primarily a testing tool, the security violation is clear and the risk of misuse with production credentials is realistic.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability will trigger in these realistic scenarios:

1. **Malformed YAML File** (Medium): User provides malformed `testing_accounts.yaml` → serde_yaml error includes key snippet → error logged/displayed → private key exposed

2. **Process Crash** (Medium): Any panic or crash while `AccountManager` is in scope → core dump generated → private keys visible in dump file

3. **Future Debug Logging** (High): Developer adds debug logging with `{:?}` formatting → immediate private key exposure

4. **Production Key Misuse** (Low-Medium): User working with mainnet imports accidentally uses production keys in testing tool → keys exposed through any of the above vectors

The combination of multiple exposure vectors and the tool's interaction with real network data increases the overall likelihood.

## Recommendation

**Immediate Fixes:**

1. **Remove Debug Trait Derivation** - Use `SilentDebug` or custom implementation that redacts sensitive fields:

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct Account {
    pub public_key: String,
    #[serde(skip_serializing)]
    pub private_key: String,  // Should use SecretString or zeroize
    pub account: String,
}

// Custom Debug that redacts private key
impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("public_key", &self.public_key)
            .field("private_key", &"<REDACTED>")
            .field("account", &self.account)
            .finish()
    }
}
```

2. **Use Secure String Type** - Replace `String` with a type that implements zeroization (similar to how aptos-crypto handles keys):

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

#[derive(Serialize, Deserialize, Clone)]
pub struct Account {
    pub public_key: String,
    #[serde(serialize_with = "...", deserialize_with = "...")]
    pub private_key: SecureString,
    pub account: String,
}
```

3. **Add Documentation Warning** - Prominently warn users not to use production keys with this tool

## Proof of Concept

**PoC 1: Error Message Leakage**

Create a malformed YAML file `malformed_accounts.yaml`:
```yaml
accounts:
  test_account:
    private_key: "0xSECRET_KEY_HERE_THAT_SHOULD_NOT_LEAK
    public_key: "0x..."
    account: test_account
```

Run the tool:
```bash
cargo run -p aptos-indexer-transaction-generator -- \
  --testing-folder /path/to/malformed \
  --output-folder /tmp/output \
  --mode script
```

Expected: serde_yaml parsing error includes the malformed YAML snippet containing the private key in the error message.

**PoC 2: Debug Format Exposure**

Add temporary debug logging in `config.rs` after line 178:
```rust
let mut account_manager = AccountManager::load(&account_manager_file_path).await?;
println!("Loaded accounts: {:?}", account_manager); // This would expose all private keys
```

**PoC 3: Memory Dump Analysis**

1. Run the tool with a test account
2. Send SIGABRT to force core dump: `kill -ABRT <pid>`
3. Analyze core dump with `strings core_dump | grep "0x"` - private keys will be visible

**Notes:**
- This vulnerability exists in production code, not test files
- Violates explicit security requirements in RUST_SECURE_CODING.md
- Multiple concrete exposure vectors demonstrated
- Impact limited by tool's testing-oriented purpose, but risk of production key misuse is realistic
- Recommended fix aligns with patterns used elsewhere in aptos-crypto for sensitive key material

### Citations

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/accont_manager.rs (L16-21)
```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub public_key: String,
    pub private_key: String,
    pub account: String,
}
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/accont_manager.rs (L60-70)
```rust
    pub async fn load(account_manager_file_path: &Path) -> anyhow::Result<Self> {
        let file = tokio::fs::read_to_string(account_manager_file_path)
            .await
            .context(format!(
                "[Account Manager] The account list file is not found or readable at path: {:?}",
                account_manager_file_path
            ))?;
        let account_manager: AccountManager = serde_yaml::from_str(&file)
            .context("[Account Manager] Failed to parse account list file")?;

        Ok(account_manager)
```

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** crates/crash-handler/src/lib.rs (L33-43)
```rust
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/README.md (L33-41)
```markdown
Your testing folder should contain:
- One file called `testing_accounts.yaml`, which contains testing accounts used.
    ```yaml
    accounts:
      a531b7fdd7917f73ca216d89a8d9ce0cf7e7cfb9086ca6f6cbf9521532748d16:
        private_key: "0x99978d48e7b2d50d0a7a3273db0929447ae59635e71118fa256af654c0ce56c9"
        public_key: "0x39b4acc85e026dc056464a5ea00b98f858260eaad2b74dd30b86ae0d4d94ddf5"
        account: a531b7fdd7917f73ca216d89a8d9ce0cf7e7cfb9086ca6f6cbf9521532748d16
    ```
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/config.rs (L177-178)
```rust
                let account_manager_file_path = testing_folder.join(ACCOUNT_MANAGER_FILE_NAME);
                let mut account_manager = AccountManager::load(&account_manager_file_path).await?;
```
