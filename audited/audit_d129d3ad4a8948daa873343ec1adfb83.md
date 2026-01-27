# Audit Report

## Title
Critical Private Key Exposure Through Command-Line Arguments in Aptos CLI

## Summary
The Aptos CLI accepts Ed25519 private keys directly through the `--private-key` command-line argument without any security protections, exposing private keys to process listings, shell history files, and system audit logs. This enables trivial theft of private keys by any user with system access or access to shell history, leading to complete account compromise and fund theft.

## Finding Description

The `PrivateKeyInputOptions` struct defines a `--private-key` command-line option that allows users to provide their Ed25519 private key directly as a command-line argument: [1](#0-0) 

When users invoke commands like `aptos init --private-key 0x<hex_key>`, the private key becomes exposed through multiple attack vectors:

1. **Process Listings**: The private key is visible in process monitoring tools (`ps aux`, `top`, `/proc/<pid>/cmdline`) accessible to all users on the system
2. **Shell History**: The command is recorded in shell history files (`~/.bash_history`, `~/.zsh_history`, etc.) which persist indefinitely
3. **System Audit Logs**: Many systems log all executed commands for security auditing purposes

The vulnerability is exploited in the `InitTool::execute()` function where `extract_private_key_cli()` is called: [2](#0-1) 

The code even acknowledges using command-line arguments for the private key but provides no security warnings. While a secure alternative (`--private-key-file`) exists, there is no documentation warning users about the risks of `--private-key`, no deprecation notices, and no technical restrictions preventing its use.

The same vulnerable pattern is replicated throughout the codebase in transaction signing operations: [3](#0-2) 

**Attack Scenario**:
1. User runs: `aptos init --private-key 0x1234567890abcdef...`
2. Attacker with basic system access runs: `ps aux | grep aptos` and captures the private key
3. Alternatively, attacker accesses `~/.bash_history` after user session and extracts the key
4. Attacker imports the stolen private key and transfers all funds from the victim's account

This breaks the **Cryptographic Correctness** invariant (#10) which requires that cryptographic material (private keys) must remain secure. Private keys are the ultimate authentication mechanism in blockchain systems and their exposure is equivalent to complete account compromise.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program criteria for the following reasons:

**Loss of Funds (Critical - up to $1,000,000)**: 
- Direct theft of private keys enables immediate and complete drainage of victim accounts
- Affects any user of the Aptos CLI who uses the `--private-key` flag
- No recovery mechanism exists once a private key is compromised
- Attackers gain full control over victim accounts including transfer of all assets

The vulnerability compromises the fundamental security model of the Aptos blockchain. Unlike smart contract vulnerabilities that affect specific protocols, this issue undermines the basic account security for any CLI user. The exposure window is permanent once a command is executed - the key remains in shell history indefinitely until manually cleared.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited for the following reasons:

1. **User Behavior**: Users may naturally assume command-line arguments are safe, especially new users following examples or tutorials
2. **Ease of Exploitation**: No special skills required - basic system access or reading history files is sufficient
3. **Wide Attack Surface**: 
   - Multi-user systems (shared servers, development environments)
   - Compromised workstations where attacker gains filesystem access
   - Backup systems that archive shell history
   - System monitoring tools that log commands
4. **Persistent Exposure**: Shell history files persist across reboots and sessions
5. **No Warnings**: The CLI provides no security warnings when using `--private-key`

Real-world exploitation scenarios:
- Developer using shared CI/CD infrastructure
- User's laptop compromised by malware that scans shell history
- Cloud instances with process monitoring enabled
- System administrators with access to user home directories

## Recommendation

**Immediate Actions**:

1. **Deprecate the `--private-key` flag** with a breaking change warning
2. **Add security validation** to prevent direct private key input via command line
3. **Display prominent warnings** if users attempt to use `--private-key`
4. **Update documentation** to explicitly warn against this practice

**Recommended Code Fix**:

```rust
#[derive(Debug, Default, Parser)]
pub struct PrivateKeyInputOptions {
    /// Signing Ed25519 private key file path
    ///
    /// Encoded with type from `--encoding`
    /// Mutually exclusive with `--private-key`
    #[clap(long, group = "private_key_input", value_parser)]
    private_key_file: Option<PathBuf>,
    
    /// DEPRECATED: Signing Ed25519 private key
    ///
    /// WARNING: Using --private-key exposes your key in shell history and process listings.
    /// This option is deprecated and will be removed. Use --private-key-file instead.
    /// 
    /// Mutually exclusive with `--private-key-file`
    #[clap(long, group = "private_key_input", hide = true)]
    #[deprecated(note = "Use --private-key-file instead. Direct key input exposes keys in shell history.")]
    private_key: Option<String>,
}

impl PrivateKeyInputOptions {
    pub fn extract_private_key_cli(
        &self,
        encoding: EncodingType,
    ) -> CliTypedResult<Option<Ed25519PrivateKey>> {
        // Emit security warning if direct private key is used
        if self.private_key.is_some() {
            eprintln!("⚠️  WARNING: Using --private-key exposes your private key in shell history!");
            eprintln!("⚠️  Your key may be visible in process listings and system logs.");
            eprintln!("⚠️  Use --private-key-file instead for secure key handling.");
            eprintln!("⚠️  This option will be removed in a future version.");
        }
        
        self.parse_private_key(
            encoding,
            self.private_key_file.clone(),
            self.private_key.clone(),
        )
    }
}
```

**Long-term Solution**:
- Remove the `--private-key` option entirely in the next major version
- Provide secure key management through hardware wallets or encrypted key files only
- Add documentation with security best practices for key handling

## Proof of Concept

**Step 1: Demonstrate Key Exposure in Process Listings**

Terminal 1 (User):
```bash
# User initializes account with private key via command line
aptos init --private-key 0xc5338cd251c22daa8c9c9cc94f498cc8a5c7e1d2e75287a8dda89f9f5acc8d00 --assume-yes
```

Terminal 2 (Attacker with basic user access):
```bash
# Attacker monitors processes and captures the private key
ps aux | grep "aptos init"
# Output shows: ... aptos init --private-key 0xc5338cd251c22daa8c9c9cc94f498cc8a5c7e1d2e75287a8dda89f9f5acc8d00 ...

# Attacker can now steal all funds by importing this key
```

**Step 2: Demonstrate Key Exposure in Shell History**

```bash
# After user session ends, attacker accesses shell history
cat ~/.bash_history | grep "private-key"
# Output: aptos init --private-key 0xc5338cd251c22daa8c9c9cc94f498cc8a5c7e1d2e75287a8dda89f9f5acc8d00 --assume-yes

# Attacker extracts the key and imports it
aptos init --private-key 0xc5338cd251c22daa8c9c9cc94f498cc8a5c7e1d2e75287a8dda89f9f5acc8d00 --profile attacker

# Attacker now has full control of victim's account
aptos account transfer --account <attacker-address> --amount 1000000
```

**Step 3: Verify Safe Alternative Works**

```bash
# Correct approach using file-based key (not exposed in process listings)
echo "0xc5338cd251c22daa8c9c9cc94f498cc8a5c7e1d2e75287a8dda89f9f5acc8d00" > /tmp/key.txt
chmod 600 /tmp/key.txt
aptos init --private-key-file /tmp/key.txt --assume-yes

# Process listing shows only the file path, not the key contents
ps aux | grep "aptos init"
# Output: ... aptos init --private-key-file /tmp/key.txt ...
```

**Impact Demonstration**:
This PoC demonstrates that any user with:
- Read access to `/proc` filesystem (standard on Linux)
- Access to user's home directory (backup systems, system admins)
- Process monitoring capabilities (default on most systems)

Can trivially extract private keys and steal all funds from affected accounts. The vulnerability requires no sophisticated tooling or privileged access, making it easily exploitable at scale.

### Citations

**File:** crates/aptos/src/common/types.rs (L780-794)
```rust
#[derive(Debug, Default, Parser)]
pub struct PrivateKeyInputOptions {
    /// Signing Ed25519 private key file path
    ///
    /// Encoded with type from `--encoding`
    /// Mutually exclusive with `--private-key`
    #[clap(long, group = "private_key_input", value_parser)]
    private_key_file: Option<PathBuf>,
    /// Signing Ed25519 private key
    ///
    /// Encoded with type from `--encoding`
    /// Mutually exclusive with `--private-key-file`
    #[clap(long, group = "private_key_input")]
    private_key: Option<String>,
}
```

**File:** crates/aptos/src/common/init.rs (L213-219)
```rust
            let ed25519_private_key = if let Some(key) = self
                .private_key_options
                .extract_private_key_cli(self.encoding_options.encoding)?
            {
                eprintln!("Using command line argument for private key");
                key
            } else {
```

**File:** crates/aptos/src/common/transactions.rs (L60-88)
```rust
#[derive(Debug, Default, Parser)]
pub struct TxnOptions {
    /// Sender account address
    ///
    /// This allows you to override the account address from the derived account address
    /// in the event that the authentication key was rotated or for a resource account
    #[clap(long, value_parser = crate::common::types::load_account_arg)]
    pub(crate) sender_account: Option<AccountAddress>,

    #[clap(flatten)]
    pub(crate) private_key_options: PrivateKeyInputOptions,
    #[clap(flatten)]
    pub(crate) encoding_options: EncodingOptions,
    #[clap(flatten)]
    pub(crate) profile_options: ProfileOptions,
    #[clap(flatten)]
    pub(crate) rest_options: RestOptions,
    #[clap(flatten)]
    pub(crate) gas_options: GasOptions,
    #[clap(flatten)]
    pub prompt_options: PromptOptions,
    /// Replay protection mechanism to use when generating the transaction.
    ///
    /// When "nonce" is chosen, the transaction will be an orderless transaction and contains a replay protection nonce.
    ///
    /// When "seqnum" is chosen, the transaction will contain a sequence number that matches with the sender's onchain sequence number.
    #[clap(long, default_value_t = ReplayProtectionType::Seqnum)]
    pub(crate) replay_protection_type: ReplayProtectionType,
}
```
