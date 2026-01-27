# Audit Report

## Title
Windows Drive Letter Injection in Move CLI Package Creation

## Summary
The Move CLI's `move new` command does not validate package names before using them as filesystem paths. On Windows, package names containing drive letters (e.g., `C:package`) cause files to be created on different drives than expected, bypassing the user's intended working directory.

## Finding Description
The vulnerability exists in the `execute()` function of the Move CLI's package creation command. When a user runs `move new <name>` without specifying an explicit path, the package name is used directly as a filesystem path without validation. [1](#0-0) 

The `name` field is defined as a plain `String` with no constraints. When no explicit path is provided, this name becomes the filesystem path: [2](#0-1) 

On Windows, the path `C:package` is interpreted as a drive-relative path (relative to the current directory on drive C:), not as a literal directory name. This causes files to be created on drive C: instead of the user's current working drive.

While package name validation exists in the codebase, it is only enforced during TOML deserialization when the package manifest is parsed, not during package creation: [3](#0-2) 

The validation rejects colons (`:`) in package names, but this check occurs **after** the filesystem operations have already completed.

## Impact Explanation
This issue is classified as **Low Severity** per Aptos bug bounty criteria (non-critical implementation bug). The impact is limited to:

1. Files created on unexpected drives/locations on Windows systems
2. User confusion and potential unintended file operations
3. No impact on blockchain consensus, validator operations, or funds
4. No privilege escalation or arbitrary file write capabilities
5. Predictable file paths (sources/, Move.toml) with no security-sensitive data

This is a CLI tool usability and path handling issue, not a blockchain protocol vulnerability.

## Likelihood Explanation
The likelihood is **Low** because:
- Requires Windows operating system
- Requires user to provide a package name with drive letter syntax
- Requires social engineering or user error (no automated attack vector)
- User must intentionally run the command
- Will fail later when attempting to build the package due to invalid package name

## Recommendation
Add package name validation to the `execute()` function before performing filesystem operations:

```rust
pub fn execute(
    self,
    path: Option<PathBuf>,
    version: &str,
    deps: impl IntoIterator<Item = (impl Display, impl Display)>,
    addrs: impl IntoIterator<Item = (impl Display, impl Display)>,
    custom: &str,
) -> anyhow::Result<()> {
    let Self { name } = self;
    
    // Add validation before using name as path
    if !is_valid_package_name(&name) {
        bail!("Invalid package name '{name}'. Package names must start with a letter or underscore and contain only letters, digits, hyphens, and underscores.");
    }
    
    let p: PathBuf;
    let path: &Path = match path {
        Some(path) => {
            p = path;
            &p
        },
        None => Path::new(&name),
    };
    // ... rest of function
}
```

Import the validation function from the package manifest crate or duplicate the validation logic.

## Proof of Concept

**Windows Test Steps:**

1. Open Command Prompt on drive D: (or any non-C drive)
2. Run: `move new C:testpackage`
3. Expected: Package created in current directory as `C:testpackage/`
4. Actual: Package created on C: drive relative to current directory on C:
5. Verify by checking: `dir C:\testpackage` or `dir C:\Users\<username>\testpackage`

**Expected Output:**
- Files created at `C:\<current-dir-on-C>\testpackage\sources\`
- Files created at `C:\<current-dir-on-C>\testpackage\Move.toml`

**Note:** This vulnerability requires manual testing on a Windows system as it depends on OS-specific path handling behavior.

## Notes

This vulnerability is **real but limited in scope**. It affects only the Move CLI tool's package creation functionality on Windows and has no impact on:
- Aptos blockchain consensus or validator operations
- Move VM execution or bytecode validation  
- On-chain state, governance, or staking systems
- Network protocol or security-critical operations

The issue is properly classified as **Low Severity** and represents a path handling bug in developer tooling rather than a blockchain security vulnerability.

### Citations

**File:** third_party/move/tools/move-cli/src/base/new.rs (L26-28)
```rust
    /// The name of the package to be created.
    pub name: String,
}
```

**File:** third_party/move/tools/move-cli/src/base/new.rs (L50-59)
```rust
        let Self { name } = self;
        let p: PathBuf;
        let path: &Path = match path {
            Some(path) => {
                p = path;
                &p
            },
            None => Path::new(&name),
        };
        create_dir_all(path.join(SourcePackageLayout::Sources.path()))?;
```

**File:** third_party/move/tools/move-package-manifest/src/package_name.rs (L58-67)
```rust
fn is_valid_package_name(s: &str) -> bool {
    let mut chars = s.chars();

    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => (),
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
```
