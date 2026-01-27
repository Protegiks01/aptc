# Audit Report

## Title
Symbolic Link Following Vulnerability in Move Package Compilation Enables Arbitrary File System Access

## Summary
The `find_move_filenames` function in `move-command-line-common` uses `walkdir` with symbolic link following enabled without validating that resolved paths remain within package boundaries. This allows attackers to craft malicious Move packages containing symbolic links that point to sensitive files outside the package directory, enabling arbitrary file system access during compilation.

## Finding Description

The vulnerability exists in the file discovery mechanism used by the Move compiler when scanning for source files within a package. [1](#0-0) 

The `find_move_filenames` function is implemented in the `move-command-line-common` crate and uses `walkdir::WalkDir` with `follow_links(true)`. [2](#0-1) 

While package paths themselves are canonicalized during dependency resolution [3](#0-2) , this canonicalization only applies to the package directory path itself, not to individual files discovered within it.

**Attack Path:**

1. Attacker creates a legitimate Move package structure at `/malicious_package/`
2. Inside `/malicious_package/sources/`, the attacker creates symbolic links:
   - `validator_key.move` → `/home/validator/.aptos/validator-identity.yaml`
   - `config.move` → `/etc/aptos/validator.yaml`
3. The attacker distributes this package via git repository or package manager
4. When a validator or developer compiles this package, `find_move_filenames` is called on the package's source directories
5. The `walkdir` traversal follows the symbolic links due to `.follow_links(true)`
6. Sensitive files are read from outside the package boundary
7. File contents may be exposed through:
   - Compilation error messages showing file contents
   - Debug output during compilation
   - Side-channel attacks observing file access patterns

**Security Guarantees Broken:**

- **Access Control Violation**: Package compilation should only access files within the package boundary
- **Information Disclosure**: Enables reading arbitrary files on the validator's file system
- **Trust Boundary Violation**: Compiled packages should not be able to access the host file system beyond their designated directory

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program criteria:

1. **Validator Node Compromise Risk**: Attackers can read sensitive validator configuration files, private keys, or identity information. If successful, this could lead to complete validator compromise.

2. **Protocol Violation**: This breaks the expected security boundary of package compilation. Validators and developers trust that compiling a Move package only accesses files within that package.

3. **Information Disclosure**: Sensitive operational data from validator nodes could be exfiltrated, including:
   - Validator identity keys
   - Network configuration
   - Internal directory structures
   - Other packages' source code

4. **Supply Chain Attack Vector**: This enables sophisticated supply chain attacks where malicious dependencies can exfiltrate data from any system that compiles them (validators, CI/CD pipelines, developer machines).

While this doesn't directly cause consensus violations or fund loss, it enables attacks that could lead to those outcomes by compromising validator security.

## Likelihood Explanation

The likelihood of exploitation is **MEDIUM to HIGH**:

**Factors Increasing Likelihood:**
- Validators frequently compile Move packages for verification and deployment
- Package dependencies are commonly added from third-party sources
- The attack requires no special privileges - only the ability to publish a package
- Symbolic link creation is a standard file system operation
- No visible indicators to the victim during compilation

**Factors Decreasing Likelihood:**
- Requires social engineering to get victims to compile the malicious package
- Some systems may have symbolic link creation restrictions
- Security-conscious validators may review package contents before compilation

**Realistic Attack Scenarios:**
- Malicious dependency in a popular Move package
- Compromised package repository injecting malicious versions
- Targeted attack against specific validators via custom packages
- CI/CD pipeline exploitation when automated builds compile untrusted packages

## Recommendation

Implement path validation after symbolic link resolution to ensure all discovered files remain within the package boundary:

**Option 1: Disable Symbolic Link Following (Recommended)**
```rust
// In third_party/move/move-command-line-common/src/files.rs
for entry in walkdir::WalkDir::new(path)
    .follow_links(false)  // Change from true to false
    .into_iter()
    .filter_map(|e| e.ok())
```

**Option 2: Add Path Boundary Validation**
```rust
fn is_within_boundary(base: &Path, target: &Path) -> bool {
    match (base.canonicalize(), target.canonicalize()) {
        (Ok(base_canonical), Ok(target_canonical)) => {
            target_canonical.starts_with(base_canonical)
        },
        _ => false,
    }
}

// Then in find_filenames:
let canonical_base = path.canonicalize()?;
for entry in walkdir::WalkDir::new(path)
    .follow_links(true)
    .into_iter()
    .filter_map(|e| e.ok())
{
    let entry_path = entry.path();
    if !is_within_boundary(&canonical_base, entry_path) {
        continue; // Skip files outside package boundary
    }
    // ... rest of processing
}
```

**Option 3: Add Security Warning**
At minimum, add logging to warn when symbolic links are encountered:
```rust
if entry.path_is_symlink() {
    eprintln!("Warning: Symbolic link detected: {}", entry.path().display());
}
```

## Proof of Concept

**Step 1: Create Malicious Package**
```bash
# Create package structure
mkdir -p malicious_package/sources
cd malicious_package

# Create Move.toml
cat > Move.toml << 'EOF'
[package]
name = "MaliciousPackage"
version = "1.0.0"

[addresses]
malicious = "0x1"
EOF

# Create symbolic link to sensitive file
ln -s /etc/passwd sources/passwd.move

# Create a valid Move file to make package appear legitimate
cat > sources/benign.move << 'EOF'
module malicious::benign {
    public fun init() {}
}
EOF
```

**Step 2: Attempt Compilation**
```bash
# Try to compile the package
aptos move compile --package-dir malicious_package

# Observe that the compiler attempts to process /etc/passwd
# This can be verified using strace:
strace -e openat aptos move compile --package-dir malicious_package 2>&1 | grep passwd
```

**Expected Result:**
The compiler will follow the symbolic link and attempt to read `/etc/passwd`, demonstrating arbitrary file system access. The compilation will fail with an error message that may reveal the file contents or confirm file access.

**Verification:**
Monitor file access during compilation to confirm files outside the package directory are accessed.

## Notes

This vulnerability is particularly concerning in the Aptos ecosystem because:

1. **Validator Security**: Validators regularly compile Move packages for verification before on-chain deployment
2. **Supply Chain Risk**: The Move package ecosystem encourages code reuse through dependencies
3. **Automated Systems**: CI/CD pipelines may automatically compile packages without human review
4. **Trust Assumptions**: Developers and validators may not expect package compilation to access arbitrary files

The fix should be implemented in the `move-command-line-common` crate to protect all users of the Move compiler toolchain, not just Aptos validators.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/mod.rs (L52-52)
```rust
                find_move_filenames(&[path.as_str()], true)?
```

**File:** third_party/move/move-command-line-common/src/files.rs (L80-81)
```rust
        for entry in walkdir::WalkDir::new(path)
            .follow_links(true)
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L334-340)
```rust
                let canonical_path = CanonicalPath::new(&dep_manitest_path).map_err(|err| {
                    anyhow!(
                        "failed to find package at {}: {}",
                        dep_manitest_path.display(),
                        err
                    )
                })?;
```
