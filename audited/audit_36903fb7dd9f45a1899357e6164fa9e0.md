# Audit Report

## Title
Git Tag Force-Push Enables Non-Deterministic Dependency Resolution Breaking Governance Proposal Verification

## Summary
The Move package dependency resolution system assumes git tags are immutable and skips re-fetching when a local tag exists. An attacker who controls or compromises a dependency repository can force-push tags to point to different code, causing different validators to compile different bytecode for the same governance proposal, breaking proposal verification integrity.

## Finding Description

The vulnerability exists in the Move package dependency resolution logic that handles git-based dependencies. [1](#0-0) 

This code checks if a git revision is a tag using a **local** tag lookup. If the tag exists locally, the function returns immediately without fetching from the remote origin, even if the remote tag has been force-pushed to point to different code. [2](#0-1) 

The `find_tag()` function executes `git tag --list <rev>` which **only checks local tags**, not remote state.

This breaks the **Deterministic Execution** and **Governance Integrity** invariants in the following attack scenario:

1. **Governance Proposal Creation**: A governance proposal script is created that depends on an external Move package specified with a git tag (e.g., `rev = "v1.0.0"`) [3](#0-2) 

2. **Validator A Verification**: Validator A compiles the proposal to verify it using the `VerifyProposal` command, which internally calls compilation: [4](#0-3) [5](#0-4) 

The compilation caches the dependency at tag v1.0.0 (pointing to commit A).

3. **Attacker Force-Push**: An attacker who has compromised the dependency repository force-pushes tag v1.0.0 to point to malicious code (commit B).

4. **Validator B Verification**: Validator B compiles the same proposal:
   - If B has never fetched this dependency, they clone fresh and get commit B (malicious)
   - If B has the tag cached, they skip the fetch and keep commit A (benign)

5. **Hash Mismatch**: The two validators compute different SHA3-256 hashes for what should be the "same" proposal: [6](#0-5) [7](#0-6) 

6. **Governance Breakdown**: Different validators reach different conclusions about whether the on-chain proposal hash matches the source code they compiled, breaking governance consensus.

Additionally, the digest verification mechanism is **optional** and not enforced: [8](#0-7) 

If a dependency doesn't specify a `digest` field in Move.toml (which is common), no verification occurs even when different code is fetched.

## Impact Explanation

This is **HIGH severity** per the Aptos bug bounty criteria as it constitutes a "significant protocol violation":

1. **Governance Integrity Violation**: Validators cannot reliably verify what code a governance proposal will execute, as different validators compile different bytecode from the "same" tagged dependency
2. **Non-Deterministic Builds**: Breaks reproducibility guarantees essential for security auditing and code verification
3. **Silent Failure**: No warning is given when a remote tag has been force-pushed; validators operate under the false assumption that tag v1.0.0 refers to the same code across all nodes
4. **Trust Breakdown**: Undermines the entire governance verification system where validators must independently verify proposals before voting

While this doesn't directly cause fund loss or consensus safety violations in normal execution (since bytecode is submitted by users), it **breaks the governance layer** which controls protocol upgrades and critical parameters.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Prerequisites:**
1. Attacker must compromise or control a git repository used as a Move package dependency
2. The dependency must use a tag (not the default branch name)
3. Multiple validators must verify proposals at different times

**Likelihood Factors:**
- Git repository compromises are realistic (supply chain attacks are common)
- Force-pushing tags is a standard git operation requiring only write access
- Governance proposals are verified independently by validators
- No cryptographic protection against tag mutation
- The default framework dependency uses a branch ("mainnet"), but custom proposals could use tags

The attack is realistic and has been demonstrated in other ecosystems (e.g., NPM package attacks, Docker image tag overwrites).

## Recommendation

**Immediate Fix**: Always fetch tags from origin before checking if they match, or use commit hashes instead of tags for security-critical dependencies.

**Code Fix for `download_and_update_if_remote()`:**

```rust
if let Ok(tag) = git::find_tag(git_path, git_rev) {
    if tag.trim().starts_with(git_rev) {
        // Tags can be force-pushed on remote - always fetch to verify
        // they still point to the same commit
        writeln!(
            writer,
            "{} {}",
            "VERIFYING GIT TAG".bold().green(),
            git_url,
        )?;
        git::fetch_origin(git_path, dep_name)?;
        
        // Verify the tag still points to the expected commit
        let local_commit = git::get_tag_commit(git_path, git_rev)?;
        git::verify_remote_tag_matches(git_path, git_rev, &local_commit, dep_name)?;
        return Ok(());
    }
}
```

**Additional Mitigations:**
1. **Enforce Digest Verification**: Make the `digest` field mandatory for all git dependencies in security-critical contexts (governance proposals)
2. **Use Commit Hashes**: Document that governance proposals should use specific commit hashes rather than tags
3. **Add Warning**: Warn users when using tags that they may not be immutable
4. **Lock File**: Implement a lock file mechanism (like Cargo.lock) that records exact commit hashes

## Proof of Concept

**Setup:**
1. Create a malicious git repository with a Move package at tag v1.0.0
2. Create a governance proposal script depending on this package

**Step 1 - Validator A builds the proposal:**
```bash
# Validator A clones and verifies proposal
cd proposal_script/
aptos governance verify-proposal --proposal-id 1 --script-path script.move

# This caches the dependency at tag v1.0.0 (commit ABC123)
# Computed hash: 0xDEADBEEF...
```

**Step 2 - Attacker force-pushes the tag:**
```bash
# Attacker modifies the dependency repository
cd malicious-dependency/
# Change code to include backdoor
echo "malicious_code()" >> sources/module.move
git add .
git commit -m "Backdoor"
git tag -f v1.0.0  # Force update tag
git push -f origin v1.0.0  # Force push to remote
```

**Step 3 - Validator B builds the proposal:**
```bash
# Validator B (fresh environment) verifies same proposal
aptos governance verify-proposal --proposal-id 1 --script-path script.move

# This fetches the dependency at tag v1.0.0 (now points to commit XYZ789)
# Computed hash: 0xCAFEBABE...  # DIFFERENT HASH!
```

**Result:** 
- Validator A: Hash `0xDEADBEEF...` (benign code)
- Validator B: Hash `0xCAFEBABE...` (malicious code)
- Governance verification breaks - validators disagree on proposal validity

**Verification:** The vulnerability can be confirmed by examining the git operations:
```bash
# Show that find_tag only checks local tags
git tag --list v1.0.0  # Returns tag name if exists locally, doesn't fetch

# Show that tags can be force-pushed
git push -f origin v1.0.0  # Succeeds with write access
```

## Notes

The vulnerability is particularly concerning because:

1. **Default behavior is unsafe for tags**: The codebase explicitly comments "tags won't be updated" assuming immutability, but git tags are mutable via force-push
2. **Affects governance verification**: The `VerifyProposal` command is specifically designed to ensure validators can verify proposals independently, but this vulnerability breaks that guarantee  
3. **No cryptographic protection**: Unlike commit hashes which are cryptographically bound to content, tags are just pointers that can be moved
4. **Supply chain attack vector**: This enables sophisticated supply chain attacks where attackers can silently inject malicious code into dependencies

The Aptos Framework itself uses local dependencies and is not directly vulnerable, but any governance proposal or user package using git tags for dependencies is affected.

### Citations

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L456-471)
```rust
        match dep.digest {
            None => (),
            Some(fixed_digest) => {
                let resolved_pkg = self
                    .package_table
                    .get(&dep_name_in_pkg)
                    .context("Unable to find resolved package by name")?;
                if fixed_digest != resolved_pkg.source_digest {
                    bail!(
                        "Source digest mismatch in dependency '{}'. Expected '{}' but got '{}'.",
                        dep_name_in_pkg,
                        fixed_digest,
                        resolved_pkg.source_digest
                    )
                }
            },
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L590-596)
```rust
                if let Ok(tag) = git::find_tag(git_path, git_rev) {
                    // If it's exactly the same, then it's a git tag, for now tags won't be updated
                    // Tags don't easily update locally and you can't use reset --hard to cleanup
                    // any extra files
                    if tag.trim().starts_with(git_rev) {
                        return Ok(());
                    }
```

**File:** third_party/move/tools/move-package/src/resolution/git.rs (L139-149)
```rust
pub(crate) fn find_tag(repo_path: &str, rev: &str) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["-C", repo_path, "tag", "--list", rev])
        .output()?;
    let status = output.status;
    if !status.success() {
        return Err(anyhow::anyhow!("Exit status: {}", status));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("Stdout contains non-UTF8 symbols"))
}
```

**File:** crates/aptos/src/move_tool/mod.rs (L260-268)
```rust
            let git_rev = self.framework_git_rev.as_deref().unwrap_or(DEFAULT_BRANCH);
            dependencies.insert(APTOS_FRAMEWORK.to_string(), Dependency {
                local: None,
                git: Some(APTOS_GIT_PATH.to_string()),
                rev: Some(git_rev.to_string()),
                subdir: Some(SUBDIR_PATH.to_string()),
                aptos: None,
                address: None,
            });
```

**File:** crates/aptos/src/governance/mod.rs (L238-242)
```rust
    async fn execute(mut self) -> CliTypedResult<VerifyProposalResponse> {
        // Compile local first to get the hash
        let (_, hash) = self
            .compile_proposal_args
            .compile("SubmitProposal", self.prompt_options)?;
```

**File:** crates/aptos/src/governance/mod.rs (L259-266)
```rust
        // Compare the hashes
        let computed_hash = hash.to_hex();
        let onchain_hash = proposal.execution_hash;

        Ok(VerifyProposalResponse {
            verified: computed_hash == onchain_hash,
            computed_hash,
            onchain_hash,
```

**File:** crates/aptos/src/governance/mod.rs (L849-850)
```rust
    let pack = BuiltPackage::build(package_dir.to_path_buf(), build_options)
        .map_err(|e| CliError::MoveCompilationError(format!("{:#}", e)))?;
```

**File:** crates/aptos/src/governance/mod.rs (L862-863)
```rust
    let bytes = pack.extract_script_code().pop().unwrap();
    let hash = HashValue::sha3_256_of(bytes.as_slice());
```
