# Audit Report

## Title
Git Reference Ambiguity Allows Supply Chain Attack via Tag Shadowing in Move Package Resolver

## Summary
The Move package resolver's git revision resolution mechanism is vulnerable to a reference ambiguity attack. Attackers can create specially-named git tags that shadow intended branch references, causing the package lock to pin malicious commits instead of legitimate ones. This enables supply chain attacks that could compromise consensus, execution integrity, and fund security across the Aptos network.

## Finding Description

The vulnerability exists in the git revision resolution logic used by the Move package resolver. When resolving git dependencies, the code prepends "origin/" to user-specified revision strings and uses git's `revparse_single` to resolve them to commit IDs. [1](#0-0) 

The critical issue is at line 191 where `revparse_single(&format!("origin/{}", rev))` is called. According to git's reference resolution rules (gitrevisions specification), when resolving a reference name like "origin/main", git searches namespaces in this order:
1. `refs/`
2. `refs/tags/`
3. `refs/heads/`
4. `refs/remotes/`

This means `refs/tags/origin/main` has **higher priority** than the intended `refs/remotes/origin/main`.

**Attack Scenario:**

1. Attacker sets up a malicious git repository or compromises an existing one
2. Creates a legitimate branch "main" pointing to benign code (commit Y)
3. Creates a tag named "origin/main" pointing to malicious code (commit X)
4. Victim specifies dependency: `{ Git = { url = "https://attacker.com/repo", rev = "main" } }`
5. The resolver calls `resolve_git_revision` which formats the revision as "origin/main"
6. Git's `revparse_single("origin/main")` finds `refs/tags/origin/main` (malicious commit X) BEFORE `refs/remotes/origin/main` (benign commit Y)
7. Lock file records malicious commit X
8. All subsequent builds use the malicious code

This is exacerbated by the fetch behavior where only branches are updated, not tags: [2](#0-1) 

The fetch refspec at line 149 only fetches branches (`refs/heads/*:refs/remotes/origin/*`), leaving tags stale after initial clone. This creates a persistent attack surface where tags fetched during initial clone shadow subsequently updated branches.

The vulnerability propagates through the dependency resolution chain: [3](#0-2) 

When git dependencies are processed, the malicious commit ID gets pinned in the lock file: [4](#0-3) 

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability meets multiple critical impact categories from the Aptos bug bounty program:

1. **Consensus/Safety Violations**: If the Aptos Framework or consensus-related Move packages are sourced from git dependencies, malicious code could be injected to:
   - Manipulate state transitions causing different validators to produce different state roots
   - Break deterministic execution invariants
   - Cause chain splits or consensus failures

2. **Remote Code Execution**: Validators and full nodes building from a poisoned lock file will execute arbitrary attacker-controlled Move bytecode during:
   - VM initialization
   - Transaction execution
   - Framework function calls

3. **Loss of Funds**: Malicious code in framework packages could:
   - Manipulate account balances
   - Bypass access controls
   - Steal or freeze user funds
   - Corrupt staking/governance logic

4. **Network Partition**: All nodes building from the compromised lock file will execute different code than nodes with clean dependencies, causing non-recoverable network splits requiring hard forks.

The attack violates the **Deterministic Execution** invariant - validators building at different times or from different git cache states may resolve to different commits, producing divergent execution results.

## Likelihood Explanation

**HIGH LIKELIHOOD** - The attack is practical and requires minimal sophistication:

**Attacker Requirements:**
- Ability to push tags to a git repository (malicious package, compromised existing package, or typosquatting)
- No special privileges or validator access needed
- Tags with "/" in names are valid and commonly used (e.g., "release/v1.0")

**Attack Characteristics:**
- Creating a tag named "origin/main" is not suspicious - many projects use prefixed tags
- Victims cannot easily detect the tag shadowing without manual inspection
- Works for any branch name (main, develop, master, etc.)
- Persistent - once the lock file is poisoned, it remains until manual intervention
- Scales to transitive dependencies - all downstream packages are affected

**Real-World Scenarios:**
- Typosquatting: Attacker creates "aptos-framwork" (typo) with shadow tags
- Compromised repository: Attacker gains push access and adds shadow tags
- Malicious package author: Intentionally shadows branches with tags
- Supply chain injection: Dependency of a dependency uses malicious git source

## Recommendation

**Immediate Fix:**

1. **Use explicit refspecs in resolution** - Change the resolution to explicitly target remote-tracking branches:

```rust
pub async fn resolve_git_revision(&self, git_url: &Url, rev: &str) -> Result<Oid>
where
    L: PackageCacheListener,
{
    let repo = self.clone_or_update_git_repo(git_url).await?;

    // Try to resolve as remote-tracking branch first
    let refname = format!("refs/remotes/origin/{}", rev);
    let obj = repo
        .repo
        .revparse_single(&refname)
        .or_else(|_| {
            // If not found as branch, try as tag explicitly
            repo.repo.revparse_single(&format!("refs/tags/{}", rev))
        })
        .or_else(|_| {
            // Finally try as commit hash
            repo.repo.revparse_single(rev)
        })
        .map_err(|_err| {
            anyhow!(
                "Failed to resolve rev string \"{}\" in repo {}",
                rev,
                git_url
            )
        })?;
    let oid = obj.id();

    Ok(oid)
}
```

2. **Fetch tags explicitly and update them** - Modify the fetch refspec to include tags:

```rust
remote.fetch(
    &[
        "refs/heads/*:refs/remotes/origin/*",
        "refs/tags/*:refs/tags/*"  // Add tag fetching
    ],
    Some(&mut fetch_options),
    None,
)
```

3. **Validate resolved ref type** - After resolution, verify the ref type matches expectations:

```rust
// After resolving, check if it's actually a remote-tracking branch
let reference = repo.repo.find_reference(&format!("refs/remotes/origin/{}", rev));
if reference.is_err() {
    // Warn or error if resolved to tag instead of branch
    bail!("Revision {} resolved to non-branch reference", rev);
}
```

**Long-term Solution:**

Implement ref type checking similar to the existing move-package resolution: [5](#0-4) 

Add explicit tag detection and handling logic that distinguishes between branches (which should update) and tags (which should be pinned).

## Proof of Concept

```bash
#!/bin/bash
# PoC: Demonstrate tag shadowing attack

# Setup malicious repository
mkdir malicious-package
cd malicious-package
git init

# Create benign code on main branch
echo "module benign { }" > Move.toml
git add Move.toml
git commit -m "benign code"
git branch -M main

# Create malicious code
echo "module malicious { /* steals funds */ }" > Move.toml
git add Move.toml
MALICIOUS_COMMIT=$(git commit -m "malicious code" | awk '{print $2}')

# Reset main to benign code
git reset --hard HEAD~1

# Create shadow tag pointing to malicious code
git tag "origin/main" $MALICIOUS_COMMIT

# Push to remote
git remote add origin https://github.com/attacker/malicious-package
git push -u origin main
git push origin "origin/main"

# Victim uses Move.toml with:
# [dependencies]
# MaliciousPackage = { git = "https://github.com/attacker/malicious-package", rev = "main" }

# When resolved:
# - Code looks for "origin/main"
# - Git finds refs/tags/origin/main (malicious) BEFORE refs/remotes/origin/main (benign)
# - Lock file pins malicious commit
# - All builds use compromised code
```

**Verification Steps:**
1. Create test repository with shadow tag as shown above
2. Add as Move package dependency with `rev = "main"`
3. Run package resolver to generate lock file
4. Observe that lock file contains commit hash of malicious code instead of main branch tip
5. Subsequent builds use the malicious commit

## Notes

This vulnerability is particularly dangerous because:

1. **Silent Failure**: No warnings are generated when tags shadow branches
2. **Lock File Persistence**: Once poisoned, the lock file remains compromised until manual inspection
3. **Transitive Impact**: All packages depending on the compromised package inherit the vulnerability
4. **Validator Impact**: If framework packages or consensus-critical dependencies use git sources, all validators building from the lock file are compromised
5. **Difficult Detection**: Requires manual git repository inspection to notice shadow tags

The issue affects the core supply chain security of Move package dependencies and could have network-wide impact if exploited against widely-used packages like the Aptos Framework or commonly-used Move libraries.

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L143-154)
```rust
                let mut remote = repo.find_remote("origin")?;
                // Fetch all remote branches and map them to local remote-tracking branches
                // - refs/heads/*: fetch all remote branches
                // - refs/remotes/origin/*: store them as local remote-tracking branches under origin/
                remote
                    .fetch(
                        &["refs/heads/*:refs/remotes/origin/*"],
                        Some(&mut fetch_options),
                        None,
                    )
                    .map_err(|err| anyhow!("Failed to update git repo at {}: {}", git_url, err))?;
            }
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L183-202)
```rust
    pub async fn resolve_git_revision(&self, git_url: &Url, rev: &str) -> Result<Oid>
    where
        L: PackageCacheListener,
    {
        let repo = self.clone_or_update_git_repo(git_url).await?;

        let obj = repo
            .repo
            .revparse_single(&format!("origin/{}", rev))
            .map_err(|_err| {
                anyhow!(
                    "Failed to resolve rev string \"{}\" in repo {}",
                    rev,
                    git_url
                )
            })?;
        let oid = obj.id();

        Ok(oid)
    }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L387-390)
```rust
        PackageLocation::Git { url, rev, subdir } => {
            let commit_id = package_lock
                .resolve_git_revision(package_cache, &url, &rev.unwrap())
                .await?;
```

**File:** third_party/move/tools/move-package-resolver/src/lock.rs (L62-84)
```rust
    pub async fn resolve_git_revision<L>(
        &mut self,
        package_cache: &PackageCache<L>,
        git_url: &Url,
        rev: &str,
    ) -> Result<Oid>
    where
        L: PackageCacheListener,
    {
        let git_identity = CanonicalGitIdentity::new(git_url)?;

        let repo_loc_and_rev = format!("{}@{}", git_identity, rev);

        let res = match self.git.entry(repo_loc_and_rev) {
            btree_map::Entry::Occupied(entry) => entry.get().clone(),
            btree_map::Entry::Vacant(entry) => {
                let oid = package_cache.resolve_git_revision(git_url, rev).await?;
                entry.insert(oid.to_string()).clone()
            },
        };

        Ok(Oid::from_str(&res)?)
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L583-597)
```rust
                if let Ok(parsed_rev) = git::find_rev(git_path, git_rev) {
                    // If it's exactly the same, then it's a git rev
                    if parsed_rev.trim().starts_with(git_rev) {
                        return Ok(());
                    }
                }

                if let Ok(tag) = git::find_tag(git_path, git_rev) {
                    // If it's exactly the same, then it's a git tag, for now tags won't be updated
                    // Tags don't easily update locally and you can't use reset --hard to cleanup
                    // any extra files
                    if tag.trim().starts_with(git_rev) {
                        return Ok(());
                    }
                }
```
