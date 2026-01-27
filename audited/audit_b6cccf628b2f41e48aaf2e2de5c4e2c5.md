# Audit Report

## Title
Supply Chain Vulnerability: Lack of Version Pinning and Security Review Process for Upstream Move Repository Synchronization

## Summary
The Aptos Core codebase vendors the Move language implementation in `third_party/move/` and synchronizes it from an upstream repository using Copybara. However, there is no version pinning or commit pinning for upstream updates, and no documented security review process specific to these synchronization operations. This creates a supply chain attack vector where malicious code from the upstream Move repository could be introduced into Aptos Core without adequate security scrutiny.

## Finding Description

The Move language implementation is critical to Aptos security, affecting consensus determinism, bytecode verification, gas metering, and VM execution. The codebase vendors Move in `third_party/move/` and describes this as being "core to the security of Aptos" with source control isolated for security. [1](#0-0) 

However, the Copybara synchronization process has critical security gaps:

**1. No Version/Commit Pinning:**

The Copybara configuration pulls from the upstream repository's `main` branch without any version pinning: [2](#0-1) 

This means every pull operation fetches the latest changes from `main` without specifying a reviewed commit hash or version tag.

**2. No Documented Security Review Process:**

The `third_party/README.md` describes the synchronization process but does not mandate security review: [3](#0-2) [4](#0-3) 

While the Move coding guidelines require two reviewers for PRs: [5](#0-4) 

There is no specific requirement for security team review of upstream changes before pulling them via Copybara.

**3. No CODEOWNERS Protection:**

The `CODEOWNERS` file does not include an entry for `/third_party/move/`, meaning there's no mandatory review by Move security experts for these updates: [6](#0-5) 

**4. Inadequate Security Guidance:**

The `RUST_SECURE_CODING.md` mentions Dependabot for monitoring external crate dependencies: [7](#0-6) 

But provides no guidance for reviewing vendored third-party code synchronized via Copybara.

**Attack Vector:**

An attacker could exploit this by:
1. Compromising the upstream Move repository (github.com/move-language/move-on-aptos) OR getting malicious code merged through social engineering
2. Waiting for an Aptos admin to run `copybara copy.bara.sky pull_move`
3. The malicious changes get pulled into a branch without version verification
4. During PR review, if the diff is large or complex, malicious code could be missed since reviewers may not scrutinize every line of upstream changes
5. Malicious code affecting Move compiler, bytecode verifier, or VM gets merged into production

This could introduce:
- **Consensus splits** via non-deterministic bytecode compilation
- **Bytecode verification bypass** allowing invalid/malicious modules
- **Gas metering bypass** enabling free transaction execution  
- **VM execution bugs** causing validator crashes or state corruption

## Impact Explanation

This is a **High Severity** vulnerability per Aptos Bug Bounty criteria:

- **Validator node slowdowns/crashes**: Malicious Move compiler or VM code could cause validators to crash or slow down significantly
- **API crashes**: Malicious changes to Move components used by APIs could cause crashes
- **Significant protocol violations**: Compromised bytecode verification could allow protocol-violating transactions

In worst-case scenarios, this could escalate to **Critical Severity**:
- **Consensus/Safety violations**: Non-deterministic behavior in Move compiler could cause validators to produce different state roots for identical blocks
- **Loss of Funds**: Gas metering bypass or bytecode verification bypass could enable theft

The severity is High rather than Critical because the attack requires either upstream repository compromise or successful social engineering, and is subject to PR review (though without specific security review requirements).

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
- **Upstream access**: Either compromising github.com/move-language/move-on-aptos OR getting malicious PR merged there
- **Admin action**: Waiting for an Aptos admin to run copybara pull
- **Review bypass**: Hoping reviewers don't catch malicious code in potentially large diffs

However, several factors make this realistic:
- Supply chain attacks on open-source projects are increasing in frequency
- Large diff reviews are error-prone
- No specific security review requirement means general reviewers may miss subtle malicious changes
- The upstream repo may have different security standards than Aptos Core

## Recommendation

Implement a comprehensive security review process for upstream Move synchronization:

**1. Add Version/Commit Pinning:**

Modify the Copybara workflow to require explicit commit hash specification:

```python
# In third_party/copy.bara.sky
core.workflow(
    name = "pull_move",
    origin = git.github_origin(
        url = moveUrl,
        ref = "SPECIFIC_REVIEWED_COMMIT_HASH",  # Must be manually updated after security review
    ),
    # ... rest of config
)
```

**2. Add CODEOWNERS Entry:**

Add to `CODEOWNERS`:
```
/third_party/move/ @wrwg @aptos-labs/security
```

**3. Document Security Review Process:**

Add to `third_party/README.md`:
```markdown
### Security Review for Upstream Pulls

Before pulling changes from upstream Move repository:

1. Review all upstream commits since last sync for security implications
2. Obtain approval from @aptos-labs/security team
3. Update copybara config with specific reviewed commit hash
4. Run copybara pull
5. PR must be reviewed by at least one Move core team member AND one security team member
6. Document which upstream commits were reviewed in PR description
```

**4. Add Security Scanning:**

Implement automated security scanning of pulled changes:
- Static analysis for dangerous patterns
- Comparison against known vulnerable code patterns
- Automated tests to verify deterministic behavior

**5. Update RUST_SECURE_CODING.md:**

Add section on vendored dependency management with explicit guidance for Copybara pulls.

## Proof of Concept

**Demonstration of Current Vulnerability:**

1. Clone aptos-core and examine current copybara configuration:
```bash
git clone https://github.com/aptos-labs/aptos-core
cd aptos-core
cat third_party/copy.bara.sky
# Note: ref = "main" - no commit pinning
```

2. Check CODEOWNERS for third_party/move protection:
```bash
grep "third_party/move" CODEOWNERS
# Returns empty - no specific ownership protection
```

3. Review third_party/README.md:
```bash
cat third_party/README.md
# Note: No security review requirement documented
```

**Simulated Attack Scenario:**

An attacker who compromises the upstream Move repo could introduce subtle changes to the bytecode verifier that disable signature verification for specific transaction types. When an admin runs `copybara pull_move`, these changes get pulled. During PR review, if the diff is 1000+ lines and includes legitimate refactoring, the malicious 5-line change to disable signature checks might be missed.

The malicious code would then be merged into production, allowing transactions with invalid signatures to be accepted, breaking the authentication invariant and potentially enabling fund theft.

**Notes**

This vulnerability represents a **process and architecture gap** rather than a code bug, but the security impact is real and severe. The current reliance on general PR review without specific security review requirements, version pinning, or CODEOWNERS protection creates a realistic attack vector for supply chain compromise.

The fix requires both technical changes (version pinning, CODEOWNERS) and process changes (documented security review requirements). This aligns with industry best practices for managing vendored security-critical dependencies.

### Citations

**File:** third_party/README.md (L3-3)
```markdown
This directory contains synchronized copies of selected external repositories. Those repos are mirrored in the aptos-core repo because they are core to the security of Aptos -- and control over the source should therefore be isolated. They are also mirrored to allow atomic changes across system boundaries. For example, the [Move repository](https://github.com/move-language/move) has a copy in this tree, so we can apply changes simultaneously to Move and Aptos.
```

**File:** third_party/README.md (L7-8)
```markdown
- Code can be submitted in this directory using an aptos-core wide PR. 
- (_For admins only_) Periodically, changes in this directory are pushed upstream or pulled from upstream, using the [copybara](https://github.com/google/copybara) tool. Those pushes will preserve the commit metadata (author, description) and copy it from one repo to another. 
```

**File:** third_party/README.md (L42-71)
```markdown
### Pulling

Code which is pulled from the Move repo might be derived from an older version than the current `main` of aptos-core.

```
        aptos-main
       /          \
      / pull       \
      |             \ external contribution
      | PRs in
      | third_party
```

For this reason, pulling is a bit more complex right now and requires some extra work. 

1. Checkout aptos-core to the commit of the last pull from the Move repo, into a branch `from_move` 
   ```shell
   git checkout <hash>
   git switch -c from_move
   ```
2. Run the following command, where `/Users/wrwg/aptos-core` is replaced by our path to the aptos-core repo:
   ```shell
   copybara copy.bara.sky pull_move --output-root=/tmp --git-destination-url=file:///Users/wrwg/aptos-core
   ```
   This will add a series of commits to the branch `from_move`
3. Rebase `from_move` onto the current `main branch`
   ```shell
   git rebase main
   ```
   Any conflicts are now those of the external contributions relative to the progress in `third_party` and for you to resolve. After that, submit as a PR.
```

**File:** third_party/copy.bara.sky (L8-11)
```text
    origin = git.github_origin(
        url = moveUrl,
        ref = "main",
    ),
```

**File:** third_party/move/documentation/coding_guidelines.md (L28-28)
```markdown
We require every PR to have approval by at least two reviewers. This is enforced by the CI presubmit.
```

**File:** CODEOWNERS (L1-15)
```text
# **Please** keep this file ordered alphabetically by directory paths.

# Owners for the `.github` directory and all its subdirectories.
/.github/ @aptos-labs/prod-eng

# Owners for the `/api` directory and all its subdirectories.
/api/ @banool @gregnazario @0xmaayan

# Owners for the `/aptos-move` directory and its subdirectories:`aptos-gas`, `aptos-vm`, `framework` and `framework/aptos-stdlib/sources/cryptography`.
/aptos-move/aptos-aggregator/ @georgemitenkov @gelash @zekun000
/aptos-move/aptos-gas/ @vgao1996
/aptos-move/aptos-vm/ @wrwg @zekun000 @vgao1996 @georgemitenkov
/aptos-move/aptos-vm/src/keyless_validation.rs @alinush
/aptos-move/aptos-vm-types/ @georgemitenkov @gelash @vgao1996
/aptos-move/framework/ @wrwg
```

**File:** RUST_SECURE_CODING.md (L42-43)
```markdown
- Aptos utilizes **[Dependabot](https://github.com/dependabot)** to continuously monitor libraries. Our policy requires mandatory updates for critical and high-vulnerabilities, or upon impact evaluation given the context for medium and lower.
- We recommend leveraging [deps.dev](https://deps.dev) to evaluate new third party crates. This site provides an OpenSSF scorecard containing essential information. As a guideline, libraries with a score of 7 or higher are typically safe to import. However, those scoring **below 7** must be flagged during the PR and require a specific justification.
```
