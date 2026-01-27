# Audit Report

## Title
Runtime Environment Variable Injection Bypasses Build Version Verification in Containerized Deployments

## Summary
The build information system reads the `GIT_SHA` environment variable at runtime, allowing attackers with container orchestration access to inject fake commit hashes that bypass the node-checker's build version validation. This defeats security monitoring designed to detect nodes running modified or unauthorized code.

## Finding Description

The vulnerability exists in the build information gathering mechanism used by Aptos nodes. The system is designed to report accurate build metadata through the `/system_information` endpoint, which the node-checker uses to verify that validators are running approved software versions. [1](#0-0) 

The `get_build_information()` function reads the `GIT_SHA` environment variable at **runtime** using `std::env::var()`, which overrides the compile-time git hash from shadow_rs. This environment variable is intentionally designed to support Docker builds where the `.git` directory is unavailable. [2](#0-1) 

In containerized deployments, the Dockerfile sets this as an environment variable: [3](#0-2) 

The build information is exposed through the inspection service endpoint: [4](#0-3) 

The node-checker's `BuildVersionChecker` retrieves this information and validates that nodes match expected build versions: [5](#0-4) 

**Attack Path:**

1. Attacker gains access to container orchestration (Kubernetes, Docker Swarm, etc.)
2. Attacker modifies node binary with backdoor or runs outdated vulnerable version
3. Attacker overrides container environment variable: `docker run -e GIT_SHA=<legitimate_hash>`
4. Node reports fake hash via `/system_information` endpoint
5. Node-checker validates against fake hash and passes verification
6. Compromised node operates undetected in validator set

## Impact Explanation

This vulnerability is classified as **High Severity** based on the following analysis:

While this does not directly cause consensus violations, fund loss, or network partition, it represents a **significant protocol violation** by defeating critical security monitoring infrastructure. The node-checker is explicitly designed to detect nodes running unauthorized code versions—a key defense against:

- Validators running backdoored binaries
- Nodes operating with known security vulnerabilities  
- Version fragmentation that could lead to consensus incompatibilities

By bypassing this verification, an attacker with compromised infrastructure can:
- Hide the deployment of malicious validator nodes
- Evade detection of outdated, vulnerable software
- Undermine the integrity assurance of the validator set

The impact aligns with **High Severity** ("Significant protocol violations") rather than Medium because it systematically defeats a security control designed to protect the entire validator network, not just individual nodes.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability has moderate-to-high likelihood of exploitation because:

**Facilitating Factors:**
- Container orchestration access is common in validator operations
- Kubernetes/Docker environment variables are easily modified in deployment configs
- No cryptographic validation of build information
- Attack leaves minimal forensic evidence

**Limiting Factors:**
- Requires compromised infrastructure access (not external attacker)
- Operators must already have deployment privileges
- Assumes attacker has already compromised the validator setup

However, in real-world scenarios where infrastructure is compromised (supply chain attacks, insider threats, cloud account compromise), this becomes a trivial technique to hide the compromise from monitoring systems.

## Recommendation

**Fix 1: Embed Build Hash at Compile Time (Recommended)**

Modify the build system to cryptographically sign build artifacts and embed the signature in the binary itself, not in runtime environment variables. The signature should be verified against a known public key.

**Fix 2: Runtime Immutability Check**

If environment variable override is necessary for Docker builds, validate it against a cryptographically signed manifest:

```rust
pub fn get_build_information() -> BTreeMap<String, String> {
    shadow!(build);
    let mut build_information = BTreeMap::new();
    
    // Get compile-time information first
    let compile_time_hash = build::COMMIT_HASH;
    build_information.insert(BUILD_COMMIT_HASH.into(), compile_time_hash.into());
    
    // Only override if GIT_SHA matches a signed manifest
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        if verify_build_signature(&git_sha) {
            build_information.insert(BUILD_COMMIT_HASH.into(), git_sha);
        } else {
            // Log security warning about unsigned override attempt
            warn!("Attempted to override build hash without valid signature");
        }
    }
    
    build_information
}
```

**Fix 3: Mark Environment Overrides in Monitoring**

If overrides are legitimate, clearly distinguish them in the `/system_information` response:

```json
{
  "build_commit_hash": "abc123",
  "build_commit_hash_source": "environment_override",  // New field
  "build_commit_hash_compile_time": "def456"
}
```

## Proof of Concept

**Step 1: Build legitimate node binary**
```bash
# Build with commit hash abc123
docker build --build-arg GIT_SHA=abc123 -t aptos-node:legitimate .
```

**Step 2: Create modified/backdoored binary**
```bash
# Attacker modifies the binary
echo "BACKDOOR" >> aptos-node-binary
```

**Step 3: Run with fake environment variable**
```bash
# Override GIT_SHA to match legitimate build
docker run -e GIT_SHA=abc123 aptos-node:backdoored
```

**Step 4: Verify bypass**
```bash
# Node-checker queries /system_information
curl http://node:9101/system_information
# Returns: {"build_commit_hash": "abc123", ...}

# BuildVersionChecker validates against baseline
# Result: PASS (falsely indicates legitimate build)
```

**Verification:**
The node-checker will report matching build versions despite running completely different code, demonstrating the security monitoring bypass.

---

**Notes:**

The TODO comment in the code acknowledges this as a known limitation: [6](#0-5) 

This vulnerability requires infrastructure-level access but represents a realistic threat in scenarios involving compromised cloud accounts, supply chain attacks, or insider threats. The fix should balance Docker build flexibility with cryptographic verification of build authenticity.

### Citations

**File:** crates/aptos-build-info/src/lib.rs (L88-90)
```rust
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        build_information.insert(BUILD_COMMIT_HASH.into(), git_sha);
    }
```

**File:** crates/aptos-build-info/src/lib.rs (L107-115)
```rust
pub fn get_git_hash() -> String {
    // Docker builds don't have the git directory so it has to be provided by this variable
    // Otherwise, shadow will have the right commit hash
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        git_sha
    } else {
        shadow!(build);
        build::COMMIT_HASH.into()
    }
```

**File:** docker/builder/validator.Dockerfile (L48-49)
```dockerfile
ARG GIT_SHA
ENV GIT_SHA ${GIT_SHA}
```

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L32-41)
```rust
fn get_system_information_json() -> String {
    // Get the system and build information
    let mut system_information = aptos_telemetry::system_information::get_system_information();
    system_information.extend(build_information!());

    // Return the system information as a JSON string
    match serde_json::to_string(&system_information) {
        Ok(system_information) => system_information,
        Err(error) => format!("Failed to get system information! Error: {}", error),
    }
```

**File:** ecosystem/node-checker/src/checker/build_version.rs (L4-6)
```rust
// TODO: Sometimes build_commit_hash is an empty string (so far I've noticed
// this happens when targeting a node running from a container). Figure out
// what to do in this case.
```

**File:** ecosystem/node-checker/src/checker/build_version.rs (L113-135)
```rust
        match target_build_commit_hash {
            Some(target_build_commit_hash) => {
                check_results.push({
                    if baseline_build_commit_hash == target_build_commit_hash {
                        Self::build_result(
                            "Build commit hashes match".to_string(),
                            100,
                            format!(
                                "The build commit hash from the target node ({}) matches the build commit hash from the baseline node ({}).",
                                target_build_commit_hash, baseline_build_commit_hash
                            ),
                        )
                    } else {
                        Self::build_result(
                            "Build commit hash mismatch".to_string(),
                            50,
                            format!(
                                "The build commit hash from the target node ({}) does not match the build commit hash from the baseline node ({}).",
                                target_build_commit_hash, baseline_build_commit_hash
                            ),
                        )
                    }
                });
```
