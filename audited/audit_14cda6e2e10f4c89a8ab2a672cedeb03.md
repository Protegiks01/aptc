# Audit Report

## Title
Named Address Hijacking via Dependency Priority Inversion in Move Compiler V2

## Summary
A critical address resolution vulnerability in the Move Compiler V2 allows malicious dependencies to hijack named addresses (including system addresses like `@aptos_framework`) by overwriting target package definitions. This occurs due to lack of duplicate address detection in `parse_addresses_from_options()` and incorrect priority ordering where dependencies override target packages. [1](#0-0) 

## Finding Description
The vulnerability exists in the integration between `make_options_for_v2_compiler()` and `parse_addresses_from_options()`. When building Move packages with Compiler V2:

1. **Address Merging Without Validation**: The `make_options_for_v2_compiler()` function merges named addresses from all packages (targets and dependencies) into a single `Vec<String>`: [2](#0-1) 

2. **Priority Inversion**: Addresses are collected with targets first, then dependencies. When the Vec is parsed, later entries (dependencies) overwrite earlier entries (targets) in the BTreeMap.

3. **No Conflict Detection**: Unlike the validated path using `verify_and_create_named_address_mapping()`, the `parse_addresses_from_options()` function performs no duplicate detection: [3](#0-2) 

The validated function exists but is never called in this code path. Instead, `parse_addresses_from_options()` simply collects into a BTreeMap, silently discarding conflicts.

4. **Same Address Map for All Packages**: The parsed addresses are then used identically for sources, source_deps, and dependencies: [4](#0-3) 

**Attack Scenario:**
1. Victim package defines `aptos_framework=0x1` (correct system address)
2. Malicious dependency package defines `aptos_framework=0xBADC0DE` (attacker-controlled)
3. During compilation, addresses are merged: `["aptos_framework=0x1", "aptos_framework=0xBADC0DE"]`
4. When collected into BTreeMap, the last value wins: `aptos_framework -> 0xBADC0DE`
5. All `@aptos_framework` references in victim's code now resolve to attacker's address
6. Victim's transactions call malicious modules deployed at `0xBADC0DE`
7. No compilation error or warning is generated

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria because it enables:

- **Significant Protocol Violations**: System address protections can be bypassed by making code reference attacker-controlled addresses instead of legitimate system modules
- **Supply Chain Attack Vector**: Any dependency can silently hijack critical named addresses
- **Potential Funds Loss**: Malicious code at hijacked addresses could steal funds, manipulate state, or cause other damage
- **Silent Failure**: No error message warns users that their address definitions are being overridden

While this doesn't directly violate consensus (it's a compile-time issue), it breaks the **Access Control** invariant: "System addresses (@aptos_framework, @core_resources) must be protected" by allowing them to be redirected to attacker-controlled addresses.

## Likelihood Explanation
**Medium-High Likelihood:**

- **Attacker Requirements**: Attacker must publish a malicious Move package that victim uses as dependency
- **Low Complexity**: Attack requires only adding named address assignments to dependency's manifest - no sophisticated exploit code needed
- **No Warning**: Users receive no indication their addresses are being overridden
- **Wide Impact**: Affects all users of Move Compiler V2 (the default in Aptos)
- **Detection Difficulty**: Issue only manifests at runtime when calling hijacked addresses, not during compilation

The attack is realistic because developers commonly use third-party dependencies, and address hijacking would be difficult to detect during code review.

## Recommendation
**Immediate Fix: Add Conflict Detection**

Replace `parse_addresses_from_options()` with the validated version:

```rust
pub fn parse_addresses_from_options(
    named_addr_strings: Vec<String>,
) -> anyhow::Result<BTreeMap<String, NumericalAddress>> {
    let parsed: Vec<(String, NumericalAddress)> = named_addr_strings
        .iter()
        .map(|x| parse_named_address(x))
        .collect::<Result<Vec<_>, _>>()?;
    
    // Use verified function to detect conflicts
    verify_and_create_named_address_mapping(parsed)
}
```

**Additional Fix: Correct Priority Order**

In `make_options_for_v2_compiler()`, reverse the order so targets override dependencies:

```rust
options.named_address_mapping = deps
    .into_iter()
    .chain(targets)  // Targets last = higher priority
    .flat_map(...)
```

**Better Solution: Per-Package Address Maps**

Maintain separate address maps for each package instead of merging, similar to the proper Move package resolution: [5](#0-4) 

## Proof of Concept

Create two packages demonstrating the hijacking:

**Victim Package (Move.toml):**
```toml
[addresses]
std = "0x1"
```

**Malicious Dependency (Move.toml):**
```toml
[addresses]
std = "0xBADC0DE"
```

**Compilation Steps:**
1. Build both packages
2. Use `make_options_for_v2_compiler()` to merge addresses
3. Call `parse_addresses_from_options()` on merged list
4. Observe that `std` resolves to `0xBADC0DE` (dependency wins)
5. Victim's `@std::vector` calls now target attacker's address

The vulnerability can be reproduced by examining the BTreeMap contents after `parse_addresses_from_options()` returns, confirming the dependency's value overwrote the target's value without any error.

## Notes
This vulnerability specifically affects the Move Compiler V2 code path through `run_checker()` and does not affect the normal Move package compilation using the proper resolution graph. However, V2 is now the default compiler in Aptos, making this a significant issue affecting most users.

### Citations

**File:** third_party/move/move-model/src/lib.rs (L511-518)
```rust
pub fn parse_addresses_from_options(
    named_addr_strings: Vec<String>,
) -> anyhow::Result<BTreeMap<String, NumericalAddress>> {
    named_addr_strings
        .iter()
        .map(|x| parse_named_address(x))
        .collect()
}
```

**File:** third_party/move/tools/move-package/src/compilation/model_builder.rs (L160-169)
```rust
    options.named_address_mapping = targets
        .into_iter()
        .chain(deps)
        .flat_map(|p| {
            p.named_address_map
                .iter()
                .map(|(n, a)| format!("{}={}", n, a.into_inner()))
                .collect_vec()
        })
        .collect_vec();
```

**File:** third_party/move/move-command-line-common/src/files.rs (L134-170)
```rust
pub fn verify_and_create_named_address_mapping<T: Copy + std::fmt::Display + Eq>(
    named_addresses: Vec<(String, T)>,
) -> anyhow::Result<BTreeMap<String, T>> {
    let mut mapping = BTreeMap::new();
    let mut invalid_mappings = BTreeMap::new();
    for (name, addr_bytes) in named_addresses {
        match mapping.insert(name.clone(), addr_bytes) {
            Some(other_addr) if other_addr != addr_bytes => {
                invalid_mappings
                    .entry(name)
                    .or_insert_with(Vec::new)
                    .push(other_addr);
            },
            None | Some(_) => (),
        }
    }

    if !invalid_mappings.is_empty() {
        let redefinitions = invalid_mappings
            .into_iter()
            .map(|(name, addr_bytes)| {
                format!(
                    "{} is assigned differing values {} and {}",
                    name,
                    addr_bytes
                        .iter()
                        .map(|x| format!("{}", x))
                        .collect::<Vec<_>>()
                        .join(","),
                    mapping[&name]
                )
            })
            .collect::<Vec<_>>();

        anyhow::bail!(
            "Redefinition of named addresses found in arguments to compiler: {}",
            redefinitions.join(", ")
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L193-206)
```rust
    let addrs = move_model::parse_addresses_from_options(options.named_address_mapping.clone())?;
    let mut env = move_model::run_model_builder_in_compiler_mode(
        PackageInfo {
            sources: options.sources.clone(),
            address_map: addrs.clone(),
        },
        PackageInfo {
            sources: options.sources_deps.clone(),
            address_map: addrs.clone(),
        },
        vec![PackageInfo {
            sources: options.dependencies.clone(),
            address_map: addrs.clone(),
        }],
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L1-50)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    package_hooks,
    resolution::{digest::compute_digest, git},
    source_package::{
        layout::SourcePackageLayout,
        manifest_parser::{parse_move_manifest_string, parse_source_manifest},
        parsed_manifest::{
            Dependencies, Dependency, FileName, NamedAddress, PackageDigest, PackageName,
            SourceManifest,
        },
        std_lib::{StdLib, StdVersion},
    },
    BuildConfig,
};
use anyhow::{bail, Context, Result};
use colored::Colorize;
use legacy_move_compiler::command_line::DEFAULT_OUTPUT_DIR;
use move_command_line_common::files::{
    extension_equals, find_filenames, find_move_filenames, FileHash, MOVE_COMPILED_EXTENSION,
};
use move_core_types::account_address::AccountAddress;
use move_symbol_pool::Symbol;
use petgraph::{algo, graphmap::DiGraphMap};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    rc::Rc,
};

pub type ResolvedTable = ResolutionTable<AccountAddress>;
pub type ResolvedPackage = ResolutionPackage<AccountAddress>;
pub type ResolvedGraph = ResolutionGraph<AccountAddress>;

pub type GraphIndex = PackageName;

type ResolutionTable<T> = BTreeMap<NamedAddress, T>;
type ResolvingTable = ResolutionTable<ResolvingNamedAddress>;
type ResolvingGraph = ResolutionGraph<ResolvingNamedAddress>;
type ResolvingPackage = ResolutionPackage<ResolvingNamedAddress>;

#[derive(Debug, Clone)]
pub struct ResolvingNamedAddress {
    value: Rc<RefCell<Option<AccountAddress>>>,
```
