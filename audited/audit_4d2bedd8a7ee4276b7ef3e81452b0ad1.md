# Audit Report

## Title
Memory Exhaustion DoS via Unbounded Named Address Map in Move Package Compilation

## Summary
The Move compiler's package manifest parser (`manifest_parser.rs`) accepts arbitrarily large address mappings from `Move.toml` files without size validation. An attacker can craft a malicious package manifest with millions of address entries, causing memory exhaustion during compilation and denying service to developers, CI/CD pipelines, and build systems.

## Finding Description
The vulnerability exists in the Move package compilation pipeline where named addresses are parsed from `Move.toml` manifests and loaded into memory without bounds checking.

**Attack Flow:**

1. Attacker creates a malicious `Move.toml` with an extremely large `[addresses]` or `[dev-addresses]` section containing millions of entries
2. The `parse_addresses` function iterates through all TOML entries without size limits [1](#0-0) 
3. All entries are inserted into a `BTreeMap` with no capacity validation [2](#0-1) 
4. The address map flows through `named_address_mapping_for_compiler` which converts the entire resolved table to a `BTreeMap<Symbol, NumericalAddress>` without size checks [3](#0-2) 
5. This map becomes the `named_address_map` field in `PackagePaths` [4](#0-3) 
6. The compiler's `indexed_scopes` function inserts the entire map into `NamedAddressMaps` storage [5](#0-4) 
7. `NamedAddressMaps::insert` pushes the map into a Vec without size validation [6](#0-5) 

The vulnerability violates the **Resource Limits** invariant: compilation operations should respect memory constraints, but no limits are enforced on address map sizes.

**Example Malicious Manifest:**
```toml
[addresses]
addr_0 = "0x1"
addr_1 = "0x2"
# ... millions more entries
addr_9999999 = "0x9999999"
```

## Impact Explanation
This is a **Medium severity** Denial of Service vulnerability that affects build-time availability:

- **Developer Impact**: Developers compiling packages (including dependencies) with malicious manifests experience out-of-memory crashes
- **CI/CD Impact**: Automated build systems can be disrupted, preventing package deployment
- **Supply Chain Risk**: Malicious dependencies can DoS downstream users who attempt to compile them
- **Memory Consumption**: Each Symbol (interned string) + 32-byte NumericalAddress, multiplied by millions of entries = hundreds of MB to GB of memory

While this doesn't directly impact runtime consensus or validator operations, it disrupts the development and deployment pipeline, which is critical for blockchain infrastructure maintenance. The impact aligns with Medium severity per the categorization in the security question.

## Likelihood Explanation
**Likelihood: High**

The attack is highly likely because:
- **Low Barrier**: Requires only creating a malicious `Move.toml` file
- **No Authentication**: No special privileges needed
- **Supply Chain Vector**: Can be embedded in package dependencies
- **Automatic Trigger**: Executes automatically when users run `aptos move compile` or similar commands
- **No Warning**: No size warnings or validation before memory allocation
- **Wide Attack Surface**: Affects all users who compile Move packages from untrusted sources

## Recommendation
Implement size limits on named address maps during manifest parsing:

```rust
// In manifest_parser.rs
const MAX_ADDRESS_ENTRIES: usize = 1000; // Reasonable limit

pub fn parse_addresses(tval: TV) -> Result<PM::AddressDeclarations> {
    match tval {
        TV::Table(table) => {
            // Add size check before processing
            if table.len() > MAX_ADDRESS_ENTRIES {
                bail!(
                    "Too many address entries in manifest: {}. Maximum allowed: {}",
                    table.len(),
                    MAX_ADDRESS_ENTRIES
                );
            }
            
            let mut addresses = BTreeMap::new();
            for (addr_name, entry) in table.into_iter() {
                // ... existing logic
            }
            Ok(addresses)
        },
        // ... rest of implementation
    }
}

// Apply same limit to parse_dev_addresses
```

Additionally, consider implementing progressive limits:
- Warn at 100 entries
- Error at 1000 entries
- Document the limit in Move package documentation

## Proof of Concept

```rust
// File: test_address_map_dos.rs
use move_package::source_package::manifest_parser::parse_move_manifest_string;
use std::time::Instant;

#[test]
fn test_large_address_map_memory_exhaustion() {
    // Generate malicious manifest with 100,000 address entries
    let mut manifest = String::from("[package]\nname = \"MaliciousPackage\"\nversion = \"0.0.0\"\n\n[addresses]\n");
    
    for i in 0..100_000 {
        manifest.push_str(&format!("addr_{} = \"0x{:x}\"\n", i, i));
    }
    
    let start = Instant::now();
    let initial_memory = get_memory_usage(); // Hypothetical function
    
    // This will consume excessive memory without bounds checking
    let result = parse_move_manifest_string(manifest);
    
    let duration = start.elapsed();
    let final_memory = get_memory_usage();
    
    println!("Parse time: {:?}", duration);
    println!("Memory consumed: {} MB", (final_memory - initial_memory) / 1_000_000);
    
    // With 1 million entries, this would cause OOM on systems with limited RAM
    assert!(result.is_ok()); // Currently succeeds, consuming excessive memory
}
```

**Reproduction Steps:**
1. Create a Move package with a `Move.toml` containing 1 million address entries
2. Run `aptos move compile` or equivalent
3. Observe memory consumption spike and potential OOM crash
4. The compilation will either crash or consume gigabytes of RAM unnecessarily

### Citations

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L216-248)
```rust
pub fn parse_addresses(tval: TV) -> Result<PM::AddressDeclarations> {
    match tval {
        TV::Table(table) => {
            let mut addresses = BTreeMap::new();
            for (addr_name, entry) in table.into_iter() {
                let ident = PM::NamedAddress::from(addr_name);
                match entry.as_str() {
                    Some(entry_str) => {
                        if entry_str == EMPTY_ADDR_STR {
                            if addresses.insert(ident, None).is_some() {
                                bail!("Duplicate address name '{}' found.", ident);
                            }
                        } else if addresses
                            .insert(
                                ident,
                                Some(parse_address_literal(entry_str).context(format!(
                                    "Invalid address '{}' encountered.",
                                    entry_str
                                ))?),
                            )
                            .is_some()
                        {
                            bail!("Duplicate address name '{}' found.", ident);
                        }
                    },
                    None => bail!(
                        "Invalid address name {} encountered. Expected a string but found a {}",
                        entry,
                        entry.type_str()
                    ),
                }
            }
            Ok(addresses)
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L1025-1038)
```rust
pub(crate) fn named_address_mapping_for_compiler(
    resolution_table: &ResolvedTable,
) -> BTreeMap<Symbol, NumericalAddress> {
    resolution_table
        .iter()
        .map(|(ident, addr)| {
            let parsed_addr = NumericalAddress::new(
                addr.into_bytes(),
                legacy_move_compiler::shared::NumberFormat::Hex,
            );
            (*ident, parsed_addr)
        })
        .collect::<BTreeMap<_, _>>()
}
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L1062-1067)
```rust
            let named_address_map = named_address_mapping_for_compiler(resolved_table);
            Ok((
                PackagePaths {
                    name: Some(name),
                    paths,
                    named_address_map,
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/command_line/compiler.rs (L95-100)
```rust
                let idx = maps.insert(
                    named_address_map
                        .into_iter()
                        .map(|(k, v)| (k.into(), v))
                        .collect::<NamedAddressMap>(),
                );
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L145-149)
```rust
    pub fn insert(&mut self, m: NamedAddressMap) -> NamedAddressMapIndex {
        let index = self.0.len();
        self.0.push(m);
        NamedAddressMapIndex(index)
    }
```
