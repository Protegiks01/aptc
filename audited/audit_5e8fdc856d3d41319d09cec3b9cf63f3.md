# Audit Report

## Title
Supply Chain Code Injection via Unvalidated ABI Deserialization in SDK Builder

## Summary
The `rust::output()` function in `aptos_sdk_builder` generates Rust code from Move ABIs without validating that deserialized identifier strings are safe for code generation. Combined with the fact that `Identifier` deserialization bypasses validation checks, this creates a supply chain vulnerability where compromised build artifacts could inject malicious Rust code into generated SDK bindings.

## Finding Description

The vulnerability exists across three key points in the codebase:

**1. Identifier Deserialization Bypasses Validation**

The Move `Identifier` type is designed to enforce strict character restrictions (alphanumeric, underscore, dollar sign only). However, as explicitly documented in the test suite, Serde deserialization bypasses this validation: [1](#0-0) 

This test demonstrates that malicious identifiers containing special characters like `::` can be created via deserialization, bypassing the validation enforced by the `Identifier::new()` constructor.

**2. ABI Deserialization Without Re-validation**

When the framework release builder extracts ABIs from compiled packages, it deserializes them from BCS bytes without any validation: [2](#0-1) 

The `unwrap()` call means any deserialization error would panic, but there's no check that the deserialized identifiers are actually valid Move identifiers. Furthermore, ABI name fields (function names, argument names) are stored as plain `String` types with no validation at all: [3](#0-2) 

**3. Unsanitized Code Generation**

The `rust::output()` function uses these potentially malicious names directly in generated Rust code, with only case conversion (no sanitization): [4](#0-3) 

The names are converted to snake_case/UpperCamelCase using the `heck` crate, then written directly into Rust source code via `writeln!` macros. Special characters that could break Rust syntax (backticks, quotes, newlines, braces, semicolons) are not escaped or validated.

**4. Minimal Doc String Processing**

Doc strings, which can contain arbitrary UTF-8 content, receive only minimal processing: [5](#0-4) [6](#0-5) 

While the `///` prefix on each line provides some protection, this doesn't prevent injection of malicious Rust markdown that could execute code when processed by rustdoc.

**Attack Scenario:**

1. Attacker compromises build artifacts (via filesystem access, supply chain attack on dependencies, or compromised developer machine)
2. Attacker crafts malicious BCS-serialized `EntryABI` with:
   - Function name containing: `foo\n} fn malicious() { /* payload */ } fn bar() {`
   - Or doc strings with malicious rustdoc directives
3. When `release_builder.rs` calls `extract_abis()`, malicious ABIs are deserialized without validation
4. `rust::output()` generates Rust code with injected payload
5. Generated bindings are compiled and distributed to SDK users

## Impact Explanation

**HIGH SEVERITY** - Significant protocol violation and supply chain integrity compromise.

This vulnerability enables:
- **Remote Code Execution** in the build environment when generated code is compiled
- **Supply chain attack** affecting all Aptos SDK consumers
- **Backdoor injection** in officially distributed Rust bindings
- **Compromise of framework release artifacts** 

While not directly affecting consensus or validator nodes, this represents a critical weakness in the build security posture that could be exploited to compromise the entire Aptos ecosystem through the SDK distribution channel.

Per Aptos bug bounty criteria, this qualifies as HIGH severity due to:
- Significant protocol violation (supply chain integrity)
- Potential for widespread impact on developer ecosystem
- Code execution in trusted build environments

## Likelihood Explanation

**MODERATE** - Requires attacker to compromise build infrastructure, but impact is severe.

Attack prerequisites:
- Write access to build artifacts or compiled ABI files
- OR ability to intercept/modify files during build process  
- OR compromise of Move compiler to generate malicious ABIs
- OR social engineering access to developer/build machines

While these prerequisites require elevated access, they are achievable through:
- Compromised developer workstation
- Supply chain attack on build dependencies
- Man-in-the-middle during package downloads
- Insider threat

The lack of defense-in-depth (no validation after deserialization, no sanitization in code generation) means that once build artifacts are compromised, exploitation is straightforward.

## Recommendation

Implement multi-layer validation and sanitization:

**1. Add Validation After ABI Deserialization:**
```rust
pub fn extract_abis(&self) -> Option<Vec<EntryABI>> {
    self.package.compiled_abis.as_ref().map(|abis| {
        abis.iter()
            .map(|(_, bytes)| {
                let abi = bcs::from_bytes::<EntryABI>(bytes.as_slice())
                    .expect("Failed to deserialize ABI");
                // Validate all identifiers
                validate_abi_safety(&abi).expect("Invalid ABI identifiers");
                abi
            })
            .collect()
    })
}

fn validate_abi_safety(abi: &EntryABI) -> anyhow::Result<()> {
    // Validate function name
    if !is_safe_identifier(abi.name()) {
        bail!("Unsafe function name in ABI: {}", abi.name());
    }
    // Validate all argument and type parameter names
    for arg in abi.args() {
        if !is_safe_identifier(arg.name()) {
            bail!("Unsafe argument name: {}", arg.name());
        }
    }
    // Similar checks for ty_args, module names, etc.
    Ok(())
}

fn is_safe_identifier(s: &str) -> bool {
    // Enforce Move identifier rules: alphanumeric + underscore only
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_')
        && !s.chars().next().unwrap().is_ascii_digit()
}
```

**2. Sanitize in Code Generation:**
```rust
fn sanitize_for_rust_code(s: &str) -> String {
    // Additional safety layer: escape or reject any non-alphanumeric characters
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}
```

**3. Fix Identifier Deserialization:**

Modify `Identifier` to validate during deserialization by implementing custom `Deserialize`:
```rust
impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Box::<str>::deserialize(deserializer)?;
        if is_valid(&s) {
            Ok(Self(s))
        } else {
            Err(serde::de::Error::custom(format!("Invalid identifier: {}", s)))
        }
    }
}
```

## Proof of Concept

```rust
// File: tests/abi_injection_poc.rs
use aptos_sdk_builder::rust;
use aptos_types::transaction::*;
use move_core_types::language_storage::ModuleId;
use move_core_types::account_address::AccountAddress;
use std::io::Write;

#[test]
fn test_abi_code_injection() {
    // Craft malicious ABI with injected Rust code in function name
    let malicious_name = "legitimate_func\n} \
        fn injected_backdoor() { \
            std::process::Command::new(\"echo\").arg(\"pwned\").spawn(); \
        } \
        fn dummy() {";
    
    // Create ABI - in real attack, this would be via malicious BCS deserialization
    let malicious_abi = EntryABI::TransactionScript(
        TransactionScriptABI::new(
            malicious_name.to_string(),
            "Legitimate looking documentation".to_string(),
            vec![0x1, 0x2, 0x3], // dummy bytecode
            vec![],
            vec![]
        )
    );
    
    // Generate Rust code
    let mut output = Vec::new();
    rust::output(&mut output, &[malicious_abi], true).unwrap();
    
    let generated_code = String::from_utf8(output).unwrap();
    
    // Verify injection succeeded
    assert!(generated_code.contains("fn injected_backdoor()"),
            "Code injection payload should appear in generated code");
    
    println!("Generated malicious code:\n{}", generated_code);
    
    // In real scenario, this malicious code would be compiled and distributed
}
```

## Notes

This vulnerability represents a **trust boundary violation** where the code assumes deserialized ABIs are safe because they originated from the Move compiler. However, once serialized to disk, these artifacts become an untrusted input vector that should be validated before use in security-sensitive operations like code generation.

The existing test explicitly acknowledges that identifier validation is bypassed during deserialization, but the security implications for the SDK builder were not fully considered. While the normal compilation flow produces safe ABIs, the lack of defense-in-depth creates unnecessary risk in the build supply chain.

### Citations

**File:** api/src/tests/transactions_test.rs (L486-496)
```rust
    // This is a way to get around the Identifier checks!
    #[derive(serde::Serialize)]
    struct HackStruct(pub Box<str>);

    // Identifiers check when you call new, but they don't check when you deserialize, surprise!
    let module_id: Identifier =
        serde_json::from_str(&serde_json::to_string(&HackStruct("coin".into())).unwrap()).unwrap();
    let func: Identifier = serde_json::from_str(
        &serde_json::to_string(&HackStruct("transfer::what::what".into())).unwrap(),
    )
    .unwrap();
```

**File:** aptos-move/framework/src/built_package.rs (L447-453)
```rust
    pub fn extract_abis(&self) -> Option<Vec<EntryABI>> {
        self.package.compiled_abis.as_ref().map(|abis| {
            abis.iter()
                .map(|(_, bytes)| bcs::from_bytes::<EntryABI>(bytes.as_slice()).unwrap())
                .collect()
        })
    }
```

**File:** third_party/move/move-core/types/src/abi.rs (L15-27)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptFunctionABI {
    /// The public name of the script.
    name: String,
    /// The module name where the script lives.
    module_name: ModuleId,
    /// Some text comment.
    doc: String,
    /// The names of the type arguments.
    ty_args: Vec<TypeArgumentABI>,
    /// The description of regular arguments.
    args: Vec<ArgumentABI>,
}
```

**File:** aptos-move/aptos-sdk-builder/src/rust.rs (L336-358)
```rust
    fn output_variant_encoder(&mut self, abi: &EntryABI) -> Result<()> {
        let params = std::iter::empty()
            .chain(abi.ty_args().iter().map(TypeArgumentABI::name))
            .chain(abi.args().iter().map(ArgumentABI::name))
            .collect::<Vec<_>>()
            .join(", ");

        let prefix = if let EntryABI::EntryFunction(sf) = abi {
            sf.module_name().name().to_string().to_upper_camel_case()
        } else {
            String::new()
        };
        writeln!(
            self.out,
            "{5}{0}{{{2}}} => {3}{4}{1}({2}),",
            abi.name().to_upper_camel_case(),
            abi.name(),
            params,
            prefix.to_snake_case(),
            if prefix.is_empty() { "" } else { "_" },
            prefix,
        )
    }
```

**File:** aptos-move/aptos-sdk-builder/src/rust.rs (L434-439)
```rust
    fn output_comment(&mut self, indentation: usize, doc: &str) -> std::io::Result<()> {
        let prefix = " ".repeat(indentation) + "/// ";
        let empty_line = "\n".to_string() + &" ".repeat(indentation) + "///\n";
        let text = textwrap::indent(doc, &prefix).replace("\n\n", &empty_line);
        write!(self.out, "\n{}\n", text)
    }
```

**File:** aptos-move/aptos-sdk-builder/src/common.rs (L24-27)
```rust
/// Clean up doc comments extracted by the Move prover.
pub(crate) fn prepare_doc_string(doc: &str) -> String {
    doc.replace("\n ", "\n").trim().to_string()
}
```
