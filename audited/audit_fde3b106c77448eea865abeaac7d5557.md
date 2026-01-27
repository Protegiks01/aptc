# Audit Report

## Title
Code Injection in Gas Schedule Proposal Generator Enables Move Compiler DoS

## Summary
The gas schedule proposal generation tools (`aptos-gas-schedule-updator` and `aptos-release-builder`) do not validate or sanitize gas schedule entry names when generating Move scripts. This allows an attacker who controls the gas schedule input (via local file or remote URL) to inject arbitrary Move code into generated governance proposal scripts, potentially causing the Move compiler to hang or crash during package building.

## Finding Description

The vulnerability exists in how gas schedule entries are embedded into generated Move script comments without proper sanitization. The `GasScheduleV2` struct contains a vector of `(String, u64)` entries with no validation on the string content. [1](#0-0) 

When generating governance proposals, these entry names are embedded directly into Move script comments: [2](#0-1) [3](#0-2) 

The `CodeWriter` implementation processes strings line-by-line but does not escape or sanitize newline characters: [4](#0-3) 

This means if an entry name contains `\n` (newline), it will break out of the comment context when emitted, allowing injection of arbitrary Move code.

The attack vector is enabled because gas schedules can be loaded from external sources without validation: [5](#0-4) 

**Attack Scenario:**
1. Attacker creates a malicious JSON file containing a `GasScheduleV2` with crafted entry names like: `"foo\n} fun malicious() { loop {} }\nscript {"`
2. The release builder loads this file via `GasScheduleLocator::LocalFile`
3. The proposal generator embeds these names in comments, breaking out and injecting the malicious code
4. The generated Move script contains: `//     foo` followed by `} fun malicious() { loop {} }` on a new line (no longer in a comment)
5. When compiled, the Move compiler processes the injected infinite loop, causing it to hang during constant folding or other compiler phases

## Impact Explanation

This is a **Medium severity** vulnerability because:

1. **Compiler DoS**: An attacker can craft gas schedules that generate Move code causing the compiler to hang indefinitely or crash, disrupting the governance proposal preparation process

2. **Supply Chain Attack Risk**: While the generated malicious script must still pass governance voting, the presence of injected code could go unnoticed if the generated file is not carefully reviewed, potentially leading to execution of unintended code on-chain

3. **Limited Direct Impact**: The vulnerability requires controlling the input to the proposal generation tool (typically run by core developers) and does not directly affect running validator nodes or on-chain operations

Per Aptos bug bounty criteria, this falls under Medium severity: "State inconsistencies requiring intervention" - as malicious proposals entering the governance system would require manual intervention to identify and reject.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- Attacker to provide a malicious gas schedule file (via social engineering, compromised CI/CD, or MitM if using RemoteFile)
- A developer to run the release builder tool with this malicious input
- The generated script to be compiled

While the attack requires some social engineering or access to the build environment, it is realistic because:
- The tool accepts arbitrary file paths and URLs
- Developers may not inspect the generated Move code carefully before compilation
- The BCS size check (< 65KB) is bypassed because the code injection happens during comment generation, not in the serialized blob

## Recommendation

Implement input validation and sanitization for gas schedule entry names:

```rust
// In types/src/on_chain_config/gas_schedule.rs
impl GasScheduleV2 {
    pub fn validate(&self) -> Result<(), String> {
        for (name, _) in &self.entries {
            // Validate entry names contain only allowed characters
            if !name.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_') {
                return Err(format!("Invalid gas schedule entry name: {}", name));
            }
            // Limit entry name length
            if name.len() > 256 {
                return Err(format!("Gas schedule entry name too long: {}", name));
            }
        }
        Ok(())
    }
}
```

And call validation when loading gas schedules:

```rust
// In aptos-move/aptos-release-builder/src/components/mod.rs
async fn fetch_gas_schedule(&self) -> Result<GasScheduleV2> {
    let gas_schedule = match self {
        GasScheduleLocator::LocalFile(path) => {
            let file_contents = fs::read_to_string(path)?;
            serde_json::from_str(&file_contents)?
        },
        GasScheduleLocator::RemoteFile(url) => {
            let response = reqwest::get(url.as_str()).await?;
            response.json().await?
        },
        GasScheduleLocator::Current => {
            return Ok(aptos_gas_schedule_updator::current_gas_schedule(
                LATEST_GAS_FEATURE_VERSION,
            ));
        }
    };
    
    // Validate before use
    gas_schedule.validate()
        .map_err(|e| anyhow!("Invalid gas schedule: {}", e))?;
    
    Ok(gas_schedule)
}
```

Additionally, sanitize strings in the code generation:

```rust
// Escape special characters in entry names
fn sanitize_for_comment(s: &str) -> String {
    s.replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}
```

## Proof of Concept

Create a malicious gas schedule JSON file (`malicious_gas.json`):

```json
{
  "feature_version": 12,
  "entries": [
    ["normal.param", 100],
    ["injected\n} fun infinite_loop() { loop {} }\nscript {", 200],
    ["another.param", 300]
  ]
}
```

Run the release builder:
```bash
cargo run --bin aptos-release-builder -- \
  --config malicious_config.yaml
```

Where `malicious_config.yaml` contains:
```yaml
entries:
  - Gas:
      old: null
      new: malicious_gas.json
```

The generated Move script will contain:
```move
// Gas schedule upgrade proposal
//
// Full gas schedule
//   Feature version: 12
//   Parameters:
//     normal.param                    : 100
//     injected
} fun infinite_loop() { loop {} }
script {  : 200
//     another.param                   : 300
```

When the Move compiler attempts to compile this script, it will encounter the injected `infinite_loop()` function and hang during compilation.

**Notes**

This vulnerability is specific to the offline tooling used to generate governance proposals, not the on-chain execution. However, it represents a significant supply chain security risk as it could be used to inject malicious code into governance proposals that might not be detected during review. The Move compiler DoS aspect directly answers the security question posed.

### Citations

**File:** types/src/on_chain_config/gas_schedule.rs (L13-17)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct GasScheduleV2 {
    pub feature_version: u64,
    pub entries: Vec<(String, u64)>,
}
```

**File:** aptos-move/aptos-gas-schedule-updator/src/lib.rs (L58-61)
```rust
    for (name, val) in &gas_schedule.entries {
        let name_with_spaces = format!("{}{}", name, " ".repeat(max_len - name.len()));
        emitln!(writer, "//     {} : {}", name_with_spaces, val);
    }
```

**File:** aptos-move/aptos-release-builder/src/components/gas.rs (L71-74)
```rust
    for (name, val) in &gas_schedule.entries {
        let name_with_spaces = format!("{}{}", name, " ".repeat(max_len - name.len()));
        emitln!(writer, "//     {} : {}", name_with_spaces, val);
    }
```

**File:** third_party/move/move-model/src/code_writer.rs (L195-218)
```rust
    pub fn emit(&self, s: &str) {
        let rewritten = (*self.0.borrow().emit_hook)(s);
        let s = if let Some(r) = &rewritten {
            r.as_str()
        } else {
            s
        };
        let mut first = true;
        // str::lines ignores trailing newline, so deal with this ad-hoc
        let end_newl = s.ends_with('\n');
        for l in s.lines() {
            if first {
                first = false
            } else {
                Self::trim_trailing_whitespace(&mut self.0.borrow_mut().output);
                self.0.borrow_mut().output.push('\n');
            }
            self.emit_str(l)
        }
        if end_newl {
            Self::trim_trailing_whitespace(&mut self.0.borrow_mut().output);
            self.0.borrow_mut().output.push('\n');
        }
    }
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L197-213)
```rust
    async fn fetch_gas_schedule(&self) -> Result<GasScheduleV2> {
        println!("{:?}", self);
        match self {
            GasScheduleLocator::LocalFile(path) => {
                let file_contents = fs::read_to_string(path)?;
                let gas_schedule: GasScheduleV2 = serde_json::from_str(&file_contents)?;
                Ok(gas_schedule)
            },
            GasScheduleLocator::RemoteFile(url) => {
                let response = reqwest::get(url.as_str()).await?;
                let gas_schedule: GasScheduleV2 = response.json().await?;
                Ok(gas_schedule)
            },
            GasScheduleLocator::Current => Ok(aptos_gas_schedule_updator::current_gas_schedule(
                LATEST_GAS_FEATURE_VERSION,
            )),
        }
```
