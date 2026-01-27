# Audit Report

## Title
Terminal Injection via Unsanitized Source Code in Move Coverage Tool

## Summary
The `move-coverage` tool's `source-coverage` binary outputs Move source code directly to the terminal without sanitizing ANSI escape sequences or terminal control characters. An attacker can embed malicious sequences in Move source files that execute when a developer runs coverage analysis, potentially manipulating the terminal display or executing commands. [1](#0-0) 

## Finding Description
The vulnerability exists in the coverage output pipeline where source file contents flow unsanitized to stdout:

1. **Source Input**: The tool reads Move source files directly from disk without validation [2](#0-1) 

2. **Processing Without Sanitization**: File contents are split into lines and segments but never escaped for terminal control sequences [3](#0-2) 

3. **Unsafe Output**: The segments are wrapped with colored annotations using the `colored` crate, but the crate does not sanitize existing ANSI codes within the input strings [4](#0-3) 

An attacker can create a malicious Move source file containing embedded ANSI escape sequences in comments or string literals. When a developer runs coverage analysis on this file, the sequences are output to their terminal and executed.

**Example Attack Vector**: A Move file with a comment like:
```
// Innocent comment \x1b]0;Fake Title - Enter Password:\x07\x1b[2J\x1b[H
```

This could clear the screen, change the terminal title, reposition the cursor, or in some terminal emulators, manipulate clipboard contents or execute commands.

## Impact Explanation
**Severity: Medium** - This qualifies as Medium severity under the "state inconsistencies requiring intervention" category, as it affects the developer's local environment integrity. However, it's important to note this is a **local developer tool vulnerability** that does NOT affect:
- Blockchain consensus or validator operations
- On-chain state or execution
- Network protocol security
- Funds or assets on the blockchain

The impact is limited to:
- Terminal display manipulation for developers running coverage
- Potential social engineering via fake prompts
- Information disclosure if terminal history is manipulated
- In rare cases with vulnerable terminal emulators, command execution

## Likelihood Explanation
**Likelihood: Medium** - Exploitation requires:
1. Attacker convinces developer to run coverage on malicious code (e.g., via dependency, shared code, or code review)
2. Developer uses the `source-coverage` tool or `aptos move coverage source` command
3. Output goes to stdout (default behavior when no `--coverage-path` specified)

This is realistic during normal development workflows, code reviews, or when analyzing third-party Move modules. However, it requires social engineering or supply chain positioning to deliver the malicious file.

## Recommendation
Implement terminal output sanitization before writing to stdout. Options include:

1. **Strip ANSI Sequences**: Use a library to remove all ANSI escape codes from source content before output
2. **Escape Control Characters**: Convert control characters to printable representations (e.g., `\x1b` → `\\x1b`)
3. **Use Terminal-Safe Output**: Leverage libraries like `strip-ansi-escapes` or implement regex-based filtering

**Example Fix**:
```rust
// Add dependency: strip-ansi-escapes = "0.2"
use strip_ansi_escapes::strip_str;

// In output_source_coverage function:
match string_segment {
    StringSegment::Covered(s) => {
        let sanitized = strip_str(s).unwrap_or_else(|_| s.clone());
        write!(output_writer, "{}", sanitized.green())?
    },
    StringSegment::Uncovered(s) => {
        let sanitized = strip_str(s).unwrap_or_else(|_| s.clone());
        write!(output_writer, "{}", sanitized.bold().red())?
    },
}
```

## Proof of Concept
Create a malicious Move source file:

```move
// File: malicious.move
module 0x1::test {
    // This comment contains malicious ANSI codes:
    // \x1b[31mFAKE ERROR\x1b[0m
    // \x1b]0;Compromised Terminal\x07
    public fun test() {}
}
```

Run coverage analysis:
```bash
# Compile the module first to get .mv and source map
move build

# Run coverage (assuming trace exists)
source-coverage \
    --input-trace-path trace.mvcov \
    --module-path build/test/bytecode_modules/test.mv \
    --source-path malicious.move \
    --is-raw-trace
```

The terminal will execute the embedded ANSI codes, changing the title and displaying colored text outside the tool's control.

## Notes
**Important Scope Limitation**: While this is a valid terminal injection vulnerability, it affects a **local developer tool** (`move-coverage`) that runs off-chain on developers' machines. It does NOT impact:
- Blockchain consensus or protocol security
- Validator node operations
- On-chain Move VM execution
- State management or storage
- Network operations or peer handling

This finding is categorized as Medium severity for **development tooling security** but would not qualify under typical blockchain protocol security audits focused on consensus, state integrity, or on-chain execution vulnerabilities.

### Citations

**File:** third_party/move/tools/move-coverage/src/bin/source-coverage.rs (L82-82)
```rust
        None => Box::new(io::stdout()),
```

**File:** third_party/move/tools/move-coverage/src/source_coverage.rs (L401-401)
```rust
        let file_contents = fs::read_to_string(file_path).unwrap();
```

**File:** third_party/move/tools/move-coverage/src/source_coverage.rs (L419-457)
```rust
        for (line_number, mut line) in file_contents.lines().map(|x| x.to_owned()).enumerate() {
            match uncovered_segments.get(&(line_number as u32)) {
                None => annotated_lines.push(vec![StringSegment::Covered(line)]),
                Some(segments) => {
                    // Note: segments are already pre-sorted by construction so don't need to be
                    // resorted.
                    let mut line_acc = Vec::new();
                    let mut cursor = 0;
                    for segment in segments {
                        match segment {
                            AbstractSegment::Bounded { start, end } => {
                                let length = end - start;
                                let (before, after) = line.split_at((start - cursor) as usize);
                                let (uncovered, rest) = after.split_at(length as usize);
                                line_acc.push(StringSegment::Covered(before.to_string()));
                                line_acc.push(StringSegment::Uncovered(uncovered.to_string()));
                                line = rest.to_string();
                                cursor = *end;
                            },
                            AbstractSegment::BoundedRight { end } => {
                                let (uncovered, rest) = line.split_at((end - cursor) as usize);
                                line_acc.push(StringSegment::Uncovered(uncovered.to_string()));
                                line = rest.to_string();
                                cursor = *end;
                            },
                            AbstractSegment::BoundedLeft { start } => {
                                let (before, after) = line.split_at((start - cursor) as usize);
                                line_acc.push(StringSegment::Covered(before.to_string()));
                                line_acc.push(StringSegment::Uncovered(after.to_string()));
                                line = "".to_string();
                                cursor = 0;
                            },
                        }
                    }
                    if !line.is_empty() {
                        line_acc.push(StringSegment::Covered(line))
                    }
                    annotated_lines.push(line_acc)
                },
```

**File:** third_party/move/tools/move-coverage/src/source_coverage.rs (L502-503)
```rust
                    StringSegment::Covered(s) => write!(output_writer, "{}", s.green())?,
                    StringSegment::Uncovered(s) => write!(output_writer, "{}", s.bold().red())?,
```
